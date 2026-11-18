use super::{ERROR_LIMIT, protocol};
use crate::{NetworkManager, Result, VpnError, network::SystemNetworkManager};
use std::{
    ffi::{c_char, c_int, c_void},
    os::fd::{IntoRawFd, OwnedFd},
    panic::{AssertUnwindSafe, catch_unwind},
};

struct State {
    runtime: tokio::runtime::Runtime,
    network: SystemNetworkManager,
}

unsafe extern "C" {
    fn ac_daemon_run(
        state: *mut c_void,
        setup: unsafe extern "C" fn(
            *mut c_void,
            *const u8,
            usize,
            *mut c_int,
            *mut c_char,
        ) -> c_int,
        cleanup: unsafe extern "C" fn(*mut c_void, *mut c_char) -> c_int,
    ) -> c_int;
}

/// Enter the foreground event loop of the signed launchd helper.
pub fn run_daemon() -> Result<()> {
    let state = Box::into_raw(Box::new(State {
        runtime: tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_io()
            .build()?,
        network: SystemNetworkManager::delegated_macos(),
    }));
    // The event loop owns the heap state after installing its serial callbacks.
    // A return indicates failure before callbacks could be installed.
    let result = unsafe { ac_daemon_run(state.cast(), setup, cleanup) };
    drop(unsafe { Box::from_raw(state) });
    if result != 0 {
        return Err(VpnError::Network(
            "requires launchd root context and a valid Developer ID helper signature".into(),
        ));
    }
    Ok(())
}

unsafe extern "C" fn setup(
    state: *mut c_void,
    data: *const u8,
    length: usize,
    descriptor: *mut c_int,
    error: *mut c_char,
) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<OwnedFd> {
        // The XPC message owns the data for the duration of this call.
        let request = protocol::Setup::decode(unsafe { std::slice::from_raw_parts(data, length) })?;
        let state = unsafe { &mut *state.cast::<State>() };
        state.runtime.block_on(state.network.setup(
            &request.settings,
            &request.config,
            request.endpoint,
        ))?;
        state.network.duplicate_tun()
    }));
    match result {
        Ok(Ok(fd)) => {
            // The caller adopts and closes this duplicate after creating the reply.
            unsafe { *descriptor = fd.into_raw_fd() };
            0
        }
        Ok(Err(cause)) => write_error(error, &cause.to_string()),
        Err(_) => write_error(error, "VPN network setup failed in the privileged worker"),
    }
}

unsafe extern "C" fn cleanup(state: *mut c_void, error: *mut c_char) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { &mut *state.cast::<State>() };
        state.runtime.block_on(state.network.cleanup())
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(cause)) => write_error(error, &cause.to_string()),
        Err(_) => write_error(error, "VPN network cleanup failed in the privileged worker"),
    }
}

fn write_error(buffer: *mut c_char, message: &str) -> c_int {
    let text = message.replace('\0', " ");
    let length = text.floor_char_boundary((ERROR_LIMIT - 1).min(text.len()));
    // The native caller allocates ERROR_LIMIT writable bytes for each callback.
    unsafe {
        std::ptr::copy_nonoverlapping(text.as_ptr(), buffer.cast::<u8>(), length);
        *buffer.add(length) = 0;
    }
    -1
}
