use crate::{Result, VpnError};
use std::{
    ffi::{CString, c_char, c_void},
    net::IpAddr,
    ptr::NonNull,
};

unsafe extern "C" {
    fn ac_dns_open(
        key: *const c_char,
        interface: *const c_char,
        servers: *const *const c_char,
        server_count: usize,
        search: *const *const c_char,
        search_count: usize,
    ) -> *mut c_void;
    fn ac_dns_close(store: *mut c_void);
}

pub(in crate::network) struct DnsSession(NonNull<c_void>);

// The store is created without callbacks or a run loop. Only its owner can
// release it, and the network state serializes access across worker threads.
unsafe impl Send for DnsSession {}

impl DnsSession {
    pub fn configure(interface: &str, servers: &[IpAddr], search: &[String]) -> Result<Self> {
        let key = CString::new(format!(
            "State:/Network/Service/arraysslvpn-{:016x}/DNS",
            rand::random::<u64>()
        ))
        .expect("fixed characters");
        let text = |value: &str| {
            CString::new(value).map_err(|_| VpnError::Network("invalid VPN DNS value".into()))
        };
        let interface = text(interface)?;
        let servers = servers
            .iter()
            .map(|ip| text(&ip.to_string()))
            .collect::<Result<Vec<_>>>()?;
        let search = search
            .iter()
            .map(|domain| text(domain))
            .collect::<Result<Vec<_>>>()?;
        let server_ptrs = servers
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        let search_ptrs = search
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        // The native function copies all strings before returning.
        let store = unsafe {
            ac_dns_open(
                key.as_ptr(),
                interface.as_ptr(),
                server_ptrs.as_ptr(),
                server_ptrs.len(),
                search_ptrs.as_ptr(),
                search_ptrs.len(),
            )
        };
        NonNull::new(store).map(Self).ok_or_else(|| {
            VpnError::Network("SystemConfiguration could not install temporary VPN DNS".into())
        })
    }
}

impl Drop for DnsSession {
    fn drop(&mut self) {
        unsafe { ac_dns_close(self.0.as_ptr()) };
    }
}
