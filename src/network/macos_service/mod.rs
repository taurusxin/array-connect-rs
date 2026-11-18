//! macOS network privilege separation for Developer ID signed desktop bundles.

mod daemon;
mod dns;
mod protocol;

use crate::{
    CancellationToken, NetworkConfig, NetworkManager, NetworkSettings, PacketIo, Result, VpnError,
};
use async_trait::async_trait;
pub use daemon::run_daemon;
pub(super) use dns::DnsSession;
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    io,
    net::SocketAddr,
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
    ptr::NonNull,
    sync::Arc,
};
use tun_rs::AsyncDevice;

const ERROR_LIMIT: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
    Unavailable,
    NotRegistered,
    ApprovalRequired,
    Enabled,
}

impl ServiceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::NotRegistered => "notRegistered",
            Self::ApprovalRequired => "approvalRequired",
            Self::Enabled => "enabled",
        }
    }

    pub fn user_message(self) -> &'static str {
        match self {
            Self::Unavailable => "后台网络服务需要安装 Developer ID 签名版及 macOS 13 或更新系统",
            Self::NotRegistered => "请先在客户端启用 macOS VPN 网络服务",
            Self::ApprovalRequired => "请在系统设置的登录项与扩展中允许 Array Connect 后台运行",
            Self::Enabled => "macOS VPN 网络服务已获授权",
        }
    }
}

unsafe extern "C" {
    fn ac_service_status() -> c_int;
    fn ac_service_authorize(error: *mut c_char) -> c_int;
    fn ac_client_open(
        context: *mut c_void,
        failed: unsafe extern "C" fn(*mut c_void),
        release: unsafe extern "C" fn(*mut c_void),
    ) -> *mut c_void;
    fn ac_client_close(client: *mut c_void);
    fn ac_client_request(
        client: *mut c_void,
        operation: c_int,
        data: *const u8,
        length: usize,
        descriptor: *mut c_int,
        error: *mut c_char,
    ) -> c_int;
}

pub fn service_status() -> ServiceStatus {
    match unsafe { ac_service_status() } {
        1 => ServiceStatus::NotRegistered,
        2 => ServiceStatus::ApprovalRequired,
        3 => ServiceStatus::Enabled,
        _ => ServiceStatus::Unavailable,
    }
}

pub fn authorize_service() -> Result<ServiceStatus> {
    let mut error = [0; ERROR_LIMIT];
    if unsafe { ac_service_authorize(error.as_mut_ptr()) } != 0 {
        return Err(service_error(&error));
    }
    Ok(service_status())
}

fn service_error(error: &[c_char; ERROR_LIMIT]) -> VpnError {
    // The bridge always zero-terminates the error text in the provided buffer.
    let error = unsafe { CStr::from_ptr(error.as_ptr()) }.to_string_lossy();
    VpnError::Network(if error.is_empty() {
        "macOS VPN 网络服务请求失败".into()
    } else {
        error.into_owned()
    })
}

struct Client {
    handle: NonNull<c_void>,
    lost: Arc<CancellationToken>,
}

// The handle owns an XPC connection. libxpc permits calls from any thread, and
// every in-flight call holds an Arc<Client> so Drop cannot close it concurrently.
unsafe impl Send for Client {}
unsafe impl Sync for Client {}

unsafe extern "C" fn mark_lost(context: *mut c_void) {
    // The bridge's callback block retains the context until release_context.
    unsafe { &*context.cast::<CancellationToken>() }.cancel();
}

unsafe extern "C" fn release_context(context: *mut c_void) {
    // Exactly one retained reference was transferred to the bridge.
    drop(unsafe { Arc::from_raw(context.cast::<CancellationToken>()) });
}

#[repr(i32)]
enum Operation {
    Probe,
    Setup,
    Cleanup,
}

impl Client {
    fn open() -> Result<Arc<Self>> {
        let lost = Arc::new(CancellationToken::new());
        let context = Arc::into_raw(lost.clone()).cast_mut().cast::<c_void>();
        // The native side releases the Arc on every path, including open failure.
        let handle = NonNull::new(unsafe { ac_client_open(context, mark_lost, release_context) })
            .ok_or_else(|| {
            VpnError::Network("无法建立经过签名校验的 macOS VPN 服务连接".into())
        })?;
        let client = Arc::new(Self { handle, lost });
        client.call(Operation::Probe, &[])?;
        Ok(client)
    }

    fn call(&self, operation: Operation, data: &[u8]) -> Result<Option<OwnedFd>> {
        let mut descriptor = -1;
        let mut error = [0; ERROR_LIMIT];
        let result = unsafe {
            ac_client_request(
                self.handle.as_ptr(),
                operation as c_int,
                data.as_ptr(),
                data.len(),
                &mut descriptor,
                error.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(service_error(&error));
        }
        // A successful reply transfers ownership of a fresh descriptor.
        Ok((descriptor >= 0).then(|| unsafe { OwnedFd::from_raw_fd(descriptor) }))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe { ac_client_close(self.handle.as_ptr()) };
    }
}

/// Configures the system through a launchd-managed service while forwarding
/// packets in the calling process.
pub struct MacNetworkManager {
    client: Option<Arc<Client>>,
}

impl MacNetworkManager {
    /// Run this bounded readiness probe on a blocking thread before login.
    pub fn prepare() -> Result<Self> {
        let status = service_status();
        if status != ServiceStatus::Enabled {
            return Err(VpnError::Network(status.user_message().into()));
        }
        Ok(Self {
            client: Some(Client::open()?),
        })
    }
}

#[async_trait]
impl NetworkManager for MacNetworkManager {
    async fn setup(
        &mut self,
        settings: &NetworkSettings,
        config: &NetworkConfig,
        endpoint: SocketAddr,
    ) -> Result<Arc<dyn PacketIo>> {
        let data = serde_json::to_vec(&protocol::Setup {
            settings: settings.clone(),
            config: config.clone(),
            endpoint,
        })?;
        if data.len() > protocol::MAX_REQUEST {
            return Err(VpnError::Network("VPN 网络配置请求过大".into()));
        }
        if self.client.is_none() {
            self.client = Some(blocking(Client::open).await?);
        }
        let client = self.client.as_ref().expect("opened").clone();
        let lost = client.lost.clone();
        let descriptor = blocking(move || client.call(Operation::Setup, &data))
            .await?
            .ok_or_else(|| VpnError::Network("缺少 macOS utun 描述符".into()))?;
        // The mutually authenticated service sends only a new utun descriptor.
        let device = unsafe { AsyncDevice::from_fd(descriptor.into_raw_fd()) }?;
        Ok(Arc::new(ManagedPacketIo { device, lost }))
    }

    async fn cleanup(&mut self) -> Result<()> {
        if let Some(client) = self.client.take() {
            blocking(move || client.call(Operation::Cleanup, &[])).await?;
        }
        Ok(())
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| VpnError::Network("macOS VPN 网络服务工作线程异常".into()))?
}

struct ManagedPacketIo {
    device: AsyncDevice,
    lost: Arc<CancellationToken>,
}

#[async_trait]
impl PacketIo for ManagedPacketIo {
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        tokio::select! {
            biased;
            _ = self.lost.cancelled() => Err(service_lost()),
            packet = PacketIo::recv(&self.device, buffer) => packet,
        }
    }

    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        tokio::select! {
            biased;
            _ = self.lost.cancelled() => Err(service_lost()),
            result = PacketIo::send(&self.device, packet) => result,
        }
    }
}

fn service_lost() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "macOS VPN 网络服务连接已断开")
}
