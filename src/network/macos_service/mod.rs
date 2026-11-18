//! macOS network privilege separation through an installed launchd helper.

mod daemon;
mod dns;
mod installation;
mod protocol;

use crate::{
    CancellationToken, NetworkConfig, NetworkManager, NetworkSettings, PacketIo, Result, VpnError,
};
use async_trait::async_trait;
pub use daemon::run_daemon;
pub(super) use dns::DnsSession;
pub use installation::install_daemon;
use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    io,
    net::SocketAddr,
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
    path::Path,
    ptr::NonNull,
    sync::Arc,
};
use tun_rs::AsyncDevice;

const ERROR_LIMIT: usize = 512;
const PROTOCOL_MISMATCH: c_int = -2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
    Unavailable,
    NotInstalled,
    UpgradeRequired,
    RepairRequired,
    Enabled,
}

impl ServiceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::NotInstalled => "notInstalled",
            Self::UpgradeRequired => "upgradeRequired",
            Self::RepairRequired => "repairRequired",
            Self::Enabled => "enabled",
        }
    }

    pub fn user_message(self) -> &'static str {
        match self {
            Self::Unavailable => "VPN 网络服务需要 macOS 13 或更新系统，请从应用程序包启动",
            Self::NotInstalled => "请先在客户端安装 macOS VPN 网络服务",
            Self::UpgradeRequired => "当前应用与已安装的 VPN 网络服务版本不匹配，请更新服务",
            Self::RepairRequired => "无法连接 VPN 网络服务，请检查后台运行权限或重新安装",
            Self::Enabled => "macOS VPN 网络服务已就绪",
        }
    }
}

unsafe extern "C" {
    fn ac_client_open(
        daemon_hash: *const c_char,
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
    ready_client().map_or_else(|status| status, |_| ServiceStatus::Enabled)
}

pub fn install_service(payload: &Path, digest: &str) -> Result<ServiceStatus> {
    if service_status() == ServiceStatus::Enabled {
        return Ok(ServiceStatus::Enabled);
    }
    installation::request_install(payload, digest)?;
    let status = service_status();
    if status != ServiceStatus::Enabled {
        return Err(VpnError::Network(status.user_message().into()));
    }
    Ok(status)
}

fn ready_client() -> std::result::Result<Arc<Client>, ServiceStatus> {
    let identity = installation::app_hash().ok_or(ServiceStatus::Unavailable)?;
    let receipt = installation::read_receipt().map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ServiceStatus::NotInstalled
        } else {
            tracing::warn!(%error, "could not read the macOS VPN service receipt");
            ServiceStatus::RepairRequired
        }
    })?;
    if receipt.client != identity || receipt.protocol != installation::protocol_version() {
        return Err(ServiceStatus::UpgradeRequired);
    }
    let client = Client::open(&receipt.daemon).map_err(|error| {
        tracing::warn!(%error, "could not open the macOS VPN service");
        ServiceStatus::RepairRequired
    })?;
    match client.request(Operation::Probe, &[]) {
        Ok(_) => Ok(client),
        Err(RequestError::Version) => Err(ServiceStatus::UpgradeRequired),
        Err(RequestError::Other(error)) => {
            tracing::warn!(%error, "macOS VPN service probe failed");
            Err(ServiceStatus::RepairRequired)
        }
    }
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

enum RequestError {
    Version,
    Other(VpnError),
}

fn connect_service() -> Result<Arc<Client>> {
    ready_client().map_err(|status| VpnError::Network(status.user_message().into()))
}

impl Client {
    fn open(daemon_hash: &str) -> Result<Arc<Self>> {
        let daemon_hash = CString::new(daemon_hash).expect("validated hexadecimal CDHash");
        let lost = Arc::new(CancellationToken::new());
        let context = Arc::into_raw(lost.clone()).cast_mut().cast::<c_void>();
        // The native side releases the Arc on every path, including open failure.
        let handle = NonNull::new(unsafe {
            ac_client_open(daemon_hash.as_ptr(), context, mark_lost, release_context)
        })
        .ok_or_else(|| VpnError::Network("无法建立经过签名校验的 macOS VPN 服务连接".into()))?;
        Ok(Arc::new(Self { handle, lost }))
    }

    fn call(&self, operation: Operation, data: &[u8]) -> Result<Option<OwnedFd>> {
        self.request(operation, data).map_err(|error| match error {
            RequestError::Version => {
                VpnError::Network(ServiceStatus::UpgradeRequired.user_message().into())
            }
            RequestError::Other(error) => error,
        })
    }

    fn request(
        &self,
        operation: Operation,
        data: &[u8],
    ) -> std::result::Result<Option<OwnedFd>, RequestError> {
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
        match result {
            PROTOCOL_MISMATCH => return Err(RequestError::Version),
            0 => {}
            _ => return Err(RequestError::Other(service_error(&error))),
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
        Ok(Self {
            client: Some(connect_service()?),
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
            self.client = Some(blocking(connect_service).await?);
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
