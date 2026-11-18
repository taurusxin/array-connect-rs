use super::{NetworkManager, PacketIo, plan_routes};
use crate::{NetworkConfig, NetworkSettings, Result, RouteMode, VpnError};
use async_trait::async_trait;
use ipnet::Ipv4Net;
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use tun_rs::{AsyncDevice, DeviceBuilder};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

#[async_trait]
impl PacketIo for AsyncDevice {
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.recv(buffer).await
    }
    async fn send(&self, packet: &[u8]) -> std::io::Result<()> {
        let n = self.send(packet).await?;
        if n != packet.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short TUN write",
            ));
        }
        Ok(())
    }
}

/// Owns a fresh, temporary TUN and a rollback journal. Normal shutdown should
/// always await cleanup; Drop only provides a synchronous best-effort fallback.
#[derive(Default)]
pub struct SystemNetworkManager {
    inner: Arc<Mutex<SystemState>>,
}

#[derive(Default)]
struct SystemState {
    device: Option<Arc<AsyncDevice>>,
    platform: Option<platform::Platform>,
    #[cfg(all(target_os = "macos", feature = "macos-network-service"))]
    delegated: bool,
}

#[cfg(all(target_os = "macos", feature = "macos-network-service"))]
impl SystemNetworkManager {
    pub(super) fn delegated_macos() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SystemState {
                delegated: true,
                ..Default::default()
            })),
        }
    }

    pub(super) fn duplicate_tun(&self) -> Result<std::os::fd::OwnedFd> {
        use std::os::fd::{AsRawFd, BorrowedFd};
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let device = state
            .device
            .as_ref()
            .ok_or_else(|| VpnError::Network("utun has not been configured".into()))?;
        // The state holds the device open until the kernel duplicates its descriptor.
        let descriptor = unsafe { BorrowedFd::borrow_raw(device.as_raw_fd()) };
        Ok(descriptor.try_clone_to_owned()?)
    }
}

impl SystemState {
    fn setup(
        &mut self,
        settings: &NetworkSettings,
        config: &NetworkConfig,
        endpoint: SocketAddr,
    ) -> Result<Arc<dyn PacketIo>> {
        self.cleanup()?;
        let mut routes = plan_routes(settings, config)?;
        // A bypass must win even against a server-supplied /32 route.
        if let IpAddr::V4(ip) = endpoint.ip() {
            routes = remove_endpoint(routes, ip)?;
        }
        // A delegated lease excludes the peer from every utun route above.
        // Its routes can then all disappear with utun, with no physical route
        // left behind after an abrupt service exit.
        let add_bypass = config.route_mode != RouteMode::None;
        #[cfg(all(target_os = "macos", feature = "macos-network-service"))]
        let add_bypass = add_bypass && !self.delegated;
        self.platform = Some(platform::Platform::new(endpoint.ip(), add_bypass)?);
        let name = config.interface_name.clone().unwrap_or_else(|| {
            #[cfg(target_os = "macos")]
            {
                String::new()
            }
            #[cfg(not(target_os = "macos"))]
            {
                format!("array{:08x}", rand::random::<u32>())
            }
        });
        if !name.is_empty() {
            platform::ensure_new_interface(&name)?;
        }
        // A TUN is a point-to-point IP transport, not an Ethernet subnet.
        // /32 prevents automatic connected routes from bypassing exclusions.
        // The gateway's advertised mask remains available in NetworkSettings.
        let mut builder = DeviceBuilder::new()
            .mtu(settings.mtu)
            .ipv4(settings.address, 32, None);
        if !name.is_empty() {
            builder = builder.name(name);
        }
        #[cfg(target_os = "macos")]
        {
            builder = builder.associate_route(false);
        }
        #[cfg(windows)]
        {
            let path = std::env::current_exe()?.with_file_name("wintun.dll");
            if !path.is_file() {
                return Err(VpnError::Network(
                    "wintun.dll is required next to the executable; run as Administrator".into(),
                ));
            }
            builder = builder
                .wintun_file(path.to_string_lossy().into_owned())
                .metric(1);
        }
        let device = Arc::new(builder.build_async().map_err(|e| {
            VpnError::Network(format!("create TUN (administrator/root required): {e}"))
        })?);
        self.device = Some(device.clone());
        let platform = self.platform.as_mut().expect("created");
        platform.configure(&device, settings, config, &routes)?;
        tracing::info!(interface=%device.name()?, address=%settings.address, prefix=settings.prefix_len, mtu=settings.mtu,
            routes=routes.len(), dns=config.manage_dns, "system network configured");
        Ok(device)
    }
    fn cleanup(&mut self) -> Result<()> {
        if let Some(platform) = &mut self.platform {
            platform.cleanup()?;
        }
        self.platform = None;
        self.device = None;
        Ok(())
    }
}

fn remove_endpoint(routes: Vec<Ipv4Net>, endpoint: std::net::Ipv4Addr) -> Result<Vec<Ipv4Net>> {
    // Reuse the same prefix subtraction policy, without adding any DNS routes.
    let settings = NetworkSettings {
        address: endpoint,
        prefix_len: 32,
        mtu: 1400,
        include_routes: routes.clone(),
        exclude_routes: vec![Ipv4Net::new(endpoint, 32).expect("valid")],
        dns_servers: vec![],
        search_domains: vec![],
    };
    let config = NetworkConfig {
        manage_dns: false,
        ..Default::default()
    };
    if routes.is_empty() {
        return Ok(routes);
    }
    // Input has already passed the route-count bound; an endpoint adds <=32.
    plan_routes(&settings, &config)
}

#[async_trait]
impl NetworkManager for SystemNetworkManager {
    async fn setup(
        &mut self,
        settings: &NetworkSettings,
        config: &NetworkConfig,
        endpoint: SocketAddr,
    ) -> Result<Arc<dyn PacketIo>> {
        let inner = self.inner.clone();
        let settings = settings.clone();
        let config = config.clone();
        tokio::task::spawn_blocking(move || {
            let mut state = inner.lock().unwrap_or_else(|e| e.into_inner());
            match state.setup(&settings, &config, endpoint) {
                Ok(io) => Ok(io),
                Err(error) => match state.cleanup() {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(VpnError::Cleanup {
                        primary: error.to_string(),
                        cleanup: cleanup.to_string(),
                    }),
                },
            }
        })
        .await
        .map_err(|_| VpnError::Network("network setup worker panicked".into()))?
    }
    async fn cleanup(&mut self) -> Result<()> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            inner.lock().unwrap_or_else(|e| e.into_inner()).cleanup()
        })
        .await
        .map_err(|_| VpnError::Network("network cleanup worker panicked".into()))?
    }
}
impl Drop for SystemNetworkManager {
    fn drop(&mut self) {
        if let Err(error) = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cleanup()
        {
            tracing::error!(%error,"network cleanup during drop failed");
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn command(program: &str, args: &[String], input: Option<&str>) -> Result<String> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    tracing::debug!(program, ?args, "system network operation");
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| VpnError::Network(format!("{program}: {e}")))?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .expect("piped")
            .write_all(input.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(VpnError::Network(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
