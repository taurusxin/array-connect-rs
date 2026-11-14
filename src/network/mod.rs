//! Injectable packet I/O, routing policy, and optional system network management.
use crate::{NetworkConfig, NetworkSettings, Result};
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};

mod routes;
pub use routes::plan_routes;
#[cfg(feature = "system-network")]
mod system;
#[cfg(feature = "system-network")]
pub use system::SystemNetworkManager;

/// Datagram-oriented TUN I/O. Implementations must be cancellation-safe for recv:
/// dropping recv must not consume a packet or leave a background read outstanding.
#[async_trait]
pub trait PacketIo: Send + Sync {
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize>;
    async fn send(&self, packet: &[u8]) -> std::io::Result<()>;
}

/// Setup/cleanup are awaited to completion, including when disconnect is requested.
/// A failed setup may have side effects: cleanup must undo those and be idempotent.
/// A successful cleanup must release all system configuration it owns.
#[async_trait]
pub trait NetworkManager: Send {
    async fn setup(
        &mut self,
        settings: &NetworkSettings,
        config: &NetworkConfig,
        endpoint: SocketAddr,
    ) -> Result<Arc<dyn PacketIo>>;
    async fn cleanup(&mut self) -> Result<()>;
}
