//! Array Networks SSL VPN over TLS, with a reusable asynchronous API.
//!
//! The library does not install a runtime, tracing subscriber, or signal handler.
//! Subscribe before connecting to observe authentication and network setup events.
mod auth;
mod client;
mod config;
mod error;
mod event;
mod http;
pub mod network;
pub mod protocol;
mod transport;
mod util;

pub use auth::{PasswordChallenge, PasswordProvider};
pub use client::{SessionHandle, VpnClient, VpnSession};
pub use config::{
    AuthConfig, ClientConfig, NetworkConfig, ReconnectConfig, RouteMode, TlsBackend, TlsConfig,
};
pub use error::{Result, VpnError};
pub use event::{ClientEvent, ConnectionState, SessionStats};
pub use network::{NetworkManager, PacketIo};
pub use protocol::NetworkSettings;
pub use secrecy::{ExposeSecret, SecretString};
pub use tokio_util::sync::CancellationToken;
pub use transport::TlsInfo;
