//! Array Networks SSL VPN over TLS, with a reusable asynchronous API.
//!
//! The library does not install a runtime, tracing subscriber, or signal handler.
//! Subscribe before connecting to observe authentication and network setup events.
mod auth;
mod client;
mod config;
mod error;
pub mod network;
pub mod protocol;
mod transport;

pub use auth::enrollment::{OtpEnrollment, OtpParameters};
pub use auth::{PasswordChallenge, PasswordProvider};
pub use client::{
    ClientEvent, ConnectionState, SessionHandle, SessionStats, VpnClient, VpnSession,
};
pub use config::{
    AuthConfig, ClientConfig, NetworkConfig, ReconnectConfig, RouteMode, TlsBackend, TlsConfig,
};
pub use error::{Result, VpnError};
pub use network::{NetworkManager, PacketIo};
pub use protocol::NetworkSettings;
pub use secrecy::{ExposeSecret, SecretString};
pub use tokio_util::sync::CancellationToken;
pub use transport::TlsInfo;
