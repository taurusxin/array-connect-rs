//! Password callbacks and Array login/session management.
mod cookie;
mod session;

pub(crate) use session::AuthSession;

use crate::{Result, SecretString, TlsInfo};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Supplied only after TLS completes with the configured certificate policy.
#[derive(Clone, Debug)]
pub struct PasswordChallenge {
    pub server: Url,
    pub username: String,
    pub authgroup: String,
    pub tls: TlsInfo,
    pub cancellation: CancellationToken,
}

/// Obtain a password after establishing TLS, without putting terminal/UI code
/// into the library. Implementations must observe challenge.cancellation and
/// return after restoring any UI/terminal state. The library awaits this cleanup.
/// Human input is not subject to connect_timeout. Reauthentication reuses the
/// password retained in memory for this session by default. Providers that
/// return one-time credentials can opt out via cache_password().
#[async_trait]
pub trait PasswordProvider: Send + Sync {
    /// Set false for one-time credentials (for example password + TOTP) so that
    /// session renewal requests fresh credentials after its next TLS handshake.
    fn cache_password(&self) -> bool {
        true
    }

    async fn password(&self, challenge: PasswordChallenge) -> Result<SecretString>;
}
