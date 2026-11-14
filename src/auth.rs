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
/// password retained in memory for this session, without invoking the provider.
#[async_trait]
pub trait PasswordProvider: Send + Sync {
    async fn password(&self, challenge: PasswordChallenge) -> Result<SecretString>;
}
