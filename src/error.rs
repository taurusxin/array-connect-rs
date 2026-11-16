use std::io;

pub type Result<T> = std::result::Result<T, VpnError>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VpnError {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("authentication failed or session expired")]
    Authentication,
    #[error(
        "OTP enrollment outcome is uncertain; the gateway may already have replaced the secret: {0}"
    )]
    OtpEnrollmentUncertain(#[source] Box<VpnError>),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("Array protocol error: {0}")]
    Protocol(String),
    #[error("HTTP request failed with status {0}")]
    Http(u16),
    #[error("proxy negotiation failed: {0}")]
    Proxy(String),
    #[error("network configuration failed: {0}")]
    Network(String),
    #[error("operation timed out: {0}")]
    Timeout(&'static str),
    #[error("operation cancelled")]
    Cancelled,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cleanup failed after {primary}: {cleanup}")]
    Cleanup { primary: String, cleanup: String },
}

impl VpnError {
    pub(crate) fn retryable(&self) -> bool {
        matches!(self, Self::Io(_) | Self::Timeout(_) | Self::Http(500..=599))
    }
}
