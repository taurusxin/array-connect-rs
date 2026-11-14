//! TLS policies, shared certificate pinning, and backend dispatch.
#[cfg(feature = "openssl-tls")]
mod openssl;
mod rustls;

use super::TlsStreamIo;
use crate::{Result, TlsBackend, TlsConfig, VpnError};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::net::TcpStream;
use x509_parser::prelude::FromDer;

#[derive(Clone, Debug, serde::Serialize)]
pub struct TlsInfo {
    pub backend: TlsBackend,
    pub protocol: String,
    pub cipher: String,
    /// Public SPKI fingerprint observed after the configured verification policy.
    pub server_pin: String,
}

#[derive(Clone)]
pub(crate) enum TlsContext {
    Rustls(Arc<::rustls::ClientConfig>),
    #[cfg(feature = "openssl-tls")]
    OpenSsl(Arc<::openssl::ssl::SslConnector>),
}

pub(crate) fn tls_config(config: &TlsConfig) -> Result<TlsContext> {
    if config.insecure && !config.server_pins.is_empty() {
        return Err(VpnError::Config(
            "--insecure and --servercert are mutually exclusive".into(),
        ));
    }
    if config.backend == TlsBackend::OpenSsl {
        #[cfg(feature = "openssl-tls")]
        {
            return openssl::context(config);
        }
        #[cfg(not(feature = "openssl-tls"))]
        {
            return Err(VpnError::Config("OpenSSL backend is not compiled in; build with --features openssl-vendored (bundled) or openssl-tls (system OpenSSL)".into()));
        }
    }
    if config.openssl_ciphers.is_some() {
        return Err(VpnError::Config(
            "--openssl-ciphers requires --tls-backend openssl".into(),
        ));
    }
    rustls::context(config)
}

pub(super) async fn connect(
    tcp: TcpStream,
    hostname: &str,
    context: TlsContext,
    _config: &TlsConfig,
) -> Result<(Box<dyn TlsStreamIo>, TlsInfo)> {
    match context {
        TlsContext::Rustls(context) => rustls::connect(tcp, hostname, context).await,
        #[cfg(feature = "openssl-tls")]
        TlsContext::OpenSsl(context) => openssl::connect(tcp, hostname, context, _config).await,
    }
}

fn decode_pins(config: &TlsConfig) -> Result<Vec<Vec<u8>>> {
    config
        .server_pins
        .iter()
        .map(|pin| {
            STANDARD
                .decode(pin.strip_prefix("pin-sha256:").unwrap_or(pin))
                .ok()
                .filter(|v| v.len() == 32)
                .ok_or_else(|| {
                    VpnError::Config("server pin must be pin-sha256:<base64 SHA256 SPKI>".into())
                })
        })
        .collect()
}

fn spki_hash(cert: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert)
        .map_err(|_| VpnError::Tls("invalid DER server certificate".into()))?;
    Ok(Sha256::digest(cert.public_key().raw).to_vec())
}
fn spki_pin(cert: &[u8]) -> Result<String> {
    Ok(format!("pin-sha256:{}", STANDARD.encode(spki_hash(cert)?)))
}
