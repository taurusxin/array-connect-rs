use super::{TlsContext, TlsInfo, TlsStreamIo, decode_pins, spki_pin};
use crate::{Result, TlsBackend, TlsConfig, VpnError};
use ::rustls as rustls_lib;
use rustls_lib::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::{io::BufReader, sync::Arc};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::FromDer;

#[derive(Debug)]
struct Verifier {
    normal: Option<Arc<rustls_lib::client::WebPkiServerVerifier>>,
    provider: Arc<CryptoProvider>,
    pins: Vec<Vec<u8>>,
    insecure: bool,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls_lib::Error> {
        if self.insecure {
            return Ok(ServerCertVerified::assertion());
        }
        if !self.pins.is_empty() {
            let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
                .map_err(|_| {
                    rustls_lib::Error::InvalidCertificate(rustls_lib::CertificateError::BadEncoding)
                })?;
            let hash = Sha256::digest(parsed.public_key().raw);
            if self
                .pins
                .iter()
                .any(|pin| pin.as_slice() == hash.as_slice())
            {
                return Ok(ServerCertVerified::assertion());
            }
            return Err(rustls_lib::Error::General(
                "server public key pin mismatch".into(),
            ));
        }
        self.normal
            .as_ref()
            .ok_or_else(|| {
                rustls_lib::Error::General("no trusted CA certificates available".into())
            })?
            .verify_server_cert(cert, intermediates, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls_lib::Error> {
        rustls_lib::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls_lib::Error> {
        rustls_lib::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(super) fn context(config: &TlsConfig) -> Result<TlsContext> {
    let provider = Arc::new(rustls_lib::crypto::ring::default_provider());
    let mut roots = rustls_lib::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(path) = &config.ca_file {
        let file = std::fs::File::open(path)?;
        let mut count = 0;
        for cert in rustls_pemfile::certs(&mut BufReader::new(file)) {
            roots
                .add(cert?)
                .map_err(|_| VpnError::Config("invalid certificate in CA file".into()))?;
            count += 1;
        }
        if count == 0 {
            return Err(VpnError::Config(
                "CA file contains no PEM certificates".into(),
            ));
        }
    }
    let pins = decode_pins(config)?;
    let normal = if roots.is_empty() {
        None
    } else {
        Some(
            rustls_lib::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                provider.clone(),
            )
            .build()
            .map_err(|e| VpnError::Tls(e.to_string()))?,
        )
    };
    let verifier = Arc::new(Verifier {
        normal,
        provider: provider.clone(),
        pins,
        insecure: config.insecure,
    });
    let mut tls = rustls_lib::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls_lib::version::TLS13, &rustls_lib::version::TLS12])
        .map_err(|e| VpnError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsContext::Rustls(Arc::new(tls)))
}

pub(super) async fn connect(
    tcp: TcpStream,
    server_host: &str,
    tls: Arc<rustls_lib::ClientConfig>,
) -> Result<(Box<dyn TlsStreamIo>, TlsInfo)> {
    let name = ServerName::try_from(server_host.to_owned())
        .map_err(|_| VpnError::Config("invalid TLS server name".into()))?;
    let stream = TlsConnector::from(tls)
        .connect(name, tcp)
        .await
        .map_err(rustls_error)?;
    let connection = stream.get_ref().1;
    let cert = connection
        .peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or_else(|| VpnError::Tls("server did not provide a certificate".into()))?;
    let info = TlsInfo {
        backend: TlsBackend::Rustls,
        protocol: format!(
            "{:?}",
            connection.protocol_version().expect("completed handshake")
        ),
        cipher: format!(
            "{:?}",
            connection
                .negotiated_cipher_suite()
                .expect("completed handshake")
                .suite()
        ),
        server_pin: spki_pin(cert.as_ref())?,
    };
    Ok((Box::new(stream), info))
}

fn rustls_error(error: std::io::Error) -> VpnError {
    let reason = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls_lib::Error>());
    if matches!(
        reason,
        Some(rustls_lib::Error::AlertReceived(
            rustls_lib::AlertDescription::HandshakeFailure
        ))
    ) {
        return VpnError::Tls("server rejected the rustls handshake (HandshakeFailure); check protocol/cipher compatibility or server policy. Rustls does not support static RSA key exchange or CBC suites such as AES128-SHA; --insecure cannot enable these suites. Use a compatible gateway configuration or the optional --tls-backend openssl".into());
    }
    if reason.is_some() || error.kind() == std::io::ErrorKind::InvalidData {
        VpnError::Tls(format!("rustls handshake failed: {error}"))
    } else {
        VpnError::Io(error)
    }
}
