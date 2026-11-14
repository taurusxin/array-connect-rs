use super::{TlsContext, TlsInfo, TlsStreamIo, decode_pins, spki_hash, spki_pin};
use crate::{Result, TlsBackend, TlsConfig, VpnError};
use ::openssl::{
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::X509,
};
use std::{pin::Pin, sync::Arc};
use tokio::net::TcpStream;

pub(super) fn context(config: &TlsConfig) -> Result<TlsContext> {
    // Validate pins before starting any network I/O.
    decode_pins(config)?;
    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| VpnError::Tls(format!("OpenSSL context initialization failed: {e}")))?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| VpnError::Tls(e.to_string()))?;
    // Array appliances can reset a ClientHello offering TLS 1.3, even when it
    // also offers TLS 1.2. This explicitly selected compatibility profile sends
    // a TLS 1.2-only ClientHello; the default Rustls profile remains unchanged.
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| VpnError::Tls(e.to_string()))?;
    builder
        .set_cipher_list(config.openssl_ciphers.as_deref().unwrap_or("DEFAULT"))
        .map_err(|_| {
            VpnError::Config("invalid OpenSSL cipher list (no available cipher)".into())
        })?;
    builder
        .set_alpn_protos(b"\x08http/1.1")
        .map_err(|e| VpnError::Tls(e.to_string()))?;
    // Use the same platform trust roots as the default Rustls backend, including
    // Windows roots. Do not depend on a separate OpenSSL PEM installation.
    for cert in rustls_native_certs::load_native_certs().certs {
        if let Ok(cert) = X509::from_der(cert.as_ref()) {
            let _ = builder.cert_store_mut().add_cert(cert);
        }
    }
    if let Some(path) = &config.ca_file {
        let certs = X509::stack_from_pem(&std::fs::read(path)?)
            .map_err(|_| VpnError::Config("invalid PEM CA file".into()))?;
        if certs.is_empty() {
            return Err(VpnError::Config(
                "CA file contains no PEM certificates".into(),
            ));
        }
        for cert in certs {
            builder
                .cert_store_mut()
                .add_cert(cert)
                .map_err(|e| VpnError::Config(format!("cannot load CA: {e}")))?;
        }
    }
    // A pin is an explicit alternative to CA/name verification, matching the
    // Rustls policy. The pin is checked immediately after TLS, before any HTTP.
    builder.set_verify(if config.insecure || !config.server_pins.is_empty() {
        SslVerifyMode::NONE
    } else {
        SslVerifyMode::PEER
    });
    Ok(TlsContext::OpenSsl(Arc::new(builder.build())))
}

pub(super) async fn connect(
    tcp: TcpStream,
    hostname: &str,
    context: Arc<SslConnector>,
    config: &TlsConfig,
) -> Result<(Box<dyn TlsStreamIo>, TlsInfo)> {
    let mut settings = context
        .configure()
        .map_err(|e| VpnError::Tls(e.to_string()))?;
    settings.set_verify_hostname(!config.insecure && config.server_pins.is_empty());
    let ssl = settings
        .into_ssl(hostname)
        .map_err(|e| VpnError::Tls(e.to_string()))?;
    let mut stream =
        tokio_openssl::SslStream::new(ssl, tcp).map_err(|e| VpnError::Tls(e.to_string()))?;
    if let Err(error) = Pin::new(&mut stream).connect().await {
        if let Some(io) = error.io_error() {
            return Err(VpnError::Io(std::io::Error::new(io.kind(), io.to_string())));
        }
        return Err(VpnError::Tls(format!(
            "OpenSSL handshake failed: {error}; certificate result: {}",
            stream.ssl().verify_result()
        )));
    }
    let cert = stream
        .ssl()
        .peer_certificate()
        .ok_or_else(|| VpnError::Tls("server did not provide a certificate".into()))?;
    let der = cert.to_der().map_err(|e| VpnError::Tls(e.to_string()))?;
    let pins = decode_pins(config)?;
    if !pins.is_empty()
        && !pins
            .iter()
            .any(|pin| spki_hash(&der).is_ok_and(|hash| &hash == pin))
    {
        return Err(VpnError::Tls("server public key pin mismatch".into()));
    }
    let info = TlsInfo {
        backend: TlsBackend::OpenSsl,
        protocol: stream.ssl().version_str().into(),
        cipher: stream
            .ssl()
            .current_cipher()
            .ok_or_else(|| VpnError::Tls("no negotiated cipher".into()))?
            .name()
            .into(),
        server_pin: spki_pin(&der)?,
    };
    Ok((Box::new(stream), info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, ClientConfig, VpnClient};
    use ::openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        ssl::{Ssl, SslAcceptor},
        x509::{X509NameBuilder, extension::SubjectAlternativeName},
    };
    use base64::Engine;
    use std::{
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    struct Fixture {
        address: SocketAddr,
        pin: String,
        task: tokio::task::JoinHandle<()>,
        received: Arc<AtomicUsize>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl Fixture {
        async fn new() -> Self {
            let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
            let mut name = X509NameBuilder::new().unwrap();
            name.append_entry_by_text("CN", "localhost").unwrap();
            let name = name.build();
            let mut cert = X509::builder().unwrap();
            cert.set_version(2).unwrap();
            cert.set_subject_name(&name).unwrap();
            cert.set_issuer_name(&name).unwrap();
            cert.set_pubkey(&key).unwrap();
            cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
                .unwrap();
            let san = SubjectAlternativeName::new()
                .dns("localhost")
                .ip("127.0.0.1")
                .build(&cert.x509v3_context(None, None))
                .unwrap();
            cert.append_extension(san).unwrap();
            cert.sign(&key, MessageDigest::sha256()).unwrap();
            let cert = cert.build();
            let pin = spki_pin(&cert.to_der().unwrap()).unwrap();
            let mut acceptor =
                SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
            acceptor
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .unwrap();
            acceptor
                .set_max_proto_version(Some(SslVersion::TLS1_2))
                .unwrap();
            acceptor.set_cipher_list("AES128-SHA").unwrap();
            acceptor.set_private_key(&key).unwrap();
            acceptor.set_certificate(&cert).unwrap();
            let acceptor = Arc::new(acceptor.build());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let received = Arc::new(AtomicUsize::new(0));
            let received_clone = received.clone();
            let task = tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let received = received_clone.clone();
                    tokio::spawn(async move {
                        let ssl = Ssl::new(acceptor.context()).unwrap();
                        let mut stream = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
                        if Pin::new(&mut stream).accept().await.is_err() {
                            return;
                        }
                        let mut buffer = [0; 4];
                        if stream.read_exact(&mut buffer).await.is_ok() {
                            received.fetch_add(4, Ordering::SeqCst);
                            let _ = stream.write_all(&buffer).await;
                        }
                    });
                }
            });
            Self {
                address,
                pin,
                task,
                received,
            }
        }
        fn config(&self, backend: TlsBackend) -> ClientConfig {
            let mut config = ClientConfig::new(
                &format!("https://localhost:{}", self.address.port()),
                AuthConfig::None,
            )
            .unwrap();
            config.resolve = Some(self.address.ip());
            config.tls.backend = backend;
            config.tls.server_pins = vec![self.pin.clone()];
            config.connect_timeout = Duration::from_secs(3);
            config
        }
    }

    #[tokio::test]
    async fn static_rsa_cbc_requires_explicit_compatibility_backend() {
        let fixture = Fixture::new().await;
        let error = VpnClient::new(fixture.config(TlsBackend::Rustls))
            .unwrap()
            .probe_tls()
            .await
            .unwrap_err();
        assert!(matches!(error, VpnError::Tls(_)));
        assert!(error.to_string().contains("AES128-SHA"));
        let config = fixture.config(TlsBackend::OpenSsl);
        let info = VpnClient::new(config.clone())
            .unwrap()
            .probe_tls()
            .await
            .unwrap();
        assert_eq!(info.protocol, "TLSv1.2");
        assert_eq!(info.cipher, "AES128-SHA");
        assert_eq!(info.server_pin, fixture.pin);
        assert_eq!(
            fixture.received.load(Ordering::SeqCst),
            0,
            "probe must not send HTTP or credentials"
        );
        let mut wire = crate::transport::connect(&config, context(&config.tls).unwrap())
            .await
            .unwrap();
        wire.stream.write_all(b"PING").await.unwrap();
        let mut reply = [0; 4];
        wire.stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"PING");
    }

    #[tokio::test]
    async fn compatibility_keeps_certificate_and_pin_verification() {
        let fixture = Fixture::new().await;
        let mut config = fixture.config(TlsBackend::OpenSsl);
        config.tls.server_pins.clear();
        assert!(matches!(
            VpnClient::new(config.clone()).unwrap().probe_tls().await,
            Err(VpnError::Tls(_))
        ));
        config.tls.server_pins = vec![format!(
            "pin-sha256:{}",
            base64::engine::general_purpose::STANDARD.encode([0u8; 32])
        )];
        assert!(matches!(
            VpnClient::new(config.clone()).unwrap().probe_tls().await,
            Err(VpnError::Tls(_))
        ));
        config.tls.server_pins.clear();
        config.tls.insecure = true;
        assert!(VpnClient::new(config).unwrap().probe_tls().await.is_ok());
        assert_eq!(fixture.received.load(Ordering::SeqCst), 0);
    }
}
