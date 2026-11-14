use crate::{ClientConfig, Result, TlsBackend, TlsConfig, VpnError};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::BytesMut;
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::{
    io::BufReader,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::FromDer;

#[cfg(feature = "openssl-tls")]
#[path = "transport_openssl.rs"]
mod legacy;

#[derive(Clone, Debug, serde::Serialize)]
pub struct TlsInfo {
    pub backend: TlsBackend,
    pub protocol: String,
    pub cipher: String,
    /// Public SPKI fingerprint observed after the configured verification policy.
    pub server_pin: String,
}

pub(crate) trait TlsStreamIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TlsStreamIo for T {}

#[derive(Clone)]
pub(crate) enum TlsContext {
    Rustls(Arc<rustls::ClientConfig>),
    #[cfg(feature = "openssl-tls")]
    OpenSsl(Arc<openssl::ssl::SslConnector>),
}

pub(crate) struct Wire {
    pub stream: Box<dyn TlsStreamIo>,
    pub buffer: BytesMut,
    pub peer: SocketAddr,
    pub info: TlsInfo,
    pub after_json: bool,
}

impl Wire {
    pub async fn read_more(&mut self) -> Result<()> {
        let mut b = [0; 16384];
        let n = self.stream.read(&mut b).await?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        self.buffer.extend_from_slice(&b[..n]);
        Ok(())
    }
}

#[derive(Debug)]
struct Verifier {
    normal: Option<Arc<rustls::client::WebPkiServerVerifier>>,
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
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if self.insecure {
            return Ok(ServerCertVerified::assertion());
        }
        if !self.pins.is_empty() {
            let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
                .map_err(|_| {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
                })?;
            let hash = Sha256::digest(parsed.public_key().raw);
            if self
                .pins
                .iter()
                .any(|pin| pin.as_slice() == hash.as_slice())
            {
                return Ok(ServerCertVerified::assertion());
            }
            return Err(rustls::Error::General(
                "server public key pin mismatch".into(),
            ));
        }
        self.normal
            .as_ref()
            .ok_or_else(|| rustls::Error::General("no trusted CA certificates available".into()))?
            .verify_server_cert(cert, intermediates, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
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
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
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

pub(crate) fn tls_config(config: &TlsConfig) -> Result<TlsContext> {
    if config.insecure && !config.server_pins.is_empty() {
        return Err(VpnError::Config(
            "--insecure and --servercert are mutually exclusive".into(),
        ));
    }
    if config.backend == TlsBackend::OpenSsl {
        #[cfg(feature = "openssl-tls")]
        {
            return legacy::context(config);
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
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
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
            rustls::client::WebPkiServerVerifier::builder_with_provider(
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
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| VpnError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsContext::Rustls(Arc::new(tls)))
}

pub(crate) async fn connect(config: &ClientConfig, tls: TlsContext) -> Result<Wire> {
    let start = tokio::time::Instant::now();

    tokio::time::timeout(config.connect_timeout, async {
        let server_host = config
            .server
            .host_str()
            .expect("validated host")
            .trim_matches(['[', ']']);
        let server_port = config.server.port_or_known_default().unwrap_or(443);
        let target = config
            .resolve
            .map(|v| v.to_string())
            .unwrap_or_else(|| server_host.into());
        let mut tcp = if let Some(proxy) = &config.proxy {
            TcpStream::connect((
                proxy
                    .host_str()
                    .expect("validated proxy")
                    .trim_matches(['[', ']']),
                proxy
                    .port()
                    .unwrap_or(if proxy.scheme() == "http" { 8080 } else { 1080 }),
            ))
            .await?
        } else {
            TcpStream::connect((target.as_str(), server_port)).await?
        };
        tcp.set_nodelay(true)?;
        let peer = tcp.peer_addr()?;
        tracing::debug!(%peer, proxy = config.proxy.is_some(), "TCP connected");
        if let Some(proxy) = &config.proxy {
            if proxy.scheme() == "http" {
                http_proxy(&mut tcp, proxy, &target, server_port).await?;
            } else {
                socks_proxy(&mut tcp, proxy, &target, server_port).await?;
            }
        }
        let (stream, info): (Box<dyn TlsStreamIo>, TlsInfo) = match tls {
            TlsContext::Rustls(tls) => {
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
                (Box::new(stream), info)
            }
            #[cfg(feature = "openssl-tls")]
            TlsContext::OpenSsl(context) => {
                legacy::connect(tcp, server_host, context, &config.tls).await?
            }
        };
        tracing::info!(backend=%info.backend,version=%info.protocol,cipher=%info.cipher,
            elapsed_ms=start.elapsed().as_millis(),"TLS connected");
        Ok(Wire {
            stream,
            peer,
            buffer: BytesMut::new(),
            info,
            after_json: false,
        })
    })
    .await
    .map_err(|_| VpnError::Timeout("TCP/proxy/TLS connect"))?
}

fn rustls_error(error: std::io::Error) -> VpnError {
    let reason = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    if matches!(
        reason,
        Some(rustls::Error::AlertReceived(
            rustls::AlertDescription::HandshakeFailure
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

fn proxy_credentials(proxy: &url::Url) -> Result<(String, String)> {
    let decode = |s: &str| {
        percent_encoding::percent_decode_str(s)
            .decode_utf8()
            .map(|s| s.into_owned())
            .map_err(|_| VpnError::Config("proxy credentials must be UTF-8".into()))
    };
    Ok((
        decode(proxy.username())?,
        decode(proxy.password().unwrap_or(""))?,
    ))
}

async fn http_proxy(tcp: &mut TcpStream, proxy: &url::Url, host: &str, port: u16) -> Result<()> {
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if !proxy.username().is_empty() {
        let (user, password) = proxy_credentials(proxy)?;
        request.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            STANDARD.encode(format!("{user}:{password}"))
        ));
    }
    request.push_str("\r\n");
    tcp.write_all(request.as_bytes()).await?;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        if headers.len() >= 65536 {
            return Err(VpnError::Proxy("oversized CONNECT response".into()));
        }
        headers.push(tcp.read_u8().await?);
    }
    let mut storage = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut storage);
    response
        .parse(&headers)
        .map_err(|_| VpnError::Proxy("invalid CONNECT response".into()))?;
    if response.code != Some(200) {
        return Err(VpnError::Proxy(format!(
            "CONNECT status {}",
            response.code.unwrap_or(0)
        )));
    }
    Ok(())
}

async fn socks_proxy(tcp: &mut TcpStream, proxy: &url::Url, host: &str, port: u16) -> Result<()> {
    let auth = !proxy.username().is_empty();
    tcp.write_all(if auth { &[5, 1, 2] } else { &[5, 1, 0] })
        .await?;
    let mut reply = [0; 2];
    tcp.read_exact(&mut reply).await?;
    if reply != [5, if auth { 2 } else { 0 }] {
        return Err(VpnError::Proxy(
            "SOCKS5 authentication method rejected".into(),
        ));
    }
    if auth {
        let (user, password) = proxy_credentials(proxy)?;
        if user.len() > 255 || password.len() > 255 {
            return Err(VpnError::Config(
                "SOCKS5 credentials exceed 255 bytes".into(),
            ));
        }
        let mut auth = vec![1, user.len() as u8];
        auth.extend_from_slice(user.as_bytes());
        auth.push(password.len() as u8);
        auth.extend_from_slice(password.as_bytes());
        tcp.write_all(&auth).await?;
        tcp.read_exact(&mut reply).await?;
        if reply != [1, 0] {
            return Err(VpnError::Proxy("SOCKS5 authentication rejected".into()));
        }
    }
    let mut request = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err(VpnError::Config("SOCKS5 hostname too long".into()));
            }
            request.extend_from_slice(&[3, host.len() as u8]);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    tcp.write_all(&request).await?;
    let mut header = [0; 4];
    tcp.read_exact(&mut header).await?;
    if header[0] != 5 || header[1] != 0 {
        return Err(VpnError::Proxy(format!(
            "SOCKS5 connect status {}",
            header[1]
        )));
    }
    let n = match header[3] {
        1 => 4,
        4 => 16,
        3 => tcp.read_u8().await? as usize,
        _ => return Err(VpnError::Proxy("invalid SOCKS5 reply".into())),
    };
    let mut tail = vec![0; n + 2];
    tcp.read_exact(&mut tail).await?;
    Ok(())
}
