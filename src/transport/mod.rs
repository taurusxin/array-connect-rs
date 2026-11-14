//! Buffered TCP transport, HTTP/SOCKS proxies, and TLS backend selection.
pub(crate) mod http;
mod proxy;
mod tls;

pub use tls::TlsInfo;
pub(crate) use tls::{TlsContext, tls_config};

use crate::{ClientConfig, Result, VpnError};
use bytes::BytesMut;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::TcpStream,
};

pub(crate) trait TlsStreamIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TlsStreamIo for T {}

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
                proxy::http_proxy(&mut tcp, proxy, &target, server_port).await?;
            } else {
                proxy::socks_proxy(&mut tcp, proxy, &target, server_port).await?;
            }
        }
        let (stream, info) = tls::connect(tcp, server_host, tls, &config.tls).await?;
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
