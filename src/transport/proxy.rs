use crate::{Result, VpnError};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::net::IpAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

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

pub(super) async fn http_proxy(
    tcp: &mut TcpStream,
    proxy: &url::Url,
    host: &str,
    port: u16,
) -> Result<()> {
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

pub(super) async fn socks_proxy(
    tcp: &mut TcpStream,
    proxy: &url::Url,
    host: &str,
    port: u16,
) -> Result<()> {
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
