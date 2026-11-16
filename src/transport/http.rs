//! Buffered HTTP response framing used before the tunnel upgrade.
use super::Wire;
use crate::{Result, VpnError};
use bytes::Buf;

const MAX_HEADERS: usize = 64 * 1024;
const MAX_BODY: usize = 1024 * 1024;

pub(crate) struct Response {
    pub status: u16,
    pub(crate) headers: Vec<(String, String)>,
}

impl Response {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub(crate) async fn headers(wire: &mut Wire) -> Result<Response> {
    loop {
        if let Some(end) = wire.buffer.windows(4).position(|v| v == b"\r\n\r\n") {
            if end + 4 > MAX_HEADERS {
                return Err(VpnError::Protocol("HTTP headers too large".into()));
            }
            let mut storage = [httparse::EMPTY_HEADER; 128];
            let mut response = httparse::Response::new(&mut storage);
            response
                .parse(&wire.buffer[..end + 4])
                .map_err(|_| VpnError::Protocol("malformed HTTP response".into()))?;
            let status = response
                .code
                .ok_or_else(|| VpnError::Protocol("missing HTTP status".into()))?;
            let mut headers = Vec::new();
            for h in response.headers {
                let v = std::str::from_utf8(h.value)
                    .map_err(|_| VpnError::Protocol("non-UTF8 HTTP header".into()))?;
                // Never log values here: even Location/unknown headers can echo secrets.
                tracing::trace!(
                    header = h.name,
                    value = "[redacted]",
                    "HTTP response header"
                );
                headers.push((h.name.into(), v.into()));
            }
            wire.buffer.advance(end + 4);
            if (100..200).contains(&status) {
                if status == 101 {
                    return Err(VpnError::Protocol("unexpected HTTP upgrade".into()));
                }
                continue;
            }
            tracing::debug!(status, "HTTP response");
            return Ok(Response { status, headers });
        }
        if wire.buffer.len() >= MAX_HEADERS {
            return Err(VpnError::Protocol("HTTP headers too large".into()));
        }
        wire.read_more().await?;
    }
}

pub(crate) async fn discard_body(wire: &mut Wire, response: &Response) -> Result<()> {
    if let Some(encoding) = response.header("transfer-encoding") {
        if !encoding.eq_ignore_ascii_case("chunked") {
            return Err(VpnError::Protocol(
                "unsupported HTTP transfer encoding".into(),
            ));
        }
        let mut total = 0usize;
        loop {
            let line = read_line(wire).await?;
            let line = std::str::from_utf8(&line)
                .map_err(|_| VpnError::Protocol("invalid HTTP chunk".into()))?;
            let len = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| VpnError::Protocol("invalid HTTP chunk length".into()))?;
            total = total
                .checked_add(len)
                .filter(|n| *n <= MAX_BODY)
                .ok_or_else(|| VpnError::Protocol("HTTP body too large".into()))?;
            if len == 0 {
                let mut trailers = 0;
                loop {
                    let line = read_line(wire).await?;
                    if line.is_empty() {
                        break;
                    }
                    trailers += line.len() + 2;
                    if trailers > MAX_HEADERS {
                        return Err(VpnError::Protocol("HTTP trailers too large".into()));
                    }
                }
                return Ok(());
            }
            while wire.buffer.len() < len + 2 {
                wire.read_more().await?;
            }
            if &wire.buffer[len..len + 2] != b"\r\n" {
                return Err(VpnError::Protocol("invalid chunk terminator".into()));
            }
            wire.buffer.advance(len + 2);
        }
    }
    if let Some(length) = response.header("content-length") {
        let len = length
            .parse::<usize>()
            .ok()
            .filter(|n| *n <= MAX_BODY)
            .ok_or_else(|| VpnError::Protocol("invalid HTTP body length".into()))?;
        while wire.buffer.len() < len {
            wire.read_more().await?;
        }
        wire.buffer.advance(len);
    }
    // Close-delimited bodies need not be read: each authentication request uses
    // its own connection, and bodies are never inspected or logged.
    Ok(())
}

async fn read_line(wire: &mut Wire) -> Result<Vec<u8>> {
    loop {
        if let Some(end) = wire.buffer.windows(2).position(|v| v == b"\r\n") {
            if end > MAX_HEADERS {
                return Err(VpnError::Protocol("HTTP line too long".into()));
            }
            let line = wire.buffer.split_to(end).to_vec();
            wire.buffer.advance(2);
            return Ok(line);
        }
        if wire.buffer.len() > MAX_HEADERS {
            return Err(VpnError::Protocol("HTTP line too long".into()));
        }
        wire.read_more().await?;
    }
}

/// Bounded portal body reader, including close-delimited and chunked pages.
pub(crate) async fn body(wire: &mut Wire, response: &Response) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    if matches!(response.status, 204 | 304) {
        return Ok(Vec::new());
    }
    if let Some(encoding) = response.header("transfer-encoding") {
        if !encoding.eq_ignore_ascii_case("chunked") || response.header("content-length").is_some()
        {
            return Err(VpnError::Protocol("ambiguous portal HTTP framing".into()));
        }
        let mut result = Vec::new();
        loop {
            let line = read_line(wire).await?;
            let line = std::str::from_utf8(&line)
                .map_err(|_| VpnError::Protocol("invalid portal chunk".into()))?;
            let len = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| VpnError::Protocol("invalid portal chunk length".into()))?;
            if result
                .len()
                .checked_add(len)
                .is_none_or(|size| size > MAX_BODY)
            {
                return Err(VpnError::Protocol("portal body too large".into()));
            }
            if len == 0 {
                let mut trailers = 0;
                loop {
                    let line = read_line(wire).await?;
                    if line.is_empty() {
                        return Ok(result);
                    }
                    trailers += line.len() + 2;
                    if trailers > MAX_HEADERS {
                        return Err(VpnError::Protocol("portal trailers too large".into()));
                    }
                }
            }
            while wire.buffer.len() < len + 2 {
                wire.read_more().await?;
            }
            if &wire.buffer[len..len + 2] != b"\r\n" {
                return Err(VpnError::Protocol("invalid portal chunk terminator".into()));
            }
            result.extend_from_slice(&wire.buffer[..len]);
            wire.buffer.advance(len + 2);
        }
    }
    if let Some(length) = response.header("content-length") {
        let len = length
            .parse::<usize>()
            .ok()
            .filter(|len| *len <= MAX_BODY)
            .ok_or_else(|| VpnError::Protocol("invalid portal body length".into()))?;
        while wire.buffer.len() < len {
            wire.read_more().await?;
        }
        return Ok(wire.buffer.split_to(len).to_vec());
    }
    let mut result = wire.buffer.split().to_vec();
    loop {
        if result.len() > MAX_BODY {
            return Err(VpnError::Protocol("portal body too large".into()));
        }
        let mut bytes = [0; 8192];
        let count = wire.stream.read(&mut bytes).await?;
        if count == 0 {
            return Ok(result);
        }
        result.extend_from_slice(&bytes[..count]);
    }
}
