//! Array MotionPro OTP self-service endpoints. No tunnel or host network changes.
use super::session::{AuthSession, send};
use crate::{
    AuthConfig, ClientConfig, ExposeSecret, PasswordChallenge, Result, SecretString, VpnError,
    client::{Shared, bounded},
    transport::{
        self, TlsContext, Wire,
        http::{self, Response},
    },
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use zeroize::Zeroizing;

const PREFIX: &str = "/prx/000/http/localhost/";
const USER_AGENT: &str = "MotionProOTP/108";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OtpParameters {
    pub period: u64,
    /// None means clock synchronization failed; use local time and tell the user.
    pub time_offset_seconds: Option<i64>,
}
#[derive(Clone, Debug)]
pub struct OtpEnrollment {
    pub parameters: OtpParameters,
}

struct Portal<'a> {
    config: ClientConfig,
    tls: TlsContext,
    shared: &'a Shared,
    cookies: AuthSession,
}
impl<'a> Portal<'a> {
    fn new(config: &ClientConfig, tls: TlsContext, shared: &'a Shared) -> Self {
        let mut config = config.clone();
        config.user_agent = USER_AGENT.into();
        Self {
            config,
            tls,
            shared,
            cookies: AuthSession::new(),
        }
    }
    async fn wire(&self) -> Result<Wire> {
        bounded(
            self.shared,
            self.config.connect_timeout,
            "OTP TLS",
            transport::connect(&self.config, self.tls.clone()),
        )
        .await
    }
    async fn exchange(
        &mut self,
        wire: &mut Wire,
        url: &Url,
        method: &str,
        data: Option<&str>,
        read_body: bool,
    ) -> Result<(Response, Zeroizing<Vec<u8>>)> {
        bounded(
            self.shared,
            self.config.connect_timeout,
            "OTP HTTP",
            async {
                send(wire, &self.config, &self.cookies, url, method, data, "").await?;
                let response = http::headers(wire).await?;
                self.cookies.update(&response, url)?;
                let body = if read_body {
                    http::body(wire, &response).await?
                } else {
                    Vec::new()
                };
                Ok((response, Zeroizing::new(body)))
            },
        )
        .await
    }
    fn redirect(&self, url: &Url, response: &Response) -> Result<Url> {
        let next = url
            .join(
                response
                    .header("location")
                    .ok_or_else(|| VpnError::Protocol("OTP redirect without Location".into()))?,
            )
            .map_err(|_| VpnError::Protocol("invalid OTP redirect".into()))?;
        if next.origin() != self.config.server.origin()
            || !next.username().is_empty()
            || next.password().is_some()
        {
            return Err(VpnError::Protocol(
                "cross-origin OTP redirect refused".into(),
            ));
        }
        Ok(next)
    }
    async fn get(&mut self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
        let url = self
            .config
            .server
            .join(&format!("{PREFIX}{path}"))
            .expect("constant portal path");
        self.get_url(url).await
    }
    async fn get_url(&mut self, mut url: Url) -> Result<Zeroizing<Vec<u8>>> {
        for _ in 0..5 {
            let mut wire = self.wire().await?;
            // Read redirect bodies only after deciding whether to follow them.
            let (response, _) = self.exchange(&mut wire, &url, "GET", None, false).await?;
            if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                url = self.redirect(&url, &response)?;
                continue;
            }
            if response.status != 200 {
                return Err(http_error(response.status));
            }
            return bounded(
                self.shared,
                self.config.connect_timeout,
                "OTP page body",
                async { Ok(Zeroizing::new(http::body(&mut wire, &response).await?)) },
            )
            .await;
        }
        Err(VpnError::Protocol("too many OTP redirects".into()))
    }
    async fn interval(&mut self) -> Result<u64> {
        tracing::info!("reading Array OTP interval");
        let body = self.get("an_login.js").await?;
        parse_interval(&String::from_utf8_lossy(&body))
    }
    async fn clock_offset(&mut self) -> Result<i64> {
        let start = unix_millis()?;
        let body = self.get("system-time").await?;
        let end = unix_millis()?;
        let server = parse_system_time(&String::from_utf8_lossy(&body))?;
        let midpoint = start + (end - start) / 2;
        i64::try_from((i128::from(server) * 1000 - midpoint) / 1000)
            .map_err(|_| VpnError::Protocol("OTP server clock offset overflow".into()))
    }
    async fn parameters(&mut self, period: u64) -> OtpParameters {
        let offset = match self.clock_offset().await {
            Ok(offset) => Some(offset),
            Err(error) => {
                tracing::warn!(%error, "OTP clock synchronization failed; using local time");
                None
            }
        };
        OtpParameters {
            period,
            time_offset_seconds: offset,
        }
    }
}

pub(crate) async fn parameters(
    config: &ClientConfig,
    tls: TlsContext,
    shared: &Shared,
) -> Result<OtpParameters> {
    let mut portal = Portal::new(config, tls, shared);
    let period = portal.interval().await?;
    if shared.cancel.is_cancelled() {
        return Err(VpnError::Cancelled);
    }
    let parameters = portal.parameters(period).await;
    if shared.cancel.is_cancelled() {
        return Err(VpnError::Cancelled);
    }
    Ok(parameters)
}

pub(crate) async fn enroll(
    config: &ClientConfig,
    tls: TlsContext,
    shared: &Shared,
    secret: SecretString,
) -> Result<OtpEnrollment> {
    if secret.expose_secret().len() != 16
        || !secret
            .expose_secret()
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
    {
        return Err(VpnError::Config(
            "Array OTP enrollment requires a 16-character uppercase BASE32 seed (80 bits)".into(),
        ));
    }
    let (username, authgroup) = match &config.auth {
        AuthConfig::Password {
            username,
            authgroup,
            ..
        }
        | AuthConfig::DeferredPassword {
            username,
            authgroup,
            ..
        } => (username, authgroup),
        _ => {
            return Err(VpnError::Config(
                "OTP enrollment requires a username and static password".into(),
            ));
        }
    };
    let mut portal = Portal::new(config, tls, shared);
    let period = portal.interval().await?;
    tracing::info!("checking Array OTP self-service availability");
    let page = portal.get("register").await?;
    if !page.windows(7).any(|bytes| bytes == b"otp_reg") {
        return Err(VpnError::Protocol(
            "Array gateway does not advertise OTP enrollment".into(),
        ));
    }
    let mut wire = portal.wire().await?;
    let password = match &config.auth {
        AuthConfig::Password { password, .. } => password.clone(),
        AuthConfig::DeferredPassword { provider, .. } => {
            provider
                .password(PasswordChallenge {
                    server: config.server.clone(),
                    username: username.clone(),
                    authgroup: authgroup.clone(),
                    tls: wire.info.clone(),
                    cancellation: shared.cancel.clone(),
                })
                .await?
        }
        _ => unreachable!(),
    };
    if shared.cancel.is_cancelled() {
        return Err(VpnError::Cancelled);
    }
    let data = Zeroizing::new(
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("method", "otp_reg")
            .append_pair("uname", username)
            .append_pair("pwd", password.expose_secret())
            .append_pair("sm", secret.expose_secret())
            .finish(),
    );
    let url = config
        .server
        .join(&format!("{PREFIX}register"))
        .expect("constant portal path");
    tracing::warn!("submitting Array OTP enrollment; this replaces any existing gateway seed");
    let confirmed = async {
        let (response, _) = portal
            .exchange(&mut wire, &url, "POST", Some(&data), false)
            .await?;
        if response.status != 302 {
            return Err(http_error(response.status));
        }
        let next = portal.redirect(&url, &response)?;
        if next.path() != format!("{PREFIX}login") {
            return Err(VpnError::Protocol(
                "unexpected Array OTP enrollment redirect".into(),
            ));
        }
        drop(wire);
        let login = portal.get_url(next).await?;
        if login_error(&String::from_utf8_lossy(&login))? {
            return Err(VpnError::Authentication);
        }
        Ok(())
    }
    .await;
    if let Err(error) = confirmed {
        return Err(VpnError::OtpEnrollmentUncertain(Box::new(error)));
    }
    // Registration is already committed remotely. A clock endpoint failure must
    // not erase the newly enrolled local seed or turn success into an unsafe retry.
    let parameters = portal.parameters(period).await;
    tracing::info!(
        period,
        clock_synchronized = parameters.time_offset_seconds.is_some(),
        "Array OTP enrollment confirmed"
    );
    Ok(OtpEnrollment { parameters })
}

fn http_error(status: u16) -> VpnError {
    if matches!(status, 401 | 403) {
        VpnError::Authentication
    } else if (200..300).contains(&status) {
        VpnError::Protocol("unexpected Array OTP enrollment response".into())
    } else {
        VpnError::Http(status)
    }
}
fn unix_millis() -> Result<i128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as i128)
        .map_err(|_| VpnError::Config("system clock predates Unix epoch".into()))
}
fn assignment<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    for (offset, _) in body.match_indices(name) {
        if offset > 0
            && (body.as_bytes()[offset - 1].is_ascii_alphanumeric()
                || body.as_bytes()[offset - 1] == b'_')
        {
            continue;
        }
        let tail = body[offset + name.len()..].trim_start();
        if let Some(value) = tail.strip_prefix('=')
            && !value.starts_with('=')
        {
            return Some(value.trim_start());
        }
    }
    None
}
fn quoted(value: &str) -> Option<&str> {
    let quote = value.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    let mut escaped = false;
    for (offset, ch) in value[1..].char_indices() {
        if ch == quote && !escaped {
            return Some(&value[1..1 + offset]);
        }
        escaped = ch == '\\' && !escaped;
    }
    None
}
fn parse_interval(body: &str) -> Result<u64> {
    let value = assignment(body, "_AN_dyncode_interval").ok_or_else(|| {
        VpnError::Protocol("Array gateway did not provide an OTP interval".into())
    })?;
    let text =
        quoted(value).unwrap_or_else(|| value.split([';', '\r', '\n']).next().unwrap_or("").trim());
    text.parse::<u64>()
        .ok()
        .filter(|period| (1..=300).contains(period))
        .ok_or_else(|| VpnError::Protocol("Array gateway returned an invalid OTP interval".into()))
}
fn login_error(body: &str) -> Result<bool> {
    match assignment(body, "_AN_str_errormsg_login") {
        None => Ok(false),
        Some(value) => quoted(value)
            .map(|message| !message.is_empty())
            .ok_or_else(|| VpnError::Protocol("malformed Array OTP login result".into())),
    }
}
fn parse_system_time(body: &str) -> Result<i64> {
    body.split_once("<time>")
        .and_then(|(_, rest)| rest.split_once("</time>"))
        .and_then(|(value, _)| value.trim().parse::<i64>().ok())
        .filter(|value| (1..=253_402_300_799).contains(value))
        .ok_or_else(|| VpnError::Protocol("Array gateway returned an invalid system time".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_only_bounded_array_parameters_without_executing_javascript() {
        for body in [
            "var _AN_dyncode_interval = 30;",
            "_AN_dyncode_interval='300';",
        ] {
            assert!(parse_interval(body).is_ok());
        }
        for body in [
            "_AN_dyncode_interval=0;",
            "_AN_dyncode_interval=301;",
            "_AN_dyncode_interval=1+30;",
            "_AN_dyncode_interval2=30;",
        ] {
            assert!(parse_interval(body).is_err());
        }
        assert!(!login_error("var _AN_str_errormsg_login = ''; ").unwrap());
        assert!(login_error("var _AN_str_errormsg_login = 'bad password';").unwrap());
        assert_eq!(
            parse_system_time("<time> 1700000000 </time>").unwrap(),
            1_700_000_000
        );
        assert!(parse_system_time("<time>-1</time>").is_err());
    }
}
