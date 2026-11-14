use crate::{
    AuthConfig, ClientConfig, ConnectionState, ExposeSecret, PasswordChallenge, Result,
    SecretString, VpnError,
    client::{Shared, bounded},
    transport::{self, TlsContext, Wire},
};
use cookie_store::CookieStore;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;
use url::Url;

use super::cookie::validate_cookie;
use crate::transport::http::{Response, discard_body, headers};

const LOGIN: &str = "/prx/000/http/localhost/login";
const LOGOUT: &str = "/prx/000/http/localhost/logout";

pub(crate) struct AuthSession {
    jar: CookieStore,
    explicit: Option<SecretString>,
    authenticated: bool,
    password_cache: Option<SecretString>,
}

impl AuthSession {
    pub fn new() -> Self {
        Self {
            jar: CookieStore::default(),
            explicit: None,
            authenticated: false,
            password_cache: None,
        }
    }
    pub fn has_session(&self) -> bool {
        self.authenticated
    }
    pub fn set_cookie(&mut self, cookie: SecretString) -> Result<()> {
        validate_cookie(cookie.expose_secret())?;
        self.explicit = Some(cookie);
        Ok(())
    }
    pub fn cookie_header(&self, url: &Url) -> String {
        let mut values = std::collections::BTreeMap::new();
        for (key, value) in self.jar.get_request_values(url) {
            values.insert(key.to_owned(), value.to_owned());
        }
        if let Some(cookie) = &self.explicit {
            for pair in cookie.expose_secret().split(';') {
                if let Some((key, value)) = pair.trim().split_once('=') {
                    values.insert(key.to_owned(), value.to_owned());
                }
            }
        }
        values
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
    fn update(&mut self, response: &Response, url: &Url) -> Result<()> {
        for (_, value) in response
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        {
            self.jar
                .parse(value, url)
                .map_err(|_| VpnError::Protocol("invalid Set-Cookie".into()))?;
            if let Some(explicit) = &self.explicit {
                let pair = value.split(';').next().unwrap_or("");
                if let Some((name, new_value)) = pair.split_once('=')
                    && name.starts_with("ANsession")
                {
                    let mut pairs = explicit
                        .expose_secret()
                        .split(';')
                        .map(str::trim)
                        .filter(|old| old.split_once('=').is_none_or(|(key, _)| key != name))
                        .map(str::to_owned)
                        .collect::<Vec<_>>();
                    if !new_value.is_empty() {
                        pairs.push(pair.to_owned());
                    }
                    self.explicit = Some(pairs.join("; ").into());
                }
            }
        }
        Ok(())
    }
    pub async fn authenticate(
        &mut self,
        config: &ClientConfig,
        tls: TlsContext,
        shared: &Shared,
        deadline: Option<Instant>,
    ) -> Result<SecretString> {
        if let AuthConfig::Cookie(cookie) = &config.auth {
            self.set_cookie(cookie.clone())?;
            return Ok(cookie.clone());
        }
        self.authenticated = false;
        if matches!(config.auth, AuthConfig::None) {
            return Err(VpnError::Config(
                "credentials are required for authentication; --tls-probe needs no credentials"
                    .into(),
            ));
        }
        self.explicit = None;
        self.jar = CookieStore::default();
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
            _ => unreachable!(),
        };
        // Authenticate the peer before asking the caller for a secret. Keep
        // this exact connection for POST /login; no separate preflight probe.
        let first = bounded(
            shared,
            auth_timeout(config, deadline)?,
            "authentication TLS",
            transport::connect(config, tls.clone()),
        )
        .await?;
        if shared.cancel.is_cancelled() {
            return Err(VpnError::Cancelled);
        }
        let password = match &config.auth {
            AuthConfig::Password { password, .. } => password.clone(),
            AuthConfig::DeferredPassword { provider, .. } => {
                if let Some(password) = &self.password_cache {
                    password.clone()
                } else {
                    shared.set_state(ConnectionState::AwaitingPassword);
                    let password = provider
                        .password(PasswordChallenge {
                            server: config.server.clone(),
                            username: username.clone(),
                            authgroup: authgroup.clone(),
                            tls: first.info.clone(),
                            cancellation: shared.cancel.clone(),
                        })
                        .await?;
                    if shared.cancel.is_cancelled() {
                        return Err(VpnError::Cancelled);
                    }
                    if provider.cache_password() {
                        self.password_cache = Some(password.clone());
                    }
                    shared.set_state(ConnectionState::Authenticating);
                    password
                }
            }
            _ => unreachable!(),
        };
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("method", authgroup)
            .append_pair("uname", username)
            .append_pair("pwd", password.expose_secret())
            .finish();
        let mut url = config.server.join(LOGIN).expect("constant URL");
        let mut method = "POST";
        let mut first = Some(first);
        for _ in 0..10 {
            let mut wire = if let Some(wire) = first.take() {
                wire
            } else {
                bounded(
                    shared,
                    auth_timeout(config, deadline)?,
                    "authentication TLS",
                    transport::connect(config, tls.clone()),
                )
                .await?
            };
            let response = bounded(
                shared,
                auth_timeout(config, deadline)?,
                "authentication HTTP",
                async {
                    send(
                        &mut wire,
                        config,
                        self,
                        &url,
                        method,
                        if method == "POST" { Some(&body) } else { None },
                        "",
                    )
                    .await?;
                    let response = headers(&mut wire).await?;
                    self.update(&response, &url)?;
                    discard_body(&mut wire, &response).await?;
                    Ok(response)
                },
            )
            .await?;
            if (300..400).contains(&response.status) {
                let location = response
                    .header("location")
                    .ok_or_else(|| VpnError::Protocol("redirect without Location".into()))?;
                let next = url
                    .join(location)
                    .map_err(|_| VpnError::Protocol("invalid login redirect".into()))?;
                if next.origin() != config.server.origin()
                    || !next.username().is_empty()
                    || next.password().is_some()
                {
                    return Err(VpnError::Protocol(
                        "cross-origin login redirect refused".into(),
                    ));
                }
                url = next;
                method = "GET";
                continue;
            }
            if !(200..300).contains(&response.status) {
                return Err(if response.status == 401 || response.status == 403 {
                    VpnError::Authentication
                } else {
                    VpnError::Http(response.status)
                });
            }
            // Some gateways scope ANsession to the portal path. OpenConnect
            // forwards it to /vpntunnel explicitly, so do the same.
            let cookie = self
                .jar
                .iter_unexpired()
                .filter(|c| c.name().starts_with("ANsession"))
                .map(|c| format!("{}={}", c.name(), c.value()))
                .collect::<Vec<_>>()
                .join("; ");
            if cookie.is_empty() {
                return Err(VpnError::Authentication);
            }
            let secret = SecretString::from(cookie);
            self.explicit = Some(secret.clone());
            self.authenticated = true;
            tracing::info!("Array authentication succeeded");
            return Ok(secret);
        }
        Err(VpnError::Protocol("too many login redirects".into()))
    }

    pub async fn tunnel(
        &mut self,
        config: &ClientConfig,
        tls: TlsContext,
        client_id: &str,
    ) -> Result<Wire> {
        let url = config.server.join("/vpntunnel").expect("constant URL");
        let extra = format!(
            "appid: SSPVPN\r\nclientid: {client_id}\r\ncpuid: {client_id}\r\nhostname: {}\r\npayload-ip-version: 6\r\nx-devtype: 6\r\n",
            config.hostname
        );
        let mut wire = transport::connect(config, tls).await?;
        send(&mut wire, config, self, &url, "GET", None, &extra).await?;
        let response = headers(&mut wire).await?;
        self.update(&response, &url)?;
        match response.status {
            200 | 201 => {
                self.authenticated = true;
                // The success response switches immediately to binary. Preserve
                // all bytes beyond the HTTP headers; never parse IP bytes as HTTP.
                if response.header("transfer-encoding").is_some() {
                    return Err(VpnError::Protocol(
                        "chunked tunnel upgrade is unsupported".into(),
                    ));
                }
                if response.header("content-length").is_some_and(|v| v != "0") {
                    discard_body(&mut wire, &response).await?;
                }
                Ok(wire)
            }
            301..=308 | 401 | 403 => Err(VpnError::Authentication),
            other => Err(VpnError::Http(other)),
        }
    }
    pub async fn logout(&mut self, config: &ClientConfig, tls: TlsContext) -> Result<()> {
        self.authenticated = false;
        self.password_cache = None;
        let url = config.server.join(LOGOUT).expect("constant URL");
        let mut wire = transport::connect(config, tls).await?;
        send(&mut wire, config, self, &url, "GET", None, "").await?;
        let response = headers(&mut wire).await?;
        if !(200..400).contains(&response.status) {
            return Err(VpnError::Http(response.status));
        }
        tracing::info!("Array logout succeeded");
        Ok(())
    }
}

fn auth_timeout(config: &ClientConfig, deadline: Option<Instant>) -> Result<Duration> {
    let remaining = deadline
        .map(|v| v.saturating_duration_since(Instant::now()))
        .unwrap_or(config.connect_timeout);
    if remaining.is_zero() {
        Err(VpnError::Timeout("reconnect deadline"))
    } else {
        Ok(remaining.min(config.connect_timeout))
    }
}

async fn send(
    wire: &mut Wire,
    config: &ClientConfig,
    auth: &AuthSession,
    url: &Url,
    method: &str,
    body: Option<&str>,
    extra: &str,
) -> Result<()> {
    let path = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().into(),
    };
    let host = config.server.host().expect("validated").to_string();
    let authority = match config.server.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {}\r\nAccept-Encoding: identity\r\n",
        config.user_agent
    );
    let cookie = auth.cookie_header(url);
    if !cookie.is_empty() {
        request.push_str(&format!("Cookie: {cookie}\r\n"));
    }
    request.push_str(extra);
    if let Some(body) = body {
        request.push_str(&format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    request.push_str("\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }
    tracing::debug!(
        method,
        body_bytes = body.map_or(0, str::len),
        cookies = !cookie.is_empty(),
        "sending HTTP request (sensitive fields redacted)"
    );
    wire.stream.write_all(request.as_bytes()).await?;
    Ok(())
}
