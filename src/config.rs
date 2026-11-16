use crate::{Result, VpnError};
use ipnet::Ipv4Net;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Duration};
use url::Url;

#[derive(Clone)]
pub enum AuthConfig {
    /// No credentials; usable for TLS probes and public OTP parameter discovery.
    None,
    Password {
        username: String,
        password: SecretString,
        authgroup: String,
    },
    Cookie(SecretString),
    /// The provider runs only after a verified TLS connection is established.
    DeferredPassword {
        username: String,
        authgroup: String,
        provider: Arc<dyn crate::PasswordProvider>,
    },
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Cookie(_) => f.debug_tuple("Cookie").field(&"[REDACTED]").finish(),
            Self::Password {
                username,
                authgroup,
                ..
            } => f
                .debug_struct("Password")
                .field("username", username)
                .field("authgroup", authgroup)
                .field("password", &"[REDACTED]")
                .finish(),
            Self::DeferredPassword {
                username,
                authgroup,
                ..
            } => f
                .debug_struct("DeferredPassword")
                .field("username", username)
                .field("authgroup", authgroup)
                .field("provider", &"[callback]")
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum TlsBackend {
    #[default]
    Rustls,
    #[cfg_attr(feature = "cli", value(name = "openssl"))]
    OpenSsl,
}
impl std::fmt::Display for TlsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rustls => "rustls",
            Self::OpenSsl => "openssl",
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct TlsConfig {
    /// OpenSSL is optional and must be enabled at build time.
    pub backend: TlsBackend,
    /// OpenSSL cipher-list syntax; only applies to the explicit OpenSSL backend.
    pub openssl_ciphers: Option<String>,
    /// Additional PEM roots, in addition to the platform trust store.
    pub ca_file: Option<PathBuf>,
    /// OpenConnect-compatible SHA-256 SubjectPublicKeyInfo pins, base64 encoded.
    /// A matching pin is an explicit alternative to CA/name validation.
    pub server_pins: Vec<String>,
    /// Explicitly bypass CA/name checks; TLS handshake signatures are still checked.
    pub insecure: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    #[default]
    Server,
    Full,
    None,
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub interface_name: Option<String>,
    pub mtu: u16,
    pub route_mode: RouteMode,
    pub include_routes: Vec<Ipv4Net>,
    pub exclude_routes: Vec<Ipv4Net>,
    pub manage_dns: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            interface_name: None,
            mtu: 1400,
            route_mode: RouteMode::Server,
            include_routes: vec![],
            exclude_routes: vec![],
            manage_dns: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReconnectConfig {
    /// Zero disables reconnecting.
    pub timeout: Duration,
    pub initial_delay: Duration,
    pub max_delay: Duration,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300),
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
        }
    }
}

#[derive(Clone)]
pub struct ClientConfig {
    pub server: Url,
    pub auth: AuthConfig,
    pub tls: TlsConfig,
    /// http:// or socks5:// URL; optional percent-encoded username/password.
    /// Omitted from Debug output because URLs can contain credentials.
    pub proxy: Option<Url>,
    /// Connect to this address, keeping the original server hostname for SNI/Host.
    pub resolve: Option<IpAddr>,
    pub hostname: String,
    pub user_agent: String,
    pub connect_timeout: Duration,
    pub dpd_interval: Option<Duration>,
    pub reconnect: ReconnectConfig,
    pub network: NetworkConfig,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("server_host", &self.server.host_str())
            .field("auth", &self.auth)
            .field("tls", &self.tls)
            .field("proxy_enabled", &self.proxy.is_some())
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl ClientConfig {
    pub fn new(server: &str, auth: AuthConfig) -> Result<Self> {
        let server = Url::parse(&if server.contains("://") {
            server.to_owned()
        } else {
            format!("https://{server}")
        })
        .map_err(|_| VpnError::Config("invalid server URL".into()))?;
        let config = Self {
            server,
            auth,
            tls: TlsConfig::default(),
            proxy: None,
            resolve: None,
            hostname: std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "arraysslvpn".into()),
            user_agent: format!("arraysslvpn/{}", env!("CARGO_PKG_VERSION")),
            connect_timeout: Duration::from_secs(30),
            dpd_interval: None,
            reconnect: ReconnectConfig::default(),
            network: NetworkConfig::default(),
        };
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.server.scheme() != "https"
            || self.server.host_str().is_none()
            || !self.server.username().is_empty()
            || self.server.password().is_some()
            || self.server.query().is_some()
            || self.server.fragment().is_some()
        {
            return Err(VpnError::Config(
                "server must be an HTTPS URL without credentials/query/fragment".into(),
            ));
        }
        for value in [&self.hostname, &self.user_agent] {
            if value.chars().any(|c| c.is_control()) {
                return Err(VpnError::Config(
                    "control characters in HTTP headers".into(),
                ));
            }
        }
        if self.connect_timeout.is_zero() || self.network.mtu < 576 {
            return Err(VpnError::Config(
                "timeout must be positive and IPv4 MTU must be >= 576".into(),
            ));
        }
        if self.network.interface_name.as_ref().is_some_and(|name| {
            name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                || name.starts_with('-')
        }) {
            return Err(VpnError::Config(
                "interface name must contain only letters, digits, underscore, dot, or hyphen"
                    .into(),
            ));
        }
        if self.dpd_interval.is_some_and(|v| v.is_zero())
            || self.reconnect.initial_delay.is_zero()
            || self.reconnect.max_delay < self.reconnect.initial_delay
        {
            return Err(VpnError::Config("invalid DPD/reconnect interval".into()));
        }
        if self.connect_timeout > Duration::from_secs(86400)
            || self.reconnect.timeout > Duration::from_secs(7 * 86400)
            || self.reconnect.max_delay > Duration::from_secs(86400)
            || self
                .dpd_interval
                .is_some_and(|v| v > Duration::from_secs(86400))
        {
            return Err(VpnError::Config(
                "timeouts exceed supported bounds (connect/DPD/delay: 1 day; reconnect: 7 days)"
                    .into(),
            ));
        }
        if self.server.port() == Some(0) {
            return Err(VpnError::Config("server port must be nonzero".into()));
        }
        if let Some(proxy) = &self.proxy
            && (!matches!(proxy.scheme(), "http" | "socks5")
                || proxy.host_str().is_none()
                || proxy.query().is_some()
                || proxy.fragment().is_some()
                || !matches!(proxy.path(), "" | "/")
                || proxy.port() == Some(0))
        {
            return Err(VpnError::Config(
                "proxy must be http:// or socks5://".into(),
            ));
        }
        Ok(())
    }
}
