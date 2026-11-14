use arraysslvpn::{ClientConfig, NetworkSettings, RouteMode, SessionStats, TlsBackend};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub server: String,
    pub username: String,
    pub authgroup: String,
    pub save_password: bool,
    #[serde(default)]
    pub password_stored: bool,
    pub two_factor: bool,
    pub auto_totp: bool,
    #[serde(default)]
    pub totp_stored: bool,
    pub totp_algorithm: String,
    pub totp_digits: u32,
    pub totp_period: u64,
    pub proxy_enabled: bool,
    pub proxy_scheme: String,
    pub proxy_host: String,
    pub proxy_port: u16,
    pub proxy_username: String,
    #[serde(default)]
    pub proxy_password_stored: bool,
    pub tls_backend: TlsBackend,
    pub insecure: bool,
    pub ca_file: String,
    pub server_pins: Vec<String>,
    pub openssl_ciphers: String,
    pub resolve: String,
    pub hostname: String,
    pub user_agent: String,
    pub interface_name: String,
    pub mtu: u16,
    pub route_mode: RouteMode,
    pub include_routes: Vec<String>,
    pub exclude_routes: Vec<String>,
    pub manage_dns: bool,
    pub connect_timeout: u64,
    pub reconnect_timeout: u64,
    pub dpd: Option<u64>,
}

impl Profile {
    pub fn validate(&self) -> Result<(), String> {
        uuid::Uuid::parse_str(&self.id).map_err(|_| "配置 ID 无效")?;
        if self.name.trim().is_empty() || self.name.len() > 120 || self.username.trim().is_empty() {
            return Err("请填写配置名称和用户名".into());
        }
        ClientConfig::new(&self.server, arraysslvpn::AuthConfig::None)
            .map_err(|e| e.to_string())?;
        if !(576..=65535).contains(&self.mtu)
            || !(1..=86400).contains(&self.connect_timeout)
            || self.reconnect_timeout > 604800
            || self.dpd.is_some_and(|n| n == 0 || n > 86400)
        {
            return Err("MTU 或超时参数超出有效范围".into());
        }
        if !["SHA1", "SHA256", "SHA512"].contains(&self.totp_algorithm.as_str())
            || ![6, 8].contains(&self.totp_digits)
            || !(15..=120).contains(&self.totp_period)
        {
            return Err("TOTP 参数无效".into());
        }
        if self.insecure && !self.server_pins.is_empty() {
            return Err("跳过证书校验与公钥固定不能同时启用".into());
        }
        if self.tls_backend == TlsBackend::Rustls && !self.openssl_ciphers.is_empty() {
            return Err("自定义密码套件需要选择 OpenSSL 后端".into());
        }
        if self.proxy_enabled
            && (!matches!(self.proxy_scheme.as_str(), "http" | "socks5")
                || self.proxy_host.trim().is_empty()
                || self.proxy_port == 0
                || self.proxy_host.contains(['/', '@', '?', '#']))
        {
            return Err("代理地址或端口无效；地址中不要包含协议或凭据".into());
        }
        if !self.resolve.is_empty() && self.resolve.parse::<std::net::IpAddr>().is_err() {
            return Err("指定解析地址必须为 IP 地址".into());
        }
        for route in self.include_routes.iter().chain(&self.exclude_routes) {
            route
                .parse::<ipnet::Ipv4Net>()
                .map_err(|_| "路由必须为 IPv4 CIDR，如 10.0.0.0/8")?;
        }
        Ok(())
    }
}

/// Input-only values; never serialized, logged, or stored in the profile table.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretUpdates {
    pub password: Option<String>,
    pub totp_secret: Option<String>,
    pub proxy_password: Option<String>,
}
impl Drop for SecretUpdates {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.totp_secret.zeroize();
        self.proxy_password.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preferences {
    pub theme: String,
    pub log_level: String,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: "system".into(),
            log_level: "info".into(),
        }
    }
}
impl Preferences {
    pub fn validate(&self) -> Result<(), String> {
        if !["system", "light", "dark"].contains(&self.theme.as_str())
            || !["error", "warn", "info", "debug", "trace"].contains(&self.log_level.as_str())
        {
            return Err("偏好设置值无效".into());
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LiveSession {
    pub profile_id: Option<String>,
    pub profile_name: Option<String>,
    pub state: String,
    pub connected_seconds: u64,
    pub stats: SessionStats,
    pub download_rate: f64,
    pub upload_rate: f64,
    pub network: Option<NetworkSettings>,
    pub error: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    pub id: String,
    pub profile_id: String,
    pub needs_password: bool,
    pub needs_otp: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialInput {
    pub id: String,
    pub password: String,
    pub otp: String,
}
impl Drop for CredentialInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.otp.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryItem {
    pub id: String,
    pub profile_name: String,
    pub server: String,
    pub started_at: u64,
    pub ended_at: Option<u64>,
    pub connected_seconds: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub state: String,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connected_seconds: u64,
    pub sessions: u64,
    pub recent: Vec<HistoryItem>,
}
