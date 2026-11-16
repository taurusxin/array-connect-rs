use arraysslvpn::{
    ClientConfig, NetworkSettings, OtpParameters, RouteMode, SessionStats, TlsBackend,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OtpMode {
    #[default]
    Manual,
    Automatic,
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
    #[serde(default)]
    pub otp_mode: OtpMode,
    #[serde(default)]
    pub otp_secret_stored: bool,
    #[serde(default)]
    pub otp_parameters: Option<OtpParameters>,
    #[serde(default)]
    pub otp_pending: bool,
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
    pub fn normalize_server(&mut self) -> Result<(), String> {
        self.server = ClientConfig::new(self.server.trim(), arraysslvpn::AuthConfig::None)
            .map_err(|error| error.to_string())?
            .server
            .to_string();
        Ok(())
    }

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
        if self.insecure && !self.server_pins.is_empty() {
            return Err("跳过证书校验与公钥固定不能同时启用".into());
        }
        if self
            .otp_parameters
            .as_ref()
            .is_some_and(|parameters| !(1..=300).contains(&parameters.period))
        {
            return Err("网关 OTP 参数无效，请重新导入密钥或注册".into());
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
    pub otp_secret: Option<String>,
    pub proxy_password: Option<String>,
}
impl Drop for SecretUpdates {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.otp_secret.zeroize();
        self.proxy_password.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OtpEnrollmentInput {
    pub id: String,
    pub password: String,
    pub confirm_overwrite: bool,
}
impl Drop for OtpEnrollmentInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtpQrCode {
    pub svg: String,
}
impl Drop for OtpQrCode {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.svg.zeroize();
    }
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CloseBehavior {
    #[default]
    Ask,
    Tray,
    Exit,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CloseChoice {
    Tray,
    Exit,
}
impl From<CloseChoice> for CloseBehavior {
    fn from(choice: CloseChoice) -> Self {
        match choice {
            CloseChoice::Tray => Self::Tray,
            CloseChoice::Exit => Self::Exit,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", from = "StoredPreferences")]
pub struct Preferences {
    pub theme: String,
    pub log_level: String,
    pub close_behavior: CloseBehavior,
}
// Accept the earlier two-switch format, but start with the corrected close dialog.
// A legacy confirmExit=false must never suppress the connected-exit warning.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredPreferences {
    theme: String,
    log_level: String,
    #[serde(default)]
    close_behavior: CloseBehavior,
    #[serde(default, rename = "closeToTray")]
    _legacy_close_to_tray: Option<bool>,
    #[serde(default, rename = "confirmExit")]
    _legacy_confirm_exit: Option<bool>,
}
impl From<StoredPreferences> for Preferences {
    fn from(value: StoredPreferences) -> Self {
        Self {
            theme: value.theme,
            log_level: value.log_level,
            close_behavior: value.close_behavior,
        }
    }
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: "system".into(),
            log_level: "info".into(),
            close_behavior: CloseBehavior::Ask,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn existing_preferences_gain_safe_close_defaults() {
        let preferences: Preferences =
            serde_json::from_str(r#"{"theme":"dark","logLevel":"debug"}"#).unwrap();
        assert_eq!(preferences.close_behavior, CloseBehavior::Ask);
        assert_eq!(preferences.theme, "dark");
    }
    #[test]
    fn old_exit_switch_cannot_disable_the_new_connection_warning() {
        let preferences: Preferences = serde_json::from_str(
            r#"{"theme":"dark","logLevel":"info","closeToTray":true,"confirmExit":false}"#,
        )
        .unwrap();
        assert_eq!(preferences.close_behavior, CloseBehavior::Ask);
        let stored = serde_json::to_value(&preferences).unwrap();
        assert!(stored.get("confirmExit").is_none());
        assert!(stored.get("closeToTray").is_none());
    }
    #[test]
    fn remembered_close_choice_survives_a_preferences_round_trip() {
        for close_behavior in [CloseBehavior::Ask, CloseBehavior::Tray, CloseBehavior::Exit] {
            let preferences = Preferences {
                close_behavior,
                ..Default::default()
            };
            let stored = serde_json::to_string(&preferences).unwrap();
            let restored: Preferences = serde_json::from_str(&stored).unwrap();
            assert_eq!(restored.close_behavior, close_behavior);
        }
    }
    #[test]
    fn gateway_shorthand_normalizes_to_https_and_defaults_to_443() {
        for (input, host, port) in [
            ("vpn.example.test", "vpn.example.test", 443),
            (" 192.0.2.1 ", "192.0.2.1", 443),
            ("192.0.2.1:8443", "192.0.2.1", 8443),
            ("https://vpn.example.test:9443", "vpn.example.test", 9443),
        ] {
            let mut profile: Profile =
                serde_json::from_str(include_str!("../../fixtures/profile.json")).unwrap();
            profile.server = input.into();
            profile.normalize_server().unwrap();
            let url = url::Url::parse(&profile.server).unwrap();
            assert_eq!(url.scheme(), "https");
            assert_eq!(url.host_str(), Some(host));
            assert_eq!(url.port_or_known_default(), Some(port));
        }
    }
}
