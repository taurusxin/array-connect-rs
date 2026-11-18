use super::{
    logging::LogFormat,
    password::{TerminalPassword, stdin_secret},
};
use arraysslvpn::{AuthConfig, ClientConfig, RouteMode, TlsBackend};
use clap::{ArgAction, Parser};
use ipnet::Ipv4Net;
use serde::Deserialize;
use std::{
    io::{self, IsTerminal},
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

/// Array Networks SSL VPN over TLS. Requires administrator/root for system networking.
/// DTLS and full IPv6 network configuration are deferred.
#[derive(Parser, Default, Deserialize)]
#[command(name = "array-connect", version, about)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct Args {
    /// HTTPS gateway URL or hostname.
    pub(super) server: Option<String>,
    #[arg(long)]
    #[serde(skip)]
    pub(super) config: Option<PathBuf>,
    #[arg(short = 'u', long)]
    pub(super) user: Option<String>,
    #[arg(long)]
    pub(super) authgroup: Option<String>,
    /// Read one password line from stdin instead of prompting.
    #[arg(long,action=ArgAction::SetTrue)]
    #[serde(skip)]
    pub(super) passwd_on_stdin: bool,
    /// Explicit session Cookie header (prefer --cookie-file for repeated use).
    #[arg(long,conflicts_with_all=["cookie_file","cookie_on_stdin","passwd_on_stdin","user"])]
    #[serde(skip)]
    pub(super) cookie: Option<String>,
    #[arg(long,conflicts_with_all=["cookie","cookie_on_stdin","passwd_on_stdin","user"])]
    pub(super) cookie_file: Option<PathBuf>,
    #[arg(long,conflicts_with_all=["cookie","cookie_file","passwd_on_stdin","user"])]
    #[serde(skip)]
    pub(super) cookie_on_stdin: bool,
    /// Authenticate and print only the session cookie to stdout; no TUN required.
    #[arg(long)]
    #[serde(skip)]
    pub(super) authenticate: bool,
    /// Verify only TCP/TLS, sending no HTTP requests or credentials.
    #[arg(long, conflicts_with = "authenticate")]
    #[serde(skip)]
    pub(super) tls_probe: bool,
    #[arg(long)]
    pub(super) port: Option<u16>,
    #[arg(long)]
    pub(super) cafile: Option<PathBuf>,
    /// rustls (default), or the optional OpenSSL compatibility backend.
    #[arg(long, value_enum)]
    pub(super) tls_backend: Option<TlsBackend>,
    /// OpenSSL cipher-list syntax; requires --tls-backend openssl.
    #[arg(long)]
    pub(super) openssl_ciphers: Option<String>,
    /// SHA-256 SPKI pin: pin-sha256:BASE64. May be repeated.
    #[arg(long, conflicts_with = "insecure")]
    pub(super) servercert: Vec<String>,
    /// Bypass certificate CA/name validation (handshake signatures still checked).
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    pub(super) insecure: Option<bool>,
    /// http:// or socks5:// proxy, optionally including percent-encoded credentials.
    #[arg(long)]
    pub(super) proxy: Option<String>,
    /// Connect to this IP while keeping the gateway hostname for TLS and HTTP.
    #[arg(long)]
    pub(super) resolve: Option<IpAddr>,
    #[arg(long)]
    pub(super) hostname: Option<String>,
    #[arg(long)]
    pub(super) useragent: Option<String>,
    /// TCP/TLS and each negotiation/write timeout in seconds.
    #[arg(long)]
    pub(super) connect_timeout: Option<u64>,
    /// Total reconnect retry window in seconds; zero disables retries.
    #[arg(long)]
    pub(super) reconnect_timeout: Option<u64>,
    /// DPD interval in seconds; defaults to server value, otherwise 30.
    #[arg(long)]
    pub(super) dpd: Option<u64>,
    #[arg(short = 'i', long)]
    pub(super) interface: Option<String>,
    #[arg(long)]
    pub(super) mtu: Option<u16>,
    #[arg(long, value_enum)]
    pub(super) route_mode: Option<RouteMode>,
    #[arg(long = "route")]
    pub(super) routes: Vec<Ipv4Net>,
    #[arg(long = "exclude-route")]
    pub(super) exclude_routes: Vec<Ipv4Net>,
    /// Leave system DNS unchanged.
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    pub(super) no_dns: Option<bool>,
    #[arg(short='v',action=ArgAction::Count)]
    #[serde(skip)]
    pub(super) verbose: u8,
    #[arg(long)]
    pub(super) log_level: Option<String>,
    #[arg(long, value_enum)]
    pub(super) log_format: Option<LogFormat>,
    /// Append logs to this file instead of stderr.
    #[arg(long)]
    pub(super) log_file: Option<PathBuf>,
}

impl Args {
    fn inherit(&mut self, file: Self) {
        macro_rules! inherit {($($f:ident),*)=>{$(if self.$f.is_none(){self.$f=file.$f;})*};}
        inherit!(
            server,
            user,
            authgroup,
            cookie_file,
            port,
            cafile,
            tls_backend,
            openssl_ciphers,
            insecure,
            proxy,
            resolve,
            hostname,
            useragent,
            connect_timeout,
            reconnect_timeout,
            dpd,
            interface,
            mtu,
            route_mode,
            no_dns,
            log_level,
            log_format,
            log_file
        );
        if self.servercert.is_empty() {
            self.servercert = file.servercert;
        }
        if self.routes.is_empty() {
            self.routes = file.routes;
        }
        if self.exclude_routes.is_empty() {
            self.exclude_routes = file.exclude_routes;
        }
    }
    pub(super) fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let mut args = Self::parse();
        if let Some(path) = &args.config {
            let text = std::fs::read_to_string(path)?;
            // Do not include TOML source snippets in diagnostics; proxy URLs may
            // contain credentials.
            let file = toml::from_str(&text)
                .map_err(|_| "invalid TOML config (see config.example.toml for supported keys)")?;
            args.inherit(file);
        }
        Ok(args)
    }
}

pub(super) fn client_config(args: &Args) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let server = args
        .server
        .as_deref()
        .ok_or("gateway URL required (positional argument or server in TOML)")?;
    let cookie_sources = usize::from(args.cookie.is_some())
        + usize::from(args.cookie_file.is_some())
        + usize::from(args.cookie_on_stdin);
    if cookie_sources > 1 || (cookie_sources > 0 && (args.user.is_some() || args.passwd_on_stdin)) {
        return Err(
            "choose either Cookie authentication or username/password authentication".into(),
        );
    }
    let auth = if args.tls_probe {
        AuthConfig::None
    } else if let Some(cookie) = &args.cookie {
        AuthConfig::Cookie(cookie.clone().into())
    } else if let Some(path) = &args.cookie_file {
        let text = std::fs::read_to_string(path)?;
        AuthConfig::Cookie(text.trim_end_matches(['\r', '\n']).to_owned().into())
    } else if args.cookie_on_stdin {
        AuthConfig::Cookie(stdin_secret()?)
    } else {
        let user = args
            .user
            .clone()
            .ok_or("--user is required for password login")?;
        let authgroup = args.authgroup.clone().unwrap_or_default();
        if args.passwd_on_stdin {
            AuthConfig::Password {
                username: user,
                password: stdin_secret()?,
                authgroup,
            }
        } else {
            if !io::stdin().is_terminal() {
                return Err("use --passwd-on-stdin for non-interactive password input".into());
            }
            AuthConfig::DeferredPassword {
                username: user,
                authgroup,
                provider: Arc::new(TerminalPassword),
            }
        }
    };
    let mut config = ClientConfig::new(server, auth)?;
    if let Some(port) = args.port {
        config
            .server
            .set_port(Some(port))
            .map_err(|_| "invalid port")?;
    }
    config.tls.ca_file = args.cafile.clone();
    config.tls.backend = args.tls_backend.unwrap_or_default();
    config.tls.openssl_ciphers = args.openssl_ciphers.clone();
    config.tls.server_pins = args.servercert.clone();
    config.tls.insecure = args.insecure.unwrap_or(false);
    config.proxy = args
        .proxy
        .as_ref()
        .map(|s| url::Url::parse(s).map_err(|_| "invalid proxy URL"))
        .transpose()?;
    config.resolve = args.resolve;
    if let Some(host) = &args.hostname {
        config.hostname = host.clone();
    }
    if let Some(agent) = &args.useragent {
        config.user_agent = agent.clone();
    }
    if let Some(secs) = args.connect_timeout {
        config.connect_timeout = Duration::from_secs(secs);
    }
    if let Some(secs) = args.reconnect_timeout {
        config.reconnect.timeout = Duration::from_secs(secs);
    }
    config.dpd_interval = args.dpd.map(Duration::from_secs);
    config.network.interface_name = args.interface.clone();
    if let Some(mtu) = args.mtu {
        config.network.mtu = mtu;
    }
    if let Some(mode) = args.route_mode {
        config.network.route_mode = mode;
    }
    config.network.include_routes = args.routes.clone();
    config.network.exclude_routes = args.exclude_routes.clone();
    config.network.manage_dns = !args.no_dns.unwrap_or(false);
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_overrides_file_and_supports_explicit_false() {
        let mut cli = Args::try_parse_from([
            "array-connect",
            "vpn.example.com",
            "--insecure=false",
            "--mtu",
            "1300",
        ])
        .unwrap();
        let file: Args =
            toml::from_str("insecure = true\nmtu = 1400\nno-dns = true\nroute-mode = 'none'")
                .unwrap();
        cli.inherit(file);
        assert_eq!(cli.insecure, Some(false));
        assert_eq!(cli.mtu, Some(1300));
        assert_eq!(cli.no_dns, Some(true));
        assert_eq!(cli.route_mode, Some(RouteMode::None));
    }
    #[test]
    fn rejects_secret_in_config() {
        assert!(toml::from_str::<Args>("password = 'secret'").is_err());
        assert!(
            Args::try_parse_from([
                "array-connect",
                "x",
                "--cookie",
                "ANsession=x",
                "--user",
                "u"
            ])
            .is_err()
        );
    }
    #[test]
    fn example_config_is_valid() {
        let file: Args = toml::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/config.example.toml"
        )))
        .unwrap();
        assert_eq!(file.route_mode, Some(RouteMode::Server));
    }
}
