use arraysslvpn::{
    AuthConfig, ClientConfig, ExposeSecret, RouteMode, SecretString, TlsBackend, VpnClient,
};
use clap::{ArgAction, Parser, ValueEnum};
use ipnet::Ipv4Net;
use serde::Deserialize;
use std::{
    io::{self, IsTerminal, Read, Write},
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing_subscriber::{EnvFilter, fmt::MakeWriter};
mod cli_password;

#[derive(Clone, Copy, Debug, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum LogFormat {
    Text,
    Json,
}

/// Array Networks SSL VPN over TLS. Requires administrator/root for system networking.
/// DTLS and full IPv6 network configuration are deferred.
#[derive(Parser, Default, Deserialize)]
#[command(version, about)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
struct Args {
    /// HTTPS gateway URL or hostname.
    server: Option<String>,
    #[arg(long)]
    #[serde(skip)]
    config: Option<PathBuf>,
    #[arg(short = 'u', long)]
    user: Option<String>,
    #[arg(long)]
    authgroup: Option<String>,
    /// Read one password line from stdin instead of prompting.
    #[arg(long,action=ArgAction::SetTrue)]
    #[serde(skip)]
    passwd_on_stdin: bool,
    /// Explicit session Cookie header (prefer --cookie-file for repeated use).
    #[arg(long,conflicts_with_all=["cookie_file","cookie_on_stdin","passwd_on_stdin","user"])]
    #[serde(skip)]
    cookie: Option<String>,
    #[arg(long,conflicts_with_all=["cookie","cookie_on_stdin","passwd_on_stdin","user"])]
    cookie_file: Option<PathBuf>,
    #[arg(long,conflicts_with_all=["cookie","cookie_file","passwd_on_stdin","user"])]
    #[serde(skip)]
    cookie_on_stdin: bool,
    /// Authenticate and print only the session cookie to stdout; no TUN required.
    #[arg(long)]
    #[serde(skip)]
    authenticate: bool,
    /// Verify only TCP/TLS, sending no HTTP requests or credentials.
    #[arg(long, conflicts_with = "authenticate")]
    #[serde(skip)]
    tls_probe: bool,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    cafile: Option<PathBuf>,
    /// rustls (default), or the optional OpenSSL compatibility backend.
    #[arg(long, value_enum)]
    tls_backend: Option<TlsBackend>,
    /// OpenSSL cipher-list syntax; requires --tls-backend openssl.
    #[arg(long)]
    openssl_ciphers: Option<String>,
    /// SHA-256 SPKI pin: pin-sha256:BASE64. May be repeated.
    #[arg(long, conflicts_with = "insecure")]
    servercert: Vec<String>,
    /// Bypass certificate CA/name validation (handshake signatures still checked).
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    insecure: Option<bool>,
    /// http:// or socks5:// proxy, optionally including percent-encoded credentials.
    #[arg(long)]
    proxy: Option<String>,
    /// Connect to this IP while keeping the gateway hostname for TLS and HTTP.
    #[arg(long)]
    resolve: Option<IpAddr>,
    #[arg(long)]
    hostname: Option<String>,
    #[arg(long)]
    useragent: Option<String>,
    /// TCP/TLS and each negotiation/write timeout in seconds.
    #[arg(long)]
    connect_timeout: Option<u64>,
    /// Total reconnect retry window in seconds; zero disables retries.
    #[arg(long)]
    reconnect_timeout: Option<u64>,
    /// DPD interval in seconds; defaults to server value, otherwise 30.
    #[arg(long)]
    dpd: Option<u64>,
    #[arg(short = 'i', long)]
    interface: Option<String>,
    #[arg(long)]
    mtu: Option<u16>,
    #[arg(long, value_enum)]
    route_mode: Option<RouteMode>,
    #[arg(long = "route")]
    routes: Vec<Ipv4Net>,
    #[arg(long = "exclude-route")]
    exclude_routes: Vec<Ipv4Net>,
    /// Leave system DNS unchanged.
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    no_dns: Option<bool>,
    #[arg(short='v',action=ArgAction::Count)]
    #[serde(skip)]
    verbose: u8,
    #[arg(long)]
    log_level: Option<String>,
    #[arg(long, value_enum)]
    log_format: Option<LogFormat>,
    /// Append logs to this file instead of stderr.
    #[arg(long)]
    log_file: Option<PathBuf>,
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
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
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

#[derive(Clone)]
struct LogWriter(Arc<Mutex<Box<dyn Write + Send>>>);
struct LogGuard<'a>(std::sync::MutexGuard<'a, Box<dyn Write + Send>>);
impl Write for LogGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl<'a> MakeWriter<'a> for LogWriter {
    type Writer = LogGuard<'a>;
    fn make_writer(&'a self) -> Self::Writer {
        LogGuard(self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
}
fn init_logging(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let level = args.log_level.clone().unwrap_or_else(|| {
        match args.verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }
        .into()
    });
    let filter = EnvFilter::try_new(level).map_err(|_| "invalid --log-level filter")?;
    let file = args.log_file.is_some();
    let writer: Box<dyn Write + Send> = if let Some(path) = &args.log_file {
        Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?,
        )
    } else {
        Box::new(io::stderr())
    };
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(!file && io::stderr().is_terminal())
        .with_writer(LogWriter(Arc::new(Mutex::new(writer))));
    match args.log_format.unwrap_or(LogFormat::Text) {
        LogFormat::Json => builder
            .json()
            .try_init()
            .map_err(|_| "cannot initialize logging")?,
        LogFormat::Text => builder
            .try_init()
            .map_err(|_| "cannot initialize logging")?,
    }
    Ok(())
}

fn stdin_secret() -> io::Result<SecretString> {
    // Avoid unbounded read_line allocation on redirected input.
    use io::BufRead;
    let mut bytes = Vec::new();
    let n = io::stdin()
        .lock()
        .take(16386)
        .read_until(b'\n', &mut bytes)?;
    if n == 0 || n > 16384 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stdin secret is empty or too long",
        ));
    }
    while bytes.last().is_some_and(|b| *b == b'\r' || *b == b'\n') {
        bytes.pop();
    }
    let value = String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "stdin secret must be UTF-8"))?;
    Ok(SecretString::from(value))
}

fn config(args: &Args) -> Result<ClientConfig, Box<dyn std::error::Error>> {
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
                provider: Arc::new(cli_password::TerminalPassword),
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

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("arraysslvpn: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::load()?;
    init_logging(&args)?;
    let config = config(&args)?;
    if config.tls.insecure {
        tracing::warn!("certificate CA/name verification explicitly disabled");
    }
    let client = VpnClient::new(config)?;
    let handle = client.handle();
    let signals = tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! {result=tokio::signal::ctrl_c()=>result?,_=term.recv()=>{}}
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await?;
        }
        handle.disconnect();
        Ok::<_, io::Error>(())
    });
    let result = if args.tls_probe {
        client.probe_tls().await.map(|info| {
            println!(
                "{}",
                serde_json::to_string(&info).expect("serializable TLS metadata")
            )
        })
    } else if args.authenticate {
        client
            .authenticate()
            .await
            .map(|cookie| println!("{}", cookie.expose_secret()))
    } else {
        match client.connect().await {
            Ok(session) => session.run().await,
            Err(error) => Err(error),
        }
    };
    signals.abort();
    match result {
        Err(arraysslvpn::VpnError::Cancelled) => Ok(()),
        other => other.map_err(Into::into),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_overrides_file_and_supports_explicit_false() {
        let mut cli = Args::try_parse_from([
            "arraysslvpn",
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
            Args::try_parse_from(["arraysslvpn", "x", "--cookie", "ANsession=x", "--user", "u"])
                .is_err()
        );
    }
    #[test]
    fn example_config_is_valid() {
        let file: Args = toml::from_str(include_str!("../config.example.toml")).unwrap();
        assert_eq!(file.route_mode, Some(RouteMode::Server));
    }
}
