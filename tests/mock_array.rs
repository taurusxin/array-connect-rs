use arraysslvpn::{
    AuthConfig, ClientConfig, ConnectionState, ExposeSecret, NetworkConfig, NetworkManager,
    NetworkSettings, PacketIo, Result, VpnClient, VpnError,
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use rcgen::{CertifiedKey, PublicKeyData, generate_simple_self_signed};
use sha2::{Digest, Sha256};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, mpsc},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

const PASSWORD: &str = "PASSWORD_SENTINEL&+不可泄露";
const COOKIE: &str = "COOKIE_SENTINEL-do-not-log";
const CONF54: [u8; 48] = [
    0x54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 1, 0, 0, 0, 10, 0, 2, 15, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x52, 0x54, 0, 0xde, 0xa2, 0xa6, 0, 0,
];

#[derive(Clone, Copy, Default)]
struct Options {
    reject_login: bool,
    expire_cookie: bool,
    reconnect: bool,
    redirect_cross_origin: bool,
    mute_dpd: bool,
    json_trailers: bool,
    clear_cookies: bool,
    cleared_session_only: bool,
    invalid_cookie_domain: bool,
}
struct Mock {
    address: SocketAddr,
    pin: String,
    pem: String,
    stop: tokio::task::JoinHandle<()>,
    logins: Arc<AtomicUsize>,
    tunnels: Arc<AtomicUsize>,
    logouts: Arc<AtomicUsize>,
    dpds: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.abort();
    }
}
impl Mock {
    async fn start(options: Options) -> Self {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pin = format!(
            "pin-sha256:{}",
            STANDARD.encode(Sha256::digest(signing_key.subject_public_key_info()))
        );
        let pem = cert.pem();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let logins = Arc::new(AtomicUsize::new(0));
        let tunnels = Arc::new(AtomicUsize::new(0));
        let logouts = Arc::new(AtomicUsize::new(0));
        let dpds = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let counts = (
            logins.clone(),
            tunnels.clone(),
            logouts.clone(),
            dpds.clone(),
        );
        let stop = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                accepted.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let counts = counts.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let _ = serve(tls, options, counts).await;
                    }
                });
            }
        });
        Self {
            address,
            pin,
            pem,
            stop,
            logins,
            tunnels,
            logouts,
            dpds,
            connections,
        }
    }
    fn config(&self) -> ClientConfig {
        let mut config = ClientConfig::new(
            &format!("https://localhost:{}", self.address.port()),
            AuthConfig::Password {
                username: "user &+测试".into(),
                password: PASSWORD.into(),
                authgroup: "local & users".into(),
            },
        )
        .unwrap();
        config.resolve = Some(self.address.ip());
        config.tls.server_pins = vec![self.pin.clone()];
        config.connect_timeout = Duration::from_secs(3);
        config.reconnect.timeout = Duration::from_secs(5);
        config.reconnect.initial_delay = Duration::from_millis(10);
        config.reconnect.max_delay = Duration::from_millis(50);
        config.dpd_interval = Some(Duration::from_secs(1));
        config
    }
}

async fn request(tls: &mut TlsStream<TcpStream>) -> io::Result<(String, Vec<u8>)> {
    let mut raw = vec![];
    while !raw.ends_with(b"\r\n\r\n") {
        raw.push(tls.read_u8().await?);
        if raw.len() > 65536 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    let text = String::from_utf8(raw).unwrap();
    let length = text
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .map(|s| s.parse().unwrap())
        .unwrap_or(0);
    let mut body = vec![0; length];
    tls.read_exact(&mut body).await?;
    Ok((text, body))
}
type Counts = (
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
);
async fn serve(
    mut tls: TlsStream<TcpStream>,
    options: Options,
    (logins, tunnels, logouts, dpds): Counts,
) -> io::Result<()> {
    let (headers, body) = request(&mut tls).await?;
    let first = headers.lines().next().unwrap();
    if first.contains("/login ") {
        logins.fetch_add(1, Ordering::SeqCst);
        let form = url::form_urlencoded::parse(&body)
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(form["method"], "local & users");
        assert_eq!(form["uname"], "user &+测试");
        assert_eq!(form["pwd"], PASSWORD);
        if options.reject_login {
            tls.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                .await?;
        } else if options.cleared_session_only {
            tls.write_all(b"HTTP/1.1 200 OK\r\nSet-Cookie: ANsessionold=discarded; Max-Age=0; Path=/; Secure\r\nSet-Cookie: ANsessionempty=; Path=/; Secure\r\nContent-Length: 0\r\n\r\n").await?;
        } else if options.invalid_cookie_domain {
            tls.write_all(format!("HTTP/1.1 200 OK\r\nSet-Cookie: ANsession999={COOKIE}; Domain=private.example.invalid; Path=/; Secure\r\nContent-Length: 0\r\n\r\n").as_bytes()).await?;
        } else if options.redirect_cross_origin {
            tls.write_all(b"HTTP/1.1 302 Found\r\nLocation: https://other.invalid/steal\r\nContent-Length: 0\r\n\r\n").await?;
        } else {
            // Echo a secret in an unrelated header/body to exercise log redaction.
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: /portal\r\n{}Set-Cookie: ANsession999={COOKIE}; Path=/portal; Secure; HttpOnly\r\nX-Echo: {COOKIE}\r\nContent-Length: 0\r\n\r\n",
                if options.clear_cookies {
                    "Set-Cookie: old=; Max-Age=0; Path=/; Secure\r\n"
                } else {
                    ""
                }
            );
            tls.write_all(response.as_bytes()).await?;
        }
    } else if first.contains("/portal ") {
        assert!(headers.contains(COOKIE));
        let body = COOKIE;
        tls.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    } else if first.contains("/logout ") {
        logouts.fetch_add(1, Ordering::SeqCst);
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await?;
    } else if first.contains("/vpntunnel ") {
        assert!(headers.contains(COOKIE));
        assert!(headers.contains("appid: SSPVPN"));
        assert!(headers.contains("payload-ip-version: 6"));
        assert!(headers.contains("clientid: "));
        let id = tunnels.fetch_add(1, Ordering::SeqCst) + 1;
        if options.expire_cookie || (options.reconnect && id == 2) {
            tls.write_all(b"HTTP/1.1 302 Found\r\nLocation: /prx/000/http/localhost/cookietest\r\nContent-Length: 0\r\n\r\n").await?;
            return Ok(());
        }
        tls.write_all(b"HTTP/1.1 201 Created\r\n\r\n").await?;
        let mut conf50 = [0; 16];
        tls.read_exact(&mut conf50).await?;
        assert_eq!(conf50, [0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut response = vec![0; 16];
        response.extend_from_slice(
            br#"{"allow_speed_tunnel":1,"speed_tunnel_encryption":1,"keepalive_interval":1}"#,
        );
        // Small writes intentionally fragment the JSON/config prefix.
        for part in response.chunks(7) {
            tls.write_all(part).await?;
            tokio::task::yield_now().await;
        }
        if options.json_trailers {
            tokio::time::sleep(Duration::from_millis(10)).await;
            tls.write_all(b"\0 \r\n").await?;
        }
        let mut conf54 = [0; 48];
        tls.read_exact(&mut conf54).await?;
        assert_eq!(conf54, CONF54);
        let address = u32::from_le_bytes([10, 0, 0, id as u8 + 1]);
        let config = serde_json::json!({"client_ipv4":address,"client_ipv4_mask":u32::MAX,
            "include_network_resource":{"ipv4":[{"ip":10,"mask":255}]},"exclude_network_resource":{"ipv4":[]},
            "dns_servers":[{"ipv4":[u32::from_le_bytes([10,0,0,53])]}],"search_domains":["internal.example"]});
        let mut response = vec![0; 16];
        response.extend(serde_json::to_vec(&config).unwrap());
        if options.json_trailers {
            tls.write_all(&response).await?;
            tokio::time::sleep(Duration::from_millis(10)).await;
            tls.write_all(b"\0 \r\n").await?;
            tls.write_all(&ip_packet(id as u8)).await?;
        } else {
            response.extend(ip_packet(id as u8));
            tls.write_all(&response).await?;
        }
        loop {
            let mut header = [0; 20];
            tls.read_exact(&mut header).await?;
            let len = u16::from_be_bytes([header[2], header[3]]) as usize;
            let mut packet = header.to_vec();
            let mut tail = vec![0; len - 20];
            tls.read_exact(&mut tail).await?;
            packet.extend(tail);
            if header[9] == 0xff {
                dpds.fetch_add(1, Ordering::SeqCst);
                if options.mute_dpd {
                    continue;
                }
            } else if options.reconnect && id == 1 {
                return Ok(());
            }
            tls.write_all(&packet).await?;
        }
    } else {
        panic!("unexpected request path");
    }
    // Sending close_notify makes close-delimited test bodies deterministic.
    tls.shutdown().await?;
    Ok(())
}

fn ip_packet(marker: u8) -> Vec<u8> {
    let mut packet = vec![0; 24];
    packet[0] = 0x45;
    packet[3] = 24;
    packet[8] = 64;
    packet[9] = 17;
    packet[20] = marker;
    packet
}
struct MemoryIo {
    outgoing: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    incoming: mpsc::Sender<Vec<u8>>,
}
#[async_trait]
impl PacketIo for MemoryIo {
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let packet = self
            .outgoing
            .lock()
            .await
            .recv()
            .await
            .ok_or(io::ErrorKind::BrokenPipe)?;
        buffer[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        self.incoming
            .send(packet.to_vec())
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}
#[derive(Default)]
struct Journal {
    setups: usize,
    cleanups: usize,
    active: bool,
    addresses: Vec<Ipv4Addr>,
}
struct MemoryNetwork {
    io: Arc<MemoryIo>,
    journal: Arc<Mutex<Journal>>,
    fail: bool,
    setup_wait: Option<Arc<Notify>>,
}
#[async_trait]
impl NetworkManager for MemoryNetwork {
    async fn setup(
        &mut self,
        s: &NetworkSettings,
        _: &NetworkConfig,
        _: SocketAddr,
    ) -> Result<Arc<dyn PacketIo>> {
        {
            let mut j = self.journal.lock().unwrap();
            j.setups += 1;
            j.active = true;
            j.addresses.push(s.address);
        }
        if let Some(wait) = &self.setup_wait {
            wait.notified().await;
        }
        if self.fail {
            return Err(VpnError::Network(
                "injected failure after simulated route installation".into(),
            ));
        }
        Ok(self.io.clone())
    }
    async fn cleanup(&mut self) -> Result<()> {
        let mut j = self.journal.lock().unwrap();
        if j.active {
            j.cleanups += 1;
            j.active = false;
        }
        Ok(())
    }
}
type MemoryFixture = (
    MemoryNetwork,
    mpsc::Sender<Vec<u8>>,
    mpsc::Receiver<Vec<u8>>,
    Arc<Mutex<Journal>>,
);
fn memory() -> MemoryFixture {
    let (send, outgoing) = mpsc::channel(16);
    let (incoming, receive) = mpsc::channel(16);
    let journal = Arc::new(Mutex::new(Journal::default()));
    (
        MemoryNetwork {
            io: Arc::new(MemoryIo {
                outgoing: tokio::sync::Mutex::new(outgoing),
                incoming,
            }),
            journal: journal.clone(),
            fail: false,
            setup_wait: None,
        },
        send,
        receive,
        journal,
    )
}

#[tokio::test]
async fn authenticate_cookie_is_redacted_and_cross_origin_is_refused() {
    let mock = Mock::start(Options::default()).await;
    let client = VpnClient::new(mock.config()).unwrap();
    let cookie = client.authenticate().await.unwrap();
    assert!(cookie.expose_secret().contains(COOKIE));
    assert!(!format!("{cookie:?}").contains(COOKIE));
    assert_eq!(mock.logins.load(Ordering::SeqCst), 1);
    assert_eq!(mock.tunnels.load(Ordering::SeqCst), 0);
    let mock = Mock::start(Options {
        redirect_cross_origin: true,
        ..Default::default()
    })
    .await;
    assert!(matches!(
        VpnClient::new(mock.config()).unwrap().authenticate().await,
        Err(VpnError::Protocol(_))
    ));
}

#[tokio::test]
async fn bidirectional_ip_dpd_and_clean_disconnect() {
    let mock = Mock::start(Options::default()).await;
    let client = VpnClient::new(mock.config()).unwrap();
    let handle = client.handle();
    let (network, send, mut receive, journal) = memory();
    let session = client.connect_with(Box::new(network)).await.unwrap();
    assert_eq!(handle.state(), ConnectionState::Connected);
    assert_eq!(session.settings().search_domains, ["internal.example"]);
    let task = tokio::spawn(session.run());
    assert_eq!(
        timeout(Duration::from_secs(3), receive.recv())
            .await
            .unwrap()
            .unwrap(),
        ip_packet(1)
    );
    send.send(ip_packet(42)).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), receive.recv())
            .await
            .unwrap()
            .unwrap(),
        ip_packet(42)
    );
    timeout(Duration::from_secs(4), async {
        while mock.dpds.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    handle.disconnect();
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(handle.state(), ConnectionState::Disconnected);
    assert_eq!(handle.stats().packets_sent, 1);
    assert_eq!(handle.stats().packets_received, 2);
    assert_eq!(mock.logouts.load(Ordering::SeqCst), 1);
    let j = journal.lock().unwrap();
    assert_eq!((j.setups, j.cleanups, j.active), (1, 1, false));
}

#[tokio::test]
async fn nul_terminated_configuration_frames_reach_the_ip_tunnel() {
    for backend in if cfg!(feature = "openssl-tls") {
        vec![
            arraysslvpn::TlsBackend::Rustls,
            arraysslvpn::TlsBackend::OpenSsl,
        ]
    } else {
        vec![arraysslvpn::TlsBackend::Rustls]
    } {
        let mock = Mock::start(Options {
            json_trailers: true,
            ..Default::default()
        })
        .await;
        let mut config = mock.config();
        config.tls.backend = backend;
        let client = VpnClient::new(config).unwrap();
        let controller = client.handle();
        let (network, send, mut receive, journal) = memory();
        let session = client.connect_with(Box::new(network)).await.unwrap();
        let task = tokio::spawn(session.run());
        assert_eq!(
            timeout(Duration::from_secs(3), receive.recv())
                .await
                .unwrap()
                .unwrap(),
            ip_packet(1)
        );
        send.send(ip_packet(42)).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), receive.recv())
                .await
                .unwrap()
                .unwrap(),
            ip_packet(42)
        );
        controller.disconnect();
        task.await.unwrap().unwrap();
        let j = journal.lock().unwrap();
        assert_eq!((j.setups, j.cleanups, j.active), (1, 1, false));
    }
}

#[tokio::test]
async fn reconnect_reauthenticates_and_reapplies_changed_config() {
    let mock = Mock::start(Options {
        reconnect: true,
        ..Default::default()
    })
    .await;
    let client = VpnClient::new(mock.config()).unwrap();
    let handle = client.handle();
    let (network, send, mut receive, journal) = memory();
    let session = client.connect_with(Box::new(network)).await.unwrap();
    let task = tokio::spawn(session.run());
    assert_eq!(receive.recv().await.unwrap(), ip_packet(1));
    send.send(ip_packet(2)).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), receive.recv())
            .await
            .unwrap()
            .unwrap(),
        ip_packet(3)
    );
    send.send(ip_packet(9)).await.unwrap();
    assert_eq!(receive.recv().await.unwrap(), ip_packet(9));
    handle.disconnect();
    task.await.unwrap().unwrap();
    assert_eq!(handle.stats().reconnects, 1);
    assert_eq!(mock.logins.load(Ordering::SeqCst), 2);
    let j = journal.lock().unwrap();
    assert_eq!((j.setups, j.cleanups, j.active), (2, 2, false));
    assert_ne!(j.addresses[0], j.addresses[1]);
}

#[tokio::test]
async fn cookie_expiry_and_auth_failure_are_terminal() {
    let mock = Mock::start(Options {
        expire_cookie: true,
        ..Default::default()
    })
    .await;
    let mut config = mock.config();
    config.auth = AuthConfig::Cookie(format!("ANsession999={COOKIE}").into());
    let (network, _, _, journal) = memory();
    assert!(matches!(
        VpnClient::new(config)
            .unwrap()
            .connect_with(Box::new(network))
            .await,
        Err(VpnError::Authentication)
    ));
    assert_eq!(mock.logins.load(Ordering::SeqCst), 0);
    assert_eq!(journal.lock().unwrap().setups, 0);
    let mock = Mock::start(Options {
        reject_login: true,
        ..Default::default()
    })
    .await;
    assert!(matches!(
        VpnClient::new(mock.config()).unwrap().authenticate().await,
        Err(VpnError::Authentication)
    ));
    assert_eq!(mock.logins.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn setup_failure_rolls_back_once() {
    let mock = Mock::start(Options::default()).await;
    let (mut network, _, _, journal) = memory();
    network.fail = true;
    assert!(matches!(
        VpnClient::new(mock.config())
            .unwrap()
            .connect_with(Box::new(network))
            .await,
        Err(VpnError::Network(_))
    ));
    let j = journal.lock().unwrap();
    assert_eq!((j.setups, j.cleanups, j.active), (1, 1, false));
}

#[tokio::test]
async fn cancellation_during_setup_waits_for_completion_then_rolls_back() {
    let mock = Mock::start(Options::default()).await;
    let client = VpnClient::new(mock.config()).unwrap();
    let handle = client.handle();
    let (mut network, _, _, journal) = memory();
    let resume = Arc::new(Notify::new());
    network.setup_wait = Some(resume.clone());
    let task = tokio::spawn(client.connect_with(Box::new(network)));
    timeout(Duration::from_secs(3), async {
        while journal.lock().unwrap().setups == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    handle.disconnect();
    assert!(journal.lock().unwrap().active);
    resume.notify_one();
    assert!(matches!(task.await.unwrap(), Err(VpnError::Cancelled)));
    let j = journal.lock().unwrap();
    assert_eq!((j.cleanups, j.active), (1, false));
}

#[tokio::test]
async fn pinned_key_and_ca_verification() {
    let mock = Mock::start(Options::default()).await;
    let mut config = mock.config();
    config.tls.server_pins = vec![format!("pin-sha256:{}", STANDARD.encode([0u8; 32]))];
    assert!(matches!(
        VpnClient::new(config).unwrap().authenticate().await,
        Err(VpnError::Tls(_))
    ));
    let path = std::env::temp_dir().join(format!("arraysslvpn-test-{}.pem", rand::random::<u64>()));
    std::fs::write(&path, &mock.pem).unwrap();
    let mut config = mock.config();
    config.tls.server_pins.clear();
    config.tls.ca_file = Some(path.clone());
    let result = VpnClient::new(config.clone()).unwrap().authenticate().await;
    assert!(result.is_ok());
    config.server.set_host(Some("wrong.example")).unwrap();
    assert!(matches!(
        VpnClient::new(config).unwrap().authenticate().await,
        Err(VpnError::Tls(_))
    ));
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn failed_handshake_does_not_attempt_remote_logout() {
    let mock = Mock::start(Options::default()).await;
    let mut config = mock.config();
    config.tls.server_pins = vec![format!("pin-sha256:{}", STANDARD.encode([0u8; 32]))];
    let (network, _, _, journal) = memory();
    assert!(matches!(
        VpnClient::new(config)
            .unwrap()
            .connect_with(Box::new(network))
            .await,
        Err(VpnError::Tls(_))
    ));
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
    assert_eq!(mock.logins.load(Ordering::SeqCst), 0);
    assert_eq!(mock.logouts.load(Ordering::SeqCst), 0);
    assert_eq!(journal.lock().unwrap().setups, 0);
}

struct DeferredPassword {
    expected_pin: String,
    calls: AtomicUsize,
    wait: Option<Arc<Notify>>,
    delay: Duration,
    cache: bool,
}
#[async_trait]
impl arraysslvpn::PasswordProvider for DeferredPassword {
    fn cache_password(&self) -> bool {
        self.cache
    }

    async fn password(
        &self,
        challenge: arraysslvpn::PasswordChallenge,
    ) -> Result<arraysslvpn::SecretString> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(challenge.tls.server_pin, self.expected_pin);
        assert_eq!(challenge.username, "user &+测试");
        if let Some(wait) = &self.wait {
            tokio::select! {_=challenge.cancellation.cancelled()=>return Err(VpnError::Cancelled),_=wait.notified()=>{}}
        }
        tokio::select! {_=challenge.cancellation.cancelled()=>Err(VpnError::Cancelled),
        _=tokio::time::sleep(self.delay)=>Ok(PASSWORD.into())}
    }
}
fn deferred(mock: &Mock, delay: Duration, wait: Option<Arc<Notify>>) -> Arc<DeferredPassword> {
    Arc::new(DeferredPassword {
        expected_pin: mock.pin.clone(),
        calls: AtomicUsize::new(0),
        delay,
        wait,
        cache: true,
    })
}
fn deferred_config(mock: &Mock, provider: Arc<DeferredPassword>) -> ClientConfig {
    let mut config = mock.config();
    config.auth = AuthConfig::DeferredPassword {
        username: "user &+测试".into(),
        authgroup: "local & users".into(),
        provider,
    };
    config
}

#[tokio::test]
async fn deferred_password_runs_after_tls_and_reuses_verified_connection() {
    for backend in if cfg!(feature = "openssl-tls") {
        vec![
            arraysslvpn::TlsBackend::Rustls,
            arraysslvpn::TlsBackend::OpenSsl,
        ]
    } else {
        vec![arraysslvpn::TlsBackend::Rustls]
    } {
        let mock = Mock::start(Options::default()).await;
        let wait = Arc::new(Notify::new());
        let provider = deferred(&mock, Duration::from_millis(1200), Some(wait.clone()));
        let mut config = deferred_config(&mock, provider.clone());
        config.tls.backend = backend;
        config.connect_timeout = Duration::from_secs(1);
        let client = VpnClient::new(config).unwrap();
        let handle = client.handle();
        let task = tokio::spawn(async move { client.authenticate().await });
        timeout(Duration::from_secs(3), async {
            while handle.state() != ConnectionState::AwaitingPassword {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
        assert_eq!(mock.logins.load(Ordering::SeqCst), 0);
        wait.notify_one();
        assert!(
            task.await
                .unwrap()
                .unwrap()
                .expose_secret()
                .contains(COOKIE)
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        // Exactly one TLS connection for login and one for its /portal redirect.
        assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn deferred_password_is_never_requested_after_certificate_failure() {
    let mock = Mock::start(Options::default()).await;
    let provider = deferred(&mock, Duration::ZERO, None);
    let mut config = deferred_config(&mock, provider.clone());
    config.tls.server_pins = vec![format!("pin-sha256:{}", STANDARD.encode([0u8; 32]))];
    assert!(matches!(
        VpnClient::new(config).unwrap().authenticate().await,
        Err(VpnError::Tls(_))
    ));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!(mock.logins.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn deferred_password_can_be_cancelled_without_http() {
    let mock = Mock::start(Options::default()).await;
    let provider = deferred(&mock, Duration::ZERO, Some(Arc::new(Notify::new())));
    let client = VpnClient::new(deferred_config(&mock, provider.clone())).unwrap();
    let handle = client.handle();
    let task = tokio::spawn(async move { client.authenticate().await });
    timeout(Duration::from_secs(3), async {
        while handle.state() != ConnectionState::AwaitingPassword {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    handle.disconnect();
    assert!(matches!(
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap(),
        Err(VpnError::Cancelled)
    ));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(mock.logins.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reconnect_reuses_the_deferred_password_in_memory() {
    verify_deferred_reauthentication(true).await;
}

#[tokio::test]
async fn reconnect_requests_fresh_one_time_credentials() {
    verify_deferred_reauthentication(false).await;
}

async fn verify_deferred_reauthentication(cache: bool) {
    let mock = Mock::start(Options {
        reconnect: true,
        ..Default::default()
    })
    .await;
    let mut provider = deferred(&mock, Duration::ZERO, None);
    Arc::get_mut(&mut provider).unwrap().cache = cache;
    let client = VpnClient::new(deferred_config(&mock, provider.clone())).unwrap();
    let handle = client.handle();
    let (network, send, mut receive, _) = memory();
    let session = client.connect_with(Box::new(network)).await.unwrap();
    let task = tokio::spawn(session.run());
    assert_eq!(receive.recv().await.unwrap(), ip_packet(1));
    send.send(ip_packet(2)).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), receive.recv())
            .await
            .unwrap()
            .unwrap(),
        ip_packet(3)
    );
    handle.disconnect();
    task.await.unwrap().unwrap();
    assert_eq!(mock.logins.load(Ordering::SeqCst), 2);
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        if cache { 1 } else { 2 }
    );
}

#[cfg(feature = "openssl-tls")]
#[tokio::test]
async fn openssl_backend_auth_tunnel_and_pin_policy() {
    let mock = Mock::start(Options::default()).await;
    let mut config = mock.config();
    config.tls.backend = arraysslvpn::TlsBackend::OpenSsl;
    let info = VpnClient::new(config.clone())
        .unwrap()
        .probe_tls()
        .await
        .unwrap();
    assert_eq!(info.protocol, "TLSv1.2");
    assert_eq!(info.server_pin, mock.pin);
    let mut bad = config.clone();
    bad.tls.server_pins = vec![format!("pin-sha256:{}", STANDARD.encode([0u8; 32]))];
    assert!(matches!(
        VpnClient::new(bad).unwrap().authenticate().await,
        Err(VpnError::Tls(_))
    ));
    assert_eq!(mock.logins.load(Ordering::SeqCst), 0);
    let client = VpnClient::new(config).unwrap();
    let controller = client.handle();
    let (network, send, mut receive, journal) = memory();
    let session = client.connect_with(Box::new(network)).await.unwrap();
    let task = tokio::spawn(session.run());
    assert_eq!(receive.recv().await.unwrap(), ip_packet(1));
    send.send(ip_packet(42)).await.unwrap();
    assert_eq!(receive.recv().await.unwrap(), ip_packet(42));
    controller.disconnect();
    task.await.unwrap().unwrap();
    assert_eq!(journal.lock().unwrap().cleanups, 1);
    assert_eq!(mock.logouts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cookie_cleanup_without_a_new_nonempty_session_is_an_authentication_failure() {
    let mock = Mock::start(Options {
        cleared_session_only: true,
        ..Default::default()
    })
    .await;
    assert!(matches!(
        VpnClient::new(mock.config()).unwrap().authenticate().await,
        Err(VpnError::Authentication)
    ));
}

#[tokio::test]
async fn password_login_accepts_old_cookie_cleanup_before_the_new_session_cookie() {
    let mock = Mock::start(Options {
        clear_cookies: true,
        ..Default::default()
    })
    .await;
    for _ in 0..3 {
        let cookie = VpnClient::new(mock.config())
            .unwrap()
            .authenticate()
            .await
            .unwrap();
        assert_eq!(cookie.expose_secret(), format!("ANsession999={COOKIE}"));
    }
    assert_eq!(mock.logins.load(Ordering::SeqCst), 3);
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn cli_tls_probe_needs_no_credentials_and_sends_no_http() {
    let mock = Mock::start(Options::default()).await;
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_arraysslvpn"))
        .args([
            &format!("https://localhost:{}", mock.address.port()),
            "--resolve",
            "127.0.0.1",
            "--servercert",
            &mock.pin,
            "--tls-probe",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["backend"], "rustls");
    assert_eq!(info["server_pin"], mock.pin);
    assert_eq!(mock.logins.load(Ordering::SeqCst), 0);
    assert_eq!(mock.tunnels.load(Ordering::SeqCst), 0);
    assert_eq!(mock.logouts.load(Ordering::SeqCst), 0);
}

async fn proxy(target: SocketAddr, socks: bool) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                if socks {
                    let mut greeting = [0; 3];
                    stream.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 1, 2]);
                    stream.write_all(&[5, 2]).await.unwrap();
                    assert_eq!(stream.read_u8().await.unwrap(), 1);
                    let n = stream.read_u8().await.unwrap() as usize;
                    let mut user = vec![0; n];
                    stream.read_exact(&mut user).await.unwrap();
                    let n = stream.read_u8().await.unwrap() as usize;
                    let mut pass = vec![0; n];
                    stream.read_exact(&mut pass).await.unwrap();
                    assert_eq!(user, b"proxy user");
                    assert_eq!(pass, b"PROXY_PASSWORD");
                    stream.write_all(&[1, 0]).await.unwrap();
                    let mut header = [0; 4];
                    stream.read_exact(&mut header).await.unwrap();
                    assert_eq!(header, [5, 1, 0, 1]);
                    let mut destination = [0; 6];
                    stream.read_exact(&mut destination).await.unwrap();
                    assert_eq!(
                        u16::from_be_bytes([destination[4], destination[5]]),
                        target.port()
                    );
                    stream
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();
                } else {
                    let mut headers = vec![];
                    while !headers.ends_with(b"\r\n\r\n") {
                        headers.push(stream.read_u8().await.unwrap());
                    }
                    let headers = String::from_utf8(headers).unwrap();
                    assert!(
                        headers
                            .starts_with(&format!("CONNECT 127.0.0.1:{} HTTP/1.1", target.port()))
                    );
                    assert!(headers.contains(&format!(
                        "Proxy-Authorization: Basic {}",
                        STANDARD.encode("proxy user:PROXY_PASSWORD")
                    )));
                    stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                }
                let mut upstream = TcpStream::connect(target).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
            });
        }
    });
    (address, task)
}

#[tokio::test]
async fn http_and_socks5_authenticated_proxies() {
    let mock = Mock::start(Options::default()).await;
    for socks in [false, true] {
        let (address, task) = proxy(mock.address, socks).await;
        let mut config = mock.config();
        config.proxy = Some(
            url::Url::parse(&format!(
                "{}://proxy%20user:PROXY_PASSWORD@{address}",
                if socks { "socks5" } else { "http" }
            ))
            .unwrap(),
        );
        assert!(!format!("{config:?}").contains("PROXY_PASSWORD"));
        assert!(
            VpnClient::new(config)
                .unwrap()
                .authenticate()
                .await
                .unwrap()
                .expose_secret()
                .contains(COOKIE)
        );
        task.abort();
    }
}

#[tokio::test]
async fn stalled_tls_times_out_and_is_cancellable() {
    let mock = Mock::start(Options::default()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hold = tokio::spawn(async move {
        let mut connections = vec![];
        while let Ok((stream, _)) = listener.accept().await {
            connections.push(stream);
        }
    });
    let mut config = mock.config();
    config.server.set_port(Some(address.port())).unwrap();
    config.connect_timeout = Duration::from_millis(100);
    assert!(matches!(
        VpnClient::new(config.clone()).unwrap().authenticate().await,
        Err(VpnError::Timeout(_))
    ));
    config.connect_timeout = Duration::from_secs(30);
    let client = VpnClient::new(config).unwrap();
    let handle = client.handle();
    let task = tokio::spawn(async move { client.authenticate().await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    handle.disconnect();
    assert!(matches!(
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap(),
        Err(VpnError::Cancelled)
    ));
    hold.abort();
}

#[tokio::test]
async fn dead_peer_deadline_cleans_up_without_reconnect() {
    let mock = Mock::start(Options {
        mute_dpd: true,
        ..Default::default()
    })
    .await;
    let mut config = mock.config();
    config.reconnect.timeout = Duration::ZERO;
    let (network, _send, mut receive, journal) = memory();
    let session = VpnClient::new(config)
        .unwrap()
        .connect_with(Box::new(network))
        .await
        .unwrap();
    let task = tokio::spawn(session.run());
    receive.recv().await.unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap(),
        Err(VpnError::Timeout("dead peer detection"))
    ));
    assert!(mock.dpds.load(Ordering::SeqCst) > 0);
    let j = journal.lock().unwrap();
    assert_eq!((j.setups, j.cleanups, j.active), (1, 1, false));
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn cli_authenticate_stdin_has_only_cookie_on_stdout() {
    use std::process::Stdio;
    let mock = Mock::start(Options::default()).await;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_arraysslvpn"))
        .args([
            &format!("https://localhost:{}", mock.address.port()),
            "--resolve",
            "127.0.0.1",
            "--user",
            "user &+测试",
            "--authgroup",
            "local & users",
            "--servercert",
            &mock.pin,
            "--passwd-on-stdin",
            "--authenticate",
            "-vv",
            "--log-format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .await
        .unwrap();
    let output = timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success(), "CLI authentication failed");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("ANsession999={COOKIE}")
    );
    let logs = String::from_utf8(output.stderr).unwrap();
    assert!(logs.contains("TLS connected"));
    assert!(!logs.contains(PASSWORD));
    assert!(!logs.contains(COOKIE));
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn trace_logs_never_contain_secrets() {
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    struct Guard(Arc<Mutex<Vec<u8>>>);
    impl io::Write for Guard {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Guard;
        fn make_writer(&'a self) -> Guard {
            Guard(self.0.clone())
        }
    }
    let mock = Mock::start(Options {
        clear_cookies: true,
        ..Default::default()
    })
    .await;
    let captured = Capture(Arc::new(Mutex::new(vec![])));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(captured.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    {
        let config = mock.config();
        assert!(!format!("{config:?}").contains(PASSWORD));
        let client = VpnClient::new(config).unwrap();
        let (network, _, _, _) = memory();
        let session = client.connect_with(Box::new(network)).await.unwrap();
        session.disconnect().await.unwrap();
    }
    let invalid = Mock::start(Options {
        invalid_cookie_domain: true,
        ..Default::default()
    })
    .await;
    let error = VpnClient::new(invalid.config())
        .unwrap()
        .authenticate()
        .await
        .unwrap_err();
    assert!(error.to_string().contains("domain mismatch"));
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("HTTP response"));
    assert!(logs.contains("Array configuration"));
    assert!(logs.contains("processed expired Set-Cookie"));
    assert!(logs.contains("domain mismatch"));
    assert!(!logs.contains(PASSWORD));
    assert!(!logs.contains(COOKIE));
    assert!(!logs.contains("private.example.invalid"));
}
