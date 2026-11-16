use arraysslvpn::{AuthConfig, ClientConfig, SecretString, VpnClient, VpnError};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

const SEED: &str = "JBSWY3DPEHPK3PXP";
const PASSWORD: &str = "PRIVATE&+password秘密";
#[derive(Default, Clone, Copy)]
struct Options {
    reject: bool,
    cross_origin: bool,
    drop_post: bool,
    bad_time: bool,
    oversized: bool,
    stall: bool,
}
struct Gateway {
    server: String,
    requests: Arc<Mutex<Vec<(String, String)>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Gateway {
    async fn start(options: Options) -> Self {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = format!(
            "https://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let records = requests.clone();
        let task = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(tls));
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let records = records.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut data = Vec::new();
                    let (method, path, headers, body) = loop {
                        let mut buffer = [0; 4096];
                        let Ok(count) = stream.read(&mut buffer).await else {
                            return;
                        };
                        if count == 0 {
                            return;
                        }
                        data.extend_from_slice(&buffer[..count]);
                        assert!(data.len() < 65_536);
                        if let Some(end) = data.windows(4).position(|p| p == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&data[..end]);
                            let mut lines = head.lines();
                            let mut request = lines.next().unwrap().split_whitespace();
                            let method = request.next().unwrap().to_owned();
                            let path = request.next().unwrap().to_owned();
                            let headers = lines
                                .map(|line| {
                                    let (k, v) = line.split_once(':').unwrap();
                                    (k.to_ascii_lowercase(), v.trim().to_owned())
                                })
                                .collect::<BTreeMap<_, _>>();
                            let length = headers
                                .get("content-length")
                                .map(|v| v.parse::<usize>().unwrap())
                                .unwrap_or(0);
                            if data.len() >= end + 4 + length {
                                break (
                                    method,
                                    path,
                                    headers,
                                    String::from_utf8_lossy(&data[end + 4..end + 4 + length])
                                        .into_owned(),
                                );
                            }
                        }
                    };
                    assert_eq!(headers.get("user-agent").unwrap(), "MotionProOTP/108");
                    assert!(!headers.get("host").unwrap().contains("localhost"));
                    records.lock().unwrap().push((method.clone(), path.clone()));
                    if options.stall {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        return;
                    }
                    let prefix = "/prx/000/http/localhost/";
                    let endpoint = path
                        .strip_prefix(prefix)
                        .unwrap()
                        .split('?')
                        .next()
                        .unwrap();
                    if endpoint != "an_login.js" {
                        assert!(headers.get("cookie").unwrap().contains("ANsessionotp="));
                    }
                    let (status, extra, body, chunked, close) = match (method.as_str(), endpoint) {
                        ("GET", "an_login.js") => {
                            if options.oversized {
                                stream
                                    .write_all(
                                        b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
                                    )
                                    .await
                                    .unwrap();
                                return;
                            }
                            (
                                200,
                                "Set-Cookie: ANsessionotp=stage1; Path=/; Secure\r\n".to_owned(),
                                "var _AN_dyncode_interval = '90';".to_owned(),
                                true,
                                false,
                            )
                        }
                        ("GET", "register") => (
                            200,
                            String::new(),
                            "<form>otp_reg</form>".into(),
                            false,
                            true,
                        ),
                        ("POST", "register") => {
                            let fields = url::form_urlencoded::parse(body.as_bytes())
                                .into_owned()
                                .collect::<BTreeMap<_, _>>();
                            assert_eq!(fields.len(), 4);
                            assert_eq!(fields["method"], "otp_reg");
                            assert_eq!(fields["uname"], "user+名字&");
                            assert_eq!(fields["pwd"], PASSWORD);
                            assert_eq!(fields["sm"], SEED);
                            if options.drop_post {
                                let _ = stream.shutdown().await;
                                return;
                            }
                            let location = if options.cross_origin {
                                "https://other.invalid/prx/000/http/localhost/login"
                            } else {
                                "/prx/000/http/localhost/login?enroll=1"
                            };
                            (
                                302,
                                format!(
                                    "Location: {location}\r\nSet-Cookie: ANsessionotp=stage2; Path=/; Secure\r\n"
                                ),
                                String::new(),
                                false,
                                false,
                            )
                        }
                        ("GET", "login") => {
                            assert!(path.ends_with("?enroll=1"));
                            assert!(headers["cookie"].contains("ANsessionotp=stage2"));
                            (
                                200,
                                String::new(),
                                format!(
                                    "var _AN_str_errormsg_login = '{}';",
                                    if options.reject { PASSWORD } else { "" }
                                ),
                                false,
                                false,
                            )
                        }
                        ("GET", "system-time") => {
                            let timestamp = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs()
                                + 120;
                            (
                                200,
                                String::new(),
                                if options.bad_time {
                                    "not a clock".into()
                                } else {
                                    format!("<time>{timestamp}</time>")
                                },
                                false,
                                false,
                            )
                        }
                        _ => panic!("unexpected portal request"),
                    };
                    let framing = if chunked {
                        "Transfer-Encoding: chunked\r\n".into()
                    } else if close {
                        "Connection: close\r\n".into()
                    } else {
                        format!("Content-Length: {}\r\n", body.len())
                    };
                    stream
                        .write_all(
                            format!("HTTP/1.1 {status} Result\r\n{extra}{framing}\r\n").as_bytes(),
                        )
                        .await
                        .unwrap();
                    if chunked {
                        for part in body.as_bytes().chunks(3) {
                            stream
                                .write_all(format!("{:x}\r\n", part.len()).as_bytes())
                                .await
                                .unwrap();
                            stream.write_all(part).await.unwrap();
                            stream.write_all(b"\r\n").await.unwrap();
                        }
                        stream
                            .write_all(b"0\r\nX-Test: bounded\r\n\r\n")
                            .await
                            .unwrap();
                    } else {
                        stream.write_all(body.as_bytes()).await.unwrap();
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            server,
            requests,
            task,
        }
    }
    fn client(&self, insecure: bool) -> VpnClient {
        let mut config = ClientConfig::new(
            &self.server,
            AuthConfig::Password {
                username: "user+名字&".into(),
                password: PASSWORD.into(),
                authgroup: "AUTHGROUP-MUST-NOT-BE-POSTED".into(),
            },
        )
        .unwrap();
        config.tls.insecure = insecure;
        config.connect_timeout = Duration::from_secs(2);
        VpnClient::new(config).unwrap()
    }
    fn posts(&self) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == "POST")
            .count()
    }
}

#[tokio::test]
async fn enrollment_preserves_cookies_encoding_body_framing_and_server_parameters() {
    let gateway = Gateway::start(Options::default()).await;
    let enrolled = gateway
        .client(true)
        .enroll_otp(SecretString::from(SEED))
        .await
        .unwrap();
    assert_eq!(enrolled.parameters.period, 90);
    assert!((119..=121).contains(&enrolled.parameters.time_offset_seconds.unwrap()));
    assert_eq!(gateway.posts(), 1);
    assert_eq!(gateway.requests.lock().unwrap().len(), 5);
}
#[tokio::test]
async fn untrusted_tls_and_invalid_lengths_never_submit_the_new_seed() {
    let gateway = Gateway::start(Options::default()).await;
    assert!(matches!(
        gateway.client(false).enroll_otp(SEED.into()).await,
        Err(VpnError::Tls(_))
    ));
    assert_eq!(gateway.posts(), 0);
    let gateway = Gateway::start(Options {
        oversized: true,
        ..Default::default()
    })
    .await;
    assert!(gateway.client(true).enroll_otp(SEED.into()).await.is_err());
    assert_eq!(gateway.posts(), 0);
}
#[tokio::test]
async fn failed_post_confirmation_is_explicitly_uncertain_and_never_echoes_secrets() {
    for options in [
        Options {
            reject: true,
            ..Default::default()
        },
        Options {
            cross_origin: true,
            ..Default::default()
        },
        Options {
            drop_post: true,
            ..Default::default()
        },
    ] {
        let gateway = Gateway::start(options).await;
        let error = gateway
            .client(true)
            .enroll_otp(SEED.into())
            .await
            .unwrap_err();
        assert!(matches!(error, VpnError::OtpEnrollmentUncertain(_)));
        assert!(!error.to_string().contains(PASSWORD));
        assert!(!error.to_string().contains(SEED));
        assert_eq!(gateway.posts(), 1);
    }
}
#[tokio::test]
async fn clock_failure_does_not_discard_a_confirmed_registration() {
    let gateway = Gateway::start(Options {
        bad_time: true,
        ..Default::default()
    })
    .await;
    let enrolled = gateway.client(true).enroll_otp(SEED.into()).await.unwrap();
    assert_eq!(enrolled.parameters.time_offset_seconds, None);
}
#[tokio::test]
async fn cancellation_before_submission_does_not_change_the_gateway() {
    let gateway = Gateway::start(Options {
        stall: true,
        ..Default::default()
    })
    .await;
    let client = gateway.client(true);
    let handle = client.handle();
    let operation = tokio::spawn(async move { client.enroll_otp(SEED.into()).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    handle.disconnect();
    assert!(matches!(operation.await.unwrap(), Err(VpnError::Cancelled)));
    assert_eq!(gateway.posts(), 0);
}
