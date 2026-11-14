use crate::{
    AuthConfig, ClientConfig, ClientEvent, ConnectionState, NetworkManager, NetworkSettings,
    PacketIo, Result, SecretString, SessionStats, VpnError,
    event::Shared,
    http::AuthSession,
    protocol::{self, PacketDecoder, TunnelPacket},
    transport::{self, TlsContext, Wire},
    util::bounded,
};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{broadcast, watch},
    time::{Instant, timeout},
};
use tracing::Instrument;

/// A cloneable control plane. Event receivers may lag without blocking packets;
/// use state()/stats() to resynchronize after a broadcast Lagged error.
#[derive(Clone)]
pub struct SessionHandle {
    shared: Arc<Shared>,
}
impl SessionHandle {
    pub fn disconnect(&self) {
        self.shared.cancel.cancel();
    }
    pub fn cancellation_token(&self) -> tokio_util::sync::CancellationToken {
        self.shared.cancel.clone()
    }
    pub fn state(&self) -> ConnectionState {
        *self.shared.state.borrow()
    }
    pub fn watch_state(&self) -> watch::Receiver<ConnectionState> {
        self.shared.state.subscribe()
    }
    pub fn subscribe(&self) -> broadcast::Receiver<ClientEvent> {
        self.shared.events.subscribe()
    }
    pub fn stats(&self) -> SessionStats {
        self.shared.stats()
    }
}

/// One connection attempt and its reconnect policy. Create a new client after
/// disconnecting; credentials stay in memory and are never persisted by the library.
pub struct VpnClient {
    config: Arc<ClientConfig>,
    tls: TlsContext,
    shared: Arc<Shared>,
}
impl VpnClient {
    pub fn new(config: ClientConfig) -> Result<Self> {
        config.validate()?;
        let tls = transport::tls_config(&config.tls)?;
        Ok(Self {
            config: Arc::new(config),
            tls,
            shared: Shared::new(),
        })
    }
    pub fn handle(&self) -> SessionHandle {
        SessionHandle {
            shared: self.shared.clone(),
        }
    }
    /// Verify TCP/TLS compatibility without sending credentials, HTTP requests,
    /// or changing the host network. Uses the configured CA/pin/insecure policy.
    pub async fn probe_tls(&self) -> Result<crate::TlsInfo> {
        self.shared.set_state(ConnectionState::Connecting);
        let result = bounded(
            &self.shared,
            self.config.connect_timeout,
            "TLS probe",
            transport::connect(&self.config, self.tls.clone()),
        )
        .await;
        self.shared.set_state(ConnectionState::Disconnected);
        result.map(|wire| wire.info)
    }
    pub async fn authenticate(&self) -> Result<SecretString> {
        self.shared.set_state(ConnectionState::Authenticating);
        let mut auth = AuthSession::new();
        let result = auth
            .authenticate(&self.config, self.tls.clone(), &self.shared, None)
            .await;
        self.shared.set_state(ConnectionState::Disconnected);
        if let Err(error) = &result {
            tracing::error!(%error,"Array authentication failed");
            self.shared.emit(ClientEvent::Error(error.to_string()));
        }
        result
    }
    #[cfg(feature = "system-network")]
    pub async fn connect(self) -> Result<VpnSession> {
        self.connect_with(Box::new(crate::network::SystemNetworkManager::default()))
            .await
    }
    /// Provide a custom system configuration implementation or userspace packet
    /// endpoint. This entry point also works without the system-network feature.
    pub async fn connect_with(self, network: Box<dyn NetworkManager>) -> Result<VpnSession> {
        let span = tracing::info_span!("vpn", session_id = self.shared.session_id);
        async move {
            let mut session = VpnSession {
                config: self.config,
                tls: self.tls,
                shared: self.shared,
                auth: AuthSession::new(),
                wire: None,
                io: None,
                network,
                settings: None,
                dpd: Duration::from_secs(30),
                client_id: client_id(),
                attempt_deadline: None,
            };
            let result = session.establish(true).await;
            if let Err(error) = result {
                tracing::error!(%error,"VPN connection failed");
                let cleanup = session.finish().await;
                session.shared.emit(ClientEvent::Error(error.to_string()));
                return match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(VpnError::Cleanup {
                        primary: error.to_string(),
                        cleanup: cleanup.to_string(),
                    }),
                };
            }
            Ok(session)
        }
        .instrument(span)
        .await
    }
}

pub struct VpnSession {
    config: Arc<ClientConfig>,
    tls: TlsContext,
    shared: Arc<Shared>,
    auth: AuthSession,
    wire: Option<Wire>,
    io: Option<Arc<dyn PacketIo>>,
    network: Box<dyn NetworkManager>,
    settings: Option<NetworkSettings>,
    dpd: Duration,
    client_id: String,
    attempt_deadline: Option<Instant>,
}

impl VpnSession {
    pub fn handle(&self) -> SessionHandle {
        SessionHandle {
            shared: self.shared.clone(),
        }
    }
    pub fn settings(&self) -> &NetworkSettings {
        self.settings.as_ref().expect("connected session")
    }

    fn operation_timeout(&self) -> Result<Duration> {
        let duration = self
            .attempt_deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
            .unwrap_or(self.config.connect_timeout)
            .min(self.config.connect_timeout);
        if duration.is_zero() {
            Err(VpnError::Timeout("reconnect deadline"))
        } else {
            Ok(duration)
        }
    }

    async fn establish(&mut self, initial: bool) -> Result<()> {
        self.shared.set_state(ConnectionState::Connecting);
        if initial {
            self.shared.set_state(ConnectionState::Authenticating);
            self.auth
                .authenticate(
                    &self.config,
                    self.tls.clone(),
                    &self.shared,
                    self.attempt_deadline,
                )
                .await?;
        }
        self.shared.set_state(ConnectionState::Negotiating);
        let open = bounded(
            &self.shared,
            self.operation_timeout()?,
            "tunnel negotiation",
            self.auth
                .tunnel(&self.config, self.tls.clone(), &self.client_id),
        )
        .await;
        let mut wire = match open {
            Err(VpnError::Authentication)
                if matches!(
                    self.config.auth,
                    AuthConfig::Password { .. } | AuthConfig::DeferredPassword { .. }
                ) && !initial =>
            {
                self.shared.set_state(ConnectionState::Authenticating);
                self.auth
                    .authenticate(
                        &self.config,
                        self.tls.clone(),
                        &self.shared,
                        self.attempt_deadline,
                    )
                    .await?;
                self.shared.set_state(ConnectionState::Negotiating);
                bounded(
                    &self.shared,
                    self.operation_timeout()?,
                    "tunnel negotiation",
                    self.auth
                        .tunnel(&self.config, self.tls.clone(), &self.client_id),
                )
                .await?
            }
            other => other?,
        };
        let speed = bounded(
            &self.shared,
            self.operation_timeout()?,
            "speed tunnel configuration",
            request_json(&mut wire, &protocol::CONF50),
        )
        .await?;
        self.dpd = self
            .config
            .dpd_interval
            .or(protocol::parse_dpd(&speed)?)
            .unwrap_or(Duration::from_secs(30));
        let value = bounded(
            &self.shared,
            self.operation_timeout()?,
            "interface configuration",
            request_json(&mut wire, &protocol::CONF54),
        )
        .await?;
        let settings = protocol::parse_network_settings(&value, self.config.network.mtu)?;
        tracing::debug!(
            ?settings,
            dpd_seconds = self.dpd.as_secs(),
            "Array configuration negotiated"
        );
        self.shared.set_state(ConnectionState::ConfiguringNetwork);
        // Never drop setup midway: it may be waiting on a blocking OS operation.
        // Always let it finish so that its complete journal can be rolled back.
        if self.shared.cancel.is_cancelled() {
            return Err(VpnError::Cancelled);
        }
        let io = self
            .network
            .setup(&settings, &self.config.network, wire.peer)
            .await?;
        self.io = Some(io);
        self.wire = Some(wire);
        self.settings = Some(settings.clone());
        if self.shared.cancel.is_cancelled() {
            return Err(VpnError::Cancelled);
        }
        self.operation_timeout()?;
        self.shared.emit(ClientEvent::NetworkConfigured(settings));
        self.shared.set_state(ConnectionState::Connected);
        Ok(())
    }

    /// Drives packet forwarding until disconnect or a terminal error, and always
    /// awaits network cleanup and best-effort remote logout before returning.
    pub async fn run(mut self) -> Result<()> {
        let span = tracing::info_span!("vpn", session_id = self.shared.session_id);
        async {
            let result = loop {
                match self.pump().await {
                    Ok(()) | Err(VpnError::Cancelled) => break Ok(()),
                    Err(error) if error.retryable() && !self.config.reconnect.timeout.is_zero() => {
                        tracing::warn!(%error,"tunnel interrupted");
                        if let Err(error) = self.reconnect().await {
                            break if matches!(error, VpnError::Cancelled) {
                                Ok(())
                            } else {
                                Err(error)
                            };
                        }
                    }
                    Err(error) => break Err(error),
                }
            };
            if let Err(error) = &result {
                tracing::error!(%error,"VPN stopped");
                self.shared.emit(ClientEvent::Error(error.to_string()));
            }
            let cleanup = self.finish().await;
            match (result, cleanup) {
                (Ok(()), other) => other,
                (Err(error), Ok(())) => Err(error),
                (Err(error), Err(cleanup)) => Err(VpnError::Cleanup {
                    primary: error.to_string(),
                    cleanup: cleanup.to_string(),
                }),
            }
        }
        .instrument(span)
        .await
    }

    /// Disconnect a session that has not been passed to run().
    pub async fn disconnect(mut self) -> Result<()> {
        self.shared.cancel.cancel();
        self.finish().await
    }

    async fn reconnect(&mut self) -> Result<()> {
        self.wire = None;
        self.io = None;
        self.network.cleanup().await?;
        self.shared.set_state(ConnectionState::Reconnecting);
        let deadline = Instant::now() + self.config.reconnect.timeout;
        self.attempt_deadline = Some(deadline);
        let mut delay = self.config.reconnect.initial_delay;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let jitter = Duration::from_millis(rand::random_range(0..=250));
            let wait = (delay + jitter).min(deadline.saturating_duration_since(Instant::now()));
            if wait.is_zero() {
                return Err(VpnError::Timeout("reconnect deadline"));
            }
            self.shared.emit(ClientEvent::ReconnectAttempt {
                attempt,
                delay_ms: wait.as_millis() as u64,
            });
            tracing::info!(attempt, delay_ms = wait.as_millis(), "reconnecting");
            tokio::select! {_ = self.shared.cancel.cancelled()=>return Err(VpnError::Cancelled),_ = tokio::time::sleep(wait)=>{}}
            if Instant::now() >= deadline {
                return Err(VpnError::Timeout("reconnect deadline"));
            }
            // Establishment is bounded per operation. The total deadline is
            // checked between operations/attempts, without cancelling OS setup.
            match self.establish(false).await {
                Ok(()) => {
                    self.attempt_deadline = None;
                    self.shared.update(|s| s.reconnects += 1);
                    return Ok(());
                }
                Err(error) => {
                    self.io = None;
                    self.wire = None;
                    self.network.cleanup().await?;
                    if !error.retryable() {
                        return Err(error);
                    }
                    tracing::warn!(%error,attempt,"reconnect attempt failed");
                    self.shared.set_state(ConnectionState::Reconnecting);
                }
            }
            delay = delay.saturating_mul(2).min(self.config.reconnect.max_delay);
        }
    }

    async fn pump(&mut self) -> Result<()> {
        let mut wire = self.wire.take().expect("established tunnel");
        let io = self.io.as_ref().expect("configured packets").clone();
        let mut decoder = PacketDecoder::after_json();
        decoder.push(&wire.buffer)?;
        let mut tcp_buffer = vec![0; 32768];
        let mut tun_buffer = vec![0; 65575];
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_rx = Instant::now();
        let mut last_dpd = Instant::now();
        loop {
            while let Some(packet) = decoder.next_packet()? {
                match packet {
                    TunnelPacket::Control { kind, .. } => {
                        tracing::debug!(kind, "received Array control packet")
                    }
                    TunnelPacket::Ip(packet) => {
                        bounded(
                            &self.shared,
                            self.config.connect_timeout,
                            "TUN write",
                            async {
                                io.send(&packet)
                                    .await
                                    .map_err(|e| VpnError::Network(format!("TUN write: {e}")))
                            },
                        )
                        .await?;
                        self.shared.update(|s| {
                            s.bytes_received += packet.len() as u64;
                            s.packets_received += 1;
                        });
                        tracing::trace!(length = packet.len(), "received IP packet");
                    }
                }
            }
            tokio::select! {
                _=self.shared.cancel.cancelled()=>return Ok(()),
                result=wire.stream.read(&mut tcp_buffer)=>{
                    let n=result?;
                    if n==0{return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());}
                    last_rx=Instant::now();decoder.push(&tcp_buffer[..n])?;
                }
                result=io.recv(&mut tun_buffer)=>{
                    let n=result.map_err(|e|VpnError::Network(format!("TUN read: {e}")))?;
                    if n==0 || n>tun_buffer.len(){return Err(VpnError::Network("invalid TUN packet length".into()));}
                    let mut validate=PacketDecoder::default();validate.push(&tun_buffer[..n])?;
                    match validate.next_packet()? {
                        Some(TunnelPacket::Ip(packet)) if packet.len()==n=>{},
                        _=>return Err(VpnError::Protocol("invalid outgoing IP packet".into()))
                    }
                    bounded(&self.shared,self.config.connect_timeout,"TLS packet write",async {
                        wire.stream.write_all(&tun_buffer[..n]).await?;Ok(())
                    }).await?;
                    self.shared.update(|s|{s.bytes_sent+=n as u64;s.packets_sent+=1;});
                    tracing::trace!(length=n,"sent IP packet");
                }
                _=tick.tick()=>{
                    if last_rx.elapsed()>=self.dpd.saturating_mul(3){return Err(VpnError::Timeout("dead peer detection"));}
                    if last_rx.elapsed()>=self.dpd && last_dpd.elapsed()>=self.dpd {
                        bounded(&self.shared,self.config.connect_timeout,"DPD write",async {
                            wire.stream.write_all(&protocol::DPD).await?;Ok(())
                        }).await?;
                        last_dpd=Instant::now();tracing::debug!("sent Array DPD");
                    }
                    self.shared.emit(ClientEvent::Stats(self.shared.stats()));
                }
            }
        }
    }
    async fn finish(&mut self) -> Result<()> {
        self.shared.set_state(ConnectionState::Disconnecting);
        self.wire = None;
        self.io = None;
        let cleanup = self.network.cleanup().await;
        // Logout is best effort and deliberately independent of the cancellation
        // token. A logout failure must not prevent restoration of local networking.
        if self.auth.has_session() {
            match timeout(
                self.config.connect_timeout.min(Duration::from_secs(5)),
                self.auth.logout(&self.config, self.tls.clone()),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(%error,"remote logout failed");
                    self.shared.emit(ClientEvent::Warning(error.to_string()));
                }
                Err(_) => {
                    tracing::warn!("remote logout timed out");
                    self.shared
                        .emit(ClientEvent::Warning("remote logout timed out".into()));
                }
            }
        } else {
            tracing::debug!("skipping remote logout: no authenticated Array session");
        }
        if let Err(error) = &cleanup {
            tracing::error!(%error,"local network cleanup failed");
        }
        self.shared.set_state(ConnectionState::Disconnected);
        cleanup
    }
}

async fn request_json(wire: &mut Wire, request: &[u8]) -> Result<serde_json::Value> {
    let started = Instant::now();
    tracing::debug!(
        kind = request[0],
        length = request.len(),
        "sending Array configuration request"
    );
    wire.stream.write_all(request).await?;
    loop {
        if let Some(value) = protocol::take_json(&mut wire.buffer, wire.after_json)? {
            wire.after_json = true;
            tracing::debug!(
                kind = request[0],
                elapsed_ms = started.elapsed().as_millis(),
                "Array configuration response decoded"
            );
            return Ok(value);
        }
        wire.read_more().await?;
    }
}

fn client_id() -> String {
    let b = rand::random::<[u8; 16]>();
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}
