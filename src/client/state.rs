use serde::Serialize;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{broadcast, watch};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    AwaitingPassword,
    Negotiating,
    ConfiguringNetwork,
    Connected,
    Reconnecting,
    Disconnecting,
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub enum ClientEvent {
    StateChanged(ConnectionState),
    NetworkConfigured(crate::NetworkSettings),
    ReconnectAttempt { attempt: u32, delay_ms: u64 },
    Warning(String),
    Error(String),
    Stats(SessionStats),
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SessionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub reconnects: u64,
}

pub(crate) struct Shared {
    pub events: broadcast::Sender<ClientEvent>,
    pub state: watch::Sender<ConnectionState>,
    pub stats: Mutex<SessionStats>,
    pub session_id: u64,
    pub cancel: tokio_util::sync::CancellationToken,
    stage_started: Mutex<std::time::Instant>,
}

impl Shared {
    pub fn new() -> Arc<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Arc::new(Self {
            events: broadcast::channel(256).0,
            state: watch::channel(ConnectionState::Disconnected).0,
            stats: Mutex::new(SessionStats::default()),
            session_id: NEXT.fetch_add(1, Ordering::Relaxed),
            cancel: tokio_util::sync::CancellationToken::new(),
            stage_started: Mutex::new(std::time::Instant::now()),
        })
    }
    pub fn set_state(&self, state: ConnectionState) {
        let mut started = self.stage_started.lock().unwrap_or_else(|e| e.into_inner());
        let elapsed = started.elapsed();
        *started = std::time::Instant::now();
        drop(started);
        self.state.send_replace(state);
        tracing::info!(
            session_id = self.session_id,
            ?state,
            previous_stage_ms = elapsed.as_millis(),
            "connection state"
        );
        self.emit(ClientEvent::StateChanged(state));
    }
    pub fn emit(&self, event: ClientEvent) {
        let _ = self.events.send(event);
    }
    pub fn stats(&self) -> SessionStats {
        self.stats.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub fn update(&self, f: impl FnOnce(&mut SessionStats)) {
        f(&mut self.stats.lock().unwrap_or_else(|e| e.into_inner()));
    }
}
