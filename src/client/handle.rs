use super::Shared;
use crate::{ClientEvent, ConnectionState, SessionStats};
use std::sync::Arc;
use tokio::sync::{broadcast, watch};

/// A cloneable control plane. Event receivers may lag without blocking packets;
/// use state()/stats() to resynchronize after a broadcast Lagged error.
#[derive(Clone)]
pub struct SessionHandle {
    pub(super) shared: Arc<Shared>,
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
