//! Connection orchestration, session control, events, and tunnel forwarding.
mod handle;
mod session;
mod state;
mod timeout;

pub use handle::SessionHandle;
pub use session::VpnSession;
pub(crate) use state::Shared;
pub use state::{ClientEvent, ConnectionState, SessionStats};
pub(crate) use timeout::bounded;

use crate::{
    ClientConfig, NetworkManager, Result, SecretString, VpnError,
    auth::AuthSession,
    transport::{self, TlsContext},
};
use std::sync::Arc;
use tracing::Instrument;

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
            let mut session = VpnSession::new(self.config, self.tls, self.shared, network);
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
