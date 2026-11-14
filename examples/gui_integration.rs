//! Integration sketch: a GUI supplies credentials, installs its own tracing
//! subscriber, and keeps SessionHandle on its UI/controller side.
use arraysslvpn::{AuthConfig, ClientConfig, ClientEvent, VpnClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A real GUI obtains these from its login dialog or credential store.
    let server = std::env::var("ARRAYVPN_SERVER")?;
    let username = std::env::var("ARRAYVPN_USER")?;
    let password = std::env::var("ARRAYVPN_PASSWORD")?;
    let config = ClientConfig::new(
        &server,
        AuthConfig::Password {
            username,
            password: password.into(),
            authgroup: String::new(),
        },
    )?;
    let client = VpnClient::new(config)?;
    let controller = client.handle();
    let mut events = controller.subscribe();
    let events_task = tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(ClientEvent::StateChanged(state)) => eprintln!("GUI state: {state:?}"),
                Ok(ClientEvent::NetworkConfigured(settings)) => {
                    eprintln!("GUI address: {}", settings.address)
                }
                Ok(ClientEvent::Stats(stats)) => eprintln!(
                    "GUI bytes: up={}, down={}",
                    stats.bytes_sent, stats.bytes_received
                ),
                Ok(event) => eprintln!("GUI event: {event:?}"),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    let signals = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            controller.disconnect();
        }
    });
    let result = match client.connect().await {
        Ok(session) => session.run().await,
        Err(error) => Err(error),
    };
    signals.abort();
    events_task.abort();
    result?;
    Ok(())
}
