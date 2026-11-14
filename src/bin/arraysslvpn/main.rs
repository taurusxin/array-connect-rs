//! Command-line frontend; terminal and logging setup stay outside the library.
mod args;
mod logging;
mod password;

use args::Args;
use arraysslvpn::{ExposeSecret, VpnClient};
use logging::init_logging;
use std::io;

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
    let config = args::client_config(&args)?;
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
