#![cfg(feature = "system-network")]
use arraysslvpn::{NetworkConfig, NetworkManager, NetworkSettings, network::SystemNetworkManager};

/// Opt in explicitly; creates a temporary TUN and TEST-NET route on this host.
#[tokio::test]
#[ignore = "requires administrator/root, TUN support, and explicit environment opt-in"]
async fn real_tun_route_cleanup() {
    assert_eq!(
        std::env::var("ARRAYSSLVPN_PRIVILEGED_TEST").as_deref(),
        Ok("1")
    );
    let settings = NetworkSettings {
        address: "10.255.254.2".parse().unwrap(),
        prefix_len: 32,
        mtu: 1400,
        include_routes: vec!["192.0.2.0/24".parse().unwrap()],
        exclude_routes: vec![],
        dns_servers: vec![],
        search_domains: vec![],
    };
    let config = NetworkConfig {
        manage_dns: false,
        ..Default::default()
    };
    let mut manager = SystemNetworkManager::default();
    let result = manager
        .setup(&settings, &config, "127.0.0.1:443".parse().unwrap())
        .await;
    // Release the caller's device handle before checking teardown.
    let setup_error = match result {
        Ok(io) => {
            drop(io);
            None
        }
        Err(error) => Some(error),
    };
    // Always attempt rollback even if setup failed.
    manager.cleanup().await.unwrap();
    manager.cleanup().await.unwrap();
    if let Some(error) = setup_error {
        panic!("network setup failed: {error}");
    }
}
