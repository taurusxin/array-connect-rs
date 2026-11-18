use crate::{NetworkConfig, NetworkSettings, Result, VpnError};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

pub(super) const MAX_REQUEST: usize = 256 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Setup {
    pub settings: NetworkSettings,
    pub config: NetworkConfig,
    pub endpoint: SocketAddr,
}

impl Setup {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_REQUEST {
            return Err(VpnError::Network(
                "invalid network service request size".into(),
            ));
        }
        let request: Self = serde_json::from_slice(bytes)
            .map_err(|_| VpnError::Network("invalid network service request".into()))?;
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<()> {
        let settings = &self.settings;
        if settings.address.is_unspecified()
            || settings.address.is_multicast()
            || settings.address.is_broadcast()
            || settings.prefix_len > 32
            || settings.mtu < 576
            || settings.mtu != self.config.mtu
            || self.endpoint.port() == 0
            || self.endpoint.ip().is_unspecified()
            || self.endpoint.ip().is_multicast()
        {
            return Err(VpnError::Network(
                "invalid utun address, MTU or endpoint".into(),
            ));
        }
        if self.config.interface_name.as_ref().is_some_and(|name| {
            name.strip_prefix("utun").is_none_or(|index| {
                index.is_empty()
                    || !index.bytes().all(|byte| byte.is_ascii_digit())
                    || index.parse::<i32>().is_err()
            })
        }) {
            return Err(VpnError::Network(
                "interface name must be utun followed by a number".into(),
            ));
        }
        let routes = settings.include_routes.len()
            + settings.exclude_routes.len()
            + self.config.include_routes.len()
            + self.config.exclude_routes.len();
        if routes > 4096 || settings.dns_servers.len() > 32 || settings.search_domains.len() > 64 {
            return Err(VpnError::Network(
                "network service configuration is too large".into(),
            ));
        }
        if settings.dns_servers.iter().any(|address| {
            !matches!(address, IpAddr::V4(ip) if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast())
        }) || settings.search_domains.iter().any(|domain| {
            domain.is_empty()
                || domain.len() > 253
                || !domain.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
        }) {
            return Err(VpnError::Network("invalid DNS configuration for the network service".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Setup {
        Setup {
            settings: NetworkSettings {
                address: "10.0.0.2".parse().unwrap(),
                prefix_len: 24,
                mtu: 1400,
                include_routes: vec!["10.0.0.0/24".parse().unwrap()],
                exclude_routes: vec![],
                dns_servers: vec!["10.0.0.53".parse().unwrap()],
                search_domains: vec!["vpn.example.test".into()],
            },
            config: NetworkConfig::default(),
            endpoint: "[2001:db8::9]:443".parse().unwrap(),
        }
    }

    #[test]
    fn typed_configuration_round_trips_and_rejects_unexpected_fields() {
        let request = request();
        let mut value = serde_json::to_value(&request).unwrap();
        let good = serde_json::to_vec(&value).unwrap();
        assert_eq!(Setup::decode(&good).unwrap().settings, request.settings);
        value["config"]["extra"] = serde_json::json!("unexpected");
        assert!(Setup::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(Setup::decode(&vec![b' '; MAX_REQUEST + 1]).is_err());
    }

    #[test]
    fn validates_network_fields_before_any_privileged_operation() {
        let mut request = request();
        request.settings.search_domains = vec!["vpn.example.test\nquit".into()];
        assert!(Setup::decode(&serde_json::to_vec(&request).unwrap()).is_err());
        request.settings.search_domains.clear();
        request.config.interface_name = Some("en0".into());
        assert!(Setup::decode(&serde_json::to_vec(&request).unwrap()).is_err());
        request.config.interface_name = Some("utun42".into());
        request.settings.mtu = 577;
        assert!(Setup::decode(&serde_json::to_vec(&request).unwrap()).is_err());
    }
}
