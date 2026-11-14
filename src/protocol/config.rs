// Wire constants and protocol behavior adapted from OpenConnect array.c.
// Copyright 2020 David Woodhouse. SPDX-License-Identifier: LGPL-2.1-only
use crate::{Result, VpnError};
use ipnet::Ipv4Net;
use serde::Serialize;
use serde_json::Value;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NetworkSettings {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
    pub include_routes: Vec<Ipv4Net>,
    pub exclude_routes: Vec<Ipv4Net>,
    pub dns_servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
}

fn le_ip(value: &Value, key: &str) -> Result<Ipv4Addr> {
    let value = value
        .get(key)
        .and_then(Value::as_u64)
        .filter(|v| *v <= u32::MAX as u64)
        .ok_or_else(|| VpnError::Protocol(format!("missing/invalid {key}")))?;
    Ok(Ipv4Addr::from((value as u32).to_le_bytes()))
}

fn prefix(mask: Ipv4Addr) -> Result<u8> {
    let mask = u32::from(mask);
    let ones = mask.leading_ones();
    if mask
        != if ones == 0 {
            0
        } else {
            u32::MAX << (32 - ones)
        }
    {
        return Err(VpnError::Protocol("non-contiguous IPv4 mask".into()));
    }
    Ok(ones as u8)
}

fn routes(value: &Value, key: &str) -> Result<Vec<Ipv4Net>> {
    let Some(object) = value.get(key) else {
        return Ok(vec![]);
    };
    if !object.is_object() {
        return Err(VpnError::Protocol(format!("invalid {key}")));
    }
    if object
        .get("ipv6")
        .and_then(Value::as_array)
        .is_some_and(|v| !v.is_empty())
    {
        tracing::warn!(
            element = key,
            "IPv6 route configuration is not supported in this release"
        );
    }
    let Some(list) = object.get("ipv4") else {
        return Ok(vec![]);
    };
    list.as_array()
        .ok_or_else(|| VpnError::Protocol(format!("invalid {key}.ipv4")))?
        .iter()
        .map(|route| {
            Ok(
                Ipv4Net::new(le_ip(route, "ip")?, prefix(le_ip(route, "mask")?)?)
                    .expect("validated prefix")
                    .trunc(),
            )
        })
        .collect()
}

pub fn parse_network_settings(value: &Value, mtu: u16) -> Result<NetworkSettings> {
    if !value.is_object() {
        return Err(VpnError::Protocol("configuration must be an object".into()));
    }
    let mut settings = NetworkSettings {
        address: le_ip(value, "client_ipv4")?,
        prefix_len: prefix(le_ip(value, "client_ipv4_mask")?)?,
        mtu,
        include_routes: routes(value, "include_network_resource")?,
        exclude_routes: routes(value, "exclude_network_resource")?,
        dns_servers: vec![],
        search_domains: vec![],
    };
    if settings.address.is_unspecified()
        || settings.address.is_multicast()
        || settings.address.is_broadcast()
    {
        return Err(VpnError::Protocol("invalid assigned IPv4 address".into()));
    }
    if let Some(dns) = value.get("dns_servers") {
        for item in dns
            .as_array()
            .ok_or_else(|| VpnError::Protocol("invalid dns_servers".into()))?
        {
            if let Some(v4) = item.get("ipv4") {
                for address in v4
                    .as_array()
                    .ok_or_else(|| VpnError::Protocol("invalid DNS ipv4 list".into()))?
                {
                    let address = le_ip(&serde_json::json!({"ip": address}), "ip")?;
                    if address.is_unspecified() || address.is_multicast() {
                        return Err(VpnError::Protocol("invalid DNS address".into()));
                    }
                    if !settings.dns_servers.contains(&IpAddr::V4(address)) {
                        settings.dns_servers.push(address.into());
                    }
                }
            }
            if item
                .get("ipv6")
                .and_then(Value::as_array)
                .is_some_and(|v| !v.is_empty())
            {
                tracing::warn!(
                    "IPv6 DNS servers ignored until IPv6 network configuration is supported"
                );
            }
        }
    }
    if let Some(domains) = value.get("search_domains") {
        for domain in domains
            .as_array()
            .ok_or_else(|| VpnError::Protocol("invalid search_domains".into()))?
        {
            let domain = domain
                .as_str()
                .ok_or_else(|| VpnError::Protocol("invalid search domain".into()))?;
            if domain.is_empty()
                || domain.len() > 253
                || !domain
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
            {
                return Err(VpnError::Protocol(
                    "invalid search domain characters".into(),
                ));
            }
            settings.search_domains.push(domain.into());
        }
    }
    for key in value.as_object().expect("checked").keys() {
        if ![
            "client_ipv4",
            "client_ipv4_mask",
            "include_network_resource",
            "exclude_network_resource",
            "dns_servers",
            "search_domains",
            "proxy_script",
        ]
        .contains(&key.as_str())
        {
            tracing::debug!(element = key, "unhandled Array configuration element");
        }
    }
    Ok(settings)
}

pub(crate) fn parse_dpd(value: &Value) -> Result<Option<Duration>> {
    if !value.is_object() {
        return Err(VpnError::Protocol(
            "speed tunnel config must be an object".into(),
        ));
    }
    let interval = value
        .get("keepalive_interval")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    tracing::debug!(allow_speed_tunnel = ?value.get("allow_speed_tunnel"), interval, "speed tunnel settings (DTLS deferred)");
    Ok((interval != 0).then(|| Duration::from_secs(interval.min(86400))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endian_and_mask() {
        let config = serde_json::json!({"client_ipv4":67305985,"client_ipv4_mask":16777215,
            "include_network_resource":{"ipv4":[{"ip":10,"mask":255}]},
            "dns_servers":[{"ipv4":[134744072]}]});
        let settings = parse_network_settings(&config, 1400).unwrap();
        assert_eq!(settings.address, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(settings.prefix_len, 24);
        assert_eq!(settings.include_routes[0].to_string(), "10.0.0.0/8");
        assert_eq!(settings.dns_servers[0].to_string(), "8.8.8.8");
        assert!(prefix(Ipv4Addr::new(255, 0, 255, 0)).is_err());
    }
}
