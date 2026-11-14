use crate::{NetworkConfig, NetworkSettings, Result, RouteMode, VpnError};
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr};

/// Compute disjoint tunnel routes; exclusions always take precedence.
/// DNS host routes are added only when DNS management is enabled, and a DNS
/// server explicitly excluded from the tunnel is rejected rather than leaked.
pub fn plan_routes(settings: &NetworkSettings, config: &NetworkConfig) -> Result<Vec<Ipv4Net>> {
    if config.route_mode == RouteMode::None {
        return Ok(vec![]);
    }
    let mut includes = if config.route_mode == RouteMode::Full || settings.include_routes.is_empty()
    {
        vec![Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("valid")]
    } else {
        settings.include_routes.clone()
    };
    includes.extend_from_slice(&config.include_routes);
    let excludes = settings
        .exclude_routes
        .iter()
        .chain(&config.exclude_routes)
        .copied()
        .collect::<Vec<_>>();
    if config.manage_dns {
        for dns in &settings.dns_servers {
            if let IpAddr::V4(dns) = dns {
                if excludes.iter().any(|net| net.contains(dns)) {
                    return Err(VpnError::Network("VPN DNS server conflicts with an excluded route; use --no-dns or adjust exclusions".into()));
                }
                includes.push(Ipv4Net::new(*dns, 32).expect("valid"));
            }
        }
    }
    let mut routes = includes.into_iter().map(|n| n.trunc()).collect::<Vec<_>>();
    for exclude in excludes {
        let mut result = Vec::new();
        for route in routes {
            subtract(route, exclude.trunc(), &mut result);
        }
        routes = result;
        if routes.len() > 4096 {
            return Err(VpnError::Network(
                "route policy exceeds 4096 prefixes".into(),
            ));
        }
    }
    routes.sort_by_key(|net| (net.prefix_len(), u32::from(net.network())));
    let mut result: Vec<Ipv4Net> = Vec::new();
    for route in routes {
        if !result
            .iter()
            .any(|net| net.contains(&route.network()) && net.prefix_len() <= route.prefix_len())
        {
            result.push(route);
        }
    }
    if result.len() > 4096 {
        return Err(VpnError::Network(
            "route policy exceeds 4096 prefixes".into(),
        ));
    }
    // Preserve the physical default route, using more-specific /1 routes.
    if result.first().is_some_and(|n| n.prefix_len() == 0) {
        return Ok(vec![
            "0.0.0.0/1".parse().unwrap(),
            "128.0.0.0/1".parse().unwrap(),
        ]);
    }
    Ok(result)
}

fn subtract(route: Ipv4Net, exclude: Ipv4Net, output: &mut Vec<Ipv4Net>) {
    if exclude.contains(&route.network()) && exclude.prefix_len() <= route.prefix_len() {
        return;
    }
    if !route.contains(&exclude.network()) {
        output.push(route);
        return;
    }
    let prefix = route.prefix_len() + 1;
    let first = Ipv4Net::new(route.network(), prefix).expect("split prefix");
    let second = Ipv4Net::new(
        Ipv4Addr::from(u32::from(route.network()) + (1u32 << (32 - prefix))),
        prefix,
    )
    .expect("split prefix");
    subtract(first, exclude, output);
    subtract(second, exclude, output);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings() -> NetworkSettings {
        NetworkSettings {
            address: "10.0.0.2".parse().unwrap(),
            prefix_len: 32,
            mtu: 1400,
            include_routes: vec![],
            exclude_routes: vec![],
            dns_servers: vec![],
            search_domains: vec![],
        }
    }
    #[test]
    fn exclusions_override_includes_and_full() {
        let mut s = settings();
        s.exclude_routes = vec!["10.0.0.0/8".parse().unwrap()];
        let mut c = NetworkConfig {
            include_routes: vec!["10.2.0.0/16".parse().unwrap()],
            ..Default::default()
        };
        let routes = plan_routes(&s, &c).unwrap();
        assert!(
            !routes
                .iter()
                .any(|r| r.contains(&"10.2.3.4".parse::<Ipv4Addr>().unwrap()))
        );
        assert!(
            routes
                .iter()
                .any(|r| r.contains(&"8.8.8.8".parse::<Ipv4Addr>().unwrap()))
        );
        assert!(routes.len() < 32);
        c.route_mode = RouteMode::None;
        assert!(plan_routes(&s, &c).unwrap().is_empty());
    }
    #[test]
    fn dns_must_be_reachable() {
        let mut s = settings();
        s.include_routes = vec!["10.0.0.0/8".parse().unwrap()];
        s.dns_servers = vec!["192.0.2.53".parse().unwrap()];
        assert!(
            plan_routes(&s, &NetworkConfig::default())
                .unwrap()
                .iter()
                .any(|r| r.to_string() == "192.0.2.53/32")
        );
        s.exclude_routes = vec!["192.0.2.0/24".parse().unwrap()];
        assert!(plan_routes(&s, &NetworkConfig::default()).is_err());
    }
}
