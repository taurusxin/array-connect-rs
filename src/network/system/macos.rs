use super::command;
use crate::{NetworkConfig, NetworkSettings, Result, VpnError};
use ipnet::{IpNet, Ipv4Net};
use route_manager::{Route, RouteManager};
use std::net::IpAddr;
use tun_rs::AsyncDevice;

pub struct Platform {
    manager: RouteManager,
    bypass: Option<Route>,
    added: Vec<Route>,
    dns_key: Option<String>,
}
pub fn ensure_new_interface(name: &str) -> Result<()> {
    let raw = command("/sbin/ifconfig", &["-l".into()], None)?;
    if raw.split_whitespace().any(|n| n == name) {
        return Err(VpnError::Network("interface already exists".into()));
    }
    Ok(())
}
impl Platform {
    pub fn new(endpoint: IpAddr, manage_routes: bool) -> Result<Self> {
        let mut manager = RouteManager::new()?;
        let bypass = if manage_routes {
            let original = manager
                .list()?
                .into_iter()
                .filter(|r| !r.if_scope())
                .filter(|r| {
                    IpNet::new(r.destination(), r.prefix()).is_ok_and(|n| n.contains(&endpoint))
                })
                .max_by_key(|r| r.prefix())
                .ok_or_else(|| {
                    VpnError::Network("no existing route to VPN/proxy endpoint".into())
                })?;
            let mut route = Route::new(endpoint, if endpoint.is_ipv4() { 32 } else { 128 });
            if let Some(gateway) = original.gateway() {
                route = route.with_gateway(gateway);
            }
            if let Some(index) = original.if_index() {
                route = route.with_if_index(index);
            }
            Some(route)
        } else {
            None
        };
        Ok(Self {
            manager,
            bypass,
            added: vec![],
            dns_key: None,
        })
    }
    fn add(&mut self, route: Route) -> Result<()> {
        let list = self.manager.list()?;
        if let Some(old) = list.iter().find(|r| {
            r.destination() == route.destination() && r.prefix() == route.prefix() && !r.if_scope()
        }) {
            if old.gateway() == route.gateway() && old.if_index() == route.if_index() {
                return Ok(());
            }
            return Err(VpnError::Network(
                "conflicting existing route; refusing to replace it".into(),
            ));
        }
        self.manager.add(&route)?;
        self.added.push(route);
        Ok(())
    }
    pub fn configure(
        &mut self,
        device: &AsyncDevice,
        settings: &NetworkSettings,
        config: &NetworkConfig,
        routes: &[Ipv4Net],
    ) -> Result<()> {
        if let Some(bypass) = self.bypass.take() {
            self.add(bypass)?;
        }
        for route in routes {
            self.add(
                Route::new(route.network().into(), route.prefix_len())
                    .with_if_index(device.if_index()?),
            )?;
        }
        if config.manage_dns && !settings.dns_servers.is_empty() {
            let name = device.name()?;
            let key = format!(
                "State:/Network/Service/arraysslvpn-{:016x}/DNS",
                rand::random::<u64>()
            );
            self.dns_key = Some(key.clone());
            let dns = settings
                .dns_servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            let search = settings.search_domains.join(" ");
            // Per-session dynamic-store service; leave physical services intact.
            let mut input = format!(
                "open\nd.init\nd.add ServerAddresses * {dns}\nd.add InterfaceName {name}\nd.add SupplementalMatchDomains * \"\"\nd.add SupplementalMatchOrders * # 1\n"
            );
            if !search.is_empty() {
                input.push_str(&format!("d.add SearchDomains * {search}\n"));
            }
            input.push_str(&format!("set {key}\nquit\n"));
            command("/usr/sbin/scutil", &[], Some(&input))?;
            let verify = command(
                "/usr/sbin/scutil",
                &[],
                Some(&format!("open\nshow {key}\nquit\n")),
            )?;
            if !verify.contains("ServerAddresses") {
                return Err(VpnError::Network("scutil failed to install VPN DNS".into()));
            }
        }
        Ok(())
    }
    pub fn cleanup(&mut self) -> Result<()> {
        let mut errors = vec![];
        if let Some(key) = &self.dns_key {
            match command(
                "/usr/sbin/scutil",
                &[],
                Some(&format!("open\nremove {key}\nquit\n")),
            ) {
                Ok(_) => {
                    match command(
                        "/usr/sbin/scutil",
                        &[],
                        Some(&format!("open\nshow {key}\nquit\n")),
                    ) {
                        Ok(verify) if verify.contains("ServerAddresses") => {
                            errors.push("scutil did not remove VPN DNS".into())
                        }
                        Ok(_) => self.dns_key = None,
                        Err(error) => errors.push(error.to_string()),
                    }
                }
                Err(e) => errors.push(e.to_string()),
            }
        }
        let mut failed = vec![];
        for route in self.added.drain(..).rev() {
            let still_owned = match self.manager.list() {
                Ok(list) => list.iter().any(|r| {
                    r.destination() == route.destination()
                        && r.prefix() == route.prefix()
                        && r.if_index() == route.if_index()
                        && r.gateway() == route.gateway()
                        && r.if_scope() == route.if_scope()
                }),
                Err(error) => {
                    errors.push(error.to_string());
                    failed.push(route);
                    continue;
                }
            };
            if !still_owned {
                continue;
            }
            if let Err(e) = self.manager.delete(&route)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                errors.push(e.to_string());
                failed.push(route);
            }
        }
        self.added = failed;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(VpnError::Network(errors.join("; ")))
        }
    }
}
