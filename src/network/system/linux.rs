use super::command;
use crate::{NetworkConfig, NetworkSettings, Result, VpnError};
use ipnet::Ipv4Net;
use std::net::IpAddr;
use tun_rs::AsyncDevice;

pub struct Platform {
    bypass: Option<Vec<String>>,
    added: Vec<Vec<String>>,
    dns: Option<(String, bool)>,
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}
pub fn ensure_new_interface(name: &str) -> Result<()> {
    if std::path::Path::new("/sys/class/net").join(name).exists() {
        return Err(VpnError::Network("interface already exists".into()));
    }
    Ok(())
}
impl Platform {
    pub fn new(endpoint: IpAddr, manage_routes: bool) -> Result<Self> {
        let bypass = if manage_routes {
            let raw = command(
                "ip",
                &args(&["-j", "route", "get", &endpoint.to_string()]),
                None,
            )?;
            let list: serde_json::Value = serde_json::from_str(&raw)?;
            let route = list
                .get(0)
                .ok_or_else(|| VpnError::Network("no route to VPN/proxy endpoint".into()))?;
            let dev = route
                .get("dev")
                .and_then(|v| v.as_str())
                .ok_or_else(|| VpnError::Network("missing endpoint egress interface".into()))?;
            let mut a = args(&[
                "route",
                "add",
                &format!("{endpoint}/{}", if endpoint.is_ipv4() { 32 } else { 128 }),
            ]);
            if let Some(gateway) = route.get("gateway").and_then(|v| v.as_str()) {
                a.extend(args(&["via", gateway]));
            }
            a.extend(args(&["dev", dev]));
            Some(a)
        } else {
            None
        };
        Ok(Self {
            bypass,
            added: vec![],
            dns: None,
        })
    }
    fn add(&mut self, a: Vec<String>) -> Result<()> {
        // Do not replace an existing route. An identical pre-existing host route
        // is already a suitable bypass and must not be removed during cleanup.
        let dest = a.get(2).expect("destination");
        let existing = command("ip", &args(&["-j", "route", "show", "exact", dest]), None)?;
        let existing: serde_json::Value = serde_json::from_str(&existing)?;
        if existing.as_array().is_some_and(|v| !v.is_empty()) {
            let dev = a.windows(2).find(|v| v[0] == "dev").map(|v| v[1].as_str());
            if existing
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r.get("dev").and_then(|v| v.as_str()) == dev)
            {
                return Ok(());
            }
            return Err(VpnError::Network(format!(
                "route {dest} already exists on another interface"
            )));
        }
        command("ip", &a, None)?;
        self.added.push(a);
        Ok(())
    }
    pub fn configure(
        &mut self,
        device: &AsyncDevice,
        settings: &NetworkSettings,
        config: &NetworkConfig,
        routes: &[Ipv4Net],
    ) -> Result<()> {
        let name = device.name()?;
        if let Some(bypass) = self.bypass.take() {
            self.add(bypass)?;
        }
        for route in routes {
            self.add(args(&["route", "add", &route.to_string(), "dev", &name]))?;
        }
        if config.manage_dns && !settings.dns_servers.is_empty() {
            let dns = settings
                .dns_servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            // Probe before taking ownership of any resolver configuration.
            if command("resolvectl", &args(&["status"]), None).is_ok() {
                self.dns = Some((name.clone(), true));
                let mut a = args(&["dns", &name]);
                a.extend(dns);
                command("resolvectl", &a, None)?;
                let mut a = args(&["domain", &name]);
                a.extend(settings.search_domains.clone());
                a.push("~.".into());
                command("resolvectl", &a, None)?;
            } else {
                command("resolvconf", &args(&["-l"]), None).map_err(|_| {
                    VpnError::Network("DNS requires resolvectl/resolvconf, or --no-dns".into())
                })?;
                let key = format!("{name}.arraysslvpn");
                self.dns = Some((key.clone(), false));
                let mut input = dns
                    .iter()
                    .map(|s| format!("nameserver {s}\n"))
                    .collect::<String>();
                if !settings.search_domains.is_empty() {
                    input.push_str(&format!("search {}\n", settings.search_domains.join(" ")));
                }
                command(
                    "resolvconf",
                    &args(&["-a", &key, "-m", "0", "-x"]),
                    Some(&input),
                )
                .map_err(|e| {
                    VpnError::Network(format!(
                        "DNS requires resolvectl/resolvconf, or --no-dns: {e}"
                    ))
                })?;
            }
        }
        Ok(())
    }
    pub fn cleanup(&mut self) -> Result<()> {
        let mut errors = vec![];
        if let Some((name, resolved)) = &self.dns {
            let result = if *resolved {
                command("resolvectl", &args(&["revert", name]), None)
            } else {
                command("resolvconf", &args(&["-d", name]), None)
            };
            match result {
                Ok(_) => self.dns = None,
                Err(e) => errors.push(e.to_string()),
            }
        }
        let mut failed = vec![];
        for mut a in self.added.drain(..).rev() {
            let existing = command("ip", &args(&["-j", "route", "show", "exact", &a[2]]), None)
                .and_then(|raw| {
                    serde_json::from_str::<serde_json::Value>(&raw).map_err(Into::into)
                });
            match existing {
                Ok(existing) => {
                    let dev = a.windows(2).find(|v| v[0] == "dev").map(|v| v[1].as_str());
                    let gateway = a.windows(2).find(|v| v[0] == "via").map(|v| v[1].as_str());
                    if !existing.as_array().is_some_and(|list| {
                        list.iter().any(|r| {
                            r.get("dev").and_then(|v| v.as_str()) == dev
                                && r.get("gateway").and_then(|v| v.as_str()) == gateway
                        })
                    }) {
                        continue;
                    }
                }
                Err(e) => {
                    errors.push(e.to_string());
                    failed.push(a);
                    continue;
                }
            }
            a[1] = "del".into();
            if let Err(e) = command("ip", &a, None) {
                errors.push(e.to_string());
                a[1] = "add".into();
                failed.push(a);
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
