use crate::{NetworkConfig, NetworkSettings, Result, VpnError};
use ipnet::Ipv4Net;
use route_manager::{Route, RouteManager};
use std::net::IpAddr;
use tun_rs::AsyncDevice;
use windows_sys::{
    Win32::NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
    core::GUID,
};

pub struct Platform {
    manager: RouteManager,
    bypass: Option<Route>,
    added: Vec<Route>,
    dns: Option<DnsSnapshot>,
}

// Snapshots own Rust strings, never borrowed pointers returned by Windows.
struct DnsSnapshot {
    guid: GUID,
    nameservers: Vec<u16>,
    search: Vec<u16>,
}

impl DnsSnapshot {
    fn restore_settings(&mut self) -> DNS_INTERFACE_SETTINGS {
        // A selected field must point to a NUL-terminated string. An empty
        // string clears the override (including restoring automatic DNS);
        // a NULL pointer with that field's flag set is invalid (ERROR 87).
        DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: (DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST) as u64,
            NameServer: self.nameservers.as_mut_ptr(),
            SearchList: self.search.as_mut_ptr(),
            ..Default::default()
        }
    }
}

fn check(operation: &str, code: u32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(VpnError::Network(format!(
            "Windows {operation}: {}",
            std::io::Error::from_raw_os_error(code as i32)
        )))
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
unsafe fn copy_wide(pointer: *const u16) -> Vec<u16> {
    if pointer.is_null() {
        return vec![0];
    }
    let mut len = 0;
    // Windows owns this NUL-terminated buffer until FreeInterfaceDnsSettings.
    unsafe {
        while *pointer.add(len) != 0 {
            len += 1;
        }
        std::slice::from_raw_parts(pointer, len + 1).to_vec()
    }
}

pub fn ensure_new_interface(name: &str) -> Result<()> {
    let mut luid = NET_LUID_LH::default();
    if unsafe { ConvertInterfaceAliasToLuid(wide(name).as_ptr(), &mut luid) } == 0 {
        return Err(VpnError::Network(
            "interface already exists; choose a fresh interface name".into(),
        ));
    }
    Ok(())
}
impl Platform {
    pub fn new(endpoint: IpAddr, manage_routes: bool) -> Result<Self> {
        let mut manager = RouteManager::new()?;
        let bypass = if manage_routes {
            let original = manager.find_route(&endpoint)?.ok_or_else(|| {
                VpnError::Network("no existing route to VPN/ proxy endpoint".into())
            })?;
            let mut route = Route::new(endpoint, if endpoint.is_ipv4() { 32 } else { 128 });
            if let Some(index) = original.if_index() {
                route = route.with_if_index(index);
            }
            if let Some(luid) = original.luid() {
                route = route.with_luid(luid);
            }
            if let Some(gateway) = original.gateway() {
                route = route.with_gateway(gateway);
            }
            Some(route.with_metric(1))
        } else {
            None
        };
        Ok(Self {
            manager,
            bypass,
            added: vec![],
            dns: None,
        })
    }
    fn add(&mut self, route: Route) -> Result<()> {
        let existing = self.manager.list()?;
        if existing.iter().any(|r| {
            r.destination() == route.destination()
                && r.prefix() == route.prefix()
                && r.if_index() == route.if_index()
                && r.gateway() == route.gateway()
        }) {
            return Ok(());
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
                    .with_if_index(device.if_index()?)
                    .with_metric(1),
            )?;
        }
        if config.manage_dns && !settings.dns_servers.is_empty() {
            let luid = device.if_luid()?;
            let mut guid = GUID::from_u128(0);
            check("ConvertInterfaceLuidToGuid", unsafe {
                ConvertInterfaceLuidToGuid(
                    std::ptr::from_ref(&luid).cast::<NET_LUID_LH>(),
                    &mut guid,
                )
            })?;
            let mut old = DNS_INTERFACE_SETTINGS {
                Version: DNS_INTERFACE_SETTINGS_VERSION1,
                ..Default::default()
            };
            check("GetInterfaceDnsSettings", unsafe {
                GetInterfaceDnsSettings(guid, &mut old)
            })?;
            let snapshot = unsafe {
                DnsSnapshot {
                    guid,
                    nameservers: if old.Flags & DNS_SETTING_NAMESERVER as u64 != 0 {
                        copy_wide(old.NameServer)
                    } else {
                        wide("")
                    },
                    search: if old.Flags & DNS_SETTING_SEARCHLIST as u64 != 0 {
                        copy_wide(old.SearchList)
                    } else {
                        wide("")
                    },
                }
            };
            unsafe { FreeInterfaceDnsSettings(&mut old) };
            self.dns = Some(snapshot);
            let mut nameservers = wide(
                &settings
                    .dns_servers
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
            let mut search = wide(&settings.search_domains.join(","));
            let new = DNS_INTERFACE_SETTINGS {
                Version: DNS_INTERFACE_SETTINGS_VERSION1,
                Flags: (DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST) as u64,
                NameServer: nameservers.as_mut_ptr(),
                SearchList: search.as_mut_ptr(),
                ..Default::default()
            };
            check("SetInterfaceDnsSettings(apply)", unsafe {
                SetInterfaceDnsSettings(guid, &new)
            })?;
        }
        Ok(())
    }
    pub fn cleanup(&mut self) -> Result<()> {
        let mut errors = vec![];
        if let Some(snapshot) = &mut self.dns {
            let old = snapshot.restore_settings();
            match check("SetInterfaceDnsSettings(restore)", unsafe {
                SetInterfaceDnsSettings(snapshot.guid, &old)
            }) {
                Ok(()) => self.dns = None,
                Err(VpnError::Network(reason)) => errors.push(reason),
                Err(error) => errors.push(error.to_string()),
            }
        }
        let mut failed = vec![];
        for route in self.added.drain(..).rev() {
            if let Err(error) = self.manager.delete(&route)
                && error.raw_os_error() != Some(1168)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                errors.push(error.to_string());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restoring_automatic_dns_uses_empty_strings_for_selected_fields() {
        let mut snapshot = DnsSnapshot {
            guid: GUID::from_u128(0),
            nameservers: wide(""),
            search: wide(""),
        };
        let settings = snapshot.restore_settings();
        assert_eq!(
            settings.Flags,
            (DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST) as u64
        );
        assert!(!settings.NameServer.is_null());
        assert!(!settings.SearchList.is_null());
        assert_eq!(unsafe { *settings.NameServer }, 0);
        assert_eq!(unsafe { *settings.SearchList }, 0);
    }

    #[test]
    fn restoring_static_dns_preserves_owned_utf16_buffers() {
        let mut snapshot = DnsSnapshot {
            guid: GUID::from_u128(0),
            nameservers: wide("10.0.0.53,10.0.0.54"),
            search: wide("corp.example,研发.example"),
        };
        let settings = snapshot.restore_settings();
        assert_eq!(
            unsafe { copy_wide(settings.NameServer) },
            wide("10.0.0.53,10.0.0.54")
        );
        assert_eq!(
            unsafe { copy_wide(settings.SearchList) },
            wide("corp.example,研发.example")
        );
    }
}
