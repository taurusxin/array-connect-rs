// Wire constants and protocol behavior adapted from OpenConnect array.c.
// Copyright 2020 David Woodhouse. SPDX-License-Identifier: LGPL-2.1-only
use crate::{Result, VpnError};
use bytes::{Buf, Bytes, BytesMut};
use ipnet::Ipv4Net;
use serde::Serialize;
use serde_json::Value;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

pub(crate) const CONF50: [u8; 16] = [0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
pub(crate) const CONF54: [u8; 48] = [
    0x54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 1, 0, 0, 0, 10, 0, 2, 15, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x52, 0x54, 0, 0xde, 0xa2, 0xa6, 0, 0,
];
pub(crate) const DPD: [u8; 20] = [
    0x45, 0, 0, 20, 0, 0, 0, 0, 0, 0xff, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
];
pub(crate) const MAX_CONFIG: usize = 1024 * 1024;
const MAX_JSON_TRAILER: usize = 16;

fn json_trailer_byte(byte: u8) -> bool {
    matches!(byte, 0 | b' ' | b'\t' | b'\r' | b'\n')
}

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

#[derive(Debug, PartialEq, Eq)]
pub enum TunnelPacket {
    Ip(Bytes),
    Control { kind: u16, data: Bytes },
}

/// Incremental raw IP stream decoder. TLS record boundaries are irrelevant.
#[derive(Default)]
pub struct PacketDecoder {
    buffer: BytesMut,
    json_trailer: Option<usize>,
}

impl PacketDecoder {
    /// Only the first frame after a valid configuration JSON may have its suffix.
    pub(crate) fn after_json() -> Self {
        Self {
            buffer: BytesMut::new(),
            json_trailer: Some(0),
        }
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        if self.buffer.len() + bytes.len() > MAX_CONFIG {
            return Err(VpnError::Protocol(
                "IP receive buffer limit exceeded".into(),
            ));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }
    pub fn next_packet(&mut self) -> Result<Option<TunnelPacket>> {
        if let Some(skipped) = &mut self.json_trailer {
            while self.buffer.first().is_some_and(|b| json_trailer_byte(*b)) {
                if *skipped == MAX_JSON_TRAILER {
                    return Err(VpnError::Protocol(
                        "JSON trailer exceeds 16 bytes before IP packet".into(),
                    ));
                }
                self.buffer.advance(1);
                *skipped += 1;
            }
            if self.buffer.is_empty() {
                return Ok(None);
            }
            if *skipped != 0 {
                tracing::debug!(
                    length = *skipped,
                    "consumed Array JSON trailer before IP stream"
                );
            }
            self.json_trailer = None;
        }
        if self.buffer.is_empty() {
            return Ok(None);
        }
        let (len, min_header) = match self.buffer[0] >> 4 {
            4 => {
                if self.buffer.len() < 4 {
                    return Ok(None);
                }
                let header = ((self.buffer[0] & 15) as usize) * 4;
                if header < 20 {
                    return Err(VpnError::Protocol("invalid IPv4 header length".into()));
                }
                (
                    u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as usize,
                    header,
                )
            }
            6 => {
                if self.buffer.len() < 6 {
                    return Ok(None);
                }
                (
                    40 + u16::from_be_bytes([self.buffer[4], self.buffer[5]]) as usize,
                    40,
                )
            }
            _ => return Err(VpnError::Protocol("unknown IP version in tunnel".into())),
        };
        if len < min_header || len > 65575 {
            return Err(VpnError::Protocol("invalid tunnel IP packet length".into()));
        }
        if self.buffer.len() < len {
            return Ok(None);
        }
        let data = self.buffer.split_to(len).freeze();
        if data[0] == 0x45 && data[9] == 0xff {
            Ok(Some(TunnelPacket::Control {
                kind: u16::from_be_bytes([data[12], data[13]]),
                data,
            }))
        } else {
            Ok(Some(TunnelPacket::Ip(data)))
        }
    }
}

pub(crate) fn take_json(buffer: &mut BytesMut, after_json: bool) -> Result<Option<Value>> {
    if buffer.len() > MAX_CONFIG {
        return Err(VpnError::Protocol("JSON configuration too large".into()));
    }
    let mut skipped = 0;
    loop {
        if buffer.len() <= 16 + skipped {
            return Ok(None);
        }
        if buffer[16 + skipped] == b'{' {
            break;
        }
        if !after_json || skipped == MAX_JSON_TRAILER || !json_trailer_byte(buffer[skipped]) {
            return Err(VpnError::Protocol(format!(
                "JSON object missing after 16-byte header (next byte 0x{:02x}, prior JSON trailer bytes {skipped})",
                buffer[16 + skipped]
            )));
        }
        // Shift a bounded candidate header only across validated prior-JSON
        // suffix bytes. Do not strip zeros blindly: the header may be all zero.
        skipped += 1;
    }
    let mut stream =
        serde_json::Deserializer::from_slice(&buffer[16 + skipped..]).into_iter::<Value>();
    match stream.next() {
        Some(Ok(value)) => {
            let len = skipped + 16 + stream.byte_offset();
            buffer.advance(len);
            if skipped != 0 {
                tracing::debug!(
                    length = skipped,
                    "consumed Array JSON trailer before configuration"
                );
            }
            Ok(Some(value))
        }
        Some(Err(e)) if e.is_eof() => Ok(None),
        Some(Err(_)) => Err(VpnError::Protocol("malformed configuration JSON".into())),
        None => Ok(None),
    }
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
    #[test]
    fn fragmented_and_coalesced_packets() {
        let mut ip = DPD;
        ip[9] = 1;
        let mut decoder = PacketDecoder::default();
        for b in &ip[..19] {
            decoder.push(&[*b]).unwrap();
            assert!(decoder.next_packet().unwrap().is_none());
        }
        decoder.push(&[ip[19]]).unwrap();
        decoder.push(&DPD).unwrap();
        assert!(matches!(
            decoder.next_packet().unwrap(),
            Some(TunnelPacket::Ip(_))
        ));
        assert!(matches!(
            decoder.next_packet().unwrap(),
            Some(TunnelPacket::Control { kind: 1, .. })
        ));
        assert!(decoder.next_packet().unwrap().is_none());
    }
    #[test]
    fn ipv6_and_bad_lengths() {
        let mut packet = [0; 40];
        packet[0] = 0x60;
        let mut d = PacketDecoder::default();
        d.push(&packet).unwrap();
        assert!(matches!(
            d.next_packet().unwrap(),
            Some(TunnelPacket::Ip(_))
        ));
        d.push(&[0x45, 0, 0, 1]).unwrap();
        assert!(d.next_packet().is_err());
    }
    #[test]
    fn json_preserves_tail() {
        let mut b = BytesMut::from(&[0; 16][..]);
        b.extend_from_slice(b"{\"a\":");
        assert!(take_json(&mut b, false).unwrap().is_none());
        b.extend_from_slice(b"1}TAIL");
        assert_eq!(take_json(&mut b, false).unwrap().unwrap()["a"], 1);
        assert_eq!(&b[..], b"TAIL");
    }

    #[test]
    fn json_trailers_across_configuration_and_packets() {
        let trailers: Vec<Vec<u8>> = vec![
            vec![],
            vec![0],
            vec![0; 4],
            b"\r\n".to_vec(),
            b" \t\r\n\0".to_vec(),
            vec![0; 16],
        ];
        for trailer in trailers {
            for tag in [0, 0x55, b' '] {
                for fragmented in [false, true] {
                    let mut input = vec![0; 16];
                    input.extend_from_slice(br#"{"value":"quoted \" } [","speed":1}"#);
                    input.extend_from_slice(&trailer);
                    let mut header = [0; 16];
                    header[0] = tag;
                    input.extend_from_slice(&header);
                    input.extend_from_slice(br#"{"client":2}"#);
                    input.extend_from_slice(&trailer);
                    let mut ip = DPD;
                    ip[9] = 17;
                    input.extend_from_slice(&ip);
                    input.extend_from_slice(&ip);
                    let mut buffer = BytesMut::new();
                    let mut stage = 0;
                    let mut packets = PacketDecoder::after_json();
                    let mut received = 0;
                    for chunk in input.chunks(if fragmented { 1 } else { input.len() }) {
                        buffer.extend_from_slice(chunk);
                        while stage < 2 {
                            let Some(value) = take_json(&mut buffer, stage != 0).unwrap() else {
                                break;
                            };
                            if stage == 0 {
                                assert_eq!(value["speed"], 1);
                            } else {
                                assert_eq!(value["client"], 2);
                            }
                            stage += 1;
                        }
                        if stage == 2 {
                            packets.push(&buffer.split()).unwrap();
                            while let Some(packet) = packets.next_packet().unwrap() {
                                assert!(
                                    matches!(packet, TunnelPacket::Ip(data) if data.as_ref() == ip)
                                );
                                received += 1;
                            }
                        }
                    }
                    assert_eq!(
                        (stage, received),
                        (2, 2),
                        "tag={tag}, trailer={trailer:?}, fragmented={fragmented}"
                    );
                }
            }
        }
    }

    #[test]
    fn json_suffix_handling_is_bounded_and_only_at_transitions() {
        let mut frame = vec![0; 16];
        frame.extend_from_slice(b"{}");
        for prefix in [b"bad".to_vec(), vec![0; 17]] {
            let mut data = BytesMut::from(prefix.as_slice());
            data.extend_from_slice(&frame);
            assert!(take_json(&mut data, true).is_err());
        }
        let mut first = BytesMut::from(&[0][..]);
        first.extend_from_slice(&frame);
        assert!(
            take_json(&mut first, false).is_err(),
            "first JSON frame must not resynchronize"
        );
        let mut malformed = BytesMut::from(&[0; 16][..]);
        malformed.extend_from_slice(br#"{"invalid":]}"#);
        assert!(take_json(&mut malformed, true).is_err());
        let mut ip = DPD;
        ip[9] = 17;
        let mut packets = PacketDecoder::after_json();
        packets.push(&ip).unwrap();
        assert!(packets.next_packet().unwrap().is_some());
        packets.push(&[0]).unwrap();
        assert!(
            packets.next_packet().is_err(),
            "established packet stream must reject a NUL"
        );
        let mut packets = PacketDecoder::after_json();
        packets.push(&[0; 17]).unwrap();
        assert!(packets.next_packet().is_err());
    }
}
