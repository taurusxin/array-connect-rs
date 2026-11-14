// Wire constants and protocol behavior adapted from OpenConnect array.c.
// Copyright 2020 David Woodhouse. SPDX-License-Identifier: LGPL-2.1-only
use super::{
    MAX_CONFIG,
    framing::{MAX_JSON_TRAILER, json_trailer_byte},
};
use crate::{Result, VpnError};
use bytes::{Buf, Bytes, BytesMut};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::DPD;

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
}
