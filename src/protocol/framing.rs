// Wire constants and protocol behavior adapted from OpenConnect array.c.
// Copyright 2020 David Woodhouse. SPDX-License-Identifier: LGPL-2.1-only
use super::MAX_CONFIG;
use crate::{Result, VpnError};
use bytes::{Buf, BytesMut};
use serde_json::Value;

pub(super) const MAX_JSON_TRAILER: usize = 16;

pub(super) fn json_trailer_byte(byte: u8) -> bool {
    matches!(byte, 0 | b' ' | b'\t' | b'\r' | b'\n')
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
    use crate::protocol::{DPD, PacketDecoder, TunnelPacket};

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
