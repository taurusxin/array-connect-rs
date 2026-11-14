// Wire constants and protocol behavior adapted from OpenConnect array.c.
// Copyright 2020 David Woodhouse. SPDX-License-Identifier: LGPL-2.1-only
//! Array configuration messages and raw IP/control packet decoding.
mod config;
mod framing;
mod packet;

pub(crate) use config::parse_dpd;
pub use config::{NetworkSettings, parse_network_settings};
pub(crate) use framing::take_json;
pub use packet::{PacketDecoder, TunnelPacket};

pub(crate) const CONF50: [u8; 16] = [0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
pub(crate) const CONF54: [u8; 48] = [
    0x54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 1, 0, 0, 0, 10, 0, 2, 15, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x52, 0x54, 0, 0xde, 0xa2, 0xa6, 0, 0,
];
pub(crate) const DPD: [u8; 20] = [
    0x45, 0, 0, 20, 0, 0, 0, 0, 0, 0xff, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
];
pub(crate) const MAX_CONFIG: usize = 1024 * 1024;
