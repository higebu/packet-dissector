//! ICMP (Internet Control Message Protocol) dissector.
//!
//! ## References
//! - RFC 792: <https://www.rfc-editor.org/rfc/rfc792>
//! - RFC 950 (updates RFC 792 — Address Mask): <https://www.rfc-editor.org/rfc/rfc950>
//! - RFC 1191 (Path MTU Discovery — updates Type 3 Code 4): <https://www.rfc-editor.org/rfc/rfc1191>
//! - RFC 1256 (Router Discovery): <https://www.rfc-editor.org/rfc/rfc1256>
//! - RFC 2521 (ICMP Security Failures / Photuris): <https://www.rfc-editor.org/rfc/rfc2521>
//! - RFC 4065 (Seamoby Experimental Mobility): <https://www.rfc-editor.org/rfc/rfc4065>
//! - RFC 4884 (Extended ICMP): <https://www.rfc-editor.org/rfc/rfc4884>
//! - RFC 6633 (Deprecation of Source Quench): <https://www.rfc-editor.org/rfc/rfc6633>
//! - RFC 6918 (Deprecation of Type 0-related Query Messages): <https://www.rfc-editor.org/rfc/rfc6918>
//! - RFC 8335 (PROBE — Extended Echo): <https://www.rfc-editor.org/rfc/rfc8335>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Returns a human-readable name for well-known ICMP type values.
fn icmp_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Echo Reply"),
        3 => Some("Destination Unreachable"),
        5 => Some("Redirect"),
        8 => Some("Echo Request"),
        11 => Some("Time Exceeded"),
        12 => Some("Parameter Problem"),
        _ => None,
    }
}

/// Minimum ICMP header size (Type + Code + Checksum + 4 bytes type-specific).
const HEADER_SIZE: usize = 8;
/// Minimum size for Timestamp/Timestamp Reply (Type 13/14): 20 bytes.
const TIMESTAMP_SIZE: usize = 20;
/// Minimum size for Address Mask Request/Reply (Type 17/18): 12 bytes.
const ADDRESS_MASK_SIZE: usize = 12;
/// Minimum IPv4 header size for invoking_packet sub-parsing.
const IPV4_MIN_HEADER: usize = 20;

const FD_TYPE: usize = 0;
const FD_CODE: usize = 1;
const FD_CHECKSUM: usize = 2;
const FD_IDENTIFIER: usize = 3;
const FD_SEQUENCE_NUMBER: usize = 4;
const FD_DATA: usize = 5;
const FD_GATEWAY: usize = 6;
const FD_POINTER: usize = 7;
const FD_LENGTH: usize = 8;
const FD_NEXT_HOP_MTU: usize = 9;
const FD_INVOKING_PACKET: usize = 10;
const FD_NUM_ADDRS: usize = 11;
const FD_ADDR_ENTRY_SIZE: usize = 12;
const FD_LIFETIME: usize = 13;
const FD_ENTRIES: usize = 14;
const FD_ORIGINATE_TIMESTAMP: usize = 15;
const FD_RECEIVE_TIMESTAMP: usize = 16;
const FD_TRANSMIT_TIMESTAMP: usize = 17;
const FD_ADDRESS_MASK: usize = 18;
const FD_SUBTYPE: usize = 19;
const FD_LOCAL: usize = 20;
const FD_STATE: usize = 21;
const FD_ACTIVE: usize = 22;
const FD_IPV4: usize = 23;
const FD_IPV6: usize = 24;

const IPC_VERSION: usize = 0;
const IPC_IHL: usize = 1;
const IPC_TOTAL_LENGTH: usize = 2;
const IPC_PROTOCOL: usize = 3;
const IPC_SRC: usize = 4;
const IPC_DST: usize = 5;

static INVOKING_PACKET_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("ihl", "Internet Header Length", FieldType::U8),
    FieldDescriptor::new("total_length", "Total Length", FieldType::U16),
    FieldDescriptor::new("protocol", "Protocol", FieldType::U8),
    FieldDescriptor::new("src", "Source Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("dst", "Destination Address", FieldType::Ipv4Addr),
];

const REC_ROUTER_ADDRESS: usize = 0;
const REC_PREFERENCE_LEVEL: usize = 1;

static ROUTER_ENTRY_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("router_address", "Router Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("preference_level", "Preference Level", FieldType::U32),
];

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => icmp_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("code", "Code", FieldType::U8),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    FieldDescriptor::new("identifier", "Identifier", FieldType::U16).optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("gateway", "Gateway Internet Address", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("pointer", "Pointer", FieldType::U8).optional(),
    FieldDescriptor::new("length", "Length", FieldType::U8).optional(),
    FieldDescriptor::new("next_hop_mtu", "Next-Hop MTU", FieldType::U16).optional(),
    FieldDescriptor::new("invoking_packet", "Invoking Packet", FieldType::Object)
        .optional()
        .with_children(INVOKING_PACKET_CHILDREN),
    FieldDescriptor::new("num_addrs", "Number of Addresses", FieldType::U8).optional(),
    FieldDescriptor::new("addr_entry_size", "Address Entry Size", FieldType::U8).optional(),
    FieldDescriptor::new("lifetime", "Lifetime", FieldType::U16).optional(),
    FieldDescriptor::new("entries", "Entries", FieldType::Array)
        .optional()
        .with_children(ROUTER_ENTRY_CHILDREN),
    FieldDescriptor::new("originate_timestamp", "Originate Timestamp", FieldType::U32).optional(),
    FieldDescriptor::new("receive_timestamp", "Receive Timestamp", FieldType::U32).optional(),
    FieldDescriptor::new("transmit_timestamp", "Transmit Timestamp", FieldType::U32).optional(),
    FieldDescriptor::new("address_mask", "Address Mask", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("subtype", "Subtype", FieldType::U8).optional(),
    FieldDescriptor::new("local", "Local", FieldType::U8).optional(),
    FieldDescriptor::new("state", "State", FieldType::U8).optional(),
    FieldDescriptor::new("active", "Active", FieldType::U8).optional(),
    FieldDescriptor::new("ipv4", "IPv4", FieldType::U8).optional(),
    FieldDescriptor::new("ipv6", "IPv6", FieldType::U8).optional(),
];

/// ICMP dissector.
pub struct IcmpDissector;

/// Push invoking packet fields as an Object container into buf.
fn push_invoking_packet<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    if data.len() >= IPV4_MIN_HEADER {
        let version = data[0] >> 4;
        let ihl = data[0] & 0x0f;
        let total_length = read_be_u16(data, 2).unwrap_or_default();
        let protocol = data[9];
        let src = [data[12], data[13], data[14], data[15]];
        let dst = [data[16], data[17], data[18], data[19]];

        let obj_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_INVOKING_PACKET],
            FieldValue::Object(0..0),
            offset..offset + data.len(),
        );
        buf.push_field(
            &INVOKING_PACKET_CHILDREN[IPC_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &INVOKING_PACKET_CHILDREN[IPC_IHL],
            FieldValue::U8(ihl),
            offset..offset + 1,
        );
        buf.push_field(
            &INVOKING_PACKET_CHILDREN[IPC_TOTAL_LENGTH],
            FieldValue::U16(total_length),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &INVOKING_PACKET_CHILDREN[IPC_PROTOCOL],
            FieldValue::U8(protocol),
            offset + 9..offset + 10,
        );
        buf.push_field(
            &INVOKING_PACKET_CHILDREN[IPC_SRC],
            FieldValue::Ipv4Addr(src),
            offset + 12..offset + 16,
        );
        buf.push_field(
            &INVOKING_PACKET_CHILDREN[IPC_DST],
            FieldValue::Ipv4Addr(dst),
            offset + 16..offset + 20,
        );
        buf.end_container(obj_idx);
    } else {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_INVOKING_PACKET],
            FieldValue::Bytes(data),
            offset..offset + data.len(),
        );
    }
}

impl Dissector for IcmpDissector {
    fn name(&self) -> &'static str {
        "Internet Control Message Protocol"
    }
    fn short_name(&self) -> &'static str {
        "ICMP"
    }
    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        let icmp_type = data[0];
        let code = data[1];
        let checksum = read_be_u16(data, 2)?;

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + data.len(),
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TYPE],
            FieldValue::U8(icmp_type),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CODE],
            FieldValue::U8(code),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM],
            FieldValue::U16(checksum),
            offset + 2..offset + 4,
        );

        match icmp_type {
            // Echo Reply (0) / Echo Request (8)
            0 | 8 => {
                let identifier = read_be_u16(data, 4)?;
                let sequence_number = read_be_u16(data, 6)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                    FieldValue::U16(sequence_number),
                    offset + 6..offset + 8,
                );
                if data.len() > HEADER_SIZE {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_DATA],
                        FieldValue::Bytes(&data[HEADER_SIZE..]),
                        offset + HEADER_SIZE..offset + data.len(),
                    );
                }
            }
            // Destination Unreachable (3)
            // Safe: HEADER_SIZE check (8 bytes) guarantees indices 0..7
            3 => {
                let length = data[5];
                if length > 0 {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_LENGTH],
                        FieldValue::U8(length),
                        offset + 5..offset + 6,
                    );
                }
                if code == 4 {
                    let next_hop_mtu = read_be_u16(data, 6)?;
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_NEXT_HOP_MTU],
                        FieldValue::U16(next_hop_mtu),
                        offset + 6..offset + 8,
                    );
                }
                if data.len() > HEADER_SIZE {
                    push_invoking_packet(buf, &data[HEADER_SIZE..], offset + HEADER_SIZE);
                }
            }
            // Source Quench (4)
            4 => {
                if data.len() > HEADER_SIZE {
                    push_invoking_packet(buf, &data[HEADER_SIZE..], offset + HEADER_SIZE);
                }
            }
            // Time Exceeded (11)
            // Safe: HEADER_SIZE check (8 bytes) guarantees indices 0..7
            11 => {
                let length = data[5];
                if length > 0 {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_LENGTH],
                        FieldValue::U8(length),
                        offset + 5..offset + 6,
                    );
                }
                if data.len() > HEADER_SIZE {
                    push_invoking_packet(buf, &data[HEADER_SIZE..], offset + HEADER_SIZE);
                }
            }
            // Redirect (5)
            5 => {
                let gateway = [data[4], data[5], data[6], data[7]];
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_GATEWAY],
                    FieldValue::Ipv4Addr(gateway),
                    offset + 4..offset + 8,
                );
                if data.len() > HEADER_SIZE {
                    push_invoking_packet(buf, &data[HEADER_SIZE..], offset + HEADER_SIZE);
                }
            }
            // Parameter Problem (12)
            12 => {
                let pointer = data[4];
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_POINTER],
                    FieldValue::U8(pointer),
                    offset + 4..offset + 5,
                );
                let length = data[5];
                if length > 0 {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_LENGTH],
                        FieldValue::U8(length),
                        offset + 5..offset + 6,
                    );
                }
                if data.len() > HEADER_SIZE {
                    push_invoking_packet(buf, &data[HEADER_SIZE..], offset + HEADER_SIZE);
                }
            }
            // Router Advertisement (9) — RFC 1256
            9 => {
                let num_addrs = data[4];
                let addr_entry_size = data[5];
                let lifetime = read_be_u16(data, 6)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_NUM_ADDRS],
                    FieldValue::U8(num_addrs),
                    offset + 4..offset + 5,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_ADDR_ENTRY_SIZE],
                    FieldValue::U8(addr_entry_size),
                    offset + 5..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_LIFETIME],
                    FieldValue::U16(lifetime),
                    offset + 6..offset + 8,
                );

                let entry_bytes = addr_entry_size as usize * 4;
                let array_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_ENTRIES],
                    FieldValue::Array(0..0),
                    offset + HEADER_SIZE..offset + data.len(),
                );
                let mut pos = HEADER_SIZE;
                for _ in 0..num_addrs {
                    if pos + entry_bytes > data.len() || entry_bytes < 8 {
                        break;
                    }
                    let router_addr = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
                    let pref = read_be_u32(data, pos + 4)?;
                    let obj_idx = buf.begin_container(
                        &ROUTER_ENTRY_CHILDREN[REC_ROUTER_ADDRESS], // reuse descriptor for object marker
                        FieldValue::Object(0..0),
                        offset + pos..offset + pos + entry_bytes,
                    );
                    buf.push_field(
                        &ROUTER_ENTRY_CHILDREN[REC_ROUTER_ADDRESS],
                        FieldValue::Ipv4Addr(router_addr),
                        offset + pos..offset + pos + 4,
                    );
                    buf.push_field(
                        &ROUTER_ENTRY_CHILDREN[REC_PREFERENCE_LEVEL],
                        FieldValue::U32(pref),
                        offset + pos + 4..offset + pos + 8,
                    );
                    buf.end_container(obj_idx);
                    pos += entry_bytes;
                }
                buf.end_container(array_idx);
            }
            // Router Solicitation (10) — no type-specific fields
            10 => {}
            // Timestamp (13) / Timestamp Reply (14)
            13 | 14 => {
                if data.len() < TIMESTAMP_SIZE {
                    return Err(PacketError::Truncated {
                        expected: TIMESTAMP_SIZE,
                        actual: data.len(),
                    });
                }
                let identifier = read_be_u16(data, 4)?;
                let sequence_number = read_be_u16(data, 6)?;
                let originate = read_be_u32(data, 8)?;
                let receive = read_be_u32(data, 12)?;
                let transmit = read_be_u32(data, 16)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                    FieldValue::U16(sequence_number),
                    offset + 6..offset + 8,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_ORIGINATE_TIMESTAMP],
                    FieldValue::U32(originate),
                    offset + 8..offset + 12,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_RECEIVE_TIMESTAMP],
                    FieldValue::U32(receive),
                    offset + 12..offset + 16,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_TRANSMIT_TIMESTAMP],
                    FieldValue::U32(transmit),
                    offset + 16..offset + 20,
                );
            }
            // Information Request (15) / Information Reply (16)
            15 | 16 => {
                let identifier = read_be_u16(data, 4)?;
                let sequence_number = read_be_u16(data, 6)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                    FieldValue::U16(sequence_number),
                    offset + 6..offset + 8,
                );
            }
            // Address Mask Request (17) / Address Mask Reply (18)
            17 | 18 => {
                if data.len() < ADDRESS_MASK_SIZE {
                    return Err(PacketError::Truncated {
                        expected: ADDRESS_MASK_SIZE,
                        actual: data.len(),
                    });
                }
                let identifier = read_be_u16(data, 4)?;
                let sequence_number = read_be_u16(data, 6)?;
                let mask = [data[8], data[9], data[10], data[11]];
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                    FieldValue::U16(sequence_number),
                    offset + 6..offset + 8,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_ADDRESS_MASK],
                    FieldValue::Ipv4Addr(mask),
                    offset + 8..offset + 12,
                );
            }
            // Photuris (40)
            40 => {
                let pointer = read_be_u16(data, 6)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_POINTER],
                    FieldValue::U16(pointer),
                    offset + 6..offset + 8,
                );
                if data.len() > HEADER_SIZE {
                    push_invoking_packet(buf, &data[HEADER_SIZE..], offset + HEADER_SIZE);
                }
            }
            // Experimental Mobility (41)
            41 => {
                let subtype = data[4];
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_SUBTYPE],
                    FieldValue::U8(subtype),
                    offset + 4..offset + 5,
                );
                if data.len() > HEADER_SIZE {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_DATA],
                        FieldValue::Bytes(&data[HEADER_SIZE..]),
                        offset + HEADER_SIZE..offset + data.len(),
                    );
                }
            }
            // Extended Echo Request (42) — RFC 8335, Section 2
            42 => {
                let identifier = read_be_u16(data, 4)?;
                // RFC 8335: Sequence Number is 1 byte, promoted to U16
                // to match the shared field descriptor.
                let sequence_number = u16::from(data[6]);
                let local = data[7] & 0x01;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                    FieldValue::U16(sequence_number),
                    offset + 6..offset + 7,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_LOCAL],
                    FieldValue::U8(local),
                    offset + 7..offset + 8,
                );
                if data.len() > HEADER_SIZE {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_DATA],
                        FieldValue::Bytes(&data[HEADER_SIZE..]),
                        offset + HEADER_SIZE..offset + data.len(),
                    );
                }
            }
            // Extended Echo Reply (43) — RFC 8335, Section 2
            43 => {
                let identifier = read_be_u16(data, 4)?;
                // RFC 8335: Sequence Number is 1 byte, promoted to U16
                // to match the shared field descriptor.
                let sequence_number = u16::from(data[6]);
                let flags_byte = data[7];
                let state = (flags_byte >> 5) & 0x07;
                let active = (flags_byte >> 2) & 0x01;
                let ipv4_flag = (flags_byte >> 1) & 0x01;
                let ipv6_flag = flags_byte & 0x01;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                    FieldValue::U16(sequence_number),
                    offset + 6..offset + 7,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_STATE],
                    FieldValue::U8(state),
                    offset + 7..offset + 8,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_ACTIVE],
                    FieldValue::U8(active),
                    offset + 7..offset + 8,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IPV4],
                    FieldValue::U8(ipv4_flag),
                    offset + 7..offset + 8,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IPV6],
                    FieldValue::U8(ipv6_flag),
                    offset + 7..offset + 8,
                );
            }
            _ => {}
        }

        buf.end_layer();

        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}
