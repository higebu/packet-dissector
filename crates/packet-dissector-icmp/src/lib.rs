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
const IPC_SRC_PORT: usize = 6;
const IPC_DST_PORT: usize = 7;
const IPC_TRANSPORT_DATA: usize = 8;

static INVOKING_PACKET_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("ihl", "Internet Header Length", FieldType::U8),
    FieldDescriptor::new("total_length", "Total Length", FieldType::U16),
    FieldDescriptor::new("protocol", "Protocol", FieldType::U8),
    FieldDescriptor::new("src", "Source Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("dst", "Destination Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("src_port", "Source Port", FieldType::U16).optional(),
    FieldDescriptor::new("dst_port", "Destination Port", FieldType::U16).optional(),
    FieldDescriptor::new("transport_data", "Transport Data", FieldType::Bytes).optional(),
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

        // RFC 792 — parse transport layer from the invoking packet.
        // ICMP error messages include the original IP header + first 8 bytes of
        // the original datagram, which covers src_port/dst_port for TCP and UDP.
        let ip_header_len = (ihl as usize) * 4;
        if ip_header_len >= IPV4_MIN_HEADER && data.len() > ip_header_len {
            let transport = &data[ip_header_len..];
            let transport_offset = offset + ip_header_len;
            match protocol {
                6 | 17 => {
                    // TCP/UDP: first 4 bytes are src_port (2) + dst_port (2)
                    if transport.len() >= 4 {
                        let src_port = u16::from_be_bytes([transport[0], transport[1]]);
                        let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
                        buf.push_field(
                            &INVOKING_PACKET_CHILDREN[IPC_SRC_PORT],
                            FieldValue::U16(src_port),
                            transport_offset..transport_offset + 2,
                        );
                        buf.push_field(
                            &INVOKING_PACKET_CHILDREN[IPC_DST_PORT],
                            FieldValue::U16(dst_port),
                            transport_offset + 2..transport_offset + 4,
                        );
                    }
                }
                _ => {
                    buf.push_field(
                        &INVOKING_PACKET_CHILDREN[IPC_TRANSPORT_DATA],
                        FieldValue::Bytes(transport),
                        transport_offset..transport_offset + transport.len(),
                    );
                }
            }
        }

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

#[cfg(test)]
mod tests {
    //! # ICMP invoking packet coverage
    //!
    //! | RFC Section                     | Description                          | Test                                      |
    //! |---------------------------------|--------------------------------------|-------------------------------------------|
    //! | RFC 792 Destination Unreachable  | IPv4 header only (regression)        | parse_invoking_packet_ipv4_only           |
    //! | RFC 792 Destination Unreachable  | UDP src_port/dst_port extraction     | parse_dest_unreachable_udp_ports          |
    //! | RFC 792 Destination Unreachable  | TCP src_port/dst_port extraction     | parse_dest_unreachable_tcp_ports          |
    //! | RFC 792 Destination Unreachable  | Other protocol → raw bytes           | parse_dest_unreachable_other_protocol     |
    //! | RFC 792 Destination Unreachable  | Truncated transport (no ports)       | parse_dest_unreachable_truncated_transport |

    use super::*;

    /// Build an ICMP Destination Unreachable (type 3) packet with an invoking packet.
    fn build_dest_unreachable(code: u8, invoking: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(HEADER_SIZE + invoking.len());
        pkt.push(3); // type = Destination Unreachable
        pkt.push(code);
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // unused
        pkt.extend_from_slice(invoking);
        pkt
    }

    /// Build a minimal IPv4 header (20 bytes, IHL=5) with the given protocol.
    fn build_ipv4_header(protocol: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut hdr = vec![0u8; 20];
        hdr[0] = 0x45; // version=4, ihl=5
        hdr[2] = 0x00; // total_length high byte
        hdr[3] = 0x28; // total_length = 40
        hdr[9] = protocol;
        hdr[12..16].copy_from_slice(&src);
        hdr[16..20].copy_from_slice(&dst);
        hdr
    }

    #[test]
    fn parse_invoking_packet_ipv4_only() {
        let invoking = build_ipv4_header(17, [10, 0, 0, 1], [10, 0, 0, 2]);
        let data = build_dest_unreachable(0, &invoking);

        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let ip_obj = fields
            .iter()
            .find(|f| f.descriptor.name == "invoking_packet")
            .unwrap();
        let range = match &ip_obj.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let children = buf.nested_fields(&range);
        assert_eq!(children[IPC_VERSION].value, FieldValue::U8(4));
        assert_eq!(children[IPC_IHL].value, FieldValue::U8(5));
        assert_eq!(children[IPC_PROTOCOL].value, FieldValue::U8(17));
        assert_eq!(children[IPC_SRC].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
        assert_eq!(children[IPC_DST].value, FieldValue::Ipv4Addr([10, 0, 0, 2]));
    }

    #[test]
    fn parse_dest_unreachable_udp_ports() {
        let src = [192, 168, 1, 1];
        let dst = [192, 168, 1, 2];
        let mut invoking = build_ipv4_header(17, src, dst); // UDP
        // Append UDP header: src_port(2) + dst_port(2) + length(2) + checksum(2)
        invoking.extend_from_slice(&[0x1F, 0x90]); // src_port = 8080
        invoking.extend_from_slice(&[0x00, 0x35]); // dst_port = 53
        invoking.extend_from_slice(&[0x00, 0x08, 0x00, 0x00]); // length + checksum
        let data = build_dest_unreachable(3, &invoking); // code 3 = Port Unreachable

        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let ip_obj = fields
            .iter()
            .find(|f| f.descriptor.name == "invoking_packet")
            .unwrap();
        let range = match &ip_obj.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let children = buf.nested_fields(&range);
        let src_port = children
            .iter()
            .find(|f| f.descriptor.name == "src_port")
            .unwrap();
        assert_eq!(src_port.value, FieldValue::U16(8080));
        let dst_port = children
            .iter()
            .find(|f| f.descriptor.name == "dst_port")
            .unwrap();
        assert_eq!(dst_port.value, FieldValue::U16(53));
    }

    #[test]
    fn parse_dest_unreachable_tcp_ports() {
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let mut invoking = build_ipv4_header(6, src, dst); // TCP
        // Append TCP header first 8 bytes: src_port(2) + dst_port(2) + seq(4)
        invoking.extend_from_slice(&[0x00, 0x50]); // src_port = 80
        invoking.extend_from_slice(&[0xC0, 0x00]); // dst_port = 49152
        invoking.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq
        let data = build_dest_unreachable(3, &invoking);

        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let ip_obj = fields
            .iter()
            .find(|f| f.descriptor.name == "invoking_packet")
            .unwrap();
        let range = match &ip_obj.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let children = buf.nested_fields(&range);
        let src_port = children
            .iter()
            .find(|f| f.descriptor.name == "src_port")
            .unwrap();
        assert_eq!(src_port.value, FieldValue::U16(80));
        let dst_port = children
            .iter()
            .find(|f| f.descriptor.name == "dst_port")
            .unwrap();
        assert_eq!(dst_port.value, FieldValue::U16(49152));
    }

    #[test]
    fn parse_dest_unreachable_other_protocol() {
        let mut invoking = build_ipv4_header(1, [10, 0, 0, 1], [10, 0, 0, 2]); // ICMP
        invoking.extend_from_slice(&[0x08, 0x00, 0xAB, 0xCD, 0x00, 0x01, 0x00, 0x01]);
        let data = build_dest_unreachable(0, &invoking);

        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let ip_obj = fields
            .iter()
            .find(|f| f.descriptor.name == "invoking_packet")
            .unwrap();
        let range = match &ip_obj.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let children = buf.nested_fields(&range);
        let transport = children
            .iter()
            .find(|f| f.descriptor.name == "transport_data")
            .unwrap();
        assert!(matches!(transport.value, FieldValue::Bytes(_)));
    }

    #[test]
    fn parse_dest_unreachable_truncated_transport() {
        // IPv4 header only, no transport data
        let invoking = build_ipv4_header(17, [10, 0, 0, 1], [10, 0, 0, 2]);
        let data = build_dest_unreachable(3, &invoking);

        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let ip_obj = fields
            .iter()
            .find(|f| f.descriptor.name == "invoking_packet")
            .unwrap();
        let range = match &ip_obj.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let children = buf.nested_fields(&range);
        // Should only have the 6 IPv4 header fields, no port fields
        assert!(children.iter().all(|f| f.descriptor.name != "src_port"));
        assert!(children.iter().all(|f| f.descriptor.name != "dst_port"));
        assert!(
            children
                .iter()
                .all(|f| f.descriptor.name != "transport_data")
        );
    }
}
