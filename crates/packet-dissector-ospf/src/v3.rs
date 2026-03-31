//! OSPFv3 (Open Shortest Path First version 3) dissector.
//!
//! ## References
//! - RFC 5340: <https://www.rfc-editor.org/rfc/rfc5340>

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

use crate::common::{LSR_ENTRY_SIZE, push_lsa_headers, push_lsu_lsas};

/// OSPFv3 common header size in bytes (RFC 5340, A.3.1).
const HEADER_SIZE: usize = 16;

/// Hello packet body size excluding neighbors (RFC 5340, A.3.2).
const HELLO_BODY_SIZE: usize = 20;

/// Database Description packet body size excluding LSA headers (RFC 5340, A.3.3).
const DD_BODY_SIZE: usize = 12;

/// Returns a human-readable name for OSPFv3 LSA function codes.
///
/// RFC 5340, A.4.
fn lsa_type_name(ls_type: u16) -> Option<&'static str> {
    // Function code is in the lower 13 bits; scope is in upper 3 bits.
    let function_code = ls_type & 0x1FFF;
    match function_code {
        1 => Some("Router-LSA"),
        2 => Some("Network-LSA"),
        3 => Some("Inter-Area-Prefix-LSA"),
        4 => Some("Inter-Area-Router-LSA"),
        5 => Some("AS-External-LSA"),
        7 => Some("Type-7-LSA"),
        8 => Some("Link-LSA"),
        9 => Some("Intra-Area-Prefix-LSA"),
        _ => None,
    }
}

/// Field descriptor indices for [`LSA_HEADER_CHILD_FIELDS`].
const FD_LSA_LS_AGE: usize = 0;
const FD_LSA_LS_TYPE: usize = 1;
const FD_LSA_LINK_STATE_ID: usize = 2;
const FD_LSA_ADVERTISING_ROUTER: usize = 3;
const FD_LSA_LS_SEQUENCE_NUMBER: usize = 4;
const FD_LSA_LS_CHECKSUM: usize = 5;
const FD_LSA_LENGTH: usize = 6;

/// Field descriptor indices for [`LSR_ENTRY_CHILD_FIELDS`].
const FD_LSR_LS_TYPE: usize = 0;
const FD_LSR_LINK_STATE_ID: usize = 1;
const FD_LSR_ADVERTISING_ROUTER: usize = 2;

/// Pushes fields for a single OSPFv3 LSA header (20 bytes) into the buffer.
///
/// RFC 5340, A.4.1.
fn push_lsa_header_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    child_fields: &'static [FieldDescriptor],
) {
    let ls_age = read_be_u16(data, 0).unwrap_or_default();
    let ls_type = read_be_u16(data, 2).unwrap_or_default();
    let link_state_id = read_be_u32(data, 4).unwrap_or_default();
    let advertising_router = [data[8], data[9], data[10], data[11]];
    let ls_seq = read_be_u32(data, 12).unwrap_or_default();
    let ls_checksum = read_be_u16(data, 16).unwrap_or_default();
    let length = read_be_u16(data, 18).unwrap_or_default();

    buf.push_field(
        &child_fields[FD_LSA_LS_AGE],
        FieldValue::U16(ls_age),
        offset..offset + 2,
    );
    buf.push_field(
        &child_fields[FD_LSA_LS_TYPE],
        FieldValue::U16(ls_type),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &child_fields[FD_LSA_LINK_STATE_ID],
        FieldValue::U32(link_state_id),
        offset + 4..offset + 8,
    );
    buf.push_field(
        &child_fields[FD_LSA_ADVERTISING_ROUTER],
        FieldValue::Ipv4Addr(advertising_router),
        offset + 8..offset + 12,
    );
    buf.push_field(
        &child_fields[FD_LSA_LS_SEQUENCE_NUMBER],
        FieldValue::U32(ls_seq),
        offset + 12..offset + 16,
    );
    buf.push_field(
        &child_fields[FD_LSA_LS_CHECKSUM],
        FieldValue::U16(ls_checksum),
        offset + 16..offset + 18,
    );
    buf.push_field(
        &child_fields[FD_LSA_LENGTH],
        FieldValue::U16(length),
        offset + 18..offset + 20,
    );
}

/// Child field descriptors for OSPFv3 LSA header entries.
static LSA_HEADER_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("ls_age", "LS Age", FieldType::U16),
    FieldDescriptor {
        name: "ls_type",
        display_name: "LS Type",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(t) => lsa_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("link_state_id", "Link State ID", FieldType::U32),
    FieldDescriptor::new(
        "advertising_router",
        "Advertising Router",
        FieldType::Ipv4Addr,
    ),
    FieldDescriptor::new("ls_sequence_number", "LS Sequence Number", FieldType::U32),
    FieldDescriptor::new("ls_checksum", "LS Checksum", FieldType::U16),
    FieldDescriptor::new("length", "Length", FieldType::U16),
];

/// Child field descriptors for OSPFv3 Link State Request entries.
static LSR_ENTRY_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "ls_type",
        display_name: "LS Type",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(t) => lsa_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("link_state_id", "Link State ID", FieldType::U32),
    FieldDescriptor::new(
        "advertising_router",
        "Advertising Router",
        FieldType::Ipv4Addr,
    ),
];

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
// Common header fields
const FD_VERSION: usize = 0;
const FD_MSG_TYPE: usize = 1;
const FD_PACKET_LENGTH: usize = 2;
const FD_ROUTER_ID: usize = 3;
const FD_AREA_ID: usize = 4;
const FD_CHECKSUM: usize = 5;
const FD_INSTANCE_ID: usize = 6;
// Hello fields
const FD_INTERFACE_ID: usize = 7;
const FD_ROUTER_PRIORITY: usize = 8;
const FD_OPTIONS: usize = 9;
const FD_HELLO_INTERVAL: usize = 10;
const FD_ROUTER_DEAD_INTERVAL: usize = 11;
const FD_DESIGNATED_ROUTER: usize = 12;
const FD_BACKUP_DESIGNATED_ROUTER: usize = 13;
const FD_NEIGHBORS: usize = 14;
// DD fields
const FD_INTERFACE_MTU: usize = 15;
const FD_DD_FLAGS: usize = 16;
const FD_DD_SEQUENCE_NUMBER: usize = 17;
const FD_LSA_HEADERS: usize = 18;
// LSR fields
const FD_REQUESTS: usize = 19;
// LSU fields
const FD_NUM_LSAS: usize = 20;
const FD_LSAS: usize = 21;

/// Field descriptors for the OSPFv3 dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // Common header fields
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor {
        name: "msg_type",
        display_name: "Message Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => crate::common::msg_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("packet_length", "Packet Length", FieldType::U16),
    FieldDescriptor::new("router_id", "Router ID", FieldType::Ipv4Addr),
    FieldDescriptor::new("area_id", "Area ID", FieldType::Ipv4Addr),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    FieldDescriptor::new("instance_id", "Instance ID", FieldType::U8),
    // Hello fields
    FieldDescriptor::new("interface_id", "Interface ID", FieldType::U32).optional(),
    FieldDescriptor::new("router_priority", "Router Priority", FieldType::U8).optional(),
    FieldDescriptor::new("options", "Options", FieldType::U32).optional(),
    FieldDescriptor::new("hello_interval", "Hello Interval", FieldType::U16).optional(),
    FieldDescriptor::new(
        "router_dead_interval",
        "Router Dead Interval",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "designated_router",
        "Designated Router",
        FieldType::Ipv4Addr,
    )
    .optional(),
    FieldDescriptor::new(
        "backup_designated_router",
        "Backup Designated Router",
        FieldType::Ipv4Addr,
    )
    .optional(),
    FieldDescriptor::new("neighbors", "Neighbors", FieldType::Array).optional(),
    // DD fields
    FieldDescriptor::new("interface_mtu", "Interface MTU", FieldType::U16).optional(),
    FieldDescriptor::new("dd_flags", "DD Flags", FieldType::U8).optional(),
    FieldDescriptor::new("dd_sequence_number", "DD Sequence Number", FieldType::U32).optional(),
    FieldDescriptor::new("lsa_headers", "LSA Headers", FieldType::Array)
        .optional()
        .with_children(LSA_HEADER_CHILD_FIELDS),
    // LSR fields
    FieldDescriptor::new("requests", "Link State Requests", FieldType::Array)
        .optional()
        .with_children(LSR_ENTRY_CHILD_FIELDS),
    // LSU fields
    FieldDescriptor::new("num_lsas", "Number of LSAs", FieldType::U32).optional(),
    FieldDescriptor::new("lsas", "LSAs", FieldType::Array)
        .optional()
        .with_children(LSA_HEADER_CHILD_FIELDS),
];

/// OSPFv3 dissector.
pub struct Ospfv3Dissector;

impl Dissector for Ospfv3Dissector {
    fn name(&self) -> &'static str {
        "Open Shortest Path First v3"
    }

    fn short_name(&self) -> &'static str {
        "OSPFv3"
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

        // RFC 5340, A.3.1 — Common header (16 bytes, no auth fields)
        let version = data[0];
        if version != 3 {
            return Err(PacketError::InvalidHeader("expected OSPFv3 (version 3)"));
        }

        let ospf_type = data[1];
        let packet_length = read_be_u16(data, 2)?;
        let router_id = [data[4], data[5], data[6], data[7]];
        let area_id = [data[8], data[9], data[10], data[11]];
        let checksum = read_be_u16(data, 12)?;
        let instance_id = data[14];
        // data[15] is reserved

        let packet_length_usize = packet_length as usize;
        if packet_length_usize < HEADER_SIZE {
            return Err(PacketError::InvalidHeader(
                "ospfv3: packet length smaller than header size",
            ));
        }
        if data.len() < packet_length_usize {
            return Err(PacketError::Truncated {
                expected: packet_length_usize,
                actual: data.len(),
            });
        }
        let total_len = packet_length_usize;

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_len,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MSG_TYPE],
            FieldValue::U8(ospf_type),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PACKET_LENGTH],
            FieldValue::U16(packet_length),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ROUTER_ID],
            FieldValue::Ipv4Addr(router_id),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_AREA_ID],
            FieldValue::Ipv4Addr(area_id),
            offset + 8..offset + 12,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM],
            FieldValue::U16(checksum),
            offset + 12..offset + 14,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_INSTANCE_ID],
            FieldValue::U8(instance_id),
            offset + 14..offset + 15,
        );

        // Type-specific parsing
        let body = &data[HEADER_SIZE..total_len];
        let body_offset = offset + HEADER_SIZE;

        match ospf_type {
            // Hello (Type 1) — RFC 5340, A.3.2
            1 => {
                if body.len() < HELLO_BODY_SIZE {
                    return Err(PacketError::InvalidHeader(
                        "ospfv3: packet length too small for Hello body",
                    ));
                }

                let interface_id = read_be_u32(body, 0)?;
                let router_priority = body[4];
                // Options: 24 bits (bytes 5-7)
                let options =
                    u32::from(body[5]) << 16 | u32::from(body[6]) << 8 | u32::from(body[7]);
                let hello_interval = read_be_u16(body, 8)?;
                let router_dead_interval = read_be_u16(body, 10)?;
                let dr = [body[12], body[13], body[14], body[15]];
                let bdr = [body[16], body[17], body[18], body[19]];

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_INTERFACE_ID],
                    FieldValue::U32(interface_id),
                    body_offset..body_offset + 4,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_ROUTER_PRIORITY],
                    FieldValue::U8(router_priority),
                    body_offset + 4..body_offset + 5,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_OPTIONS],
                    FieldValue::U32(options),
                    body_offset + 5..body_offset + 8,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_HELLO_INTERVAL],
                    FieldValue::U16(hello_interval),
                    body_offset + 8..body_offset + 10,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_ROUTER_DEAD_INTERVAL],
                    FieldValue::U16(router_dead_interval),
                    body_offset + 10..body_offset + 12,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_DESIGNATED_ROUTER],
                    FieldValue::Ipv4Addr(dr),
                    body_offset + 12..body_offset + 16,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_BACKUP_DESIGNATED_ROUTER],
                    FieldValue::Ipv4Addr(bdr),
                    body_offset + 16..body_offset + 20,
                );

                // Neighbor list (Router IDs, 4 bytes each)
                let neighbor_data = &body[HELLO_BODY_SIZE..];
                if neighbor_data.len() % 4 != 0 {
                    // Neighbor list must be a sequence of 4-byte Router IDs (RFC 5340, A.3.2).
                    // Treat trailing partial IDs as truncation of the expected structure.
                    let trailing = neighbor_data.len() % 4;
                    return Err(PacketError::Truncated {
                        expected: data.len() - trailing,
                        actual: data.len(),
                    });
                }
                let neighbors_start = body_offset + HELLO_BODY_SIZE;
                let array_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_NEIGHBORS],
                    FieldValue::Array(0..0),
                    neighbors_start..body_offset + body.len(),
                );
                let mut pos = 0;
                while pos + 4 <= neighbor_data.len() {
                    let addr = [
                        neighbor_data[pos],
                        neighbor_data[pos + 1],
                        neighbor_data[pos + 2],
                        neighbor_data[pos + 3],
                    ];
                    let abs = body_offset + HELLO_BODY_SIZE + pos;
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_NEIGHBORS],
                        FieldValue::Ipv4Addr(addr),
                        abs..abs + 4,
                    );
                    pos += 4;
                }
                buf.end_container(array_idx);
            }
            // Database Description (Type 2) — RFC 5340, A.3.3
            2 => {
                if body.len() < DD_BODY_SIZE {
                    return Err(PacketError::Truncated {
                        expected: HEADER_SIZE + DD_BODY_SIZE,
                        actual: HEADER_SIZE + body.len(),
                    });
                }

                // byte 0: reserved
                // bytes 1-3: Options (24 bits)
                let options =
                    u32::from(body[1]) << 16 | u32::from(body[2]) << 8 | u32::from(body[3]);
                let interface_mtu = read_be_u16(body, 4)?;
                // byte 6: reserved
                let dd_flags = body[7];
                let dd_seq = read_be_u32(body, 8)?;

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_OPTIONS],
                    FieldValue::U32(options),
                    body_offset + 1..body_offset + 4,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_INTERFACE_MTU],
                    FieldValue::U16(interface_mtu),
                    body_offset + 4..body_offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_DD_FLAGS],
                    FieldValue::U8(dd_flags),
                    body_offset + 7..body_offset + 8,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_DD_SEQUENCE_NUMBER],
                    FieldValue::U32(dd_seq),
                    body_offset + 8..body_offset + 12,
                );

                // LSA headers
                let lsa_data = &body[DD_BODY_SIZE..];
                let lsa_start = body_offset + DD_BODY_SIZE;
                let array_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_LSA_HEADERS],
                    FieldValue::Array(0..0),
                    lsa_start..body_offset + body.len(),
                );
                push_lsa_headers(
                    buf,
                    lsa_data,
                    lsa_start,
                    LSA_HEADER_CHILD_FIELDS,
                    push_lsa_header_fields,
                );
                buf.end_container(array_idx);
            }
            // Link State Request (Type 3) — RFC 5340, A.3.4
            3 => {
                let array_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_REQUESTS],
                    FieldValue::Array(0..0),
                    body_offset..body_offset + body.len(),
                );
                let mut pos = 0;
                while pos + LSR_ENTRY_SIZE <= body.len() {
                    // bytes 0-1: reserved, bytes 2-3: LS Type
                    let ls_type = read_be_u16(body, pos + 2)?;
                    let link_state_id = read_be_u32(body, pos + 4)?;
                    let adv_router = [body[pos + 8], body[pos + 9], body[pos + 10], body[pos + 11]];
                    let abs = body_offset + pos;

                    let obj_idx = buf.begin_container(
                        &LSR_ENTRY_CHILD_FIELDS[FD_LSR_LS_TYPE],
                        FieldValue::Object(0..0),
                        abs..abs + LSR_ENTRY_SIZE,
                    );
                    buf.push_field(
                        &LSR_ENTRY_CHILD_FIELDS[FD_LSR_LS_TYPE],
                        FieldValue::U16(ls_type),
                        abs + 2..abs + 4,
                    );
                    buf.push_field(
                        &LSR_ENTRY_CHILD_FIELDS[FD_LSR_LINK_STATE_ID],
                        FieldValue::U32(link_state_id),
                        abs + 4..abs + 8,
                    );
                    buf.push_field(
                        &LSR_ENTRY_CHILD_FIELDS[FD_LSR_ADVERTISING_ROUTER],
                        FieldValue::Ipv4Addr(adv_router),
                        abs + 8..abs + 12,
                    );
                    buf.end_container(obj_idx);

                    pos += LSR_ENTRY_SIZE;
                }
                buf.end_container(array_idx);
            }
            // Link State Update (Type 4) — RFC 5340, A.3.5
            4 => {
                if body.len() < 4 {
                    return Err(PacketError::Truncated {
                        expected: HEADER_SIZE + 4,
                        actual: HEADER_SIZE + body.len(),
                    });
                }

                let num_lsas = read_be_u32(body, 0)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_NUM_LSAS],
                    FieldValue::U32(num_lsas),
                    body_offset..body_offset + 4,
                );

                let array_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_LSAS],
                    FieldValue::Array(0..0),
                    body_offset + 4..body_offset + body.len(),
                );
                push_lsu_lsas(
                    buf,
                    body,
                    num_lsas,
                    body_offset,
                    LSA_HEADER_CHILD_FIELDS,
                    push_lsa_header_fields,
                );
                buf.end_container(array_idx);
            }
            // Link State Acknowledgment (Type 5) — RFC 5340, A.3.6
            5 => {
                let array_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_LSA_HEADERS],
                    FieldValue::Array(0..0),
                    body_offset..body_offset + body.len(),
                );
                push_lsa_headers(
                    buf,
                    body,
                    body_offset,
                    LSA_HEADER_CHILD_FIELDS,
                    push_lsa_header_fields,
                );
                buf.end_container(array_idx);
            }
            _ => {}
        }

        buf.end_layer();

        Ok(DissectResult::new(total_len, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 5340 (OSPFv3) Coverage
    //
    // | RFC Section | Description | Test |
    // |-------------|-------------|------|
    // | A.3.1 | Common header | parse_hello |
    // | A.3.2 | Hello packet | parse_hello, parse_hello_with_neighbors |
    // | A.3.3 | Database Description | parse_dd |
    // | A.3.4 | Link State Request | parse_lsr |
    // | A.3.5 | Link State Update | parse_lsu |
    // | A.3.6 | Link State Ack | parse_lsack |

    /// Build an OSPFv3 common header (16 bytes).
    fn build_header(ospf_type: u8, packet_length: u16, router_id: [u8; 4]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(3); // version
        buf.push(ospf_type);
        buf.extend_from_slice(&packet_length.to_be_bytes());
        buf.extend_from_slice(&router_id); // Router ID
        buf.extend_from_slice(&[0, 0, 0, 0]); // Area ID
        buf.extend_from_slice(&[0x00, 0x00]); // Checksum
        buf.push(0); // Instance ID
        buf.push(0); // Reserved
        buf
    }

    /// Build a sample OSPFv3 LSA header.
    fn build_lsa_header(ls_type: u16, lsa_length: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x01]); // LS Age = 1
        buf.extend_from_slice(&ls_type.to_be_bytes()); // LS Type
        buf.extend_from_slice(&[0, 0, 0, 1]); // Link State ID = 1
        buf.extend_from_slice(&[1, 1, 1, 1]); // Advertising Router
        buf.extend_from_slice(&[0x80, 0x00, 0x00, 0x01]); // LS Seq
        buf.extend_from_slice(&[0xAB, 0xCD]); // LS Checksum
        buf.extend_from_slice(&lsa_length.to_be_bytes()); // Length
        buf
    }

    #[test]
    fn parse_hello() {
        let mut pkt = build_header(1, 36, [1, 1, 1, 1]);
        // Hello body: 20 bytes, no neighbors
        pkt.extend_from_slice(&[0, 0, 0, 1]); // Interface ID = 1
        pkt.push(1); // Router Priority
        pkt.extend_from_slice(&[0x00, 0x00, 0x13]); // Options (24-bit) = 0x13
        pkt.extend_from_slice(&[0, 10]); // Hello Interval = 10
        pkt.extend_from_slice(&[0, 40]); // Router Dead Interval = 40
        pkt.extend_from_slice(&[10, 0, 0, 1]); // DR
        pkt.extend_from_slice(&[10, 0, 0, 2]); // BDR

        let mut buf = DissectBuffer::new();
        let result = Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 36);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("OSPFv3").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.field_by_name(layer, "msg_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "msg_type_name"),
            Some("Hello")
        );
        assert_eq!(
            buf.field_by_name(layer, "interface_id").unwrap().value,
            FieldValue::U32(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "router_priority").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "options").unwrap().value,
            FieldValue::U32(0x13)
        );
        assert_eq!(
            buf.field_by_name(layer, "hello_interval").unwrap().value,
            FieldValue::U16(10)
        );
        assert_eq!(
            buf.field_by_name(layer, "router_dead_interval")
                .unwrap()
                .value,
            FieldValue::U16(40)
        );
        assert_eq!(
            buf.field_by_name(layer, "designated_router").unwrap().value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
    }

    #[test]
    fn parse_hello_with_neighbors() {
        let mut pkt = build_header(1, 44, [1, 1, 1, 1]);
        // Hello body
        pkt.extend_from_slice(&[0, 0, 0, 1]); // Interface ID
        pkt.push(1);
        pkt.extend_from_slice(&[0x00, 0x00, 0x13]); // Options
        pkt.extend_from_slice(&[0, 10]);
        pkt.extend_from_slice(&[0, 40]);
        pkt.extend_from_slice(&[10, 0, 0, 1]); // DR
        pkt.extend_from_slice(&[10, 0, 0, 2]); // BDR
        // Two neighbors
        pkt.extend_from_slice(&[2, 2, 2, 2]);
        pkt.extend_from_slice(&[3, 3, 3, 3]);

        let mut buf = DissectBuffer::new();
        let result = Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 44);

        let layer = buf.layer_by_name("OSPFv3").unwrap();
        let neighbors = buf.field_by_name(layer, "neighbors").unwrap();
        if let FieldValue::Array(ref range) = neighbors.value {
            let items = buf.nested_fields(range);
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].value, FieldValue::Ipv4Addr([2, 2, 2, 2]));
            assert_eq!(items[1].value, FieldValue::Ipv4Addr([3, 3, 3, 3]));
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn parse_dd() {
        let mut pkt = build_header(2, 48, [1, 1, 1, 1]);
        // DD body: 12 bytes fixed
        pkt.push(0); // Reserved
        pkt.extend_from_slice(&[0x00, 0x00, 0x13]); // Options
        pkt.extend_from_slice(&[0x05, 0xDC]); // Interface MTU = 1500
        pkt.push(0); // Reserved
        pkt.push(0x07); // Flags: I|M|MS
        pkt.extend_from_slice(&[0, 0, 0, 1]); // DD Seq = 1
        // One LSA header
        pkt.extend_from_slice(&build_lsa_header(0x2001, 20)); // Router-LSA

        let mut buf = DissectBuffer::new();
        let result = Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 48);

        let layer = buf.layer_by_name("OSPFv3").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "interface_mtu").unwrap().value,
            FieldValue::U16(1500)
        );
        assert_eq!(
            buf.field_by_name(layer, "dd_flags").unwrap().value,
            FieldValue::U8(0x07)
        );
    }

    #[test]
    fn parse_lsr() {
        let mut pkt = build_header(3, 28, [1, 1, 1, 1]);
        // One LSR entry: 12 bytes
        pkt.extend_from_slice(&[0, 0]); // Reserved
        pkt.extend_from_slice(&[0x20, 0x01]); // LS Type = 0x2001
        pkt.extend_from_slice(&[0, 0, 0, 1]); // Link State ID
        pkt.extend_from_slice(&[2, 2, 2, 2]); // Advertising Router

        let mut buf = DissectBuffer::new();
        let result = Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 28);

        let layer = buf.layer_by_name("OSPFv3").unwrap();
        let requests = buf.field_by_name(layer, "requests").unwrap();
        if let FieldValue::Array(ref range) = requests.value {
            let items = buf.nested_fields(range);
            let first_obj = items
                .iter()
                .find(|f| f.value.is_object())
                .expect("expected Object");
            if let FieldValue::Object(ref obj_range) = first_obj.value {
                let obj_fields = buf.nested_fields(obj_range);
                assert_eq!(obj_fields[0].value, FieldValue::U16(0x2001));
            } else {
                panic!("expected Object");
            }
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn parse_lsu() {
        let lsa = build_lsa_header(0x2001, 20);
        let pkt_len = (HEADER_SIZE + 4 + lsa.len()) as u16;
        let mut pkt = build_header(4, pkt_len, [1, 1, 1, 1]);
        pkt.extend_from_slice(&[0, 0, 0, 1]); // # LSAs = 1
        pkt.extend_from_slice(&lsa);

        let mut buf = DissectBuffer::new();
        let result = Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, pkt_len as usize);

        let layer = buf.layer_by_name("OSPFv3").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "num_lsas").unwrap().value,
            FieldValue::U32(1)
        );
    }

    #[test]
    fn parse_lsack() {
        let lsa = build_lsa_header(0x2001, 20);
        let pkt_len = (HEADER_SIZE + lsa.len()) as u16;
        let mut pkt = build_header(5, pkt_len, [1, 1, 1, 1]);
        pkt.extend_from_slice(&lsa);

        let mut buf = DissectBuffer::new();
        let result = Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, pkt_len as usize);

        let layer = buf.layer_by_name("OSPFv3").unwrap();
        let lsa_headers = buf.field_by_name(layer, "lsa_headers").unwrap();
        if let FieldValue::Array(ref range) = lsa_headers.value {
            let items = buf.nested_fields(range);
            let obj_count = items.iter().filter(|f| f.value.is_object()).count();
            assert_eq!(obj_count, 1);
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn parse_truncated_header() {
        let data = [0x03, 0x01, 0x00];
        let mut buf = DissectBuffer::new();
        let err = Ospfv3Dissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 16,
                actual: 3
            }
        ));
    }

    #[test]
    fn parse_wrong_version() {
        let pkt = build_header(1, 36, [1, 1, 1, 1]);
        let mut modified = pkt.clone();
        modified[0] = 2; // Set version to 2

        let mut buf = DissectBuffer::new();
        let err = Ospfv3Dissector.dissect(&modified, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }
}
