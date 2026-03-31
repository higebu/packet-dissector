//! OSPFv2 (Open Shortest Path First version 2) dissector.
//!
//! ## References
//! - RFC 2328: <https://www.rfc-editor.org/rfc/rfc2328>

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

use crate::common::{LSR_ENTRY_SIZE, push_lsa_headers, push_lsu_lsas};

/// OSPFv2 common header size in bytes (RFC 2328, A.3.1).
const HEADER_SIZE: usize = 24;

/// Hello packet body size excluding neighbors (RFC 2328, A.3.2).
const HELLO_BODY_SIZE: usize = 20;

/// Database Description packet body size excluding LSA headers (RFC 2328, A.3.3).
const DD_BODY_SIZE: usize = 8;

/// Field descriptor indices for [`LSA_HEADER_CHILD_FIELDS`].
const FD_LSA_LS_AGE: usize = 0;
const FD_LSA_OPTIONS: usize = 1;
const FD_LSA_LS_TYPE: usize = 2;
const FD_LSA_LINK_STATE_ID: usize = 3;
const FD_LSA_ADVERTISING_ROUTER: usize = 4;
const FD_LSA_LS_SEQUENCE_NUMBER: usize = 5;
const FD_LSA_LS_CHECKSUM: usize = 6;
const FD_LSA_LENGTH: usize = 7;

/// Child field descriptors for LSA header entries.
static LSA_HEADER_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("ls_age", "LS Age", FieldType::U16),
    FieldDescriptor::new("options", "Options", FieldType::U8),
    FieldDescriptor {
        name: "ls_type",
        display_name: "LS Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => lsa_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("link_state_id", "Link State ID", FieldType::Ipv4Addr),
    FieldDescriptor::new(
        "advertising_router",
        "Advertising Router",
        FieldType::Ipv4Addr,
    ),
    FieldDescriptor::new("ls_sequence_number", "LS Sequence Number", FieldType::U32),
    FieldDescriptor::new("ls_checksum", "LS Checksum", FieldType::U16),
    FieldDescriptor::new("length", "Length", FieldType::U16),
];

/// Field descriptor indices for [`LSR_ENTRY_CHILD_FIELDS`].
const FD_LSR_LS_TYPE: usize = 0;
const FD_LSR_LINK_STATE_ID: usize = 1;
const FD_LSR_ADVERTISING_ROUTER: usize = 2;

/// Child field descriptors for Link State Request entries.
static LSR_ENTRY_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("ls_type", "LS Type", FieldType::U32),
    FieldDescriptor::new("link_state_id", "Link State ID", FieldType::Ipv4Addr),
    FieldDescriptor::new(
        "advertising_router",
        "Advertising Router",
        FieldType::Ipv4Addr,
    ),
];

/// Returns a human-readable name for LSA types.
///
/// RFC 2328, Section 12.1.
fn lsa_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Router-LSA"),
        2 => Some("Network-LSA"),
        3 => Some("Summary-LSA (IP network)"),
        4 => Some("Summary-LSA (ASBR)"),
        5 => Some("AS-external-LSA"),
        _ => None,
    }
}

/// Pushes fields for a single LSA header (20 bytes) into the buffer.
///
/// RFC 2328, A.4.1.
fn push_lsa_header_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    child_fields: &'static [FieldDescriptor],
) {
    let ls_age = read_be_u16(data, 0).unwrap_or_default();
    let options = data[2];
    let ls_type = data[3];
    let link_state_id = [data[4], data[5], data[6], data[7]];
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
        &child_fields[FD_LSA_OPTIONS],
        FieldValue::U8(options),
        offset + 2..offset + 3,
    );
    buf.push_field(
        &child_fields[FD_LSA_LS_TYPE],
        FieldValue::U8(ls_type),
        offset + 3..offset + 4,
    );
    buf.push_field(
        &child_fields[FD_LSA_LINK_STATE_ID],
        FieldValue::Ipv4Addr(link_state_id),
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

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
// Common header fields
const FD_VERSION: usize = 0;
const FD_MSG_TYPE: usize = 1;
const FD_PACKET_LENGTH: usize = 2;
const FD_ROUTER_ID: usize = 3;
const FD_AREA_ID: usize = 4;
const FD_CHECKSUM: usize = 5;
const FD_AUTH_TYPE: usize = 6;
const FD_AUTHENTICATION: usize = 7;
// Hello fields
const FD_NETWORK_MASK: usize = 8;
const FD_HELLO_INTERVAL: usize = 9;
const FD_OPTIONS: usize = 10;
const FD_ROUTER_PRIORITY: usize = 11;
const FD_ROUTER_DEAD_INTERVAL: usize = 12;
const FD_DESIGNATED_ROUTER: usize = 13;
const FD_BACKUP_DESIGNATED_ROUTER: usize = 14;
const FD_NEIGHBORS: usize = 15;
// DD fields
const FD_INTERFACE_MTU: usize = 16;
const FD_DD_FLAGS: usize = 17;
const FD_DD_SEQUENCE_NUMBER: usize = 18;
const FD_LSA_HEADERS: usize = 19;
// LSR fields
const FD_REQUESTS: usize = 20;
// LSU fields
const FD_NUM_LSAS: usize = 21;
const FD_LSAS: usize = 22;

/// Field descriptors for the OSPFv2 dissector.
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
    FieldDescriptor::new("auth_type", "Authentication Type", FieldType::U16),
    FieldDescriptor::new("authentication", "Authentication", FieldType::Bytes),
    // Hello fields
    FieldDescriptor::new("network_mask", "Network Mask", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("hello_interval", "Hello Interval", FieldType::U16).optional(),
    FieldDescriptor::new("options", "Options", FieldType::U8).optional(),
    FieldDescriptor::new("router_priority", "Router Priority", FieldType::U8).optional(),
    FieldDescriptor::new(
        "router_dead_interval",
        "Router Dead Interval",
        FieldType::U32,
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

/// OSPFv2 dissector.
pub struct Ospfv2Dissector;

impl Dissector for Ospfv2Dissector {
    fn name(&self) -> &'static str {
        "Open Shortest Path First v2"
    }

    fn short_name(&self) -> &'static str {
        "OSPFv2"
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

        // RFC 2328, A.3.1 — Common header
        let version = data[0];
        if version != 2 {
            return Err(PacketError::InvalidHeader("expected OSPFv2 (version 2)"));
        }

        let ospf_type = data[1];
        let packet_length = read_be_u16(data, 2)?;
        let router_id = [data[4], data[5], data[6], data[7]];
        let area_id = [data[8], data[9], data[10], data[11]];
        let checksum = read_be_u16(data, 12)?;
        let auth_type = read_be_u16(data, 14)?;

        // Validate declared packet length before slicing the body.
        if (packet_length as usize) < HEADER_SIZE {
            return Err(PacketError::InvalidHeader(
                "OSPFv2 packet length is smaller than header size",
            ));
        }

        // Ensure the buffer is at least as long as the declared packet length.
        if data.len() < packet_length as usize {
            return Err(PacketError::Truncated {
                expected: packet_length as usize,
                actual: data.len(),
            });
        }

        let total_len = packet_length as usize;

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
            &FIELD_DESCRIPTORS[FD_AUTH_TYPE],
            FieldValue::U16(auth_type),
            offset + 14..offset + 16,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_AUTHENTICATION],
            FieldValue::Bytes(&data[16..24]),
            offset + 16..offset + 24,
        );

        // Type-specific parsing
        let body = &data[HEADER_SIZE..total_len];
        let body_offset = offset + HEADER_SIZE;

        match ospf_type {
            // Hello (Type 1) — RFC 2328, A.3.2
            1 => {
                if body.len() < HELLO_BODY_SIZE {
                    return Err(PacketError::InvalidHeader(
                        "ospfv2: packet length too small for Hello body",
                    ));
                }

                let network_mask = [body[0], body[1], body[2], body[3]];
                let hello_interval = read_be_u16(body, 4)?;
                let options = body[6];
                let router_priority = body[7];
                let router_dead_interval = read_be_u32(body, 8)?;
                let dr = [body[12], body[13], body[14], body[15]];
                let bdr = [body[16], body[17], body[18], body[19]];

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_NETWORK_MASK],
                    FieldValue::Ipv4Addr(network_mask),
                    body_offset..body_offset + 4,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_HELLO_INTERVAL],
                    FieldValue::U16(hello_interval),
                    body_offset + 4..body_offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_OPTIONS],
                    FieldValue::U8(options),
                    body_offset + 6..body_offset + 7,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_ROUTER_PRIORITY],
                    FieldValue::U8(router_priority),
                    body_offset + 7..body_offset + 8,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_ROUTER_DEAD_INTERVAL],
                    FieldValue::U32(router_dead_interval),
                    body_offset + 8..body_offset + 12,
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

                // Parse neighbor list
                let neighbor_data = &body[HELLO_BODY_SIZE..];
                if neighbor_data.len() % 4 != 0 {
                    return Err(PacketError::InvalidHeader(
                        "ospfv2: neighbor list length is not a multiple of 4",
                    ));
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
            // Database Description (Type 2) — RFC 2328, A.3.3
            2 => {
                if body.len() < DD_BODY_SIZE {
                    return Err(PacketError::Truncated {
                        expected: HEADER_SIZE + DD_BODY_SIZE,
                        actual: HEADER_SIZE + body.len(),
                    });
                }

                let interface_mtu = read_be_u16(body, 0)?;
                let dd_options = body[2];
                let dd_flags = body[3];
                let dd_seq = read_be_u32(body, 4)?;

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_INTERFACE_MTU],
                    FieldValue::U16(interface_mtu),
                    body_offset..body_offset + 2,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_OPTIONS],
                    FieldValue::U8(dd_options),
                    body_offset + 2..body_offset + 3,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_DD_FLAGS],
                    FieldValue::U8(dd_flags),
                    body_offset + 3..body_offset + 4,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_DD_SEQUENCE_NUMBER],
                    FieldValue::U32(dd_seq),
                    body_offset + 4..body_offset + 8,
                );

                // Parse LSA headers
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
            // Link State Request (Type 3) — RFC 2328, A.3.4
            3 => {
                let array_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_REQUESTS],
                    FieldValue::Array(0..0),
                    body_offset..body_offset + body.len(),
                );
                let mut pos = 0;
                while pos + LSR_ENTRY_SIZE <= body.len() {
                    let ls_type = read_be_u32(body, pos)?;
                    let link_state_id =
                        [body[pos + 4], body[pos + 5], body[pos + 6], body[pos + 7]];
                    let adv_router = [body[pos + 8], body[pos + 9], body[pos + 10], body[pos + 11]];
                    let abs = body_offset + pos;

                    let obj_idx = buf.begin_container(
                        &LSR_ENTRY_CHILD_FIELDS[FD_LSR_LS_TYPE],
                        FieldValue::Object(0..0),
                        abs..abs + LSR_ENTRY_SIZE,
                    );
                    buf.push_field(
                        &LSR_ENTRY_CHILD_FIELDS[FD_LSR_LS_TYPE],
                        FieldValue::U32(ls_type),
                        abs..abs + 4,
                    );
                    buf.push_field(
                        &LSR_ENTRY_CHILD_FIELDS[FD_LSR_LINK_STATE_ID],
                        FieldValue::Ipv4Addr(link_state_id),
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
            // Link State Update (Type 4) — RFC 2328, A.3.5
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

                // Parse LSAs (header only — full LSA body parsing is out of scope)
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
            // Link State Acknowledgment (Type 5) — RFC 2328, A.3.6
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
            // Unknown type — common header only
            _ => {}
        }

        buf.end_layer();

        Ok(DissectResult::new(total_len, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 2328 (OSPFv2) Coverage
    //
    // | RFC Section | Description | Test |
    // |-------------|-------------|------|
    // | A.3.1 | Common header | parse_hello, parse_common_header |
    // | A.3.2 | Hello packet | parse_hello, parse_hello_with_neighbors |
    // | A.3.3 | Database Description | parse_dd |
    // | A.3.4 | Link State Request | parse_lsr |
    // | A.3.5 | Link State Update | parse_lsu |
    // | A.3.6 | Link State Ack | parse_lsack |
    // | A.4.1 | LSA header | parse_dd, parse_lsu, parse_lsack |

    /// Build an OSPFv2 common header.
    fn build_header(ospf_type: u8, packet_length: u16, router_id: [u8; 4]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(2); // version
        buf.push(ospf_type);
        buf.extend_from_slice(&packet_length.to_be_bytes());
        buf.extend_from_slice(&router_id); // Router ID
        buf.extend_from_slice(&[0, 0, 0, 0]); // Area ID (0.0.0.0)
        buf.extend_from_slice(&[0x00, 0x00]); // Checksum
        buf.extend_from_slice(&[0x00, 0x00]); // Auth Type (Null)
        buf.extend_from_slice(&[0u8; 8]); // Authentication
        buf
    }

    /// Build a sample LSA header.
    fn build_lsa_header(ls_type: u8, lsa_length: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x01]); // LS Age = 1
        buf.push(0x02); // Options
        buf.push(ls_type); // LS Type
        buf.extend_from_slice(&[10, 0, 0, 1]); // Link State ID
        buf.extend_from_slice(&[1, 1, 1, 1]); // Advertising Router
        buf.extend_from_slice(&[0x80, 0x00, 0x00, 0x01]); // LS Seq
        buf.extend_from_slice(&[0xAB, 0xCD]); // LS Checksum
        buf.extend_from_slice(&lsa_length.to_be_bytes()); // Length
        buf
    }

    #[test]
    fn parse_hello() {
        let mut pkt = build_header(1, 44, [1, 1, 1, 1]);
        // Hello body: 20 bytes, no neighbors
        pkt.extend_from_slice(&[255, 255, 255, 0]); // Network Mask
        pkt.extend_from_slice(&[0, 10]); // Hello Interval = 10
        pkt.push(0x02); // Options
        pkt.push(1); // Router Priority
        pkt.extend_from_slice(&[0, 0, 0, 40]); // Router Dead Interval = 40
        pkt.extend_from_slice(&[10, 0, 0, 1]); // DR
        pkt.extend_from_slice(&[10, 0, 0, 2]); // BDR

        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 44);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("OSPFv2").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(2)
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
            buf.field_by_name(layer, "router_id").unwrap().value,
            FieldValue::Ipv4Addr([1, 1, 1, 1])
        );
        assert_eq!(
            buf.field_by_name(layer, "network_mask").unwrap().value,
            FieldValue::Ipv4Addr([255, 255, 255, 0])
        );
        assert_eq!(
            buf.field_by_name(layer, "hello_interval").unwrap().value,
            FieldValue::U16(10)
        );
        assert_eq!(
            buf.field_by_name(layer, "router_priority").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "router_dead_interval")
                .unwrap()
                .value,
            FieldValue::U32(40)
        );
        assert_eq!(
            buf.field_by_name(layer, "designated_router").unwrap().value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert_eq!(
            buf.field_by_name(layer, "backup_designated_router")
                .unwrap()
                .value,
            FieldValue::Ipv4Addr([10, 0, 0, 2])
        );
    }

    #[test]
    fn parse_hello_with_neighbors() {
        let mut pkt = build_header(1, 52, [1, 1, 1, 1]);
        // Hello body
        pkt.extend_from_slice(&[255, 255, 255, 0]); // Network Mask
        pkt.extend_from_slice(&[0, 10]); // Hello Interval
        pkt.push(0x02); // Options
        pkt.push(1); // Router Priority
        pkt.extend_from_slice(&[0, 0, 0, 40]); // Router Dead Interval
        pkt.extend_from_slice(&[10, 0, 0, 1]); // DR
        pkt.extend_from_slice(&[10, 0, 0, 2]); // BDR
        // Two neighbors
        pkt.extend_from_slice(&[2, 2, 2, 2]);
        pkt.extend_from_slice(&[3, 3, 3, 3]);

        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 52);

        let layer = buf.layer_by_name("OSPFv2").unwrap();
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
        let mut pkt = build_header(2, 52, [1, 1, 1, 1]);
        // DD body: 8 bytes fixed
        pkt.extend_from_slice(&[0x05, 0xDC]); // Interface MTU = 1500
        pkt.push(0x02); // Options
        pkt.push(0x07); // Flags: I|M|MS
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // DD Seq = 1
        // One LSA header
        pkt.extend_from_slice(&build_lsa_header(1, 20));

        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 52);

        let layer = buf.layer_by_name("OSPFv2").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "interface_mtu").unwrap().value,
            FieldValue::U16(1500)
        );
        assert_eq!(
            buf.field_by_name(layer, "dd_flags").unwrap().value,
            FieldValue::U8(0x07)
        );
        assert_eq!(
            buf.field_by_name(layer, "dd_sequence_number")
                .unwrap()
                .value,
            FieldValue::U32(1)
        );

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
    fn parse_lsr() {
        let mut pkt = build_header(3, 36, [1, 1, 1, 1]);
        // One request entry: 12 bytes
        pkt.extend_from_slice(&[0, 0, 0, 1]); // LS Type = 1
        pkt.extend_from_slice(&[10, 0, 0, 1]); // Link State ID
        pkt.extend_from_slice(&[2, 2, 2, 2]); // Advertising Router

        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 36);

        let layer = buf.layer_by_name("OSPFv2").unwrap();
        let requests = buf.field_by_name(layer, "requests").unwrap();
        if let FieldValue::Array(ref range) = requests.value {
            let items = buf.nested_fields(range);
            let first_obj = items
                .iter()
                .find(|f| f.value.is_object())
                .expect("expected Object");
            if let FieldValue::Object(ref obj_range) = first_obj.value {
                let obj_fields = buf.nested_fields(obj_range);
                assert_eq!(obj_fields[0].value, FieldValue::U32(1)); // ls_type
                assert_eq!(obj_fields[1].value, FieldValue::Ipv4Addr([10, 0, 0, 1])); // link_state_id
                assert_eq!(obj_fields[2].value, FieldValue::Ipv4Addr([2, 2, 2, 2])); // advertising_router
            } else {
                panic!("expected Object");
            }
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn parse_lsu() {
        let lsa = build_lsa_header(1, 20);
        let pkt_len = (HEADER_SIZE + 4 + lsa.len()) as u16;
        let mut pkt = build_header(4, pkt_len, [1, 1, 1, 1]);
        pkt.extend_from_slice(&[0, 0, 0, 1]); // # LSAs = 1
        pkt.extend_from_slice(&lsa);

        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, pkt_len as usize);

        let layer = buf.layer_by_name("OSPFv2").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "num_lsas").unwrap().value,
            FieldValue::U32(1)
        );
        let lsas = buf.field_by_name(layer, "lsas").unwrap();
        if let FieldValue::Array(ref range) = lsas.value {
            let items = buf.nested_fields(range);
            let obj_count = items.iter().filter(|f| f.value.is_object()).count();
            assert_eq!(obj_count, 1);
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn parse_lsack() {
        let lsa = build_lsa_header(1, 20);
        let pkt_len = (HEADER_SIZE + lsa.len()) as u16;
        let mut pkt = build_header(5, pkt_len, [1, 1, 1, 1]);
        pkt.extend_from_slice(&lsa);

        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, pkt_len as usize);

        let layer = buf.layer_by_name("OSPFv2").unwrap();
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
        let data = [0x02, 0x01, 0x00];
        let mut buf = DissectBuffer::new();
        let err = Ospfv2Dissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 24,
                actual: 3
            }
        ));
    }

    #[test]
    fn parse_wrong_version() {
        let pkt = build_header(1, 44, [1, 1, 1, 1]);
        let mut modified = pkt.clone();
        modified[0] = 3; // Set version to 3

        let mut buf = DissectBuffer::new();
        let err = Ospfv2Dissector.dissect(&modified, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_with_offset() {
        let mut pkt = build_header(1, 44, [1, 1, 1, 1]);
        // Hello body, no neighbors
        pkt.extend_from_slice(&[255, 255, 255, 0]);
        pkt.extend_from_slice(&[0, 10]);
        pkt.push(0x02);
        pkt.push(1);
        pkt.extend_from_slice(&[0, 0, 0, 40]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);

        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 34).unwrap();
        assert_eq!(result.bytes_consumed, 44);

        let layer = buf.layer_by_name("OSPFv2").unwrap();
        assert_eq!(layer.range, 34..78);
        // Version field should be at absolute offset 34
        assert_eq!(buf.field_by_name(layer, "version").unwrap().range, 34..35);
    }
}
