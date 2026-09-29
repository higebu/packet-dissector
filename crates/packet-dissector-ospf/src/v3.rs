//! OSPFv3 (Open Shortest Path First version 3) dissector.
//!
//! ## References
//! - RFC 5340: <https://www.rfc-editor.org/rfc/rfc5340>
//! - RFC 5613 (LLS): <https://www.rfc-editor.org/rfc/rfc5613>
//! - RFC 7166 (Authentication Trailer): <https://www.rfc-editor.org/rfc/rfc7166>
//! - RFC 7770 (Router Information): <https://www.rfc-editor.org/rfc/rfc7770>
//! - RFC 8362 (Extended LSAs): <https://www.rfc-editor.org/rfc/rfc8362>
//! - RFC 8666 (Segment Routing): <https://www.rfc-editor.org/rfc/rfc8666>
//! - RFC 9513 (SRv6): <https://www.rfc-editor.org/rfc/rfc9513>

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

use crate::common::{LSR_ENTRY_SIZE, push_lsa_headers, push_lsu_lsas};
use crate::tlv::UNPARSED_DESCRIPTOR;
use crate::trailer::{
    AUTH_TRAILER_DESCRIPTOR, LLS_DESCRIPTOR, auth_trailer_len, push_auth_trailer, push_lls,
};
use crate::v3_lsa::{
    FD_LSA, FD_LSA_HEADER, LSA_CHILD_FIELDS, LSA_HEADER_FIELDS, lsa_type_name, push_lsa,
    push_lsa_header_fields,
};

/// OSPFv3 common header size in bytes.
///
/// RFC 5340, Appendix A.3.1 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.3.1>
const HEADER_SIZE: usize = 16;

/// Hello packet body size excluding neighbors.
///
/// RFC 5340, Appendix A.3.2 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.3.2>
const HELLO_BODY_SIZE: usize = 20;

/// Database Description packet body size excluding LSA headers.
///
/// RFC 5340, Appendix A.3.3 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.3.3>
const DD_BODY_SIZE: usize = 12;

/// Field descriptor indices for [`LSR_ENTRY_CHILD_FIELDS`].
const FD_LSR_LS_TYPE: usize = 0;
const FD_LSR_LINK_STATE_ID: usize = 1;
const FD_LSR_ADVERTISING_ROUTER: usize = 2;

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

/// Container descriptor for an LSR entry Object.
///
/// The outer label resolves to the LSA type name (e.g. `Router-LSA`) by
/// looking up the inner `ls_type` field, avoiding collision with the
/// inner "LS Type" label.
static FD_LSR_ENTRY: FieldDescriptor = FieldDescriptor {
    name: "lsr_entry",
    display_name: "LSR Entry",
    field_type: FieldType::Object,
    optional: false,
    children: Some(LSR_ENTRY_CHILD_FIELDS),
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("ls_type", FieldValue::U16(t)) => lsa_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

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
// Data after the packet
const FD_LLS: usize = 22;
const FD_AUTH_TRAILER: usize = 23;

/// L-bit in the OSPFv3 Options field.
///
/// RFC 5613, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc5613#section-2.1>
const OPTIONS_L_BIT: u32 = 0x200;

/// AT-bit in the OSPFv3 Options field.
///
/// RFC 7166, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc7166#section-2.1>
const OPTIONS_AT_BIT: u32 = 0x400;

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
        .with_children(LSA_HEADER_FIELDS),
    // LSR fields
    FieldDescriptor::new("requests", "Link State Requests", FieldType::Array)
        .optional()
        .with_children(LSR_ENTRY_CHILD_FIELDS),
    // LSU fields
    FieldDescriptor::new("num_lsas", "Number of LSAs", FieldType::U32).optional(),
    FieldDescriptor::new("lsas", "LSAs", FieldType::Array)
        .optional()
        .with_children(LSA_CHILD_FIELDS),
    // LLS data block — RFC 5613, Section 2.2
    // <https://www.rfc-editor.org/rfc/rfc5613#section-2.2>
    LLS_DESCRIPTOR,
    // Authentication Trailer — RFC 7166, Section 4.1
    // <https://www.rfc-editor.org/rfc/rfc7166#section-4.1>
    AUTH_TRAILER_DESCRIPTOR,
    // Bytes after the last LSA / LSA header that could be delimited.
    UNPARSED_DESCRIPTOR,
];

/// OSPFv3 dissector.
pub struct Ospfv3Dissector;

/// Specification references for the OSPFv3 dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 5340",
        "OSPF for IPv6",
        "https://www.rfc-editor.org/rfc/rfc5340",
    ),
    SpecReference::new(
        "RFC 5613",
        "OSPF Link-Local Signaling",
        "https://www.rfc-editor.org/rfc/rfc5613",
    ),
    SpecReference::new(
        "RFC 7166",
        "Supporting Authentication Trailer for OSPFv3",
        "https://www.rfc-editor.org/rfc/rfc7166",
    ),
    SpecReference::new(
        "RFC 7770",
        "Extensions to OSPF for Advertising Optional Router Capabilities",
        "https://www.rfc-editor.org/rfc/rfc7770",
    ),
    SpecReference::new(
        "RFC 8362",
        "OSPFv3 Link State Advertisement (LSA) Extensibility",
        "https://www.rfc-editor.org/rfc/rfc8362",
    ),
    SpecReference::new(
        "RFC 8666",
        "OSPFv3 Extensions for Segment Routing",
        "https://www.rfc-editor.org/rfc/rfc8666",
    ),
    SpecReference::new(
        "RFC 9513",
        "OSPFv3 Extensions for Segment Routing over IPv6 (SRv6)",
        "https://www.rfc-editor.org/rfc/rfc9513",
    ),
];

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

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Network)
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

        // RFC 5340, Appendix A.3.1 — Common header (16 bytes, no auth fields)
        // <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.3.1>
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

        // Options of Hello / DD packets, used for the L and AT bits.
        let mut packet_options = None;
        match ospf_type {
            // Hello (Type 1) — RFC 5340, Appendix A.3.2
            // <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.3.2>
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
                packet_options = Some(options);
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

                // Neighbor list (Router IDs, 4 bytes each).
                // RFC 5340, Appendix A.3.2 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.3.2>
                let neighbor_data = &body[HELLO_BODY_SIZE..];
                if neighbor_data.len() % 4 != 0 {
                    return Err(PacketError::InvalidHeader(
                        "ospfv3: neighbor list length is not a multiple of 4",
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
            // Database Description (Type 2) — RFC 5340, Appendix A.3.3
            // <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.3.3>
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
                packet_options = Some(options);
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
                push_lsa_headers(
                    buf,
                    &FIELD_DESCRIPTORS[FD_LSA_HEADERS],
                    lsa_data,
                    lsa_start,
                    &FD_LSA_HEADER,
                    push_lsa_header_fields,
                );
            }
            // Link State Request (Type 3) — RFC 5340, Appendix A.3.4
            // <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.3.4>
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
                        &FD_LSR_ENTRY,
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
            // Link State Update (Type 4) — RFC 5340, Appendix A.3.5
            // <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.3.5>
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

                // LSAs, each delimited by its own length field.
                push_lsu_lsas(
                    buf,
                    &FIELD_DESCRIPTORS[FD_LSAS],
                    body,
                    num_lsas,
                    body_offset,
                    &FD_LSA,
                    push_lsa,
                );
            }
            // Link State Acknowledgment (Type 5) — RFC 5340, Appendix A.3.6
            // <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.3.6>
            5 => {
                push_lsa_headers(
                    buf,
                    &FIELD_DESCRIPTORS[FD_LSA_HEADERS],
                    body,
                    body_offset,
                    &FD_LSA_HEADER,
                    push_lsa_header_fields,
                );
            }
            _ => {}
        }

        // Data appended after the packet, outside `packet_length`.
        let mut consumed = total_len;

        // RFC 5613, Section 2 — <https://www.rfc-editor.org/rfc/rfc5613#section-2>
        // Only Hello and DD packets carry an LLS block, and "the LLS data
        // block is only examined if the L-bit is set."
        if packet_options.is_some_and(|o| o & OPTIONS_L_BIT != 0) {
            consumed += push_lls(
                buf,
                &data[consumed..],
                offset + consumed,
                &FIELD_DESCRIPTORS[FD_LLS],
            );
        }

        // RFC 7166, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc7166#section-2.1>
        // "For OSPFv3 Hello and Database Description packets, the AT-bit
        // indicates that the AT is present." Other packet types rely on
        // per-neighbor state that a single packet does not carry, so the
        // trailer is decoded only when its Auth Data Len accounts for exactly
        // the remaining bytes.
        let rest = &data[consumed..];
        if let Some(len) = auth_trailer_len(rest) {
            let present = match packet_options {
                Some(o) => o & OPTIONS_AT_BIT != 0,
                None => len == rest.len(),
            };
            if present {
                push_auth_trailer(
                    buf,
                    rest,
                    len,
                    offset + consumed,
                    &FIELD_DESCRIPTORS[FD_AUTH_TRAILER],
                );
                consumed += len;
            }
        }

        if let Some(layer) = buf.last_layer_mut() {
            layer.range.end = offset + consumed;
        }
        buf.end_layer();

        Ok(DissectResult::new(consumed, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 5340 (OSPFv3) Coverage
    //
    // RFC 5340: <https://www.rfc-editor.org/rfc/rfc5340>
    //
    // | RFC Section      | Description                   | Test                                         |
    // |------------------|-------------------------------|----------------------------------------------|
    // | Appendix A.3.1   | Common header                 | parse_hello, parse_wrong_version,            |
    // |                  |                               | parse_truncated_header                       |
    // | Appendix A.3.2   | Hello packet                  | parse_hello, parse_hello_with_neighbors,     |
    // |                  |                               | parse_hello_misaligned_neighbors             |
    // | Appendix A.3.3   | Database Description          | parse_dd                                     |
    // | Appendix A.3.4   | Link State Request            | parse_lsr, lsa_type_nssa_name,               |
    // |                  |                               | lsr_entry_container_resolves_to_lsa_type_name |
    // | Appendix A.3.5   | Link State Update             | parse_lsu, lsa_containers_are_labeled        |
    // | Appendix A.3.6   | Link State Ack                | parse_lsack, lsa_containers_are_labeled      |
    // | Appendix A.4.1   | IPv6 prefix encoding          | parse_network_and_inter_area_lsas,           |
    // |                  |                               | parse_invalid_prefix_length                  |
    // | Appendix A.4.2   | LSA header                    | parse_dd, parse_lsu, parse_lsack             |
    // | Appendix A.4.2.1 | LSA Type / Function Code      | lsa_type_names_cover_rfc5340,                |
    // |                  |                               | lsa_type_nssa_name, lsa_type_names_cover_registry |
    // | Appendix A.4.3   | Router-LSA                    | parse_router_lsa                             |
    // | Appendix A.4.4   | Network-LSA                   | parse_network_and_inter_area_lsas            |
    // | Appendix A.4.5   | Inter-Area-Prefix-LSA         | parse_network_and_inter_area_lsas            |
    // | Appendix A.4.6   | Inter-Area-Router-LSA         | parse_network_and_inter_area_lsas            |
    // | Appendix A.4.7   | AS-External-LSA               | parse_as_external_and_nssa_lsas              |
    // | Appendix A.4.8   | NSSA-LSA                      | parse_as_external_and_nssa_lsas              |
    // | Appendix A.4.9   | Link-LSA                      | parse_link_and_intra_area_prefix_lsas        |
    // | Appendix A.4.10  | Intra-Area-Prefix-LSA         | parse_link_and_intra_area_prefix_lsas        |
    // | —                | Unknown / malformed LSAs      | parse_unknown_and_malformed_lsas             |
    //
    // | Other RFC           | Description                   | Test                                      |
    // |---------------------|-------------------------------|-------------------------------------------|
    // | RFC 7770 Sec. 2.2   | Router Information LSA        | parse_router_information_lsa              |
    // | RFC 9513 Sec. 2     | SRv6 Capabilities TLV         | parse_router_information_lsa              |
    // | RFC 8362 Sec. 3.2, 4.1 | E-Router-LSA, Router-Link TLV | parse_e_router_lsa                     |
    // | RFC 8362 Sec. 3.3-3.12, 4.2-4.8 | Other Extended LSAs / TLVs | parse_extended_lsas             |
    // | RFC 8666 Sec. 3.1, 6, 7 | SID/Label, Prefix-SID, Adj-SID | parse_e_router_lsa, parse_extended_lsas |
    // | RFC 9513 Sec. 7-8   | SRv6 Locator LSA, End SID     | parse_srv6_locator_lsa                    |
    // | RFC 9513 Sec. 9     | SRv6 End.X / LAN End.X SID    | parse_e_router_lsa                        |
    // | RFC 5613 Sec. 2     | LLS data block                | parse_hello_lls_and_auth_trailer          |
    // | RFC 7166 Sec. 2.1, 4.1 | Authentication Trailer     | parse_hello_lls_and_auth_trailer,         |
    // |                     |                               | parse_hello_without_at_bit_ignores_trailer, |
    // |                     |                               | parse_auth_trailer_on_lsack_and_dd        |

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

    /// RFC 5340, Appendix A.4.2.1 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.2.1>
    ///
    /// LSA function code 7 (LS Type 0x2007) is "NSSA-LSA", not "Type-7-LSA".
    #[test]
    fn lsa_type_nssa_name() {
        // Build an LSR with LS Type = 0x2007 (NSSA-LSA, area scope).
        let mut pkt = build_header(3, 28, [1, 1, 1, 1]);
        pkt.extend_from_slice(&[0, 0]); // Reserved
        pkt.extend_from_slice(&[0x20, 0x07]); // LS Type = 0x2007
        pkt.extend_from_slice(&[0, 0, 0, 1]); // Link State ID
        pkt.extend_from_slice(&[2, 2, 2, 2]); // Advertising Router

        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("OSPFv3").unwrap();
        let requests = buf.field_by_name(layer, "requests").unwrap();
        let FieldValue::Array(ref range) = requests.value else {
            panic!("expected Array");
        };
        let items = buf.nested_fields(range);
        let first_obj = items
            .iter()
            .find(|f| f.value.is_object())
            .expect("expected Object");
        let FieldValue::Object(ref obj_range) = first_obj.value else {
            panic!("expected Object");
        };
        assert_eq!(
            buf.resolve_nested_display_name(obj_range, "ls_type_name"),
            Some("NSSA-LSA"),
        );
    }

    /// RFC 5340, Appendix A.4.2.1 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.2.1>
    ///
    /// All LSA function codes defined in RFC 5340 resolve to human-readable names.
    /// Function code 6 is explicitly marked "Deprecated (may be reassigned)" and
    /// intentionally has no name.
    #[test]
    fn lsa_type_names_cover_rfc5340() {
        fn name_of(ls_type: u16) -> Option<&'static str> {
            lsa_type_name(ls_type)
        }
        assert_eq!(name_of(0x2001), Some("Router-LSA"));
        assert_eq!(name_of(0x2002), Some("Network-LSA"));
        assert_eq!(name_of(0x2003), Some("Inter-Area-Prefix-LSA"));
        assert_eq!(name_of(0x2004), Some("Inter-Area-Router-LSA"));
        assert_eq!(name_of(0x4005), Some("AS-External-LSA"));
        assert_eq!(name_of(0x2006), None); // Deprecated
        assert_eq!(name_of(0x2007), Some("NSSA-LSA"));
        assert_eq!(name_of(0x0008), Some("Link-LSA"));
        assert_eq!(name_of(0x2009), Some("Intra-Area-Prefix-LSA"));
    }

    /// RFC 5340, Appendix A.3.2 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.3.2>
    ///
    /// The neighbor list is a sequence of 4-byte Router IDs. If the declared
    /// packet length leaves a remainder that is not a multiple of 4, the header
    /// itself is malformed — report `InvalidHeader` rather than `Truncated`,
    /// because all the declared bytes are present in the buffer.
    #[test]
    fn parse_hello_misaligned_neighbors() {
        // Header (16) + Hello body (20) + 2 spurious bytes = 38.
        let mut pkt = build_header(1, 38, [1, 1, 1, 1]);
        pkt.extend_from_slice(&[0, 0, 0, 1]); // Interface ID
        pkt.push(1); // Rtr Priority
        pkt.extend_from_slice(&[0x00, 0x00, 0x13]); // Options
        pkt.extend_from_slice(&[0, 10]); // HelloInterval
        pkt.extend_from_slice(&[0, 40]); // RouterDeadInterval
        pkt.extend_from_slice(&[10, 0, 0, 1]); // DR
        pkt.extend_from_slice(&[10, 0, 0, 2]); // BDR
        pkt.extend_from_slice(&[0xAA, 0xBB]); // 2 extra bytes (misaligned)

        let mut buf = DissectBuffer::new();
        let err = Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap_err();
        assert!(
            matches!(err, PacketError::InvalidHeader(_)),
            "expected InvalidHeader, got {err:?}",
        );
    }

    #[test]
    fn references_and_layer_are_populated() {
        let dissector = Ospfv3Dissector;
        let references = dissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Network));
    }

    // ---------------------------------------------------------------------
    // LSA bodies, Extended LSAs and trailers
    // ---------------------------------------------------------------------

    use crate::common::test_util::{assert_child, child, children, has_child, index_of, range};

    /// Build an OSPFv3 LSA: 20-byte header followed by `body`.
    fn build_lsa(ls_type: u16, body: &[u8]) -> Vec<u8> {
        let mut lsa = build_lsa_header(ls_type, (20 + body.len()) as u16);
        lsa.extend_from_slice(body);
        lsa
    }

    /// Build an LSU packet carrying `lsas`.
    fn build_lsu(lsas: &[Vec<u8>]) -> Vec<u8> {
        let total: usize = lsas.iter().map(Vec::len).sum();
        let mut pkt = build_header(4, (HEADER_SIZE + 4 + total) as u16, [1, 1, 1, 1]);
        pkt.extend_from_slice(&(lsas.len() as u32).to_be_bytes());
        for lsa in lsas {
            pkt.extend_from_slice(lsa);
        }
        pkt
    }

    /// Build a TLV (type, length, value) padded to a 4-octet boundary.
    fn tlv(t: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    /// 2001:db8::/32 encoded as an OSPFv3 address prefix (one 32-bit word).
    const DOC_PREFIX: [u8; 4] = [0x20, 0x01, 0x0d, 0xb8];

    fn ipv6(prefix: &[u8]) -> FieldValue<'static> {
        let mut addr = [0u8; 16];
        addr[..prefix.len()].copy_from_slice(prefix);
        FieldValue::Ipv6Addr(addr)
    }

    fn lsa_range(buf: &DissectBuffer<'_>, index: usize) -> core::ops::Range<u32> {
        let layer = buf.layer_by_name("OSPFv3").unwrap();
        let lsas = buf.field_by_name(layer, "lsas").unwrap();
        range(children(buf, &range(lsas))[index])
    }

    fn item_range(
        buf: &DissectBuffer<'_>,
        parent: &core::ops::Range<u32>,
        array: &str,
        index: usize,
    ) -> core::ops::Range<u32> {
        range(children(buf, &range(child(buf, parent, array)))[index])
    }

    fn item_name(
        buf: &DissectBuffer<'_>,
        parent: &core::ops::Range<u32>,
        array: &str,
        index: usize,
    ) -> Option<&'static str> {
        let items = children(buf, &range(child(buf, parent, array)));
        buf.resolve_container_display_name(index_of(buf, items[index]))
    }

    /// OSPFv3 LSR entries use a dedicated `lsr_entry` container.
    #[test]
    fn lsr_entry_container_resolves_to_lsa_type_name() {
        let mut pkt = build_header(3, 28, [1, 1, 1, 1]);
        pkt.extend_from_slice(&[0, 0, 0x20, 0x01, 0, 0, 0, 0, 2, 2, 2, 2]);
        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("OSPFv3").unwrap();
        let items = children(&buf, &range(buf.field_by_name(layer, "requests").unwrap()));
        assert_eq!(items[0].name(), "lsr_entry");
        assert_eq!(
            buf.resolve_container_display_name(index_of(&buf, items[0])),
            Some("Router-LSA")
        );
    }

    /// DD / LSAck entries are `lsa_header` objects; LSU entries are `lsa`.
    #[test]
    fn lsa_containers_are_labeled() {
        let lsa = build_lsa_header(0x2009, 20);
        let mut pkt = build_header(5, (HEADER_SIZE + lsa.len()) as u16, [1, 1, 1, 1]);
        pkt.extend_from_slice(&lsa);
        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("OSPFv3").unwrap();
        let items = children(
            &buf,
            &range(buf.field_by_name(layer, "lsa_headers").unwrap()),
        );
        assert_eq!(items[0].name(), "lsa_header");
        assert_eq!(
            buf.resolve_container_display_name(index_of(&buf, items[0])),
            Some("Intra-Area-Prefix-LSA")
        );

        let pkt = build_lsu(&[build_lsa(0x2001, &[0, 0, 0, 0x13])]);
        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("OSPFv3").unwrap();
        let items = children(&buf, &range(buf.field_by_name(layer, "lsas").unwrap()));
        assert_eq!(items[0].name(), "lsa");
        assert_eq!(
            buf.resolve_container_display_name(index_of(&buf, items[0])),
            Some("Router-LSA")
        );
    }

    /// RFC 5340, Appendix A.4.3 — Router-LSA.
    /// <https://www.rfc-editor.org/rfc/rfc5340>
    #[test]
    fn parse_router_lsa() {
        let mut body = vec![0x03, 0x00, 0x00, 0x13]; // E|B, options V6|E|R
        body.extend_from_slice(&[1, 0, 0, 10, 0, 0, 0, 5, 0, 0, 0, 6, 2, 2, 2, 2]);
        body.extend_from_slice(&[2, 0]); // trailing garbage
        let pkt = build_lsu(&[build_lsa(0x2001, &body)]);
        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let lsa = lsa_range(&buf, 0);
        assert_child(&buf, &lsa, "flags", FieldValue::U8(0x03));
        assert_child(&buf, &lsa, "flag_nt", FieldValue::U8(0));
        assert_child(&buf, &lsa, "flag_v", FieldValue::U8(0));
        assert_child(&buf, &lsa, "flag_e", FieldValue::U8(1));
        assert_child(&buf, &lsa, "flag_b", FieldValue::U8(1));
        assert_child(&buf, &lsa, "options", FieldValue::U32(0x13));
        let link = item_range(&buf, &lsa, "links", 0);
        assert_child(&buf, &link, "link_type", FieldValue::U8(1));
        assert_eq!(
            buf.resolve_nested_display_name(&link, "link_type_name"),
            Some("Point-to-point")
        );
        assert_child(&buf, &link, "metric", FieldValue::U16(10));
        assert_child(&buf, &link, "interface_id", FieldValue::U32(5));
        assert_child(&buf, &link, "neighbor_interface_id", FieldValue::U32(6));
        assert_child(
            &buf,
            &link,
            "neighbor_router_id",
            FieldValue::Ipv4Addr([2, 2, 2, 2]),
        );
        assert_child(&buf, &lsa, "unparsed", FieldValue::Bytes(&[2, 0]));
    }

    /// RFC 5340, Appendices A.4.4-A.4.6 — Network, Inter-Area-Prefix and
    /// Inter-Area-Router LSAs.
    /// <https://www.rfc-editor.org/rfc/rfc5340>
    #[test]
    fn parse_network_and_inter_area_lsas() {
        let network = [0, 0, 0, 0x13, 1, 1, 1, 1, 2, 2, 2, 2];
        let mut iap = vec![0, 0, 0, 20, 32, 0x02, 0, 0];
        iap.extend_from_slice(&DOC_PREFIX);
        let iar = [0, 0, 0, 0x13, 0, 0, 0, 30, 3, 3, 3, 3];
        let pkt = build_lsu(&[
            build_lsa(0x2002, &network),
            build_lsa(0x2003, &iap),
            build_lsa(0x2004, &iar),
        ]);
        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let net = lsa_range(&buf, 0);
        assert_child(&buf, &net, "options", FieldValue::U32(0x13));
        let routers = children(&buf, &range(child(&buf, &net, "attached_routers")));
        assert_eq!(routers.len(), 2);
        assert_eq!(routers[0].value, FieldValue::Ipv4Addr([1, 1, 1, 1]));

        let iap = lsa_range(&buf, 1);
        assert_child(&buf, &iap, "metric", FieldValue::U32(20));
        assert_child(&buf, &iap, "prefix_length", FieldValue::U8(32));
        assert_child(&buf, &iap, "prefix_options", FieldValue::U8(0x02));
        assert_child(&buf, &iap, "prefix", ipv6(&DOC_PREFIX));

        let iar = lsa_range(&buf, 2);
        assert_child(&buf, &iar, "options", FieldValue::U32(0x13));
        assert_child(&buf, &iar, "metric", FieldValue::U32(30));
        assert_child(
            &buf,
            &iar,
            "destination_router_id",
            FieldValue::Ipv4Addr([3, 3, 3, 3]),
        );
    }

    /// RFC 5340, Appendices A.4.7-A.4.8 — AS-External-LSA with F/T bits and a
    /// referenced LSA, and NSSA-LSA without optional fields.
    /// <https://www.rfc-editor.org/rfc/rfc5340>
    #[test]
    fn parse_as_external_and_nssa_lsas() {
        let mut ext = vec![0x07, 0, 0, 100, 32, 0, 0x20, 0x01];
        ext.extend_from_slice(&DOC_PREFIX);
        let fwd = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        ext.extend_from_slice(&fwd);
        ext.extend_from_slice(&[0, 0, 0, 77]); // route tag
        ext.extend_from_slice(&[0, 0, 0, 5]); // referenced link state ID
        let mut nssa = vec![0x00, 0, 0, 1, 0, 0, 0, 0];
        nssa.extend_from_slice(&[]);
        let pkt = build_lsu(&[build_lsa(0x4005, &ext), build_lsa(0x2007, &nssa)]);
        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let ext = lsa_range(&buf, 0);
        assert_child(&buf, &ext, "flags", FieldValue::U8(0x07));
        assert_child(&buf, &ext, "flag_e", FieldValue::U8(1));
        assert_child(&buf, &ext, "flag_f", FieldValue::U8(1));
        assert_child(&buf, &ext, "flag_t", FieldValue::U8(1));
        assert_child(&buf, &ext, "metric", FieldValue::U32(100));
        assert_child(&buf, &ext, "referenced_ls_type", FieldValue::U16(0x2001));
        assert_child(&buf, &ext, "prefix", ipv6(&DOC_PREFIX));
        assert_child(&buf, &ext, "forwarding_address", ipv6(&fwd));
        assert_child(&buf, &ext, "external_route_tag", FieldValue::U32(77));
        assert_child(&buf, &ext, "referenced_link_state_id", FieldValue::U32(5));

        let nssa = lsa_range(&buf, 1);
        assert_child(&buf, &nssa, "prefix_length", FieldValue::U8(0));
        assert_child(&buf, &nssa, "prefix", ipv6(&[]));
        assert!(!has_child(&buf, &nssa, "forwarding_address"));
        assert!(!has_child(&buf, &nssa, "unparsed"));
    }

    /// RFC 5340, Appendices A.4.9-A.4.10 — Link-LSA and Intra-Area-Prefix-LSA.
    /// <https://www.rfc-editor.org/rfc/rfc5340>
    #[test]
    fn parse_link_and_intra_area_prefix_lsas() {
        let mut link = vec![1, 0, 0, 0x13];
        link.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        link.extend_from_slice(&[0, 0, 0, 1, 64, 0, 0, 0]);
        link.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]);
        let mut iap = vec![0, 1, 0x20, 0x01, 0, 0, 0, 0, 1, 1, 1, 1];
        iap.extend_from_slice(&[128, 0x02, 0, 0]);
        iap.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let pkt = build_lsu(&[build_lsa(0x0008, &link), build_lsa(0x2009, &iap)]);
        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let link = lsa_range(&buf, 0);
        assert_child(&buf, &link, "router_priority", FieldValue::U8(1));
        assert_child(&buf, &link, "options", FieldValue::U32(0x13));
        assert_child(
            &buf,
            &link,
            "link_local_address",
            ipv6(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        );
        assert_child(&buf, &link, "num_prefixes", FieldValue::U32(1));
        let p = item_range(&buf, &link, "prefixes", 0);
        assert_child(&buf, &p, "prefix_length", FieldValue::U8(64));
        assert_child(
            &buf,
            &p,
            "prefix",
            ipv6(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]),
        );

        let iap = lsa_range(&buf, 1);
        assert_child(&buf, &iap, "num_prefixes", FieldValue::U32(1));
        assert_child(&buf, &iap, "referenced_ls_type", FieldValue::U16(0x2001));
        assert_child(
            &buf,
            &iap,
            "referenced_advertising_router",
            FieldValue::Ipv4Addr([1, 1, 1, 1]),
        );
        let p = item_range(&buf, &iap, "prefixes", 0);
        assert_child(&buf, &p, "prefix_length", FieldValue::U8(128));
        assert_child(&buf, &p, "prefix_options", FieldValue::U8(0x02));
        assert_child(&buf, &p, "metric", FieldValue::U16(0));
    }

    /// A PrefixLength above 128 stops decoding; the rest is `unparsed`.
    #[test]
    fn parse_invalid_prefix_length() {
        let iap = [0, 0, 0, 1, 200, 0, 0, 0, 1, 2, 3, 4];
        let pkt = build_lsu(&[build_lsa(0x2003, &iap)]);
        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let lsa = lsa_range(&buf, 0);
        assert!(!has_child(&buf, &lsa, "prefix"));
        assert_child(&buf, &lsa, "body", FieldValue::Bytes(&iap));
    }

    /// RFC 7770, Section 2.2 and RFC 9513, Section 2 — OSPFv3 Router
    /// Information LSA with the SRv6 Capabilities TLV.
    /// <https://www.rfc-editor.org/rfc/rfc7770#section-2.2>
    /// <https://www.rfc-editor.org/rfc/rfc9513#section-2>
    #[test]
    fn parse_router_information_lsa() {
        let mut body = tlv(8, &[0, 128]);
        body.extend(tlv(20, &[0x40, 0, 0, 0]));
        let pkt = build_lsu(&[build_lsa(0xA00C, &body)]);
        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("OSPFv3").unwrap();
        let lsas = children(&buf, &range(buf.field_by_name(layer, "lsas").unwrap()));
        assert_eq!(
            buf.resolve_container_display_name(index_of(&buf, lsas[0])),
            Some("OSPFv3 Router Information (RI) LSA")
        );
        let lsa = lsa_range(&buf, 0);
        assert_eq!(item_name(&buf, &lsa, "tlvs", 0), Some("SR-Algorithm"));
        assert_eq!(item_name(&buf, &lsa, "tlvs", 1), Some("SRv6 Capabilities"));
        let caps = item_range(&buf, &lsa, "tlvs", 1);
        assert_child(&buf, &caps, "flags", FieldValue::U16(0x4000));
    }

    /// RFC 8362, Sections 3.2 and 4.1; RFC 8666, Section 7; RFC 9513,
    /// Section 9 — E-Router-LSA with a Router-Link TLV and SR sub-TLVs.
    /// <https://www.rfc-editor.org/rfc/rfc8362#section-3.2>
    /// <https://www.rfc-editor.org/rfc/rfc8666#section-7>
    /// <https://www.rfc-editor.org/rfc/rfc9513>
    #[test]
    fn parse_e_router_lsa() {
        let mut link = vec![1, 0, 0, 10, 0, 0, 0, 5, 0, 0, 0, 6, 2, 2, 2, 2];
        link.extend(tlv(5, &[0x60, 1, 0, 0, 0x00, 0x5d, 0xc0])); // Adj-SID
        link.extend(tlv(6, &[0x60, 1, 0, 0, 3, 3, 3, 3, 0x00, 0x5d, 0xc1]));
        let mut end_x = vec![0, 5, 0x80, 0, 0, 1, 0, 0];
        end_x.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x41,
        ]);
        link.extend(tlv(31, &end_x));
        let mut lan_end_x = vec![0, 5, 0, 0, 0, 1, 0, 0, 4, 4, 4, 4];
        lan_end_x.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
        ]);
        link.extend(tlv(32, &lan_end_x));
        let mut body = vec![0x01, 0, 0, 0x13];
        body.extend(tlv(1, &link));
        let pkt = build_lsu(&[build_lsa(0xA021, &body)]);
        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("OSPFv3").unwrap();
        let lsas = children(&buf, &range(buf.field_by_name(layer, "lsas").unwrap()));
        assert_eq!(
            buf.resolve_container_display_name(index_of(&buf, lsas[0])),
            Some("E-Router-LSA")
        );
        let lsa = lsa_range(&buf, 0);
        assert_child(&buf, &lsa, "flag_b", FieldValue::U8(1));
        assert_child(&buf, &lsa, "options", FieldValue::U32(0x13));
        assert_eq!(item_name(&buf, &lsa, "tlvs", 0), Some("Router-Link"));
        let rl = item_range(&buf, &lsa, "tlvs", 0);
        assert_child(&buf, &rl, "link_type", FieldValue::U8(1));
        assert_child(&buf, &rl, "metric", FieldValue::U32(10));
        assert_child(&buf, &rl, "interface_id", FieldValue::U32(5));
        assert_child(&buf, &rl, "neighbor_interface_id", FieldValue::U32(6));
        assert_child(
            &buf,
            &rl,
            "neighbor_router_id",
            FieldValue::Ipv4Addr([2, 2, 2, 2]),
        );
        assert_eq!(item_name(&buf, &rl, "sub_tlvs", 0), Some("Adj-SID"));
        let adj = item_range(&buf, &rl, "sub_tlvs", 0);
        assert_child(&buf, &adj, "flags", FieldValue::U8(0x60));
        assert_child(&buf, &adj, "weight", FieldValue::U8(1));
        assert_child(&buf, &adj, "sid", FieldValue::U32(24000));
        let lan = item_range(&buf, &rl, "sub_tlvs", 1);
        assert_child(
            &buf,
            &lan,
            "neighbor_id",
            FieldValue::Ipv4Addr([3, 3, 3, 3]),
        );
        assert_child(&buf, &lan, "sid", FieldValue::U32(24001));
        let ex = item_range(&buf, &rl, "sub_tlvs", 2);
        assert_eq!(item_name(&buf, &rl, "sub_tlvs", 2), Some("SRv6 End.X SID"));
        assert_child(&buf, &ex, "endpoint_behavior", FieldValue::U16(5));
        assert_child(&buf, &ex, "flags", FieldValue::U8(0x80));
        assert_child(&buf, &ex, "weight", FieldValue::U8(1));
        assert_child(
            &buf,
            &ex,
            "srv6_sid",
            ipv6(&[
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x41,
            ]),
        );
        let lex = item_range(&buf, &rl, "sub_tlvs", 3);
        assert_child(
            &buf,
            &lex,
            "neighbor_id",
            FieldValue::Ipv4Addr([4, 4, 4, 4]),
        );
    }

    /// RFC 8362, Sections 3.3-3.12 and 4.2-4.8 — the other Extended LSAs.
    /// <https://www.rfc-editor.org/rfc/rfc8362#section-3.3>
    #[test]
    fn parse_extended_lsas() {
        // E-Network-LSA: Options + Attached-Routers TLV
        let mut enet = vec![0, 0, 0, 0x13];
        enet.extend(tlv(2, &[1, 1, 1, 1, 2, 2, 2, 2]));
        // E-Inter-Area-Prefix-LSA: Inter-Area-Prefix TLV with Prefix-SID
        let mut iap = vec![0, 0, 0, 10, 32, 0x20, 0, 0];
        iap.extend_from_slice(&DOC_PREFIX);
        iap.extend(tlv(4, &[0x40, 0, 0, 0, 0, 0, 0, 7]));
        // E-Inter-Area-Router-LSA
        let iar = tlv(4, &[0, 0, 0, 0x13, 0, 0, 0, 9, 3, 3, 3, 3]);
        // E-AS-External-LSA: External-Prefix TLV with forwarding/tag sub-TLVs
        let mut ext = vec![0x04, 0, 0, 50, 0, 0, 0, 0];
        ext.extend(tlv(
            1,
            &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ));
        ext.extend(tlv(2, &[192, 0, 2, 1]));
        ext.extend(tlv(3, &[0, 0, 0, 99]));
        ext.extend(tlv(7, &[0, 0, 0, 3])); // SID/Label
        // E-Link-LSA: priority + options + link-local TLVs + Intra-Area-Prefix
        let mut elink = vec![1, 0, 0, 0x13];
        elink.extend(tlv(
            7,
            &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        ));
        elink.extend(tlv(8, &[169, 254, 0, 1]));
        // E-Intra-Area-Prefix-LSA
        let mut eiap = vec![0, 0, 0xA0, 0x21, 0, 0, 0, 0, 1, 1, 1, 1];
        let mut prefix = vec![0, 0, 0, 1, 32, 0, 0, 0];
        prefix.extend_from_slice(&DOC_PREFIX);
        eiap.extend(tlv(6, &prefix));
        let pkt = build_lsu(&[
            build_lsa(0xA022, &enet),
            build_lsa(0xA023, &tlv(3, &iap)),
            build_lsa(0xA024, &iar),
            build_lsa(0xC025, &tlv(5, &ext)),
            build_lsa(0x8028, &elink),
            build_lsa(0xA029, &eiap),
            build_lsa(0xA027, &[]),
        ]);
        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let enet = lsa_range(&buf, 0);
        assert_child(&buf, &enet, "options", FieldValue::U32(0x13));
        let ar = item_range(&buf, &enet, "tlvs", 0);
        assert_eq!(
            children(&buf, &range(child(&buf, &ar, "attached_routers"))).len(),
            2
        );

        let iap = item_range(&buf, &lsa_range(&buf, 1), "tlvs", 0);
        assert_child(&buf, &iap, "metric", FieldValue::U32(10));
        assert_child(&buf, &iap, "prefix_options", FieldValue::U8(0x20));
        assert_child(&buf, &iap, "prefix", ipv6(&DOC_PREFIX));
        let psid = item_range(&buf, &iap, "sub_tlvs", 0);
        assert_eq!(item_name(&buf, &iap, "sub_tlvs", 0), Some("Prefix-SID"));
        assert_child(&buf, &psid, "flags", FieldValue::U8(0x40));
        assert_child(&buf, &psid, "algorithm", FieldValue::U8(0));
        assert_child(&buf, &psid, "sid", FieldValue::U32(7));

        let iar = item_range(&buf, &lsa_range(&buf, 2), "tlvs", 0);
        assert_child(&buf, &iar, "options", FieldValue::U32(0x13));
        assert_child(&buf, &iar, "metric", FieldValue::U32(9));
        assert_child(
            &buf,
            &iar,
            "destination_router_id",
            FieldValue::Ipv4Addr([3, 3, 3, 3]),
        );

        let ext = item_range(&buf, &lsa_range(&buf, 3), "tlvs", 0);
        assert_child(&buf, &ext, "flag_e", FieldValue::U8(1));
        assert_child(&buf, &ext, "metric", FieldValue::U32(50));
        let fwd = item_range(&buf, &ext, "sub_tlvs", 0);
        assert_child(
            &buf,
            &fwd,
            "forwarding_address",
            ipv6(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        );
        let fwd4 = item_range(&buf, &ext, "sub_tlvs", 1);
        assert_child(
            &buf,
            &fwd4,
            "ipv4_forwarding_address",
            FieldValue::Ipv4Addr([192, 0, 2, 1]),
        );
        let tag = item_range(&buf, &ext, "sub_tlvs", 2);
        assert_child(&buf, &tag, "route_tag", FieldValue::U32(99));
        let sl = item_range(&buf, &ext, "sub_tlvs", 3);
        assert_child(&buf, &sl, "sid", FieldValue::U32(3));

        let elink = lsa_range(&buf, 4);
        assert_child(&buf, &elink, "router_priority", FieldValue::U8(1));
        let ll6 = item_range(&buf, &elink, "tlvs", 0);
        assert_child(
            &buf,
            &ll6,
            "link_local_address",
            ipv6(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        );
        let ll4 = item_range(&buf, &elink, "tlvs", 1);
        assert_child(
            &buf,
            &ll4,
            "ipv4_link_local_address",
            FieldValue::Ipv4Addr([169, 254, 0, 1]),
        );

        let eiap = lsa_range(&buf, 5);
        assert_child(&buf, &eiap, "referenced_ls_type", FieldValue::U16(0xA021));
        let p = item_range(&buf, &eiap, "tlvs", 0);
        assert_child(&buf, &p, "metric", FieldValue::U32(1));

        let empty = lsa_range(&buf, 6);
        assert!(children(&buf, &range(child(&buf, &empty, "tlvs"))).is_empty());
    }

    /// RFC 9513, Sections 7-8 — SRv6 Locator LSA with an End SID.
    /// <https://www.rfc-editor.org/rfc/rfc9513#section-7>
    #[test]
    fn parse_srv6_locator_lsa() {
        let mut loc = vec![1, 0, 48, 0, 0, 0, 0, 10];
        loc.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0]);
        let mut end = vec![0, 0, 0, 1];
        end.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        loc.extend(tlv(1, &end));
        loc.extend(tlv(3, &[0, 0, 0, 8]));
        loc.extend(tlv(
            2,
            &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
        ));
        let pkt = build_lsu(&[build_lsa(0xA02A, &tlv(1, &loc))]);
        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let lsa = lsa_range(&buf, 0);
        assert_eq!(item_name(&buf, &lsa, "tlvs", 0), Some("SRv6 Locator"));
        let l = item_range(&buf, &lsa, "tlvs", 0);
        assert_child(&buf, &l, "route_type", FieldValue::U8(1));
        assert_child(&buf, &l, "prefix_length", FieldValue::U8(48));
        assert_child(&buf, &l, "metric", FieldValue::U32(10));
        assert_child(
            &buf,
            &l,
            "locator",
            ipv6(&[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0]),
        );
        assert_eq!(item_name(&buf, &l, "sub_tlvs", 0), Some("SRv6 End SID"));
        let e = item_range(&buf, &l, "sub_tlvs", 0);
        assert_child(&buf, &e, "endpoint_behavior", FieldValue::U16(1));
        assert_child(
            &buf,
            &e,
            "srv6_sid",
            ipv6(&[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        );
        let tag = item_range(&buf, &l, "sub_tlvs", 1);
        assert_child(&buf, &tag, "route_tag", FieldValue::U32(8));
        let fwd = item_range(&buf, &l, "sub_tlvs", 2);
        assert!(has_child(&buf, &fwd, "forwarding_address"));
    }

    /// Unknown function codes keep a raw body; malformed Extended-LSA TLVs
    /// fall back to raw values.
    #[test]
    fn parse_unknown_and_malformed_lsas() {
        let mut bad = tlv(1, &[1, 0, 0]); // Router-Link too short
        bad.extend(tlv(3, &[0, 0, 0, 1, 200, 0, 0, 0])); // bad prefix length
        bad.extend(tlv(5, &[0, 0, 0, 1, 200, 0, 0, 0]));
        bad.extend(tlv(4, &[0; 4])); // Inter-Area-Router too short
        bad.extend(tlv(99, &[1]));
        let pkt = build_lsu(&[
            build_lsa(0x2006, &[9, 9]),
            build_lsa(0xA021, &[]),
            build_lsa(0xA023, &bad),
            build_lsa(0xA02A, &tlv(1, &[1, 0, 200, 0, 0, 0, 0, 0])),
        ]);
        let mut buf = DissectBuffer::new();
        Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let unknown = lsa_range(&buf, 0);
        assert_child(&buf, &unknown, "body", FieldValue::Bytes(&[9, 9]));
        let empty = lsa_range(&buf, 1);
        assert!(!has_child(&buf, &empty, "flags"));
        let bad = lsa_range(&buf, 2);
        for i in 0..5 {
            let t = item_range(&buf, &bad, "tlvs", i);
            assert!(has_child(&buf, &t, "value"), "tlv {i} should be raw");
        }
        let loc = item_range(&buf, &lsa_range(&buf, 3), "tlvs", 0);
        assert!(has_child(&buf, &loc, "value"));
    }

    /// RFC 8362 and RFC 9513 function-code names.
    /// <https://www.rfc-editor.org/rfc/rfc8362>
    /// <https://www.rfc-editor.org/rfc/rfc9513>
    #[test]
    fn lsa_type_names_cover_registry() {
        assert_eq!(lsa_type_name(0xA00A), Some("Intra-Area-TE-LSA"));
        assert_eq!(lsa_type_name(0x000B), Some("GRACE-LSA"));
        assert_eq!(lsa_type_name(0xA022), Some("E-Network-LSA"));
        assert_eq!(lsa_type_name(0xA023), Some("E-Inter-Area-Prefix-LSA"));
        assert_eq!(lsa_type_name(0xA024), Some("E-Inter-Area-Router-LSA"));
        assert_eq!(lsa_type_name(0xC025), Some("E-AS-External-LSA"));
        assert_eq!(lsa_type_name(0xA026), None);
        assert_eq!(lsa_type_name(0xA027), Some("E-Type-7-LSA"));
        assert_eq!(lsa_type_name(0x8028), Some("E-Link-LSA"));
        assert_eq!(lsa_type_name(0xA029), Some("E-Intra-Area-Prefix-LSA"));
        assert_eq!(lsa_type_name(0xC02A), Some("SRv6 Locator LSA"));
    }

    /// Hello body with the given 24-bit Options.
    fn hello_body(options: u32) -> Vec<u8> {
        let mut body = vec![0, 0, 0, 1, 1];
        body.extend_from_slice(&options.to_be_bytes()[1..]);
        body.extend_from_slice(&[0, 10, 0, 40, 10, 0, 0, 1, 10, 0, 0, 2]);
        body
    }

    /// Authentication Trailer with a 32-byte digest.
    fn auth_trailer() -> Vec<u8> {
        let mut at = vec![0, 1, 0, 48, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 9];
        at.extend_from_slice(&[0xDD; 32]);
        at
    }

    /// RFC 5613, Section 2 and RFC 7166, Section 4.1 — LLS block and
    /// Authentication Trailer after a Hello with the L and AT bits.
    /// <https://www.rfc-editor.org/rfc/rfc5613#section-2>
    /// <https://www.rfc-editor.org/rfc/rfc7166#section-4.1>
    #[test]
    fn parse_hello_lls_and_auth_trailer() {
        let mut pkt = build_header(1, 36, [1, 1, 1, 1]);
        pkt.extend(hello_body(0x613)); // AT | L | V6 | E | R
        pkt.extend_from_slice(&[0, 0, 0, 3]);
        pkt.extend(tlv(1, &[0, 0, 0, 1]));
        pkt.extend(auth_trailer());
        let mut buf = DissectBuffer::new();
        let result = Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, pkt.len());

        let layer = buf.layer_by_name("OSPFv3").unwrap();
        assert_eq!(layer.range, 0..pkt.len());
        let lls = buf.field_by_name(layer, "lls").unwrap();
        assert_eq!(lls.range, 36..48);
        let at = buf.field_by_name(layer, "auth_trailer").unwrap();
        assert_eq!(at.range, 48..96);
        let at = range(at);
        assert_child(&buf, &at, "auth_type", FieldValue::U16(1));
        assert_eq!(
            buf.resolve_nested_display_name(&at, "auth_type_name"),
            Some("HMAC Cryptographic Authentication")
        );
        assert_child(&buf, &at, "auth_data_len", FieldValue::U16(48));
        assert_child(&buf, &at, "sa_id", FieldValue::U16(3));
        assert_child(&buf, &at, "crypto_sequence_number", FieldValue::U64(9));
        assert_child(&buf, &at, "auth_data", FieldValue::Bytes(&[0xDD; 32]));
    }

    /// Without the AT-bit, trailing bytes after a Hello are not consumed.
    #[test]
    fn parse_hello_without_at_bit_ignores_trailer() {
        let mut pkt = build_header(1, 36, [1, 1, 1, 1]);
        pkt.extend(hello_body(0x13));
        pkt.extend(auth_trailer());
        let mut buf = DissectBuffer::new();
        let result = Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 36);
    }

    /// RFC 7166, Section 2.1 — packets without an Options field carry the
    /// trailer when the neighbor negotiated it; a trailer whose Auth Data Len
    /// matches the remaining bytes is decoded. DD packets use the AT-bit.
    /// <https://www.rfc-editor.org/rfc/rfc7166#section-2.1>
    #[test]
    fn parse_auth_trailer_on_lsack_and_dd() {
        let lsa = build_lsa_header(0x2001, 20);
        let mut pkt = build_header(5, (HEADER_SIZE + lsa.len()) as u16, [1, 1, 1, 1]);
        pkt.extend_from_slice(&lsa);
        pkt.extend(auth_trailer());
        let mut buf = DissectBuffer::new();
        let result = Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, pkt.len());

        // Mismatched Auth Data Len: not consumed.
        let mut pkt = build_header(5, HEADER_SIZE as u16, [1, 1, 1, 1]);
        pkt.extend(auth_trailer());
        pkt.push(0);
        let mut buf = DissectBuffer::new();
        let result = Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, HEADER_SIZE);

        let mut pkt = build_header(2, 28, [1, 1, 1, 1]);
        pkt.extend_from_slice(&[0, 0, 0x04, 0x13, 0x05, 0xDC, 0, 0x07, 0, 0, 0, 1]);
        pkt.extend(auth_trailer());
        let mut buf = DissectBuffer::new();
        let result = Ospfv3Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, pkt.len());
    }
}
