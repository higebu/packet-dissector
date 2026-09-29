//! OSPFv2 (Open Shortest Path First version 2) dissector.
//!
//! ## References
//! - RFC 2328: <https://www.rfc-editor.org/rfc/rfc2328>
//! - RFC 3101 (NSSA): <https://www.rfc-editor.org/rfc/rfc3101>
//! - RFC 3630 (TE): <https://www.rfc-editor.org/rfc/rfc3630>
//! - RFC 5250 (Opaque LSAs): <https://www.rfc-editor.org/rfc/rfc5250>
//! - RFC 5613 (LLS): <https://www.rfc-editor.org/rfc/rfc5613>
//! - RFC 5709 (HMAC-SHA authentication): <https://www.rfc-editor.org/rfc/rfc5709>
//! - RFC 7684 (Prefix/Link Attributes): <https://www.rfc-editor.org/rfc/rfc7684>
//! - RFC 7770 (Router Information): <https://www.rfc-editor.org/rfc/rfc7770>
//! - RFC 8665 (Segment Routing): <https://www.rfc-editor.org/rfc/rfc8665>

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

use crate::common::{LSR_ENTRY_SIZE, push_lsa_headers, push_lsu_lsas};
use crate::tlv::UNPARSED_DESCRIPTOR;
use crate::trailer::{LLS_DESCRIPTOR, push_lls};
use crate::v2_lsa::{
    FD_LSA, FD_LSA_HEADER, LSA_CHILD_FIELDS, LSA_HEADER_FIELDS, lsa_type_name, push_lsa,
    push_lsa_header_fields,
};

/// OSPFv2 common header size in bytes.
///
/// RFC 2328, Appendix A.3.1 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.3.1>
const HEADER_SIZE: usize = 24;

/// Hello packet body size excluding neighbors.
///
/// RFC 2328, Appendix A.3.2 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.3.2>
const HELLO_BODY_SIZE: usize = 20;

/// Database Description packet body size excluding LSA headers.
///
/// RFC 2328, Appendix A.3.3 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.3.3>
const DD_BODY_SIZE: usize = 8;

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
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("ls_type", FieldValue::U32(t)) => u8::try_from(*t).ok().and_then(lsa_type_name),
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
// Cryptographic authentication (AuType 2) and LLS
const FD_KEY_ID: usize = 23;
const FD_AUTH_DATA_LEN: usize = 24;
const FD_CRYPTO_SEQUENCE_NUMBER: usize = 25;
const FD_AUTH_DIGEST: usize = 26;
const FD_LLS: usize = 27;

/// Authentication type for Cryptographic authentication.
///
/// RFC 2328, Appendix D — <https://www.rfc-editor.org/rfc/rfc2328#appendix-D>
const AUTH_TYPE_CRYPTOGRAPHIC: u16 = 2;

/// L-bit in the OSPFv2 Options field.
///
/// RFC 5613, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc5613#section-2.1>
const OPTIONS_L_BIT: u8 = 0x10;

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
    // Cryptographic authentication — RFC 2328, Appendix D.3
    // <https://www.rfc-editor.org/rfc/rfc2328>
    FieldDescriptor::new("key_id", "Key ID", FieldType::U8).optional(),
    FieldDescriptor::new("auth_data_len", "Auth Data Len", FieldType::U8).optional(),
    FieldDescriptor::new(
        "crypto_sequence_number",
        "Cryptographic Sequence Number",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("auth_digest", "Authentication Digest", FieldType::Bytes).optional(),
    // LLS data block — RFC 5613, Section 2.2
    // <https://www.rfc-editor.org/rfc/rfc5613#section-2.2>
    LLS_DESCRIPTOR,
    // Bytes after the last LSA / LSA header that could be delimited.
    UNPARSED_DESCRIPTOR,
];

/// OSPFv2 dissector.
pub struct Ospfv2Dissector;

/// Specification references for the OSPFv2 dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 2328",
        "OSPF Version 2",
        "https://www.rfc-editor.org/rfc/rfc2328",
    ),
    SpecReference::new(
        "RFC 3101",
        "The OSPF Not-So-Stubby Area (NSSA) Option",
        "https://www.rfc-editor.org/rfc/rfc3101",
    ),
    SpecReference::new(
        "RFC 3630",
        "Traffic Engineering (TE) Extensions to OSPF Version 2",
        "https://www.rfc-editor.org/rfc/rfc3630",
    ),
    SpecReference::new(
        "RFC 5250",
        "The OSPF Opaque LSA Option",
        "https://www.rfc-editor.org/rfc/rfc5250",
    ),
    SpecReference::new(
        "RFC 5613",
        "OSPF Link-Local Signaling",
        "https://www.rfc-editor.org/rfc/rfc5613",
    ),
    SpecReference::new(
        "RFC 7684",
        "OSPFv2 Prefix/Link Attribute Advertisement",
        "https://www.rfc-editor.org/rfc/rfc7684",
    ),
    SpecReference::new(
        "RFC 7770",
        "Extensions to OSPF for Advertising Optional Router Capabilities",
        "https://www.rfc-editor.org/rfc/rfc7770",
    ),
    SpecReference::new(
        "RFC 8665",
        "OSPF Extensions for Segment Routing",
        "https://www.rfc-editor.org/rfc/rfc8665",
    ),
];

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

        // RFC 2328, Appendix A.3.1 — Common header
        // <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.3.1>
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
        // RFC 2328, Appendix D.3 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-D.3>
        // Layout: 0 (2 octets), Key ID, Auth Data Len, Cryptographic sequence number.
        if auth_type == AUTH_TYPE_CRYPTOGRAPHIC {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_KEY_ID],
                FieldValue::U8(data[18]),
                offset + 18..offset + 19,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_AUTH_DATA_LEN],
                FieldValue::U8(data[19]),
                offset + 19..offset + 20,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_CRYPTO_SEQUENCE_NUMBER],
                FieldValue::U32(read_be_u32(data, 20)?),
                offset + 20..offset + 24,
            );
        }

        // Type-specific parsing
        let body = &data[HEADER_SIZE..total_len];
        let body_offset = offset + HEADER_SIZE;

        // Options of Hello / DD packets, used for the LLS L-bit.
        let mut options = None;
        match ospf_type {
            // Hello (Type 1) — RFC 2328, Appendix A.3.2
            // <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.3.2>
            1 => {
                if body.len() < HELLO_BODY_SIZE {
                    return Err(PacketError::InvalidHeader(
                        "ospfv2: packet length too small for Hello body",
                    ));
                }

                let network_mask = [body[0], body[1], body[2], body[3]];
                let hello_interval = read_be_u16(body, 4)?;
                let hello_options = body[6];
                options = Some(hello_options);
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
                    FieldValue::U8(hello_options),
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
            // Database Description (Type 2) — RFC 2328, Appendix A.3.3
            // <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.3.3>
            2 => {
                if body.len() < DD_BODY_SIZE {
                    return Err(PacketError::Truncated {
                        expected: HEADER_SIZE + DD_BODY_SIZE,
                        actual: HEADER_SIZE + body.len(),
                    });
                }

                let interface_mtu = read_be_u16(body, 0)?;
                let dd_options = body[2];
                options = Some(dd_options);
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
                push_lsa_headers(
                    buf,
                    &FIELD_DESCRIPTORS[FD_LSA_HEADERS],
                    lsa_data,
                    lsa_start,
                    &FD_LSA_HEADER,
                    push_lsa_header_fields,
                );
            }
            // Link State Request (Type 3) — RFC 2328, Appendix A.3.4
            // <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.3.4>
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
                        &FD_LSR_ENTRY,
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
            // Link State Update (Type 4) — RFC 2328, Appendix A.3.5
            // <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.3.5>
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
            // Link State Acknowledgment (Type 5) — RFC 2328, Appendix A.3.6
            // <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.3.6>
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
            // Unknown type — common header only
            _ => {}
        }

        // Data appended after the packet, outside `packet_length`.
        let mut consumed = total_len;

        // RFC 2328, Appendix D.3 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-D.3>
        // "the key is used to generate/verify a "message digest" that is
        // appended to the end of the OSPF packet."
        // When the digest is not fully present, the LLS block that would
        // follow it cannot be located either.
        let mut digest_present = true;
        if auth_type == AUTH_TYPE_CRYPTOGRAPHIC {
            let digest_len = data[19] as usize;
            digest_present = data.len() >= consumed + digest_len;
            if digest_len > 0 && digest_present {
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_AUTH_DIGEST],
                    FieldValue::Bytes(&data[consumed..consumed + digest_len]),
                    offset + consumed..offset + consumed + digest_len,
                );
                consumed += digest_len;
            }
        }

        // RFC 5613, Section 2 — <https://www.rfc-editor.org/rfc/rfc5613#section-2>
        // "OSPF routers add a special data block to the end of OSPF packets
        // or right after the authentication data block when cryptographic
        // authentication is used." Only Hello and DD packets carry it, and
        // "the LLS data block is only examined if the L-bit is set."
        if digest_present && options.is_some_and(|o| o & OPTIONS_L_BIT != 0) {
            consumed += push_lls(
                buf,
                &data[consumed..],
                offset + consumed,
                &FIELD_DESCRIPTORS[FD_LLS],
            );
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

    // # RFC 2328 (OSPFv2) Coverage
    //
    // RFC 2328: <https://www.rfc-editor.org/rfc/rfc2328>
    //
    // | RFC Section        | Description                  | Test                                     |
    // |--------------------|------------------------------|------------------------------------------|
    // | Appendix A.3.1     | Common header                | parse_hello, parse_wrong_version,        |
    // |                    |                              | parse_truncated_header, parse_with_offset |
    // | Appendix A.3.2     | Hello packet                 | parse_hello, parse_hello_with_neighbors  |
    // | Appendix A.3.3     | Database Description         | parse_dd                                 |
    // | Appendix A.3.4     | Link State Request           | parse_lsr,                               |
    // |                    |                              | lsr_entry_container_resolves_to_lsa_type_name |
    // | Appendix A.3.5     | Link State Update            | parse_lsu, parse_lsu_router_lsa_stub_link |
    // | Appendix A.3.6     | Link State Ack               | parse_lsack, lsa_header_containers_are_labeled |
    // | Appendix A.4.1     | LSA header, LS type names    | parse_dd, parse_lsu, parse_lsack,        |
    // |                    |                              | lsa_type_names_cover_registry            |
    // | Appendix A.4.2     | Router-LSA                   | parse_lsu_router_lsa_stub_link,          |
    // |                    |                              | parse_router_lsa_flags_and_tos,          |
    // |                    |                              | parse_router_lsa_truncated_links         |
    // | Appendix A.4.3     | Network-LSA                  | parse_network_lsa                        |
    // | Appendix A.4.4     | Summary-LSAs (3, 4)          | parse_summary_lsas                       |
    // | Appendix A.4.5     | AS-external-LSA              | parse_as_external_and_nssa_lsas          |
    // | Appendix D.3       | Cryptographic authentication | parse_crypto_auth_digest,                |
    // |                    |                              | parse_crypto_auth_missing_digest         |
    // | —                  | Unknown LSA type (raw body)  | parse_unknown_lsa_body_is_raw            |
    //
    // | Other RFC          | Description                  | Test                                     |
    // |--------------------|------------------------------|------------------------------------------|
    // | RFC 3101 App. C    | NSSA-LSA (type 7)            | parse_as_external_and_nssa_lsas          |
    // | RFC 5250 Sec. 3    | Opaque LSA type / ID         | parse_router_information_opaque_lsa,     |
    // |                    |                              | parse_unknown_opaque_type_is_raw         |
    // | RFC 3630 Sec. 2.4-2.5 | TE LSA TLVs / sub-TLVs    | parse_traffic_engineering_opaque_lsa     |
    // | RFC 7770 Sec. 2    | Router Information LSA       | parse_router_information_opaque_lsa      |
    // | RFC 8665 Sec. 3    | SR-Algorithm, SID/Label Range, | parse_router_information_opaque_lsa    |
    // |                    | SRLB, SRMS Preference        |                                          |
    // | RFC 7684 Sec. 2.1  | Extended Prefix TLV          | parse_extended_prefix_opaque_lsa         |
    // | RFC 8665 Sec. 4-5  | Prefix Range, Prefix-SID     | parse_extended_prefix_opaque_lsa         |
    // | RFC 7684 Sec. 3.1  | Extended Link TLV            | parse_extended_link_opaque_lsa           |
    // | RFC 8665 Sec. 6    | Adj-SID, LAN Adj-SID         | parse_extended_link_opaque_lsa           |
    // | RFC 3630 Sec. 2.3.2 | Malformed TLV handling      | parse_opaque_lsa_malformed_tlvs          |
    // | RFC 5613 Sec. 2    | LLS data block               | parse_lls_block_after_digest,            |
    // |                    |                              | parse_lls_block_requires_l_bit_and_length, |
    // |                    |                              | parse_lls_block_after_dd                 |

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

    #[test]
    fn lsr_entry_container_resolves_to_lsa_type_name() {
        // LSR entry with LS Type = 1 (Router-LSA) so the container label
        // resolves to "Router-LSA" instead of duplicating "LS Type".
        let mut pkt = build_header(3, 36, [1, 1, 1, 1]);
        pkt.extend_from_slice(&[0, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[2, 2, 2, 2]);

        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let (idx, field) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "lsr_entry")
            .expect("lsr_entry container not found");
        assert!(matches!(field.value, FieldValue::Object(_)));
        assert_eq!(field.display_name(), "LSR Entry");
        assert_eq!(
            buf.resolve_container_display_name(idx as u32),
            Some("Router-LSA")
        );
    }

    #[test]
    fn references_and_layer_are_populated() {
        let dissector = Ospfv2Dissector;
        let references = dissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Network));
    }

    // ---------------------------------------------------------------------
    // LSA bodies, opaque TLVs and trailers
    // ---------------------------------------------------------------------

    use crate::common::test_util::{assert_child, child, children, has_child, index_of, range};

    /// Build an LSA: 20-byte header followed by `body`, with the length set.
    fn build_lsa(ls_type: u8, link_state_id: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut lsa = build_lsa_header(ls_type, (20 + body.len()) as u16);
        lsa[4..8].copy_from_slice(&link_state_id);
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

    /// Dissects `pkt` and returns the child range of `lsas[index]`.
    fn lsa_range(buf: &DissectBuffer<'_>, index: usize) -> core::ops::Range<u32> {
        let layer = buf.layer_by_name("OSPFv2").unwrap();
        let lsas = buf.field_by_name(layer, "lsas").unwrap();
        let items = children(buf, &range(lsas));
        range(items[index])
    }

    /// Returns the child range of `tlvs[index]` inside `parent`.
    fn tlv_range(
        buf: &DissectBuffer<'_>,
        parent: &core::ops::Range<u32>,
        array: &str,
        index: usize,
    ) -> core::ops::Range<u32> {
        let items = children(buf, &range(child(buf, parent, array)));
        range(items[index])
    }

    /// Returns the container display name for `tlvs[index]` inside `parent`.
    fn tlv_name(
        buf: &DissectBuffer<'_>,
        parent: &core::ops::Range<u32>,
        array: &str,
        index: usize,
    ) -> Option<&'static str> {
        let items = children(buf, &range(child(buf, parent, array)));
        buf.resolve_container_display_name(index_of(buf, items[index]))
    }

    /// RFC 2328, Appendix A.4.2 — the reproduction from the issue: one
    /// Router-LSA with a stub link 192.0.2.0/24, metric 10.
    /// <https://www.rfc-editor.org/rfc/rfc2328>
    #[test]
    fn parse_lsu_router_lsa_stub_link() {
        let pkt: Vec<u8> = vec![
            0x02, 0x04, 0x00, 0x40, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x02, 0x01, 0xc0, 0x00, 0x02, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x80, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0xc0, 0x00, 0x02, 0x00,
            0xff, 0xff, 0xff, 0x00, 0x03, 0x00, 0x00, 0x0a,
        ];
        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 64);

        let layer = buf.layer_by_name("OSPFv2").unwrap();
        let lsas = buf.field_by_name(layer, "lsas").unwrap();
        let items = children(&buf, &range(lsas));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name(), "lsa");
        assert_eq!(items[0].display_name(), "LSA");
        assert_eq!(items[0].range, 28..64);
        assert_eq!(
            buf.resolve_container_display_name(index_of(&buf, items[0])),
            Some("Router-LSA")
        );

        let lsa = range(items[0]);
        assert_child(&buf, &lsa, "ls_age", FieldValue::U16(1));
        assert_child(&buf, &lsa, "length", FieldValue::U16(36));
        assert_child(&buf, &lsa, "flags", FieldValue::U8(0));
        assert_child(&buf, &lsa, "num_links", FieldValue::U16(1));
        let link = tlv_range(&buf, &lsa, "links", 0);
        assert_child(&buf, &link, "link_id", FieldValue::Ipv4Addr([192, 0, 2, 0]));
        assert_child(
            &buf,
            &link,
            "link_data",
            FieldValue::Ipv4Addr([255, 255, 255, 0]),
        );
        assert_child(&buf, &link, "link_type", FieldValue::U8(3));
        assert_eq!(
            buf.resolve_nested_display_name(&link, "link_type_name"),
            Some("Stub network")
        );
        assert_child(&buf, &link, "num_tos", FieldValue::U8(0));
        assert_child(&buf, &link, "metric", FieldValue::U16(10));
        assert!(!has_child(&buf, &link, "tos_metrics"));
        assert!(!has_child(&buf, &lsa, "unparsed"));
    }

    /// RFC 2328, Appendix A.4.2 — V/E/B bits, Nt bit (RFC 3101) and TOS metrics.
    /// <https://www.rfc-editor.org/rfc/rfc2328>
    /// <https://www.rfc-editor.org/rfc/rfc3101>
    #[test]
    fn parse_router_lsa_flags_and_tos() {
        let mut body = vec![0x17, 0x00, 0x00, 0x01]; // Nt|V|E|B, #links = 1
        body.extend_from_slice(&[10, 0, 0, 2, 10, 0, 0, 1, 1, 1, 0, 5]); // p2p, 1 TOS
        body.extend_from_slice(&[8, 0, 0, 7]); // TOS 8, metric 7
        let pkt = build_lsu(&[build_lsa(1, [1, 1, 1, 1], &body)]);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let lsa = lsa_range(&buf, 0);
        assert_child(&buf, &lsa, "flags", FieldValue::U8(0x17));
        assert_child(&buf, &lsa, "flag_nt", FieldValue::U8(1));
        assert_child(&buf, &lsa, "flag_v", FieldValue::U8(1));
        assert_child(&buf, &lsa, "flag_e", FieldValue::U8(1));
        assert_child(&buf, &lsa, "flag_b", FieldValue::U8(1));
        let link = tlv_range(&buf, &lsa, "links", 0);
        assert_eq!(
            buf.resolve_nested_display_name(&link, "link_type_name"),
            Some("Point-to-point")
        );
        let tos = tlv_range(&buf, &link, "tos_metrics", 0);
        assert_child(&buf, &tos, "tos", FieldValue::U8(8));
        assert_child(&buf, &tos, "metric", FieldValue::U32(7));
    }

    /// Router-LSA whose `# links` overstates the body: the parsed links are
    /// kept and the remaining bytes are exposed as `unparsed`.
    #[test]
    fn parse_router_lsa_truncated_links() {
        let mut body = vec![0x00, 0x00, 0x00, 0x02]; // #links = 2
        body.extend_from_slice(&[10, 0, 0, 0, 255, 0, 0, 0, 3, 0, 0, 1]);
        body.extend_from_slice(&[10, 1, 0, 0]); // partial second link
        let pkt = build_lsu(&[build_lsa(1, [1, 1, 1, 1], &body)]);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let lsa = lsa_range(&buf, 0);
        let links = child(&buf, &lsa, "links");
        assert_eq!(children(&buf, &range(links)).len(), 1);
        assert_eq!(links.range, 52..64);
        assert_child(&buf, &lsa, "unparsed", FieldValue::Bytes(&[10, 1, 0, 0]));
    }

    /// RFC 2328, Appendix A.4.3 — Network-LSA.
    /// <https://www.rfc-editor.org/rfc/rfc2328>
    #[test]
    fn parse_network_lsa() {
        let body = [255, 255, 255, 0, 1, 1, 1, 1, 2, 2, 2, 2];
        let pkt = build_lsu(&[build_lsa(2, [10, 0, 0, 1], &body)]);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let lsa = lsa_range(&buf, 0);
        assert_child(
            &buf,
            &lsa,
            "network_mask",
            FieldValue::Ipv4Addr([255, 255, 255, 0]),
        );
        let routers = children(&buf, &range(child(&buf, &lsa, "attached_routers")));
        assert_eq!(routers.len(), 2);
        assert_eq!(routers[1].value, FieldValue::Ipv4Addr([2, 2, 2, 2]));
    }

    /// RFC 2328, Appendix A.4.4 — Summary-LSAs (types 3 and 4) with a TOS entry.
    /// <https://www.rfc-editor.org/rfc/rfc2328>
    #[test]
    fn parse_summary_lsas() {
        let body = [255, 255, 0, 0, 0, 0x00, 0x01, 0x00, 4, 0x00, 0x00, 0x20];
        let pkt = build_lsu(&[
            build_lsa(3, [172, 16, 0, 0], &body),
            build_lsa(4, [3, 3, 3, 3], &[0, 0, 0, 0, 0, 0, 0, 5]),
        ]);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let lsa = lsa_range(&buf, 0);
        assert_child(
            &buf,
            &lsa,
            "network_mask",
            FieldValue::Ipv4Addr([255, 255, 0, 0]),
        );
        assert_child(&buf, &lsa, "metric", FieldValue::U32(256));
        let tos = tlv_range(&buf, &lsa, "tos_metrics", 0);
        assert_child(&buf, &tos, "tos", FieldValue::U8(4));
        assert_child(&buf, &tos, "metric", FieldValue::U32(32));

        let asbr = lsa_range(&buf, 1);
        assert_child(&buf, &asbr, "metric", FieldValue::U32(5));
        assert!(!has_child(&buf, &asbr, "tos_metrics"));
    }

    /// RFC 2328, Appendix A.4.5 — AS-external-LSA; RFC 3101, Appendix C — NSSA-LSA.
    /// <https://www.rfc-editor.org/rfc/rfc2328>
    /// <https://www.rfc-editor.org/rfc/rfc3101>
    #[test]
    fn parse_as_external_and_nssa_lsas() {
        let mut body = vec![255, 255, 255, 0];
        body.extend_from_slice(&[0x80, 0x00, 0x00, 0x14, 10, 0, 0, 9, 0, 0, 0, 42]);
        body.extend_from_slice(&[0x08, 0x00, 0x00, 0x05, 0, 0, 0, 0, 0, 0, 0, 0]);
        let nssa = [255, 0, 0, 0, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 7];
        let pkt = build_lsu(&[
            build_lsa(5, [198, 51, 100, 0], &body),
            build_lsa(7, [10, 0, 0, 0], &nssa),
        ]);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let lsa = lsa_range(&buf, 0);
        assert_child(&buf, &lsa, "flag_e", FieldValue::U8(1));
        assert_child(&buf, &lsa, "metric", FieldValue::U32(20));
        assert_child(
            &buf,
            &lsa,
            "forwarding_address",
            FieldValue::Ipv4Addr([10, 0, 0, 9]),
        );
        assert_child(&buf, &lsa, "external_route_tag", FieldValue::U32(42));
        let tos = tlv_range(&buf, &lsa, "tos_metrics", 0);
        assert_child(&buf, &tos, "flag_e", FieldValue::U8(0));
        assert_child(&buf, &tos, "tos", FieldValue::U8(8));
        assert_child(&buf, &tos, "metric", FieldValue::U32(5));

        let layer = buf.layer_by_name("OSPFv2").unwrap();
        let lsas = children(&buf, &range(buf.field_by_name(layer, "lsas").unwrap()));
        assert_eq!(
            buf.resolve_container_display_name(index_of(&buf, lsas[1])),
            Some("NSSA AS-external LSA")
        );
        let nssa = range(lsas[1]);
        assert_child(&buf, &nssa, "flag_e", FieldValue::U8(0));
        assert_child(&buf, &nssa, "external_route_tag", FieldValue::U32(7));
    }

    /// Unknown LSA types keep their body as raw bytes.
    #[test]
    fn parse_unknown_lsa_body_is_raw() {
        let pkt = build_lsu(&[build_lsa(6, [224, 0, 0, 1], &[1, 2, 3, 4])]);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let lsa = lsa_range(&buf, 0);
        assert_child(&buf, &lsa, "body", FieldValue::Bytes(&[1, 2, 3, 4]));
    }

    /// The DD and LSAck arrays hold `lsa_header` objects, labeled by LS type.
    #[test]
    fn lsa_header_containers_are_labeled() {
        let lsa = build_lsa_header(10, 20);
        let mut pkt = build_header(5, (HEADER_SIZE + lsa.len()) as u16, [1, 1, 1, 1]);
        pkt.extend_from_slice(&lsa);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("OSPFv2").unwrap();
        let headers = children(
            &buf,
            &range(buf.field_by_name(layer, "lsa_headers").unwrap()),
        );
        assert_eq!(headers[0].name(), "lsa_header");
        assert_eq!(
            buf.resolve_container_display_name(index_of(&buf, headers[0])),
            Some("Area-scoped Opaque LSA")
        );
    }

    /// RFC 2328, Appendix A.4.1 and the IANA "OSPFv2 Link State (LS) Type" registry.
    /// <https://www.rfc-editor.org/rfc/rfc2328>
    #[test]
    fn lsa_type_names_cover_registry() {
        assert_eq!(lsa_type_name(6), Some("Group-membership-LSA"));
        assert_eq!(lsa_type_name(7), Some("NSSA AS-external LSA"));
        assert_eq!(lsa_type_name(8), None);
        assert_eq!(lsa_type_name(9), Some("Link-scoped Opaque LSA"));
        assert_eq!(lsa_type_name(11), Some("AS-scoped Opaque LSA"));
    }

    /// RFC 7770, Section 2.1 and RFC 8665, Section 3 — Router Information
    /// Opaque LSA with SR capability TLVs.
    /// <https://www.rfc-editor.org/rfc/rfc7770#section-2.1>
    /// <https://www.rfc-editor.org/rfc/rfc8665#section-3>
    #[test]
    fn parse_router_information_opaque_lsa() {
        let mut body = tlv(1, &[0x60, 0, 0, 0]); // Informational Capabilities
        body.extend(tlv(7, b"r1")); // Dynamic Hostname (RFC 5642)
        body.extend(tlv(8, &[0, 1])); // SR-Algorithm
        let mut range_value = vec![0x00, 0x1f, 0x40, 0x00]; // Range Size 8000
        range_value.extend(tlv(1, &[0x00, 0x3e, 0x80])); // SID/Label: label 16000
        body.extend(tlv(9, &range_value)); // SID/Label Range
        let mut srlb = vec![0x00, 0x03, 0xe8, 0x00]; // Range Size 1000
        srlb.extend(tlv(1, &[0, 0, 0x3a, 0x98])); // SID 15000
        body.extend(tlv(14, &srlb)); // SR Local Block
        body.extend(tlv(15, &[100, 0, 0, 0])); // SRMS Preference
        body.extend(tlv(12, &[1, 10])); // Node MSD (not decoded)
        let pkt = build_lsu(&[build_lsa(10, [4, 0, 0, 0], &body)]);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let lsa = lsa_range(&buf, 0);
        assert_child(&buf, &lsa, "opaque_type", FieldValue::U8(4));
        assert_child(&buf, &lsa, "opaque_id", FieldValue::U32(0));
        assert_eq!(
            buf.resolve_nested_display_name(&lsa, "opaque_type_name"),
            Some("Router Information (RI)")
        );
        assert_eq!(
            tlv_name(&buf, &lsa, "tlvs", 0),
            Some("Router Informational Capabilities")
        );
        let caps = tlv_range(&buf, &lsa, "tlvs", 0);
        assert_child(&buf, &caps, "type", FieldValue::U16(1));
        assert_child(&buf, &caps, "length", FieldValue::U16(4));
        assert_child(
            &buf,
            &caps,
            "informational_capabilities",
            FieldValue::U32(0x6000_0000),
        );
        let host = tlv_range(&buf, &lsa, "tlvs", 1);
        assert_child(&buf, &host, "hostname", FieldValue::Bytes(b"r1"));
        let algs = tlv_range(&buf, &lsa, "tlvs", 2);
        let algs = children(&buf, &range(child(&buf, &algs, "algorithms")));
        assert_eq!(algs.len(), 2);
        assert_eq!(algs[1].value, FieldValue::U8(1));
        let srgb = tlv_range(&buf, &lsa, "tlvs", 3);
        assert_child(&buf, &srgb, "range_size", FieldValue::U32(8000));
        assert_eq!(tlv_name(&buf, &srgb, "sub_tlvs", 0), Some("SID/Label"));
        let sid = tlv_range(&buf, &srgb, "sub_tlvs", 0);
        assert_child(&buf, &sid, "sid", FieldValue::U32(16000));
        let srlb = tlv_range(&buf, &lsa, "tlvs", 4);
        assert_child(&buf, &srlb, "range_size", FieldValue::U32(1000));
        let sid = tlv_range(&buf, &srlb, "sub_tlvs", 0);
        assert_child(&buf, &sid, "sid", FieldValue::U32(15000));
        let pref = tlv_range(&buf, &lsa, "tlvs", 5);
        assert_child(&buf, &pref, "preference", FieldValue::U8(100));
        let msd = tlv_range(&buf, &lsa, "tlvs", 6);
        assert_eq!(tlv_name(&buf, &lsa, "tlvs", 6), Some("Node MSD"));
        assert_child(&buf, &msd, "value", FieldValue::Bytes(&[1, 10]));
    }

    /// RFC 3630, Sections 2.4-2.5 — Traffic Engineering LSA.
    /// <https://www.rfc-editor.org/rfc/rfc3630#section-2.4>
    #[test]
    fn parse_traffic_engineering_opaque_lsa() {
        let mut body = tlv(1, &[1, 1, 1, 1]); // Router Address
        let mut link = tlv(1, &[1]); // Link type: point-to-point
        link.extend(tlv(2, &[2, 2, 2, 2])); // Link ID
        link.extend(tlv(3, &[10, 0, 0, 1, 10, 0, 1, 1])); // Local addresses
        link.extend(tlv(4, &[10, 0, 0, 2])); // Remote address
        link.extend(tlv(5, &[0, 0, 0, 10])); // TE metric
        link.extend(tlv(6, &1.25e8f32.to_bits().to_be_bytes())); // Max BW
        link.extend(tlv(7, &1.0e8f32.to_bits().to_be_bytes())); // Max reservable
        let mut unreserved = Vec::new();
        for _ in 0..8 {
            unreserved.extend_from_slice(&5.0e7f32.to_bits().to_be_bytes());
        }
        link.extend(tlv(8, &unreserved)); // Unreserved BW
        link.extend(tlv(9, &[0, 0, 0, 0x0f])); // Admin group
        link.extend(tlv(16, &[0, 0, 0, 1])); // SRLG (not decoded)
        body.extend(tlv(2, &link));
        let pkt = build_lsu(&[build_lsa(10, [1, 0, 0, 7], &body)]);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let lsa = lsa_range(&buf, 0);
        assert_child(&buf, &lsa, "opaque_type", FieldValue::U8(1));
        assert_child(&buf, &lsa, "opaque_id", FieldValue::U32(7));
        assert_eq!(tlv_name(&buf, &lsa, "tlvs", 0), Some("Router Address"));
        let ra = tlv_range(&buf, &lsa, "tlvs", 0);
        assert_child(
            &buf,
            &ra,
            "router_address",
            FieldValue::Ipv4Addr([1, 1, 1, 1]),
        );
        let link = tlv_range(&buf, &lsa, "tlvs", 1);
        assert_eq!(tlv_name(&buf, &lsa, "tlvs", 1), Some("Link"));
        let sub = |i| tlv_range(&buf, &link, "sub_tlvs", i);
        assert_child(&buf, &sub(0), "link_type", FieldValue::U8(1));
        assert_child(&buf, &sub(1), "link_id", FieldValue::Ipv4Addr([2, 2, 2, 2]));
        let locals = children(&buf, &range(child(&buf, &sub(2), "local_addresses")));
        assert_eq!(locals.len(), 2);
        assert_eq!(locals[1].value, FieldValue::Ipv4Addr([10, 0, 1, 1]));
        let remotes = children(&buf, &range(child(&buf, &sub(3), "remote_addresses")));
        assert_eq!(remotes[0].value, FieldValue::Ipv4Addr([10, 0, 0, 2]));
        assert_child(&buf, &sub(4), "te_metric", FieldValue::U32(10));
        assert_child(
            &buf,
            &sub(5),
            "max_bandwidth",
            FieldValue::U32(1.25e8f32.to_bits()),
        );
        assert_child(
            &buf,
            &sub(6),
            "max_reservable_bandwidth",
            FieldValue::U32(1.0e8f32.to_bits()),
        );
        let unreserved = children(&buf, &range(child(&buf, &sub(7), "unreserved_bandwidth")));
        assert_eq!(unreserved.len(), 8);
        assert_child(&buf, &sub(8), "admin_group", FieldValue::U32(0x0f));
        assert_eq!(
            tlv_name(&buf, &link, "sub_tlvs", 9),
            Some("Shared Risk Link Group")
        );
        assert_child(&buf, &sub(9), "value", FieldValue::Bytes(&[0, 0, 0, 1]));
    }

    /// RFC 7684, Section 2.1 and RFC 8665, Sections 4-5 — Extended Prefix
    /// Opaque LSA with a Prefix-SID and an Extended Prefix Range TLV.
    /// <https://www.rfc-editor.org/rfc/rfc7684#section-2.1>
    /// <https://www.rfc-editor.org/rfc/rfc8665#section-4>
    #[test]
    fn parse_extended_prefix_opaque_lsa() {
        let mut prefix = vec![1, 32, 0, 0x40, 10, 0, 0, 1]; // intra, /32, IPv4, N
        prefix.extend(tlv(2, &[0x40, 0, 0, 0, 0, 0, 0, 101])); // Prefix-SID idx 101
        let mut body = tlv(1, &prefix);
        let mut prange = vec![24, 0, 0, 16, 0x80, 0, 0, 0, 192, 168, 0, 0];
        prange.extend(tlv(2, &[0x60, 0, 0, 0, 0x00, 0x3e, 0x80])); // V|L label 16000
        body.extend(tlv(2, &prange));
        let pkt = build_lsu(&[build_lsa(10, [7, 0, 0, 1], &body)]);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let lsa = lsa_range(&buf, 0);
        assert_eq!(
            tlv_name(&buf, &lsa, "tlvs", 0),
            Some("OSPFv2 Extended Prefix")
        );
        let p = tlv_range(&buf, &lsa, "tlvs", 0);
        assert_child(&buf, &p, "route_type", FieldValue::U8(1));
        assert_child(&buf, &p, "prefix_length", FieldValue::U8(32));
        assert_child(&buf, &p, "address_family", FieldValue::U8(0));
        assert_child(&buf, &p, "flags", FieldValue::U8(0x40));
        assert_child(&buf, &p, "prefix", FieldValue::Ipv4Addr([10, 0, 0, 1]));
        assert_eq!(tlv_name(&buf, &p, "sub_tlvs", 0), Some("Prefix-SID"));
        let sid = tlv_range(&buf, &p, "sub_tlvs", 0);
        assert_child(&buf, &sid, "flags", FieldValue::U8(0x40));
        assert_child(&buf, &sid, "mt_id", FieldValue::U8(0));
        assert_child(&buf, &sid, "algorithm", FieldValue::U8(0));
        assert_child(&buf, &sid, "sid", FieldValue::U32(101));

        let r = tlv_range(&buf, &lsa, "tlvs", 1);
        assert_eq!(
            tlv_name(&buf, &lsa, "tlvs", 1),
            Some("OSPF Extended Prefix Range")
        );
        assert_child(&buf, &r, "prefix_length", FieldValue::U8(24));
        assert_child(&buf, &r, "range_size", FieldValue::U32(16));
        assert_child(&buf, &r, "flags", FieldValue::U8(0x80));
        assert_child(&buf, &r, "prefix", FieldValue::Ipv4Addr([192, 168, 0, 0]));
        let sid = tlv_range(&buf, &r, "sub_tlvs", 0);
        assert_child(&buf, &sid, "sid", FieldValue::U32(16000));
    }

    /// RFC 7684, Section 3.1 and RFC 8665, Section 6 — Extended Link Opaque
    /// LSA with Adj-SID and LAN Adj-SID sub-TLVs.
    /// <https://www.rfc-editor.org/rfc/rfc7684#section-3.1>
    /// <https://www.rfc-editor.org/rfc/rfc8665#section-6>
    #[test]
    fn parse_extended_link_opaque_lsa() {
        let mut link = vec![1, 0, 0, 0, 2, 2, 2, 2, 10, 0, 0, 1];
        link.extend(tlv(2, &[0x60, 0, 0, 5, 0x00, 0x5d, 0xc0])); // Adj-SID label 24000
        link.extend(tlv(3, &[0x60, 0, 0, 0, 3, 3, 3, 3, 0x00, 0x5d, 0xc1]));
        link.extend(tlv(1, &[0, 0, 0, 9])); // SID/Label
        let body = tlv(1, &link);
        let pkt = build_lsu(&[build_lsa(10, [8, 0, 0, 3], &body)]);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let lsa = lsa_range(&buf, 0);
        assert_eq!(
            tlv_name(&buf, &lsa, "tlvs", 0),
            Some("OSPFv2 Extended Link")
        );
        let l = tlv_range(&buf, &lsa, "tlvs", 0);
        assert_child(&buf, &l, "link_type", FieldValue::U8(1));
        assert_child(&buf, &l, "link_id", FieldValue::Ipv4Addr([2, 2, 2, 2]));
        assert_child(&buf, &l, "link_data", FieldValue::Ipv4Addr([10, 0, 0, 1]));
        assert_eq!(tlv_name(&buf, &l, "sub_tlvs", 0), Some("Adj-SID"));
        let adj = tlv_range(&buf, &l, "sub_tlvs", 0);
        assert_child(&buf, &adj, "flags", FieldValue::U8(0x60));
        assert_child(&buf, &adj, "weight", FieldValue::U8(5));
        assert_child(&buf, &adj, "sid", FieldValue::U32(24000));
        let lan = tlv_range(&buf, &l, "sub_tlvs", 1);
        assert_eq!(tlv_name(&buf, &l, "sub_tlvs", 1), Some("LAN Adj-SID/Label"));
        assert_child(
            &buf,
            &lan,
            "neighbor_id",
            FieldValue::Ipv4Addr([3, 3, 3, 3]),
        );
        assert_child(&buf, &lan, "sid", FieldValue::U32(24001));
        let sl = tlv_range(&buf, &l, "sub_tlvs", 2);
        assert_child(&buf, &sl, "sid", FieldValue::U32(9));
    }

    /// Malformed TLVs: a short fixed part is kept raw, and a TLV whose length
    /// overruns the LSA stops the walk with the rest exposed as `unparsed`.
    #[test]
    fn parse_opaque_lsa_malformed_tlvs() {
        let mut body = tlv(1, &[1, 1]); // TE Router Address, too short
        body.extend_from_slice(&[0, 2, 0, 40, 9, 9]); // Link TLV overruns
        let pkt = build_lsu(&[build_lsa(10, [1, 0, 0, 0], &body)]);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let lsa = lsa_range(&buf, 0);
        let ra = tlv_range(&buf, &lsa, "tlvs", 0);
        assert_child(&buf, &ra, "value", FieldValue::Bytes(&[1, 1]));
        assert_child(
            &buf,
            &lsa,
            "unparsed",
            FieldValue::Bytes(&[0, 2, 0, 40, 9, 9]),
        );
    }

    /// Opaque LSA of an opaque type without a TLV decoder keeps a raw body.
    #[test]
    fn parse_unknown_opaque_type_is_raw() {
        let pkt = build_lsu(&[build_lsa(9, [3, 0, 0, 0], &[0, 1, 0, 4, 0, 0, 0, 60])]);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let lsa = lsa_range(&buf, 0);
        assert_eq!(
            buf.resolve_nested_display_name(&lsa, "opaque_type_name"),
            Some("grace-LSA")
        );
        assert_child(
            &buf,
            &lsa,
            "body",
            FieldValue::Bytes(&[0, 1, 0, 4, 0, 0, 0, 60]),
        );
    }

    /// Build a Hello packet body (20 bytes) with the given Options.
    fn hello_body(options: u8) -> Vec<u8> {
        let mut body = vec![255, 255, 255, 0, 0, 10, options, 1, 0, 0, 0, 40];
        body.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        body
    }

    /// RFC 2328, Appendix D.3 — Cryptographic authentication: the
    /// authentication field is split and the digest after the packet is
    /// consumed.
    /// <https://www.rfc-editor.org/rfc/rfc2328>
    #[test]
    fn parse_crypto_auth_digest() {
        let mut pkt = build_header(1, 44, [1, 1, 1, 1]);
        pkt[14..16].copy_from_slice(&[0, 2]); // AuType 2
        pkt[16..24].copy_from_slice(&[0, 0, 7, 16, 0, 0, 1, 0]); // Key 7, len 16, seq 256
        pkt.extend(hello_body(0x02));
        pkt.extend_from_slice(&[0xAA; 16]); // MD5 digest

        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 60);

        let layer = buf.layer_by_name("OSPFv2").unwrap();
        assert_eq!(layer.range, 0..60);
        assert_eq!(buf.field_u8(layer, "key_id"), Some(7));
        assert_eq!(buf.field_u8(layer, "auth_data_len"), Some(16));
        assert_eq!(buf.field_u32(layer, "crypto_sequence_number"), Some(256));
        let digest = buf.field_by_name(layer, "auth_digest").unwrap();
        assert_eq!(digest.value, FieldValue::Bytes(&[0xAA; 16]));
        assert_eq!(digest.range, 44..60);
    }

    /// A digest that is not fully present is not consumed.
    #[test]
    fn parse_crypto_auth_missing_digest() {
        let mut pkt = build_header(1, 44, [1, 1, 1, 1]);
        pkt[14..16].copy_from_slice(&[0, 2]);
        pkt[16..24].copy_from_slice(&[0, 0, 1, 16, 0, 0, 0, 1]);
        pkt.extend(hello_body(0x02));
        pkt.extend_from_slice(&[0xAA; 4]);

        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 44);
        let layer = buf.layer_by_name("OSPFv2").unwrap();
        assert!(buf.field_by_name(layer, "auth_digest").is_none());
    }

    /// With the L-bit set but the digest missing, the bytes after the packet
    /// are not taken as an LLS block.
    #[test]
    fn parse_lls_not_read_when_digest_missing() {
        let mut pkt = build_header(1, 44, [1, 1, 1, 1]);
        pkt[14..16].copy_from_slice(&[0, 2]);
        pkt[16..24].copy_from_slice(&[0, 0, 1, 16, 0, 0, 0, 1]);
        pkt.extend(hello_body(0x12));
        pkt.extend_from_slice(&[0, 0, 0, 2, 0, 1, 0, 0]); // looks like LLS
        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 44);
        let layer = buf.layer_by_name("OSPFv2").unwrap();
        assert!(buf.field_by_name(layer, "lls").is_none());
    }

    /// Bytes after the last LSA that can be delimited, and a trailing partial
    /// LSA header in an LSAck, are exposed as `unparsed`; the arrays only
    /// cover the decoded entries.
    #[test]
    fn parse_lsu_and_lsack_trailing_bytes() {
        let lsa = build_lsa(2, [10, 0, 0, 1], &[255, 255, 255, 0]);
        let mut pkt = build_lsu(core::slice::from_ref(&lsa));
        pkt[24..28].copy_from_slice(&[0, 0, 0, 2]); // claims 2 LSAs
        pkt.extend_from_slice(&[0, 1, 2, 3]);
        let len = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&len.to_be_bytes());
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("OSPFv2").unwrap();
        let lsas = buf.field_by_name(layer, "lsas").unwrap();
        assert_eq!(lsas.range, 28..28 + lsa.len());
        let unparsed = buf.field_by_name(layer, "unparsed").unwrap();
        assert_eq!(unparsed.value, FieldValue::Bytes(&[0, 1, 2, 3]));

        let mut pkt = build_header(5, (HEADER_SIZE + 22) as u16, [1, 1, 1, 1]);
        pkt.extend_from_slice(&build_lsa_header(1, 20));
        pkt.extend_from_slice(&[7, 7]);
        let mut buf = DissectBuffer::new();
        Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("OSPFv2").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "lsa_headers").unwrap().range,
            24..44
        );
        assert_eq!(
            buf.field_by_name(layer, "unparsed").unwrap().value,
            FieldValue::Bytes(&[7, 7])
        );
    }

    /// RFC 5613, Section 2 — LLS data block after a Hello with the L-bit,
    /// following the cryptographic digest.
    /// <https://www.rfc-editor.org/rfc/rfc5613#section-2>
    #[test]
    fn parse_lls_block_after_digest() {
        let mut pkt = build_header(1, 44, [1, 1, 1, 1]);
        pkt[14..16].copy_from_slice(&[0, 2]);
        pkt[16..24].copy_from_slice(&[0, 0, 1, 16, 0, 0, 0, 9]);
        pkt.extend(hello_body(0x12)); // L | E
        pkt.extend_from_slice(&[0xBB; 16]); // digest
        let mut tlvs = tlv(1, &[0, 0, 0, 1]); // EOF-TLV: LR bit
        tlvs.extend(tlv(2, &[0, 0, 0, 9, 0xCC, 0xCC, 0xCC, 0xCC])); // CA-TLV
        let words = ((4 + tlvs.len()) / 4) as u16;
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(&words.to_be_bytes());
        pkt.extend(tlvs);

        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, pkt.len());

        let layer = buf.layer_by_name("OSPFv2").unwrap();
        let lls = buf.field_by_name(layer, "lls").unwrap();
        assert_eq!(lls.range, 60..pkt.len());
        let lls = range(lls);
        assert_child(&buf, &lls, "checksum", FieldValue::U16(0));
        assert_child(&buf, &lls, "lls_data_length", FieldValue::U16(words));
        assert_eq!(
            tlv_name(&buf, &lls, "tlvs", 0),
            Some("Extended Options and Flags")
        );
        let eof = tlv_range(&buf, &lls, "tlvs", 0);
        assert_child(&buf, &eof, "extended_options", FieldValue::U32(1));
        let ca = tlv_range(&buf, &lls, "tlvs", 1);
        assert_child(&buf, &ca, "sequence_number", FieldValue::U32(9));
        assert_child(&buf, &ca, "auth_data", FieldValue::Bytes(&[0xCC; 4]));
    }

    /// The LLS block is only examined when the L-bit is set, and a block whose
    /// declared length overruns the data is ignored.
    #[test]
    fn parse_lls_block_requires_l_bit_and_length() {
        let mut pkt = build_header(1, 44, [1, 1, 1, 1]);
        pkt.extend(hello_body(0x02));
        pkt.extend_from_slice(&[0, 0, 0, 2, 0, 1, 0, 4]);
        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 44);

        let mut pkt = build_header(1, 44, [1, 1, 1, 1]);
        pkt.extend(hello_body(0x10));
        pkt.extend_from_slice(&[0, 0, 0, 9, 0, 1, 0, 4]); // 9 words > 8 bytes
        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 44);
        let layer = buf.layer_by_name("OSPFv2").unwrap();
        assert!(buf.field_by_name(layer, "lls").is_none());
    }

    /// RFC 5613, Section 2 — LLS may also follow a Database Description packet.
    /// <https://www.rfc-editor.org/rfc/rfc5613#section-2>
    #[test]
    fn parse_lls_block_after_dd() {
        let mut pkt = build_header(2, 32, [1, 1, 1, 1]);
        pkt.extend_from_slice(&[0x05, 0xDC, 0x12, 0x07, 0, 0, 0, 1]);
        pkt.extend_from_slice(&[0, 0, 0, 3]);
        pkt.extend(tlv(1, &[0, 0, 0, 2]));
        let mut buf = DissectBuffer::new();
        let result = Ospfv2Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 44);
    }
}
