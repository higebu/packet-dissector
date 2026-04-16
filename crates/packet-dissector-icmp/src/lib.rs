//! ICMP (Internet Control Message Protocol) dissector.
//!
//! ## References
//! - RFC 792: <https://www.rfc-editor.org/rfc/rfc792>
//! - RFC 950 (updates RFC 792 — Address Mask): <https://www.rfc-editor.org/rfc/rfc950>
//! - RFC 1191 (Path MTU Discovery — updates Type 3 Code 4): <https://www.rfc-editor.org/rfc/rfc1191>
//! - RFC 1256 (Router Discovery): <https://www.rfc-editor.org/rfc/rfc1256>
//! - RFC 2521 (ICMP Security Failures / Photuris): <https://www.rfc-editor.org/rfc/rfc2521>
//! - RFC 4065 (Seamoby Experimental Mobility): <https://www.rfc-editor.org/rfc/rfc4065>
//! - RFC 4884 (Extended ICMP — adds Length at offset 5 for Types 3/11/12): <https://www.rfc-editor.org/rfc/rfc4884>
//! - RFC 4950 (MPLS Label Stack — Extension Object Class 1): <https://www.rfc-editor.org/rfc/rfc4950>
//! - RFC 5837 (Interface Information Object — Extension Object Class 2): <https://www.rfc-editor.org/rfc/rfc5837>
//! - RFC 6633 (Deprecation of Source Quench): <https://www.rfc-editor.org/rfc/rfc6633>
//! - RFC 6918 (Formally Deprecating Types 6, 15–18, 30–39): <https://www.rfc-editor.org/rfc/rfc6918>
//! - RFC 8335 (PROBE — Extended Echo Request/Reply, Types 42/43; Interface Identification Class 3): <https://www.rfc-editor.org/rfc/rfc8335>

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
const FD_PHOTURIS_RESERVED: usize = 25;
const FD_PHOTURIS_POINTER: usize = 26;
const FD_EXTENSIONS: usize = 27;

// Minimum ICMP Extension Header size per RFC 4884, Section 7.
// <https://www.rfc-editor.org/rfc/rfc4884#section-7>
const EXT_HEADER_SIZE: usize = 4;
// Minimum ICMP Extension Object header size per RFC 4884, Section 7.
const EXT_OBJECT_HEADER_SIZE: usize = 4;
// Minimum padded original datagram length when extensions are present, per
// RFC 4884, Section 5.5. <https://www.rfc-editor.org/rfc/rfc4884#section-5.5>
const EXT_COMPAT_MIN_ORIG_DATAGRAM: usize = 128;

// EXTENSION_CHILDREN indices
const EXT_VERSION: usize = 0;
const EXT_RESERVED: usize = 1;
const EXT_CHECKSUM: usize = 2;
const EXT_OBJECTS: usize = 3;

// EXTENSION_OBJECT_CHILDREN indices
const EOBJ_LENGTH: usize = 0;
const EOBJ_CLASS_NUM: usize = 1;
const EOBJ_C_TYPE: usize = 2;
const EOBJ_PAYLOAD: usize = 3;
const EOBJ_MPLS_LABELS: usize = 4;
const EOBJ_INTERFACE_ROLE: usize = 5;
const EOBJ_IF_INDEX: usize = 6;
const EOBJ_AFI: usize = 7;
const EOBJ_ADDRESS_LENGTH: usize = 8;
const EOBJ_IPV4_ADDRESS: usize = 9;
const EOBJ_IPV6_ADDRESS: usize = 10;
const EOBJ_INTERFACE_NAME: usize = 11;
const EOBJ_MTU: usize = 12;

// MPLS_LABEL_CHILDREN indices
const MPLS_LABEL: usize = 0;
const MPLS_TC: usize = 1;
const MPLS_S: usize = 2;
const MPLS_TTL: usize = 3;

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
    // RFC 1256, Section 3.1 — Preference Level is "A signed, twos-complement value;
    // higher values mean more preferable." The minimum value (0x80000000 = i32::MIN)
    // signals that the address MUST NOT be used as a default router.
    // <https://www.rfc-editor.org/rfc/rfc1256#section-3.1>
    FieldDescriptor::new("preference_level", "Preference Level", FieldType::I32),
];

// RFC 4950, Section 3 — MPLS Label Stack Entry (4 octets).
// <https://www.rfc-editor.org/rfc/rfc4950#section-3>
static MPLS_LABEL_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("label", "Label", FieldType::U32),
    FieldDescriptor::new("tc", "Traffic Class", FieldType::U8),
    FieldDescriptor::new("s", "Bottom of Stack", FieldType::U8),
    FieldDescriptor::new("ttl", "Time to Live", FieldType::U8),
];

// RFC 4884, Section 7.1 — ICMP Extension Object Header, plus per-class payload
// fields parsed out by this dissector (RFC 4950 Class 1, RFC 5837 Class 2,
// RFC 8335 Section 2.1 Class 3). Only the first three entries are always present;
// the remainder are conditional on class/c_type.
// <https://www.rfc-editor.org/rfc/rfc4884#section-7.1>
static EXTENSION_OBJECT_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("class_num", "Class-Num", FieldType::U8),
    FieldDescriptor::new("c_type", "C-Type", FieldType::U8),
    FieldDescriptor::new("payload", "Payload", FieldType::Bytes).optional(),
    FieldDescriptor::new("mpls_labels", "MPLS Label Stack", FieldType::Array)
        .optional()
        .with_children(MPLS_LABEL_CHILDREN),
    FieldDescriptor::new("interface_role", "Interface Role", FieldType::U8).optional(),
    FieldDescriptor::new("if_index", "ifIndex", FieldType::U32).optional(),
    FieldDescriptor::new("afi", "Address Family Identifier", FieldType::U16).optional(),
    FieldDescriptor::new("address_length", "Address Length", FieldType::U8).optional(),
    FieldDescriptor::new("ipv4_address", "IPv4 Address", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("ipv6_address", "IPv6 Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("interface_name", "Interface Name", FieldType::Bytes).optional(),
    FieldDescriptor::new("mtu", "MTU", FieldType::U32).optional(),
];

// RFC 4884, Section 7 — ICMP Extension Header fields.
// <https://www.rfc-editor.org/rfc/rfc4884#section-7>
static EXTENSION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U16),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    FieldDescriptor::new("objects", "Objects", FieldType::Array)
        .with_children(EXTENSION_OBJECT_CHILDREN),
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
    // RFC 2521, Section 2 — Photuris (Type 40) Reserved is 16 bits, Pointer is 16 bits.
    // These distinct descriptors coexist with the 8-bit `pointer` used by Parameter
    // Problem (Type 12, RFC 792) so each field carries the correct declared width.
    // <https://www.rfc-editor.org/rfc/rfc2521#section-2>
    FieldDescriptor::new("photuris_reserved", "Reserved", FieldType::U16).optional(),
    FieldDescriptor::new("photuris_pointer", "Pointer", FieldType::U16).optional(),
    // RFC 4884, Section 7 — ICMP Extension Structure (Types 3/11/12 after padded
    // original datagram; Type 42 after the fixed 8-byte header).
    // <https://www.rfc-editor.org/rfc/rfc4884#section-7>
    FieldDescriptor::new("extensions", "ICMP Extension Structure", FieldType::Object)
        .optional()
        .with_children(EXTENSION_CHILDREN),
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

/// Parse an ICMP Extension Structure (RFC 4884, Section 7) starting at `data[0..]`.
///
/// The caller is responsible for locating the start of the Extension Structure
/// (after the padded original datagram for Types 3/11/12, or immediately after
/// the 8-byte header for Type 42 per RFC 8335, Section 2).
///
/// Silently stops on malformed input (length fields out of range, truncated
/// objects) per Postel's Law — the ICMP message itself remains valid.
///
/// RFC 4884, Section 7 — <https://www.rfc-editor.org/rfc/rfc4884#section-7>
fn push_extensions<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    if data.len() < EXT_HEADER_SIZE {
        return;
    }
    // RFC 4884, Section 7 — Version (4 bits) + Reserved (12 bits) + Checksum (16 bits).
    let version = data[0] >> 4;
    let reserved = (u16::from(data[0] & 0x0F) << 8) | u16::from(data[1]);
    let checksum = read_be_u16(data, 2).unwrap_or_default();

    let ext_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_EXTENSIONS],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    buf.push_field(
        &EXTENSION_CHILDREN[EXT_VERSION],
        FieldValue::U8(version),
        offset..offset + 1,
    );
    buf.push_field(
        &EXTENSION_CHILDREN[EXT_RESERVED],
        FieldValue::U16(reserved),
        offset..offset + 2,
    );
    buf.push_field(
        &EXTENSION_CHILDREN[EXT_CHECKSUM],
        FieldValue::U16(checksum),
        offset + 2..offset + 4,
    );

    let objects_idx = buf.begin_container(
        &EXTENSION_CHILDREN[EXT_OBJECTS],
        FieldValue::Array(0..0),
        offset + EXT_HEADER_SIZE..offset + data.len(),
    );
    let mut pos = EXT_HEADER_SIZE;
    while pos + EXT_OBJECT_HEADER_SIZE <= data.len() {
        // RFC 4884, Section 7.1 — Object header: Length(u16) + Class-Num(u8) + C-Type(u8).
        let obj_len = read_be_u16(data, pos).unwrap_or_default() as usize;
        let class_num = data[pos + 2];
        let c_type = data[pos + 3];
        // Length covers the whole Object header plus payload (minimum 4 octets).
        if obj_len < EXT_OBJECT_HEADER_SIZE || pos + obj_len > data.len() {
            break;
        }
        let body = &data[pos + EXT_OBJECT_HEADER_SIZE..pos + obj_len];
        let body_offset = offset + pos + EXT_OBJECT_HEADER_SIZE;
        let c_type_offset = offset + pos + 3;

        let obj_idx = buf.begin_container(
            &EXTENSION_CHILDREN[EXT_OBJECTS],
            FieldValue::Object(0..0),
            offset + pos..offset + pos + obj_len,
        );
        buf.push_field(
            &EXTENSION_OBJECT_CHILDREN[EOBJ_LENGTH],
            FieldValue::U16(obj_len as u16),
            offset + pos..offset + pos + 2,
        );
        buf.push_field(
            &EXTENSION_OBJECT_CHILDREN[EOBJ_CLASS_NUM],
            FieldValue::U8(class_num),
            offset + pos + 2..offset + pos + 3,
        );
        buf.push_field(
            &EXTENSION_OBJECT_CHILDREN[EOBJ_C_TYPE],
            FieldValue::U8(c_type),
            offset + pos + 3..offset + pos + 4,
        );

        match (class_num, c_type) {
            // RFC 4950, Section 3 — MPLS Label Stack (Class-Num 1, C-Type 1).
            // <https://www.rfc-editor.org/rfc/rfc4950#section-3>
            (1, 1) => push_mpls_labels(buf, body, body_offset),
            // RFC 5837, Section 4 — Interface Information (Class-Num 2).
            // C-Type itself encodes Role + sub-object presence flags.
            // <https://www.rfc-editor.org/rfc/rfc5837#section-4>
            (2, _) => push_interface_info(buf, body, body_offset, c_type, c_type_offset),
            // RFC 8335, Section 2.1 — Interface Identification (Class-Num 3).
            // <https://www.rfc-editor.org/rfc/rfc8335#section-2.1>
            (3, _) => push_interface_id(buf, body, body_offset, c_type),
            _ => {
                if !body.is_empty() {
                    buf.push_field(
                        &EXTENSION_OBJECT_CHILDREN[EOBJ_PAYLOAD],
                        FieldValue::Bytes(body),
                        body_offset..body_offset + body.len(),
                    );
                }
            }
        }
        buf.end_container(obj_idx);
        pos += obj_len;
    }
    buf.end_container(objects_idx);
    buf.end_container(ext_idx);
}

/// Parse an RFC 4950 MPLS Label Stack Object body as an array of 4-octet LSEs.
///
/// Each entry: Label (20 bits) | TC (3 bits) | S (1 bit) | TTL (8 bits).
/// <https://www.rfc-editor.org/rfc/rfc4950#section-3>
fn push_mpls_labels<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], offset: usize) {
    let arr_idx = buf.begin_container(
        &EXTENSION_OBJECT_CHILDREN[EOBJ_MPLS_LABELS],
        FieldValue::Array(0..0),
        offset..offset + body.len(),
    );
    let mut p = 0usize;
    while p + 4 <= body.len() {
        let b0 = u32::from(body[p]);
        let b1 = u32::from(body[p + 1]);
        let b2 = u32::from(body[p + 2]);
        // Label occupies the high 20 bits of octets 0..3.
        let label = (b0 << 12) | (b1 << 4) | (b2 >> 4);
        let tc = (body[p + 2] >> 1) & 0x07;
        let s = body[p + 2] & 0x01;
        let ttl = body[p + 3];

        let entry_idx = buf.begin_container(
            &EXTENSION_OBJECT_CHILDREN[EOBJ_MPLS_LABELS],
            FieldValue::Object(0..0),
            offset + p..offset + p + 4,
        );
        buf.push_field(
            &MPLS_LABEL_CHILDREN[MPLS_LABEL],
            FieldValue::U32(label),
            offset + p..offset + p + 3,
        );
        buf.push_field(
            &MPLS_LABEL_CHILDREN[MPLS_TC],
            FieldValue::U8(tc),
            offset + p + 2..offset + p + 3,
        );
        buf.push_field(
            &MPLS_LABEL_CHILDREN[MPLS_S],
            FieldValue::U8(s),
            offset + p + 2..offset + p + 3,
        );
        buf.push_field(
            &MPLS_LABEL_CHILDREN[MPLS_TTL],
            FieldValue::U8(ttl),
            offset + p + 3..offset + p + 4,
        );
        buf.end_container(entry_idx);
        p += 4;
    }
    buf.end_container(arr_idx);
}

/// Parse an RFC 5837 Interface Information Object body.
///
/// The C-Type byte itself encodes the Interface Role (bits 0-1) and four
/// presence flags: ifIndex (bit 4), IP Address (bit 5), Interface Name (bit 6),
/// MTU (bit 7). Sub-objects appear in that fixed order.
///
/// RFC 5837, Section 4 — <https://www.rfc-editor.org/rfc/rfc5837#section-4>
fn push_interface_info<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    body_offset: usize,
    c_type: u8,
    c_type_offset: usize,
) {
    // RFC 5837, Section 4.1 — Interface Role: bits 0-1 of the C-Type byte
    // (bit 0 = MSB; i.e. (c_type >> 6) & 0x03).
    let role = (c_type >> 6) & 0x03;
    let has_ifindex = (c_type & 0x08) != 0;
    let has_addr = (c_type & 0x04) != 0;
    let has_name = (c_type & 0x02) != 0;
    let has_mtu = (c_type & 0x01) != 0;

    buf.push_field(
        &EXTENSION_OBJECT_CHILDREN[EOBJ_INTERFACE_ROLE],
        FieldValue::U8(role),
        c_type_offset..c_type_offset + 1,
    );

    let mut p = 0usize;
    if has_ifindex {
        if p + 4 > body.len() {
            return;
        }
        let ifindex = read_be_u32(body, p).unwrap_or_default();
        buf.push_field(
            &EXTENSION_OBJECT_CHILDREN[EOBJ_IF_INDEX],
            FieldValue::U32(ifindex),
            body_offset + p..body_offset + p + 4,
        );
        p += 4;
    }
    if has_addr {
        // RFC 5837, Section 4.2 — IP Address Sub-Object: AFI(u16) + Reserved(u16) + Address.
        if p + 4 > body.len() {
            return;
        }
        let afi = read_be_u16(body, p).unwrap_or_default();
        buf.push_field(
            &EXTENSION_OBJECT_CHILDREN[EOBJ_AFI],
            FieldValue::U16(afi),
            body_offset + p..body_offset + p + 2,
        );
        p += 4; // skip AFI + Reserved
        match afi {
            // IANA Address Family Numbers: 1 = IPv4, 2 = IPv6.
            1 => {
                if p + 4 > body.len() {
                    return;
                }
                let addr = [body[p], body[p + 1], body[p + 2], body[p + 3]];
                buf.push_field(
                    &EXTENSION_OBJECT_CHILDREN[EOBJ_IPV4_ADDRESS],
                    FieldValue::Ipv4Addr(addr),
                    body_offset + p..body_offset + p + 4,
                );
                p += 4;
            }
            2 => {
                if p + 16 > body.len() {
                    return;
                }
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&body[p..p + 16]);
                buf.push_field(
                    &EXTENSION_OBJECT_CHILDREN[EOBJ_IPV6_ADDRESS],
                    FieldValue::Ipv6Addr(addr),
                    body_offset + p..body_offset + p + 16,
                );
                p += 16;
            }
            _ => return,
        }
    }
    if has_name {
        // RFC 5837, Section 4.5 — Interface Name Sub-Object: 1-octet Length
        // (including itself, multiple of 4, max 64), then name bytes padded with NULs.
        if p >= body.len() {
            return;
        }
        let name_total = body[p] as usize;
        if name_total < 2 || p + name_total > body.len() {
            return;
        }
        let name_bytes = &body[p + 1..p + name_total];
        buf.push_field(
            &EXTENSION_OBJECT_CHILDREN[EOBJ_INTERFACE_NAME],
            FieldValue::Bytes(name_bytes),
            body_offset + p + 1..body_offset + p + name_total,
        );
        p += name_total;
    }
    if has_mtu {
        // RFC 5837, Section 4.6 — MTU Sub-Object: 32-bit unsigned MTU.
        if p + 4 > body.len() {
            return;
        }
        let mtu = read_be_u32(body, p).unwrap_or_default();
        buf.push_field(
            &EXTENSION_OBJECT_CHILDREN[EOBJ_MTU],
            FieldValue::U32(mtu),
            body_offset + p..body_offset + p + 4,
        );
    }
}

/// Parse an RFC 8335 Interface Identification Object body (Class-Num 3).
///
/// - C-Type 1: interface name (raw bytes, NUL-padded to 32-bit boundary).
/// - C-Type 2: 32-bit ifIndex.
/// - C-Type 3: AFI(u16) + AddrLen(u8) + Reserved(u8) + Address (NUL-padded).
///
/// <https://www.rfc-editor.org/rfc/rfc8335#section-2.1>
fn push_interface_id<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    body_offset: usize,
    c_type: u8,
) {
    match c_type {
        1 => {
            if !body.is_empty() {
                buf.push_field(
                    &EXTENSION_OBJECT_CHILDREN[EOBJ_INTERFACE_NAME],
                    FieldValue::Bytes(body),
                    body_offset..body_offset + body.len(),
                );
            }
        }
        2 => {
            if body.len() >= 4 {
                let ifindex = read_be_u32(body, 0).unwrap_or_default();
                buf.push_field(
                    &EXTENSION_OBJECT_CHILDREN[EOBJ_IF_INDEX],
                    FieldValue::U32(ifindex),
                    body_offset..body_offset + 4,
                );
            }
        }
        3 => {
            if body.len() < 4 {
                return;
            }
            let afi = read_be_u16(body, 0).unwrap_or_default();
            let addr_len = body[2];
            buf.push_field(
                &EXTENSION_OBJECT_CHILDREN[EOBJ_AFI],
                FieldValue::U16(afi),
                body_offset..body_offset + 2,
            );
            buf.push_field(
                &EXTENSION_OBJECT_CHILDREN[EOBJ_ADDRESS_LENGTH],
                FieldValue::U8(addr_len),
                body_offset + 2..body_offset + 3,
            );
            match afi {
                // IANA AFI: 1 = IPv4 (4 octets), 2 = IPv6 (16 octets).
                1 if addr_len as usize >= 4 && body.len() >= 8 => {
                    let a = [body[4], body[5], body[6], body[7]];
                    buf.push_field(
                        &EXTENSION_OBJECT_CHILDREN[EOBJ_IPV4_ADDRESS],
                        FieldValue::Ipv4Addr(a),
                        body_offset + 4..body_offset + 8,
                    );
                }
                2 if addr_len as usize >= 16 && body.len() >= 20 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&body[4..20]);
                    buf.push_field(
                        &EXTENSION_OBJECT_CHILDREN[EOBJ_IPV6_ADDRESS],
                        FieldValue::Ipv6Addr(a),
                        body_offset + 4..body_offset + 20,
                    );
                }
                _ => {}
            }
        }
        _ => {}
    }
}

/// Compute where the RFC 4884 Extension Structure starts for an error message
/// (Types 3, 11, 12). Returns `Some(offset)` when the Length field indicates
/// extensions follow, or `None` when there are no extensions to parse.
///
/// Per RFC 4884, Section 5.5, when the Length field is non-zero the original
/// datagram MUST be padded to at least 128 octets before the extensions.
/// <https://www.rfc-editor.org/rfc/rfc4884#section-5.5>
fn rfc4884_extension_offset(data_len: usize, length: u8) -> Option<usize> {
    if length == 0 {
        return None;
    }
    let orig_len = (length as usize) * 4;
    let padded = orig_len.max(EXT_COMPAT_MIN_ORIG_DATAGRAM);
    let ext_start = HEADER_SIZE + padded;
    if ext_start + EXT_HEADER_SIZE <= data_len {
        Some(ext_start)
    } else {
        None
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
            // RFC 792 — Echo Reply (0) / Echo Request (8)
            // <https://www.rfc-editor.org/rfc/rfc792#page-14>
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
            // RFC 792 — Destination Unreachable (3)
            // <https://www.rfc-editor.org/rfc/rfc792#page-4>
            // Safe: HEADER_SIZE check (8 bytes) guarantees indices 0..7
            3 => {
                // RFC 4884, Section 4.5 — Length field (offset 5) in 32-bit words.
                // <https://www.rfc-editor.org/rfc/rfc4884#section-4.5>
                let length = data[5];
                if length > 0 {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_LENGTH],
                        FieldValue::U8(length),
                        offset + 5..offset + 6,
                    );
                }
                if code == 4 {
                    // RFC 1191, Section 4 — Next-Hop MTU (u16 at offset 6).
                    // <https://www.rfc-editor.org/rfc/rfc1191#section-4>
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
                if let Some(ext_start) = rfc4884_extension_offset(data.len(), length) {
                    push_extensions(buf, &data[ext_start..], offset + ext_start);
                }
            }
            // RFC 792 / RFC 6633 — Source Quench (4), deprecated.
            // <https://www.rfc-editor.org/rfc/rfc6633#section-1>
            4 => {
                if data.len() > HEADER_SIZE {
                    push_invoking_packet(buf, &data[HEADER_SIZE..], offset + HEADER_SIZE);
                }
            }
            // RFC 792 — Time Exceeded (11)
            // <https://www.rfc-editor.org/rfc/rfc792#page-6>
            // Safe: HEADER_SIZE check (8 bytes) guarantees indices 0..7
            11 => {
                // RFC 4884, Section 4.5 — Length field (offset 5) in 32-bit words.
                // <https://www.rfc-editor.org/rfc/rfc4884#section-4.5>
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
                if let Some(ext_start) = rfc4884_extension_offset(data.len(), length) {
                    push_extensions(buf, &data[ext_start..], offset + ext_start);
                }
            }
            // RFC 792 — Redirect (5)
            // <https://www.rfc-editor.org/rfc/rfc792#page-12>
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
            // RFC 792 — Parameter Problem (12)
            // <https://www.rfc-editor.org/rfc/rfc792#page-8>
            12 => {
                // RFC 792 — Pointer (u8 at offset 4), identifies the octet in error.
                let pointer = data[4];
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_POINTER],
                    FieldValue::U8(pointer),
                    offset + 4..offset + 5,
                );
                // RFC 4884, Section 4.5 — Length field (offset 5) in 32-bit words.
                // <https://www.rfc-editor.org/rfc/rfc4884#section-4.5>
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
                if let Some(ext_start) = rfc4884_extension_offset(data.len(), length) {
                    push_extensions(buf, &data[ext_start..], offset + ext_start);
                }
            }
            // RFC 1256 — Router Advertisement (9)
            // <https://www.rfc-editor.org/rfc/rfc1256>
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
                    // RFC 1256, Section 3.1 — Preference Level is a signed 32-bit
                    // twos-complement value. <https://www.rfc-editor.org/rfc/rfc1256#section-3.1>
                    let pref = read_be_u32(data, pos + 4)? as i32;
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
                        FieldValue::I32(pref),
                        offset + pos + 4..offset + pos + 8,
                    );
                    buf.end_container(obj_idx);
                    pos += entry_bytes;
                }
                buf.end_container(array_idx);
            }
            // RFC 1256 — Router Solicitation (10), no type-specific fields
            // <https://www.rfc-editor.org/rfc/rfc1256>
            10 => {}
            // RFC 792 — Timestamp (13) / Timestamp Reply (14)
            // <https://www.rfc-editor.org/rfc/rfc792#page-16>
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
            // RFC 792 / RFC 6918 — Information Request (15) / Reply (16), deprecated.
            // <https://www.rfc-editor.org/rfc/rfc6918#section-3>
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
            // RFC 950 / RFC 6918 — Address Mask Request (17) / Reply (18), deprecated.
            // <https://www.rfc-editor.org/rfc/rfc950>
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
            // ICMP Security Failures / Photuris (Type 40) — RFC 2521, Section 2.
            // Layout: Reserved (u16 at offset 4), Pointer (u16 at offset 6), then
            // the Original Internet Headers + 64 bits of the offending payload.
            // <https://www.rfc-editor.org/rfc/rfc2521#section-2>
            40 => {
                let reserved = read_be_u16(data, 4)?;
                let pointer = read_be_u16(data, 6)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_PHOTURIS_RESERVED],
                    FieldValue::U16(reserved),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_PHOTURIS_POINTER],
                    FieldValue::U16(pointer),
                    offset + 6..offset + 8,
                );
                if data.len() > HEADER_SIZE {
                    push_invoking_packet(buf, &data[HEADER_SIZE..], offset + HEADER_SIZE);
                }
            }
            // RFC 4065, Section 8 — Experimental Mobility (41)
            // <https://www.rfc-editor.org/rfc/rfc4065#section-8>
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
            // RFC 8335, Section 2 — Extended Echo Request (42).
            // Body after the 8-byte header is an RFC 4884 Extension Structure
            // carrying the Interface Identification Object (Class-Num 3).
            // <https://www.rfc-editor.org/rfc/rfc8335#section-2>
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
                    push_extensions(buf, &data[HEADER_SIZE..], offset + HEADER_SIZE);
                }
            }
            // RFC 8335, Section 3 — Extended Echo Reply (43)
            // <https://www.rfc-editor.org/rfc/rfc8335#section-3>
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
    //! # RFC Coverage
    //!
    //! | RFC Section                        | Description                            | Test                                           |
    //! |------------------------------------|----------------------------------------|------------------------------------------------|
    //! | RFC 792 Echo Request/Reply         | Echo Request basic fields              | parse_echo_request                             |
    //! | RFC 792 Destination Unreachable    | Code 4 Next-Hop MTU (RFC 1191)         | parse_dest_unreachable_fragmentation_needed     |
    //! | RFC 4884 §4.5                      | Length field (offset 5)                | parse_dest_unreachable_with_rfc4884_length      |
    //! | RFC 792 Destination Unreachable    | IPv4 header only (regression)          | parse_invoking_packet_ipv4_only                |
    //! | RFC 792 Destination Unreachable    | UDP src_port/dst_port extraction       | parse_dest_unreachable_udp_ports               |
    //! | RFC 792 Destination Unreachable    | TCP src_port/dst_port extraction       | parse_dest_unreachable_tcp_ports               |
    //! | RFC 792 Destination Unreachable    | Other protocol → raw bytes             | parse_dest_unreachable_other_protocol          |
    //! | RFC 792 Destination Unreachable    | Truncated transport (no ports)         | parse_dest_unreachable_truncated_transport      |
    //! | RFC 792 Redirect                   | Gateway address                        | parse_redirect                                 |
    //! | RFC 792 Parameter Problem          | Pointer + RFC 4884 Length              | parse_parameter_problem                        |
    //! | RFC 792 Timestamp                  | 20-byte timestamp fields               | parse_timestamp_request                        |
    //! | RFC 792 Timestamp                  | Truncated timestamp → error            | parse_timestamp_truncated                      |
    //! | RFC 950 Address Mask               | Identifier + Seq + Mask                | parse_address_mask_reply                       |
    //! | RFC 1256 Router Advertisement      | Signed preference level                | parse_router_advertisement_signed_preference   |
    //! | RFC 1256 Router Advertisement      | Do-not-use preference (0x80000000)     | parse_router_advertisement_do_not_use          |
    //! | RFC 2521 Photuris (Type 40)        | Reserved(u16) + Pointer(u16)           | parse_photuris                                 |
    //! | RFC 8335 §2 Extended Echo Request  | Identifier, Seq(u8), L-bit             | parse_extended_echo_request                    |
    //! | RFC 8335 §3 Extended Echo Reply    | State, Active, IPv4, IPv6 flags        | parse_extended_echo_reply                      |
    //! | RFC 792                            | Header < 8 bytes → Truncated error     | parse_truncated_header                         |
    //! | RFC 4884 §7 Extension Header       | Version / Reserved / Checksum          | parse_extension_header_fields                  |
    //! | RFC 4884 §5.5                      | Length=0 → no extensions               | parse_extensions_not_parsed_when_length_zero   |
    //! | RFC 4884 §5.5                      | 128-octet min padded datagram rule     | rfc4884_extension_offset_padding_semantics     |
    //! | RFC 4884 §7.1                      | Malformed Object Length → stop         | parse_extension_malformed_object_length_stops_parsing |
    //! | RFC 4884 §7.1                      | Unknown class → raw payload            | parse_extension_unknown_class_preserves_payload |
    //! | RFC 4950 §3 MPLS Label Stack       | Class 1 LSE: Label/TC/S/TTL            | parse_extension_mpls_label_stack_class1        |
    //! | RFC 5837 §4 Interface Information  | Class 2 all sub-objects (IPv4)         | parse_extension_interface_info_class2_all_sub_objects |
    //! | RFC 5837 §4.2                      | Class 2 IPv6 address sub-object        | parse_extension_interface_info_class2_ipv6_address |
    //! | RFC 8335 §2.1 Interface ID         | Class 3 C-Type 1 (by Name)             | parse_extension_interface_id_class3_by_name    |
    //! | RFC 8335 §2.1 Interface ID         | Class 3 C-Type 2 (by Index)            | parse_extension_interface_id_class3_by_index   |
    //! | RFC 8335 §2.1 Interface ID         | Class 3 C-Type 3 (by IPv4 Address)     | parse_extension_interface_id_class3_by_address_ipv4 |
    //! | RFC 8335 §2.1 Interface ID         | Class 3 C-Type 3 (by IPv6 Address)     | parse_extension_interface_id_class3_by_address_ipv6 |
    //! | RFC 8335 §2 + RFC 4884             | Type 42 body IS Extension Structure    | parse_extended_echo_request_with_interface_id_extension |

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

    // ---- Basic type coverage tests ----

    #[test]
    fn parse_truncated_header() {
        let data = [0x08, 0x00, 0x00, 0x00]; // only 4 bytes, need 8
        let mut buf = DissectBuffer::new();
        let err = IcmpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PacketError::Truncated {
                    expected: 8,
                    actual: 4
                }
            ),
            "expected Truncated(8,4), got {err:?}"
        );
    }

    #[test]
    fn parse_echo_request() {
        // RFC 792 Echo Request: type=8, code=0, checksum, id=0x1234, seq=0x0001, data
        let data: &[u8] = &[
            0x08, 0x00, 0xAB, 0xCD, // type=8, code=0, checksum=0xABCD
            0x12, 0x34, 0x00, 0x01, // id=0x1234, seq=1
            0xDE, 0xAD, // 2 bytes payload
        ];
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        assert_eq!(fields[FD_TYPE].value, FieldValue::U8(8));
        assert_eq!(fields[FD_CODE].value, FieldValue::U8(0));
        assert_eq!(fields[FD_CHECKSUM].value, FieldValue::U16(0xABCD));
        let id = fields
            .iter()
            .find(|f| f.descriptor.name == "identifier")
            .unwrap();
        assert_eq!(id.value, FieldValue::U16(0x1234));
        let seq = fields
            .iter()
            .find(|f| f.descriptor.name == "sequence_number")
            .unwrap();
        assert_eq!(seq.value, FieldValue::U16(1));
        let payload = fields.iter().find(|f| f.descriptor.name == "data").unwrap();
        assert_eq!(payload.value, FieldValue::Bytes(&[0xDE, 0xAD]));
    }

    #[test]
    fn parse_dest_unreachable_fragmentation_needed() {
        // RFC 1191 — Type 3, Code 4: Next-Hop MTU at offset 6.
        let data: &[u8] = &[
            0x03, 0x04, 0x00, 0x00, // type=3, code=4, checksum
            0x00, 0x00, 0x05, 0xDC, // unused=0, next_hop_mtu=1500
        ];
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let mtu = fields
            .iter()
            .find(|f| f.descriptor.name == "next_hop_mtu")
            .unwrap();
        assert_eq!(mtu.value, FieldValue::U16(1500));
    }

    #[test]
    fn parse_dest_unreachable_with_rfc4884_length() {
        // RFC 4884 — Length field at offset 5 (non-zero → exposed).
        let mut data = vec![
            0x03, 0x01, 0x00, 0x00, // type=3, code=1, checksum
            0x00, 0x07, 0x00, 0x00, // unused, length=7 (28 bytes), unused
        ];
        // Append 28 bytes of invoking data (7 * 4)
        data.extend_from_slice(&[0u8; 28]);
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let len = fields
            .iter()
            .find(|f| f.descriptor.name == "length")
            .unwrap();
        assert_eq!(len.value, FieldValue::U8(7));
    }

    #[test]
    fn parse_redirect() {
        // RFC 792 Redirect — Type 5, Code 1, Gateway at offset 4–7.
        let data: &[u8] = &[
            0x05, 0x01, 0x00, 0x00, // type=5, code=1, checksum
            0xC0, 0xA8, 0x01, 0x01, // gateway=192.168.1.1
        ];
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let gw = fields
            .iter()
            .find(|f| f.descriptor.name == "gateway")
            .unwrap();
        assert_eq!(gw.value, FieldValue::Ipv4Addr([192, 168, 1, 1]));
    }

    #[test]
    fn parse_parameter_problem() {
        // RFC 792 — Type 12: Pointer at offset 4 (u8), RFC 4884 Length at offset 5.
        let data: &[u8] = &[
            0x0C, 0x00, 0x00, 0x00, // type=12, code=0, checksum
            0x08, 0x03, 0x00, 0x00, // pointer=8, length=3, unused
        ];
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let ptr = fields
            .iter()
            .find(|f| f.descriptor.name == "pointer")
            .unwrap();
        assert_eq!(ptr.value, FieldValue::U8(8));
        assert_eq!(ptr.descriptor.field_type, FieldType::U8);
        let len = fields
            .iter()
            .find(|f| f.descriptor.name == "length")
            .unwrap();
        assert_eq!(len.value, FieldValue::U8(3));
    }

    #[test]
    fn parse_timestamp_request() {
        // RFC 792 Timestamp Request — 20 bytes total.
        let data: &[u8] = &[
            0x0D, 0x00, 0x00, 0x00, // type=13, code=0, checksum
            0x00, 0x01, 0x00, 0x02, // id=1, seq=2
            0x00, 0x01, 0x51, 0x80, // originate=86400 (ms)
            0x00, 0x02, 0xA3, 0x00, // receive=172800
            0x00, 0x03, 0xF4, 0x80, // transmit=259200
        ];
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let orig = fields
            .iter()
            .find(|f| f.descriptor.name == "originate_timestamp")
            .unwrap();
        assert_eq!(orig.value, FieldValue::U32(86400));
        let recv = fields
            .iter()
            .find(|f| f.descriptor.name == "receive_timestamp")
            .unwrap();
        assert_eq!(recv.value, FieldValue::U32(172800));
        let xmit = fields
            .iter()
            .find(|f| f.descriptor.name == "transmit_timestamp")
            .unwrap();
        assert_eq!(xmit.value, FieldValue::U32(259200));
    }

    #[test]
    fn parse_timestamp_truncated() {
        // Timestamp requires 20 bytes; supply only 16.
        let data: &[u8] = &[
            0x0D, 0x00, 0x00, 0x00, // type=13
            0x00, 0x01, 0x00, 0x02, // id, seq
            0x00, 0x00, 0x00, 0x00, // originate
            0x00, 0x00, 0x00, 0x00, // receive (no transmit)
        ];
        let mut buf = DissectBuffer::new();
        let err = IcmpDissector.dissect(data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PacketError::Truncated {
                    expected: 20,
                    actual: 16
                }
            ),
            "expected Truncated(20,16), got {err:?}"
        );
    }

    #[test]
    fn parse_address_mask_reply() {
        // RFC 950 — Type 18, Address Mask Reply.
        let data: &[u8] = &[
            0x12, 0x00, 0x00, 0x00, // type=18, code=0, checksum
            0x00, 0x0A, 0x00, 0x05, // id=10, seq=5
            0xFF, 0xFF, 0xFF, 0x00, // mask=255.255.255.0
        ];
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let mask = fields
            .iter()
            .find(|f| f.descriptor.name == "address_mask")
            .unwrap();
        assert_eq!(mask.value, FieldValue::Ipv4Addr([255, 255, 255, 0]));
    }

    // ---- Bug-regression tests (previously incorrect behavior) ----

    #[test]
    fn parse_router_advertisement_signed_preference() {
        // RFC 1256, Section 3.1 — Preference Level is signed twos-complement.
        // Positive preference 0x00000064 = 100.
        let data: &[u8] = &[
            0x09, 0x00, 0x00, 0x00, // type=9, code=0, checksum
            0x01, 0x02, 0x00, 0x1E, // num_addrs=1, addr_entry_size=2, lifetime=30
            0xC0, 0xA8, 0x01, 0x01, // router_address=192.168.1.1
            0x00, 0x00, 0x00, 0x64, // preference_level=+100
        ];
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let entries = fields
            .iter()
            .find(|f| f.descriptor.name == "entries")
            .unwrap();
        let range = match &entries.value {
            FieldValue::Array(r) => r.clone(),
            other => panic!("expected Array, got {other:?}"),
        };
        let items = buf.nested_fields(&range);
        let obj = items.iter().find(|f| f.value.is_object()).unwrap();
        let obj_range = match &obj.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let children = buf.nested_fields(&obj_range);
        let pref = children
            .iter()
            .find(|f| f.descriptor.name == "preference_level")
            .unwrap();
        // Must be I32, not U32
        assert_eq!(pref.descriptor.field_type, FieldType::I32);
        assert_eq!(pref.value, FieldValue::I32(100));
    }

    #[test]
    fn parse_router_advertisement_do_not_use() {
        // RFC 1256 — 0x80000000 (i32::MIN) signals "do not use as default router".
        let data: &[u8] = &[
            0x09, 0x00, 0x00, 0x00, // type=9, code=0, checksum
            0x01, 0x02, 0x00, 0x1E, // num_addrs=1, addr_entry_size=2, lifetime=30
            0x0A, 0x00, 0x00, 0x01, // router_address=10.0.0.1
            0x80, 0x00, 0x00, 0x00, // preference_level=0x80000000 = i32::MIN
        ];
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let entries = fields
            .iter()
            .find(|f| f.descriptor.name == "entries")
            .unwrap();
        let range = match &entries.value {
            FieldValue::Array(r) => r.clone(),
            other => panic!("expected Array, got {other:?}"),
        };
        let items = buf.nested_fields(&range);
        let obj = items.iter().find(|f| f.value.is_object()).unwrap();
        let obj_range = match &obj.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let children = buf.nested_fields(&obj_range);
        let pref = children
            .iter()
            .find(|f| f.descriptor.name == "preference_level")
            .unwrap();
        assert_eq!(pref.value, FieldValue::I32(i32::MIN));
    }

    #[test]
    fn parse_photuris() {
        // RFC 2521, Section 2 — Type 40: Reserved (u16 at 4–5), Pointer (u16 at 6–7).
        let data: &[u8] = &[
            0x28, 0x01, 0x00, 0x00, // type=40, code=1 (Auth Failed), checksum
            0x00, 0x00, 0x00, 0x14, // reserved=0, pointer=20
        ];
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);

        // Verify Reserved field is U16
        let reserved = fields
            .iter()
            .find(|f| f.descriptor.name == "photuris_reserved")
            .unwrap();
        assert_eq!(reserved.value, FieldValue::U16(0));
        assert_eq!(reserved.descriptor.field_type, FieldType::U16);

        // Verify Pointer field is U16 (not U8 as it was before the fix)
        let ptr = fields
            .iter()
            .find(|f| f.descriptor.name == "photuris_pointer")
            .unwrap();
        assert_eq!(ptr.value, FieldValue::U16(20));
        assert_eq!(ptr.descriptor.field_type, FieldType::U16);
    }

    // ---- RFC 8335 Extended Echo ----

    #[test]
    fn parse_extended_echo_request() {
        // RFC 8335, Section 2 — Type 42, Seq=u8 at offset 6, L-bit at offset 7 bit 0.
        let data: &[u8] = &[
            0x2A, 0x00, 0x00, 0x00, // type=42, code=0, checksum
            0xAB, 0xCD, 0x07, 0x01, // id=0xABCD, seq=7, Reserved|L=1 (L-bit set)
        ];
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let id = fields
            .iter()
            .find(|f| f.descriptor.name == "identifier")
            .unwrap();
        assert_eq!(id.value, FieldValue::U16(0xABCD));
        let seq = fields
            .iter()
            .find(|f| f.descriptor.name == "sequence_number")
            .unwrap();
        // Sequence Number is 1 byte (value=7) promoted to U16.
        assert_eq!(seq.value, FieldValue::U16(7));
        let local = fields
            .iter()
            .find(|f| f.descriptor.name == "local")
            .unwrap();
        assert_eq!(local.value, FieldValue::U8(1)); // L-bit set
    }

    #[test]
    fn parse_extended_echo_reply() {
        // RFC 8335, Section 3 — Type 43, flags in offset 7:
        // State(3 bits)=2 (Reachable), Res(2)=0, A(1)=1, 4(1)=1, 6(1)=0
        // Byte 7 = 0b010_00_1_1_0 = 0x46
        let data: &[u8] = &[
            0x2B, 0x00, 0x00, 0x00, // type=43, code=0, checksum
            0x00, 0x01, 0x03, 0x46, // id=1, seq=3, flags=0x46
        ];
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let state = fields
            .iter()
            .find(|f| f.descriptor.name == "state")
            .unwrap();
        assert_eq!(state.value, FieldValue::U8(2)); // Reachable
        let active = fields
            .iter()
            .find(|f| f.descriptor.name == "active")
            .unwrap();
        assert_eq!(active.value, FieldValue::U8(1));
        let ipv4 = fields.iter().find(|f| f.descriptor.name == "ipv4").unwrap();
        assert_eq!(ipv4.value, FieldValue::U8(1));
        let ipv6 = fields.iter().find(|f| f.descriptor.name == "ipv6").unwrap();
        assert_eq!(ipv6.value, FieldValue::U8(0));
    }

    // ---- RFC 4884 Extension Structure ----

    /// Build a Time Exceeded (type 11) packet with a padded-to-128 original
    /// datagram followed by the supplied extension structure bytes. The Length
    /// field (offset 5) is set to 32 (= 128 / 4 octets) to indicate extensions.
    fn build_time_exceeded_with_extensions(ext: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(HEADER_SIZE + 128 + ext.len());
        pkt.push(11); // type = Time Exceeded
        pkt.push(0); // code = TTL exceeded
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.push(0); // unused
        pkt.push(32); // RFC 4884 Length = 32 (32 * 4 = 128 bytes)
        pkt.extend_from_slice(&[0x00, 0x00]); // unused
        // 128 bytes of padded original datagram (zeros here)
        pkt.extend_from_slice(&[0u8; 128]);
        pkt.extend_from_slice(ext);
        pkt
    }

    /// Walk `layer.fields -> extensions -> objects` and return the list of
    /// direct Object container ranges (skipping past each object's descendants
    /// so that nested Objects inside Arrays — e.g. MPLS LSEs — are not
    /// mistaken for top-level extension objects).
    fn extension_object_ranges(
        buf: &DissectBuffer<'_>,
        layer_idx: usize,
    ) -> Vec<core::ops::Range<u32>> {
        let layer = &buf.layers()[layer_idx];
        let fields = buf.layer_fields(layer);
        let ext = fields
            .iter()
            .find(|f| f.descriptor.name == "extensions")
            .expect("extensions field present");
        let ext_range = match &ext.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let ext_children = buf.nested_fields(&ext_range);
        let objects = ext_children
            .iter()
            .find(|f| f.descriptor.name == "objects")
            .expect("objects array");
        let objects_range = match &objects.value {
            FieldValue::Array(r) => r.clone(),
            other => panic!("expected Array, got {other:?}"),
        };
        let items = buf.nested_fields(&objects_range);
        let mut result = Vec::new();
        let mut i = 0;
        while i < items.len() {
            let f = &items[i];
            match &f.value {
                FieldValue::Object(r) => {
                    let descendants = (r.end - r.start) as usize;
                    result.push(r.clone());
                    i += 1 + descendants;
                }
                FieldValue::Array(r) => {
                    let descendants = (r.end - r.start) as usize;
                    i += 1 + descendants;
                }
                _ => i += 1,
            }
        }
        result
    }

    #[test]
    fn parse_extension_header_fields() {
        // RFC 4884 §7 — Extension Header: Version (high nibble) + Reserved (12 bits) + Checksum.
        // Build one object (class=99/unknown/1 byte payload) to verify the header is parsed.
        let ext = [
            0x20, 0x00, 0x12, 0x34, // version=2, reserved=0, checksum=0x1234
            0x00, 0x05, 0x63, 0x01, // obj_len=5, class_num=99, c_type=1
            0xAA, 0x00, 0x00,
            0x00, // 1 payload byte + 3 bytes don't care (length=5 stops here)
        ];
        let pkt = build_time_exceeded_with_extensions(&ext[..9]); // exact 5-byte object
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let ext_field = fields
            .iter()
            .find(|f| f.descriptor.name == "extensions")
            .unwrap();
        let ext_range = match &ext_field.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let children = buf.nested_fields(&ext_range);
        let version = children
            .iter()
            .find(|f| f.descriptor.name == "version")
            .unwrap();
        assert_eq!(version.value, FieldValue::U8(2));
        let reserved = children
            .iter()
            .find(|f| f.descriptor.name == "reserved")
            .unwrap();
        assert_eq!(reserved.value, FieldValue::U16(0));
        let checksum = children
            .iter()
            .find(|f| f.descriptor.name == "checksum")
            .unwrap();
        assert_eq!(checksum.value, FieldValue::U16(0x1234));
    }

    #[test]
    fn parse_extensions_not_parsed_when_length_zero() {
        // RFC 4884 §4.5 — With Length=0, the trailing bytes are NOT an Extension
        // Structure. push_extensions must not run.
        let mut pkt = vec![
            11, 0, 0, 0, // type=11, code=0, checksum
            0, 0, 0, 0, // unused + length=0 + unused
        ];
        // 128 bytes that COULD be mistaken for a bogus Extension Structure.
        pkt.extend_from_slice(&[0u8; 128]);
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        assert!(
            fields.iter().all(|f| f.descriptor.name != "extensions"),
            "extensions must not be present when RFC 4884 Length is 0"
        );
    }

    #[test]
    fn parse_extension_mpls_label_stack_class1() {
        // RFC 4950 — Class-Num=1, C-Type=1, two label stack entries.
        // LSE1: Label=0x12345, TC=5, S=0, TTL=64
        //   Bytes: 0x12, 0x34, 0x5A, 0x40 (label[19:0]=0x12345, TC=0b101=5, S=0, TTL=64)
        // LSE2: Label=0x00010, TC=0, S=1, TTL=32
        //   Bytes: 0x00, 0x01, 0x01, 0x20 (label=0x10, TC=0, S=1, TTL=32)
        let ext = [
            0x20, 0x00, 0x00, 0x00, // version=2, reserved=0, checksum=0
            0x00, 0x0C, 0x01, 0x01, // obj_len=12, class=1 (MPLS), c_type=1
            0x12, 0x34, 0x5A, 0x40, // LSE1
            0x00, 0x01, 0x01, 0x20, // LSE2
        ];
        let pkt = build_time_exceeded_with_extensions(&ext);
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let objs = extension_object_ranges(&buf, 0);
        assert_eq!(objs.len(), 1, "one MPLS object");
        let obj_children = buf.nested_fields(&objs[0]);
        let class_num = obj_children
            .iter()
            .find(|f| f.descriptor.name == "class_num")
            .unwrap();
        assert_eq!(class_num.value, FieldValue::U8(1));
        let mpls_labels = obj_children
            .iter()
            .find(|f| f.descriptor.name == "mpls_labels")
            .unwrap();
        let mpls_range = match &mpls_labels.value {
            FieldValue::Array(r) => r.clone(),
            other => panic!("expected Array, got {other:?}"),
        };
        let entries: Vec<_> = buf
            .nested_fields(&mpls_range)
            .iter()
            .filter_map(|f| match &f.value {
                FieldValue::Object(r) => Some(r.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(entries.len(), 2);

        // LSE1
        let lse1 = buf.nested_fields(&entries[0]);
        let l1 = lse1.iter().find(|f| f.descriptor.name == "label").unwrap();
        assert_eq!(l1.value, FieldValue::U32(0x12345));
        let tc1 = lse1.iter().find(|f| f.descriptor.name == "tc").unwrap();
        assert_eq!(tc1.value, FieldValue::U8(5));
        let s1 = lse1.iter().find(|f| f.descriptor.name == "s").unwrap();
        assert_eq!(s1.value, FieldValue::U8(0));
        let ttl1 = lse1.iter().find(|f| f.descriptor.name == "ttl").unwrap();
        assert_eq!(ttl1.value, FieldValue::U8(64));

        // LSE2 (bottom of stack)
        let lse2 = buf.nested_fields(&entries[1]);
        let l2 = lse2.iter().find(|f| f.descriptor.name == "label").unwrap();
        assert_eq!(l2.value, FieldValue::U32(0x00010));
        let s2 = lse2.iter().find(|f| f.descriptor.name == "s").unwrap();
        assert_eq!(s2.value, FieldValue::U8(1));
        let ttl2 = lse2.iter().find(|f| f.descriptor.name == "ttl").unwrap();
        assert_eq!(ttl2.value, FieldValue::U8(32));
    }

    #[test]
    fn parse_extension_interface_info_class2_all_sub_objects() {
        // RFC 5837 — Class-Num=2, C-Type encodes:
        //   Role=2 (Outgoing IP Interface) -> bits 0-1 = 10 -> 0x80
        //   ifIndex=1, IPAddr=1, Name=1, MTU=1 -> 0x0F
        //   C-Type = 0x8F = 0b10_00_1_1_1_1
        // Sub-objects in order: ifIndex(4) + IP Address(8, IPv4) + Name(8) + MTU(4) = 24 bytes
        // Object length = 4 (header) + 24 = 28
        let ext = [
            0x20, 0x00, 0x00, 0x00, // ext header
            0x00, 0x1C, 0x02, 0x8F, // obj_len=28, class=2, c_type=0x8F (Role=2, all bits set)
            0x00, 0x00, 0x00, 0x07, // ifIndex=7
            0x00, 0x01, 0x00, 0x00, // AFI=1 (IPv4), Reserved=0
            0xC0, 0xA8, 0x00, 0x01, // Address=192.168.0.1
            0x08, b'e', b't', b'h', // Name Length=8, "eth"
            b'0', 0x00, 0x00, 0x00, // "0" + NUL padding (total 8 bytes)
            0x00, 0x00, 0x05, 0xDC, // MTU=1500
        ];
        let pkt = build_time_exceeded_with_extensions(&ext);
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let objs = extension_object_ranges(&buf, 0);
        assert_eq!(objs.len(), 1);
        let obj = buf.nested_fields(&objs[0]);

        let role = obj
            .iter()
            .find(|f| f.descriptor.name == "interface_role")
            .unwrap();
        assert_eq!(role.value, FieldValue::U8(2));

        let ifi = obj
            .iter()
            .find(|f| f.descriptor.name == "if_index")
            .unwrap();
        assert_eq!(ifi.value, FieldValue::U32(7));

        let afi = obj.iter().find(|f| f.descriptor.name == "afi").unwrap();
        assert_eq!(afi.value, FieldValue::U16(1));

        let ip = obj
            .iter()
            .find(|f| f.descriptor.name == "ipv4_address")
            .unwrap();
        assert_eq!(ip.value, FieldValue::Ipv4Addr([192, 168, 0, 1]));

        let name = obj
            .iter()
            .find(|f| f.descriptor.name == "interface_name")
            .unwrap();
        // The name bytes exclude the leading Length octet; trailing NULs remain.
        assert_eq!(name.value, FieldValue::Bytes(b"eth0\x00\x00\x00"));

        let mtu = obj.iter().find(|f| f.descriptor.name == "mtu").unwrap();
        assert_eq!(mtu.value, FieldValue::U32(1500));
    }

    #[test]
    fn parse_extension_interface_info_class2_ipv6_address() {
        // RFC 5837 — Class 2, Role=0 (Incoming IP), IPAddr bit only (C-Type=0x04).
        // IP Address Sub-Object: AFI=2 (IPv6) + Reserved + 16-byte address = 20 bytes.
        // Object length = 4 + 20 = 24.
        let ext = [
            0x20, 0x00, 0x00, 0x00, // ext header
            0x00, 0x18, 0x02, 0x04, // obj_len=24, class=2, c_type=0x04 (Role=0, IPAddr only)
            0x00, 0x02, 0x00, 0x00, // AFI=2 (IPv6), Reserved=0
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // 2001:db8::...
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // ...::1
        ];
        let pkt = build_time_exceeded_with_extensions(&ext);
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let objs = extension_object_ranges(&buf, 0);
        let obj = buf.nested_fields(&objs[0]);
        let role = obj
            .iter()
            .find(|f| f.descriptor.name == "interface_role")
            .unwrap();
        assert_eq!(role.value, FieldValue::U8(0));
        let ipv6 = obj
            .iter()
            .find(|f| f.descriptor.name == "ipv6_address")
            .unwrap();
        let mut expected = [0u8; 16];
        expected[0] = 0x20;
        expected[1] = 0x01;
        expected[2] = 0x0d;
        expected[3] = 0xb8;
        expected[15] = 0x01;
        assert_eq!(ipv6.value, FieldValue::Ipv6Addr(expected));
    }

    #[test]
    fn parse_extension_interface_id_class3_by_index() {
        // RFC 8335 §2.1 — Class-Num=3, C-Type=2 (by index): 4-byte ifIndex.
        let ext = [
            0x20, 0x00, 0x00, 0x00, // ext header
            0x00, 0x08, 0x03, 0x02, // obj_len=8, class=3, c_type=2
            0x00, 0x00, 0x00, 0x2A, // ifIndex=42
        ];
        let pkt = build_time_exceeded_with_extensions(&ext);
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let objs = extension_object_ranges(&buf, 0);
        let obj = buf.nested_fields(&objs[0]);
        let ifi = obj
            .iter()
            .find(|f| f.descriptor.name == "if_index")
            .unwrap();
        assert_eq!(ifi.value, FieldValue::U32(42));
    }

    #[test]
    fn parse_extension_interface_id_class3_by_name() {
        // RFC 8335 §2.1 — Class-Num=3, C-Type=1: body is raw name, NUL-padded.
        let ext = [
            0x20, 0x00, 0x00, 0x00, // ext header
            0x00, 0x0C, 0x03, 0x01, // obj_len=12, class=3, c_type=1
            b'e', b'n', b'0', 0x00, // "en0" + NUL padding
            0x00, 0x00, 0x00, 0x00, // more NUL padding (to 8-byte payload)
        ];
        let pkt = build_time_exceeded_with_extensions(&ext);
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let objs = extension_object_ranges(&buf, 0);
        let obj = buf.nested_fields(&objs[0]);
        let name = obj
            .iter()
            .find(|f| f.descriptor.name == "interface_name")
            .unwrap();
        assert_eq!(name.value, FieldValue::Bytes(b"en0\x00\x00\x00\x00\x00"));
    }

    #[test]
    fn parse_extension_interface_id_class3_by_address_ipv4() {
        // RFC 8335 §2.1 — Class-Num=3, C-Type=3: AFI(u16) + AddrLen(u8) + Reserved(u8) + Address.
        let ext = [
            0x20, 0x00, 0x00, 0x00, // ext header
            0x00, 0x0C, 0x03, 0x03, // obj_len=12, class=3, c_type=3
            0x00, 0x01, 0x04, 0x00, // AFI=1 (IPv4), AddrLen=4, Reserved=0
            0x0A, 0x00, 0x00, 0x01, // 10.0.0.1
        ];
        let pkt = build_time_exceeded_with_extensions(&ext);
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let objs = extension_object_ranges(&buf, 0);
        let obj = buf.nested_fields(&objs[0]);
        let afi = obj.iter().find(|f| f.descriptor.name == "afi").unwrap();
        assert_eq!(afi.value, FieldValue::U16(1));
        let alen = obj
            .iter()
            .find(|f| f.descriptor.name == "address_length")
            .unwrap();
        assert_eq!(alen.value, FieldValue::U8(4));
        let ip = obj
            .iter()
            .find(|f| f.descriptor.name == "ipv4_address")
            .unwrap();
        assert_eq!(ip.value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
    }

    #[test]
    fn parse_extension_interface_id_class3_by_address_ipv6() {
        // RFC 8335 §2.1 — Class-Num=3, C-Type=3, AFI=2, IPv6 address.
        // Object length = 4 (header) + 4 (AFI/AddrLen/Reserved) + 16 (address) = 24
        let ext = [
            0x20, 0x00, 0x00, 0x00, // ext header
            0x00, 0x18, 0x03, 0x03, // obj_len=24, class=3, c_type=3
            0x00, 0x02, 0x10, 0x00, // AFI=2 (IPv6), AddrLen=16, Reserved=0
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fe80::...
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // ...::5
        ];
        let pkt = build_time_exceeded_with_extensions(&ext);
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let objs = extension_object_ranges(&buf, 0);
        let obj = buf.nested_fields(&objs[0]);
        let ipv6 = obj
            .iter()
            .find(|f| f.descriptor.name == "ipv6_address")
            .unwrap();
        let mut expected = [0u8; 16];
        expected[0] = 0xfe;
        expected[1] = 0x80;
        expected[15] = 0x05;
        assert_eq!(ipv6.value, FieldValue::Ipv6Addr(expected));
    }

    #[test]
    fn parse_extension_unknown_class_preserves_payload() {
        // Unknown class-num — raw payload bytes must be captured under the
        // object's `payload` child.
        let ext = [
            0x20, 0x00, 0x00, 0x00, // ext header
            0x00, 0x08, 0x7F, 0x05, // obj_len=8, class=127 (unknown), c_type=5
            0xDE, 0xAD, 0xBE, 0xEF, // payload
        ];
        let pkt = build_time_exceeded_with_extensions(&ext);
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let objs = extension_object_ranges(&buf, 0);
        let obj = buf.nested_fields(&objs[0]);
        let payload = obj.iter().find(|f| f.descriptor.name == "payload").unwrap();
        assert_eq!(payload.value, FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn parse_extension_malformed_object_length_stops_parsing() {
        // Postel's Law — an object with length < 4 must stop the loop without
        // panicking, and must not emit a malformed object child.
        let ext = [
            0x20, 0x00, 0x00, 0x00, // ext header
            0x00, 0x03, 0x01, 0x01, // obj_len=3 (< 4) -> malformed
            0xAA, 0xBB, 0xCC, 0xDD, // tail (ignored)
        ];
        let pkt = build_time_exceeded_with_extensions(&ext);
        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        // The extensions object is present (header parsed) but the objects
        // array should be empty.
        let objs = extension_object_ranges(&buf, 0);
        assert!(
            objs.is_empty(),
            "malformed object length must not yield objects"
        );
    }

    #[test]
    fn parse_extended_echo_request_with_interface_id_extension() {
        // RFC 8335 §2 — Body of Type 42 is itself an Extension Structure
        // carrying the Interface Identification Object (Class-Num 3).
        let mut pkt = vec![
            42, 0, 0x00, 0x00, // type=42, code=0, checksum
            0x00, 0x01, 0x01, 0x01, // identifier=1, seq=1, L-bit set
        ];
        let ext = [
            0x20, 0x00, 0x00, 0x00, // ext header
            0x00, 0x08, 0x03, 0x02, // obj_len=8, class=3, c_type=2 (ByIndex)
            0x00, 0x00, 0x00, 0x03, // ifIndex=3
        ];
        pkt.extend_from_slice(&ext);

        let mut buf = DissectBuffer::new();
        IcmpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let objs = extension_object_ranges(&buf, 0);
        assert_eq!(objs.len(), 1);
        let obj = buf.nested_fields(&objs[0]);
        let ifi = obj
            .iter()
            .find(|f| f.descriptor.name == "if_index")
            .unwrap();
        assert_eq!(ifi.value, FieldValue::U32(3));
    }

    #[test]
    fn rfc4884_extension_offset_padding_semantics() {
        // Length=32 means 128 octets (already padded); ext starts at 8+128=136.
        assert_eq!(rfc4884_extension_offset(200, 32), Some(HEADER_SIZE + 128));
        // Length=10 means 40 octets; MUST be padded to 128 before extensions.
        assert_eq!(rfc4884_extension_offset(200, 10), Some(HEADER_SIZE + 128));
        // Length=40 means 160 octets; no padding because already >= 128.
        assert_eq!(rfc4884_extension_offset(300, 40), Some(HEADER_SIZE + 160));
        // Length=0 -> no extensions parsed.
        assert_eq!(rfc4884_extension_offset(200, 0), None);
        // Not enough trailing bytes for even an Extension Header -> None.
        assert_eq!(rfc4884_extension_offset(100, 32), None);
    }
}
