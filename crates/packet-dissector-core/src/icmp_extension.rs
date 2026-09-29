//! ICMP Extension Structure (RFC 4884) shared by the ICMP and ICMPv6
//! dissectors.
//!
//! ## References
//! - RFC 4884 (Extended ICMP to Support Multi-Part Messages): <https://www.rfc-editor.org/rfc/rfc4884>
//! - RFC 4950 (MPLS Label Stack Object, Class-Num 1): <https://www.rfc-editor.org/rfc/rfc4950>
//! - RFC 5837 (Interface Information Object, Class-Num 2): <https://www.rfc-editor.org/rfc/rfc5837>
//! - RFC 8335 (Interface Identification Object, Class-Num 3): <https://www.rfc-editor.org/rfc/rfc8335>

use crate::field::{FieldDescriptor, FieldType, FieldValue};
use crate::packet::DissectBuffer;
use crate::util::{read_be_u16, read_be_u32};

/// ICMP Extension Header size (RFC 4884, Section 7).
/// <https://www.rfc-editor.org/rfc/rfc4884#section-7>
const EXTENSION_HEADER_SIZE: usize = 4;
// Minimum ICMP Extension Object header size per RFC 4884, Section 7.
// <https://www.rfc-editor.org/rfc/rfc4884#section-7>
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

/// RFC 4950, Section 3 — MPLS Label Stack Entry (4 octets).
/// <https://www.rfc-editor.org/rfc/rfc4950#section-3>
static MPLS_LABEL_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("label", "Label", FieldType::U32),
    FieldDescriptor::new("tc", "Traffic Class", FieldType::U8),
    FieldDescriptor::new("s", "Bottom of Stack", FieldType::U8),
    FieldDescriptor::new("ttl", "Time to Live", FieldType::U8),
];

/// RFC 4884, Section 7.1 — ICMP Extension Object Header, plus per-class payload
/// fields parsed out by [`push_extension_structure`] (RFC 4950 Class 1, RFC 5837
/// Class 2, RFC 8335 Section 2.1 Class 3). Only the first three entries are
/// always present; the remainder are conditional on class/c_type.
/// <https://www.rfc-editor.org/rfc/rfc4884#section-7.1>
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

/// RFC 4884, Section 7 — ICMP Extension Header fields. Use as the children of
/// the container descriptor passed to [`push_extension_structure`].
/// <https://www.rfc-editor.org/rfc/rfc4884#section-7>
pub static EXTENSION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U16),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    FieldDescriptor::new("objects", "Objects", FieldType::Array)
        .with_children(EXTENSION_OBJECT_CHILDREN),
];

/// Parse an ICMP Extension Structure (RFC 4884, Section 7) starting at `data[0..]`.
///
/// The caller is responsible for locating the start of the Extension Structure
/// (after the padded original datagram for Types 3/11/12, or immediately after
/// the 8-byte header for Extended Echo Request per RFC 8335, Section 2).
///
/// Silently stops on malformed input (length fields out of range, truncated
/// objects) per Postel's Law — the ICMP message itself remains valid.
///
/// `container` is the caller's `Object` descriptor for the structure; its
/// children should be [`EXTENSION_CHILDREN`]. The same structure is used by
/// ICMPv4 and ICMPv6 (RFC 4884, Section 7).
///
/// RFC 4884, Section 7 — <https://www.rfc-editor.org/rfc/rfc4884#section-7>
pub fn push_extension_structure<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    container: &'static FieldDescriptor,
    data: &'pkt [u8],
    offset: usize,
) {
    if data.len() < EXTENSION_HEADER_SIZE {
        return;
    }
    // RFC 4884, Section 7 — Version (4 bits) + Reserved (12 bits) + Checksum (16 bits).
    // <https://www.rfc-editor.org/rfc/rfc4884#section-7>
    let version = data[0] >> 4;
    let reserved = (u16::from(data[0] & 0x0F) << 8) | u16::from(data[1]);
    let checksum = read_be_u16(data, 2).unwrap_or_default();

    let ext_idx = buf.begin_container(
        container,
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
        offset + EXTENSION_HEADER_SIZE..offset + data.len(),
    );
    let mut pos = EXTENSION_HEADER_SIZE;
    while pos + EXT_OBJECT_HEADER_SIZE <= data.len() {
        // RFC 4884, Section 7.1 — Object header: Length(u16) + Class-Num(u8) + C-Type(u8).
        // <https://www.rfc-editor.org/rfc/rfc4884#section-7.1>
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
    // <https://www.rfc-editor.org/rfc/rfc5837#section-4.1>
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
        // <https://www.rfc-editor.org/rfc/rfc5837#section-4.2>
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
        // <https://www.rfc-editor.org/rfc/rfc5837#section-4.5>
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
        // <https://www.rfc-editor.org/rfc/rfc5837#section-4.6>
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
        1 if !body.is_empty() => {
            buf.push_field(
                &EXTENSION_OBJECT_CHILDREN[EOBJ_INTERFACE_NAME],
                FieldValue::Bytes(body),
                body_offset..body_offset + body.len(),
            );
        }
        2 if body.len() >= 4 => {
            let ifindex = read_be_u32(body, 0).unwrap_or_default();
            buf.push_field(
                &EXTENSION_OBJECT_CHILDREN[EOBJ_IF_INDEX],
                FieldValue::U32(ifindex),
                body_offset..body_offset + 4,
            );
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

/// Compute where the Extension Structure starts in an ICMP error message.
///
/// `header_len` is the ICMP header length (8 for ICMPv4 and ICMPv6),
/// `original_datagram_len` the "original datagram" length in octets given by
/// the Length attribute (32-bit words for ICMPv4, 64-bit words for ICMPv6)
/// and `data_len` the length of the whole ICMP message. Returns `None` when
/// the Length attribute is zero ("the compliant application MUST determine
/// that the message contains no extensions", RFC 4884, Section 5.5) or when
/// no Extension Header fits in the message.
///
/// RFC 4884, Section 4 — the "original datagram" field "MUST contain at least
/// 128 octets", so a shorter Length is treated as 128 octets.
/// <https://www.rfc-editor.org/rfc/rfc4884#section-4>
pub fn extension_structure_start(
    header_len: usize,
    original_datagram_len: usize,
    data_len: usize,
) -> Option<usize> {
    if original_datagram_len == 0 {
        return None;
    }
    let padded = original_datagram_len.max(EXT_COMPAT_MIN_ORIG_DATAGRAM);
    let ext_start = header_len + padded;
    if ext_start + EXTENSION_HEADER_SIZE <= data_len {
        Some(ext_start)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 4884 / RFC 5837 / RFC 8335 extension object edge cases
    //!
    //! | RFC Section    | Description                               | Test                                   |
    //! |----------------|-------------------------------------------|----------------------------------------|
    //! | 4884 §4        | Extension start with 128-octet padding    | extension_structure_start_padding      |
    //! | 4884 §7        | Structure shorter than the header         | structure_shorter_than_header_is_skipped |
    //! | 5837 §4        | Truncated Interface Information sub-objects | interface_information_truncated_sub_objects |
    //! | 5837 §4.2      | Unknown AFI stops parsing                 | interface_information_unknown_afi      |
    //! | 8335 §2.1      | Interface Identification edge cases       | interface_identification_edge_cases    |

    use super::*;

    static FD_TEST_EXTENSIONS: FieldDescriptor =
        FieldDescriptor::new("extensions", "Extensions", FieldType::Object)
            .with_children(EXTENSION_CHILDREN);

    /// Parse one object (class, c-type, body) and return the names of the
    /// fields pushed inside it.
    fn object_fields(class_num: u8, c_type: u8, body: &[u8]) -> Vec<(&'static str, String)> {
        let mut data = vec![0x20, 0x00, 0x00, 0x00];
        let len = (4 + body.len()) as u16;
        data.extend_from_slice(&len.to_be_bytes());
        data.push(class_num);
        data.push(c_type);
        data.extend_from_slice(body);
        let mut buf = DissectBuffer::new();
        push_extension_structure(&mut buf, &FD_TEST_EXTENSIONS, &data, 0);
        buf.fields()
            .iter()
            .skip(5) // container, version, reserved, checksum, objects
            .filter(|f| !matches!(f.name(), "length" | "class_num" | "c_type"))
            .filter(|f| !matches!(f.value, FieldValue::Object(_)))
            .map(|f| (f.name(), format!("{:?}", f.value)))
            .collect()
    }

    fn names(fields: &[(&'static str, String)]) -> Vec<&'static str> {
        fields.iter().map(|(n, _)| *n).collect()
    }

    #[test]
    fn structure_shorter_than_header_is_skipped() {
        let mut buf = DissectBuffer::new();
        push_extension_structure(&mut buf, &FD_TEST_EXTENSIONS, &[0x20, 0x00], 0);
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn interface_information_truncated_sub_objects() {
        // RFC 5837, Section 4 — C-Type flags: ifIndex 0x08, IP Address 0x04,
        // Name 0x02, MTU 0x01. Each truncated sub-object ends parsing.
        assert_eq!(names(&object_fields(2, 0x08, &[])), ["interface_role"]);
        assert_eq!(
            names(&object_fields(2, 0x0C, &[0, 0, 0, 1])),
            ["interface_role", "if_index"]
        );
        assert_eq!(
            names(&object_fields(2, 0x04, &[0, 1, 0, 0])),
            ["interface_role", "afi"]
        );
        assert_eq!(
            names(&object_fields(2, 0x04, &[0, 2, 0, 0, 0, 0, 0, 0])),
            ["interface_role", "afi"]
        );
        assert_eq!(names(&object_fields(2, 0x02, &[])), ["interface_role"]);
        assert_eq!(
            names(&object_fields(2, 0x02, &[1, 0, 0, 0])),
            ["interface_role"]
        );
        assert_eq!(names(&object_fields(2, 0x01, &[])), ["interface_role"]);
    }

    #[test]
    fn interface_information_unknown_afi() {
        // RFC 5837, Section 4.2 — AFI values other than IPv4 (1) and IPv6
        // (2) have no known address length, so parsing stops.
        assert_eq!(
            names(&object_fields(2, 0x05, &[0, 9, 0, 0, 0, 0, 0, 0])),
            ["interface_role", "afi"]
        );
    }

    #[test]
    fn interface_identification_edge_cases() {
        // RFC 8335, Section 2.1 — C-Type 3 needs AFI, Address Length and
        // Reserved; unknown AFIs and C-Types keep no address fields.
        assert!(object_fields(3, 3, &[0, 1]).is_empty());
        assert_eq!(
            names(&object_fields(3, 3, &[0, 4, 4, 0, 1, 2, 3, 4])),
            ["afi", "address_length"]
        );
        assert!(object_fields(3, 9, &[0, 0, 0, 0]).is_empty());
    }

    #[test]
    fn extension_structure_start_padding() {
        // RFC 4884, Section 4 — at least 128 octets of original datagram.
        // <https://www.rfc-editor.org/rfc/rfc4884#section-4>
        assert_eq!(extension_structure_start(8, 128, 200), Some(136));
        assert_eq!(extension_structure_start(8, 40, 200), Some(136));
        assert_eq!(extension_structure_start(8, 160, 300), Some(168));
        assert_eq!(extension_structure_start(8, 0, 200), None);
        assert_eq!(extension_structure_start(8, 128, 100), None);
    }
}
