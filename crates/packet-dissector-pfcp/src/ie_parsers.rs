//! Per-IE-type value parsers for PFCP Information Elements.
//!
//! 3GPP TS 29.244, Section 8.2.

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u32, read_be_u64, read_ipv4_addr, read_ipv6_addr};

static FD_INLINE_CAUSE_VALUE: FieldDescriptor = FieldDescriptor {
    name: "cause_value",
    display_name: "Cause Value",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(t) => cause_name(*t),
        _ => None,
    }),
    format_fn: None,
};

static FD_INLINE_NODE_ID_TYPE: FieldDescriptor =
    FieldDescriptor::new("node_id_type", "Node ID Type", FieldType::U8);

static FD_INLINE_NODE_ID_VALUE: FieldDescriptor =
    FieldDescriptor::new("node_id_value", "Node ID Value", FieldType::Ipv4Addr);

static FD_INLINE_RECOVERY_TIME_STAMP: FieldDescriptor =
    FieldDescriptor::new("recovery_time_stamp", "Recovery Time Stamp", FieldType::U32);

static FD_INLINE_NETWORK_INSTANCE: FieldDescriptor =
    FieldDescriptor::new("network_instance", "Network Instance", FieldType::Bytes);

// Shared field descriptors for F-SEID and F-TEID.

static FD_INLINE_V4: FieldDescriptor = FieldDescriptor::new("v4", "V4", FieldType::U8);

static FD_INLINE_V6: FieldDescriptor = FieldDescriptor::new("v6", "V6", FieldType::U8);

static FD_INLINE_IPV4_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv4_address", "IPv4 Address", FieldType::Ipv4Addr).optional();

static FD_INLINE_IPV6_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv6_address", "IPv6 Address", FieldType::Ipv6Addr).optional();

// F-SEID specific field descriptors.

static FD_INLINE_SEID: FieldDescriptor = FieldDescriptor::new("seid", "SEID", FieldType::U64);

// F-TEID specific field descriptors.

static FD_INLINE_CH: FieldDescriptor = FieldDescriptor::new("ch", "CH (CHOOSE)", FieldType::U8);

static FD_INLINE_CHID: FieldDescriptor = FieldDescriptor::new("chid", "CHID", FieldType::U8);

static FD_INLINE_TEID: FieldDescriptor =
    FieldDescriptor::new("teid", "TEID", FieldType::U32).optional();

static FD_INLINE_CHOOSE_ID: FieldDescriptor =
    FieldDescriptor::new("choose_id", "CHOOSE ID", FieldType::U8).optional();

/// Parse the value portion of a PFCP IE into a structured [`FieldValue`],
/// pushing fields directly into `buf` for Object and grouped IE values.
///
/// Falls back to raw [`FieldValue::Bytes`] for unrecognised or variable-length IE types.
/// `depth` tracks grouped IE recursion depth; see [`crate::ie::MAX_GROUPED_DEPTH`].
///
/// For Object values (cause, node_id, etc.), this pushes an Object container
/// with child fields into `buf` and returns the Object `FieldValue`.
/// For grouped IEs, it pushes an Array container and returns a sentinel
/// `FieldValue::Array(0..0)`.
///
/// 3GPP TS 29.244, Section 8.2.
pub fn parse_ie_value<'pkt>(
    ie_type: u16,
    data: &'pkt [u8],
    offset: usize,
    depth: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    match ie_type {
        // 3GPP TS 29.244, Section 8.2.1 — Cause
        19 if !data.is_empty() => {
            let obj_idx = buf.begin_container(
                &crate::ie::IE_CHILD_FIELDS[2],
                FieldValue::Object(0..0),
                offset..offset + data.len(),
            );
            buf.push_field(
                &FD_INLINE_CAUSE_VALUE,
                FieldValue::U8(data[0]),
                offset..offset + 1,
            );
            buf.end_container(obj_idx);
            FieldValue::Object(0..0) // sentinel, actual value pushed above
        }
        // 3GPP TS 29.244, Section 8.2.3 — F-TEID
        21 if !data.is_empty() => parse_f_teid(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.4 — Network Instance
        22 if !data.is_empty() => {
            let obj_idx = buf.begin_container(
                &crate::ie::IE_CHILD_FIELDS[2],
                FieldValue::Object(0..0),
                offset..offset + data.len(),
            );
            // Store raw bytes (zero-copy) instead of decoded String
            buf.push_field(
                &FD_INLINE_NETWORK_INSTANCE,
                FieldValue::Bytes(data),
                offset..offset + data.len(),
            );
            buf.end_container(obj_idx);
            FieldValue::Object(0..0)
        }
        // 3GPP TS 29.244, Section 8.2.37 — F-SEID
        57 if data.len() >= 9 => parse_f_seid(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.38 — Node ID
        60 if !data.is_empty() => parse_node_id(data, offset, buf),
        // 3GPP TS 29.244, Section 8.2.65 — Recovery Time Stamp
        96 if data.len() >= 4 => {
            let ts = read_be_u32(data, 0).unwrap_or_default();
            let obj_idx = buf.begin_container(
                &crate::ie::IE_CHILD_FIELDS[2],
                FieldValue::Object(0..0),
                offset..offset + 4,
            );
            buf.push_field(
                &FD_INLINE_RECOVERY_TIME_STAMP,
                FieldValue::U32(ts),
                offset..offset + 4,
            );
            buf.end_container(obj_idx);
            FieldValue::Object(0..0)
        }
        // Grouped IEs — 3GPP TS 29.244, Table 8.1.2-1.
        // These contain nested IE TLVs and are parsed recursively.
        1..=18
        | 51
        | 54
        | 58..=59
        | 68
        | 77..=80
        | 83
        | 85..=87
        | 99
        | 102
        | 105
        | 118
        | 127..=130
        | 132
        | 143
        | 147
        | 165..=169
        | 175..=176
        | 183
        | 187..=190
        | 195
        | 199..=201
        | 203
        | 205
        | 211..=214
        | 216
        | 218
        | 220..=221
        | 225..=227
        | 233
        | 238..=240
        | 242
        | 247
        | 252
        | 254..=256
        | 261
        | 263..=264
        | 267
        | 270..=272
        | 276..=277
        | 279
        | 290
        | 295
        | 300..=304
        | 310..=311
        | 315
        | 316
        | 323..=324
        | 331
        | 334
        | 340..=341
        | 355..=356
        | 361..=363
        | 378
        | 383
        | 386
        | 397
        | 399..=401 => parse_grouped_ie(data, offset, depth, buf),
        _ => FieldValue::Bytes(data),
    }
}

/// Parse a Grouped IE value as a sequence of nested IEs.
///
/// 3GPP TS 29.244, Section 8.1.1 — Grouped IEs contain nested IE TLVs.
/// Recursion is bounded by [`crate::ie::MAX_GROUPED_DEPTH`].
fn parse_grouped_ie<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    depth: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    if depth >= crate::ie::MAX_GROUPED_DEPTH {
        return FieldValue::Bytes(data);
    }
    let array_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    match crate::ie::parse_ies(data, offset, depth + 1, buf) {
        Ok(()) => {
            buf.end_container(array_idx);
            FieldValue::Array(0..0) // sentinel
        }
        Err(_) => {
            // Revert the placeholder
            buf.truncate_fields(array_idx as usize);
            FieldValue::Bytes(data)
        }
    }
}

/// Parse F-SEID IE value.
///
/// 3GPP TS 29.244, Section 8.2.37 — F-SEID:
/// - Octet 1: Spare(6 bits) | V4(bit 2) | V6(bit 1)
/// - Octets 2-9: SEID (64 bits)
/// - If V4=1: IPv4 address (4 bytes)
/// - If V6=1: IPv6 address (16 bytes)
fn parse_f_seid<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    // Caller guarantees data.len() >= 9 via match guard.
    let v4 = (data[0] >> 1) & 0x01;
    let v6 = data[0] & 0x01;
    let seid = read_be_u64(data, 1).unwrap_or_default();

    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );

    buf.push_field(&FD_INLINE_V4, FieldValue::U8(v4), offset..offset + 1);
    buf.push_field(&FD_INLINE_V6, FieldValue::U8(v6), offset..offset + 1);
    buf.push_field(
        &FD_INLINE_SEID,
        FieldValue::U64(seid),
        offset + 1..offset + 9,
    );

    let mut pos = 9usize;
    if v4 != 0 && pos + 4 <= data.len() {
        buf.push_field(
            &FD_INLINE_IPV4_ADDRESS,
            FieldValue::Ipv4Addr(read_ipv4_addr(data, pos).unwrap_or_default()),
            offset + pos..offset + pos + 4,
        );
        pos += 4;
    }
    if v6 != 0 && pos + 16 <= data.len() {
        let addr = read_ipv6_addr(data, pos).unwrap_or_default();
        buf.push_field(
            &FD_INLINE_IPV6_ADDRESS,
            FieldValue::Ipv6Addr(addr),
            offset + pos..offset + pos + 16,
        );
    }

    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse F-TEID IE value.
///
/// 3GPP TS 29.244, Section 8.2.3 — F-TEID:
/// - Octet 1: Spare(4 bits) | CHID(bit 4) | CH(bit 3) | V6(bit 2) | V4(bit 1)
/// - If CH=0: Octets 2-5: TEID (32 bits), then optional IPv4/IPv6
/// - If CHID=1: CHOOSE ID (1 byte)
fn parse_f_teid<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    // Caller guarantees !data.is_empty() via match guard.
    let v4 = data[0] & 0x01;
    let v6 = (data[0] >> 1) & 0x01;
    let ch = (data[0] >> 2) & 0x01;
    let chid = (data[0] >> 3) & 0x01;

    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );

    buf.push_field(&FD_INLINE_V4, FieldValue::U8(v4), offset..offset + 1);
    buf.push_field(&FD_INLINE_V6, FieldValue::U8(v6), offset..offset + 1);
    buf.push_field(&FD_INLINE_CH, FieldValue::U8(ch), offset..offset + 1);
    buf.push_field(&FD_INLINE_CHID, FieldValue::U8(chid), offset..offset + 1);

    if ch == 0 {
        // TEID present when CH=0
        if data.len() < 5 {
            buf.end_container(obj_idx);
            // Revert to bytes — remove the container
            buf.truncate_fields(obj_idx as usize);
            return FieldValue::Bytes(data);
        }
        let teid = read_be_u32(data, 1).unwrap_or_default();
        buf.push_field(
            &FD_INLINE_TEID,
            FieldValue::U32(teid),
            offset + 1..offset + 5,
        );
        let mut pos = 5usize;
        if v4 != 0 && pos + 4 <= data.len() {
            buf.push_field(
                &FD_INLINE_IPV4_ADDRESS,
                FieldValue::Ipv4Addr([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]),
                offset + pos..offset + pos + 4,
            );
            pos += 4;
        }
        if v6 != 0 && pos + 16 <= data.len() {
            let addr = read_ipv6_addr(data, pos).unwrap_or_default();
            buf.push_field(
                &FD_INLINE_IPV6_ADDRESS,
                FieldValue::Ipv6Addr(addr),
                offset + pos..offset + pos + 16,
            );
        }
    } else {
        // CH=1: CHOOSE mode — no TEID or addresses
        if chid != 0 && data.len() >= 2 {
            buf.push_field(
                &FD_INLINE_CHOOSE_ID,
                FieldValue::U8(data[1]),
                offset + 1..offset + 2,
            );
        }
    }

    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Parse Node ID IE value.
///
/// 3GPP TS 29.244, Section 8.2.38 — Node ID:
/// - Octet 1: Spare(4 bits) | Node ID Type(4 bits)
///   - 0: IPv4 address (4 bytes follow)
///   - 1: IPv6 address (16 bytes follow)
///   - 2: FQDN (variable length follows)
fn parse_node_id<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    let node_id_type = data[0] & 0x0F;

    let obj_idx = buf.begin_container(
        &crate::ie::IE_CHILD_FIELDS[2],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );

    buf.push_field(
        &FD_INLINE_NODE_ID_TYPE,
        FieldValue::U8(node_id_type),
        offset..offset + 1,
    );

    match node_id_type {
        // IPv4
        0 if data.len() >= 5 => {
            buf.push_field(
                &FD_INLINE_NODE_ID_VALUE,
                FieldValue::Ipv4Addr(read_ipv4_addr(data, 1).unwrap_or_default()),
                offset + 1..offset + 5,
            );
        }
        // IPv6
        1 if data.len() >= 17 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            buf.push_field(
                &FD_INLINE_NODE_ID_VALUE,
                FieldValue::Ipv6Addr(octets),
                offset + 1..offset + 17,
            );
        }
        // FQDN — store as raw bytes (zero-copy)
        2 if data.len() >= 2 => {
            buf.push_field(
                &FD_INLINE_NODE_ID_VALUE,
                FieldValue::Bytes(&data[1..]),
                offset + 1..offset + data.len(),
            );
        }
        _ => {
            buf.push_field(
                &FD_INLINE_NODE_ID_VALUE,
                FieldValue::Bytes(&data[1..]),
                offset + 1..offset + data.len(),
            );
        }
    }

    buf.end_container(obj_idx);
    FieldValue::Object(0..0)
}

/// Returns the human-readable name for a PFCP Cause value.
///
/// 3GPP TS 29.244, Section 8.2.1.
fn cause_name(value: u8) -> Option<&'static str> {
    match value {
        1 => Some("Request accepted"),
        64 => Some("Request rejected"),
        65 => Some("Session context not found"),
        66 => Some("Mandatory IE missing"),
        67 => Some("Conditional IE missing"),
        68 => Some("Invalid length"),
        69 => Some("Mandatory IE incorrect"),
        70 => Some("Invalid Forwarding Policy"),
        71 => Some("Invalid F-TEID allocation option"),
        72 => Some("No established Pfcp Association"),
        73 => Some("Rule creation/modification Failure"),
        74 => Some("PFCP entity in congestion"),
        75 => Some("No resources available"),
        76 => Some("Service not supported"),
        77 => Some("System failure"),
        78 => Some("Redirection Requested"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to get a named field from an Object's children in the buffer.
    fn obj_field_buf<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        obj_range: &core::ops::Range<u32>,
        name: &str,
    ) -> Option<&'a packet_dissector_core::field::Field<'pkt>> {
        buf.nested_fields(obj_range)
            .iter()
            .find(|f| f.name() == name)
    }

    /// Helper: parse an IE value and return the buffer with fields.
    fn parse_and_buf<'pkt>(
        ie_type: u16,
        data: &'pkt [u8],
        offset: usize,
    ) -> (FieldValue<'pkt>, DissectBuffer<'pkt>) {
        let mut buf = DissectBuffer::new();
        let val = parse_ie_value(ie_type, data, offset, 0, &mut buf);
        (val, buf)
    }

    #[test]
    fn parse_cause_accepted() {
        let data = [1u8]; // Request accepted
        let (val, buf) = parse_and_buf(19, &data, 0);
        // The return value is a sentinel Object(0..0); actual data is in buf
        assert!(matches!(val, FieldValue::Object(_)));
        // buf should have: Object placeholder, cause_value field
        assert!(buf.fields().len() >= 2);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let cause_f = obj_field_buf(&buf, r, "cause_value").unwrap();
                assert_eq!(cause_f.value, FieldValue::U8(1));
                assert_eq!(
                    buf.resolve_nested_display_name(r, "cause_value_name"),
                    Some("Request accepted")
                );
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_cause_rejected() {
        let data = [64u8]; // Request rejected
        let (val, buf) = parse_and_buf(19, &data, 0);
        assert!(matches!(val, FieldValue::Object(_)));
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let cause_f = obj_field_buf(&buf, r, "cause_value").unwrap();
                assert_eq!(cause_f.value, FieldValue::U8(64));
                assert_eq!(
                    buf.resolve_nested_display_name(r, "cause_value_name"),
                    Some("Request rejected")
                );
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_cause_empty_data() {
        let data: &[u8] = &[];
        let (val, _buf) = parse_and_buf(19, data, 0);
        assert_eq!(val, FieldValue::Bytes(&[]));
    }

    #[test]
    fn parse_node_id_ipv4() {
        let data = [0x00, 10, 0, 0, 1]; // type=0 (IPv4), addr=10.0.0.1
        let (_val, buf) = parse_and_buf(60, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let nid_type = obj_field_buf(&buf, r, "node_id_type").unwrap();
                assert_eq!(nid_type.value, FieldValue::U8(0));
                let nid_val = obj_field_buf(&buf, r, "node_id_value").unwrap();
                assert_eq!(nid_val.value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_node_id_ipv6() {
        let mut data = vec![0x01]; // type=1 (IPv6)
        // ::1
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let (_val, buf) = parse_and_buf(60, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let nid_type = obj_field_buf(&buf, r, "node_id_type").unwrap();
                assert_eq!(nid_type.value, FieldValue::U8(1));
                let nid_val = obj_field_buf(&buf, r, "node_id_value").unwrap();
                assert_eq!(
                    nid_val.value,
                    FieldValue::Ipv6Addr([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                );
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_node_id_fqdn() {
        // type=2 (FQDN), DNS-encoded "example.com"
        let data = [
            0x02, // Node ID Type = FQDN
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            3, b'c', b'o', b'm', // "com"
            0,    // terminator
        ];
        let (_val, buf) = parse_and_buf(60, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let nid_type = obj_field_buf(&buf, r, "node_id_type").unwrap();
                assert_eq!(nid_type.value, FieldValue::U8(2));
                let nid_val = obj_field_buf(&buf, r, "node_id_value").unwrap();
                // Now stored as raw bytes
                assert_eq!(
                    nid_val.value,
                    FieldValue::Bytes(&[
                        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
                    ])
                );
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_node_id_empty() {
        let data: &[u8] = &[];
        let (val, _buf) = parse_and_buf(60, data, 0);
        assert_eq!(val, FieldValue::Bytes(&[]));
    }

    #[test]
    fn parse_recovery_time_stamp() {
        // NTP timestamp: 0x12345678
        let data = [0x12, 0x34, 0x56, 0x78];
        let (_val, buf) = parse_and_buf(96, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let ts = obj_field_buf(&buf, r, "recovery_time_stamp").unwrap();
                assert_eq!(ts.value, FieldValue::U32(0x12345678));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_recovery_time_stamp_truncated() {
        let data = [0x12, 0x34, 0x56]; // only 3 bytes
        let (val, _buf) = parse_and_buf(96, &data, 0);
        assert_eq!(val, FieldValue::Bytes(&[0x12, 0x34, 0x56]));
    }

    #[test]
    fn parse_unknown_ie_type() {
        let data = [0xAA, 0xBB];
        let (val, _buf) = parse_and_buf(9999, &data, 0);
        assert_eq!(val, FieldValue::Bytes(&[0xAA, 0xBB]));
    }

    #[test]
    fn cause_name_known_values() {
        assert_eq!(cause_name(1), Some("Request accepted"));
        assert_eq!(cause_name(64), Some("Request rejected"));
        assert_eq!(cause_name(65), Some("Session context not found"));
        assert_eq!(cause_name(66), Some("Mandatory IE missing"));
        assert_eq!(cause_name(67), Some("Conditional IE missing"));
        assert_eq!(cause_name(68), Some("Invalid length"));
        assert_eq!(cause_name(69), Some("Mandatory IE incorrect"));
        assert_eq!(cause_name(70), Some("Invalid Forwarding Policy"));
        assert_eq!(cause_name(71), Some("Invalid F-TEID allocation option"));
        assert_eq!(cause_name(72), Some("No established Pfcp Association"));
        assert_eq!(cause_name(73), Some("Rule creation/modification Failure"));
        assert_eq!(cause_name(74), Some("PFCP entity in congestion"));
        assert_eq!(cause_name(75), Some("No resources available"));
        assert_eq!(cause_name(76), Some("Service not supported"));
        assert_eq!(cause_name(77), Some("System failure"));
        assert_eq!(cause_name(78), Some("Redirection Requested"));
    }

    #[test]
    fn cause_name_unknown() {
        assert_eq!(cause_name(0), None);
        assert_eq!(cause_name(2), None);
        assert_eq!(cause_name(63), None);
        assert_eq!(cause_name(79), None);
        assert_eq!(cause_name(255), None);
    }

    #[test]
    fn non_zero_offset_cause() {
        let data = [1u8];
        let (_val, buf) = parse_and_buf(19, &data, 100);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let cause_f = obj_field_buf(&buf, r, "cause_value").unwrap();
                assert_eq!(cause_f.range, 100..101);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn non_zero_offset_node_id() {
        let data = [0x00, 10, 0, 0, 1]; // type=0 (IPv4)
        let (_val, buf) = parse_and_buf(60, &data, 200);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let nid_type = obj_field_buf(&buf, r, "node_id_type").unwrap();
                assert_eq!(nid_type.range, 200..201);
                let nid_val = obj_field_buf(&buf, r, "node_id_value").unwrap();
                assert_eq!(nid_val.range, 201..205);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn non_zero_offset_recovery() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let (_val, buf) = parse_and_buf(96, &data, 50);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let ts = obj_field_buf(&buf, r, "recovery_time_stamp").unwrap();
                assert_eq!(ts.range, 50..54);
            }
            _ => panic!("expected Object"),
        }
    }

    // --- Grouped IE tests ---

    #[test]
    fn parse_grouped_ie_create_pdr() {
        // Create PDR (type 1) containing a Cause IE (type 19, length 1, value 1)
        let inner_cause = [0x00, 0x13, 0x00, 0x01, 0x01];
        let mut buf = DissectBuffer::new();
        let val = parse_ie_value(1, &inner_cause, 0, 0, &mut buf);
        // Should be a sentinel Array
        assert!(matches!(val, FieldValue::Array(_)));
        // Buffer should contain the grouped Array with nested IE objects
        assert!(!buf.fields().is_empty());

        // The first field should be the Array container
        let arr = &buf.fields()[0];
        match &arr.value {
            FieldValue::Array(r) => {
                // Should have children (the nested IE)
                assert!(r.start < r.end);
                let children = buf.nested_fields(r);
                // First child should be an Object (the IE)
                assert!(children[0].value.is_object());
                match &children[0].value {
                    FieldValue::Object(or) => {
                        let type_f = obj_field_buf(&buf, or, "type").unwrap();
                        assert_eq!(type_f.value, FieldValue::U32(19));
                    }
                    _ => panic!("expected Object"),
                }
            }
            _ => panic!("expected Array for grouped IE"),
        }
    }

    #[test]
    fn parse_grouped_ie_nested() {
        // PDI (type 2) containing Source Interface IE (type 20, length 1, value 0)
        let inner_src_if = [0x00, 0x14, 0x00, 0x01, 0x00];
        // Create PDR (type 1) containing the PDI
        let mut create_pdr_value = Vec::new();
        // PDI IE header: type=2, length=inner_src_if.len()
        create_pdr_value.extend_from_slice(&[0x00, 0x02]);
        create_pdr_value.extend_from_slice(&(inner_src_if.len() as u16).to_be_bytes());
        create_pdr_value.extend_from_slice(&inner_src_if);

        let mut buf = DissectBuffer::new();
        let val = parse_ie_value(1, &create_pdr_value, 0, 0, &mut buf);
        assert!(matches!(val, FieldValue::Array(_)));

        // The outermost Array should contain one child (PDI IE Object)
        let arr = &buf.fields()[0];
        match &arr.value {
            FieldValue::Array(r) => {
                let children = buf.nested_fields(r);
                // PDI IE Object
                let pdi = &children[0];
                match &pdi.value {
                    FieldValue::Object(or) => {
                        // Find the value field — it should be an Array (nested grouped IE)
                        // In the new API, the grouped IE value is pushed inline
                        // Check that type=2 (PDI) is present
                        let type_f = obj_field_buf(&buf, or, "type").unwrap();
                        assert_eq!(type_f.value, FieldValue::U32(2));
                    }
                    _ => panic!("expected Object"),
                }
            }
            _ => panic!("expected Array"),
        }
    }

    #[test]
    fn parse_grouped_ie_additional_types() {
        // Verify types that were previously parsed as raw bytes are now
        // recognised as grouped IEs (3GPP TS 29.244 Table 8.1.2-1).
        //
        // A grouped IE containing a single Cause IE (type 19, length 1) should
        // produce an Array sentinel, whereas a non-grouped IE would yield Bytes.
        let inner_cause = [0x00, 0x13, 0x00, 0x01, 0x01];

        // Each value is a grouped IE type that the parser must recognise.
        for ie_type in [
            183u16, 211, 212, 213, 216, 218, 242, 247, 252, 295, 315, 378,
        ] {
            let mut buf = DissectBuffer::new();
            let val = parse_ie_value(ie_type, &inner_cause, 0, 0, &mut buf);
            assert!(
                matches!(val, FieldValue::Array(_)),
                "ie_type {ie_type} expected grouped (Array sentinel), got {val:?}",
            );
            // A grouped IE must push at least one nested Array container.
            assert!(
                !buf.fields().is_empty(),
                "ie_type {ie_type} did not push any fields",
            );
        }
    }

    #[test]
    fn parse_grouped_ie_depth_limit() {
        let data = [0x00, 0x13, 0x00, 0x01, 0x01]; // Cause IE
        // At MAX_GROUPED_DEPTH, should fall back to bytes
        let mut buf = DissectBuffer::new();
        let val = parse_ie_value(1, &data, 0, crate::ie::MAX_GROUPED_DEPTH, &mut buf);
        assert_eq!(val, FieldValue::Bytes(&data));
    }

    #[test]
    fn parse_grouped_ie_empty() {
        let data: &[u8] = &[];
        let mut buf = DissectBuffer::new();
        let val = parse_ie_value(1, data, 0, 0, &mut buf);
        // Empty grouped IE — Array with no children
        assert!(matches!(val, FieldValue::Array(_)));
    }

    // --- F-SEID tests ---

    #[test]
    fn parse_f_seid_v4_only() {
        // flags=0x02 (V4=1, V6=0), SEID=0x0123456789ABCDEF, IPv4=10.0.0.1
        let mut data = vec![0x02];
        data.extend_from_slice(&0x0123456789ABCDEFu64.to_be_bytes());
        data.extend_from_slice(&[10, 0, 0, 1]);
        let (_val, buf) = parse_and_buf(57, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].value, FieldValue::U8(1)); // v4
                assert_eq!(fields[1].value, FieldValue::U8(0)); // v6
                assert_eq!(fields[2].value, FieldValue::U64(0x0123456789ABCDEF)); // seid
                assert_eq!(fields[3].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_seid_v6_only() {
        // flags=0x01 (V4=0, V6=1), SEID, IPv6=::1
        let mut data = vec![0x01];
        data.extend_from_slice(&1u64.to_be_bytes()); // SEID=1
        let mut ipv6 = [0u8; 16];
        ipv6[15] = 1; // ::1
        data.extend_from_slice(&ipv6);
        let (_val, buf) = parse_and_buf(57, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].value, FieldValue::U8(0)); // v4
                assert_eq!(fields[1].value, FieldValue::U8(1)); // v6
                assert_eq!(fields[2].value, FieldValue::U64(1)); // seid
                assert_eq!(fields[3].value, FieldValue::Ipv6Addr(ipv6));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_seid_dual_stack() {
        // flags=0x03 (V4=1, V6=1)
        let mut data = vec![0x03];
        data.extend_from_slice(&42u64.to_be_bytes());
        data.extend_from_slice(&[192, 168, 1, 1]); // IPv4
        let mut ipv6 = [0u8; 16];
        ipv6[15] = 1;
        data.extend_from_slice(&ipv6); // IPv6
        let (_val, buf) = parse_and_buf(57, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields.len(), 5); // v4, v6, seid, ipv4, ipv6
                assert_eq!(fields[3].value, FieldValue::Ipv4Addr([192, 168, 1, 1]));
                assert_eq!(fields[4].value, FieldValue::Ipv6Addr(ipv6));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_seid_truncated() {
        let data = [0x02, 0x01, 0x02, 0x03]; // Only 4 bytes, need 9
        let (val, _buf) = parse_and_buf(57, &data, 0);
        assert_eq!(val, FieldValue::Bytes(&data));
    }

    #[test]
    fn parse_f_seid_nonzero_offset() {
        let mut data = vec![0x02]; // V4=1
        data.extend_from_slice(&1u64.to_be_bytes());
        data.extend_from_slice(&[10, 0, 0, 1]);
        let (_val, buf) = parse_and_buf(57, &data, 100);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].range, 100..101); // flags
                assert_eq!(fields[2].range, 101..109); // seid
                assert_eq!(fields[3].range, 109..113); // ipv4
            }
            _ => panic!("expected Object"),
        }
    }

    // --- F-TEID tests ---

    #[test]
    fn parse_f_teid_v4_only() {
        // CH=0, V4=1, V6=0: flags=0x01, TEID=0x12345678, IPv4=192.168.1.1
        let mut data = vec![0x01];
        data.extend_from_slice(&0x12345678u32.to_be_bytes());
        data.extend_from_slice(&[192, 168, 1, 1]);
        let (_val, buf) = parse_and_buf(21, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].value, FieldValue::U8(1)); // v4
                assert_eq!(fields[1].value, FieldValue::U8(0)); // v6
                assert_eq!(fields[2].value, FieldValue::U8(0)); // ch
                assert_eq!(fields[3].value, FieldValue::U8(0)); // chid
                assert_eq!(fields[4].value, FieldValue::U32(0x12345678)); // teid
                assert_eq!(fields[5].value, FieldValue::Ipv4Addr([192, 168, 1, 1]));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_teid_v6_only() {
        // CH=0, V4=0, V6=1: flags=0x02
        let mut data = vec![0x02];
        data.extend_from_slice(&0xAABBCCDDu32.to_be_bytes());
        let mut ipv6 = [0u8; 16];
        ipv6[0] = 0xFE;
        ipv6[1] = 0x80;
        data.extend_from_slice(&ipv6);
        let (_val, buf) = parse_and_buf(21, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].value, FieldValue::U8(0)); // v4
                assert_eq!(fields[1].value, FieldValue::U8(1)); // v6
                assert_eq!(fields[4].value, FieldValue::U32(0xAABBCCDD)); // teid
                assert_eq!(fields[5].value, FieldValue::Ipv6Addr(ipv6));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_teid_dual_stack() {
        // CH=0, V4=1, V6=1: flags=0x03
        let mut data = vec![0x03];
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&[10, 0, 0, 1]); // IPv4
        let mut ipv6 = [0u8; 16];
        ipv6[15] = 1;
        data.extend_from_slice(&ipv6); // IPv6
        let (_val, buf) = parse_and_buf(21, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields.len(), 7); // v4, v6, ch, chid, teid, ipv4, ipv6
                assert_eq!(fields[5].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
                assert_eq!(fields[6].value, FieldValue::Ipv6Addr(ipv6));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_teid_choose_with_id() {
        // CH=1, CHID=1, V4=1: flags=0x0D (bit0=V4=1, bit2=CH=1, bit3=CHID=1)
        let data = [0x0D, 0x05]; // CHOOSE ID=5
        let (_val, buf) = parse_and_buf(21, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[2].value, FieldValue::U8(1)); // ch
                assert_eq!(fields[3].value, FieldValue::U8(1)); // chid
                assert_eq!(fields[4].value, FieldValue::U8(5)); // choose_id
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_teid_choose_without_id() {
        // CH=1, CHID=0, V4=1: flags=0x05 (bit0=V4=1, bit2=CH=1)
        let data = [0x05];
        let (_val, buf) = parse_and_buf(21, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields.len(), 4); // v4, v6, ch, chid only
                assert_eq!(fields[2].value, FieldValue::U8(1)); // ch
                assert_eq!(fields[3].value, FieldValue::U8(0)); // chid
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_f_teid_empty() {
        let data: &[u8] = &[];
        let (val, _buf) = parse_and_buf(21, data, 0);
        assert_eq!(val, FieldValue::Bytes(&[]));
    }

    #[test]
    fn parse_f_teid_ch0_truncated_teid() {
        // CH=0, V4=1 but only 3 bytes (need 5 for TEID)
        let data = [0x01, 0x00, 0x00];
        let (val, _buf) = parse_and_buf(21, &data, 0);
        assert_eq!(val, FieldValue::Bytes(&data));
    }

    #[test]
    fn parse_f_teid_nonzero_offset() {
        let mut data = vec![0x01]; // V4=1, CH=0
        data.extend_from_slice(&0x12345678u32.to_be_bytes());
        data.extend_from_slice(&[10, 0, 0, 1]);
        let (_val, buf) = parse_and_buf(21, &data, 50);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].range, 50..51); // flags
                assert_eq!(fields[4].range, 51..55); // teid
                assert_eq!(fields[5].range, 55..59); // ipv4
            }
            _ => panic!("expected Object"),
        }
    }

    // --- Network Instance (type 22) tests ---

    #[test]
    fn parse_network_instance_dns_label() {
        // DNS label-length encoded "foo.bar"
        let data = [
            3, b'f', b'o', b'o', // "foo"
            3, b'b', b'a', b'r', // "bar"
            0,    // terminator
        ];
        let (_val, buf) = parse_and_buf(22, &data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].name(), "network_instance");
                // Stored as raw bytes now
                assert_eq!(fields[0].value, FieldValue::Bytes(&data));
                assert_eq!(fields[0].range, 0..9);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_network_instance_plain_utf8() {
        let data = b"internet";
        let (_val, buf) = parse_and_buf(22, data, 0);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].name(), "network_instance");
                assert_eq!(fields[0].value, FieldValue::Bytes(b"internet" as &[u8]));
                assert_eq!(fields[0].range, 0..8);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn parse_network_instance_empty() {
        let data: &[u8] = &[];
        let (val, _buf) = parse_and_buf(22, data, 0);
        assert_eq!(val, FieldValue::Bytes(&[]));
    }

    #[test]
    fn non_zero_offset_network_instance() {
        let data = b"internet";
        let (_val, buf) = parse_and_buf(22, data, 100);
        let obj = &buf.fields()[0];
        match &obj.value {
            FieldValue::Object(r) => {
                let fields = buf.nested_fields(r);
                assert_eq!(fields[0].range, 100..108);
            }
            _ => panic!("expected Object"),
        }
    }
}
