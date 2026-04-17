//! GTPv1-U (GPRS Tunnelling Protocol User Plane) dissector.
//!
//! ## References
//! - 3GPP TS 29.281: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.281/>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Map a GTPv1-U message type code to its name.
///
/// 3GPP TS 29.281, Section 6.1, Table 6.1-1 — GTP-U Message Types.
/// <https://www.3gpp.org/ftp/Specs/archive/29_series/29.281/>
fn gtpv1u_message_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Echo Request"),
        2 => Some("Echo Response"),
        26 => Some("Error Indication"),
        31 => Some("Supported Extension Headers Notification"),
        254 => Some("End Marker"),
        255 => Some("G-PDU"),
        _ => None,
    }
}

/// Map a GTPv1-U Next Extension Header Type value to its name.
///
/// 3GPP TS 29.281, Section 5.2.1, Table 5.2.1-3.
fn gtpv1u_ext_header_type_name(v: u8) -> Option<&'static str> {
    match v {
        0x00 => Some("No more extension headers"),
        0x01 => Some("MBMS support indication"),
        0x02 => Some("MS Info Change Reporting support indication"),
        0x20 => Some("Service Class Indicator"),
        0x40 => Some("UDP Port"),
        0x81 => Some("RAN Container"),
        0x82 => Some("Long PDCP PDU Number"),
        0x83 => Some("Xw RAN Container"),
        0x84 => Some("NR RAN Container"),
        0x85 => Some("PDU Session Container"),
        0xC0 => Some("PDCP PDU Number"),
        0xC1 => Some("Suspend Request"),
        0xC2 => Some("Suspend Response"),
        _ => None,
    }
}

/// Minimum GTP-U header size (mandatory fields only).
///
/// 3GPP TS 29.281, Section 5.1 — The GTP-U header is a variable length
/// header whose minimum length is 8 bytes.
const MIN_HEADER_SIZE: usize = 8;

/// Extended header size when any of E, S, or PN flags are set.
///
/// 3GPP TS 29.281, Section 5.1 — If and only if one or more of these three
/// flags are set, the fields Sequence Number, N-PDU and Extension Header
/// shall be present.
const EXTENDED_HEADER_SIZE: usize = 12;

/// GTP-U message type for G-PDU (user data).
///
/// 3GPP TS 29.281, Section 6.1, Table 6.1-1.
const MSG_TYPE_G_PDU: u8 = 255;

const FD_VERSION: usize = 0;
const FD_PT: usize = 1;
const FD_E: usize = 2;
const FD_S: usize = 3;
const FD_PN: usize = 4;
const FD_MESSAGE_TYPE: usize = 5;
const FD_LENGTH: usize = 6;
const FD_TEID: usize = 7;
const FD_SEQUENCE_NUMBER: usize = 8;
const FD_N_PDU_NUMBER: usize = 9;
const FD_NEXT_EXTENSION_HEADER_TYPE: usize = 10;
const FD_EXTENSION_HEADERS: usize = 11;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("pt", "Protocol Type", FieldType::U8),
    FieldDescriptor::new("e", "Extension Header Flag", FieldType::U8),
    FieldDescriptor::new("s", "Sequence Number Flag", FieldType::U8),
    FieldDescriptor::new("pn", "N-PDU Number Flag", FieldType::U8),
    FieldDescriptor {
        name: "message_type",
        display_name: "Message Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => gtpv1u_message_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("teid", "Tunnel Endpoint Identifier", FieldType::U32),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("n_pdu_number", "N-PDU Number", FieldType::U8).optional(),
    FieldDescriptor::new(
        "next_extension_header_type",
        "Next Extension Header Type",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("extension_headers", "Extension Headers", FieldType::Array).optional(),
];

/// Extension header child field descriptor indices.
const FD_EXT_TYPE: usize = 0;
const FD_EXT_LENGTH: usize = 1;
const FD_EXT_CONTENT: usize = 2;

static EXT_HEADER_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("content", "Content", FieldType::Bytes),
];

/// Container descriptor for a GTPv1-U extension header entry.
///
/// `display_fn` resolves the outer container's label to the extension header
/// type name (e.g. "PDU Session Container") by looking up the inner `type`
/// field.
static FD_EXTENSION_HEADER: FieldDescriptor = FieldDescriptor {
    name: "extension_header",
    display_name: "Extension Header",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => gtpv1u_ext_header_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// GTPv1-U dissector.
///
/// Parses GTP-U headers as defined in 3GPP TS 29.281. Supports the mandatory
/// 8-byte header, optional Sequence Number / N-PDU Number / Extension Header
/// fields, and extension header chains.
///
/// For G-PDU messages (type 255), the dissector dispatches to the inner IP
/// layer based on the first nibble of the T-PDU payload (IPv4 or IPv6).
pub struct Gtpv1uDissector;

impl Dissector for Gtpv1uDissector {
    fn name(&self) -> &'static str {
        "GPRS Tunnelling Protocol User Plane"
    }

    fn short_name(&self) -> &'static str {
        "GTPv1-U"
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
        // 3GPP TS 29.281, Section 5.1 — minimum 8 bytes
        if data.len() < MIN_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // 3GPP TS 29.281, Section 5.1 — Octet 1: flags
        let version = (data[0] >> 5) & 0x07;
        let pt = (data[0] >> 4) & 0x01;
        let e_flag = (data[0] >> 2) & 0x01;
        let s_flag = (data[0] >> 1) & 0x01;
        let pn_flag = data[0] & 0x01;

        // 3GPP TS 29.281, Section 5.1 — "The version number shall be set to '1'."
        if version != 1 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: version as u32,
            });
        }

        // 3GPP TS 29.281, Section 5.1 — PT=1 for GTP, PT=0 for GTP'
        if pt != 1 {
            return Err(PacketError::InvalidFieldValue {
                field: "pt",
                value: pt as u32,
            });
        }

        // 3GPP TS 29.281, Section 5.1 — Octet 2: Message Type
        let message_type = data[1];

        // 3GPP TS 29.281, Section 5.1 — Octets 3-4: Length
        let length = read_be_u16(data, 2)?;

        // 3GPP TS 29.281, Section 5.1 — Octets 5-8: TEID
        let teid = read_be_u32(data, 4)?;

        let has_optional = e_flag != 0 || s_flag != 0 || pn_flag != 0;

        // Validate that we have enough data for the payload indicated by length.
        // Length covers everything after the first 8 mandatory bytes.
        let total_gtp_size = MIN_HEADER_SIZE + length as usize;
        if data.len() < total_gtp_size {
            return Err(PacketError::Truncated {
                expected: total_gtp_size,
                actual: data.len(),
            });
        }

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + MIN_HEADER_SIZE,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PT],
            FieldValue::U8(pt),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_E],
            FieldValue::U8(e_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_S],
            FieldValue::U8(s_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PN],
            FieldValue::U8(pn_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_TYPE],
            FieldValue::U8(message_type),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LENGTH],
            FieldValue::U16(length),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TEID],
            FieldValue::U32(teid),
            offset + 4..offset + 8,
        );

        // 3GPP TS 29.281, Section 5.1 — Optional fields present when any flag set
        let mut header_end = MIN_HEADER_SIZE;

        if has_optional {
            if data.len() < EXTENDED_HEADER_SIZE {
                return Err(PacketError::Truncated {
                    expected: EXTENDED_HEADER_SIZE,
                    actual: data.len(),
                });
            }

            // 3GPP TS 29.281, Section 5.1 — Octets 9-10: Sequence Number
            let seq = read_be_u16(data, 8)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                FieldValue::U16(seq),
                offset + 8..offset + 10,
            );

            // 3GPP TS 29.281, Section 5.1 — Octet 11: N-PDU Number
            let n_pdu = data[10];
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_N_PDU_NUMBER],
                FieldValue::U8(n_pdu),
                offset + 10..offset + 11,
            );

            // 3GPP TS 29.281, Section 5.1 — Octet 12: Next Extension Header Type
            let next_ext_type = data[11];
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_NEXT_EXTENSION_HEADER_TYPE],
                FieldValue::U8(next_ext_type),
                offset + 11..offset + 12,
            );

            header_end = EXTENDED_HEADER_SIZE;

            // 3GPP TS 29.281, Section 5.2 — Parse extension header chain
            if e_flag != 0 && next_ext_type != 0 {
                let ext_range_start = offset + EXTENDED_HEADER_SIZE;
                let ext_array_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_EXTENSION_HEADERS],
                    FieldValue::Array(0..0),
                    ext_range_start..ext_range_start,
                );
                let ext_end = parse_extension_headers(buf, data, EXTENDED_HEADER_SIZE, offset)?;
                // Update the container range end
                if let Some(field) = buf.field_mut(ext_array_idx as usize) {
                    field.range = ext_range_start..offset + ext_end;
                }
                buf.end_container(ext_array_idx);
                header_end = ext_end;
            }
        }

        // Update layer range to actual header_end
        if let Some(layer) = buf.last_layer_mut() {
            layer.range = offset..offset + header_end;
        }
        buf.end_layer();

        // Determine next dissector for G-PDU payloads
        let next = if message_type == MSG_TYPE_G_PDU && total_gtp_size > header_end {
            // 3GPP TS 29.281, Section 6.1 — G-PDU carries a T-PDU (IP datagram)
            let payload_start = header_end;
            if payload_start < data.len() {
                let ip_version = (data[payload_start] >> 4) & 0x0F;
                match ip_version {
                    4 => DispatchHint::ByEtherType(0x0800),
                    6 => DispatchHint::ByEtherType(0x86DD),
                    _ => DispatchHint::End,
                }
            } else {
                DispatchHint::End
            }
        } else {
            DispatchHint::End
        };

        Ok(DissectResult::new(header_end, next))
    }
}

/// Parse a chain of GTP-U extension headers.
///
/// 3GPP TS 29.281, Section 5.2.1 — Each extension header has:
/// - Octet 1: Length in 4-octet units
/// - Octets 2..m: Content
/// - Octet m+1: Next Extension Header Type
///
/// Returns the parsed extension headers and the byte offset where the chain
/// ends (relative to the start of `data`).
fn parse_extension_headers<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    start: usize,
    packet_offset: usize,
) -> Result<usize, PacketError> {
    // 3GPP TS 29.281 does not specify a maximum chain length.
    // Cap at 64 to prevent infinite loops from malformed packets
    // where the next-type field points back into the chain.
    const MAX_EXT_HEADERS: usize = 64;

    let mut count = 0usize;
    let mut pos = start;

    // The next_ext_type for the first extension header was already read
    // from data[11]. We enter this function only when it's non-zero.
    let mut next_type = data[11];

    while next_type != 0 {
        if count >= MAX_EXT_HEADERS {
            return Err(PacketError::InvalidHeader(
                "GTPv1-U extension header chain exceeds maximum depth",
            ));
        }
        // 3GPP TS 29.281, Section 5.2.1 — need at least 4 bytes for
        // the minimum extension header (length=1 → 4 octets)
        if pos >= data.len() {
            return Err(PacketError::Truncated {
                expected: pos + 4,
                actual: data.len(),
            });
        }

        // 3GPP TS 29.281, Section 5.2.1 — Extension Header Length
        let ext_len_units = data[pos] as usize;
        if ext_len_units == 0 {
            return Err(PacketError::InvalidHeader(
                "GTPv1-U extension header length must be > 0",
            ));
        }
        let ext_len_bytes = ext_len_units * 4;

        if pos + ext_len_bytes > data.len() {
            return Err(PacketError::Truncated {
                expected: pos + ext_len_bytes,
                actual: data.len(),
            });
        }

        // Content is between length byte and the next extension header type byte
        let content_start = pos + 1;
        let content_end = pos + ext_len_bytes - 1;
        let content = &data[content_start..content_end];

        // Last byte is the Next Extension Header Type
        let next = data[pos + ext_len_bytes - 1];

        let obj_idx = buf.begin_container(
            &FD_EXTENSION_HEADER,
            FieldValue::Object(0..0),
            packet_offset + pos..packet_offset + pos + ext_len_bytes,
        );
        buf.push_field(
            &EXT_HEADER_FIELD_DESCRIPTORS[FD_EXT_TYPE],
            FieldValue::U8(next_type),
            packet_offset + pos..packet_offset + pos + 1,
        );
        buf.push_field(
            &EXT_HEADER_FIELD_DESCRIPTORS[FD_EXT_LENGTH],
            FieldValue::U8(ext_len_units as u8),
            packet_offset + pos..packet_offset + pos + 1,
        );
        buf.push_field(
            &EXT_HEADER_FIELD_DESCRIPTORS[FD_EXT_CONTENT],
            FieldValue::Bytes(content),
            packet_offset + content_start..packet_offset + content_end,
        );
        buf.end_container(obj_idx);

        next_type = next;
        pos += ext_len_bytes;
        count += 1;
    }

    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    // # 3GPP TS 29.281 Coverage
    //
    // | TS Section | Description                  | Test                            |
    // |------------|------------------------------|---------------------------------|
    // | 5.1        | Basic G-PDU (8-byte header)  | test_gpdu_basic                 |
    // | 5.1        | G-PDU with optional fields   | test_gpdu_with_optional_fields  |
    // | 5.1        | Version validation           | test_invalid_version            |
    // | 5.1        | PT validation                | test_invalid_pt                 |
    // | 5.1        | Truncated header             | test_truncated_header           |
    // | 5.1        | Truncated optional fields    | test_truncated_optional         |
    // | 5.1        | Echo Request (type 1)        | test_echo_request               |
    // | 5.1        | Length validation             | test_length_exceeds_data        |
    // | 5.2        | Extension header chain       | test_extension_headers          |
    // | 5.2        | Extension header truncated   | test_extension_header_truncated |
    // | 5.2        | Extension header zero length | test_extension_header_zero_length |
    // | 5.1        | G-PDU with IPv6 payload      | test_gpdu_ipv6_payload          |
    // | 6.1        | End Marker (type 254)        | test_end_marker                 |
    // | 6.1        | Message Type Name lookup     | test_message_type_name          |

    /// Build a minimal G-PDU header (8 bytes) with an IPv4 payload stub.
    fn make_gpdu_basic() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Octet 1: Version=1, PT=1, Spare=0, E=0, S=0, PN=0
        // 001 1 0 0 0 0 = 0x30
        pkt.push(0x30);
        // Octet 2: Message Type = 255 (G-PDU)
        pkt.push(0xFF);
        // Octets 3-4: Length = 20 (IPv4 minimum header as payload)
        pkt.extend_from_slice(&20u16.to_be_bytes());
        // Octets 5-8: TEID = 0x12345678
        pkt.extend_from_slice(&0x12345678u32.to_be_bytes());
        // Payload: minimal IPv4 header stub (20 bytes, version nibble = 4)
        pkt.push(0x45); // Version=4, IHL=5
        pkt.extend_from_slice(&[0u8; 19]);
        pkt
    }

    #[test]
    fn test_gpdu_basic() {
        let data = make_gpdu_basic();
        let mut buf = DissectBuffer::new();
        let dissector = Gtpv1uDissector;
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "GTPv1-U");
        assert_eq!(layer.range, 0..8);

        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "pt").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "e").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "s").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "pn").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "message_type").unwrap().value,
            FieldValue::U8(255)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("G-PDU")
        );
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U16(20)
        );
        assert_eq!(
            buf.field_by_name(layer, "teid").unwrap().value,
            FieldValue::U32(0x12345678)
        );
    }

    #[test]
    fn test_gpdu_with_optional_fields() {
        let mut pkt = Vec::new();
        // Octet 1: Version=1, PT=1, Spare=0, E=0, S=1, PN=0
        // 001 1 0 0 1 0 = 0x32
        pkt.push(0x32);
        // Message Type = 255 (G-PDU)
        pkt.push(0xFF);
        // Length = 24 (4 optional bytes + 20 payload)
        pkt.extend_from_slice(&24u16.to_be_bytes());
        // TEID
        pkt.extend_from_slice(&0xAABBCCDDu32.to_be_bytes());
        // Sequence Number = 0x0042
        pkt.extend_from_slice(&0x0042u16.to_be_bytes());
        // N-PDU Number = 0
        pkt.push(0x00);
        // Next Extension Header Type = 0 (no extensions)
        pkt.push(0x00);
        // Payload: minimal IPv4 stub
        pkt.push(0x45);
        pkt.extend_from_slice(&[0u8; 19]);

        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 12);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "s").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_number").unwrap().value,
            FieldValue::U16(0x0042)
        );
        assert_eq!(
            buf.field_by_name(layer, "n_pdu_number").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "next_extension_header_type")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn test_invalid_version() {
        let mut data = make_gpdu_basic();
        // Set version to 2: 010 1 0 0 0 0 = 0x50
        data[0] = 0x50;
        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidHeader(_) | PacketError::InvalidFieldValue { .. }
        ));
    }

    #[test]
    fn test_invalid_pt() {
        let mut data = make_gpdu_basic();
        // Set PT=0: 001 0 0 0 0 0 = 0x20
        data[0] = 0x20;
        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidHeader(_) | PacketError::InvalidFieldValue { .. }
        ));
    }

    #[test]
    fn test_truncated_header() {
        let data = vec![0x30, 0xFF, 0x00]; // only 3 bytes
        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { expected: 8, .. }));
    }

    #[test]
    fn test_truncated_optional() {
        let mut pkt = Vec::new();
        // S flag set → needs 12 bytes
        pkt.push(0x32);
        pkt.push(0xFF);
        pkt.extend_from_slice(&4u16.to_be_bytes()); // length=4
        pkt.extend_from_slice(&0u32.to_be_bytes()); // TEID
        // Only 8 bytes, but optional fields need 12
        // Add 4 bytes of payload so length field is satisfied
        // but optional fields are missing
        pkt.extend_from_slice(&[0u8; 4]);

        // Actually the length check passes (8+4=12), but we only have
        // the mandatory header. The data is exactly 12 bytes but the
        // optional field parsing should work. Let me construct a proper
        // truncated case: length says 4 bytes of payload but we don't
        // have enough bytes for the optional header.
        let mut pkt2 = Vec::new();
        pkt2.push(0x32); // S=1
        pkt2.push(0xFF);
        pkt2.extend_from_slice(&4u16.to_be_bytes()); // length=4
        pkt2.extend_from_slice(&0u32.to_be_bytes()); // TEID
        // 8 bytes total, need 12 for optional fields, but length says
        // total = 8+4=12 and we only have 8 bytes of data
        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&pkt2, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    #[test]
    fn test_echo_request() {
        let mut pkt = Vec::new();
        // Echo Request: Version=1, PT=1, S=1 (mandatory for Echo)
        // 001 1 0 0 1 0 = 0x32
        pkt.push(0x32);
        // Message Type = 1 (Echo Request)
        pkt.push(0x01);
        // Length = 4 (seq + npdu + next ext)
        pkt.extend_from_slice(&4u16.to_be_bytes());
        // TEID = 0 (for Echo Request)
        pkt.extend_from_slice(&0u32.to_be_bytes());
        // Sequence Number
        pkt.extend_from_slice(&0x0001u16.to_be_bytes());
        // N-PDU Number
        pkt.push(0x00);
        // Next Extension Header Type
        pkt.push(0x00);

        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 12);
        // Echo Request has no T-PDU payload → None
        assert_eq!(result.next, DispatchHint::End);

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "message_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("Echo Request")
        );
        assert_eq!(
            buf.field_by_name(layer, "teid").unwrap().value,
            FieldValue::U32(0)
        );
    }

    #[test]
    fn test_length_exceeds_data() {
        let mut pkt = Vec::new();
        pkt.push(0x30);
        pkt.push(0xFF);
        // Length = 100 but we provide very little data
        pkt.extend_from_slice(&100u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // TEID
        // Only 8 bytes total, length says 108

        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    #[test]
    fn test_extension_headers() {
        let mut pkt = Vec::new();
        // Version=1, PT=1, E=1
        // 001 1 0 1 0 0 = 0x34
        pkt.push(0x34);
        // Message Type = 255 (G-PDU)
        pkt.push(0xFF);
        // Length placeholder (will fix)
        let len_pos = pkt.len();
        pkt.extend_from_slice(&0u16.to_be_bytes());
        // TEID
        pkt.extend_from_slice(&0x11223344u32.to_be_bytes());
        // Sequence Number (present but not meaningful when only E set)
        pkt.extend_from_slice(&0u16.to_be_bytes());
        // N-PDU Number
        pkt.push(0x00);
        // Next Extension Header Type = 0x85 (PDU Session Container)
        pkt.push(0x85);

        // Extension header: PDU Session Container
        // Length = 1 (4 bytes total)
        pkt.push(0x01);
        // Content: 2 bytes
        pkt.extend_from_slice(&[0x09, 0x00]);
        // Next Extension Header Type = 0 (no more)
        pkt.push(0x00);

        // Payload: IPv4 stub
        pkt.push(0x45);
        pkt.extend_from_slice(&[0u8; 19]);

        // Fix length: everything after first 8 bytes
        let length = (pkt.len() - MIN_HEADER_SIZE) as u16;
        pkt[len_pos..len_pos + 2].copy_from_slice(&length.to_be_bytes());

        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        // Header: 12 base + 4 extension = 16
        assert_eq!(result.bytes_consumed, 16);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "e").unwrap().value,
            FieldValue::U8(1)
        );

        let ext_headers = buf.field_by_name(layer, "extension_headers").unwrap();
        let ext_range = ext_headers.value.as_container_range().unwrap();
        let elems = buf.nested_fields(ext_range);
        // One Object container
        assert!(elems[0].value.is_object());
        let obj_range = elems[0].value.as_container_range().unwrap();
        let ext = buf.nested_fields(obj_range);
        let ext_type = ext.iter().find(|f| f.name() == "type").unwrap();
        assert_eq!(ext_type.value, FieldValue::U8(0x85));
        let ext_content = ext.iter().find(|f| f.name() == "content").unwrap();
        assert_eq!(ext_content.value, FieldValue::Bytes(&[0x09, 0x00]));
    }

    #[test]
    fn extension_header_container_resolves_to_type_name() {
        let mut pkt = Vec::new();
        // Version=1, PT=1, E=1 → 0x34
        pkt.push(0x34);
        pkt.push(0xFF); // Message Type = G-PDU
        let len_pos = pkt.len();
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0x11223344u32.to_be_bytes()); // TEID
        pkt.extend_from_slice(&0u16.to_be_bytes()); // Sequence Number
        pkt.push(0x00); // N-PDU Number
        pkt.push(0x85); // Next Extension Header Type = PDU Session Container

        // Extension header: type carried via next-field above
        pkt.push(0x01); // Length = 1 (4 bytes)
        pkt.extend_from_slice(&[0x09, 0x00]); // content
        pkt.push(0x00); // Next Extension Header Type = 0

        // Payload: IPv4 stub
        pkt.push(0x45);
        pkt.extend_from_slice(&[0u8; 19]);

        let length = (pkt.len() - MIN_HEADER_SIZE) as u16;
        pkt[len_pos..len_pos + 2].copy_from_slice(&length.to_be_bytes());

        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let ext_headers = buf.field_by_name(layer, "extension_headers").unwrap();
        let ext_range = ext_headers.value.as_container_range().unwrap().clone();
        let elems = buf.nested_fields(&ext_range);
        let (offset, object) = elems
            .iter()
            .enumerate()
            .find(|(_, f)| matches!(f.value, FieldValue::Object(_)))
            .expect("extension header Object must be present");
        assert_eq!(object.descriptor.display_name, "Extension Header");
        let obj_idx = ext_range.start + offset as u32;
        assert_eq!(
            buf.resolve_container_display_name(obj_idx),
            Some("PDU Session Container"),
        );
    }

    #[test]
    fn test_extension_header_truncated() {
        let mut pkt = Vec::new();
        // E=1
        pkt.push(0x34);
        pkt.push(0xFF);
        // Length covers optional fields + extension header that exceeds data
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // TEID
        // Optional fields
        pkt.extend_from_slice(&0u16.to_be_bytes()); // seq
        pkt.push(0x00); // npdu
        pkt.push(0x85); // next ext type = 0x85

        // Extension header: length=2 (8 bytes) but only 2 bytes available
        pkt.push(0x02);
        pkt.push(0x00);
        // Missing 6 more bytes

        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    #[test]
    fn test_extension_header_zero_length() {
        let mut pkt = Vec::new();
        // E=1
        pkt.push(0x34);
        pkt.push(0xFF);
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.push(0x00);
        pkt.push(0x85); // next ext type

        // Extension header with length = 0 (invalid)
        pkt.push(0x00);
        pkt.extend_from_slice(&[0u8; 7]);

        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidHeader(_) | PacketError::InvalidFieldValue { .. }
        ));
    }

    #[test]
    fn test_gpdu_ipv6_payload() {
        let mut pkt = Vec::new();
        pkt.push(0x30); // no optional flags
        pkt.push(0xFF); // G-PDU
        pkt.extend_from_slice(&40u16.to_be_bytes()); // length = 40 (IPv6 header)
        pkt.extend_from_slice(&0xDEADBEEFu32.to_be_bytes()); // TEID
        // IPv6 stub: version nibble = 6
        pkt.push(0x60); // Version=6
        pkt.extend_from_slice(&[0u8; 39]);

        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn test_end_marker() {
        let mut pkt = Vec::new();
        // Version=1, PT=1, no flags
        pkt.push(0x30);
        // Message Type = 254 (End Marker)
        pkt.push(0xFE);
        // Length = 0 (no payload)
        pkt.extend_from_slice(&0u16.to_be_bytes());
        // TEID
        pkt.extend_from_slice(&0x00000001u32.to_be_bytes());

        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::End);

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "message_type").unwrap().value,
            FieldValue::U8(254)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("End Marker")
        );
    }

    #[test]
    fn test_message_type_name() {
        // Known types
        assert_eq!(gtpv1u_message_type_name(1), Some("Echo Request"));
        assert_eq!(gtpv1u_message_type_name(2), Some("Echo Response"));
        assert_eq!(gtpv1u_message_type_name(26), Some("Error Indication"));
        assert_eq!(
            gtpv1u_message_type_name(31),
            Some("Supported Extension Headers Notification")
        );
        assert_eq!(gtpv1u_message_type_name(254), Some("End Marker"));
        assert_eq!(gtpv1u_message_type_name(255), Some("G-PDU"));
        // Unknown types return None
        assert_eq!(gtpv1u_message_type_name(0), None);
        assert_eq!(gtpv1u_message_type_name(100), None);
    }

    #[test]
    fn test_multiple_extension_headers() {
        let mut pkt = Vec::new();
        // Version=1, PT=1, E=1
        pkt.push(0x34);
        pkt.push(0xFF); // G-PDU
        let len_pos = pkt.len();
        pkt.extend_from_slice(&0u16.to_be_bytes()); // length placeholder
        pkt.extend_from_slice(&0x00000001u32.to_be_bytes()); // TEID
        pkt.extend_from_slice(&0u16.to_be_bytes()); // seq
        pkt.push(0x00); // npdu
        pkt.push(0x85); // next ext type = PDU Session Container

        // First extension header (4 bytes)
        pkt.push(0x01); // length = 1 (4 bytes)
        pkt.extend_from_slice(&[0x01, 0x02]); // content
        pkt.push(0x40); // next ext type = UDP Port

        // Second extension header (4 bytes)
        pkt.push(0x01); // length = 1 (4 bytes)
        pkt.extend_from_slice(&[0xAB, 0xCD]); // content
        pkt.push(0x00); // no more

        // Payload: IPv4 stub
        pkt.push(0x45);
        pkt.extend_from_slice(&[0u8; 19]);

        // Fix length
        let length = (pkt.len() - MIN_HEADER_SIZE) as u16;
        pkt[len_pos..len_pos + 2].copy_from_slice(&length.to_be_bytes());

        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        // 12 base + 4 + 4 = 20
        assert_eq!(result.bytes_consumed, 20);

        let layer = &buf.layers()[0];
        let ext_headers = buf.field_by_name(layer, "extension_headers").unwrap();
        let ext_range = ext_headers.value.as_container_range().unwrap();
        let elems = buf.nested_fields(ext_range);
        let objs: Vec<_> = elems.iter().filter(|f| f.value.is_object()).collect();
        assert_eq!(objs.len(), 2);

        // First: type 0x85
        let first_range = objs[0].value.as_container_range().unwrap();
        let first = buf.nested_fields(first_range);
        assert_eq!(
            first.iter().find(|f| f.name() == "type").unwrap().value,
            FieldValue::U8(0x85)
        );
        // Second: type 0x40
        let second_range = objs[1].value.as_container_range().unwrap();
        let second = buf.nested_fields(second_range);
        assert_eq!(
            second.iter().find(|f| f.name() == "type").unwrap().value,
            FieldValue::U8(0x40)
        );
    }

    #[test]
    fn test_with_nonzero_offset() {
        // Simulate being called after Ethernet+IPv4+UDP headers
        let offset = 42; // typical Eth(14) + IPv4(20) + UDP(8)
        let data = make_gpdu_basic();
        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&data, &mut buf, offset).unwrap();

        assert_eq!(result.bytes_consumed, 8);
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 42..50);
        // Field ranges should be offset-adjusted
        assert_eq!(buf.field_by_name(layer, "version").unwrap().range, 42..43);
        assert_eq!(buf.field_by_name(layer, "teid").unwrap().range, 46..50);
    }
}
