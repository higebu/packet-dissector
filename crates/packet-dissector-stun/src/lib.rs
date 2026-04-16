//! STUN (Session Traversal Utilities for NAT) dissector.
//!
//! ## References
//! - RFC 8489 (Obsoletes RFC 5389): <https://www.rfc-editor.org/rfc/rfc8489>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// STUN header size in bytes.
///
/// RFC 8489, Section 5 — <https://www.rfc-editor.org/rfc/rfc8489#section-5>.
const HEADER_SIZE: usize = 20;

/// STUN magic cookie value.
///
/// RFC 8489, Section 5 — "The Magic Cookie field MUST contain the fixed value
/// 0x2112A442 in network byte order."
/// <https://www.rfc-editor.org/rfc/rfc8489#section-5>.
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Minimum attribute size: Type(2) + Length(2).
///
/// RFC 8489, Section 14 — "After the STUN header are zero or more attributes.
/// Each attribute MUST be TLV encoded, with a 16-bit type, 16-bit length, and
/// value." <https://www.rfc-editor.org/rfc/rfc8489#section-14>.
const MIN_ATTR_SIZE: usize = 4;

/// Returns a human-readable name for the STUN message class.
///
/// RFC 8489, Section 5 — Message class values —
/// <https://www.rfc-editor.org/rfc/rfc8489#section-5>.
fn class_name(class: u8) -> &'static str {
    match class {
        0b00 => "Request",
        0b01 => "Indication",
        0b10 => "Success Response",
        0b11 => "Error Response",
        _ => unreachable!(),
    }
}

/// Returns a human-readable name for the STUN method.
///
/// RFC 8489, Section 18.2 — STUN Methods Registry —
/// <https://www.rfc-editor.org/rfc/rfc8489#section-18.2>.
fn method_name(method: u16) -> Option<&'static str> {
    match method {
        0x001 => Some("Binding"),
        _ => None,
    }
}

/// Returns a human-readable name for a STUN attribute type.
///
/// RFC 8489, Section 18.3 — STUN Attributes Registry —
/// <https://www.rfc-editor.org/rfc/rfc8489#section-18.3>.
pub fn attribute_type_name(attr_type: u16) -> Option<&'static str> {
    match attr_type {
        // Comprehension-required range (0x0000-0x7FFF).
        0x0001 => Some("MAPPED-ADDRESS"),
        0x0006 => Some("USERNAME"),
        0x0008 => Some("MESSAGE-INTEGRITY"),
        0x0009 => Some("ERROR-CODE"),
        0x000A => Some("UNKNOWN-ATTRIBUTES"),
        0x0014 => Some("REALM"),
        0x0015 => Some("NONCE"),
        0x001C => Some("MESSAGE-INTEGRITY-SHA256"),
        0x001D => Some("PASSWORD-ALGORITHM"),
        0x001E => Some("USERHASH"),
        0x0020 => Some("XOR-MAPPED-ADDRESS"),
        // Comprehension-optional range (0x8000-0xFFFF).
        0x8002 => Some("PASSWORD-ALGORITHMS"),
        0x8003 => Some("ALTERNATE-DOMAIN"),
        0x8022 => Some("SOFTWARE"),
        0x8023 => Some("ALTERNATE-SERVER"),
        0x8028 => Some("FINGERPRINT"),
        _ => None,
    }
}

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_MESSAGE_TYPE: usize = 0;
const FD_MESSAGE_CLASS: usize = 1;
const FD_MESSAGE_METHOD: usize = 2;
const FD_MESSAGE_LENGTH: usize = 3;
const FD_MAGIC_COOKIE: usize = 4;
const FD_TRANSACTION_ID: usize = 5;
const FD_ATTRIBUTES: usize = 6;

/// Field descriptor indices for [`ATTR_CHILD_FIELDS`].
const AFD_TYPE: usize = 0;
const AFD_LENGTH: usize = 1;
const AFD_VALUE: usize = 2;

/// Child field descriptors for attribute Array elements.
///
/// RFC 8489, Section 14 — Each attribute is TLV-encoded —
/// <https://www.rfc-editor.org/rfc/rfc8489#section-14>.
static ATTR_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Attribute Type",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(t) => attribute_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Attribute Length", FieldType::U16),
    FieldDescriptor::new("value", "Value", FieldType::Bytes),
];

/// Field descriptors for the STUN dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("message_type", "Message Type", FieldType::U16),
    FieldDescriptor {
        name: "message_class",
        display_name: "Message Class",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(c) => Some(class_name(*c)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "message_method",
        display_name: "Message Method",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(m) => method_name(*m),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("message_length", "Message Length", FieldType::U16),
    FieldDescriptor::new("magic_cookie", "Magic Cookie", FieldType::U32),
    FieldDescriptor::new("transaction_id", "Transaction ID", FieldType::Bytes),
    FieldDescriptor::new("attributes", "Attributes", FieldType::Array)
        .optional()
        .with_children(ATTR_CHILD_FIELDS),
];

/// Decode the STUN message type into class and method.
///
/// RFC 8489, Section 5, Figure 3 — The message type field uses a non-contiguous
/// bit layout:
///
/// ```text
///         0                 1
///         2  3  4 5 6 7 8 9 0 1 2 3 4 5
///        +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
///        |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
///        |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
///        +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// <https://www.rfc-editor.org/rfc/rfc8489#section-5>.
fn decode_message_type(raw_type: u16) -> (u8, u16) {
    // RFC 8489, Section 5 — https://www.rfc-editor.org/rfc/rfc8489#section-5
    // C0 is at bit 4, C1 at bit 8 of the 14-bit message type value.
    let c0 = (raw_type >> 4) & 0x1;
    let c1 = (raw_type >> 8) & 0x1;
    let class = ((c1 << 1) | c0) as u8;

    // Method bits:
    //   M0-M3  → bits 0-3  (mask 0x000F)
    //   M4-M6  → bits 5-7  (mask 0x00E0, shift right by 1 to skip C0 at bit 4)
    //   M7-M11 → bits 9-13 (mask 0x3E00, shift right by 2 to skip C0 and C1)
    let method = (raw_type & 0x000F) | ((raw_type & 0x00E0) >> 1) | ((raw_type & 0x3E00) >> 2);

    (class, method)
}

/// Push STUN attributes into a [`DissectBuffer`].
///
/// RFC 8489, Section 14 — Each attribute is TLV-encoded with 4-byte alignment —
/// <https://www.rfc-editor.org/rfc/rfc8489#section-14>.
fn push_attrs<'pkt>(attr_data: &'pkt [u8], buf_offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let mut pos = 0;

    while pos + MIN_ATTR_SIZE <= attr_data.len() {
        let attr_type = read_be_u16(attr_data, pos).unwrap_or_default();
        let attr_len = read_be_u16(attr_data, pos + 2).unwrap_or_default() as usize;

        // RFC 8489, Section 14 — "The value in the Length field MUST contain
        // the length of the Value part of the attribute, prior to padding,
        // measured in bytes." Length excludes the 4-byte TLV header and any
        // trailing padding bytes.
        // https://www.rfc-editor.org/rfc/rfc8489#section-14
        if pos + MIN_ATTR_SIZE + attr_len > attr_data.len() {
            break;
        }

        let abs = buf_offset + pos;
        let value_data = &attr_data[pos + MIN_ATTR_SIZE..pos + MIN_ATTR_SIZE + attr_len];

        let obj_idx = buf.begin_container(
            &ATTR_CHILD_FIELDS[AFD_TYPE],
            FieldValue::Object(0..0),
            abs..abs + MIN_ATTR_SIZE + attr_len,
        );
        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_TYPE],
            FieldValue::U16(attr_type),
            abs..abs + 2,
        );
        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_LENGTH],
            FieldValue::U16(attr_len as u16),
            abs + 2..abs + 4,
        );
        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_VALUE],
            FieldValue::Bytes(value_data),
            abs + MIN_ATTR_SIZE..abs + MIN_ATTR_SIZE + attr_len,
        );
        buf.end_container(obj_idx);

        // RFC 8489, Section 14 — "STUN aligns attributes on 32-bit boundaries,
        // attributes whose content is not a multiple of 4 bytes are padded
        // with 1, 2, or 3 bytes of padding so that its value contains a
        // multiple of 4 bytes."
        // https://www.rfc-editor.org/rfc/rfc8489#section-14
        let padded_len = MIN_ATTR_SIZE + attr_len.next_multiple_of(4);
        pos += padded_len;
    }
}

/// STUN dissector.
pub struct StunDissector;

impl Dissector for StunDissector {
    fn name(&self) -> &'static str {
        "Session Traversal Utilities for NAT"
    }

    fn short_name(&self) -> &'static str {
        "STUN"
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
        // RFC 8489, Section 5 — STUN header is 20 bytes.
        // https://www.rfc-editor.org/rfc/rfc8489#section-5
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 8489, Section 5 — "The most significant 2 bits of every STUN
        // message MUST be zeroes."
        // https://www.rfc-editor.org/rfc/rfc8489#section-5
        if data[0] & 0xC0 != 0 {
            return Err(PacketError::InvalidHeader(
                "top 2 bits of STUN message must be zero",
            ));
        }

        // RFC 8489, Section 5 — STUN Message Type (14 bits, bytes 0-1).
        // https://www.rfc-editor.org/rfc/rfc8489#section-5
        let raw_type = read_be_u16(data, 0)? & 0x3FFF;
        let (class, method) = decode_message_type(raw_type);

        // RFC 8489, Section 5 — Message Length (bytes 2-3).
        // https://www.rfc-editor.org/rfc/rfc8489#section-5
        let msg_len_raw = read_be_u16(data, 2)?;
        let msg_len = msg_len_raw as usize;

        // RFC 8489, Section 5 — "The message length MUST contain the size, in
        // bytes, of the message not including the 20-byte STUN header. Since all
        // STUN attributes are padded to a multiple of 4 bytes, the last 2 bits
        // of this field are always zero."
        // https://www.rfc-editor.org/rfc/rfc8489#section-5
        if msg_len % 4 != 0 {
            return Err(PacketError::InvalidHeader(
                "STUN message length must be a multiple of 4",
            ));
        }

        // RFC 8489, Section 5 — Magic Cookie (bytes 4-7).
        // https://www.rfc-editor.org/rfc/rfc8489#section-5
        let cookie = read_be_u32(data, 4)?;
        if cookie != MAGIC_COOKIE {
            return Err(PacketError::InvalidFieldValue {
                field: "magic_cookie",
                value: cookie,
            });
        }

        // RFC 8489, Section 5 — Transaction ID (bytes 8-19, 96 bits).
        // https://www.rfc-editor.org/rfc/rfc8489#section-5
        let transaction_id = &data[8..20];

        let total_len = HEADER_SIZE + msg_len;
        if data.len() < total_len {
            return Err(PacketError::Truncated {
                expected: total_len,
                actual: data.len(),
            });
        }

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_len,
        );

        // Build header fields.
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_TYPE],
            FieldValue::U16(raw_type),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_CLASS],
            FieldValue::U8(class),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_METHOD],
            FieldValue::U16(method),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_LENGTH],
            FieldValue::U16(msg_len_raw),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MAGIC_COOKIE],
            FieldValue::U32(cookie),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TRANSACTION_ID],
            FieldValue::Bytes(transaction_id),
            offset + 8..offset + 20,
        );

        // RFC 8489, Section 14 — Parse STUN attributes (TLV).
        // https://www.rfc-editor.org/rfc/rfc8489#section-14
        if msg_len > 0 {
            let attr_data = &data[HEADER_SIZE..total_len];
            let array_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_ATTRIBUTES],
                FieldValue::Array(0..0),
                offset + HEADER_SIZE..offset + total_len,
            );
            push_attrs(attr_data, offset + HEADER_SIZE, buf);
            buf.end_container(array_idx);
        }

        buf.end_layer();

        Ok(DissectResult::new(total_len, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 8489 Coverage
    //
    // | RFC Section | Description                           | Test                                    |
    // |-------------|---------------------------------------|-----------------------------------------|
    // | 5           | Header: top 2 bits must be zero       | test_invalid_top_bits                   |
    // | 5           | Header: Message Type (class+method)   | test_parse_binding_request              |
    // | 5           | Header: Message Length                | test_parse_binding_request              |
    // | 5           | Header: Message Length multiple of 4  | test_message_length_not_multiple_of_4   |
    // | 5           | Header: Magic Cookie                  | test_parse_binding_request              |
    // | 5           | Header: Magic Cookie validation       | test_invalid_magic_cookie               |
    // | 5           | Header: Transaction ID                | test_parse_binding_request              |
    // | 5           | Message class: Request                | test_parse_binding_request              |
    // | 5           | Message class: Success Response       | test_parse_binding_response             |
    // | 5           | Message class: Indication             | test_parse_binding_indication           |
    // | 5           | Message class: Error Response         | test_parse_binding_error_response       |
    // | 5           | Truncated header                      | test_truncated_header                   |
    // | 5           | Truncated attributes                  | test_truncated_attributes               |
    // | 14          | TLV attribute parsing                 | test_parse_binding_response             |
    // | 14          | Multiple attributes                   | test_multiple_attributes                |
    // | 14          | 4-byte attribute padding              | test_attribute_with_non_aligned_length  |
    // | 18.2        | Method: Binding (0x001)               | test_parse_binding_request              |
    // | 18.3        | Attribute Registry (codes & names)    | test_attribute_type_name_lookup         |

    /// Build a STUN message from parts.
    fn build_stun(class: u8, method: u16, attrs: &[u8]) -> Vec<u8> {
        // Encode message type from class and method.
        // RFC 8489, Section 14.1
        let c0 = (class & 0x1) as u16;
        let c1 = ((class >> 1) & 0x1) as u16;
        let m0_3 = method & 0x000F;
        let m4_6 = (method & 0x0070) << 1;
        let m7_11 = (method & 0x0F80) << 2;
        let raw_type = m7_11 | c1 << 8 | m4_6 | c0 << 4 | m0_3;

        let msg_len = attrs.len() as u16;
        let mut pkt = Vec::with_capacity(HEADER_SIZE + attrs.len());
        pkt.extend_from_slice(&raw_type.to_be_bytes());
        pkt.extend_from_slice(&msg_len.to_be_bytes());
        pkt.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        // Transaction ID: 12 bytes
        pkt.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ]);
        pkt.extend_from_slice(attrs);
        pkt
    }

    /// Build a TLV attribute with padding.
    fn build_attr(attr_type: u16, value: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&attr_type.to_be_bytes());
        buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        buf.extend_from_slice(value);
        // Pad to 4-byte boundary.
        let pad = (4 - (value.len() % 4)) % 4;
        buf.extend(core::iter::repeat_n(0u8, pad));
        buf
    }

    #[test]
    fn test_parse_binding_request() {
        // STUN Binding Request: class=0b00, method=0x001, no attributes.
        let data = build_stun(0b00, 0x001, &[]);
        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(buf.layers().len(), 1);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "STUN");
        assert_eq!(layer.range, 0..20);

        // Message type: Binding Request → raw_type = 0x0001
        assert_eq!(
            buf.field_by_name(layer, "message_type").unwrap().value,
            FieldValue::U16(0x0001)
        );
        assert_eq!(
            buf.field_by_name(layer, "message_class").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_class_name"),
            Some("Request")
        );
        assert_eq!(
            buf.field_by_name(layer, "message_method").unwrap().value,
            FieldValue::U16(0x001)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_method_name"),
            Some("Binding")
        );
        assert_eq!(
            buf.field_by_name(layer, "message_length").unwrap().value,
            FieldValue::U16(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "magic_cookie").unwrap().value,
            FieldValue::U32(MAGIC_COOKIE)
        );
        assert_eq!(
            buf.field_by_name(layer, "transaction_id").unwrap().value,
            FieldValue::Bytes(&[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C
            ])
        );
        // No attributes field when message_length is 0.
        assert!(buf.field_by_name(layer, "attributes").is_none());
    }

    /// Helper: find the nth Object entry within an Array's nested fields.
    fn nth_object_range(
        buf: &DissectBuffer,
        array_range: &core::ops::Range<u32>,
        index: usize,
    ) -> core::ops::Range<u32> {
        let children = buf.nested_fields(array_range);
        let mut obj_count = 0;
        for field in children {
            if let FieldValue::Object(r) = &field.value {
                if obj_count == index {
                    return r.clone();
                }
                obj_count += 1;
            }
        }
        panic!("Object at index {index} not found");
    }

    /// Helper: count Object entries within an Array's nested fields.
    fn count_objects(buf: &DissectBuffer, array_range: &core::ops::Range<u32>) -> usize {
        buf.nested_fields(array_range)
            .iter()
            .filter(|f| matches!(f.value, FieldValue::Object(_)))
            .count()
    }

    #[test]
    fn test_parse_binding_response() {
        // STUN Binding Success Response with XOR-MAPPED-ADDRESS attribute.
        // XOR-MAPPED-ADDRESS (0x0020): 8 bytes value.
        let xor_mapped = build_attr(0x0020, &[0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43]);
        let data = build_stun(0b10, 0x001, &xor_mapped);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        // class = 0b10 → Success Response
        assert_eq!(
            buf.field_by_name(layer, "message_class").unwrap().value,
            FieldValue::U8(0b10)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_class_name"),
            Some("Success Response")
        );

        // Check attribute
        let attrs_field = buf.field_by_name(layer, "attributes").unwrap();
        if let FieldValue::Array(ref array_range) = attrs_field.value {
            assert_eq!(count_objects(&buf, array_range), 1);
            let obj_range = nth_object_range(&buf, array_range, 0);
            let fields = buf.nested_fields(&obj_range);
            let type_field = fields.iter().find(|f| f.name() == "type").unwrap();
            assert_eq!(type_field.value, FieldValue::U16(0x0020));
            let value_field = fields.iter().find(|f| f.name() == "value").unwrap();
            assert_eq!(
                value_field.value,
                FieldValue::Bytes(&[0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43])
            );
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn test_parse_binding_indication() {
        // STUN Binding Indication: class=0b01, method=0x001.
        let data = build_stun(0b01, 0x001, &[]);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "message_class").unwrap().value,
            FieldValue::U8(0b01)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_class_name"),
            Some("Indication")
        );
    }

    #[test]
    fn test_parse_binding_error_response() {
        // STUN Binding Error Response with ERROR-CODE attribute (0x0009).
        // ERROR-CODE: 4 bytes header (reserved + class + number) + reason phrase.
        let error_value = [
            0x00, 0x00, // reserved
            0x04, // class = 4
            0x01, // number = 01 → error 401
            b'U', b'n', b'a', b'u', b't', b'h', b'o', b'r',
        ];
        let error_attr = build_attr(0x0009, &error_value);
        let data = build_stun(0b11, 0x001, &error_attr);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "message_class").unwrap().value,
            FieldValue::U8(0b11)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_class_name"),
            Some("Error Response")
        );

        let attrs_field = buf.field_by_name(layer, "attributes").unwrap();
        if let FieldValue::Array(ref array_range) = attrs_field.value {
            assert_eq!(count_objects(&buf, array_range), 1);
            let obj_range = nth_object_range(&buf, array_range, 0);
            let fields = buf.nested_fields(&obj_range);
            let type_field = fields.iter().find(|f| f.name() == "type").unwrap();
            assert_eq!(type_field.value, FieldValue::U16(0x0009));
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn test_invalid_magic_cookie() {
        let mut data = build_stun(0b00, 0x001, &[]);
        // Corrupt magic cookie (bytes 4-7).
        data[4] = 0x00;
        data[5] = 0x00;
        data[6] = 0x00;
        data[7] = 0x00;

        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "magic_cookie");
            }
            other => panic!("Expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn test_truncated_header() {
        let data = [0u8; 19];
        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, 20);
                assert_eq!(actual, 19);
            }
            other => panic!("Expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn test_truncated_attributes() {
        // Build a valid header claiming 8 bytes of attributes, but only provide 4.
        let mut data = build_stun(0b00, 0x001, &[]);
        // Set message length to 8 in header.
        data[2] = 0x00;
        data[3] = 0x08;
        // Only 20 bytes total (header only), but claims 20 + 8 = 28.

        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, 28);
                assert_eq!(actual, 20);
            }
            other => panic!("Expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn test_message_length_not_multiple_of_4() {
        let mut data = build_stun(0b00, 0x001, &[]);
        // Set message length to 3 (not multiple of 4).
        data[2] = 0x00;
        data[3] = 0x03;

        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("multiple of 4"));
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn test_invalid_top_bits() {
        let mut data = build_stun(0b00, 0x001, &[]);
        // Set top 2 bits to non-zero.
        data[0] |= 0x80;

        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("top 2 bits"));
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn test_multiple_attributes() {
        // Two attributes: SOFTWARE (0x8022) and FINGERPRINT (0x8028).
        let software = build_attr(0x8022, b"test");
        let fingerprint = build_attr(0x8028, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&software);
        attrs.extend_from_slice(&fingerprint);

        let data = build_stun(0b00, 0x001, &attrs);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let attrs_field = buf.field_by_name(layer, "attributes").unwrap();
        if let FieldValue::Array(ref array_range) = attrs_field.value {
            assert_eq!(count_objects(&buf, array_range), 2);
            // First attribute: SOFTWARE
            let obj0 = nth_object_range(&buf, array_range, 0);
            let fields0 = buf.nested_fields(&obj0);
            let type_field = fields0.iter().find(|f| f.name() == "type").unwrap();
            assert_eq!(type_field.value, FieldValue::U16(0x8022));
            // Second attribute: FINGERPRINT
            let obj1 = nth_object_range(&buf, array_range, 1);
            let fields1 = buf.nested_fields(&obj1);
            let type_field = fields1.iter().find(|f| f.name() == "type").unwrap();
            assert_eq!(type_field.value, FieldValue::U16(0x8028));
            let value_field = fields1.iter().find(|f| f.name() == "value").unwrap();
            assert_eq!(
                value_field.value,
                FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
            );
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn test_dissect_with_offset() {
        let data = build_stun(0b00, 0x001, &[]);
        let offset = 42;
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, offset).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(layer.range, offset..offset + HEADER_SIZE);
        assert_eq!(
            buf.field_by_name(layer, "transaction_id").unwrap().range,
            offset + 8..offset + 20
        );
    }

    #[test]
    fn test_field_descriptors() {
        let descriptors = StunDissector.field_descriptors();
        assert_eq!(descriptors.len(), 7);
        assert_eq!(descriptors[0].name, "message_type");
        assert_eq!(descriptors[6].name, "attributes");
        assert!(descriptors[6].children.is_some());
    }

    #[test]
    fn test_attribute_type_name_lookup() {
        // RFC 8489, Section 18.3 — https://www.rfc-editor.org/rfc/rfc8489#section-18.3
        // Comprehension-required range (0x0000-0x7FFF).
        assert_eq!(attribute_type_name(0x0001), Some("MAPPED-ADDRESS"));
        assert_eq!(attribute_type_name(0x0006), Some("USERNAME"));
        assert_eq!(attribute_type_name(0x0008), Some("MESSAGE-INTEGRITY"));
        assert_eq!(attribute_type_name(0x0009), Some("ERROR-CODE"));
        assert_eq!(attribute_type_name(0x000A), Some("UNKNOWN-ATTRIBUTES"));
        assert_eq!(attribute_type_name(0x0014), Some("REALM"));
        assert_eq!(attribute_type_name(0x0015), Some("NONCE"));
        assert_eq!(
            attribute_type_name(0x001C),
            Some("MESSAGE-INTEGRITY-SHA256")
        );
        assert_eq!(attribute_type_name(0x001D), Some("PASSWORD-ALGORITHM"));
        assert_eq!(attribute_type_name(0x001E), Some("USERHASH"));
        assert_eq!(attribute_type_name(0x0020), Some("XOR-MAPPED-ADDRESS"));
        // Comprehension-optional range (0x8000-0xFFFF).
        assert_eq!(attribute_type_name(0x8002), Some("PASSWORD-ALGORITHMS"));
        assert_eq!(attribute_type_name(0x8003), Some("ALTERNATE-DOMAIN"));
        assert_eq!(attribute_type_name(0x8022), Some("SOFTWARE"));
        assert_eq!(attribute_type_name(0x8023), Some("ALTERNATE-SERVER"));
        assert_eq!(attribute_type_name(0x8028), Some("FINGERPRINT"));
        // Reserved or unassigned codepoints return None.
        assert_eq!(attribute_type_name(0x0000), None);
        assert_eq!(attribute_type_name(0x0002), None);
        assert_eq!(attribute_type_name(0x802B), None);
        assert_eq!(attribute_type_name(0xFFFF), None);
    }

    #[test]
    fn test_attribute_with_non_aligned_length() {
        // Attribute with 3-byte value (needs 1 byte of padding).
        let attr = build_attr(0x8022, b"abc");
        let data = build_stun(0b10, 0x001, &attr);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let attrs_field = buf.field_by_name(layer, "attributes").unwrap();
        if let FieldValue::Array(ref array_range) = attrs_field.value {
            assert_eq!(count_objects(&buf, array_range), 1);
            let obj_range = nth_object_range(&buf, array_range, 0);
            let fields = buf.nested_fields(&obj_range);
            let len_field = fields.iter().find(|f| f.name() == "length").unwrap();
            assert_eq!(len_field.value, FieldValue::U16(3));
            let value_field = fields.iter().find(|f| f.name() == "value").unwrap();
            assert_eq!(value_field.value, FieldValue::Bytes(b"abc"));
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn test_attribute_display_name() {
        let attr = build_attr(0x0020, &[0x00; 8]);
        let data = build_stun(0b10, 0x001, &attr);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let attrs_field = buf.field_by_name(layer, "attributes").unwrap();
        if let FieldValue::Array(ref array_range) = attrs_field.value {
            let obj_range = nth_object_range(&buf, array_range, 0);
            assert_eq!(
                buf.resolve_nested_display_name(&obj_range, "type_name"),
                Some("XOR-MAPPED-ADDRESS")
            );
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn test_no_attributes_when_length_zero() {
        let data = build_stun(0b00, 0x001, &[]);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(buf.field_by_name(&buf.layers()[0], "attributes").is_none());
    }
}
