//! L2TPv3 AVP (Attribute Value Pair) parser.
//!
//! ## References
//! - RFC 3931, Section 5.1: <https://www.rfc-editor.org/rfc/rfc3931#section-5.1>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

static FD_INLINE_ATTRIBUTE_TYPE: FieldDescriptor =
    FieldDescriptor::new("attribute_type", "Attribute Type", FieldType::U16);

static FD_INLINE_HIDDEN: FieldDescriptor = FieldDescriptor::new("hidden", "Hidden", FieldType::U8);

static FD_INLINE_LENGTH: FieldDescriptor = FieldDescriptor::new("length", "Length", FieldType::U16);

static FD_INLINE_MANDATORY: FieldDescriptor =
    FieldDescriptor::new("mandatory", "Mandatory", FieldType::U8);

static FD_INLINE_VALUE: FieldDescriptor = FieldDescriptor::new("value", "Value", FieldType::Bytes);

static FD_INLINE_VENDOR_ID: FieldDescriptor =
    FieldDescriptor::new("vendor_id", "Vendor ID", FieldType::U16);

/// Map an L2TPv3 base-protocol Attribute Type (Vendor ID=0) to its AVP name.
///
/// RFC 3931, Section 5.4 — Control Message Attribute Value Pairs.
/// <https://www.rfc-editor.org/rfc/rfc3931#section-5.4>
pub(crate) fn avp_name(attribute_type: u16) -> Option<&'static str> {
    match attribute_type {
        0 => Some("Message Type"),
        1 => Some("Result Code"),
        2 => Some("Protocol Version"),
        3 => Some("Framing Capabilities"),
        4 => Some("Bearer Capabilities"),
        5 => Some("Tie Breaker"),
        6 => Some("Firmware Revision"),
        7 => Some("Host Name"),
        8 => Some("Vendor Name"),
        9 => Some("Assigned Control Connection ID"),
        10 => Some("Receive Window Size"),
        11 => Some("Challenge"),
        13 => Some("Challenge Response"),
        14 => Some("Cause Code"),
        15 => Some("Assigned Session ID"),
        16 => Some("Remote Session ID"),
        18 => Some("Assigned Cookie"),
        19 => Some("Remote End ID"),
        21 => Some("Pseudowire Type"),
        22 => Some("L2-Specific Sublayer"),
        23 => Some("Data Sequencing"),
        24 => Some("Circuit Status"),
        25 => Some("Preferred Language"),
        26 => Some("Control Message Authentication Nonce"),
        27 => Some("Tx Connect Speed"),
        28 => Some("Rx Connect Speed"),
        29 => Some("Failover Capability"),
        30 => Some("Tunnel Recovery"),
        31 => Some("Suggested Control Sequence"),
        32 => Some("Failover Session State"),
        36 => Some("Random Vector"),
        37 => Some("Message Digest"),
        38 => Some("Router ID"),
        39 => Some("Assigned Control Connection ID"),
        40 => Some("Pseudowire Capabilities List"),
        _ => None,
    }
}

/// Container descriptor for an L2TPv3 AVP entry.
///
/// `display_fn` resolves the outer container's label to the AVP name by
/// looking up the inner `vendor_id` and `attribute_type` fields.
/// When `vendor_id == 0`, the Attribute Type is mapped via [`avp_name`];
/// otherwise the label is "Vendor-Specific AVP".
static FD_AVP: FieldDescriptor = FieldDescriptor {
    name: "avp",
    display_name: "AVP",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| {
        let FieldValue::Object(_) = v else {
            return None;
        };
        let vendor_id = children.iter().find_map(|f| match (f.name(), &f.value) {
            ("vendor_id", FieldValue::U16(v)) => Some(*v),
            _ => None,
        })?;
        let attribute_type = children.iter().find_map(|f| match (f.name(), &f.value) {
            ("attribute_type", FieldValue::U16(t)) => Some(*t),
            _ => None,
        })?;
        if vendor_id == 0 {
            avp_name(attribute_type)
        } else {
            Some("Vendor-Specific AVP")
        }
    }),
    format_fn: None,
};

/// Minimum AVP size: M(1 bit) + H(1 bit) + rsvd(4 bits) + Length(10 bits) +
/// Vendor ID(16 bits) + Attribute Type(16 bits) = 6 octets.
///
/// RFC 3931, Section 5.1 — "The Length ... is calculated as 6 + the length of
/// the Attribute Value field in octets."
const MIN_AVP_SIZE: usize = 6;

/// AVP child field descriptors for Array elements.
pub(crate) static AVP_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("mandatory", "Mandatory", FieldType::U8),
    FieldDescriptor::new("hidden", "Hidden", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("vendor_id", "Vendor ID", FieldType::U16),
    FieldDescriptor::new("attribute_type", "Attribute Type", FieldType::U16),
    FieldDescriptor::new("value", "Value", FieldType::Bytes),
];

/// Parse a sequence of L2TPv3 AVPs from the given buffer.
///
/// `buf` contains AVP data starting at byte 0. `buf_offset` is the absolute
/// byte position of `buf[0]` in the original packet, used for accurate byte
/// ranges.
///
/// RFC 3931, Section 5.1 — AVP format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |M|H| rsvd  |      Length       |           Vendor ID           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Attribute Type        |        Attribute Value ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub(crate) fn parse_avps<'pkt>(data: &'pkt [u8], buf_offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let mut pos = 0;

    while pos + MIN_AVP_SIZE <= data.len() {
        // RFC 3931, Section 5.1 — First two octets: M, H, reserved, Length
        let Ok(first_word) = read_be_u16(data, pos) else {
            break;
        };

        // Bit 15: Mandatory (M)
        let m_flag = ((first_word >> 15) & 1) as u8;
        // Bit 14: Hidden (H)
        let h_flag = ((first_word >> 14) & 1) as u8;
        // Bits 9-0: Length (10 bits)
        let length = (first_word & 0x03FF) as usize;

        if length < MIN_AVP_SIZE || pos + length > data.len() {
            break;
        }

        // RFC 3931, Section 5.1 — Vendor ID (2 octets)
        let Ok(vendor_id) = read_be_u16(data, pos + 2) else {
            break;
        };
        // RFC 3931, Section 5.1 — Attribute Type (2 octets)
        let Ok(attribute_type) = read_be_u16(data, pos + 4) else {
            break;
        };

        let value_data = &data[pos + MIN_AVP_SIZE..pos + length];

        let abs = buf_offset + pos;
        let obj_idx = buf.begin_container(&FD_AVP, FieldValue::Object(0..0), abs..abs + length);
        buf.push_field(&FD_INLINE_MANDATORY, FieldValue::U8(m_flag), abs..abs + 1);
        buf.push_field(&FD_INLINE_HIDDEN, FieldValue::U8(h_flag), abs..abs + 1);
        buf.push_field(
            &FD_INLINE_LENGTH,
            FieldValue::U16(length as u16),
            abs..abs + 2,
        );
        buf.push_field(
            &FD_INLINE_VENDOR_ID,
            FieldValue::U16(vendor_id),
            abs + 2..abs + 4,
        );
        buf.push_field(
            &FD_INLINE_ATTRIBUTE_TYPE,
            FieldValue::U16(attribute_type),
            abs + 4..abs + 6,
        );
        buf.push_field(
            &FD_INLINE_VALUE,
            FieldValue::Bytes(value_data),
            abs + MIN_AVP_SIZE..abs + length,
        );
        buf.end_container(obj_idx);

        pos += length;
    }
}

/// Extract the message type from the first AVP if it is the Message Type AVP
/// (Vendor ID=0, Attribute Type=0).
///
/// RFC 3931, Section 5.4.1 — "The Message Type AVP ... MUST be the first AVP
/// in a control message."
pub(crate) fn extract_message_type(buf: &[u8]) -> Option<u16> {
    if buf.len() < MIN_AVP_SIZE {
        return None;
    }

    let first_word = read_be_u16(buf, 0).ok()?;
    let length = (first_word & 0x03FF) as usize;

    if length < MIN_AVP_SIZE {
        return None;
    }

    let vendor_id = read_be_u16(buf, 2).ok()?;
    let attribute_type = read_be_u16(buf, 4).ok()?;

    // RFC 3931, Section 5.4.1 — Message Type AVP: Vendor ID=0, Type=0,
    // Value is a 2-byte message type code.
    if vendor_id == 0 && attribute_type == 0 && length >= MIN_AVP_SIZE + 2 && buf.len() >= length {
        Some(read_be_u16(buf, 6).ok()?)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 3931 (L2TPv3 AVP) Coverage
    //
    // | RFC Section | Description            | Test                       |
    // |-------------|------------------------|----------------------------|
    // | 5.1         | AVP format             | parse_avp_basic            |
    // | 5.1         | Mandatory bit          | parse_avp_mandatory        |
    // | 5.1         | Hidden bit             | parse_avp_hidden           |
    // | 5.1         | Multiple AVPs          | parse_avps_multiple        |
    // | 5.1         | Truncated AVP          | parse_avp_truncated        |
    // | 5.1         | Length too small        | parse_avp_length_too_small |
    // | 5.4.1       | Message Type extraction | extract_message_type_sccrq |
    // | 5.4.1       | Non-message-type AVP   | extract_message_type_wrong |

    #[test]
    fn parse_avp_basic() {
        let data: &[u8] = &[0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..8);
        parse_avps(data, 100, &mut buf);
        buf.end_layer();

        let fields = buf.fields();
        // Should have 1 Object container + 6 children = 7 fields
        assert!(fields[0].value.is_object());
        let obj_range = fields[0].value.as_container_range().unwrap();
        let children = buf.nested_fields(obj_range);
        assert_eq!(children.len(), 6);
        assert_eq!(children[0].value, FieldValue::U8(0)); // mandatory
        assert_eq!(children[1].value, FieldValue::U8(0)); // hidden
        assert_eq!(children[2].value, FieldValue::U16(8)); // length
        assert_eq!(children[3].value, FieldValue::U16(0)); // vendor_id
        assert_eq!(children[4].value, FieldValue::U16(0)); // attribute_type
        assert_eq!(children[5].value, FieldValue::Bytes(&[0x00, 0x01])); // value
    }

    #[test]
    fn parse_avp_mandatory() {
        let data: &[u8] = &[0x80, 0x06, 0x00, 0x00, 0x00, 0x63];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..6);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();
        let obj_range = buf.fields()[0].value.as_container_range().unwrap();
        let children = buf.nested_fields(obj_range);
        assert_eq!(children[0].value, FieldValue::U8(1)); // mandatory=1
        assert_eq!(children[1].value, FieldValue::U8(0)); // hidden=0
    }

    #[test]
    fn parse_avp_hidden() {
        let data: &[u8] = &[0x40, 0x06, 0x00, 0x00, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..6);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();
        let obj_range = buf.fields()[0].value.as_container_range().unwrap();
        let children = buf.nested_fields(obj_range);
        assert_eq!(children[0].value, FieldValue::U8(0)); // mandatory=0
        assert_eq!(children[1].value, FieldValue::U8(1)); // hidden=1
    }

    #[test]
    fn parse_avps_multiple() {
        let data: &[u8] = &[
            0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x07, 0x00, 0x00, 0x00, 0x02,
            0xAB,
        ];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..15);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();
        let objs: Vec<_> = buf
            .fields()
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(objs.len(), 2);
        assert_eq!(objs[0].range, 0..8);
        assert_eq!(objs[1].range, 8..15);
    }

    #[test]
    fn parse_avp_truncated() {
        let data: &[u8] = &[0x00, 0x08, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..4);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();
        assert!(buf.fields().iter().all(|f| !f.value.is_object()));
    }

    #[test]
    fn parse_avp_length_too_small() {
        let data: &[u8] = &[0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..6);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();
        assert!(buf.fields().iter().all(|f| !f.value.is_object()));
    }

    #[test]
    fn avp_container_resolves_to_avp_name() {
        // Message Type AVP: Vendor=0, Type=0 → "Message Type".
        let data: &[u8] = &[0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..8);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();

        assert!(buf.fields()[0].value.is_object());
        assert_eq!(buf.fields()[0].descriptor.display_name, "AVP");
        assert_eq!(buf.resolve_container_display_name(0), Some("Message Type"),);
    }

    #[test]
    fn avp_container_vendor_specific_label() {
        // Non-zero Vendor ID → "Vendor-Specific AVP".
        let data: &[u8] = &[0x00, 0x08, 0x12, 0x34, 0x00, 0x01, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..8);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();

        assert!(buf.fields()[0].value.is_object());
        assert_eq!(
            buf.resolve_container_display_name(0),
            Some("Vendor-Specific AVP"),
        );
    }

    #[test]
    fn extract_message_type_sccrq() {
        let buf: &[u8] = &[
            0x80, 0x08, // M=1, Length=8
            0x00, 0x00, // Vendor=0
            0x00, 0x00, // Type=0
            0x00, 0x01, // Value: SCCRQ (1)
        ];
        assert_eq!(extract_message_type(buf), Some(1));
    }

    #[test]
    fn extract_message_type_wrong() {
        // Non-message-type AVP (Vendor=0, Type=2)
        let buf: &[u8] = &[0x80, 0x08, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03];
        assert_eq!(extract_message_type(buf), None);
    }

    #[test]
    fn extract_message_type_empty() {
        assert_eq!(extract_message_type(&[]), None);
    }
}
