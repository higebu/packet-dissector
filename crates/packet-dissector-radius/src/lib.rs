//! RADIUS (Remote Authentication Dial In User Service) dissector.
//!
//! Parses the RADIUS message header (20 bytes) and TLV-encoded attributes.
//! Each attribute is represented as an element in an Array of Objects.
//!
//! ## References
//! - RFC 2865 (RADIUS base protocol): <https://www.rfc-editor.org/rfc/rfc2865>
//! - RFC 2866 (RADIUS Accounting): <https://www.rfc-editor.org/rfc/rfc2866>
//!
//! RFC 2865 is also updated by the following RFCs. They do not alter the
//! wire format parsed here, but are recorded for completeness:
//! - RFC 3575 (IANA Considerations for RADIUS): <https://www.rfc-editor.org/rfc/rfc3575>
//! - RFC 5997 (Use of Status-Server Packets): <https://www.rfc-editor.org/rfc/rfc5997>

#![deny(missing_docs)]

mod attr;

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32, read_ipv4_addr};

use attr::{RadiusAttrType, code_name, enum_value_name, lookup_attr};

/// RADIUS header size: Code(1) + Identifier(1) + Length(2) + Authenticator(16).
///
/// RFC 2865, Section 3 — "A RADIUS packet is a minimum of 20 and maximum of
/// 4096 octets."
/// <https://www.rfc-editor.org/rfc/rfc2865#section-3>
const HEADER_SIZE: usize = 20;

/// Minimum attribute size: Type(1) + Length(1).
///
/// RFC 2865, Section 5 — "The Length field is one octet, and indicates the
/// length of this Attribute including the Type, Length and Value fields."
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5>
const MIN_ATTR_SIZE: usize = 2;

/// Maximum RADIUS packet length.
///
/// RFC 2865, Section 3 — "minimum of 20 and maximum of 4096 octets".
/// <https://www.rfc-editor.org/rfc/rfc2865#section-3>
const MAX_PACKET_LENGTH: usize = 4096;

/// Vendor-Specific attribute type code.
///
/// RFC 2865, Section 5.26 — <https://www.rfc-editor.org/rfc/rfc2865#section-5.26>
const ATTR_VENDOR_SPECIFIC: u8 = 26;

/// Minimum Vendor-Specific value size: Vendor-Id(4).
///
/// The RFC mandates Length >= 7 (i.e. value_data.len() >= 5), but we
/// intentionally accept an empty String portion (value_data.len() == 4) so
/// the Vendor-Id can still be surfaced for minimally malformed inputs
/// (Postel's Law). See RFC 2865, Section 5.26 —
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5.26>.
const MIN_VSA_VALUE_SIZE: usize = 4;

/// Field descriptor indices for [`ATTR_CHILD_FIELDS`].
const AFD_TYPE: usize = 0;
const AFD_LENGTH: usize = 1;
const AFD_NAME: usize = 2;
const AFD_VALUE: usize = 3;
const AFD_VENDOR_ID: usize = 4;
const AFD_VENDOR_DATA: usize = 5;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_CODE: usize = 0;
const FD_IDENTIFIER: usize = 1;
const FD_LENGTH: usize = 2;
const FD_AUTHENTICATOR: usize = 3;
const FD_ATTRIBUTES: usize = 4;

/// Child field descriptors for attribute Array elements.
static ATTR_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Attribute Type", FieldType::U8),
    FieldDescriptor::new("length", "Attribute Length", FieldType::U8),
    FieldDescriptor::new("name", "Attribute Name", FieldType::Str),
    FieldDescriptor {
        name: "value",
        display_name: "Value",
        field_type: FieldType::Bytes,
        optional: false,
        children: None,
        display_fn: Some(|v, siblings| {
            let FieldValue::U32(int_val) = v else {
                return None;
            };
            let attr_type = siblings
                .iter()
                .find(|f| f.name() == "type")
                .and_then(|f| match &f.value {
                    FieldValue::U8(v) => Some(*v),
                    _ => None,
                })?;
            enum_value_name(attr_type, *int_val)
        }),
        format_fn: None,
    },
    FieldDescriptor::new("vendor_id", "Vendor-Id", FieldType::U32).optional(),
    FieldDescriptor::new("vendor_data", "Vendor Data", FieldType::Bytes).optional(),
];

/// Field descriptors for the RADIUS dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "code",
        display_name: "Code",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(c) => Some(code_name(*c)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("identifier", "Identifier", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("authenticator", "Authenticator", FieldType::Bytes),
    FieldDescriptor::new("attributes", "Attributes", FieldType::Array)
        .optional()
        .with_children(ATTR_CHILD_FIELDS),
];

/// Attribute name lookup table for zero-copy attribute name references.
///
/// Returns a static byte slice for the attribute name to avoid String allocation.
fn attr_name_str(attr_type_code: u8) -> &'static str {
    let attr_def = lookup_attr(attr_type_code);
    attr_def.map(|d| d.name).unwrap_or("Unknown")
}

/// Descriptor for the RADIUS attribute Object container.
///
/// `display_fn` is invoked by
/// [`DissectBuffer::resolve_container_display_name`] with the container's
/// children, so the outer label resolves to the attribute name (e.g.
/// "User-Name") instead of colliding with the inner `Attribute Type`
/// field.
static FD_ATTRIBUTE: FieldDescriptor = FieldDescriptor {
    name: "attribute",
    display_name: "Attribute",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(c)) => Some(attr_name_str(*c)),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Parse attribute value according to its type.
///
/// RFC 2865, Section 5 — attribute data types.
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5>
fn parse_attr_value<'pkt>(attr_type: RadiusAttrType, data: &'pkt [u8]) -> FieldValue<'pkt> {
    match attr_type {
        // RFC 2865, Section 5 — "1-253 octets containing UTF-8 encoded
        // 10646 [7] characters".
        // <https://www.rfc-editor.org/rfc/rfc2865#section-5>
        RadiusAttrType::Text => FieldValue::Bytes(data),
        // RFC 2865, Section 5 — "1-253 octets containing binary data
        // (values 0 through 255 decimal, inclusive)".
        // <https://www.rfc-editor.org/rfc/rfc2865#section-5>
        RadiusAttrType::String => FieldValue::Bytes(data),
        // RFC 2865, Section 5 — "32 bit value, most significant octet
        // first".
        // <https://www.rfc-editor.org/rfc/rfc2865#section-5>
        RadiusAttrType::Address if data.len() == 4 => {
            FieldValue::Ipv4Addr(read_ipv4_addr(data, 0).unwrap_or_default())
        }
        // RFC 2865, Section 5 — "32 bit unsigned value, most significant
        // octet first".
        // <https://www.rfc-editor.org/rfc/rfc2865#section-5>
        RadiusAttrType::Integer if data.len() == 4 => {
            FieldValue::U32(read_be_u32(data, 0).unwrap_or_default())
        }
        // Fallback for unexpected sizes or VendorSpecific (handled separately in parse_attrs).
        _ => FieldValue::Bytes(data),
    }
}

/// Parse a slice of attribute bytes and push them into the buffer as
/// Array elements (each is an Object).
///
/// `buf_offset` is the absolute byte position of `attr_data[0]` in the original
/// packet, used to produce accurate `range` values.
fn parse_attrs<'pkt>(buf: &mut DissectBuffer<'pkt>, attr_data: &'pkt [u8], buf_offset: usize) {
    let mut pos = 0;

    while pos + MIN_ATTR_SIZE <= attr_data.len() {
        let attr_type_code = attr_data[pos];
        let attr_len = attr_data[pos + 1] as usize;

        // RFC 2865, Section 5 — "The Length field is one octet, and
        // indicates the length of this Attribute including the Type, Length
        // and Value fields." Stop parsing on malformed lengths.
        // <https://www.rfc-editor.org/rfc/rfc2865#section-5>
        if attr_len < MIN_ATTR_SIZE || pos + attr_len > attr_data.len() {
            break;
        }

        let value_data = &attr_data[pos + 2..pos + attr_len];
        let abs = buf_offset + pos;
        let attr_def = lookup_attr(attr_type_code);

        // Begin Object for this attribute.
        let obj_idx =
            buf.begin_container(&FD_ATTRIBUTE, FieldValue::Object(0..0), abs..abs + attr_len);

        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_TYPE],
            FieldValue::U8(attr_type_code),
            abs..abs + 1,
        );
        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_LENGTH],
            FieldValue::U8(attr_len as u8),
            abs + 1..abs + 2,
        );
        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_NAME],
            FieldValue::Str(attr_name_str(attr_type_code)),
            abs..abs + 1,
        );

        let value_range = abs + 2..abs + attr_len;

        if attr_type_code == ATTR_VENDOR_SPECIFIC && value_data.len() >= MIN_VSA_VALUE_SIZE {
            // RFC 2865, Section 5.26 — Vendor-Specific: Vendor-Id(4) + String.
            // <https://www.rfc-editor.org/rfc/rfc2865#section-5.26>
            let vendor_id = read_be_u32(value_data, 0).unwrap_or_default();
            // Emit raw value bytes for consistent filtering across all attribute types.
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_VALUE],
                FieldValue::Bytes(value_data),
                value_range,
            );
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_VENDOR_ID],
                FieldValue::U32(vendor_id),
                abs + 2..abs + 6,
            );
            let vdata = &value_data[4..];
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_VENDOR_DATA],
                FieldValue::Bytes(vdata),
                abs + 6..abs + attr_len,
            );
        } else {
            let parsed_type = attr_def.map(|d| d.attr_type);
            let value = parsed_type
                .map(|t| parse_attr_value(t, value_data))
                .unwrap_or_else(|| FieldValue::Bytes(value_data));

            buf.push_field(&ATTR_CHILD_FIELDS[AFD_VALUE], value, value_range);
        }

        buf.end_container(obj_idx);
        pos += attr_len;
    }
}

/// RADIUS dissector.
pub struct RadiusDissector;

impl Dissector for RadiusDissector {
    fn name(&self) -> &'static str {
        "RADIUS"
    }

    fn short_name(&self) -> &'static str {
        "RADIUS"
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
        // RFC 2865, Section 3 — Minimum header is 20 bytes.
        // <https://www.rfc-editor.org/rfc/rfc2865#section-3>
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        let code = data[0];
        let identifier = data[1];
        let length = read_be_u16(data, 2)? as usize;

        // RFC 2865, Section 3 — "minimum of 20 and maximum of 4096 octets".
        // <https://www.rfc-editor.org/rfc/rfc2865#section-3>
        if !(HEADER_SIZE..=MAX_PACKET_LENGTH).contains(&length) {
            return Err(PacketError::InvalidHeader(
                "RADIUS length out of valid range",
            ));
        }

        // RFC 2865, Section 3 — "If the packet is shorter than the Length
        // field indicates, it MUST be silently discarded." As a dissector
        // we instead surface this as a Truncated error.
        // <https://www.rfc-editor.org/rfc/rfc2865#section-3>
        if length > data.len() {
            return Err(PacketError::Truncated {
                expected: length,
                actual: data.len(),
            });
        }

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + length,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CODE],
            FieldValue::U8(code),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_IDENTIFIER],
            FieldValue::U8(identifier),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LENGTH],
            FieldValue::U16(length as u16),
            offset + 2..offset + 4,
        );
        // RFC 2865, Section 3 — 16-octet Authenticator field.
        // <https://www.rfc-editor.org/rfc/rfc2865#section-3>
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_AUTHENTICATOR],
            FieldValue::Bytes(&data[4..20]),
            offset + 4..offset + 20,
        );

        // Parse attributes within the Length boundary.
        let attr_data = &data[HEADER_SIZE..length];
        if !attr_data.is_empty() {
            let array_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_ATTRIBUTES],
                FieldValue::Array(0..0),
                offset + HEADER_SIZE..offset + length,
            );
            parse_attrs(buf, attr_data, offset + HEADER_SIZE);
            buf.end_container(array_idx);
        }

        buf.end_layer();

        Ok(DissectResult::new(length, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC Coverage
    //
    // | RFC Section   | Description                          | Test                                   |
    // |---------------|--------------------------------------|----------------------------------------|
    // | 2865 § 3      | Header: Code, Identifier, Length     | test_parse_access_request              |
    // | 2865 § 3      | Header: Authenticator (16 bytes)     | test_parse_access_request              |
    // | 2865 § 3      | Code: Access-Request (1)             | test_parse_access_request              |
    // | 2865 § 3      | Code: Access-Accept (2)              | test_parse_access_accept               |
    // | 2865 § 3      | Code: Access-Reject (3)              | test_parse_access_reject               |
    // | 2865 § 3      | Code: Access-Challenge (11)          | test_parse_access_challenge            |
    // | 2865 § 3      | Length validation: < 20              | test_invalid_length_too_small          |
    // | 2865 § 3      | Length validation: > 4096            | test_invalid_length_too_large          |
    // | 2865 § 3      | Length > data.len()                  | test_truncated_by_length_field         |
    // | 2865 § 5      | Attribute TLV parsing                | test_parse_access_request              |
    // | 2865 § 5.1    | User-Name (String)                   | test_parse_access_request              |
    // | 2865 § 5.4    | NAS-IP-Address (Address)             | test_parse_address_attribute           |
    // | 2865 § 5.6    | Service-Type (Integer/Enum)          | test_parse_access_accept               |
    // | 2865 § 5.18   | Reply-Message (Text)                 | test_parse_access_reject               |
    // | 2865 § 5.26   | Vendor-Specific (type 26)            | test_parse_vendor_specific             |
    // | 2865 § 5      | String-typed attrs match RFC labels  | attr::test_string_typed_attrs_match_rfc_labels |
    // | 2865 § 5      | Text-typed attrs match RFC labels    | attr::test_text_typed_attrs_match_rfc_labels   |
    // | 2866 § 3      | Code: Accounting-Request (4)         | test_parse_accounting_request          |
    // | 2866 § 3      | Code: Accounting-Response (5)        | test_parse_accounting_response         |
    // | 2866 § 5.1    | Acct-Status-Type (Integer/Enum)      | test_parse_accounting_request          |
    // | ---           | Multiple attributes                  | test_parse_multiple_attributes         |
    // | ---           | Truncated header                     | test_truncated_header                  |
    // | ---           | Malformed attribute                  | test_malformed_attribute_stops_parsing |
    // | ---           | No attributes (Length=20)            | test_no_attributes                     |
    // | ---           | Unknown attribute type               | test_unknown_attribute_type            |
    // | ---           | Field descriptors                    | test_field_descriptors                 |
    // | ---           | Byte ranges with offset              | test_dissect_with_offset               |
    // | ---           | All known code values                | test_code_values                       |

    /// Build a RADIUS packet from components.
    fn build_radius(code: u8, id: u8, authenticator: &[u8; 16], attrs: &[u8]) -> Vec<u8> {
        let length = (HEADER_SIZE + attrs.len()) as u16;
        let mut pkt = Vec::with_capacity(length as usize);
        pkt.push(code);
        pkt.push(id);
        pkt.extend_from_slice(&length.to_be_bytes());
        pkt.extend_from_slice(authenticator);
        pkt.extend_from_slice(attrs);
        pkt
    }

    /// Build a single RADIUS attribute.
    fn build_attr(attr_type: u8, value: &[u8]) -> Vec<u8> {
        let len = (2 + value.len()) as u8;
        let mut attr = Vec::with_capacity(len as usize);
        attr.push(attr_type);
        attr.push(len);
        attr.extend_from_slice(value);
        attr
    }

    fn auth() -> [u8; 16] {
        [0xAA; 16]
    }

    /// Helper: get the attributes Array range from the RADIUS layer.
    fn attrs_array_range(buf: &DissectBuffer) -> core::ops::Range<u32> {
        let layer = buf.layer_by_name("RADIUS").unwrap();
        let field = buf.field_by_name(layer, "attributes").unwrap();
        match &field.value {
            FieldValue::Array(r) => r.clone(),
            _ => panic!("expected Array"),
        }
    }

    /// Helper: get the n-th Object range in an array.
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
        panic!("object at index {index} not found");
    }

    /// Helper: find a named field value in an Object range.
    fn obj_field_value<'a>(
        buf: &'a DissectBuffer,
        obj_range: &core::ops::Range<u32>,
        name: &str,
    ) -> &'a FieldValue<'a> {
        let fields = buf.nested_fields(obj_range);
        &fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("field '{name}' not found"))
            .value
    }

    /// Helper: count Objects in an array.
    fn count_objects(buf: &DissectBuffer, array_range: &core::ops::Range<u32>) -> usize {
        buf.nested_fields(array_range)
            .iter()
            .filter(|f| f.value.is_object())
            .count()
    }

    #[test]
    fn test_parse_access_request() {
        // Access-Request (Code=1) with User-Name attribute (type=1)
        let user_name = build_attr(1, b"admin");
        let data = build_radius(1, 42, &auth(), &user_name);
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "RADIUS");

        assert_eq!(
            buf.field_by_name(layer, "code").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "code_name"),
            Some("Access-Request")
        );
        assert_eq!(
            buf.field_by_name(layer, "identifier").unwrap().value,
            FieldValue::U8(42)
        );
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U16(data.len() as u16)
        );
        assert_eq!(
            buf.field_by_name(layer, "authenticator").unwrap().value,
            FieldValue::Bytes(&[0xAA; 16])
        );

        // Check attributes array
        let array_range = attrs_array_range(&buf);
        assert_eq!(count_objects(&buf, &array_range), 1);
        let obj_range = nth_object_range(&buf, &array_range, 0);
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "name"),
            FieldValue::Str("User-Name")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "value"),
            FieldValue::Bytes(b"admin" as &[u8])
        );
    }

    #[test]
    fn attribute_container_resolves_to_attribute_name() {
        // Attribute 1 (User-Name): the outer container label should
        // resolve to "User-Name" rather than duplicating "Attribute Type".
        let user_name = build_attr(1, b"admin");
        let data = build_radius(1, 42, &auth(), &user_name);
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();

        let (idx, field) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "attribute")
            .expect("attribute container not found");
        assert!(matches!(field.value, FieldValue::Object(_)));
        assert_eq!(field.display_name(), "Attribute");
        assert_eq!(
            buf.resolve_container_display_name(idx as u32),
            Some("User-Name")
        );
    }

    #[test]
    fn test_parse_access_accept() {
        // Access-Accept (Code=2) with Service-Type=2 (Framed)
        let service_type = build_attr(6, &2u32.to_be_bytes());
        let data = build_radius(2, 42, &auth(), &service_type);
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "code").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "code_name"),
            Some("Access-Accept")
        );

        let array_range = attrs_array_range(&buf);
        let obj_range = nth_object_range(&buf, &array_range, 0);
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "name"),
            FieldValue::Str("Service-Type")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "value"),
            FieldValue::U32(2)
        );
        assert_eq!(
            buf.resolve_nested_display_name(&obj_range, "value_name"),
            Some("Framed")
        );
    }

    #[test]
    fn test_parse_access_reject() {
        // Access-Reject (Code=3) with Reply-Message
        let reply = build_attr(18, b"Authentication failed");
        let data = build_radius(3, 1, &auth(), &reply);
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "code").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "code_name"),
            Some("Access-Reject")
        );

        let array_range = attrs_array_range(&buf);
        let obj_range = nth_object_range(&buf, &array_range, 0);
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "value"),
            FieldValue::Bytes(b"Authentication failed" as &[u8])
        );
    }

    #[test]
    fn test_parse_accounting_request() {
        // Accounting-Request (Code=4) with Acct-Status-Type=1 (Start)
        let acct_status = build_attr(40, &1u32.to_be_bytes());
        let data = build_radius(4, 10, &auth(), &acct_status);
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "code").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "code_name"),
            Some("Accounting-Request")
        );

        let array_range = attrs_array_range(&buf);
        let obj_range = nth_object_range(&buf, &array_range, 0);
        assert_eq!(
            buf.resolve_nested_display_name(&obj_range, "value_name"),
            Some("Start")
        );
    }

    #[test]
    fn test_parse_accounting_response() {
        let data = build_radius(5, 10, &auth(), &[]);
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "code").unwrap().value,
            FieldValue::U8(5)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "code_name"),
            Some("Accounting-Response")
        );
    }

    #[test]
    fn test_parse_access_challenge() {
        let state = build_attr(24, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let data = build_radius(11, 99, &auth(), &state);
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "code").unwrap().value,
            FieldValue::U8(11)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "code_name"),
            Some("Access-Challenge")
        );

        let array_range = attrs_array_range(&buf);
        let obj_range = nth_object_range(&buf, &array_range, 0);
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "name"),
            FieldValue::Str("State")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "value"),
            FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
        );
    }

    #[test]
    fn test_parse_vendor_specific() {
        // Vendor-Specific (type=26): Vendor-Id=9 (Cisco), vendor data
        let mut vsa_value = Vec::new();
        vsa_value.extend_from_slice(&9u32.to_be_bytes()); // Vendor-Id = 9
        vsa_value.extend_from_slice(b"\x01\x0bhello=world"); // vendor sub-attribute
        let vsa = build_attr(26, &vsa_value);
        let data = build_radius(1, 1, &auth(), &vsa);
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();

        let array_range = attrs_array_range(&buf);
        let obj_range = nth_object_range(&buf, &array_range, 0);
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "name"),
            FieldValue::Str("Vendor-Specific")
        );
        // VSA emits raw value bytes for consistent filtering across all attributes.
        let mut expected_raw = Vec::new();
        expected_raw.extend_from_slice(&9u32.to_be_bytes());
        expected_raw.extend_from_slice(b"\x01\x0bhello=world");
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "value"),
            FieldValue::Bytes(&expected_raw)
        );
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "vendor_id"),
            FieldValue::U32(9)
        );
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "vendor_data"),
            FieldValue::Bytes(b"\x01\x0bhello=world")
        );
    }

    #[test]
    fn test_parse_address_attribute() {
        // NAS-IP-Address (type=4) = 10.0.0.1
        let nas_ip = build_attr(4, &[10, 0, 0, 1]);
        let data = build_radius(1, 1, &auth(), &nas_ip);
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();

        let array_range = attrs_array_range(&buf);
        let obj_range = nth_object_range(&buf, &array_range, 0);
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "value"),
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
    }

    #[test]
    fn test_parse_multiple_attributes() {
        let mut attrs_data = Vec::new();
        attrs_data.extend_from_slice(&build_attr(1, b"admin"));
        attrs_data.extend_from_slice(&build_attr(4, &[192, 168, 1, 1]));
        attrs_data.extend_from_slice(&build_attr(6, &2u32.to_be_bytes()));
        let data = build_radius(1, 1, &auth(), &attrs_data);
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();

        let array_range = attrs_array_range(&buf);
        assert_eq!(count_objects(&buf, &array_range), 3);
    }

    #[test]
    fn test_truncated_header() {
        let data = [0u8; 19];
        let mut buf = DissectBuffer::new();
        let result = RadiusDissector.dissect(&data, &mut buf, 0);
        match result.unwrap_err() {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, 20);
                assert_eq!(actual, 19);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn test_truncated_by_length_field() {
        // Header says length=100, but data is only 30 bytes
        let mut data = build_radius(1, 1, &auth(), &[0u8; 10]);
        data[2] = 0;
        data[3] = 100; // set length to 100
        let mut buf = DissectBuffer::new();
        let result = RadiusDissector.dissect(&data, &mut buf, 0);
        match result.unwrap_err() {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, 100);
                assert_eq!(actual, 30);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn test_invalid_length_too_small() {
        let mut data = build_radius(1, 1, &auth(), &[]);
        data[2] = 0;
        data[3] = 19; // length < 20
        let mut buf = DissectBuffer::new();
        let result = RadiusDissector.dissect(&data, &mut buf, 0);
        assert!(matches!(result.unwrap_err(), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn test_invalid_length_too_large() {
        let mut data = build_radius(1, 1, &auth(), &[]);
        data[2] = 0x10;
        data[3] = 0x01; // length = 4097
        let mut buf = DissectBuffer::new();
        let result = RadiusDissector.dissect(&data, &mut buf, 0);
        assert!(matches!(result.unwrap_err(), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn test_malformed_attribute_stops_parsing() {
        // First attribute valid, second has length=0 (malformed)
        let mut attrs_data = build_attr(1, b"ok");
        attrs_data.push(2); // type
        attrs_data.push(0); // length=0 (invalid)
        let data = build_radius(1, 1, &auth(), &attrs_data);
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();

        // Only the first valid attribute should be parsed
        let array_range = attrs_array_range(&buf);
        assert_eq!(count_objects(&buf, &array_range), 1);
    }

    #[test]
    fn test_no_attributes() {
        let data = build_radius(5, 10, &auth(), &[]);
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("RADIUS").unwrap();
        assert!(buf.field_by_name(layer, "attributes").is_none());
    }

    #[test]
    fn test_unknown_attribute_type() {
        // Type 200 is not in the lookup table
        let attr = build_attr(200, &[0x01, 0x02, 0x03]);
        let data = build_radius(1, 1, &auth(), &attr);
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();

        let array_range = attrs_array_range(&buf);
        let obj_range = nth_object_range(&buf, &array_range, 0);
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "name"),
            FieldValue::Str("Unknown")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj_range, "value"),
            FieldValue::Bytes(&[0x01, 0x02, 0x03])
        );
    }

    #[test]
    fn test_field_descriptors() {
        let descriptors = RadiusDissector.field_descriptors();
        assert_eq!(descriptors.len(), 5);
        assert_eq!(descriptors[0].name, "code");
        assert_eq!(descriptors[4].name, "attributes");
        assert!(descriptors[4].children.is_some());
    }

    #[test]
    fn test_dissect_with_offset() {
        let data = build_radius(1, 1, &auth(), &[]);
        let offset = 42;
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, offset).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(layer.range, offset..offset + HEADER_SIZE);
        assert_eq!(
            buf.field_by_name(layer, "code").unwrap().range,
            offset..offset + 1
        );
        assert_eq!(
            buf.field_by_name(layer, "authenticator").unwrap().range,
            offset + 4..offset + 20
        );
    }

    #[test]
    fn test_code_values() {
        for code in [1, 2, 3, 4, 5, 11, 12, 13, 255] {
            let data = build_radius(code, 0, &auth(), &[]);
            let mut buf = DissectBuffer::new();
            RadiusDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            if let Some(name) = buf.resolve_display_name(layer, "code_name") {
                assert!(!name.is_empty());
                assert_ne!(name, "Unknown");
            } else {
                panic!("code_name should resolve");
            }
        }
    }

    #[test]
    fn test_dissect_with_offset_attributes() {
        let user_name = build_attr(1, b"test");
        let data = build_radius(1, 1, &auth(), &user_name);
        let offset = 100;
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, offset).unwrap();

        let layer = &buf.layers()[0];
        let attrs_field = buf.field_by_name(layer, "attributes").unwrap();
        assert_eq!(attrs_field.range, offset + 20..offset + data.len());

        // Check that the first Object in the array has the correct byte range
        if let FieldValue::Array(ref array_range) = attrs_field.value {
            let obj_range = nth_object_range(&buf, array_range, 0);
            // The object fields contain the attribute. Check a child field range.
            let fields = buf.nested_fields(&obj_range);
            let type_field = fields.iter().find(|f| f.name() == "type").unwrap();
            assert_eq!(type_field.range.start, offset + 20);
        } else {
            panic!("expected Array");
        }
    }
}
