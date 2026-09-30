//! RADIUS (Remote Authentication Dial In User Service) dissector.
//!
//! Parses the RADIUS message header (20 bytes) and TLV-encoded attributes.
//! Each attribute is represented as an element in an Array of Objects.
//!
//! ## References
//! - RFC 2865 (RADIUS base protocol): <https://www.rfc-editor.org/rfc/rfc2865>
//! - RFC 2866 (RADIUS Accounting): <https://www.rfc-editor.org/rfc/rfc2866>
//! - RFC 2867 (Tunnel Protocol Support accounting): <https://www.rfc-editor.org/rfc/rfc2867>
//! - RFC 2868 (Tunnel Protocol Support attributes): <https://www.rfc-editor.org/rfc/rfc2868>
//! - RFC 2869 (RADIUS Extensions): <https://www.rfc-editor.org/rfc/rfc2869>
//! - RFC 3162 (RADIUS and IPv6): <https://www.rfc-editor.org/rfc/rfc3162>
//! - RFC 3579 (RADIUS Support for EAP): <https://www.rfc-editor.org/rfc/rfc3579>
//! - RFC 4372 (Chargeable User Identity): <https://www.rfc-editor.org/rfc/rfc4372>
//! - RFC 4818 (Delegated-IPv6-Prefix): <https://www.rfc-editor.org/rfc/rfc4818>
//! - RFC 5176 (Dynamic Authorization Extensions): <https://www.rfc-editor.org/rfc/rfc5176>
//! - RFC 6911 (IPv6 Access Networks): <https://www.rfc-editor.org/rfc/rfc6911>
//! - RFC 6929 (RADIUS Protocol Extensions): <https://www.rfc-editor.org/rfc/rfc6929>
//! - RFC 8044 (Data Types in RADIUS): <https://www.rfc-editor.org/rfc/rfc8044>
//! - RFC 2548 (Microsoft Vendor-specific RADIUS Attributes): <https://www.rfc-editor.org/rfc/rfc2548>
//! - 3GPP TS 29.061 v19.1.0, clause 16.4.7 (3GPP Vendor-Specific attributes):
//!   <https://www.3gpp.org/ftp/Specs/archive/29_series/29.061/>
//! - IANA RADIUS Types: <https://www.iana.org/assignments/radius-types/radius-types.xhtml>
//!
//! EAP-Message (79) values are emitted as raw bytes. With the `eap` feature
//! an EAP packet that fits in one EAP-Message is also decoded into an `eap`
//! Object; packets split over several attributes are not reassembled.
//!
//! RFC 2865 is also updated by the following RFCs. They do not alter the
//! wire format parsed here, but are recorded for completeness:
//! - RFC 3575 (IANA Considerations for RADIUS): <https://www.rfc-editor.org/rfc/rfc3575>
//! - RFC 5997 (Use of Status-Server Packets): <https://www.rfc-editor.org/rfc/rfc5997>

#![deny(missing_docs)]

mod attr;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{DisplayFn, Field, FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{
    read_be_u16, read_be_u24, read_be_u32, read_be_u64, read_ipv4_addr, read_ipv6_addr,
};

use attr::{
    EXTENDED_TYPE_EVS, RadiusAttrType, VENDOR_3GPP, VENDOR_MICROSOFT, attr_display_name, code_name,
    enum_value_name, extended_enum_value_name, lookup_attr, lookup_extended_attr,
    lookup_vendor_attr, microsoft_value_name, tgpp_value_name, vendor_name,
};

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
/// EAP-Message attribute type.
/// RFC 3579, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc3579#section-3.1>
#[cfg(feature = "eap")]
const ATTR_EAP_MESSAGE: u8 = 79;

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
const AFD_TAG: usize = 6;
const AFD_SALT: usize = 7;
const AFD_PREFIX_LENGTH: usize = 8;
const AFD_EXTENDED_TYPE: usize = 9;
const AFD_MORE: usize = 10;
const AFD_VENDOR_TYPE: usize = 11;
const AFD_VENDOR_ATTRIBUTES: usize = 12;
#[cfg(feature = "eap")]
const AFD_EAP: usize = 13;

/// Field descriptor indices for [`VSA_CHILD_FIELDS`].
const VFD_TYPE: usize = 0;
const VFD_LENGTH: usize = 1;
const VFD_NAME: usize = 2;
const VFD_VALUE: usize = 3;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_CODE: usize = 0;
const FD_IDENTIFIER: usize = 1;
const FD_LENGTH: usize = 2;
const FD_AUTHENTICATOR: usize = 3;
const FD_ATTRIBUTES: usize = 4;

/// Largest Tag value; RFC 2868, Section 3.1 — "Valid values for this field
/// are 0x01 through 0x1F, inclusive."
/// <https://www.rfc-editor.org/rfc/rfc2868#section-3.1>
const MAX_TAG: u8 = 0x1F;

/// Return the `U8` value of the sibling field called `name`.
fn sibling_u8(siblings: &[Field<'_>], name: &str) -> Option<u8> {
    siblings
        .iter()
        .find(|f| f.name() == name)
        .and_then(|f| match &f.value {
            FieldValue::U8(v) => Some(*v),
            _ => None,
        })
}

/// Build the child descriptors of a Vendor-Specific sub-attribute Object.
///
/// Each vendor dictionary gets its own copy so that the `value` display
/// function can resolve vendor-specific enumerations.
const fn vsa_child_fields(value_display: Option<DisplayFn>) -> [FieldDescriptor; 4] {
    [
        FieldDescriptor::new("vendor_type", "Vendor Type", FieldType::U8),
        FieldDescriptor::new("vendor_length", "Vendor Length", FieldType::U8),
        FieldDescriptor::new("name", "Attribute Name", FieldType::Str),
        FieldDescriptor {
            name: "value",
            display_name: "Value",
            field_type: FieldType::Any,
            optional: false,
            children: None,
            display_fn: value_display,
            format_fn: None,
        },
    ]
}

/// Build the Object descriptor of a Vendor-Specific sub-attribute.
const fn vsa_container(display: Option<DisplayFn>) -> FieldDescriptor {
    FieldDescriptor {
        name: "vendor_attribute",
        display_name: "Vendor Attribute",
        field_type: FieldType::Object,
        optional: false,
        children: None,
        display_fn: display,
        format_fn: None,
    }
}

/// Resolve a 3GPP sub-attribute Object label from its `vendor_type` child.
fn tgpp_container_name(_v: &FieldValue<'_>, children: &[Field<'_>]) -> Option<&'static str> {
    lookup_vendor_attr(VENDOR_3GPP, sibling_u8(children, "vendor_type")?).map(|d| d.name)
}

/// Resolve a Microsoft sub-attribute Object label from its `vendor_type` child.
fn microsoft_container_name(_v: &FieldValue<'_>, children: &[Field<'_>]) -> Option<&'static str> {
    lookup_vendor_attr(VENDOR_MICROSOFT, sibling_u8(children, "vendor_type")?).map(|d| d.name)
}

/// Resolve a 3GPP sub-attribute value name.
fn tgpp_value_display(v: &FieldValue<'_>, siblings: &[Field<'_>]) -> Option<&'static str> {
    let val = match v {
        FieldValue::U32(x) => *x,
        FieldValue::U8(x) => u32::from(*x),
        _ => return None,
    };
    tgpp_value_name(sibling_u8(siblings, "vendor_type")?, val)
}

/// Resolve a Microsoft sub-attribute value name.
fn microsoft_value_display(v: &FieldValue<'_>, siblings: &[Field<'_>]) -> Option<&'static str> {
    let FieldValue::U32(val) = v else {
        return None;
    };
    microsoft_value_name(sibling_u8(siblings, "vendor_type")?, *val)
}

/// Sub-attribute descriptors used for the schema in [`ATTR_CHILD_FIELDS`].
static VSA_CHILD_FIELDS: [FieldDescriptor; 4] = vsa_child_fields(None);
/// Sub-attribute descriptors for 3GPP (TS 29.061, clause 16.4.7).
static TGPP_VSA_FIELDS: [FieldDescriptor; 4] = vsa_child_fields(Some(tgpp_value_display));
/// Sub-attribute descriptors for Microsoft (RFC 2548).
static MICROSOFT_VSA_FIELDS: [FieldDescriptor; 4] = vsa_child_fields(Some(microsoft_value_display));
/// Sub-attribute Object descriptor for 3GPP.
static FD_VSA_3GPP: FieldDescriptor = vsa_container(Some(tgpp_container_name));
/// Sub-attribute Object descriptor for Microsoft.
static FD_VSA_MICROSOFT: FieldDescriptor = vsa_container(Some(microsoft_container_name));

/// Child field descriptors for attribute Array elements.
static ATTR_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Attribute Type", FieldType::U8),
    FieldDescriptor::new("length", "Attribute Length", FieldType::U8),
    FieldDescriptor::new("name", "Attribute Name", FieldType::Str),
    FieldDescriptor {
        name: "value",
        display_name: "Value",
        // The value is typed by the attribute dictionary: U32, U64, Str,
        // Ipv4Addr, Ipv6Addr or Bytes.
        field_type: FieldType::Any,
        optional: false,
        children: None,
        display_fn: Some(|v, siblings| {
            let FieldValue::U32(int_val) = v else {
                return None;
            };
            let code = sibling_u8(siblings, "type")?;
            // RFC 6929, Section 2.1 — extended attributes are identified by
            // "Type.Extended-Type", not by the outer Type alone.
            // <https://www.rfc-editor.org/rfc/rfc6929#section-2.1>
            match sibling_u8(siblings, "extended_type") {
                Some(ext) => extended_enum_value_name(code, ext, *int_val),
                None => enum_value_name(code, *int_val),
            }
        }),
        format_fn: None,
    },
    FieldDescriptor::new("vendor_id", "Vendor-Id", FieldType::U32)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U32(id) => vendor_name(*id),
            _ => None,
        }),
    FieldDescriptor::new("vendor_data", "Vendor Data", FieldType::Bytes).optional(),
    // RFC 2868, Section 3.1 — https://www.rfc-editor.org/rfc/rfc2868#section-3.1
    FieldDescriptor::new("tag", "Tag", FieldType::U8).optional(),
    // RFC 2868, Section 3.5 — https://www.rfc-editor.org/rfc/rfc2868#section-3.5
    FieldDescriptor::new("salt", "Salt", FieldType::U16).optional(),
    // RFC 8044, Sections 3.10-3.11 — https://www.rfc-editor.org/rfc/rfc8044#section-3.10
    FieldDescriptor::new("prefix_length", "Prefix-Length", FieldType::U8).optional(),
    // RFC 6929, Section 2.1 — https://www.rfc-editor.org/rfc/rfc6929#section-2.1
    FieldDescriptor::new("extended_type", "Extended-Type", FieldType::U8).optional(),
    // RFC 6929, Section 2.2 — https://www.rfc-editor.org/rfc/rfc6929#section-2.2
    FieldDescriptor::new("more", "More", FieldType::U8).optional(),
    // RFC 6929, Section 2.4 — https://www.rfc-editor.org/rfc/rfc6929#section-2.4
    FieldDescriptor::new("vendor_type", "Vendor-Type", FieldType::U8).optional(),
    // RFC 2865, Section 5.26 — https://www.rfc-editor.org/rfc/rfc2865#section-5.26
    FieldDescriptor::new("vendor_attributes", "Vendor Attributes", FieldType::Array)
        .optional()
        .with_children(&VSA_CHILD_FIELDS),
    // RFC 3579, Section 3.1 — https://www.rfc-editor.org/rfc/rfc3579#section-3.1
    #[cfg(feature = "eap")]
    packet_dissector_eap::EAP_OBJECT_DESCRIPTOR,
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

/// Descriptor for the RADIUS attribute Object container.
///
/// `display_fn` is invoked by
/// [`DissectBuffer::resolve_container_display_name`] with the container's
/// children, so the outer label resolves to the attribute name (e.g.
/// "User-Name") instead of colliding with the inner `Attribute Type`
/// field. Extended attributes resolve to their "Type.Extended-Type" name.
static FD_ATTRIBUTE: FieldDescriptor = FieldDescriptor {
    name: "attribute",
    display_name: "Attribute",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => attr_display_name(
            sibling_u8(children, "type")?,
            sibling_u8(children, "extended_type"),
        ),
        _ => None,
    }),
    format_fn: None,
};

/// Parse attribute value according to its type.
///
/// RFC 2865, Section 5 — attribute data types.
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5>
/// RFC 8044, Section 3 — data type definitions.
/// <https://www.rfc-editor.org/rfc/rfc8044#section-3>
///
/// Values whose length does not match the data type fall back to raw bytes.
fn parse_attr_value<'pkt>(attr_type: RadiusAttrType, data: &'pkt [u8]) -> FieldValue<'pkt> {
    match attr_type {
        // RFC 2865, Section 5 — "1-253 octets containing UTF-8 encoded
        // 10646 [7] characters". Invalid UTF-8 is kept as raw octets.
        // <https://www.rfc-editor.org/rfc/rfc2865#section-5>
        RadiusAttrType::Text => match core::str::from_utf8(data) {
            Ok(s) => FieldValue::Str(s),
            Err(_) => FieldValue::Bytes(data),
        },
        // RFC 2865, Section 5 — "32 bit value, most significant octet
        // first".
        // <https://www.rfc-editor.org/rfc/rfc2865#section-5>
        RadiusAttrType::Address if data.len() == 4 => {
            FieldValue::Ipv4Addr(read_ipv4_addr(data, 0).unwrap_or_default())
        }
        // RFC 2865, Section 5 — "32 bit unsigned value, most significant
        // octet first". RFC 8044, Section 3.3 — "time" uses the same
        // encoding (seconds since 1970-01-01 00:00:00 UTC).
        // <https://www.rfc-editor.org/rfc/rfc2865#section-5>
        // <https://www.rfc-editor.org/rfc/rfc8044#section-3.3>
        RadiusAttrType::Integer | RadiusAttrType::Time if data.len() == 4 => {
            FieldValue::U32(read_be_u32(data, 0).unwrap_or_default())
        }
        // RFC 8044, Section 3.12 — "integer64".
        // <https://www.rfc-editor.org/rfc/rfc8044#section-3.12>
        RadiusAttrType::Integer64 if data.len() == 8 => {
            FieldValue::U64(read_be_u64(data, 0).unwrap_or_default())
        }
        // RFC 8044, Section 3.9 — "ipv6addr" is 16 octets.
        // <https://www.rfc-editor.org/rfc/rfc8044#section-3.9>
        RadiusAttrType::Ipv6Addr if data.len() == 16 => {
            FieldValue::Ipv6Addr(read_ipv6_addr(data, 0).unwrap_or_default())
        }
        RadiusAttrType::Octet if data.len() == 1 => FieldValue::U8(data[0]),
        // String, and every structured type with an unexpected length.
        _ => FieldValue::Bytes(data),
    }
}

/// Push the `value` field of an attribute or sub-attribute.
fn push_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    descriptor: &'static FieldDescriptor,
    attr_type: Option<RadiusAttrType>,
    data: &'pkt [u8],
    start: usize,
) {
    let value = attr_type
        .map(|t| parse_attr_value(t, data))
        .unwrap_or(FieldValue::Bytes(data));
    buf.push_field(descriptor, value, start..start + data.len());
}

/// Try to decode an RFC 2868 / RFC 8044 structured value. Returns `false`
/// (and pushes nothing) when the value does not match the format, so the
/// caller can fall back to raw bytes.
fn push_structured<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    attr_type: RadiusAttrType,
    data: &'pkt [u8],
    start: usize,
) -> bool {
    match attr_type {
        // RFC 2868, Section 3.1 — "Length: Always 6." Tag (1) + Value (3).
        // <https://www.rfc-editor.org/rfc/rfc2868#section-3.1>
        RadiusAttrType::TaggedInteger if data.len() == 4 => {
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_TAG],
                FieldValue::U8(data[0]),
                start..start + 1,
            );
            let value = read_be_u24(data, 1).unwrap_or_default();
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_VALUE],
                FieldValue::U32(value),
                start + 1..start + 4,
            );
            true
        }
        // RFC 2868, Section 3.3 — "If the value of the Tag field is greater
        // than 0x00 and less than or equal to 0x1F, it SHOULD be interpreted
        // as indicating which tunnel (of several alternatives) this attribute
        // pertains. If the Tag field is greater than 0x1F, it SHOULD be
        // interpreted as the first byte of the following String field."
        // A leading 0x00 (unused Tag) is also treated as a Tag.
        // <https://www.rfc-editor.org/rfc/rfc2868#section-3.3>
        RadiusAttrType::TaggedText if !data.is_empty() => {
            if data[0] <= MAX_TAG {
                buf.push_field(
                    &ATTR_CHILD_FIELDS[AFD_TAG],
                    FieldValue::U8(data[0]),
                    start..start + 1,
                );
                push_value(
                    buf,
                    &ATTR_CHILD_FIELDS[AFD_VALUE],
                    Some(RadiusAttrType::Text),
                    &data[1..],
                    start + 1,
                );
            } else {
                push_value(
                    buf,
                    &ATTR_CHILD_FIELDS[AFD_VALUE],
                    Some(RadiusAttrType::Text),
                    data,
                    start,
                );
            }
            true
        }
        // RFC 2868, Section 3.5 — Tag (1) + Salt (2) + String; "Length >= 5".
        // <https://www.rfc-editor.org/rfc/rfc2868#section-3.5>
        RadiusAttrType::TunnelPassword if data.len() >= 3 => {
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_TAG],
                FieldValue::U8(data[0]),
                start..start + 1,
            );
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_SALT],
                FieldValue::U16(read_be_u16(data, 1).unwrap_or_default()),
                start + 1..start + 3,
            );
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_VALUE],
                FieldValue::Bytes(&data[3..]),
                start + 3..start + data.len(),
            );
            true
        }
        // RFC 3162, Section 2.3 — "Length: At least 4 and no larger than 20."
        // "Prefix-Length: ... At least 0 and no larger than 128."
        // <https://www.rfc-editor.org/rfc/rfc3162#section-2.3>
        RadiusAttrType::Ipv6Prefix if (2..=18).contains(&data.len()) && data[1] <= 128 => {
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_PREFIX_LENGTH],
                FieldValue::U8(data[1]),
                start + 1..start + 2,
            );
            let mut prefix = [0u8; 16];
            prefix[..data.len() - 2].copy_from_slice(&data[2..]);
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_VALUE],
                FieldValue::Ipv6Addr(prefix),
                start + 2..start + data.len(),
            );
            true
        }
        // RFC 8044, Section 3.11 — "Length: Six octets"; "Attributes with a
        // Prefix-Length field having a value greater than 32 MUST be treated
        // as invalid attributes."
        // <https://www.rfc-editor.org/rfc/rfc8044#section-3.11>
        RadiusAttrType::Ipv4Prefix if data.len() == 6 && data[1] <= 32 => {
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_PREFIX_LENGTH],
                FieldValue::U8(data[1]),
                start + 1..start + 2,
            );
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_VALUE],
                FieldValue::Ipv4Addr(read_ipv4_addr(data, 2).unwrap_or_default()),
                start + 2..start + 6,
            );
            true
        }
        _ => false,
    }
}

/// Size of the extended attribute header inside the Value: Extended-Type
/// (1) for "Extended Type", plus the M / Reserved octet (1) for "Long
/// Extended Type". `None` for non-extended attributes.
///
/// RFC 6929, Sections 2.1 and 2.2 —
/// <https://www.rfc-editor.org/rfc/rfc6929#section-2.1>
const fn extended_header_len(attr_type: Option<RadiusAttrType>) -> Option<usize> {
    match attr_type {
        Some(RadiusAttrType::Extended) => Some(1),
        Some(RadiusAttrType::LongExtended) => Some(2),
        _ => None,
    }
}

/// Decode an RFC 6929 "Extended Type" (241-244) or "Long Extended Type"
/// (245-246) attribute value. `header` comes from [`extended_header_len`]
/// and the caller guarantees `data.len() > header`, i.e. RFC 6929,
/// Section 2.1 — "Permitted values are between 4 and 255" and Section 2.2
/// — "Permitted values are between 5 and 255". `continuation` is set when
/// the attribute is a later fragment of a Long Extended Type value (see
/// [`LongExtendedFragments`]).
///
/// RFC 6929, Sections 2.1, 2.2 and 2.4 —
/// <https://www.rfc-editor.org/rfc/rfc6929#section-2>
fn push_extended<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    code: u8,
    header: usize,
    data: &'pkt [u8],
    start: usize,
    continuation: bool,
) {
    let ext_type = data[0];
    buf.push_field(
        &ATTR_CHILD_FIELDS[AFD_EXTENDED_TYPE],
        FieldValue::U8(ext_type),
        start..start + 1,
    );
    // RFC 6929, Section 2.2 — "The More field is one (1) bit in length and
    // indicates whether or not the current attribute contains "more" than
    // 251 octets of data."
    // <https://www.rfc-editor.org/rfc/rfc6929#section-2.2>
    let long = header == 2;
    let more = long && data[1] & 0x80 != 0;
    if long {
        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_MORE],
            FieldValue::U8(u8::from(more)),
            start + 1..start + 2,
        );
    }
    let value = &data[header..];
    let value_start = start + header;

    // RFC 6929, Section 2.4 — Extended-Vendor-Specific: Vendor-Id (4) +
    // Vendor-Type (1) + Value. "The EVS-Value field is one or more
    // octets." Only the first fragment of a Long Extended Type value
    // carries the Vendor-Id and EVS-Type.
    // <https://www.rfc-editor.org/rfc/rfc6929#section-2.4>
    if ext_type == EXTENDED_TYPE_EVS && !continuation && value.len() >= EVS_MIN_LEN {
        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_VENDOR_ID],
            FieldValue::U32(read_be_u32(value, 0).unwrap_or_default()),
            value_start..value_start + 4,
        );
        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_VENDOR_TYPE],
            FieldValue::U8(value[4]),
            value_start + 4..value_start + 5,
        );
        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_VALUE],
            FieldValue::Bytes(&value[5..]),
            value_start + 5..value_start + value.len(),
        );
        return;
    }

    // RFC 6929, Section 2.2 — "Any interpretation of the resulting data
    // MUST occur after the fragments have been reassembled." A fragment
    // (M set, or a later fragment of a value) is therefore left raw.
    // <https://www.rfc-editor.org/rfc/rfc6929#section-2.2>
    let attr_type = if more || continuation {
        None
    } else {
        lookup_extended_attr(code, ext_type).map(|d| d.attr_type)
    };
    push_value(
        buf,
        &ATTR_CHILD_FIELDS[AFD_VALUE],
        attr_type,
        value,
        value_start,
    );
}

/// Minimum EVS data length: Vendor-Id (4) + EVS-Type (1) + at least one
/// EVS-Value octet.
///
/// RFC 6929, Section 2.4 — "The EVS-Value field is one or more octets."
/// <https://www.rfc-editor.org/rfc/rfc6929#section-2.4>
const EVS_MIN_LEN: usize = 6;

/// Tracks Long Extended Type (245, 246) values whose previous fragment had
/// the More flag set, so that later fragments are recognised.
///
/// RFC 6929, Section 2.2 — "When the More field is set (1), the Attribute
/// MUST have a Length field of value 255, there MUST be an attribute
/// following this one, and the next attribute MUST have both the same Type
/// and "Extended Type"." and "Implementations MUST be able to process
/// non-contiguous fragments -- that is, fragments that are mixed together
/// with other attributes of a different Type."
/// <https://www.rfc-editor.org/rfc/rfc6929#section-2.2>
#[derive(Default)]
struct LongExtendedFragments {
    /// One bit per Extended-Type for each Long Extended Type attribute
    /// (index 0 for 246, 1 for 245), set while a value is pending.
    pending: [[u128; 2]; 2],
}

impl LongExtendedFragments {
    /// Record a Long Extended Type attribute (`data` is its Value, holding
    /// at least the Extended-Type and flags octets) and return whether it
    /// continues a value whose previous fragment had the More flag set.
    fn update(&mut self, code: u8, data: &[u8]) -> bool {
        let ext_type = data[0];
        let word = &mut self.pending[usize::from(code & 1)][usize::from(ext_type >> 7)];
        let bit = 1u128 << (ext_type & 0x7F);
        let continuation = *word & bit != 0;
        if data[1] & 0x80 != 0 {
            *word |= bit;
        } else {
            *word &= !bit;
        }
        continuation
    }
}

/// Returns `true` when `data` is a non-empty sequence of RFC 2865
/// Section 5.26 "Vendor type / Vendor length / Attribute-Specific"
/// sub-attributes whose lengths add up exactly.
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5.26>
fn is_vsa_tlv_shaped(data: &[u8]) -> bool {
    let mut pos = 0;
    while pos < data.len() {
        match data.get(pos + 1) {
            Some(&len) if len >= 2 && pos + len as usize <= data.len() => pos += len as usize,
            _ => return false,
        }
    }
    !data.is_empty()
}

/// Sub-attribute descriptors for vendors whose String is known to use the
/// RFC 2865 Section 5.26 recommended format. Other vendors (some use 2- or
/// 4-octet vendor types) keep only the raw `vendor_data`.
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5.26>
fn vsa_descriptors(
    vendor_id: u32,
) -> Option<(&'static FieldDescriptor, &'static [FieldDescriptor; 4])> {
    match vendor_id {
        // TS 29.061, clause 16.4.7.2 — "3GPP type" (1) / "3GPP Length" (1).
        VENDOR_3GPP => Some((&FD_VSA_3GPP, &TGPP_VSA_FIELDS)),
        // RFC 2548, Section 2 — Vendor-Type (1) / Vendor-Length (1).
        // <https://www.rfc-editor.org/rfc/rfc2548#section-2>
        VENDOR_MICROSOFT => Some((&FD_VSA_MICROSOFT, &MICROSOFT_VSA_FIELDS)),
        _ => None,
    }
}

/// Push the Vendor-Specific sub-attributes of `data` (the String part of a
/// VSA) as an Array of Objects when the vendor uses the recommended format
/// and the lengths add up exactly; otherwise push nothing.
///
/// RFC 2865, Section 5.26 — "It SHOULD be encoded as a sequence of vendor
/// type / vendor length / value fields".
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5.26>
fn push_vendor_attributes<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    vendor_id: u32,
    data: &'pkt [u8],
    start: usize,
) {
    let Some((container, fields)) = vsa_descriptors(vendor_id) else {
        return;
    };
    if !is_vsa_tlv_shaped(data) {
        return;
    }
    let array_idx = buf.begin_container(
        &ATTR_CHILD_FIELDS[AFD_VENDOR_ATTRIBUTES],
        FieldValue::Array(0..0),
        start..start + data.len(),
    );
    let mut pos = 0;
    // `is_vsa_tlv_shaped` guarantees every sub-attribute is in bounds.
    while pos < data.len() {
        let vtype = data[pos];
        let vlen = data[pos + 1] as usize;
        let abs = start + pos;
        let def = lookup_vendor_attr(vendor_id, vtype);
        let obj_idx = buf.begin_container(container, FieldValue::Object(0..0), abs..abs + vlen);
        buf.push_field(&fields[VFD_TYPE], FieldValue::U8(vtype), abs..abs + 1);
        buf.push_field(
            &fields[VFD_LENGTH],
            FieldValue::U8(vlen as u8),
            abs + 1..abs + 2,
        );
        buf.push_field(
            &fields[VFD_NAME],
            FieldValue::Str(def.map(|d| d.name).unwrap_or("Unknown")),
            abs..abs + 1,
        );
        push_value(
            buf,
            &fields[VFD_VALUE],
            def.map(|d| d.attr_type),
            &data[pos + 2..pos + vlen],
            abs + 2,
        );
        buf.end_container(obj_idx);
        pos += vlen;
    }
    buf.end_container(array_idx);
}

/// Parse a slice of attribute bytes and push them into the buffer as
/// Array elements (each is an Object).
///
/// `buf_offset` is the absolute byte position of `attr_data[0]` in the original
/// packet, used to produce accurate `range` values.
fn parse_attrs<'pkt>(buf: &mut DissectBuffer<'pkt>, attr_data: &'pkt [u8], buf_offset: usize) {
    #[cfg(feature = "eap")]
    let single_eap_message = count_attrs(attr_data, ATTR_EAP_MESSAGE) == 1;
    let mut fragments = LongExtendedFragments::default();
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
        let value_start = abs + 2;
        let attr_type = lookup_attr(attr_type_code).map(|d| d.attr_type);

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

        // RFC 6929, Section 2.1 — the attribute is identified by
        // "Type.Extended-Type".
        // <https://www.rfc-editor.org/rfc/rfc6929#section-2.1>
        // Shorter values are invalid and are left raw.
        let ext_header = extended_header_len(attr_type).filter(|h| value_data.len() > *h);
        let ext_type = ext_header.map(|_| value_data[0]);
        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_NAME],
            FieldValue::Str(attr_display_name(attr_type_code, ext_type).unwrap_or("Unknown")),
            abs..abs + 1,
        );

        if attr_type_code == ATTR_VENDOR_SPECIFIC && value_data.len() >= MIN_VSA_VALUE_SIZE {
            // RFC 2865, Section 5.26 — Vendor-Specific: Vendor-Id(4) + String.
            // <https://www.rfc-editor.org/rfc/rfc2865#section-5.26>
            let vendor_id = read_be_u32(value_data, 0).unwrap_or_default();
            // Emit raw value bytes for consistent filtering across all attribute types.
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_VALUE],
                FieldValue::Bytes(value_data),
                value_start..abs + attr_len,
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
            push_vendor_attributes(buf, vendor_id, vdata, abs + 6);
        } else if let Some(header) = ext_header {
            let continuation = header == 2 && fragments.update(attr_type_code, value_data);
            push_extended(
                buf,
                attr_type_code,
                header,
                value_data,
                value_start,
                continuation,
            );
        } else if !attr_type.is_some_and(|t| push_structured(buf, t, value_data, value_start)) {
            push_value(
                buf,
                &ATTR_CHILD_FIELDS[AFD_VALUE],
                attr_type,
                value_data,
                value_start,
            );
            // RFC 3579, Section 3.1 — "If multiple EAP-Message attributes
            // are present in a packet their values should be concatenated;
            // this allows EAP packets longer than 253 octets to be
            // transported by RADIUS." An EAP packet is decoded only when
            // it is carried by a single EAP-Message; one split over several
            // attributes stays raw (reassembly would need a copy).
            // <https://www.rfc-editor.org/rfc/rfc3579#section-3.1>
            #[cfg(feature = "eap")]
            if attr_type_code == ATTR_EAP_MESSAGE && single_eap_message {
                packet_dissector_eap::push_eap_object(
                    &ATTR_CHILD_FIELDS[AFD_EAP],
                    value_data,
                    value_start,
                    buf,
                );
            }
        }

        buf.end_container(obj_idx);
        pos += attr_len;
    }
}

/// Number of well-formed top-level attributes of type `attr_type`.
#[cfg(feature = "eap")]
fn count_attrs(attr_data: &[u8], attr_type: u8) -> usize {
    let mut count = 0;
    let mut pos = 0;
    while pos + MIN_ATTR_SIZE <= attr_data.len() {
        let attr_len = usize::from(attr_data[pos + 1]);
        if attr_len < MIN_ATTR_SIZE || pos + attr_len > attr_data.len() {
            break;
        }
        count += usize::from(attr_data[pos] == attr_type);
        pos += attr_len;
    }
    count
}

/// RADIUS dissector.
pub struct RadiusDissector;

/// Specification references for the RADIUS dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 2865",
        "Remote Authentication Dial In User Service (RADIUS)",
        "https://www.rfc-editor.org/rfc/rfc2865",
    ),
    SpecReference::new(
        "RFC 2866",
        "RADIUS Accounting",
        "https://www.rfc-editor.org/rfc/rfc2866",
    ),
    SpecReference::new(
        "RFC 2867",
        "RADIUS Accounting Modifications for Tunnel Protocol Support",
        "https://www.rfc-editor.org/rfc/rfc2867",
    ),
    SpecReference::new(
        "RFC 2868",
        "RADIUS Attributes for Tunnel Protocol Support",
        "https://www.rfc-editor.org/rfc/rfc2868",
    ),
    SpecReference::new(
        "RFC 2869",
        "RADIUS Extensions",
        "https://www.rfc-editor.org/rfc/rfc2869",
    ),
    SpecReference::new(
        "RFC 3162",
        "RADIUS and IPv6",
        "https://www.rfc-editor.org/rfc/rfc3162",
    ),
    SpecReference::new(
        "RFC 4818",
        "RADIUS Delegated-IPv6-Prefix Attribute",
        "https://www.rfc-editor.org/rfc/rfc4818",
    ),
    SpecReference::new(
        "RFC 5176",
        "Dynamic Authorization Extensions to Remote Authentication Dial In User Service (RADIUS)",
        "https://www.rfc-editor.org/rfc/rfc5176",
    ),
    SpecReference::new(
        "RFC 6911",
        "RADIUS Attributes for IPv6 Access Networks",
        "https://www.rfc-editor.org/rfc/rfc6911",
    ),
    SpecReference::new(
        "RFC 6929",
        "Remote Authentication Dial In User Service (RADIUS) Protocol Extensions",
        "https://www.rfc-editor.org/rfc/rfc6929",
    ),
    SpecReference::new(
        "RFC 8044",
        "Data Types in RADIUS",
        "https://www.rfc-editor.org/rfc/rfc8044",
    ),
    SpecReference::new(
        "RFC 2548",
        "Microsoft Vendor-specific RADIUS Attributes",
        "https://www.rfc-editor.org/rfc/rfc2548",
    ),
    SpecReference::new(
        "3GPP TS 29.061",
        "Interworking between the Public Land Mobile Network (PLMN) supporting packet based services and Packet Data Networks (PDN)",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.061/",
    ),
    SpecReference::new(
        "RFC 3575",
        "IANA Considerations for RADIUS (Remote Authentication Dial In User Service)",
        "https://www.rfc-editor.org/rfc/rfc3575",
    ),
    SpecReference::new(
        "RFC 5997",
        "Use of Status-Server Packets in the Remote Authentication Dial In User Service (RADIUS) Protocol",
        "https://www.rfc-editor.org/rfc/rfc5997",
    ),
];

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

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
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
    // | 2865 § 5     | Text as Str when valid UTF-8         | test_parse_access_reject               |
    // | 2865 § 5     | Text with invalid UTF-8 stays Bytes  | test_text_invalid_utf8_is_bytes        |
    // | 2865 § 5.26   | VSA sub-attributes (3GPP)            | test_vsa_3gpp_sub_attributes           |
    // | 2865 § 5.26   | VSA not TLV-shaped: raw fallback     | test_vsa_not_tlv_shaped_falls_back     |
    // | 2865 § 5.26   | VSA sub-attributes (Microsoft)       | test_vsa_microsoft_sub_attribute       |
    // | 2865 § 5.26   | VSA of vendor w/o dictionary: raw    | test_parse_vendor_specific             |
    // | 2866 § 3      | Code: Accounting-Request (4)         | test_parse_accounting_request          |
    // | 2866 § 3      | Code: Accounting-Response (5)        | test_parse_accounting_response         |
    // | 2866 § 5.1    | Acct-Status-Type (Integer/Enum)      | test_parse_accounting_request          |
    // | 2866 § 5.10   | Acct-Terminate-Cause                 | attr::test_enum_value_name_acct_terminate_cause |
    // | 2867 § 3      | Acct-Status-Type tunnel values       | attr::test_enum_value_name_acct_status_type_tunnel |
    // | 2867 § 4.1-2  | Acct-Tunnel-Connection / -Packets-Lost | test_rfc2867_attributes              |
    // | 2868 § 3.1    | Tunnel-Type (tagged Integer)         | test_tunnel_type_tagged                |
    // | 2868 § 3.2    | Tunnel-Medium-Type (tagged Integer)  | test_tunnel_medium_type_tagged         |
    // | 2868 § 3.3    | Tunnel-Client-Endpoint with Tag      | test_tunnel_text_with_tag              |
    // | 2868 § 3.3    | Tunnel-Client-Endpoint without Tag   | test_tunnel_text_without_tag           |
    // | 2868 § 3.5    | Tunnel-Password (Tag, Salt, String)  | test_tunnel_password                   |
    // | 2868 § 3.1    | Tagged Integer with bad length       | test_tagged_integer_bad_length         |
    // | 2869 § 5.1-2  | Acct-Input/Output-Gigawords          | test_acct_gigawords                    |
    // | 2869 § 5.3    | Event-Timestamp (Time)               | test_event_timestamp                   |
    // | 2869 § 5.13   | EAP-Message (raw)                    | test_eap_message_and_authenticator     |
    // | 3579 § 3.1    | EAP-Message decoded as EAP (eap)     | test_eap_message_decoded               |
    // | 3579 § 3.1    | Fragmented EAP-Message stays raw     | test_eap_message_fragment_stays_raw    |
    // | 3579 § 3.1    | Continuation fragment not decoded    | test_eap_message_continuation_not_decoded |
    // | 2869 § 5.14   | Message-Authenticator                | test_eap_message_and_authenticator     |
    // | 3162 § 2.1    | NAS-IPv6-Address                     | test_nas_ipv6_address                  |
    // | 3162 § 2.3    | Framed-IPv6-Prefix                   | test_framed_ipv6_prefix                |
    // | 3162 § 2.3    | Invalid Prefix-Length: raw fallback  | test_ipv6_prefix_invalid_falls_back    |
    // | 4372 § 2.1    | Chargeable-User-Identity             | test_chargeable_user_identity          |
    // | 4818 § 3      | Delegated-IPv6-Prefix                | test_delegated_ipv6_prefix             |
    // | 5176 § 2.3    | Codes 40-45 (Disconnect / CoA)       | test_dynamic_authorization_codes       |
    // | 5176 § 3.5    | Error-Cause values                   | test_error_cause                       |
    // | 5447 § 4.2.5  | MIP6-Feature-Vector (integer64)      | test_integer64_attribute               |
    // | 6572 § 4.12   | PMIP6-Home-IPv4-HoA (ipv4prefix)     | test_ipv4_prefix_attribute             |
    // | 6911 § 3.1    | Framed-IPv6-Address                  | test_framed_ipv6_address               |
    // | 6929 § 2.1    | Extended-Type (241.1 Frag-Status)    | test_extended_type_attribute           |
    // | 6929 § 2.2    | Long-Extended-Type with M flag       | test_long_extended_type_more_flag      |
    // | 6929 § 2.4    | Extended-Vendor-Specific             | test_extended_vendor_specific          |
    // | 6929 § 2.2    | Last fragment (M clear) stays raw    | test_long_extended_last_fragment_not_interpreted |
    // | 6929 § 2.2    | Non-contiguous fragments             | test_long_extended_non_contiguous_fragments |
    // | 6929 § 2.2    | Fragments tracked per Extended-Type  | test_long_extended_fragments_tracked_per_extended_type |
    // | 6929 § 2.4    | EVS continuation fragment not split  | test_long_extended_evs_continuation_not_split |
    // | 6929 § 2.4    | EVS with empty EVS-Value: raw        | test_extended_vendor_specific_empty_value_is_raw |
    // | 6929 § 2.1    | Extended-Type too short: raw         | test_extended_type_too_short           |
    // | 6929 § 2.1    | Unknown Extended-Type                | test_extended_type_unknown             |
    // | 7930 § 4      | Protocol-Error / Original-Packet-Code | test_extended_original_packet_code    |
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
            FieldValue::Str("Authentication failed")
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
        vsa_value.extend_from_slice(b"\x01\x0dhello=world"); // vendor sub-attribute
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
        expected_raw.extend_from_slice(b"\x01\x0dhello=world");
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
            FieldValue::Bytes(b"\x01\x0dhello=world")
        );
        assert_eq!(
            buf.resolve_nested_display_name(&obj_range, "vendor_id_name"),
            Some("Cisco")
        );
        // Vendors without a dictionary are not assumed to follow the
        // RFC 2865, Section 5.26 recommended format (some use 2- or 4-octet
        // vendor types), so no sub-attributes are emitted.
        assert!(!has_field(&buf, &obj_range, "vendor_attributes"));
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

    /// Dissect a packet carrying a single attribute and return the buffer.
    fn dissect_single_attr(attr_type: u8, value: &[u8]) -> DissectBuffer<'static> {
        dissect_attrs(&[build_attr(attr_type, value)])
    }

    /// Return the first attribute Object range of `buf`.
    fn first_attr(buf: &DissectBuffer) -> core::ops::Range<u32> {
        let array_range = attrs_array_range(buf);
        nth_object_range(buf, &array_range, 0)
    }

    fn has_field(buf: &DissectBuffer, obj_range: &core::ops::Range<u32>, name: &str) -> bool {
        buf.nested_fields(obj_range)
            .iter()
            .any(|f| f.name() == name)
    }

    #[test]
    fn test_acct_gigawords() {
        // RFC 2869, Section 5.1 / 5.2 — Acct-Input-Gigawords (52) and
        // Acct-Output-Gigawords (53) are Integer attributes.
        for (code, name) in [(52, "Acct-Input-Gigawords"), (53, "Acct-Output-Gigawords")] {
            let buf = dissect_single_attr(code, &[0, 0, 0, 1]);
            let obj = first_attr(&buf);
            assert_eq!(*obj_field_value(&buf, &obj, "name"), FieldValue::Str(name));
            assert_eq!(*obj_field_value(&buf, &obj, "value"), FieldValue::U32(1));
        }
    }

    #[test]
    fn test_event_timestamp() {
        let buf = dissect_single_attr(55, &0x6500_0000u32.to_be_bytes());
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Event-Timestamp")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::U32(0x6500_0000)
        );
    }

    #[test]
    fn test_eap_message_and_authenticator() {
        let buf = dissect_single_attr(79, &[0x02, 0x01, 0x00, 0x05, 0x01]);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("EAP-Message")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Bytes(&[0x02, 0x01, 0x00, 0x05, 0x01])
        );

        let buf = dissect_single_attr(80, &[0x11; 16]);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Message-Authenticator")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Bytes(&[0x11; 16])
        );
    }

    #[cfg(feature = "eap")]
    #[test]
    fn test_eap_message_decoded() {
        // RFC 3579, Section 3.1 — EAP-Message carries an EAP packet.
        // https://www.rfc-editor.org/rfc/rfc3579#section-3.1
        let buf = dissect_single_attr(79, &[0x02, 0x01, 0x00, 0x08, 0x01, b'b', b'o', b'b']);
        let obj = first_attr(&buf);
        // The raw value stays for filtering.
        assert!(has_field(&buf, &obj, "value"));
        let eap = obj_field_value(&buf, &obj, "eap");
        assert!(matches!(eap, FieldValue::Object(_)));
        let eap = eap.as_container_range().unwrap();
        assert_eq!(
            buf.resolve_nested_display_name(eap, "code_name"),
            Some("Response")
        );
        assert_eq!(
            buf.resolve_nested_display_name(eap, "type_name"),
            Some("Identity")
        );
        let identity = buf
            .nested_fields(eap)
            .iter()
            .find(|f| f.name() == "identity")
            .unwrap();
        assert_eq!(identity.value, FieldValue::Bytes(b"bob"));
    }

    #[cfg(feature = "eap")]
    #[test]
    fn test_eap_message_fragment_stays_raw() {
        // An EAP packet split over several EAP-Message attributes (RFC 3579,
        // Section 3.1 — https://www.rfc-editor.org/rfc/rfc3579#section-3.1)
        // is longer than the first attribute; only the raw value is shown.
        let buf = dissect_single_attr(79, &[0x01, 0x02, 0x01, 0x00, 0x0D, 0x80]);
        let obj = first_attr(&buf);
        assert!(has_field(&buf, &obj, "value"));
        assert!(!has_field(&buf, &obj, "eap"));
    }

    #[cfg(feature = "eap")]
    #[test]
    fn test_eap_message_continuation_not_decoded() {
        // RFC 3579, Section 3.1 — several EAP-Message attributes form one EAP
        // packet (https://www.rfc-editor.org/rfc/rfc3579#section-3.1). A
        // continuation fragment that happens to look like a whole EAP packet
        // must not be decoded on its own.
        let first = build_attr(79, &[0x01, 0x02, 0x00, 0x0A, 0x0D, 0x00]);
        let second = build_attr(79, &[0x03, 0x02, 0x00, 0x04]);
        let data = build_radius(11, 2, &auth(), &[first, second].concat());
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();
        let attrs = attrs_array_range(&buf);
        for n in 0..2 {
            let obj = nth_object_range(&buf, &attrs, n);
            assert!(!has_field(&buf, &obj, "eap"), "attribute {n}");
        }
    }

    #[test]
    fn test_text_invalid_utf8_is_bytes() {
        // Reply-Message (Text) with invalid UTF-8 keeps the raw octets.
        let buf = dissect_single_attr(18, &[0xff, 0xfe]);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Bytes(&[0xff, 0xfe])
        );
    }

    #[test]
    fn test_rfc2867_attributes() {
        let buf = dissect_single_attr(68, b"conn-1");
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Acct-Tunnel-Connection")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Str("conn-1")
        );

        let buf = dissect_single_attr(86, &7u32.to_be_bytes());
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Acct-Tunnel-Packets-Lost")
        );
        assert_eq!(*obj_field_value(&buf, &obj, "value"), FieldValue::U32(7));
    }

    #[test]
    fn test_tunnel_type_tagged() {
        // RFC 2868, Section 3.1 — Tag (1) + Value (3). 3 = L2TP.
        let buf = dissect_single_attr(64, &[0x01, 0x00, 0x00, 0x03]);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Tunnel-Type")
        );
        assert_eq!(*obj_field_value(&buf, &obj, "tag"), FieldValue::U8(1));
        assert_eq!(*obj_field_value(&buf, &obj, "value"), FieldValue::U32(3));
        assert_eq!(
            buf.resolve_nested_display_name(&obj, "value_name"),
            Some("Layer Two Tunneling Protocol (L2TP)")
        );
        let fields = buf.nested_fields(&obj);
        let tag = fields.iter().find(|f| f.name() == "tag").unwrap();
        assert_eq!(tag.range, 22..23);
        let value = fields.iter().find(|f| f.name() == "value").unwrap();
        assert_eq!(value.range, 23..26);
    }

    #[test]
    fn test_tunnel_medium_type_tagged() {
        let buf = dissect_single_attr(65, &[0x00, 0x00, 0x00, 0x01]);
        let obj = first_attr(&buf);
        assert_eq!(*obj_field_value(&buf, &obj, "tag"), FieldValue::U8(0));
        assert_eq!(*obj_field_value(&buf, &obj, "value"), FieldValue::U32(1));
        assert_eq!(
            buf.resolve_nested_display_name(&obj, "value_name"),
            Some("IPv4 (IP version 4)")
        );

        let buf = dissect_single_attr(83, &[0x02, 0x00, 0x00, 0x0a]);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Tunnel-Preference")
        );
        assert_eq!(*obj_field_value(&buf, &obj, "tag"), FieldValue::U8(2));
        assert_eq!(*obj_field_value(&buf, &obj, "value"), FieldValue::U32(10));
    }

    #[test]
    fn test_tagged_integer_bad_length() {
        // Tunnel-Type must be exactly Tag + 3 octets; anything else is raw.
        let buf = dissect_single_attr(64, &[0x01, 0x03]);
        let obj = first_attr(&buf);
        assert!(!has_field(&buf, &obj, "tag"));
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Bytes(&[0x01, 0x03])
        );
    }

    #[test]
    fn test_tunnel_text_with_tag() {
        // RFC 2868, Section 3.3 — Tag 0x01..=0x1F precedes the string.
        let buf = dissect_single_attr(66, b"\x05192.0.2.1");
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Tunnel-Client-Endpoint")
        );
        assert_eq!(*obj_field_value(&buf, &obj, "tag"), FieldValue::U8(5));
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Str("192.0.2.1")
        );
    }

    #[test]
    fn test_tunnel_text_without_tag() {
        // RFC 2868, Section 3.3 — a first octet > 0x1F is part of the string.
        let buf = dissect_single_attr(81, b"vlan10");
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Tunnel-Private-Group-ID")
        );
        assert!(!has_field(&buf, &obj, "tag"));
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Str("vlan10")
        );
    }

    #[test]
    fn test_tunnel_password() {
        // RFC 2868, Section 3.5 — Tag (1) + Salt (2) + String.
        let buf = dissect_single_attr(69, &[0x01, 0x80, 0x01, 0xaa, 0xbb]);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Tunnel-Password")
        );
        assert_eq!(*obj_field_value(&buf, &obj, "tag"), FieldValue::U8(1));
        assert_eq!(
            *obj_field_value(&buf, &obj, "salt"),
            FieldValue::U16(0x8001)
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Bytes(&[0xaa, 0xbb])
        );
    }

    #[test]
    fn test_chargeable_user_identity() {
        let buf = dissect_single_attr(89, b"cui-1");
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Chargeable-User-Identity")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Bytes(b"cui-1")
        );
    }

    #[test]
    fn test_nas_ipv6_address() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let buf = dissect_single_attr(95, &addr);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("NAS-IPv6-Address")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Ipv6Addr(addr)
        );
    }

    #[test]
    fn test_framed_ipv6_address() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let buf = dissect_single_attr(168, &addr);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Framed-IPv6-Address")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Ipv6Addr(addr)
        );
    }

    #[test]
    fn test_framed_ipv6_prefix() {
        // RFC 3162, Section 2.3 — Reserved (1) + Prefix-Length (1) + Prefix.
        let buf = dissect_single_attr(97, &[0x00, 32, 0x20, 0x01, 0x0d, 0xb8]);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Framed-IPv6-Prefix")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "prefix_length"),
            FieldValue::U8(32)
        );
        let mut expected = [0u8; 16];
        expected[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Ipv6Addr(expected)
        );
    }

    #[test]
    fn test_delegated_ipv6_prefix() {
        // RFC 4818, Section 3 — same format as Framed-IPv6-Prefix.
        let mut value = vec![0x00, 56];
        value.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x02]);
        let buf = dissect_single_attr(123, &value);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Delegated-IPv6-Prefix")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "prefix_length"),
            FieldValue::U8(56)
        );
    }

    #[test]
    fn test_ipv6_prefix_invalid_falls_back() {
        // Prefix-Length > 128 is invalid: keep raw bytes.
        let buf = dissect_single_attr(97, &[0x00, 129, 0x20]);
        let obj = first_attr(&buf);
        assert!(!has_field(&buf, &obj, "prefix_length"));
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Bytes(&[0x00, 129, 0x20])
        );
        // Prefix longer than 16 octets is invalid as well.
        let buf = dissect_single_attr(97, &[0u8; 19]);
        let obj = first_attr(&buf);
        assert!(!has_field(&buf, &obj, "prefix_length"));
    }

    #[test]
    fn test_ipv4_prefix_attribute() {
        // RFC 8044, Section 3.11 — Reserved (1) + Prefix-Length (1) + Prefix (4).
        let buf = dissect_single_attr(155, &[0x00, 24, 192, 0, 2, 0]);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("PMIP6-Home-IPv4-HoA")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "prefix_length"),
            FieldValue::U8(24)
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Ipv4Addr([192, 0, 2, 0])
        );
        // Prefix-Length > 32 is invalid.
        let buf = dissect_single_attr(155, &[0x00, 33, 192, 0, 2, 0]);
        let obj = first_attr(&buf);
        assert!(!has_field(&buf, &obj, "prefix_length"));
    }

    #[test]
    fn test_integer64_attribute() {
        let buf = dissect_single_attr(124, &0x0102_0304_0506_0708u64.to_be_bytes());
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("MIP6-Feature-Vector")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::U64(0x0102_0304_0506_0708)
        );
    }

    #[test]
    fn test_error_cause() {
        let buf = dissect_single_attr(101, &503u32.to_be_bytes());
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Error-Cause")
        );
        assert_eq!(*obj_field_value(&buf, &obj, "value"), FieldValue::U32(503));
        assert_eq!(
            buf.resolve_nested_display_name(&obj, "value_name"),
            Some("Session Context Not Found")
        );
    }

    #[test]
    fn test_dynamic_authorization_codes() {
        // RFC 5176, Section 2.3 — codes 40-45.
        let expected = [
            (40, "Disconnect-Request"),
            (41, "Disconnect-ACK"),
            (42, "Disconnect-NAK"),
            (43, "CoA-Request"),
            (44, "CoA-ACK"),
            (45, "CoA-NAK"),
        ];
        for (code, name) in expected {
            let data = build_radius(code, 1, &auth(), &[]);
            let mut buf = DissectBuffer::new();
            RadiusDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert_eq!(buf.resolve_display_name(layer, "code_name"), Some(name));
        }
    }

    #[test]
    fn test_extended_type_attribute() {
        // RFC 6929, Section 2.1 — 241.1 Frag-Status (RFC 7499), integer.
        let buf = dissect_single_attr(241, &[0x01, 0, 0, 0, 2]);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "extended_type"),
            FieldValue::U8(1)
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Frag-Status")
        );
        assert_eq!(*obj_field_value(&buf, &obj, "value"), FieldValue::U32(2));
        let (idx, _) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "attribute")
            .unwrap();
        assert_eq!(
            buf.resolve_container_display_name(idx as u32),
            Some("Frag-Status")
        );
    }

    #[test]
    fn test_extended_original_packet_code() {
        // RFC 7930, Section 4 — Protocol-Error (52) carrying
        // Original-Packet-Code (241.4) = CoA-Request (43).
        let data = build_radius(52, 1, &auth(), &build_attr(241, &[0x04, 0, 0, 0, 43]));
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "code_name"),
            Some("Protocol-Error")
        );
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Original-Packet-Code")
        );
        assert_eq!(
            buf.resolve_nested_display_name(&obj, "value_name"),
            Some("CoA-Request")
        );
        // Other extended integers have no value names.
        let buf = dissect_single_attr(241, &[0x02, 0, 0, 0, 43]);
        let obj = first_attr(&buf);
        assert_eq!(buf.resolve_nested_display_name(&obj, "value_name"), None);
    }

    #[test]
    fn test_extended_type_unknown() {
        let buf = dissect_single_attr(243, &[0x07, 0xaa]);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "extended_type"),
            FieldValue::U8(7)
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Extended-Attribute-3")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Bytes(&[0xaa])
        );
    }

    #[test]
    fn test_extended_type_too_short() {
        // RFC 6929, Section 2.1 — Length >= 4; a bare Extended-Type is invalid.
        let buf = dissect_single_attr(241, &[0x01]);
        let obj = first_attr(&buf);
        assert!(!has_field(&buf, &obj, "extended_type"));
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Bytes(&[0x01])
        );
        // Long Extended Type needs Extended-Type, flags and one value octet.
        let buf = dissect_single_attr(245, &[0x01, 0x00]);
        let obj = first_attr(&buf);
        assert!(!has_field(&buf, &obj, "extended_type"));
    }

    #[test]
    fn test_long_extended_type_more_flag() {
        // RFC 6929, Section 2.2 — Extended-Type, M flag, Reserved, Value.
        let buf = dissect_single_attr(245, &[0x01, 0x80, b'<', b'a', b'>']);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("SAML-Assertion")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "extended_type"),
            FieldValue::U8(1)
        );
        assert_eq!(*obj_field_value(&buf, &obj, "more"), FieldValue::U8(1));
        // A fragment is not interpreted: the value stays raw.
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Bytes(b"<a>")
        );

        let buf = dissect_single_attr(245, &[0x01, 0x00, b'<', b'a', b'>']);
        let obj = first_attr(&buf);
        assert_eq!(*obj_field_value(&buf, &obj, "more"), FieldValue::U8(0));
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Str("<a>")
        );
    }

    #[test]
    fn test_extended_vendor_specific() {
        // RFC 6929, Section 2.4 — Extended-Type 26: Vendor-Id (4) +
        // Vendor-Type (1) + Value.
        let buf = dissect_single_attr(241, &[26, 0, 0, 0x28, 0xaf, 0x05, 0xde, 0xad]);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "name"),
            FieldValue::Str("Extended-Vendor-Specific-1")
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "vendor_id"),
            FieldValue::U32(10415)
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "vendor_type"),
            FieldValue::U8(5)
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Bytes(&[0xde, 0xad])
        );

        // Long Extended EVS carries the flags octet before the Vendor-Id.
        let buf = dissect_single_attr(246, &[26, 0x00, 0, 0, 0x01, 0x37, 0x09, 0x01]);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "vendor_id"),
            FieldValue::U32(311)
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "vendor_type"),
            FieldValue::U8(9)
        );
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Bytes(&[0x01])
        );

        // EVS too short for Vendor-Id + Vendor-Type: raw value.
        let buf = dissect_single_attr(241, &[26, 0, 0, 0x28]);
        let obj = first_attr(&buf);
        assert!(!has_field(&buf, &obj, "vendor_id"));
    }

    /// Dissect a packet carrying the given raw attributes.
    fn dissect_attrs(attrs: &[Vec<u8>]) -> DissectBuffer<'static> {
        let data = build_radius(4, 1, &auth(), &attrs.concat());
        let leaked: &'static [u8] = Box::leak(data.into_boxed_slice());
        let mut buf = DissectBuffer::new();
        RadiusDissector.dissect(leaked, &mut buf, 0).unwrap();
        buf
    }

    /// RFC 6929, Section 2.2 — "Any interpretation of the resulting data
    /// MUST occur after the fragments have been reassembled." The last
    /// fragment (M clear) of a fragmented value is not a complete value.
    /// <https://www.rfc-editor.org/rfc/rfc6929#section-2.2>
    #[test]
    fn test_long_extended_last_fragment_not_interpreted() {
        let buf = dissect_attrs(&[
            build_attr(245, &[0x01, 0x80, b'<', b'a']),
            build_attr(245, &[0x01, 0x00, b'/', b'>']),
        ]);
        let array = attrs_array_range(&buf);
        let last = nth_object_range(&buf, &array, 1);
        assert_eq!(*obj_field_value(&buf, &last, "more"), FieldValue::U8(0));
        assert_eq!(
            *obj_field_value(&buf, &last, "value"),
            FieldValue::Bytes(b"/>")
        );
    }

    /// RFC 6929, Section 2.2 — fragments may be "mixed together with other
    /// attributes of a different Type", so a fragment is recognised even
    /// when another attribute sits between it and the previous fragment.
    /// A later attribute of the same Type.Extended-Type after the last
    /// fragment is a new, complete value.
    /// <https://www.rfc-editor.org/rfc/rfc6929#section-2.2>
    #[test]
    fn test_long_extended_non_contiguous_fragments() {
        let buf = dissect_attrs(&[
            build_attr(245, &[0x01, 0x80, b'<', b'a']),
            build_attr(1, b"bob"),
            build_attr(245, &[0x01, 0x00, b'/', b'>']),
            build_attr(245, &[0x01, 0x00, b'<', b'b', b'>']),
        ]);
        let array = attrs_array_range(&buf);
        let last_fragment = nth_object_range(&buf, &array, 2);
        assert_eq!(
            *obj_field_value(&buf, &last_fragment, "value"),
            FieldValue::Bytes(b"/>")
        );
        let complete = nth_object_range(&buf, &array, 3);
        assert_eq!(
            *obj_field_value(&buf, &complete, "value"),
            FieldValue::Str("<b>")
        );
    }

    /// RFC 6929, Section 2.2 — fragments of one Type.Extended-Type are
    /// tracked separately from other Extended-Types of the same Type, for
    /// both Long Extended Type attributes (245 and 246).
    /// <https://www.rfc-editor.org/rfc/rfc6929#section-2.2>
    #[test]
    fn test_long_extended_fragments_tracked_per_extended_type() {
        for code in [245, 246] {
            let buf = dissect_attrs(&[
                build_attr(code, &[0x01, 0x80, b'<', b'a']),
                build_attr(code, &[0x02, 0x80, 0xaa]),
                build_attr(code, &[0x02, 0x00, 0xbb]),
                build_attr(code, &[0x01, 0x00, b'/', b'>']),
            ]);
            let array = attrs_array_range(&buf);
            let last = nth_object_range(&buf, &array, 3);
            assert_eq!(
                *obj_field_value(&buf, &last, "value"),
                FieldValue::Bytes(b"/>"),
                "type {code}"
            );
        }
    }

    /// RFC 6929, Section 2.4 — the Vendor-Id and EVS-Type are only in the
    /// first fragment; later fragments carry data only and must not be
    /// split into Vendor-Id / Vendor-Type.
    /// <https://www.rfc-editor.org/rfc/rfc6929#section-2.4>
    #[test]
    fn test_long_extended_evs_continuation_not_split() {
        let buf = dissect_attrs(&[
            build_attr(245, &[26, 0x80, 0, 0, 0x28, 0xaf, 0x05, 0xde]),
            build_attr(245, &[26, 0x00, 0, 0, 0x01, 0x37, 0x09, 0x01]),
        ]);
        let array = attrs_array_range(&buf);
        let first = nth_object_range(&buf, &array, 0);
        assert_eq!(
            *obj_field_value(&buf, &first, "vendor_id"),
            FieldValue::U32(10415)
        );
        let last = nth_object_range(&buf, &array, 1);
        assert!(!has_field(&buf, &last, "vendor_id"));
        assert!(!has_field(&buf, &last, "vendor_type"));
        assert_eq!(
            *obj_field_value(&buf, &last, "value"),
            FieldValue::Bytes(&[0, 0, 0x01, 0x37, 0x09, 0x01])
        );
    }

    /// RFC 6929, Section 2.4 — "The EVS-Value field is one or more octets."
    /// An EVS with Vendor-Id and EVS-Type but no EVS-Value is invalid and
    /// stays raw.
    /// <https://www.rfc-editor.org/rfc/rfc6929#section-2.4>
    #[test]
    fn test_extended_vendor_specific_empty_value_is_raw() {
        let buf = dissect_single_attr(241, &[26, 0, 0, 0x28, 0xaf, 0x05]);
        let obj = first_attr(&buf);
        assert!(!has_field(&buf, &obj, "vendor_id"));
        assert_eq!(
            *obj_field_value(&buf, &obj, "value"),
            FieldValue::Bytes(&[0, 0, 0x28, 0xaf, 0x05])
        );
    }

    /// Return the `vendor_attributes` Array range of the first attribute.
    fn vendor_attrs_range(buf: &DissectBuffer) -> core::ops::Range<u32> {
        let obj = first_attr(buf);
        match obj_field_value(buf, &obj, "vendor_attributes") {
            FieldValue::Array(r) => r.clone(),
            other => panic!("expected Array, got {other:?}"),
        }
    }

    #[test]
    fn test_vsa_3gpp_sub_attributes() {
        // TS 29.061 v19.1.0, clause 16.4.7.2 — 3GPP-IMSI (1, Text) and
        // 3GPP-PDP-Type (3, Unsigned32).
        let mut vsa = 10415u32.to_be_bytes().to_vec();
        vsa.extend_from_slice(&[0x01, 0x0a]);
        vsa.extend_from_slice(b"00101012");
        vsa.extend_from_slice(&[0x03, 0x06, 0, 0, 0, 2]);
        vsa.extend_from_slice(&[0x15, 0x03, 0x06]);
        let buf = dissect_single_attr(26, &vsa);
        let obj = first_attr(&buf);
        assert_eq!(
            *obj_field_value(&buf, &obj, "vendor_id"),
            FieldValue::U32(10415)
        );
        assert_eq!(
            buf.resolve_nested_display_name(&obj, "vendor_id_name"),
            Some("3GPP")
        );

        let arr = vendor_attrs_range(&buf);
        assert_eq!(count_objects(&buf, &arr), 3);
        let imsi = nth_object_range(&buf, &arr, 0);
        assert_eq!(
            *obj_field_value(&buf, &imsi, "vendor_type"),
            FieldValue::U8(1)
        );
        assert_eq!(
            *obj_field_value(&buf, &imsi, "vendor_length"),
            FieldValue::U8(10)
        );
        assert_eq!(
            *obj_field_value(&buf, &imsi, "name"),
            FieldValue::Str("3GPP-IMSI")
        );
        assert_eq!(
            *obj_field_value(&buf, &imsi, "value"),
            FieldValue::Str("00101012")
        );
        let imsi_value = buf
            .nested_fields(&imsi)
            .iter()
            .find(|f| f.name() == "value")
            .unwrap()
            .range
            .clone();
        assert_eq!(imsi_value, 28..36);

        let pdp = nth_object_range(&buf, &arr, 1);
        assert_eq!(
            *obj_field_value(&buf, &pdp, "name"),
            FieldValue::Str("3GPP-PDP-Type")
        );
        assert_eq!(*obj_field_value(&buf, &pdp, "value"), FieldValue::U32(2));
        assert_eq!(
            buf.resolve_nested_display_name(&pdp, "value_name"),
            Some("IPv6")
        );

        let rat = nth_object_range(&buf, &arr, 2);
        assert_eq!(
            *obj_field_value(&buf, &rat, "name"),
            FieldValue::Str("3GPP-RAT-Type")
        );
        assert_eq!(*obj_field_value(&buf, &rat, "value"), FieldValue::U8(6));

        // Container label resolves to the vendor attribute name.
        let (idx, _) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "vendor_attribute")
            .unwrap();
        assert_eq!(
            buf.resolve_container_display_name(idx as u32),
            Some("3GPP-IMSI")
        );
    }

    #[test]
    fn test_vsa_microsoft_sub_attribute() {
        // RFC 2548, Section 2.4.4 — MS-MPPE-Encryption-Policy (7), Integer.
        let mut vsa = 311u32.to_be_bytes().to_vec();
        vsa.extend_from_slice(&[0x07, 0x06, 0, 0, 0, 2]);
        let buf = dissect_single_attr(26, &vsa);
        let obj = first_attr(&buf);
        assert_eq!(
            buf.resolve_nested_display_name(&obj, "vendor_id_name"),
            Some("Microsoft")
        );
        let arr = vendor_attrs_range(&buf);
        let policy = nth_object_range(&buf, &arr, 0);
        assert_eq!(
            *obj_field_value(&buf, &policy, "name"),
            FieldValue::Str("MS-MPPE-Encryption-Policy")
        );
        assert_eq!(*obj_field_value(&buf, &policy, "value"), FieldValue::U32(2));
        assert_eq!(
            buf.resolve_nested_display_name(&policy, "value_name"),
            Some("Encryption-Required")
        );
    }

    #[test]
    fn test_vsa_not_tlv_shaped_falls_back() {
        // The vendor String does not follow the recommended format: the
        // sub-attribute lengths do not add up, so only raw bytes are kept.
        let mut vsa = 10415u32.to_be_bytes().to_vec();
        vsa.extend_from_slice(&[0x01, 0x09, b'a', b'b']);
        let buf = dissect_single_attr(26, &vsa);
        let obj = first_attr(&buf);
        assert!(!has_field(&buf, &obj, "vendor_attributes"));
        assert_eq!(
            *obj_field_value(&buf, &obj, "vendor_data"),
            FieldValue::Bytes(&[0x01, 0x09, b'a', b'b'])
        );
        // Vendor length < 2 is invalid as well.
        let mut vsa = 10415u32.to_be_bytes().to_vec();
        vsa.extend_from_slice(&[0x01, 0x01]);
        let buf = dissect_single_attr(26, &vsa);
        let obj = first_attr(&buf);
        assert!(!has_field(&buf, &obj, "vendor_attributes"));
        // Empty vendor String: no sub-attributes.
        let buf = dissect_single_attr(26, &10415u32.to_be_bytes());
        let obj = first_attr(&buf);
        assert!(!has_field(&buf, &obj, "vendor_attributes"));
    }

    #[test]
    fn references_and_layer_are_populated() {
        let dissector = RadiusDissector;
        let references = dissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Application));
    }
}
