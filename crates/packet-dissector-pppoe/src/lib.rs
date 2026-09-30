//! PPPoE (PPP over Ethernet) dissector.
//!
//! Decodes the PPPoE header shared by both stages (RFC 2516, Section 4), the
//! TAGs carried by Discovery packets (EtherType 0x8863; Section 5 and
//! Appendix A) and the header of PPP Session packets (EtherType 0x8864;
//! Section 6). A Session payload is handed to the PPP dissector.
//!
//! Three dissectors produce the same `PPPoE` layer:
//!
//! - [`PppoeDiscoveryDissector`] for EtherType 0x8863,
//! - [`PppoeSessionDissector`] for EtherType 0x8864,
//! - [`PppoeDissector`] for `LINKTYPE_PPP_ETHER` (51), where the stage is
//!   told apart by the CODE field alone.
//!
//! ## References
//! - RFC 2516 (PPPoE): <https://www.rfc-editor.org/rfc/rfc2516>
//! - RFC 2516 errata (5634 on Appendix A): <https://www.rfc-editor.org/errata/rfc2516>
//! - RFC 4638 (PPP-Max-Payload TAG): <https://www.rfc-editor.org/rfc/rfc4638>
//! - RFC 5578 (Credits, Metrics, Sequence Number TAGs and PADG/PADC/PADQ):
//!   <https://www.rfc-editor.org/rfc/rfc5578>
//! - RFC 4937 (IANA Considerations for PPPoE, establishes the code and TAG
//!   registries): <https://www.rfc-editor.org/rfc/rfc4937>
//! - IANA PPPoE Parameters: <https://www.iana.org/assignments/pppoe-parameters>
//! - LINKTYPE_PPP_ETHER: <https://www.tcpdump.org/linktypes.html>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

/// PPPoE header size: VER/TYPE, CODE, SESSION_ID and LENGTH.
/// RFC 2516, Section 4 — <https://www.rfc-editor.org/rfc/rfc2516#section-4>
pub const HEADER_SIZE: usize = 6;

/// TAG header size: TAG_TYPE and TAG_LENGTH.
/// RFC 2516, Section 5 — <https://www.rfc-editor.org/rfc/rfc2516#section-5>
const TAG_HEADER_SIZE: usize = 4;

/// RFC 2516, Section 4 — "The VER field is four bits and MUST be set to 0x1
/// for this version of the PPPoE specification."
/// <https://www.rfc-editor.org/rfc/rfc2516#section-4>
const VERSION_1: u8 = 1;

/// RFC 2516, Section 4 — "The TYPE field is four bits and MUST be set to 0x1
/// for this version of the PPPoE specification."
/// <https://www.rfc-editor.org/rfc/rfc2516#section-4>
const TYPE_1: u8 = 1;

/// RFC 2516, Section 6 — "The PPPoE CODE MUST be set to 0x00."
/// <https://www.rfc-editor.org/rfc/rfc2516#section-6>
const CODE_SESSION: u8 = 0x00;

/// EtherType of PPP frames (IEEE-assigned 0x880B), under which the PPP
/// dissector is registered. A PPPoE Session payload is a PPP frame that
/// "begins with the PPP Protocol-ID" (RFC 2516, Section 6 —
/// <https://www.rfc-editor.org/rfc/rfc2516#section-6>).
const ETHERTYPE_PPP: u16 = 0x880B;

// TAG types — RFC 2516, Appendix A
// <https://www.rfc-editor.org/rfc/rfc2516#appendix-A>
const TAG_END_OF_LIST: u16 = 0x0000;
const TAG_SERVICE_NAME: u16 = 0x0101;
const TAG_AC_NAME: u16 = 0x0102;
const TAG_VENDOR_SPECIFIC: u16 = 0x0105;
const TAG_SERVICE_NAME_ERROR: u16 = 0x0201;
const TAG_AC_SYSTEM_ERROR: u16 = 0x0202;
const TAG_GENERIC_ERROR: u16 = 0x0203;

/// Size of the vendor id at the start of a Vendor-Specific TAG_VALUE.
/// RFC 2516, Appendix A — "The first four octets of the TAG_VALUE contain
/// the vendor id and the remainder is unspecified."
/// <https://www.rfc-editor.org/rfc/rfc2516#appendix-A>
const VENDOR_ID_SIZE: usize = 4;

/// Returns the name of a PPPoE CODE value.
///
/// RFC 2516, Sections 5.1–5.5 and 6 —
/// <https://www.rfc-editor.org/rfc/rfc2516#section-5.1>; RFC 5578,
/// Section 3.2 — <https://www.rfc-editor.org/rfc/rfc5578#section-3.2>; IANA
/// "PPPoE Active Discovery Code fields" (registry established by RFC 4937 —
/// <https://www.rfc-editor.org/rfc/rfc4937>) —
/// <https://www.iana.org/assignments/pppoe-parameters>. PADM and PADN are
/// assigned there from an Internet-Draft.
pub fn code_name(code: u8) -> Option<&'static str> {
    match code {
        0x00 => Some("Session Data"),
        0x07 => Some("PADO"),
        0x09 => Some("PADI"),
        0x0A => Some("PADG"),
        0x0B => Some("PADC"),
        0x0C => Some("PADQ"),
        0x19 => Some("PADR"),
        0x65 => Some("PADS"),
        0xA7 => Some("PADT"),
        0xD3 => Some("PADM"),
        0xD4 => Some("PADN"),
        _ => None,
    }
}

/// Returns the name of a PPPoE TAG_TYPE value.
///
/// RFC 2516, Appendix A — <https://www.rfc-editor.org/rfc/rfc2516#appendix-A>;
/// IANA "PPPoE TAG Values" (registry established by RFC 4937 —
/// <https://www.rfc-editor.org/rfc/rfc4937>) —
/// <https://www.iana.org/assignments/pppoe-parameters>
/// (RFC 4638 PPP-Max-Payload, RFC 5578 Section 3.1 Credits / Metrics /
/// Sequence Number / Credit Scale Factor —
/// <https://www.rfc-editor.org/rfc/rfc5578#section-3.1>).
pub fn tag_type_name(tag_type: u16) -> Option<&'static str> {
    match tag_type {
        0x0000 => Some("End-Of-List"),
        0x0101 => Some("Service-Name"),
        0x0102 => Some("AC-Name"),
        0x0103 => Some("Host-Uniq"),
        0x0104 => Some("AC-Cookie"),
        0x0105 => Some("Vendor-Specific"),
        0x0106 => Some("Credits"),
        0x0107 => Some("Metrics"),
        0x0108 => Some("Sequence Number"),
        0x0109 => Some("Credit Scale Factor"),
        0x0110 => Some("Relay-Session-Id"),
        0x0111 => Some("HURL"),
        0x0112 => Some("MOTM"),
        0x0120 => Some("PPP-Max-Payload"),
        0x0121 => Some("IP_Route_Add"),
        0x0201 => Some("Service-Name-Error"),
        0x0202 => Some("AC-System-Error"),
        0x0203 => Some("Generic-Error"),
        _ => None,
    }
}

/// Whether the TAG_VALUE of this TAG_TYPE is a UTF-8 string.
///
/// RFC 2516, Appendix A — Service-Name, AC-Name, Service-Name-Error,
/// AC-System-Error and Generic-Error carry UTF-8 text.
/// <https://www.rfc-editor.org/rfc/rfc2516#appendix-A>
fn tag_is_text(tag_type: u16) -> bool {
    matches!(
        tag_type,
        TAG_SERVICE_NAME
            | TAG_AC_NAME
            | TAG_SERVICE_NAME_ERROR
            | TAG_AC_SYSTEM_ERROR
            | TAG_GENERIC_ERROR
    )
}

const FD_VERSION: usize = 0;
const FD_TYPE: usize = 1;
const FD_CODE: usize = 2;
const FD_SESSION_ID: usize = 3;
const FD_LENGTH: usize = 4;
const FD_TAGS: usize = 5;

const FD_TAG_TYPE: usize = 0;
const FD_TAG_LENGTH: usize = 1;
const FD_TAG_VALUE: usize = 2;
const FD_TAG_STRING: usize = 3;
const FD_TAG_VENDOR_ID: usize = 4;

/// Child fields of one TAG.
///
/// RFC 2516, Section 5 — <https://www.rfc-editor.org/rfc/rfc2516#section-5>
static TAG_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Tag Type", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(t) => tag_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Tag Length", FieldType::U16),
    FieldDescriptor::new("value", "Tag Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("string", "Tag Value", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("vendor_id", "Vendor ID", FieldType::U32).optional(),
];

/// One TAG; its label resolves to the TAG name.
static FD_TAG: FieldDescriptor = FieldDescriptor::new("tag", "Tag", FieldType::Object)
    .with_children(TAG_CHILD_FIELDS)
    .with_display_fn(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U16(t)) => tag_type_name(*t),
            _ => None,
        }),
        _ => None,
    });

/// Field descriptors of the `PPPoE` layer.
///
/// RFC 2516, Section 4 — <https://www.rfc-editor.org/rfc/rfc2516#section-4>
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("type", "Type", FieldType::U8),
    FieldDescriptor::new("code", "Code", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(c) => code_name(*c),
        _ => None,
    }),
    FieldDescriptor::new("session_id", "Session ID", FieldType::U16),
    FieldDescriptor::new("length", "Payload Length", FieldType::U16),
    FieldDescriptor::new("tags", "Tags", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_TAG)),
];

/// Specification references shared by the PPPoE dissectors.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 2516",
        "A Method for Transmitting PPP Over Ethernet (PPPoE)",
        "https://www.rfc-editor.org/rfc/rfc2516",
    ),
    SpecReference::new(
        "RFC 4937",
        "IANA Considerations for PPP over Ethernet (PPPoE)",
        "https://www.rfc-editor.org/rfc/rfc4937",
    ),
    SpecReference::new(
        "RFC 4638",
        "Accommodating a Maximum Transit Unit/Maximum Receive Unit (MTU/MRU) Greater Than 1492 in the Point-to-Point Protocol over Ethernet (PPPoE)",
        "https://www.rfc-editor.org/rfc/rfc4638",
    ),
    SpecReference::new(
        "RFC 5578",
        "PPP over Ethernet (PPPoE) Extensions for Credit Flow and Link Metrics",
        "https://www.rfc-editor.org/rfc/rfc5578",
    ),
];

/// Which PPPoE stage a dissector accepts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Discovery,
    Session,
    /// Decide from the CODE field (LINKTYPE_PPP_ETHER).
    Any,
}

/// Parsed PPPoE header.
struct Header {
    code: u8,
    length: u16,
}

/// Read and validate the common PPPoE header.
///
/// RFC 2516, Section 4 — <https://www.rfc-editor.org/rfc/rfc2516#section-4>
fn parse_header(data: &[u8]) -> Result<Header, PacketError> {
    if data.len() < HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: HEADER_SIZE,
            actual: data.len(),
        });
    }
    let version = data[0] >> 4;
    let pppoe_type = data[0] & 0x0F;
    if version != VERSION_1 {
        return Err(PacketError::InvalidFieldValue {
            field: "version",
            value: u32::from(version),
        });
    }
    if pppoe_type != TYPE_1 {
        return Err(PacketError::InvalidFieldValue {
            field: "type",
            value: u32::from(pppoe_type),
        });
    }
    Ok(Header {
        code: data[1],
        length: read_be_u16(data, 4)?,
    })
}

/// Push the common header fields of an already validated header.
fn push_header<'pkt>(data: &'pkt [u8], buf: &mut DissectBuffer<'pkt>, offset: usize) {
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_VERSION],
        FieldValue::U8(data[0] >> 4),
        offset..offset + 1,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_TYPE],
        FieldValue::U8(data[0] & 0x0F),
        offset..offset + 1,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_CODE],
        FieldValue::U8(data[1]),
        offset + 1..offset + 2,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_SESSION_ID],
        FieldValue::U16(u16::from_be_bytes([data[2], data[3]])),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_LENGTH],
        FieldValue::U16(u16::from_be_bytes([data[4], data[5]])),
        offset + 4..offset + 6,
    );
}

/// Check that the TAG list is well formed before anything is pushed.
///
/// Every TAG must lie within the LENGTH-octet payload; the caller has
/// checked that the payload itself was captured, so a TAG running past
/// LENGTH is malformed rather than truncated. Returns the end of the last
/// TAG that is decoded: parsing stops after an End-Of-List TAG ("there are
/// no further TAGs in the list", RFC 2516, Appendix A —
/// <https://www.rfc-editor.org/rfc/rfc2516#appendix-A>).
fn validate_tags(data: &[u8], end: usize) -> Result<usize, PacketError> {
    const TAG_PAST_LENGTH: PacketError = PacketError::InvalidHeader("PPPoE TAG exceeds LENGTH");
    let mut pos = HEADER_SIZE;
    while pos < end {
        if pos + TAG_HEADER_SIZE > end {
            return Err(TAG_PAST_LENGTH);
        }
        let tag_type = read_be_u16(data, pos)?;
        let tag_end = pos + TAG_HEADER_SIZE + usize::from(read_be_u16(data, pos + 2)?);
        if tag_end > end {
            return Err(TAG_PAST_LENGTH);
        }
        pos = tag_end;
        if tag_type == TAG_END_OF_LIST {
            break;
        }
    }
    Ok(pos)
}

/// Push the TAGs of a Discovery packet between the header and `tags_end`,
/// which [`validate_tags`] has checked.
///
/// RFC 2516, Section 5 — <https://www.rfc-editor.org/rfc/rfc2516#section-5>
fn push_tags<'pkt>(
    data: &'pkt [u8],
    tags_end: usize,
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
) {
    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_TAGS],
        FieldValue::Array(0..0),
        offset + HEADER_SIZE..offset + tags_end,
    );
    let mut pos = HEADER_SIZE;
    while pos < tags_end {
        let tag_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let tag_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let value_start = pos + TAG_HEADER_SIZE;
        let value_end = value_start + usize::from(tag_len);
        let value = &data[value_start..value_end];

        let obj_idx = buf.begin_container(
            &FD_TAG,
            FieldValue::Object(0..0),
            offset + pos..offset + value_end,
        );
        buf.push_field(
            &TAG_CHILD_FIELDS[FD_TAG_TYPE],
            FieldValue::U16(tag_type),
            offset + pos..offset + pos + 2,
        );
        buf.push_field(
            &TAG_CHILD_FIELDS[FD_TAG_LENGTH],
            FieldValue::U16(tag_len),
            offset + pos + 2..offset + value_start,
        );
        if tag_is_text(tag_type) {
            buf.push_field(
                &TAG_CHILD_FIELDS[FD_TAG_STRING],
                FieldValue::Bytes(value),
                offset + value_start..offset + value_end,
            );
        } else if tag_type == TAG_VENDOR_SPECIFIC && value.len() >= VENDOR_ID_SIZE {
            // RFC 2516, Appendix A — "The first four octets of the TAG_VALUE
            // contain the vendor id and the remainder is unspecified."
            // <https://www.rfc-editor.org/rfc/rfc2516#appendix-A>
            let vendor_id = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            buf.push_field(
                &TAG_CHILD_FIELDS[FD_TAG_VENDOR_ID],
                FieldValue::U32(vendor_id),
                offset + value_start..offset + value_start + VENDOR_ID_SIZE,
            );
            buf.push_field(
                &TAG_CHILD_FIELDS[FD_TAG_VALUE],
                FieldValue::Bytes(&value[VENDOR_ID_SIZE..]),
                offset + value_start + VENDOR_ID_SIZE..offset + value_end,
            );
        } else {
            buf.push_field(
                &TAG_CHILD_FIELDS[FD_TAG_VALUE],
                FieldValue::Bytes(value),
                offset + value_start..offset + value_end,
            );
        }
        buf.end_container(obj_idx);
        pos = value_end;
    }
    buf.end_container(array_idx);
}

fn dissect_pppoe<'pkt>(
    stage: Stage,
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
) -> Result<DissectResult, PacketError> {
    let header = parse_header(data)?;
    let is_session = match stage {
        Stage::Discovery => false,
        Stage::Session => true,
        Stage::Any => header.code == CODE_SESSION,
    };

    if is_session {
        // RFC 2516, Section 6 — "The PPPoE CODE MUST be set to 0x00."
        // <https://www.rfc-editor.org/rfc/rfc2516#section-6>
        if header.code != CODE_SESSION {
            return Err(PacketError::InvalidFieldValue {
                field: "code",
                value: u32::from(header.code),
            });
        }
        buf.begin_layer(
            "PPPoE",
            None,
            FIELD_DESCRIPTORS,
            offset..offset + HEADER_SIZE,
        );
        push_header(data, buf, offset);
        buf.end_layer();
        // RFC 2516, Section 4 — LENGTH "indicates the length of the PPPoE
        // payload", so octets after it (Ethernet padding) are not PPP data.
        // <https://www.rfc-editor.org/rfc/rfc2516#section-4>
        return Ok(
            DissectResult::new(HEADER_SIZE, DispatchHint::ByEtherType(ETHERTYPE_PPP))
                .with_payload_len(usize::from(header.length)),
        );
    }

    // CODE 0x00 is the PPP Session Stage (IANA "PPPoE Active Discovery Code
    // fields"); it is not a Discovery packet.
    // <https://www.iana.org/assignments/pppoe-parameters>
    if header.code == CODE_SESSION {
        return Err(PacketError::InvalidFieldValue {
            field: "code",
            value: u32::from(header.code),
        });
    }
    let end = HEADER_SIZE + usize::from(header.length);
    if data.len() < end {
        return Err(PacketError::Truncated {
            expected: end,
            actual: data.len(),
        });
    }
    let tags_end = validate_tags(data, end)?;

    buf.begin_layer("PPPoE", None, FIELD_DESCRIPTORS, offset..offset + end);
    push_header(data, buf, offset);
    if tags_end > HEADER_SIZE {
        push_tags(data, tags_end, buf, offset);
    }
    buf.end_layer();
    Ok(DissectResult::new(end, DispatchHint::End))
}

macro_rules! pppoe_dissector {
    ($(#[$doc:meta])* $ty:ident, $stage:expr) => {
        $(#[$doc])*
        pub struct $ty;

        impl Dissector for $ty {
            fn name(&self) -> &'static str {
                "PPP-over-Ethernet"
            }

            fn short_name(&self) -> &'static str {
                "PPPoE"
            }

            fn field_descriptors(&self) -> &'static [FieldDescriptor] {
                FIELD_DESCRIPTORS
            }

            fn references(&self) -> &'static [SpecReference] {
                REFERENCES
            }

            fn layer(&self) -> Option<ProtocolLayer> {
                Some(ProtocolLayer::Link)
            }

            fn dissect<'pkt>(
                &self,
                data: &'pkt [u8],
                buf: &mut DissectBuffer<'pkt>,
                offset: usize,
            ) -> Result<DissectResult, PacketError> {
                dissect_pppoe($stage, data, buf, offset)
            }
        }
    };
}

pppoe_dissector!(
    /// PPPoE Discovery dissector (EtherType 0x8863).
    ///
    /// Decodes PADI, PADO, PADR, PADS, PADT and the other Discovery codes
    /// with their TAGs. A CODE of 0x00 (Session Data) is rejected.
    /// RFC 2516, Section 5 — <https://www.rfc-editor.org/rfc/rfc2516#section-5>
    PppoeDiscoveryDissector,
    Stage::Discovery
);

pppoe_dissector!(
    /// PPPoE Session dissector (EtherType 0x8864).
    ///
    /// Decodes the header and hands the LENGTH-octet payload to the PPP
    /// dissector; octets past LENGTH (Ethernet padding) are not passed on.
    /// A CODE other than 0x00 is rejected.
    /// RFC 2516, Section 6 — <https://www.rfc-editor.org/rfc/rfc2516#section-6>
    PppoeSessionDissector,
    Stage::Session
);

pppoe_dissector!(
    /// PPPoE dissector for `LINKTYPE_PPP_ETHER` (51), where the packet begins
    /// with a PPPoE header and no EtherType tells the stages apart.
    ///
    /// CODE 0x00 is decoded as a Session packet and any other CODE as a
    /// Discovery packet (RFC 2516, Sections 5 and 6 —
    /// <https://www.rfc-editor.org/rfc/rfc2516#section-5>).
    PppoeDissector,
    Stage::Any
);

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 2516 (PPPoE) Coverage
    //
    // | RFC Section | Description                               | Test                                  |
    // |-------------|-------------------------------------------|---------------------------------------|
    // | 4           | Header (VER, TYPE, CODE, SESSION_ID, LEN) | padi_service_name_and_host_uniq       |
    // | 4           | Header truncated                          | truncated_header                      |
    // | 4           | VER != 1 rejected                         | invalid_version                       |
    // | 4           | TYPE != 1 rejected                        | invalid_type                          |
    // | 4           | LENGTH beyond captured data (Discovery)   | discovery_length_exceeds_data         |
    // | 5           | TAG TLV encoding                          | padi_service_name_and_host_uniq       |
    // | 5           | TAG extends past payload                  | truncated_tag                         |
    // | 5           | TAG header truncated                      | truncated_tag_header                  |
    // | 5           | TAG past LENGTH into padding              | tag_exceeds_length_with_padding       |
    // | 5           | Unknown TAG_TYPE kept as raw value        | unknown_tag_type                      |
    // | 5.1         | PADI (0x09), empty Service-Name           | padi_service_name_and_host_uniq       |
    // | 5.2         | PADO (0x07), AC-Name                      | pado_ac_name_and_cookie               |
    // | 5.4         | PADS (0x65), SESSION_ID                   | pads_session_id                       |
    // | 5.5         | PADT (0xa7), no TAGs                      | padt_without_tags                     |
    // | 5           | CODE 0x00 on Discovery rejected           | discovery_rejects_session_code        |
    // | 6           | Session payload handed to PPP             | session_lcp_configure_request         |
    // | 6           | Session LENGTH excludes Ethernet padding  | session_with_ethernet_padding         |
    // | 6           | Non-zero CODE on Session rejected         | session_rejects_discovery_code        |
    // | 6           | Session LENGTH beyond captured data       | session_length_exceeds_data           |
    // | A           | End-Of-List stops TAG parsing             | end_of_list_stops_parsing             |
    // | A           | Vendor-Specific vendor id                 | vendor_specific_tag                   |
    // | A           | Error TAGs carry UTF-8 text               | service_name_error_text               |
    // | A           | Vendor-Specific shorter than vendor id    | vendor_specific_short_value           |
    // | —           | LINKTYPE_PPP_ETHER selects stage by CODE  | link_type_dissector_selects_stage     |
    // | 4           | Discovery LENGTH excludes Ethernet padding| discovery_ignores_ethernet_padding    |
    // | A           | Tag object label is the TAG name          | tag_object_display_name_is_tag_name   |
    // | —           | Name tables (RFC 4937 IANA registries)    | code_and_tag_names                    |
    // | —           | Dissector metadata                        | dissector_metadata                    |

    fn tag_fields<'a>(
        buf: &'a DissectBuffer<'_>,
    ) -> Vec<&'a [packet_dissector_core::field::Field<'a>]> {
        let layer = &buf.layers()[0];
        let tags = buf.field_by_name(layer, "tags").expect("tags");
        let FieldValue::Array(range) = &tags.value else {
            panic!("tags must be an Array");
        };
        buf.nested_fields(range)
            .iter()
            .filter_map(|f| match &f.value {
                FieldValue::Object(r) => Some(buf.nested_fields(r)),
                _ => None,
            })
            .collect()
    }

    fn child<'a>(
        fields: &'a [packet_dissector_core::field::Field<'a>],
        name: &str,
    ) -> Option<&'a FieldValue<'a>> {
        fields.iter().find(|f| f.name() == name).map(|f| &f.value)
    }

    #[test]
    fn padi_service_name_and_host_uniq() {
        // RFC 2516, Appendix B PADI plus a 4-octet Host-Uniq —
        // <https://www.rfc-editor.org/rfc/rfc2516#appendix-B>
        let raw: &[u8] = &[
            0x11, 0x09, 0x00, 0x00, 0x00, 0x0C, // VER=1 TYPE=1 PADI, SID 0, LEN 12
            0x01, 0x01, 0x00, 0x00, // Service-Name, length 0
            0x01, 0x03, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, // Host-Uniq
        ];
        let mut buf = DissectBuffer::new();
        let r = PppoeDiscoveryDissector.dissect(raw, &mut buf, 14).unwrap();
        assert_eq!(r.bytes_consumed, raw.len());
        assert_eq!(r.next, DispatchHint::End);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "PPPoE");
        assert_eq!(layer.range, 14..14 + raw.len());
        assert_eq!(buf.field_u8(layer, "version"), Some(1));
        assert_eq!(buf.field_u8(layer, "type"), Some(1));
        assert_eq!(buf.field_u8(layer, "code"), Some(0x09));
        assert_eq!(buf.resolve_display_name(layer, "code_name"), Some("PADI"));
        assert_eq!(buf.field_u16(layer, "session_id"), Some(0));
        assert_eq!(buf.field_u16(layer, "length"), Some(12));

        let tags = tag_fields(&buf);
        assert_eq!(tags.len(), 2);
        assert_eq!(child(tags[0], "type"), Some(&FieldValue::U16(0x0101)));
        assert_eq!(child(tags[0], "length"), Some(&FieldValue::U16(0)));
        assert_eq!(child(tags[0], "string"), Some(&FieldValue::Bytes(&[])));
        assert_eq!(child(tags[1], "type"), Some(&FieldValue::U16(0x0103)));
        assert_eq!(
            child(tags[1], "value"),
            Some(&FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF]))
        );
        let value = tags[1].iter().find(|f| f.name() == "value").unwrap();
        assert_eq!(value.range, 14 + 14..14 + 18);
    }

    #[test]
    fn pado_ac_name_and_cookie() {
        let raw: &[u8] = &[
            0x11, 0x07, 0x00, 0x00, 0x00, 0x12, // PADO, LEN 18
            0x01, 0x02, 0x00, 0x04, b'B', b'R', b'A', b'S', // AC-Name "BRAS"
            0x01, 0x04, 0x00, 0x02, 0x12, 0x34, // AC-Cookie
            0x01, 0x01, 0x00, 0x00, // Service-Name (any)
        ];
        let mut buf = DissectBuffer::new();
        PppoeDiscoveryDissector.dissect(raw, &mut buf, 0).unwrap();
        let tags = tag_fields(&buf);
        assert_eq!(tags.len(), 3);
        assert_eq!(child(tags[0], "string"), Some(&FieldValue::Bytes(b"BRAS")));
        assert_eq!(
            child(tags[1], "value"),
            Some(&FieldValue::Bytes(&[0x12, 0x34]))
        );
        assert_eq!(child(tags[2], "type"), Some(&FieldValue::U16(0x0101)));
    }

    #[test]
    fn pads_session_id() {
        let raw: &[u8] = &[
            0x11, 0x65, 0x12, 0x34, 0x00, 0x04, // PADS, SID 0x1234
            0x01, 0x01, 0x00, 0x00,
        ];
        let mut buf = DissectBuffer::new();
        PppoeDiscoveryDissector.dissect(raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(buf.resolve_display_name(layer, "code_name"), Some("PADS"));
        assert_eq!(buf.field_u16(layer, "session_id"), Some(0x1234));
    }

    #[test]
    fn padt_without_tags() {
        let raw: &[u8] = &[0x11, 0xA7, 0x12, 0x34, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        let r = PppoeDiscoveryDissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, HEADER_SIZE);
        let layer = &buf.layers()[0];
        assert_eq!(buf.resolve_display_name(layer, "code_name"), Some("PADT"));
        assert!(buf.field_by_name(layer, "tags").is_none());
    }

    #[test]
    fn discovery_ignores_ethernet_padding() {
        // PADT padded to the Ethernet minimum; LENGTH = 0.
        let mut raw = vec![0x11, 0xA7, 0x00, 0x01, 0x00, 0x00];
        raw.extend_from_slice(&[0u8; 40]);
        let mut buf = DissectBuffer::new();
        let r = PppoeDiscoveryDissector.dissect(&raw, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, HEADER_SIZE);
        assert_eq!(buf.layers()[0].range, 0..HEADER_SIZE);
    }

    #[test]
    fn end_of_list_stops_parsing() {
        let raw: &[u8] = &[
            0x11, 0x09, 0x00, 0x00, 0x00, 0x0C, // PADI, LEN 12
            0x01, 0x01, 0x00, 0x00, // Service-Name
            0x00, 0x00, 0x00, 0x00, // End-Of-List
            0xFF, 0xFF, 0x00, 0x09, // garbage after End-Of-List
        ];
        let mut buf = DissectBuffer::new();
        let r = PppoeDiscoveryDissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, raw.len());
        let tags = tag_fields(&buf);
        assert_eq!(tags.len(), 2);
        assert_eq!(child(tags[1], "type"), Some(&FieldValue::U16(0x0000)));
    }

    #[test]
    fn vendor_specific_tag() {
        let raw: &[u8] = &[
            0x11, 0x07, 0x00, 0x00, 0x00, 0x0A, // PADO, LEN 10
            0x01, 0x05, 0x00, 0x06, 0x00, 0x00, 0x0D, 0xE9, 0xAB, 0xCD, // DSL Forum 3561
        ];
        let mut buf = DissectBuffer::new();
        PppoeDiscoveryDissector.dissect(raw, &mut buf, 0).unwrap();
        let tags = tag_fields(&buf);
        assert_eq!(child(tags[0], "vendor_id"), Some(&FieldValue::U32(3561)));
        assert_eq!(
            child(tags[0], "value"),
            Some(&FieldValue::Bytes(&[0xAB, 0xCD]))
        );
    }

    #[test]
    fn vendor_specific_short_value() {
        let raw: &[u8] = &[
            0x11, 0x07, 0x00, 0x00, 0x00, 0x06, // PADO, LEN 6
            0x01, 0x05, 0x00, 0x02, 0x00, 0x00, // Vendor-Specific, 2 octets
        ];
        let mut buf = DissectBuffer::new();
        PppoeDiscoveryDissector.dissect(raw, &mut buf, 0).unwrap();
        let tags = tag_fields(&buf);
        assert_eq!(child(tags[0], "vendor_id"), None);
        assert_eq!(child(tags[0], "value"), Some(&FieldValue::Bytes(&[0, 0])));
    }

    #[test]
    fn service_name_error_text() {
        let raw: &[u8] = &[
            0x11, 0x65, 0x00, 0x00, 0x00, 0x07, // PADS, LEN 7
            0x02, 0x01, 0x00, 0x03, b'b', b'a', b'd',
        ];
        let mut buf = DissectBuffer::new();
        PppoeDiscoveryDissector.dissect(raw, &mut buf, 0).unwrap();
        let tags = tag_fields(&buf);
        assert_eq!(child(tags[0], "string"), Some(&FieldValue::Bytes(b"bad")));
        assert_eq!(child(tags[0], "value"), None);
    }

    #[test]
    fn unknown_tag_type() {
        let raw: &[u8] = &[
            0x11, 0x09, 0x00, 0x00, 0x00, 0x05, // PADI, LEN 5
            0x7F, 0x7F, 0x00, 0x01, 0x42,
        ];
        let mut buf = DissectBuffer::new();
        PppoeDiscoveryDissector.dissect(raw, &mut buf, 0).unwrap();
        let tags = tag_fields(&buf);
        assert_eq!(child(tags[0], "type"), Some(&FieldValue::U16(0x7F7F)));
        assert_eq!(child(tags[0], "value"), Some(&FieldValue::Bytes(&[0x42])));
    }

    #[test]
    fn truncated_header() {
        let mut buf = DissectBuffer::new();
        let err = PppoeDiscoveryDissector
            .dissect(&[0x11, 0x09, 0x00], &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: 3
            }
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn invalid_version() {
        let mut buf = DissectBuffer::new();
        let err = PppoeDiscoveryDissector
            .dissect(&[0x21, 0x09, 0x00, 0x00, 0x00, 0x00], &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidFieldValue {
                field: "version",
                value: 2
            }
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn invalid_type() {
        let mut buf = DissectBuffer::new();
        let err = PppoeSessionDissector
            .dissect(&[0x12, 0x00, 0x00, 0x01, 0x00, 0x00], &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidFieldValue {
                field: "type",
                value: 2
            }
        );
    }

    #[test]
    fn discovery_length_exceeds_data() {
        let raw: &[u8] = &[0x11, 0x09, 0x00, 0x00, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        let err = PppoeDiscoveryDissector
            .dissect(raw, &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: 14,
                actual: 10
            }
        );
    }

    #[test]
    fn truncated_tag() {
        // TAG_LENGTH 8 but only 2 value octets within LENGTH.
        let raw: &[u8] = &[
            0x11, 0x09, 0x00, 0x00, 0x00, 0x06, // PADI, LEN 6
            0x01, 0x03, 0x00, 0x08, 0xAA, 0xBB,
        ];
        let mut buf = DissectBuffer::new();
        let err = PppoeDiscoveryDissector
            .dissect(raw, &mut buf, 0)
            .unwrap_err();
        assert_eq!(err, PacketError::InvalidHeader("PPPoE TAG exceeds LENGTH"));
    }

    #[test]
    fn truncated_tag_header() {
        let raw: &[u8] = &[
            0x11, 0x09, 0x00, 0x00, 0x00, 0x06, // PADI, LEN 6
            0x01, 0x01, 0x00, 0x00, 0x01, 0x03,
        ];
        let mut buf = DissectBuffer::new();
        let err = PppoeDiscoveryDissector
            .dissect(raw, &mut buf, 0)
            .unwrap_err();
        assert_eq!(err, PacketError::InvalidHeader("PPPoE TAG exceeds LENGTH"));
    }

    #[test]
    fn tag_exceeds_length_with_padding() {
        // TAG runs past LENGTH into Ethernet padding: malformed, not truncated.
        let raw: &[u8] = &[
            0x11, 0x09, 0x00, 0x00, 0x00, 0x04, // PADI, LEN 4
            0x01, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut buf = DissectBuffer::new();
        let err = PppoeDiscoveryDissector
            .dissect(raw, &mut buf, 0)
            .unwrap_err();
        assert_eq!(err, PacketError::InvalidHeader("PPPoE TAG exceeds LENGTH"));
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn discovery_rejects_session_code() {
        let mut buf = DissectBuffer::new();
        let err = PppoeDiscoveryDissector
            .dissect(&[0x11, 0x00, 0x00, 0x01, 0x00, 0x00], &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidFieldValue {
                field: "code",
                value: 0
            }
        );
    }

    #[test]
    fn session_lcp_configure_request() {
        // Session 0x0011 carrying LCP Configure-Request with Magic-Number.
        let raw: &[u8] = &[
            0x11, 0x00, 0x00, 0x11, 0x00, 0x0C, // Session, SID 0x11, LEN 12
            0xC0, 0x21, // PPP Protocol LCP
            0x01, 0x01, 0x00, 0x0A, // Configure-Request id 1 len 10
            0x05, 0x06, 0x12, 0x34, 0x56, 0x78, // Magic-Number
        ];
        let mut buf = DissectBuffer::new();
        let r = PppoeSessionDissector.dissect(raw, &mut buf, 14).unwrap();
        assert_eq!(r.bytes_consumed, HEADER_SIZE);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x880B));
        assert_eq!(r.payload_len, Some(12));
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 14..14 + HEADER_SIZE);
        assert_eq!(
            buf.resolve_display_name(layer, "code_name"),
            Some("Session Data")
        );
        assert_eq!(buf.field_u16(layer, "session_id"), Some(0x11));
        assert_eq!(buf.field_u16(layer, "length"), Some(12));
        assert!(buf.field_by_name(layer, "tags").is_none());
    }

    #[test]
    fn session_with_ethernet_padding() {
        // LCP Echo-Request (8 octets + 2 protocol) padded to 46 octets.
        let mut raw = vec![0x11, 0x00, 0x00, 0x11, 0x00, 0x0A];
        raw.extend_from_slice(&[0xC0, 0x21, 0x09, 0x02, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78]);
        raw.resize(46, 0);
        let mut buf = DissectBuffer::new();
        let r = PppoeSessionDissector.dissect(&raw, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, HEADER_SIZE);
        assert_eq!(r.payload_len, Some(10));
    }

    #[test]
    fn session_length_exceeds_data() {
        // Snaplen truncation: the header is kept and the payload bound is the
        // declared LENGTH; the registry clamps it to the captured end.
        let raw: &[u8] = &[0x11, 0x00, 0x00, 0x11, 0x05, 0xD4, 0xC0, 0x21];
        let mut buf = DissectBuffer::new();
        let r = PppoeSessionDissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, HEADER_SIZE);
        assert_eq!(r.payload_len, Some(1492));
    }

    #[test]
    fn session_rejects_discovery_code() {
        let mut buf = DissectBuffer::new();
        let err = PppoeSessionDissector
            .dissect(&[0x11, 0x09, 0x00, 0x00, 0x00, 0x00], &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidFieldValue {
                field: "code",
                value: 9
            }
        );
    }

    #[test]
    fn link_type_dissector_selects_stage() {
        let session: &[u8] = &[0x11, 0x00, 0x00, 0x11, 0x00, 0x02, 0xC0, 0x21];
        let mut buf = DissectBuffer::new();
        let r = PppoeDissector.dissect(session, &mut buf, 0).unwrap();
        assert_eq!(r.next, DispatchHint::ByEtherType(ETHERTYPE_PPP));

        let padi: &[u8] = &[0x11, 0x09, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        let r = PppoeDissector.dissect(padi, &mut buf, 0).unwrap();
        assert_eq!(r.next, DispatchHint::End);
        assert_eq!(tag_fields(&buf).len(), 1);
    }

    #[test]
    fn code_and_tag_names() {
        assert_eq!(code_name(0x07), Some("PADO"));
        assert_eq!(code_name(0x19), Some("PADR"));
        assert_eq!(code_name(0x0A), Some("PADG"));
        assert_eq!(code_name(0x0B), Some("PADC"));
        assert_eq!(code_name(0x0C), Some("PADQ"));
        assert_eq!(code_name(0xD3), Some("PADM"));
        assert_eq!(code_name(0xD4), Some("PADN"));
        assert_eq!(code_name(0x01), None);
        for (t, n) in [
            (0x0104, "AC-Cookie"),
            (0x0106, "Credits"),
            (0x0107, "Metrics"),
            (0x0108, "Sequence Number"),
            (0x0109, "Credit Scale Factor"),
            (0x0110, "Relay-Session-Id"),
            (0x0111, "HURL"),
            (0x0112, "MOTM"),
            (0x0120, "PPP-Max-Payload"),
            (0x0121, "IP_Route_Add"),
            (0x0202, "AC-System-Error"),
            (0x0203, "Generic-Error"),
        ] {
            assert_eq!(tag_type_name(t), Some(n));
        }
        assert_eq!(tag_type_name(0x0300), None);
    }

    #[test]
    fn tag_object_display_name_is_tag_name() {
        let raw: &[u8] = &[0x11, 0x09, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        PppoeDiscoveryDissector.dissect(raw, &mut buf, 0).unwrap();
        let idx = buf.fields().iter().position(|f| f.name() == "tag").unwrap() as u32;
        assert_eq!(
            buf.resolve_container_display_name(idx),
            Some("Service-Name")
        );
    }

    #[test]
    fn dissector_metadata() {
        for d in [
            &PppoeDiscoveryDissector as &dyn Dissector,
            &PppoeSessionDissector,
            &PppoeDissector,
        ] {
            assert_eq!(d.short_name(), "PPPoE");
            assert_eq!(d.name(), "PPP-over-Ethernet");
            assert!(std::ptr::eq(d.field_descriptors(), FIELD_DESCRIPTORS));
            assert_eq!(d.references()[0].id, "RFC 2516");
            assert_eq!(d.layer(), Some(ProtocolLayer::Link));
        }
    }
}
