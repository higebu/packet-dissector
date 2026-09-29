//! GTP-U signalling message Information Elements.
//!
//! ## References
//! - 3GPP TS 29.281, Section 8: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.281/>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32, read_ipv4_addr, read_ipv6_addr};

use crate::ext_header::gtpv1u_ext_header_type_name;

/// IE type: Recovery (TV, 1 octet). 3GPP TS 29.281, Section 8.2.
const IE_RECOVERY: u8 = 14;
/// IE type: Tunnel Endpoint Identifier Data I (TV, 4 octets). Section 8.3.
const IE_TEID_DATA_I: u8 = 16;
/// IE type: GTP-U Peer Address (TLV). Section 8.4.
const IE_GTPU_PEER_ADDRESS: u8 = 133;
/// IE type: Extension Header Type List (TLV, one-octet Length). Section 8.5.
const IE_EXT_HEADER_TYPE_LIST: u8 = 141;
/// IE type: GTP-U Tunnel Status Information (TLV). Section 8.7.
const IE_TUNNEL_STATUS_INFORMATION: u8 = 230;
/// IE type: Recovery Time Stamp (TLV). Section 8.8.
const IE_RECOVERY_TIME_STAMP: u8 = 231;
/// IE type: Private Extension (TLV). Section 8.6.
const IE_PRIVATE_EXTENSION: u8 = 255;

/// Map a GTP-U IE type to its name.
///
/// 3GPP TS 29.281, Section 8.1, Table 8.1-1 — Information Elements.
pub(crate) fn gtpv1u_ie_type_name(v: u8) -> Option<&'static str> {
    match v {
        IE_RECOVERY => Some("Recovery"),
        IE_TEID_DATA_I => Some("Tunnel Endpoint Identifier Data I"),
        // Table 8.1-1 NOTE 1: "This IE is named as " GTP-U Peer Address" in
        // the rest of this specification."
        IE_GTPU_PEER_ADDRESS => Some("GTP-U Peer Address"),
        IE_EXT_HEADER_TYPE_LIST => Some("Extension Header Type List"),
        IE_TUNNEL_STATUS_INFORMATION => Some("GTP-U Tunnel Status Information"),
        IE_RECOVERY_TIME_STAMP => Some("Recovery Time Stamp"),
        IE_PRIVATE_EXTENSION => Some("Private Extension"),
        _ => None,
    }
}

/// Container descriptor for one IE; its label resolves to the IE name.
static FD_IE: FieldDescriptor = FieldDescriptor {
    name: "ie",
    display_name: "IE",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => gtpv1u_ie_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Child fields of an IE object.
pub(crate) static IE_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => gtpv1u_ie_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U16).optional(),
    FieldDescriptor::new("restart_counter", "Restart Counter", FieldType::U8).optional(),
    FieldDescriptor::new(
        "teid_data_i",
        "Tunnel Endpoint Identifier Data I",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("gtpu_peer_address", "GTP-U Peer Address", FieldType::Any).optional(),
    FieldDescriptor::new(
        "extension_header_types",
        "Extension Header Types",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new("spoc", "Start Pause Of Charging", FieldType::U8).optional(),
    FieldDescriptor::new("recovery_time_stamp", "Recovery Time Stamp", FieldType::U32).optional(),
    FieldDescriptor::new(
        "extension_identifier",
        "Extension Identifier",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("extension_value", "Extension Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

const FD_TYPE: usize = 0;
const FD_LENGTH: usize = 1;
const FD_RESTART_COUNTER: usize = 2;
const FD_TEID_DATA_I: usize = 3;
const FD_PEER_ADDRESS: usize = 4;
const FD_EXT_TYPES: usize = 5;
const FD_SPOC: usize = 6;
const FD_RECOVERY_TIME_STAMP: usize = 7;
const FD_EXTENSION_IDENTIFIER: usize = 8;
const FD_EXTENSION_VALUE: usize = 9;
const FD_VALUE: usize = 10;

/// Element descriptor for an entry of the Extension Header Type List.
static FD_EXT_TYPE_ENTRY: FieldDescriptor = FieldDescriptor::new(
    "extension_header_type",
    "Extension Header Type",
    FieldType::U8,
)
.with_display_fn(|v, _| match v {
    FieldValue::U8(t) => gtpv1u_ext_header_type_name(*t),
    _ => None,
});

/// Value length of a TV-format IE, or `None` if the type is unknown.
///
/// 3GPP TS 29.281, Section 8.1 — "The most significant bit in the Type
/// field is set to 0 when the TV format is used". Only the TV IEs listed in
/// Table 8.1-1 have a known length.
fn tv_value_len(ie_type: u8) -> Option<usize> {
    match ie_type {
        IE_RECOVERY => Some(1),
        IE_TEID_DATA_I => Some(4),
        _ => None,
    }
}

/// Parse the IEs of a signalling message.
///
/// `data` is the part of the GTP-PDU after the header (and after any
/// extension headers); `base` is its absolute packet offset. An IE whose
/// extent cannot be determined (unknown TV type, or a Length that runs past
/// the message) ends the walk, and the remaining octets are kept as a raw
/// `value` of that IE.
pub(crate) fn parse_ies<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], base: usize) {
    let mut pos = 0;
    while pos < data.len() {
        let ie_type = data[pos];
        let start = base + pos;
        let obj = buf.begin_container(&FD_IE, FieldValue::Object(0..0), start..start);
        buf.push_field(
            &IE_FIELD_DESCRIPTORS[FD_TYPE],
            FieldValue::U8(ie_type),
            start..start + 1,
        );

        let extent = if ie_type & 0x80 == 0 {
            // TV format
            tv_value_len(ie_type)
                .filter(|len| pos + 1 + len <= data.len())
                .map(|len| (pos + 1, len))
        } else {
            // TLV format. The Extension Header Type List has a one-octet
            // Length (TS 29.281, Figure 8.5-1); all others have two octets.
            let (len_size, len) = if ie_type == IE_EXT_HEADER_TYPE_LIST {
                (1, data.get(pos + 1).map(|l| usize::from(*l)))
            } else {
                (2, read_be_u16(data, pos + 1).ok().map(usize::from))
            };
            match len {
                Some(len) if pos + 1 + len_size + len <= data.len() => {
                    buf.push_field(
                        &IE_FIELD_DESCRIPTORS[FD_LENGTH],
                        FieldValue::U16(len as u16),
                        start + 1..start + 1 + len_size,
                    );
                    Some((pos + 1 + len_size, len))
                }
                _ => None,
            }
        };

        let Some((value_pos, value_len)) = extent else {
            let rest = &data[pos + 1..];
            buf.push_field(
                &IE_FIELD_DESCRIPTORS[FD_VALUE],
                FieldValue::Bytes(rest),
                start + 1..base + data.len(),
            );
            close(buf, obj, start..base + data.len());
            break;
        };

        let value = &data[value_pos..value_pos + value_len];
        push_ie_value(buf, ie_type, value, base + value_pos);
        let end = value_pos + value_len;
        close(buf, obj, start..base + end);
        pos = end;
    }
}

fn close(buf: &mut DissectBuffer<'_>, obj: u32, range: core::ops::Range<usize>) {
    if let Some(f) = buf.field_mut(obj as usize) {
        f.range = range;
    }
    buf.end_container(obj);
}

/// Push the decoded value of one IE; `at` is the absolute offset of `value`.
fn push_ie_value<'pkt>(buf: &mut DissectBuffer<'pkt>, ie_type: u8, value: &'pkt [u8], at: usize) {
    let range = at..at + value.len();
    match (ie_type, value.len()) {
        // 3GPP TS 29.281, Section 8.2 — Restart counter
        (IE_RECOVERY, 1) => buf.push_field(
            &IE_FIELD_DESCRIPTORS[FD_RESTART_COUNTER],
            FieldValue::U8(value[0]),
            range,
        ),
        // Section 8.3 — Tunnel Endpoint Identifier Data I
        (IE_TEID_DATA_I, 4) => {
            if let Ok(teid) = read_be_u32(value, 0) {
                buf.push_field(
                    &IE_FIELD_DESCRIPTORS[FD_TEID_DATA_I],
                    FieldValue::U32(teid),
                    range,
                );
            }
        }
        // Section 8.4 — "The Length field may have only two values (4 or 16)
        // that determine if the Value field contains IPv4 or IPv6 address."
        (IE_GTPU_PEER_ADDRESS, 4) => {
            if let Ok(a) = read_ipv4_addr(value, 0) {
                buf.push_field(
                    &IE_FIELD_DESCRIPTORS[FD_PEER_ADDRESS],
                    FieldValue::Ipv4Addr(a),
                    range,
                );
            }
        }
        (IE_GTPU_PEER_ADDRESS, 16) => {
            if let Ok(a) = read_ipv6_addr(value, 0) {
                buf.push_field(
                    &IE_FIELD_DESCRIPTORS[FD_PEER_ADDRESS],
                    FieldValue::Ipv6Addr(a),
                    range,
                );
            }
        }
        // Section 8.5 — list of 'n' Extension Header Types
        (IE_EXT_HEADER_TYPE_LIST, _) => {
            let arr = buf.begin_container(
                &IE_FIELD_DESCRIPTORS[FD_EXT_TYPES],
                FieldValue::Array(0..0),
                range,
            );
            for (i, t) in value.iter().enumerate() {
                buf.push_field(&FD_EXT_TYPE_ENTRY, FieldValue::U8(*t), at + i..at + i + 1);
            }
            buf.end_container(arr);
        }
        // Section 8.7 — Octet 4, Bit 1: SPOC
        (IE_TUNNEL_STATUS_INFORMATION, 1..) => {
            buf.push_field(
                &IE_FIELD_DESCRIPTORS[FD_SPOC],
                FieldValue::U8(value[0] & 0x01),
                at..at + 1,
            );
            push_rest(buf, &value[1..], at + 1);
        }
        // Section 8.8 — Octets 4 to 7: Recovery Time Stamp value
        (IE_RECOVERY_TIME_STAMP, 4..) => {
            if let Ok(ts) = read_be_u32(value, 0) {
                buf.push_field(
                    &IE_FIELD_DESCRIPTORS[FD_RECOVERY_TIME_STAMP],
                    FieldValue::U32(ts),
                    at..at + 4,
                );
            }
            push_rest(buf, &value[4..], at + 4);
        }
        // Section 8.6 — Extension Identifier (2 octets) + Extension Value
        (IE_PRIVATE_EXTENSION, 2..) => {
            if let Ok(id) = read_be_u16(value, 0) {
                buf.push_field(
                    &IE_FIELD_DESCRIPTORS[FD_EXTENSION_IDENTIFIER],
                    FieldValue::U16(id),
                    at..at + 2,
                );
            }
            buf.push_field(
                &IE_FIELD_DESCRIPTORS[FD_EXTENSION_VALUE],
                FieldValue::Bytes(&value[2..]),
                at + 2..range.end,
            );
        }
        _ => buf.push_field(
            &IE_FIELD_DESCRIPTORS[FD_VALUE],
            FieldValue::Bytes(value),
            range,
        ),
    }
}

/// Push octets "present only if explicitly specified" as a raw `value`.
fn push_rest<'pkt>(buf: &mut DissectBuffer<'pkt>, rest: &'pkt [u8], at: usize) {
    if !rest.is_empty() {
        buf.push_field(
            &IE_FIELD_DESCRIPTORS[FD_VALUE],
            FieldValue::Bytes(rest),
            at..at + rest.len(),
        );
    }
}
