//! GTPv1-C (GPRS Tunnelling Protocol Control Plane v1) dissector.
//!
//! ## References
//! - 3GPP TS 29.060: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.060/>

#![deny(missing_docs)]

pub mod ie;
pub mod message_type;

use core::ops::Range;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Specification references for the GTPv1-C dissector.
static REFERENCES: &[SpecReference] = &[SpecReference::new(
    "3GPP TS 29.060",
    "General Packet Radio Service (GPRS); GPRS Tunnelling Protocol (GTP) across the Gn and Gp \
     interface",
    "https://www.3gpp.org/ftp/Specs/archive/29_series/29.060/",
)];

/// Mandatory part of the GTP header.
///
/// 3GPP TS 29.060, Section 6 — "The minimum length of the GTP header is 8
/// bytes."
const MIN_HEADER_SIZE: usize = 8;

/// Header size when the Sequence Number, N-PDU Number and Next Extension
/// Header Type fields are present.
///
/// 3GPP TS 29.060, Section 6, Figure 2, NOTE 4 — "This field shall be
/// present if and only if any one or more of the S, PN and E flags are set."
const OPTIONAL_HEADER_SIZE: usize = 12;

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
const FD_IES: usize = 12;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("pt", "Protocol Type", FieldType::U8),
    FieldDescriptor::new("e", "Extension Header Flag", FieldType::U8),
    FieldDescriptor::new("s", "Sequence Number Flag", FieldType::U8),
    FieldDescriptor::new("pn", "N-PDU Number Flag", FieldType::U8),
    FieldDescriptor::new("message_type", "Message Type", FieldType::U8).with_display_fn(|v, _| {
        match v {
            FieldValue::U8(t) => message_type::message_type_name(*t),
            _ => None,
        }
    }),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("teid", "Tunnel Endpoint Identifier", FieldType::U32),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("n_pdu_number", "N-PDU Number", FieldType::U8).optional(),
    FieldDescriptor::new(
        "next_extension_header_type",
        "Next Extension Header Type",
        FieldType::U8,
    )
    .optional()
    .with_display_fn(|v, _| match v {
        FieldValue::U8(t) => extension_header_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("extension_headers", "Extension Headers", FieldType::Array)
        .optional()
        .with_children(EXT_HEADER_FIELD_DESCRIPTORS),
    FieldDescriptor::new("ies", "Information Elements", FieldType::Array)
        .optional()
        .with_children(ie::IE_FIELD_DESCRIPTORS),
];

const FD_EXT_TYPE: usize = 0;
const FD_EXT_LENGTH: usize = 1;
const FD_EXT_CONTENT: usize = 2;
const FD_EXT_PDCP_PDU_NUMBER: usize = 3;

/// Child fields of one extension header object.
static EXT_HEADER_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => extension_header_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("content", "Content", FieldType::Bytes),
    FieldDescriptor::new("pdcp_pdu_number", "PDCP PDU Number", FieldType::U16).optional(),
];

/// Container descriptor for one extension header; its label resolves to
/// the extension header type name.
static FD_EXTENSION_HEADER: FieldDescriptor = FieldDescriptor {
    name: "extension_header",
    display_name: "Extension Header",
    field_type: FieldType::Object,
    optional: false,
    children: Some(EXT_HEADER_FIELD_DESCRIPTORS),
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => extension_header_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Extension header type: PDCP PDU number. 3GPP TS 29.060, Section 6.1.1.
const EXT_PDCP_PDU_NUMBER: u8 = 0xC0;

/// Returns the name of a GTPv1-C extension header type.
///
/// 3GPP TS 29.060, Section 6, Figure 5 — "Definition of Extension Header
/// Type". The values reserved for GTP-U are left to the GTPv1-U dissector.
fn extension_header_type_name(v: u8) -> Option<&'static str> {
    match v {
        0x00 => Some("No more extension headers"),
        0x01 => Some("MBMS support indication"),
        0x02 => Some("MS Info Change Reporting support indication"),
        EXT_PDCP_PDU_NUMBER => Some("PDCP PDU number"),
        0xC1 => Some("Suspend Request"),
        0xC2 => Some("Suspend Response"),
        _ => None,
    }
}

/// GTPv1-C dissector.
///
/// Parses the GTP header of 3GPP TS 29.060 Section 6 (with the optional
/// Sequence Number / N-PDU Number / Next Extension Header Type fields and the
/// extension header chain) and the TV / TLV Information Elements of Section
/// 7.7. Only version 1 with PT = 1 is accepted; GTP' (PT = 0, TS 32.295) and
/// other versions are rejected so that a version dispatcher can route them.
pub struct Gtpv1cDissector;

impl Dissector for Gtpv1cDissector {
    fn name(&self) -> &'static str {
        "GPRS Tunnelling Protocol Control Plane v1"
    }

    fn short_name(&self) -> &'static str {
        "GTPv1-C"
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
        // 3GPP TS 29.060, Section 6 — minimum 8 bytes
        if data.len() < MIN_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // 3GPP TS 29.060, Section 6 — Octet 1: Version (bits 8-6), PT (5),
        // spare (4), E (3), S (2), PN (1).
        let version = data[0] >> 5;
        let pt = (data[0] >> 4) & 0x01;
        let e_flag = (data[0] >> 2) & 0x01;
        let s_flag = (data[0] >> 1) & 0x01;
        let pn_flag = data[0] & 0x01;

        // Section 8.2 — "Version shall be set to decimal 1 ("001")."
        if version != 1 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }
        // Section 6 — "This bit is used as a protocol discriminator between
        // GTP (when PT is "1") and GTP' (when PT is "0")."
        if pt != 1 {
            return Err(PacketError::InvalidFieldValue {
                field: "pt",
                value: u32::from(pt),
            });
        }

        let message_type = data[1];
        let length = read_be_u16(data, 2)?;
        let teid = read_be_u32(data, 4)?;

        // Section 6 — "Length: This field indicates the length in octets of
        // the payload, i.e. the rest of the packet following the mandatory
        // part of the GTP header (that is the first 8 octets)."
        let total = MIN_HEADER_SIZE + usize::from(length);
        if data.len() < total {
            return Err(PacketError::Truncated {
                expected: total,
                actual: data.len(),
            });
        }
        let data = &data[..total];

        let has_optional = e_flag != 0 || s_flag != 0 || pn_flag != 0;
        if has_optional && data.len() < OPTIONAL_HEADER_SIZE {
            return Err(PacketError::InvalidHeader(
                "GTPv1-C Length does not cover the optional header fields",
            ));
        }
        // Section 6 — the Next Extension Header Type "shall be interpreted"
        // only when E = 1. Validate the chain before pushing any field so
        // that an error leaves the buffer untouched.
        let header_end = if !has_optional {
            MIN_HEADER_SIZE
        } else if e_flag != 0 && data[11] != 0 {
            extension_chain_end(data)?
        } else {
            OPTIONAL_HEADER_SIZE
        };

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total,
        );
        let flags = offset..offset + 1;
        push(buf, FD_VERSION, FieldValue::U8(version), flags.clone());
        push(buf, FD_PT, FieldValue::U8(pt), flags.clone());
        push(buf, FD_E, FieldValue::U8(e_flag), flags.clone());
        push(buf, FD_S, FieldValue::U8(s_flag), flags.clone());
        push(buf, FD_PN, FieldValue::U8(pn_flag), flags);
        push(
            buf,
            FD_MESSAGE_TYPE,
            FieldValue::U8(message_type),
            offset + 1..offset + 2,
        );
        push(
            buf,
            FD_LENGTH,
            FieldValue::U16(length),
            offset + 2..offset + 4,
        );
        push(buf, FD_TEID, FieldValue::U32(teid), offset + 4..offset + 8);

        if has_optional {
            // Section 6 — octets 9-10 Sequence Number, 11 N-PDU Number,
            // 12 Next Extension Header Type.
            let seq = read_be_u16(data, 8)?;
            push(
                buf,
                FD_SEQUENCE_NUMBER,
                FieldValue::U16(seq),
                offset + 8..offset + 10,
            );
            push(
                buf,
                FD_N_PDU_NUMBER,
                FieldValue::U8(data[10]),
                offset + 10..offset + 11,
            );
            push(
                buf,
                FD_NEXT_EXTENSION_HEADER_TYPE,
                FieldValue::U8(data[11]),
                offset + 11..offset + 12,
            );
            if header_end > OPTIONAL_HEADER_SIZE {
                let arr = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_EXTENSION_HEADERS],
                    FieldValue::Array(0..0),
                    offset + OPTIONAL_HEADER_SIZE..offset + header_end,
                );
                push_extension_headers(buf, &data[..header_end], offset);
                buf.end_container(arr);
            }
        }

        // Section 8.2 — "The GTP-C header may be followed by subsequent
        // information elements dependent on the type of control plane
        // message."
        if header_end < total {
            let arr = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_IES],
                FieldValue::Array(0..0),
                offset + header_end..offset + total,
            );
            ie::parse_ies(buf, &data[header_end..], offset + header_end);
            buf.end_container(arr);
        }

        buf.end_layer();
        Ok(DissectResult::new(total, DispatchHint::End))
    }
}

fn push<'pkt>(buf: &mut DissectBuffer<'pkt>, fd: usize, value: FieldValue<'pkt>, r: Range<usize>) {
    buf.push_field(&FIELD_DESCRIPTORS[fd], value, r);
}

/// Walk the extension header chain and return where it ends.
///
/// 3GPP TS 29.060, Section 6, Figure 3 — each extension header is an
/// Extension Header Length octet (in 4-octet units), the content, and the
/// Next Extension Header Type; "m+1 = n*4 octets, where n is a positive
/// integer". `data` is bounded by the GTP Length, so a chain that runs past
/// it is malformed. Every header is at least 4 octets, so the walk ends.
fn extension_chain_end(data: &[u8]) -> Result<usize, PacketError> {
    let mut pos = OPTIONAL_HEADER_SIZE;
    let mut next = data[OPTIONAL_HEADER_SIZE - 1];
    while next != 0 {
        let units = *data.get(pos).ok_or(PacketError::InvalidHeader(
            "GTPv1-C extension header chain exceeds the GTP Length",
        ))?;
        if units == 0 {
            return Err(PacketError::InvalidHeader(
                "GTPv1-C extension header length must be > 0",
            ));
        }
        let end = pos + usize::from(units) * 4;
        if end > data.len() {
            return Err(PacketError::InvalidHeader(
                "GTPv1-C extension header chain exceeds the GTP Length",
            ));
        }
        next = data[end - 1];
        pos = end;
    }
    Ok(pos)
}

/// Push the extension headers of a chain already validated by
/// [`extension_chain_end`]; `data` ends where the chain ends.
fn push_extension_headers<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let mut pos = OPTIONAL_HEADER_SIZE;
    let mut ext_type = data[OPTIONAL_HEADER_SIZE - 1];
    while pos < data.len() {
        let units = data[pos];
        let end = pos + usize::from(units) * 4;
        let start = offset + pos;
        let obj = buf.begin_container(
            &FD_EXTENSION_HEADER,
            FieldValue::Object(0..0),
            start..offset + end,
        );
        let d = EXT_HEADER_FIELD_DESCRIPTORS;
        // The type is carried in the preceding Next Extension Header Type.
        buf.push_field(&d[FD_EXT_TYPE], FieldValue::U8(ext_type), start..start + 1);
        buf.push_field(&d[FD_EXT_LENGTH], FieldValue::U8(units), start..start + 1);
        let content = &data[pos + 1..end - 1];
        buf.push_field(
            &d[FD_EXT_CONTENT],
            FieldValue::Bytes(content),
            start + 1..offset + end - 1,
        );
        // Section 6.1.1 — PDCP PDU number in octets 2-3.
        if ext_type == EXT_PDCP_PDU_NUMBER {
            if let Ok(n) = read_be_u16(content, 0) {
                buf.push_field(
                    &d[FD_EXT_PDCP_PDU_NUMBER],
                    FieldValue::U16(n),
                    start + 1..start + 3,
                );
            }
        }
        buf.end_container(obj);
        ext_type = data[end - 1];
        pos = end;
    }
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 29.060 (GTPv1-C) Coverage
    //!
    //! | Section    | Description                                   | Test                                         |
    //! |------------|-----------------------------------------------|----------------------------------------------|
    //! | 6          | Header, S=1 (Echo Request)                    | parse_echo_request                           |
    //! | 6          | Header without optional fields                | parse_header_without_optional_fields         |
    //! | 6          | Version must be 1                             | reject_version_2, reject_version_0           |
    //! | 6          | PT must be 1 (PT=0 is GTP')                   | reject_gtp_prime                             |
    //! | 6          | Minimum header length                         | truncated_header                             |
    //! | 6          | Length covers the whole payload               | truncated_payload, trailing_bytes_not_consumed |
    //! | 6          | Length shorter than the optional fields       | length_shorter_than_optional_fields          |
    //! | 6, 6.1     | Extension header chain                        | parse_extension_header_chain                 |
    //! | 6          | Extension header Length = 0                   | extension_header_zero_length                 |
    //! | 6          | Extension header past Length                  | extension_header_past_length                 |
    //! | 6          | Extension header type names                   | extension_header_type_names                  |
    //! | 7.1        | Message type display name                     | parse_echo_request                           |
    //! | 7.2.2      | Echo Response with Recovery                   | parse_echo_response_with_recovery            |
    //! | 7.3.1      | Create PDP Context Request                    | parse_create_pdp_context_request             |
    //! | 7.7        | IE decoding                                   | ie::tests::*                                 |
    //! | 7.7.40     | Extension Header Type List one-octet Length   | ie::tests::tlv_extension_header_type_list_one_octet_length |
    //! | 8.2        | PN=1 accepted                                 | parse_pn_flag_set                            |

    use super::*;
    use packet_dissector_core::field::FieldValue;

    fn dissect(data: &[u8]) -> Result<(DissectResult, DissectBuffer<'_>), PacketError> {
        let mut buf = DissectBuffer::new();
        let res = Gtpv1cDissector.dissect(data, &mut buf, 0)?;
        Ok((res, buf))
    }

    fn u(buf: &DissectBuffer<'_>, name: &str) -> FieldValue<'static> {
        let layer = &buf.layers()[0];
        match buf.field_by_name(layer, name).map(|f| &f.value) {
            Some(FieldValue::U8(v)) => FieldValue::U8(*v),
            Some(FieldValue::U16(v)) => FieldValue::U16(*v),
            Some(FieldValue::U32(v)) => FieldValue::U32(*v),
            other => panic!("{name}: {other:?}"),
        }
    }

    fn ie_types(buf: &DissectBuffer<'_>) -> Vec<u8> {
        buf.fields()
            .iter()
            .filter(|f| f.name() == "type")
            .filter_map(|f| f.value.as_u8())
            .collect()
    }

    const ECHO_REQUEST: &[u8] = &[
        0x32, // Version 1, PT 1, E 0, S 1, PN 0
        0x01, // Echo Request
        0x00, 0x04, // Length
        0x00, 0x00, 0x00, 0x00, // TEID
        0x12, 0x34, // Sequence Number
        0x00, // N-PDU Number
        0x00, // Next Extension Header Type
    ];

    #[test]
    fn parse_echo_request() {
        let (res, buf) = dissect(ECHO_REQUEST).unwrap();
        assert_eq!(res.bytes_consumed, 12);
        assert_eq!(res.next, DispatchHint::End);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "GTPv1-C");
        assert_eq!(layer.range, 0..12);
        assert_eq!(u(&buf, "version"), FieldValue::U8(1));
        assert_eq!(u(&buf, "pt"), FieldValue::U8(1));
        assert_eq!(u(&buf, "e"), FieldValue::U8(0));
        assert_eq!(u(&buf, "s"), FieldValue::U8(1));
        assert_eq!(u(&buf, "pn"), FieldValue::U8(0));
        assert_eq!(u(&buf, "message_type"), FieldValue::U8(1));
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("Echo Request")
        );
        assert_eq!(u(&buf, "length"), FieldValue::U16(4));
        assert_eq!(u(&buf, "teid"), FieldValue::U32(0));
        assert_eq!(u(&buf, "sequence_number"), FieldValue::U16(0x1234));
        assert_eq!(u(&buf, "n_pdu_number"), FieldValue::U8(0));
        assert_eq!(u(&buf, "next_extension_header_type"), FieldValue::U8(0));
        assert!(buf.field_by_name(layer, "ies").is_none());
        assert!(buf.field_by_name(layer, "extension_headers").is_none());
    }

    #[test]
    fn parse_echo_response_with_recovery() {
        let data = [
            0x32, 0x02, 0x00, 0x06, 0, 0, 0, 0, 0x12, 0x34, 0, 0, // header
            14, 0x05, // Recovery
        ];
        let (res, buf) = dissect(&data).unwrap();
        assert_eq!(res.bytes_consumed, 14);
        let layer = &buf.layers()[0];
        let ies = buf.field_by_name(layer, "ies").unwrap();
        assert_eq!(ies.range, 12..14);
        assert_eq!(ie_types(&buf), vec![14]);
    }

    #[test]
    fn parse_create_pdp_context_request() {
        let mut body = vec![
            2, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xF5, // IMSI
            14, 0x01, // Recovery
            15, 0xFC, // Selection Mode
            16, 0x00, 0x00, 0x00, 0x01, // TEID Data I
            17, 0x00, 0x00, 0x00, 0x02, // TEID Control Plane
            20, 0x05, // NSAPI
            128, 0x00, 0x02, 0xF1, 0x21, // End User Address (IPv4, dynamic)
            131, 0x00, 0x04, 3, b'a', b'p', b'n', // APN
            133, 0x00, 0x04, 10, 0, 0, 1, // GSN Address (signalling)
            133, 0x00, 0x04, 10, 0, 0, 2, // GSN Address (user traffic)
            135, 0x00, 0x04, 0x02, 0x23, 0x92, 0x1F, // QoS Profile
        ];
        let mut data = vec![0x32, 16];
        data.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        data.extend_from_slice(&[0, 0, 0, 0, 0x00, 0x07, 0, 0]);
        data.append(&mut body);
        let (res, buf) = dissect(&data).unwrap();
        assert_eq!(res.bytes_consumed, data.len());
        assert_eq!(
            ie_types(&buf),
            vec![2, 14, 15, 16, 17, 20, 128, 131, 133, 133, 135]
        );
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("Create PDP Context Request")
        );
    }

    #[test]
    fn parse_header_without_optional_fields() {
        // S=0 (not allowed for GTP-C by TS 29.060 Section 8.2, but the
        // header itself is well formed): IEs start right after octet 8.
        let data = [0x30, 0x01, 0x00, 0x02, 0, 0, 0, 0, 14, 0x09];
        let (res, buf) = dissect(&data).unwrap();
        assert_eq!(res.bytes_consumed, 10);
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "sequence_number").is_none());
        assert!(buf.field_by_name(layer, "n_pdu_number").is_none());
        assert_eq!(ie_types(&buf), vec![14]);
    }

    #[test]
    fn parse_pn_flag_set() {
        // TS 29.060 Section 8.2 — "A GTP-C receiver shall not return an
        // error if this flag is set to "1"."
        let mut data = ECHO_REQUEST.to_vec();
        data[0] = 0x33;
        data[10] = 0x7F;
        let (_, buf) = dissect(&data).unwrap();
        assert_eq!(u(&buf, "pn"), FieldValue::U8(1));
        assert_eq!(u(&buf, "n_pdu_number"), FieldValue::U8(0x7F));
    }

    #[test]
    fn reject_version_2() {
        let mut data = ECHO_REQUEST.to_vec();
        data[0] = 0x48;
        let mut buf = DissectBuffer::new();
        let err = Gtpv1cDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "version",
                value: 2
            }
        ));
        assert!(buf.layers().is_empty());
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn reject_version_0() {
        let mut data = ECHO_REQUEST.to_vec();
        data[0] = 0x12;
        let err = dissect(&data).err().unwrap();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "version",
                value: 0
            }
        ));
    }

    #[test]
    fn reject_gtp_prime() {
        let mut data = ECHO_REQUEST.to_vec();
        data[0] = 0x22;
        let err = dissect(&data).err().unwrap();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "pt",
                value: 0
            }
        ));
    }

    #[test]
    fn truncated_header() {
        let err = dissect(&ECHO_REQUEST[..7]).err().unwrap();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 7
            }
        ));
    }

    #[test]
    fn truncated_payload() {
        let err = dissect(&ECHO_REQUEST[..11]).err().unwrap();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 12,
                actual: 11
            }
        ));
    }

    #[test]
    fn trailing_bytes_not_consumed() {
        let mut data = ECHO_REQUEST.to_vec();
        data.extend_from_slice(&[0xAA, 0xBB]);
        let (res, buf) = dissect(&data).unwrap();
        assert_eq!(res.bytes_consumed, 12);
        assert_eq!(buf.layers()[0].range, 0..12);
    }

    #[test]
    fn length_shorter_than_optional_fields() {
        let data = [0x32, 0x01, 0x00, 0x02, 0, 0, 0, 0, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        let err = Gtpv1cDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn parse_extension_header_chain() {
        let data = [
            0x36, // Version 1, PT 1, E 1, S 1
            50,   // SGSN Context Request
            0x00, 0x0E, // Length = 4 + 8 + 2
            0, 0, 0, 0, // TEID
            0x00, 0x01, // Sequence Number
            0x00, // N-PDU Number
            0xC1, // Next: Suspend Request
            0x01, 0xFF, 0xFF, 0xC0, // Suspend Request, next PDCP PDU number
            0x01, 0x12, 0x34, 0x00, // PDCP PDU number, next none
            14, 0x03, // Recovery
        ];
        let (res, buf) = dissect(&data).unwrap();
        assert_eq!(res.bytes_consumed, 22);
        let layer = &buf.layers()[0];
        let ext = buf.field_by_name(layer, "extension_headers").unwrap();
        assert_eq!(ext.range, 12..20);
        let FieldValue::Array(r) = &ext.value else {
            panic!("not an array")
        };
        let children = buf.nested_fields(r);
        let types: Vec<u8> = children
            .iter()
            .filter(|f| f.name() == "type")
            .filter_map(|f| f.value.as_u8())
            .collect();
        assert_eq!(types, vec![0xC1, 0xC0]);
        let pdcp = children
            .iter()
            .find(|f| f.name() == "pdcp_pdu_number")
            .unwrap();
        assert_eq!(pdcp.value, FieldValue::U16(0x1234));
        let first_obj = r.start;
        assert_eq!(
            buf.resolve_container_display_name(first_obj),
            Some("Suspend Request")
        );
        let ies = buf.field_by_name(layer, "ies").unwrap();
        assert_eq!(ies.range, 20..22);
    }

    #[test]
    fn extension_header_zero_length() {
        let data = [
            0x36, 50, 0x00, 0x08, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut buf = DissectBuffer::new();
        let err = Gtpv1cDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn extension_header_past_length() {
        let data = [
            0x36, 50, 0x00, 0x08, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0xC0, 0x02, 0x00, 0x00, 0x00,
        ];
        let err = dissect(&data).err().unwrap();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
        // Chain announced but no room for it at all.
        let data = [0x36, 50, 0x00, 0x04, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0xC0];
        let err = dissect(&data).err().unwrap();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn extension_header_type_names() {
        assert_eq!(
            extension_header_type_name(0x01),
            Some("MBMS support indication")
        );
        assert_eq!(
            extension_header_type_name(0x02),
            Some("MS Info Change Reporting support indication")
        );
        assert_eq!(extension_header_type_name(0xC0), Some("PDCP PDU number"));
        assert_eq!(extension_header_type_name(0xC1), Some("Suspend Request"));
        assert_eq!(extension_header_type_name(0xC2), Some("Suspend Response"));
        assert_eq!(extension_header_type_name(0x20), None);
    }

    #[test]
    fn display_fns_reject_other_values() {
        for d in FIELD_DESCRIPTORS
            .iter()
            .chain(EXT_HEADER_FIELD_DESCRIPTORS)
            .chain([&FD_EXTENSION_HEADER])
        {
            if let Some(f) = d.display_fn {
                assert_eq!(f(&FieldValue::U16(0), &[]), None, "{}", d.name);
            }
        }
        assert_eq!(
            extension_header_type_name(0),
            Some("No more extension headers")
        );
    }

    #[test]
    fn offset_is_applied() {
        let mut buf = DissectBuffer::new();
        Gtpv1cDissector.dissect(ECHO_REQUEST, &mut buf, 42).unwrap();
        assert_eq!(buf.layers()[0].range, 42..54);
    }

    #[test]
    fn metadata() {
        let d = Gtpv1cDissector;
        assert_eq!(d.name(), "GPRS Tunnelling Protocol Control Plane v1");
        assert_eq!(d.short_name(), "GTPv1-C");
        assert_eq!(d.layer(), Some(ProtocolLayer::Application));
        assert!(!d.references().is_empty());
        assert!(d.field_descriptors().iter().any(|f| f.name == "ies"));
    }
}
