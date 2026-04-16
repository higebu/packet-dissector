//! PPP (Point-to-Point Protocol) frame dissector and sub-protocol parsers.
//!
//! Provides a [`PppDissector`] for PPP frame dissection (RFC 1661 S2) as well
//! as sub-protocol parsers commonly carried inside 3GPP Protocol Configuration
//! Options (PCO) and PPPoE sessions:
//!
//! - **IPCP** -- Internet Protocol Control Protocol ([RFC 1332], [RFC 1877])
//! - **LCP** -- Link Control Protocol ([RFC 1661])
//! - **PAP** -- Password Authentication Protocol ([RFC 1334])
//! - **CHAP** -- Challenge Handshake Authentication Protocol ([RFC 1994])
//!
//! The sub-protocol parsers accept raw PPP packet bytes (starting with the Code
//! field) and push fields directly into a [`DissectBuffer`].
//!
//! ## References
//! - RFC 1661 (PPP): <https://www.rfc-editor.org/rfc/rfc1661>
//! - RFC 1332 (IPCP): <https://www.rfc-editor.org/rfc/rfc1332>
//! - RFC 1334 (PAP / CHAP): <https://www.rfc-editor.org/rfc/rfc1334>
//! - RFC 1877 (DNS extensions for IPCP): <https://www.rfc-editor.org/rfc/rfc1877>
//! - RFC 1994 (CHAP): <https://www.rfc-editor.org/rfc/rfc1994>
//!
//! [RFC 1332]: https://www.rfc-editor.org/rfc/rfc1332
//! [RFC 1334]: https://www.rfc-editor.org/rfc/rfc1334
//! [RFC 1661]: https://www.rfc-editor.org/rfc/rfc1661
//! [RFC 1877]: https://www.rfc-editor.org/rfc/rfc1877
//! [RFC 1994]: https://www.rfc-editor.org/rfc/rfc1994

#![deny(missing_docs)]

use packet_dissector_core::packet::DissectBuffer;

macro_rules! ppp_header_descriptors {
    ($dfn:expr) => {
        &[
            FieldDescriptor::new("code", "Code", FieldType::U8).with_display_fn($dfn),
            FieldDescriptor::new("identifier", "Identifier", FieldType::U8),
            FieldDescriptor::new("length", "Length", FieldType::U16),
        ]
    };
}

macro_rules! ppp_option_descriptors {
    ($dfn:expr) => {
        &[
            FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn($dfn),
            FieldDescriptor::new("length", "Length", FieldType::U8),
            FieldDescriptor::new("value", "Value", FieldType::Bytes),
        ]
    };
}

pub mod chap;
pub mod ipcp;
pub mod lcp;
pub mod pap;

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::util::read_be_u16;

/// Minimum PPP packet header size (Code + Identifier + Length).
///
/// RFC 1661, Section 5 -- all PPP control packets share this 4-byte header.
pub const PPP_HEADER_SIZE: usize = 4;

const FD_HDR_CODE: usize = 0;
const FD_HDR_IDENTIFIER: usize = 1;
const FD_HDR_LENGTH: usize = 2;

pub(crate) static HEADER_DESCRIPTORS: &[FieldDescriptor] =
    ppp_header_descriptors!(|v, _| match v {
        FieldValue::U8(c) => Some(code_name(*c)),
        _ => None,
    });
pub(crate) static PAP_HEADER_DESCRIPTORS: &[FieldDescriptor] =
    ppp_header_descriptors!(|v, _| match v {
        FieldValue::U8(c) => Some(pap_code_name(*c)),
        _ => None,
    });
pub(crate) static CHAP_HEADER_DESCRIPTORS: &[FieldDescriptor] =
    ppp_header_descriptors!(|v, _| match v {
        FieldValue::U8(c) => Some(chap_code_name(*c)),
        _ => None,
    });

const FD_OPT_TYPE: usize = 0;
const FD_OPT_LENGTH: usize = 1;
const FD_OPT_VALUE: usize = 2;

/// Parse the common PPP packet header (Code, Identifier, Length) into a DissectBuffer.
///
/// RFC 1661, Section 5 -- <https://www.rfc-editor.org/rfc/rfc1661#section-5>
///
/// Returns `Some((code, length))` or `None` if the data is too short.
pub fn parse_header(
    data: &[u8],
    offset: usize,
    descriptors: &'static [FieldDescriptor],
    buf: &mut DissectBuffer<'_>,
) -> Option<(u8, u16)> {
    if data.len() < PPP_HEADER_SIZE {
        return None;
    }
    let code = data[0];
    let length = read_be_u16(data, 2).unwrap_or_default();
    buf.push_field(
        &descriptors[FD_HDR_CODE],
        FieldValue::U8(code),
        offset..offset + 1,
    );
    buf.push_field(
        &descriptors[FD_HDR_IDENTIFIER],
        FieldValue::U8(data[1]),
        offset + 1..offset + 2,
    );
    buf.push_field(
        &descriptors[FD_HDR_LENGTH],
        FieldValue::U16(length),
        offset + 2..offset + 4,
    );
    Some((code, length))
}

/// Returns the human-readable name for a PPP Code value.
pub fn code_name(code: u8) -> &'static str {
    match code {
        1 => "Configure-Request",
        2 => "Configure-Ack",
        3 => "Configure-Nak",
        4 => "Configure-Reject",
        5 => "Terminate-Request",
        6 => "Terminate-Ack",
        7 => "Code-Reject",
        _ => "Unknown",
    }
}

/// Returns the human-readable name for a PAP Code value.
pub fn pap_code_name(code: u8) -> &'static str {
    match code {
        1 => "Authenticate-Request",
        2 => "Authenticate-Ack",
        3 => "Authenticate-Nak",
        _ => "Unknown",
    }
}

/// Returns the human-readable name for a CHAP Code value.
pub fn chap_code_name(code: u8) -> &'static str {
    match code {
        1 => "Challenge",
        2 => "Response",
        3 => "Success",
        4 => "Failure",
        _ => "Unknown",
    }
}

/// Dispatch a PPP sub-protocol payload to the appropriate parser.
pub fn parse_protocol<'pkt>(
    protocol_id: u16,
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    match protocol_id {
        0x8021 => ipcp::parse(data, offset, buf),
        0xC021 => lcp::parse(data, offset, buf),
        0xC023 => pap::parse(data, offset, buf),
        0xC223 => chap::parse(data, offset, buf),
        _ => {
            static FD_RAW: FieldDescriptor = FieldDescriptor::new("data", "Data", FieldType::Bytes);
            buf.push_field(
                &FD_RAW,
                FieldValue::Bytes(data),
                offset..offset + data.len(),
            );
        }
    }
}

/// Parse TLV-encoded configuration options into a DissectBuffer. Returns `true` if any parsed.
pub(crate) fn parse_options<'pkt>(
    options_data: &'pkt [u8],
    base_offset: usize,
    descriptors: &'static [FieldDescriptor],
    value_parser: fn(u8, &[u8]) -> FieldValue,
    buf: &mut DissectBuffer<'pkt>,
) -> bool {
    let mut pos: usize = 0;
    let mut count = 0;
    while pos + 2 <= options_data.len() {
        let opt_type = options_data[pos];
        let opt_len = options_data[pos + 1] as usize;
        if opt_len < 2 {
            break;
        }
        if pos
            .checked_add(opt_len)
            .is_none_or(|end| end > options_data.len())
        {
            break;
        }
        let opt_start = base_offset + pos;
        let opt_value = value_parser(opt_type, &options_data[pos + 2..pos + opt_len]);
        let obj_idx = buf.begin_container(
            &descriptors[FD_OPT_TYPE],
            FieldValue::Object(0..0),
            opt_start..opt_start + opt_len,
        );
        buf.push_field(
            &descriptors[FD_OPT_TYPE],
            FieldValue::U8(opt_type),
            opt_start..opt_start + 1,
        );
        buf.push_field(
            &descriptors[FD_OPT_LENGTH],
            FieldValue::U8(opt_len as u8),
            opt_start + 1..opt_start + 2,
        );
        buf.push_field(
            &descriptors[FD_OPT_VALUE],
            opt_value,
            opt_start + 2..opt_start + opt_len,
        );
        buf.end_container(obj_idx);
        count += 1;
        pos += opt_len;
    }
    count > 0
}

const HDLC_ADDRESS: u8 = 0xFF;
const HDLC_CONTROL: u8 = 0x03;
const MIN_FRAME_SIZE: usize = 2;
const PPP_PROTO_IPV4: u16 = 0x0021;
const PPP_PROTO_IPV6: u16 = 0x0057;
const PPP_PROTO_IPCP: u16 = 0x8021;
const PPP_PROTO_LCP: u16 = 0xC021;
const PPP_PROTO_PAP: u16 = 0xC023;
const PPP_PROTO_CHAP: u16 = 0xC223;

const FD_ADDRESS: usize = 0;
const FD_CONTROL: usize = 1;
const FD_PROTOCOL: usize = 2;
const FD_PAYLOAD: usize = 3;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("address", "Address", FieldType::U8).optional(),
    FieldDescriptor::new("control", "Control", FieldType::U8).optional(),
    FieldDescriptor {
        name: "protocol",
        display_name: "Protocol",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _| match v {
            FieldValue::U16(p) => protocol_name(*p),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("payload", "Payload", FieldType::Object).optional(),
];

fn protocol_name(proto: u16) -> Option<&'static str> {
    match proto {
        0x0021 => Some("IPv4"),
        0x0057 => Some("IPv6"),
        0x8021 => Some("IPCP"),
        0x8057 => Some("IPv6CP"),
        0xC021 => Some("LCP"),
        0xC023 => Some("PAP"),
        0xC223 => Some("CHAP"),
        0x0031 => Some("Bridging PDU"),
        0x003D => Some("Multi-Link"),
        0x00FD => Some("MPPC/MPPE"),
        0x8031 => Some("Bridging NCP"),
        0x80FD => Some("CCP"),
        _ => None,
    }
}

/// PPP frame dissector.
pub struct PppDissector;

impl Dissector for PppDissector {
    fn name(&self) -> &'static str {
        "Point-to-Point Protocol"
    }
    fn short_name(&self) -> &'static str {
        "PPP"
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
        if data.len() < MIN_FRAME_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_FRAME_SIZE,
                actual: data.len(),
            });
        }
        let mut pos = 0;
        let has_hdlc = data.len() >= 4 && data[0] == HDLC_ADDRESS && data[1] == HDLC_CONTROL;
        if has_hdlc {
            pos = 2;
        }
        if data.len() < pos + 2 {
            return Err(PacketError::Truncated {
                expected: pos + 2,
                actual: data.len(),
            });
        }
        let proto = read_be_u16(data, pos)?;
        pos += 2;
        let header_len = pos;
        let payload = &data[pos..];
        let dispatch = match proto {
            PPP_PROTO_IPCP | PPP_PROTO_LCP | PPP_PROTO_PAP | PPP_PROTO_CHAP => DispatchHint::End,
            PPP_PROTO_IPV4 => DispatchHint::ByEtherType(0x0800),
            PPP_PROTO_IPV6 => DispatchHint::ByEtherType(0x86DD),
            _ => DispatchHint::End,
        };
        buf.begin_layer("PPP", None, FIELD_DESCRIPTORS, offset..offset + header_len);
        if has_hdlc {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_ADDRESS],
                FieldValue::U8(HDLC_ADDRESS),
                offset..offset + 1,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_CONTROL],
                FieldValue::U8(HDLC_CONTROL),
                offset + 1..offset + 2,
            );
        }
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PROTOCOL],
            FieldValue::U16(proto),
            offset + header_len - 2..offset + header_len,
        );
        match proto {
            PPP_PROTO_IPCP | PPP_PROTO_LCP | PPP_PROTO_PAP | PPP_PROTO_CHAP
                if !payload.is_empty() =>
            {
                let obj_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_PAYLOAD],
                    FieldValue::Object(0..0),
                    offset + pos..offset + data.len(),
                );
                parse_protocol(proto, payload, offset + pos, buf);
                buf.end_container(obj_idx);
            }
            _ => {}
        }
        buf.end_layer();
        Ok(DissectResult::new(header_len, dispatch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header_valid() {
        let data = [0x01, 0x42, 0x00, 0x04];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..4);
        let result = parse_header(&data, 10, HEADER_DESCRIPTORS, &mut buf);
        buf.end_layer();
        let (code, length) = result.unwrap();
        assert_eq!(code, 1);
        assert_eq!(length, 4);
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].value, FieldValue::U8(1));
        assert_eq!(fields[0].range, 10..11);
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Configure-Request")
        );
        assert_eq!(fields[1].value, FieldValue::U8(0x42));
        assert_eq!(fields[2].value, FieldValue::U16(4));
    }

    #[test]
    fn parse_header_truncated() {
        let mut buf = DissectBuffer::new();
        assert!(parse_header(&[0x01, 0x02], 0, HEADER_DESCRIPTORS, &mut buf).is_none());
    }

    #[test]
    fn dispatch_ipcp() {
        let data = [0x01, 0x01, 0x00, 0x04];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..4);
        let idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_PAYLOAD],
            FieldValue::Object(0..0),
            0..4,
        );
        parse_protocol(0x8021, &data, 0, &mut buf);
        buf.end_container(idx);
        buf.end_layer();
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        assert!(matches!(fields[0].value, FieldValue::Object(_)));
    }

    #[test]
    fn dispatch_unknown() {
        let data = [0x01, 0x02, 0x03];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..3);
        parse_protocol(0xFFFF, &data, 0, &mut buf);
        buf.end_layer();
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        assert_eq!(fields[0].value, FieldValue::Bytes(&[0x01, 0x02, 0x03]));
    }

    #[test]
    fn dissect_hdlc_ipv4() {
        let data = [0xFF, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        let result = PppDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
        let layer = buf.layer_by_name("PPP").unwrap();
        let fields = buf.layer_fields(layer);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].value, FieldValue::U8(0xFF));
        assert_eq!(fields[1].value, FieldValue::U8(0x03));
        assert_eq!(fields[2].value, FieldValue::U16(0x0021));
        let display = fields[2].descriptor.display_fn.unwrap()(&fields[2].value, fields);
        assert_eq!(display, Some("IPv4"));
    }

    #[test]
    fn dissect_no_hdlc_ipv4() {
        let data = [0x00, 0x21, 0x45, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        let result = PppDissector.dissect(&data, &mut buf, 10).unwrap();
        assert_eq!(result.bytes_consumed, 2);
        let layer = buf.layer_by_name("PPP").unwrap();
        let fields = buf.layer_fields(layer);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].value, FieldValue::U16(0x0021));
        assert_eq!(fields[0].range, 10..12);
    }

    #[test]
    fn dissect_ipv6() {
        let data = [0x00, 0x57, 0x60, 0x00];
        let mut buf = DissectBuffer::new();
        let result = PppDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
        let layer = buf.layer_by_name("PPP").unwrap();
        let fields = buf.layer_fields(layer);
        let display = fields[0].descriptor.display_fn.unwrap()(&fields[0].value, fields);
        assert_eq!(display, Some("IPv6"));
    }

    #[test]
    fn dissect_lcp_inline() {
        let data = [0xC0, 0x21, 0x01, 0x01, 0x00, 0x08, 1, 4, 0x05, 0xDC];
        let mut buf = DissectBuffer::new();
        let result = PppDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 2);
        assert_eq!(result.next, DispatchHint::End);
        let layer = buf.layer_by_name("PPP").unwrap();
        let fields = buf.layer_fields(layer);
        // protocol is first field, payload Object is second
        assert!(fields.len() >= 2);
        let display = fields[0].descriptor.display_fn.unwrap()(&fields[0].value, fields);
        assert_eq!(display, Some("LCP"));
        assert!(matches!(fields[1].value, FieldValue::Object(_)));
    }

    #[test]
    fn dissect_unknown_protocol() {
        let data = [0x00, 0x99, 0xAA, 0xBB];
        let mut buf = DissectBuffer::new();
        let result = PppDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.next, DispatchHint::End);
        let layer = buf.layer_by_name("PPP").unwrap();
        let fields = buf.layer_fields(layer);
        assert_eq!(fields.len(), 1);
    }

    #[test]
    fn dissect_truncated() {
        let mut buf = DissectBuffer::new();
        let result = PppDissector.dissect(&[0x00], &mut buf, 0);
        assert!(matches!(result, Err(PacketError::Truncated { .. })));
    }
}
