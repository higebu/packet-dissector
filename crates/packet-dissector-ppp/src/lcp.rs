//! LCP (Link Control Protocol) parser.
//!
//! ## References
//! - RFC 1661 (PPP / LCP): <https://www.rfc-editor.org/rfc/rfc1661>
//! - RFC 2153 (updates RFC 1661; vendor-specific code/option): <https://www.rfc-editor.org/rfc/rfc2153>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

use crate::PPP_HEADER_SIZE;

/// Option descriptors for LCP configuration options.
///
/// RFC 1661, Section 6 — <https://www.rfc-editor.org/rfc/rfc1661#section-6>
static LCP_OPTION_DESCRIPTORS: &[FieldDescriptor] = ppp_option_descriptors!(|v, _| match v {
    FieldValue::U8(t) => Some(lcp_option_name(*t)),
    _ => None,
});

/// Container descriptor for an LCP configuration option entry.
///
/// `display_fn` resolves the outer container's label to the option name
/// (e.g. "Maximum-Receive-Unit") by looking up the inner `type` field.
static FD_LCP_OPTION: FieldDescriptor = FieldDescriptor {
    name: "option",
    display_name: "Option",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => Some(lcp_option_name(*t)),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

static FD_INLINE_DATA: FieldDescriptor = FieldDescriptor::new("data", "Data", FieldType::Bytes);

static FD_INLINE_OPTIONS: FieldDescriptor =
    FieldDescriptor::new("options", "Options", FieldType::Array);

// Protocol-Reject (Code 8) data fields.
// RFC 1661, Section 5.7 — <https://www.rfc-editor.org/rfc/rfc1661#section-5.7>
static FD_REJECTED_PROTOCOL: FieldDescriptor =
    FieldDescriptor::new("rejected_protocol", "Rejected-Protocol", FieldType::U16);
static FD_REJECTED_INFORMATION: FieldDescriptor = FieldDescriptor::new(
    "rejected_information",
    "Rejected-Information",
    FieldType::Bytes,
);

// Echo-Request / Echo-Reply / Discard-Request (Codes 9/10/11) data fields.
// RFC 1661, Sections 5.8–5.10 — <https://www.rfc-editor.org/rfc/rfc1661#section-5.8>
static FD_MAGIC_NUMBER: FieldDescriptor =
    FieldDescriptor::new("magic_number", "Magic-Number", FieldType::U32);

/// Parse an LCP packet into a DissectBuffer.
///
/// RFC 1661, Section 5 — <https://www.rfc-editor.org/rfc/rfc1661#section-5>
pub fn parse<'pkt>(data: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let Some((code, length)) =
        crate::parse_header(data, offset, crate::LCP_HEADER_DESCRIPTORS, buf)
    else {
        static FD_RAW: FieldDescriptor = FieldDescriptor::new("data", "Data", FieldType::Bytes);
        buf.push_field(
            &FD_RAW,
            FieldValue::Bytes(data),
            offset..offset + data.len(),
        );
        return;
    };

    if data.len() <= PPP_HEADER_SIZE {
        return;
    }

    // Honour the Length field per RFC 1661, Section 5 — truncate any payload
    // beyond Length as padding; clip Length that exceeds the supplied buffer.
    let payload = if (length as usize) <= data.len() && length >= PPP_HEADER_SIZE as u16 {
        &data[PPP_HEADER_SIZE..length as usize]
    } else {
        &data[PPP_HEADER_SIZE..]
    };
    let payload_offset = offset + PPP_HEADER_SIZE;

    match code {
        // Configure-Request / -Ack / -Nak / -Reject carry TLV-encoded options.
        // RFC 1661, Sections 5.1–5.4 — <https://www.rfc-editor.org/rfc/rfc1661#section-5.1>
        1..=4 => {
            let array_idx = buf.begin_container(
                &FD_INLINE_OPTIONS,
                FieldValue::Array(0..0),
                payload_offset..payload_offset + payload.len(),
            );
            let has_options = crate::parse_options(
                payload,
                payload_offset,
                &FD_LCP_OPTION,
                LCP_OPTION_DESCRIPTORS,
                parse_option_value,
                buf,
            );
            buf.end_container(array_idx);
            if !has_options {
                buf.pop_field();
            }
        }
        // Protocol-Reject: Rejected-Protocol (2 octets) + Rejected-Information.
        // RFC 1661, Section 5.7 — <https://www.rfc-editor.org/rfc/rfc1661#section-5.7>
        8 if payload.len() >= 2 => {
            let rejected_protocol = read_be_u16(payload, 0).unwrap_or_default();
            buf.push_field(
                &FD_REJECTED_PROTOCOL,
                FieldValue::U16(rejected_protocol),
                payload_offset..payload_offset + 2,
            );
            if payload.len() > 2 {
                buf.push_field(
                    &FD_REJECTED_INFORMATION,
                    FieldValue::Bytes(&payload[2..]),
                    payload_offset + 2..payload_offset + payload.len(),
                );
            }
        }
        // Echo-Request / Echo-Reply / Discard-Request: Magic-Number (4 octets) + Data.
        // RFC 1661, Sections 5.8–5.10 —
        // <https://www.rfc-editor.org/rfc/rfc1661#section-5.8>
        9..=11 if payload.len() >= 4 => {
            let magic = read_be_u32(payload, 0).unwrap_or_default();
            buf.push_field(
                &FD_MAGIC_NUMBER,
                FieldValue::U32(magic),
                payload_offset..payload_offset + 4,
            );
            if payload.len() > 4 {
                buf.push_field(
                    &FD_INLINE_DATA,
                    FieldValue::Bytes(&payload[4..]),
                    payload_offset + 4..payload_offset + payload.len(),
                );
            }
        }
        _ => {
            buf.push_field(
                &FD_INLINE_DATA,
                FieldValue::Bytes(payload),
                payload_offset..payload_offset + payload.len(),
            );
        }
    }
}

fn parse_option_value(opt_type: u8, value_data: &[u8]) -> FieldValue<'_> {
    match opt_type {
        // MRU — RFC 1661, Section 6.1 —
        // <https://www.rfc-editor.org/rfc/rfc1661#section-6.1>
        1 if value_data.len() >= 2 => {
            FieldValue::U16(read_be_u16(value_data, 0).unwrap_or_default())
        }
        // Authentication-Protocol — RFC 1661, Section 6.2 —
        // <https://www.rfc-editor.org/rfc/rfc1661#section-6.2>
        3 if value_data.len() >= 2 => {
            FieldValue::U16(read_be_u16(value_data, 0).unwrap_or_default())
        }
        // Quality-Protocol — RFC 1661, Section 6.3 —
        // <https://www.rfc-editor.org/rfc/rfc1661#section-6.3>
        4 if value_data.len() >= 2 => {
            FieldValue::U16(read_be_u16(value_data, 0).unwrap_or_default())
        }
        // Magic-Number — RFC 1661, Section 6.4 —
        // <https://www.rfc-editor.org/rfc/rfc1661#section-6.4>
        5 if value_data.len() >= 4 => {
            FieldValue::U32(read_be_u32(value_data, 0).unwrap_or_default())
        }
        _ => FieldValue::Bytes(value_data),
    }
}

// LCP Configuration Option Types.
// RFC 1661, Section 6 — <https://www.rfc-editor.org/rfc/rfc1661#section-6>
// Type 0 (Vendor-Specific) from RFC 2153 —
// <https://www.rfc-editor.org/rfc/rfc2153#section-4>
fn lcp_option_name(opt_type: u8) -> &'static str {
    match opt_type {
        0 => "Vendor-Specific",
        1 => "Maximum-Receive-Unit",
        3 => "Authentication-Protocol",
        4 => "Quality-Protocol",
        5 => "Magic-Number",
        7 => "Protocol-Field-Compression",
        8 => "Address-and-Control-Field-Compression",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 1661 (LCP) Coverage
    //!
    //! | RFC Section | Description                                 | Test                                   |
    //! |-------------|---------------------------------------------|----------------------------------------|
    //! | 5           | Packet Format (Code/Identifier/Length)      | parse_lcp_no_data, parse_lcp_truncated |
    //! | 5.1         | Configure-Request + options                 | parse_configure_request_mru            |
    //! | 5.2         | Configure-Ack                               | parse_configure_ack                    |
    //! | 5.3         | Configure-Nak                               | parse_configure_nak                    |
    //! | 5.4         | Configure-Reject                            | parse_configure_reject                 |
    //! | 5.5         | Terminate-Request                           | parse_lcp_with_data                    |
    //! | 5.6         | Terminate-Ack                               | parse_terminate_ack                    |
    //! | 5.7         | Code-Reject                                 | parse_code_reject                      |
    //! | 5.7         | Protocol-Reject                             | parse_protocol_reject                  |
    //! | 5.8         | Echo-Request (Magic-Number + Data)          | parse_echo_request                     |
    //! | 5.9         | Echo-Reply (Magic-Number + Data)            | parse_echo_reply                       |
    //! | 5.10        | Discard-Request (Magic-Number + Data)       | parse_discard_request                  |
    //! | 6.1         | Maximum-Receive-Unit option                 | parse_configure_request_mru            |
    //! | 6.2         | Authentication-Protocol option              | parse_configure_request_auth           |
    //! | 6.3         | Quality-Protocol option                     | parse_quality_protocol_option          |
    //! | 6.4         | Magic-Number option                         | parse_configure_request_magic          |
    //! | 6.5/6.6     | PFC / ACFC options                          | parse_pfc_and_acfc_combined            |
    //! | —           | Unknown code fallback                       | parse_unknown_code                     |
    //! | —           | Length larger than buffer                   | parse_length_exceeds_data              |
    //! | —           | Truncated option                            | parse_truncated_option                 |
    //! | —           | Unknown option                              | parse_unknown_option                   |
    //! | —           | Configure-Request with multiple options     | parse_multiple_options                 |
    //! | —           | Code name display for codes 8..=11          | lcp_code_name_extended_codes           |

    use super::*;

    fn obj_fields<'a, 'b>(
        buf: &'a DissectBuffer<'b>,
    ) -> &'a [packet_dissector_core::field::Field<'b>] {
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        match &fields[0].value {
            FieldValue::Object(r) => buf.nested_fields(r),
            _ => panic!("expected Object"),
        }
    }

    fn count_objects(buf: &DissectBuffer, range: &core::ops::Range<u32>) -> usize {
        buf.nested_fields(range)
            .iter()
            .filter(|f| f.value.is_object())
            .count()
    }

    fn nth_obj<'a, 'b>(
        buf: &'a DissectBuffer<'b>,
        range: &core::ops::Range<u32>,
        n: usize,
    ) -> &'a [packet_dissector_core::field::Field<'b>] {
        let mut i = 0;
        for f in buf.nested_fields(range) {
            if let FieldValue::Object(r) = &f.value {
                if i == n {
                    return buf.nested_fields(r);
                }
                i += 1;
            }
        }
        panic!("Object at index {n} not found");
    }

    fn parse_to_buf(data: &[u8], offset: usize) -> DissectBuffer<'_> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..data.len());
        let idx = buf.begin_container(
            &crate::FIELD_DESCRIPTORS[crate::FD_PAYLOAD],
            FieldValue::Object(0..0),
            offset..offset + data.len(),
        );
        parse(data, offset, &mut buf);
        buf.end_container(idx);
        buf.end_layer();
        buf
    }

    #[test]
    fn parse_lcp_with_data() {
        #[rustfmt::skip]
        let data = [0x05, 0x01, 0x00, 0x07, 0xAA, 0xBB, 0xCC];
        let buf = parse_to_buf(&data, 50);
        let fields = obj_fields(&buf);
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].value, FieldValue::U8(5));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Terminate-Request")
        );
        assert_eq!(fields[3].value, FieldValue::Bytes(&[0xAA, 0xBB, 0xCC]));
        assert_eq!(fields[3].range, 54..57);
    }

    #[test]
    fn parse_lcp_no_data() {
        let data = [0x01, 0x01, 0x00, 0x04];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn parse_lcp_truncated() {
        let data = [0x01, 0x02];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..2);
        parse(&data, 0, &mut buf);
        buf.end_layer();
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        assert!(matches!(fields[0].value, FieldValue::Bytes(_)));
    }

    #[test]
    fn parse_configure_request_mru() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x08, 1, 4, 0x05, 0xDC];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        assert_eq!(count_objects(&buf, r), 1);
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(opt[0].value, FieldValue::U8(1));
        assert_eq!(
            opt[0].descriptor.display_fn.unwrap()(&opt[0].value, &[]),
            Some("Maximum-Receive-Unit")
        );
        assert_eq!(opt[2].value, FieldValue::U16(1500));
    }

    #[test]
    fn parse_configure_request_auth() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x08, 3, 4, 0xC0, 0x23];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(
            opt[0].descriptor.display_fn.unwrap()(&opt[0].value, &[]),
            Some("Authentication-Protocol")
        );
        assert_eq!(opt[2].value, FieldValue::U16(0xC023));
    }

    #[test]
    fn parse_configure_request_magic() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x0A, 5, 6, 0xDE, 0xAD, 0xBE, 0xEF];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(
            opt[0].descriptor.display_fn.unwrap()(&opt[0].value, &[]),
            Some("Magic-Number")
        );
        assert_eq!(opt[2].value, FieldValue::U32(0xDEADBEEF));
    }

    #[test]
    fn parse_multiple_options() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x0E, 1, 4, 0x05, 0xDC, 5, 6, 0x12, 0x34, 0x56, 0x78];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        assert_eq!(count_objects(&buf, r), 2);
    }

    #[test]
    fn parse_unknown_option() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x08, 99, 4, 0x01, 0x02];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(opt[0].value, FieldValue::U8(99));
        assert_eq!(
            opt[0].descriptor.display_fn.unwrap()(&opt[0].value, &[]),
            Some("Unknown")
        );
        assert_eq!(opt[2].value, FieldValue::Bytes(&[0x01, 0x02]));
    }

    #[test]
    fn parse_truncated_option() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x08, 1, 4, 0x05];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn parse_length_exceeds_data() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x14, 1, 4, 0x05, 0xDC];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        assert_eq!(count_objects(&buf, r), 1);
    }

    #[test]
    fn parse_configure_ack() {
        #[rustfmt::skip]
        let data = [0x02, 0x01, 0x00, 0x08, 1, 4, 0x05, 0xDC];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields[0].value, FieldValue::U8(2));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Configure-Ack")
        );
    }

    #[test]
    fn parse_terminate_ack() {
        #[rustfmt::skip]
        let data = [0x06, 0x02, 0x00, 0x06, 0x11, 0x22];
        let buf = parse_to_buf(&data, 50);
        let fields = obj_fields(&buf);
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].value, FieldValue::U8(6));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Terminate-Ack")
        );
        assert_eq!(fields[3].value, FieldValue::Bytes(&[0x11, 0x22]));
    }

    #[test]
    fn parse_code_reject() {
        #[rustfmt::skip]
        let data = [0x07, 0x03, 0x00, 0x08, 0xAA, 0xBB, 0xCC, 0xDD];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].value, FieldValue::U8(7));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Code-Reject")
        );
    }

    #[test]
    fn parse_pfc_and_acfc_combined() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x08, 7, 2, 8, 2];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        assert_eq!(count_objects(&buf, r), 2);
        let opt0 = nth_obj(&buf, r, 0);
        assert_eq!(
            opt0[0].descriptor.display_fn.unwrap()(&opt0[0].value, &[]),
            Some("Protocol-Field-Compression")
        );
        let opt1 = nth_obj(&buf, r, 1);
        assert_eq!(
            opt1[0].descriptor.display_fn.unwrap()(&opt1[0].value, &[]),
            Some("Address-and-Control-Field-Compression")
        );
    }

    #[test]
    fn parse_terminate_ack_no_payload() {
        let data = [0x06, 0x01, 0x00, 0x04];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields[0].value, FieldValue::U8(6));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Terminate-Ack")
        );
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn parse_unknown_code() {
        #[rustfmt::skip]
        let data = [0xFE, 0x01, 0x00, 0x06, 0x01, 0x02];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields[0].value, FieldValue::U8(0xFE));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Unknown")
        );
        assert_eq!(fields[3].value, FieldValue::Bytes(&[0x01, 0x02]));
    }

    #[test]
    fn parse_protocol_reject() {
        // Code=8 (Protocol-Reject), Id=1, Len=8,
        // Rejected-Protocol=0x8021, Rejected-Information=0xDE 0xAD
        #[rustfmt::skip]
        let data = [0x08, 0x01, 0x00, 0x08, 0x80, 0x21, 0xDE, 0xAD];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields[0].value, FieldValue::U8(8));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Protocol-Reject")
        );
        // Expect Code, Identifier, Length, Rejected-Protocol, Rejected-Information
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[3].name(), "rejected_protocol");
        assert_eq!(fields[3].value, FieldValue::U16(0x8021));
        assert_eq!(fields[4].name(), "rejected_information");
        assert_eq!(fields[4].value, FieldValue::Bytes(&[0xDE, 0xAD]));
    }

    #[test]
    fn parse_protocol_reject_no_info() {
        // Code=8, no Rejected-Information (minimum valid Length=6).
        #[rustfmt::skip]
        let data = [0x08, 0x01, 0x00, 0x06, 0xC0, 0x23];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[3].value, FieldValue::U16(0xC023));
    }

    #[test]
    fn parse_echo_request() {
        // Code=9 (Echo-Request), Magic-Number=0xDEADBEEF, Data=[0xAB, 0xCD]
        #[rustfmt::skip]
        let data = [0x09, 0x01, 0x00, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF, 0xAB, 0xCD];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields[0].value, FieldValue::U8(9));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Echo-Request")
        );
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[3].name(), "magic_number");
        assert_eq!(fields[3].value, FieldValue::U32(0xDEAD_BEEF));
        assert_eq!(fields[4].name(), "data");
        assert_eq!(fields[4].value, FieldValue::Bytes(&[0xAB, 0xCD]));
    }

    #[test]
    fn parse_echo_reply() {
        // Code=10 (Echo-Reply), Magic-Number only.
        #[rustfmt::skip]
        let data = [0x0A, 0x02, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Echo-Reply")
        );
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[3].value, FieldValue::U32(0x0102_0304));
    }

    #[test]
    fn parse_discard_request() {
        // Code=11 (Discard-Request), Magic-Number + Data.
        #[rustfmt::skip]
        let data = [0x0B, 0x03, 0x00, 0x0B, 0x11, 0x22, 0x33, 0x44, b'x', b'y', b'z'];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Discard-Request")
        );
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[3].value, FieldValue::U32(0x1122_3344));
        assert_eq!(fields[4].value, FieldValue::Bytes(b"xyz" as &[u8]));
    }

    #[test]
    fn parse_echo_request_truncated_magic() {
        // Echo-Request with fewer than 4 bytes of data must fall back to raw Data.
        #[rustfmt::skip]
        let data = [0x09, 0x01, 0x00, 0x07, 0xAA, 0xBB, 0xCC];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[3].name(), "data");
        assert_eq!(fields[3].value, FieldValue::Bytes(&[0xAA, 0xBB, 0xCC]));
    }

    #[test]
    fn parse_quality_protocol_option() {
        // Configure-Request with Quality-Protocol (Type=4, Length=8,
        // Protocol=0xC025 LQR, 4 bytes Reporting-Period).
        #[rustfmt::skip]
        let data = [
            0x01, 0x01, 0x00, 0x0C, 4, 8, 0xC0, 0x25, 0x00, 0x00, 0x03, 0xE8,
        ];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(
            opt[0].descriptor.display_fn.unwrap()(&opt[0].value, &[]),
            Some("Quality-Protocol")
        );
        assert_eq!(opt[2].value, FieldValue::U16(0xC025));
    }

    #[test]
    fn option_container_resolves_to_option_name() {
        // Configure-Request with MRU option (Type=1, Length=4, Value=1500).
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x08, 1, 4, 0x05, 0xDC];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        // Locate the option Object; its descriptor must be the generic
        // container, and the resolved label must be the option name.
        let mut opt_idx = r.start;
        while opt_idx < r.end {
            if let FieldValue::Object(_) = buf.fields()[opt_idx as usize].value {
                break;
            }
            opt_idx += 1;
        }
        let obj = &buf.fields()[opt_idx as usize];
        assert_eq!(obj.descriptor.display_name, "Option");
        assert_eq!(
            buf.resolve_container_display_name(opt_idx),
            Some("Maximum-Receive-Unit"),
        );
    }

    #[test]
    fn lcp_code_name_extended_codes() {
        // Direct coverage of the LCP-only code name table (8..=11).
        assert_eq!(crate::lcp_code_name(8), "Protocol-Reject");
        assert_eq!(crate::lcp_code_name(9), "Echo-Request");
        assert_eq!(crate::lcp_code_name(10), "Echo-Reply");
        assert_eq!(crate::lcp_code_name(11), "Discard-Request");
        assert_eq!(crate::lcp_code_name(12), "Unknown");
        // IPCP-facing code_name still covers only 1..=7 per RFC 1332 Section 2.
        assert_eq!(crate::code_name(8), "Unknown");
    }
}
