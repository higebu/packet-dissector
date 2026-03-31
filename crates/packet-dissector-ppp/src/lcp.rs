//! LCP (Link Control Protocol) parser.
//!
//! ## References
//! - RFC 1661 (PPP / LCP): <https://www.rfc-editor.org/rfc/rfc1661>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

use crate::PPP_HEADER_SIZE;

/// Option descriptors for LCP configuration options.
static LCP_OPTION_DESCRIPTORS: &[FieldDescriptor] = ppp_option_descriptors!(|v, _| match v {
    FieldValue::U8(t) => Some(lcp_option_name(*t)),
    _ => None,
});

static FD_INLINE_DATA: FieldDescriptor = FieldDescriptor::new("data", "Data", FieldType::Bytes);

static FD_INLINE_OPTIONS: FieldDescriptor =
    FieldDescriptor::new("options", "Options", FieldType::Array);

/// Parse an LCP packet into a DissectBuffer.
///
/// RFC 1661, Section 5 -- <https://www.rfc-editor.org/rfc/rfc1661#section-5>
pub fn parse<'pkt>(data: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let Some((code, length)) = crate::parse_header(data, offset, crate::HEADER_DESCRIPTORS, buf)
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

    if matches!(code, 1..=4) {
        let options_data = if (length as usize) <= data.len() && length >= 4 {
            &data[PPP_HEADER_SIZE..length as usize]
        } else {
            &data[PPP_HEADER_SIZE..]
        };
        let options_end = offset + PPP_HEADER_SIZE + options_data.len();
        let array_idx = buf.begin_container(
            &FD_INLINE_OPTIONS,
            FieldValue::Array(0..0),
            offset + PPP_HEADER_SIZE..options_end,
        );
        let has_options = crate::parse_options(
            options_data,
            offset + PPP_HEADER_SIZE,
            LCP_OPTION_DESCRIPTORS,
            parse_option_value,
            buf,
        );
        buf.end_container(array_idx);
        if !has_options {
            buf.pop_field();
        }
    } else {
        buf.push_field(
            &FD_INLINE_DATA,
            FieldValue::Bytes(&data[PPP_HEADER_SIZE..]),
            offset + PPP_HEADER_SIZE..offset + data.len(),
        );
    }
}

fn parse_option_value(opt_type: u8, value_data: &[u8]) -> FieldValue<'_> {
    match opt_type {
        1 if value_data.len() >= 2 => {
            FieldValue::U16(read_be_u16(value_data, 0).unwrap_or_default())
        }
        3 if value_data.len() >= 2 => {
            FieldValue::U16(read_be_u16(value_data, 0).unwrap_or_default())
        }
        5 if value_data.len() >= 4 => {
            FieldValue::U32(read_be_u32(value_data, 0).unwrap_or_default())
        }
        _ => FieldValue::Bytes(value_data),
    }
}

fn lcp_option_name(opt_type: u8) -> &'static str {
    match opt_type {
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
        let data = [0x09, 0x01, 0x00, 0x06, 0x01, 0x02];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields[0].value, FieldValue::U8(9));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Unknown")
        );
        assert_eq!(fields[3].value, FieldValue::Bytes(&[0x01, 0x02]));
    }
}
