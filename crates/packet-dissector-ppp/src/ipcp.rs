//! IPCP (Internet Protocol Control Protocol) parser.
//!
//! ## References
//! - RFC 1332 (IPCP): <https://www.rfc-editor.org/rfc/rfc1332>
//! - RFC 1877 (DNS extensions): <https://www.rfc-editor.org/rfc/rfc1877>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

use crate::PPP_HEADER_SIZE;

/// Option descriptors for IPCP configuration options.
static IPCP_OPTION_DESCRIPTORS: &[FieldDescriptor] = ppp_option_descriptors!(|v, _| match v {
    FieldValue::U8(t) => Some(ipcp_option_name(*t)),
    _ => None,
});

static FD_INLINE_OPTIONS: FieldDescriptor =
    FieldDescriptor::new("options", "Options", FieldType::Array);

/// Parse an IPCP packet into a DissectBuffer.
///
/// RFC 1332 -- <https://www.rfc-editor.org/rfc/rfc1332>
pub fn parse<'pkt>(data: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let Some((_code, length)) = crate::parse_header(data, offset, crate::HEADER_DESCRIPTORS, buf)
    else {
        static FD_RAW: FieldDescriptor = FieldDescriptor::new("data", "Data", FieldType::Bytes);
        buf.push_field(
            &FD_RAW,
            FieldValue::Bytes(data),
            offset..offset + data.len(),
        );
        return;
    };

    let options_data = if (length as usize) <= data.len() && length >= 4 {
        &data[PPP_HEADER_SIZE..length as usize]
    } else if data.len() > PPP_HEADER_SIZE {
        &data[PPP_HEADER_SIZE..]
    } else {
        &[]
    };

    if !options_data.is_empty() {
        let options_end = offset + PPP_HEADER_SIZE + options_data.len();
        let array_idx = buf.begin_container(
            &FD_INLINE_OPTIONS,
            FieldValue::Array(0..0),
            offset + PPP_HEADER_SIZE..options_end,
        );
        let has_options = crate::parse_options(
            options_data,
            offset + PPP_HEADER_SIZE,
            IPCP_OPTION_DESCRIPTORS,
            ipcp_option_value,
            buf,
        );
        buf.end_container(array_idx);
        if !has_options {
            buf.pop_field();
        }
    }
}

fn ipcp_option_name(opt_type: u8) -> &'static str {
    match opt_type {
        3 => "IP Address",
        129 => "Primary DNS",
        131 => "Secondary DNS",
        _ => "Unknown",
    }
}

fn ipcp_option_value(opt_type: u8, value_data: &[u8]) -> FieldValue<'_> {
    if value_data.len() >= 4 && matches!(opt_type, 3 | 129 | 131) {
        FieldValue::Ipv4Addr([value_data[0], value_data[1], value_data[2], value_data[3]])
    } else {
        FieldValue::Bytes(value_data)
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
    fn parse_configure_request() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x0A, 129, 6, 8, 8, 8, 8];
        let buf = parse_to_buf(&data, 100);
        let fields = obj_fields(&buf);
        assert_eq!(fields[0].value, FieldValue::U8(1));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Configure-Request")
        );
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        assert_eq!(count_objects(&buf, r), 1);
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(opt[0].value, FieldValue::U8(129));
        assert_eq!(
            opt[0].descriptor.display_fn.unwrap()(&opt[0].value, &[]),
            Some("Primary DNS")
        );
        assert_eq!(opt[2].value, FieldValue::Ipv4Addr([8, 8, 8, 8]));
    }

    #[test]
    fn parse_dns_options() {
        #[rustfmt::skip]
        let data = [0x01, 0x02, 0x00, 0x10, 129, 6, 8, 8, 8, 8, 131, 6, 8, 8, 4, 4];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        assert_eq!(count_objects(&buf, r), 2);
        let opt1 = nth_obj(&buf, r, 0);
        assert_eq!(opt1[2].value, FieldValue::Ipv4Addr([8, 8, 8, 8]));
        let opt2 = nth_obj(&buf, r, 1);
        assert_eq!(opt2[2].value, FieldValue::Ipv4Addr([8, 8, 4, 4]));
    }

    #[test]
    fn parse_ip_address_option() {
        #[rustfmt::skip]
        let data = [0x02, 0x01, 0x00, 0x0A, 3, 6, 192, 168, 1, 1];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(
            opt[0].descriptor.display_fn.unwrap()(&opt[0].value, &[]),
            Some("IP Address")
        );
        assert_eq!(opt[2].value, FieldValue::Ipv4Addr([192, 168, 1, 1]));
    }

    #[test]
    fn parse_truncated() {
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
    fn parse_no_options() {
        let data = [0x01, 0x01, 0x00, 0x04];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn parse_truncated_option() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x08, 129, 6, 8, 8];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn parse_unknown_option_type() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x08, 42, 4, 0x01, 0x02];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(opt[0].value, FieldValue::U8(42));
        assert_eq!(
            opt[0].descriptor.display_fn.unwrap()(&opt[0].value, &[]),
            Some("Unknown")
        );
        assert_eq!(opt[2].value, FieldValue::Bytes(&[0x01, 0x02]));
    }

    #[test]
    fn parse_length_exceeds_data() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x14, 129, 6, 8, 8, 8, 8];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        assert_eq!(count_objects(&buf, r), 1);
    }

    #[test]
    fn parse_header_only_no_options_data() {
        let data = [0x01, 0x01, 0x00, 0x04];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn parse_configure_ack() {
        #[rustfmt::skip]
        let data = [0x02, 0x01, 0x00, 0x0A, 3, 6, 10, 0, 0, 1];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields[0].value, FieldValue::U8(2));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Configure-Ack")
        );
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        assert_eq!(count_objects(&buf, r), 1);
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(
            opt[0].descriptor.display_fn.unwrap()(&opt[0].value, &[]),
            Some("IP Address")
        );
        assert_eq!(opt[2].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
    }

    #[test]
    fn parse_configure_nak() {
        #[rustfmt::skip]
        let data = [0x03, 0x02, 0x00, 0x0A, 129, 6, 8, 8, 8, 8];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields[0].value, FieldValue::U8(3));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Configure-Nak")
        );
    }

    #[test]
    fn parse_configure_reject() {
        #[rustfmt::skip]
        let data = [0x04, 0x03, 0x00, 0x0A, 131, 6, 1, 1, 1, 1];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields[0].value, FieldValue::U8(4));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Configure-Reject")
        );
    }

    #[test]
    fn parse_code_5_terminate_request() {
        let data = [0x05, 0x01, 0x00, 0x04];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields[0].value, FieldValue::U8(5));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Terminate-Request")
        );
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn parse_code_6_terminate_ack() {
        let data = [0x06, 0x02, 0x00, 0x04];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields[0].value, FieldValue::U8(6));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Terminate-Ack")
        );
    }

    #[test]
    fn parse_code_7_code_reject() {
        #[rustfmt::skip]
        let data = [0x07, 0x03, 0x00, 0x06, 0xAA, 0xBB];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        assert_eq!(fields[0].value, FieldValue::U8(7));
        assert_eq!(
            fields[0].descriptor.display_fn.unwrap()(&fields[0].value, &[]),
            Some("Code-Reject")
        );
    }

    #[test]
    fn parse_ip_address_option_short_value() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x08, 3, 4, 0x0A, 0x01];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(opt[2].value, FieldValue::Bytes(&[0x0A, 0x01]));
    }

    #[test]
    fn parse_primary_dns_short_value() {
        #[rustfmt::skip]
        let data = [0x02, 0x01, 0x00, 0x08, 129, 4, 0x08, 0x08];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(opt[2].value, FieldValue::Bytes(&[0x08, 0x08]));
    }

    #[test]
    fn parse_secondary_dns_option() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x0A, 131, 6, 1, 0, 0, 1];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(
            opt[0].descriptor.display_fn.unwrap()(&opt[0].value, &[]),
            Some("Secondary DNS")
        );
        assert_eq!(opt[2].value, FieldValue::Ipv4Addr([1, 0, 0, 1]));
    }

    #[test]
    fn parse_combined_ip_dns_options() {
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x16, 3, 6, 10, 0, 0, 1, 129, 6, 8, 8, 8, 8, 131, 6, 8, 8, 4, 4];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        assert_eq!(count_objects(&buf, r), 3);
        let opt0 = nth_obj(&buf, r, 0);
        assert_eq!(
            opt0[0].descriptor.display_fn.unwrap()(&opt0[0].value, &[]),
            Some("IP Address")
        );
        assert_eq!(opt0[2].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
        let opt1 = nth_obj(&buf, r, 1);
        assert_eq!(
            opt1[0].descriptor.display_fn.unwrap()(&opt1[0].value, &[]),
            Some("Primary DNS")
        );
        assert_eq!(opt1[2].value, FieldValue::Ipv4Addr([8, 8, 8, 8]));
        let opt2 = nth_obj(&buf, r, 2);
        assert_eq!(
            opt2[0].descriptor.display_fn.unwrap()(&opt2[0].value, &[]),
            Some("Secondary DNS")
        );
        assert_eq!(opt2[2].value, FieldValue::Ipv4Addr([8, 8, 4, 4]));
    }
}
