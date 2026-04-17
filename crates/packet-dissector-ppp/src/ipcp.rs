//! IPCP (Internet Protocol Control Protocol) parser.
//!
//! ## References
//! - RFC 1332 (IPCP): <https://www.rfc-editor.org/rfc/rfc1332>
//! - RFC 1877 (PPP IPCP extensions for Name Server addresses): <https://www.rfc-editor.org/rfc/rfc1877>
//! - RFC 3241 (updates RFC 1332; multiple IP-Compression-Protocol options): <https://www.rfc-editor.org/rfc/rfc3241>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

use crate::PPP_HEADER_SIZE;

/// Option descriptors for IPCP configuration options.
///
/// RFC 1332, Section 3 — <https://www.rfc-editor.org/rfc/rfc1332#section-3>
static IPCP_OPTION_DESCRIPTORS: &[FieldDescriptor] = ppp_option_descriptors!(|v, _| match v {
    FieldValue::U8(t) => Some(ipcp_option_name(*t)),
    _ => None,
});

/// Container descriptor for an IPCP configuration option entry.
///
/// `display_fn` resolves the outer container's label to the option name
/// (e.g. "IP-Address") by looking up the inner `type` field.
static FD_IPCP_OPTION: FieldDescriptor = FieldDescriptor {
    name: "option",
    display_name: "Option",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => Some(ipcp_option_name(*t)),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

static FD_INLINE_OPTIONS: FieldDescriptor =
    FieldDescriptor::new("options", "Options", FieldType::Array);

/// Parse an IPCP packet into a DissectBuffer.
///
/// IPCP uses the LCP packet format (RFC 1332, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc1332#section-2>) with a distinct set of
/// Configuration Options (RFC 1332, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc1332#section-3>; RFC 1877 Section 1 —
/// <https://www.rfc-editor.org/rfc/rfc1877#section-1>).
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

    // Honour Length field per RFC 1332, Section 2; clip buffer when shorter.
    let options_data = if (length as usize) <= data.len() && length >= PPP_HEADER_SIZE as u16 {
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
            &FD_IPCP_OPTION,
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

// IPCP Configuration Option Types.
// RFC 1332, Section 3 — <https://www.rfc-editor.org/rfc/rfc1332#section-3>
// (Types 1, 2, 3)
// RFC 1877, Section 1 — <https://www.rfc-editor.org/rfc/rfc1877#section-1>
// (Types 129, 130, 131, 132)
fn ipcp_option_name(opt_type: u8) -> &'static str {
    match opt_type {
        // Deprecated per RFC 1332, Section 3.1 — still seen on the wire.
        1 => "IP-Addresses",
        // RFC 1332, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc1332#section-3.2>
        2 => "IP-Compression-Protocol",
        // RFC 1332, Section 3.3 — <https://www.rfc-editor.org/rfc/rfc1332#section-3.3>
        3 => "IP-Address",
        // RFC 1877, Section 1.1 — <https://www.rfc-editor.org/rfc/rfc1877#section-1.1>
        129 => "Primary DNS",
        // RFC 1877, Section 1.2 — <https://www.rfc-editor.org/rfc/rfc1877#section-1.2>
        130 => "Primary NBNS",
        // RFC 1877, Section 1.3 — <https://www.rfc-editor.org/rfc/rfc1877#section-1.3>
        131 => "Secondary DNS",
        // RFC 1877, Section 1.4 — <https://www.rfc-editor.org/rfc/rfc1877#section-1.4>
        132 => "Secondary NBNS",
        _ => "Unknown",
    }
}

fn ipcp_option_value(opt_type: u8, value_data: &[u8]) -> FieldValue<'_> {
    match opt_type {
        // Type 3 / 129 / 130 / 131 / 132 — single 4-octet IPv4 address.
        // RFC 1332 Section 3.3; RFC 1877 Sections 1.1–1.4.
        3 | 129 | 130 | 131 | 132 if value_data.len() >= 4 => {
            FieldValue::Ipv4Addr([value_data[0], value_data[1], value_data[2], value_data[3]])
        }
        // Type 2 — IP-Compression-Protocol: 2-octet protocol identifier +
        // optional sub-option data. RFC 1332 Section 3.2.
        2 if value_data.len() >= 2 => {
            FieldValue::U16(read_be_u16(value_data, 0).unwrap_or_default())
        }
        // Type 1 — IP-Addresses (deprecated): Source-IP + Destination-IP (8
        // octets). Represented as raw bytes to preserve structure without a
        // dedicated FieldValue variant. RFC 1332 Section 3.1.
        _ => FieldValue::Bytes(value_data),
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 1332 (IPCP) + RFC 1877 Coverage
    //!
    //! | RFC Section   | Description                        | Test                                 |
    //! |---------------|------------------------------------|--------------------------------------|
    //! | 1332 §2       | Packet Format (Code/Id/Length)     | parse_truncated, parse_no_options    |
    //! | 1332 §2       | Configure-Request                  | parse_configure_request              |
    //! | 1332 §2       | Configure-Ack                      | parse_configure_ack                  |
    //! | 1332 §2       | Configure-Nak                      | parse_configure_nak                  |
    //! | 1332 §2       | Configure-Reject                   | parse_configure_reject               |
    //! | 1332 §2       | Terminate-Request                  | parse_code_5_terminate_request       |
    //! | 1332 §2       | Terminate-Ack                      | parse_code_6_terminate_ack           |
    //! | 1332 §2       | Code-Reject                        | parse_code_7_code_reject             |
    //! | 1332 §3.1     | IP-Addresses option (deprecated)   | parse_ip_addresses_option            |
    //! | 1332 §3.2     | IP-Compression-Protocol option     | parse_ip_compression_protocol_option |
    //! | 1332 §3.3     | IP-Address option                  | parse_ip_address_option              |
    //! | 1877 §1.1     | Primary-DNS option                 | parse_configure_request, parse_dns_options |
    //! | 1877 §1.2     | Primary-NBNS option                | parse_primary_nbns_option            |
    //! | 1877 §1.3     | Secondary-DNS option               | parse_secondary_dns_option           |
    //! | 1877 §1.4     | Secondary-NBNS option              | parse_secondary_nbns_option          |
    //! | —             | Length exceeds buffer              | parse_length_exceeds_data            |
    //! | —             | Short-value IP option              | parse_ip_address_option_short_value  |
    //! | —             | Unknown option type                | parse_unknown_option_type            |

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
            Some("IP-Address")
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
            Some("IP-Address")
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
            Some("IP-Address")
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

    #[test]
    fn parse_ip_addresses_option() {
        // RFC 1332, Section 3.1 — deprecated IP-Addresses option:
        // Type=1, Length=10, Source-IP (4) + Destination-IP (4).
        #[rustfmt::skip]
        let data = [
            0x01, 0x01, 0x00, 0x0E,
            1, 10, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
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
            Some("IP-Addresses")
        );
        // Deprecated option: value is emitted as raw bytes (two IPv4 addresses).
        assert_eq!(opt[2].value, FieldValue::Bytes(&[10, 0, 0, 1, 10, 0, 0, 2]));
    }

    #[test]
    fn parse_ip_compression_protocol_option() {
        // RFC 1332, Section 3.2 — IP-Compression-Protocol option:
        // Type=2, Length=6, Protocol=0x002D (VJ), MaxSlotId=0x0F, CompSlotId=0x01.
        #[rustfmt::skip]
        let data = [
            0x01, 0x01, 0x00, 0x0A,
            2, 6, 0x00, 0x2D, 0x0F, 0x01,
        ];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(opt[0].value, FieldValue::U8(2));
        assert_eq!(
            opt[0].descriptor.display_fn.unwrap()(&opt[0].value, &[]),
            Some("IP-Compression-Protocol")
        );
        assert_eq!(opt[2].value, FieldValue::U16(0x002D));
    }

    #[test]
    fn parse_ip_compression_protocol_short_value() {
        // Length=4 (protocol-only, no sub-option data).
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x08, 2, 4, 0x00, 0x03];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(opt[2].value, FieldValue::U16(0x0003));
    }

    #[test]
    fn parse_primary_nbns_option() {
        // RFC 1877, Section 1.2 — Type=130, Length=6, 4-octet IPv4.
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x0A, 130, 6, 192, 168, 10, 20];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(opt[0].value, FieldValue::U8(130));
        assert_eq!(
            opt[0].descriptor.display_fn.unwrap()(&opt[0].value, &[]),
            Some("Primary NBNS")
        );
        assert_eq!(opt[2].value, FieldValue::Ipv4Addr([192, 168, 10, 20]));
    }

    #[test]
    fn parse_secondary_nbns_option() {
        // RFC 1877, Section 1.4 — Type=132, Length=6, 4-octet IPv4.
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x0A, 132, 6, 192, 168, 10, 21];
        let buf = parse_to_buf(&data, 0);
        let fields = obj_fields(&buf);
        let FieldValue::Array(ref r) = fields[3].value else {
            panic!("expected Array")
        };
        let opt = nth_obj(&buf, r, 0);
        assert_eq!(opt[0].value, FieldValue::U8(132));
        assert_eq!(
            opt[0].descriptor.display_fn.unwrap()(&opt[0].value, &[]),
            Some("Secondary NBNS")
        );
        assert_eq!(opt[2].value, FieldValue::Ipv4Addr([192, 168, 10, 21]));
    }
}
