//! Protocol Configuration Options (PCO) parser.
//!
//! Parses PCO/APCO/ePCO content per 3GPP TS 24.008, Section 10.5.6.3.
//!
//! PPP sub-protocol parsing (IPCP, LCP, PAP, CHAP) is delegated to the
//! [`packet_dissector_ppp`] crate.

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_ipv4_addr, read_ipv6_addr};

static FD_INLINE_CONFIGURATION_PROTOCOL: FieldDescriptor = FieldDescriptor::new(
    "configuration_protocol",
    "Configuration Protocol",
    FieldType::U8,
);

static FD_INLINE_CONTENTS: FieldDescriptor =
    FieldDescriptor::new("contents", "Contents", FieldType::Bytes);

static FD_INLINE_LENGTH: FieldDescriptor = FieldDescriptor::new("length", "Length", FieldType::U8);

static FD_INLINE_PROTOCOLS: FieldDescriptor =
    FieldDescriptor::new("protocols", "Protocols", FieldType::Array);

static FD_INLINE_PROTOCOL_ID: FieldDescriptor = FieldDescriptor {
    name: "protocol_id",
    display_name: "Protocol ID",
    field_type: FieldType::U16,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U16(id) => Some(pco_protocol_name(*id)),
        _ => None,
    }),
    format_fn: None,
};

/// Push Protocol Configuration Options data into `buf`.
///
/// 3GPP TS 24.008, Section 10.5.6.3.
pub fn push_pco<'pkt>(
    data: &'pkt [u8],
    base_offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.is_empty() {
        buf.push_field(value_desc, FieldValue::Bytes(&[]), value_range.clone());
        return;
    }

    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());

    // First octet: ext(1) | spare(4) | configuration_protocol(3)
    let config_protocol = data[0] & 0x07;
    buf.push_field(
        &FD_INLINE_CONFIGURATION_PROTOCOL,
        FieldValue::U8(config_protocol),
        base_offset..base_offset + 1,
    );

    // Parse protocol entries
    let protocols_idx = buf.begin_container(
        &FD_INLINE_PROTOCOLS,
        FieldValue::Array(0..0),
        base_offset + 1..base_offset + data.len(),
    );

    let mut pos: usize = 1;
    while pos + 3 <= data.len() {
        let protocol_id = read_be_u16(data, pos).unwrap_or_default();
        let entry_len = data[pos + 2] as usize;

        if pos + 3 + entry_len > data.len() {
            break;
        }

        let entry_data = &data[pos + 3..pos + 3 + entry_len];
        let entry_offset = base_offset + pos + 3;
        let entry_start = base_offset + pos;
        let entry_end = entry_start + 3 + entry_len;

        // Begin Object for this protocol entry
        let entry_idx = buf.begin_container(
            &FD_INLINE_PROTOCOL_ID,
            FieldValue::Object(0..0),
            entry_start..entry_end,
        );

        buf.push_field(
            &FD_INLINE_PROTOCOL_ID,
            FieldValue::U16(protocol_id),
            entry_start..entry_start + 2,
        );
        buf.push_field(
            &FD_INLINE_LENGTH,
            FieldValue::U8(entry_len as u8),
            entry_start + 2..entry_start + 3,
        );

        // Push contents
        push_pco_protocol_contents(protocol_id, entry_data, entry_offset, entry_end, buf);

        buf.end_container(entry_idx);

        pos += 3 + entry_len;
    }

    buf.end_container(protocols_idx);
    buf.end_container(obj_idx);
}

/// Returns the protocol name for a PCO protocol/container ID.
fn pco_protocol_name(id: u16) -> &'static str {
    match id {
        0x0001 => "P-CSCF IPv6 Address Request",
        0x0002 => "IM CN Subsystem Signaling Flag",
        0x0003 => "DNS Server IPv6 Address Request",
        0x0004 => "Not Supported",
        0x0005 => "MS Support of Network Requested Bearer Control indicator",
        0x0006 => "DSMIPv6 Home Agent Address Request",
        0x0007 => "DSMIPv6 Home Network Prefix Request",
        0x0008 => "DSMIPv6 IPv4 Home Agent Address Request",
        0x0009 => "IP address allocation via NAS signalling",
        0x000A => "IPv4 address allocation via DHCPv4",
        0x000C => "P-CSCF IPv4 Address Request",
        0x000D => "DNS Server IPv4 Address Request",
        0x000E => "MSISDN Request",
        0x000F => "IFOM Support Request",
        0x0010 => "IPv4 Link MTU Request",
        0x0011 => "MS support of Local address in TFT indicator",
        0x0012 => "P-CSCF Re-selection Support",
        0x0013 => "NBIFOM request indicator",
        0x0014 => "NBIFOM mode",
        0x0015 => "Non-IP Link MTU Request",
        0x0016 => "APN rate control support indicator",
        0x0017 => "3GPP PS data off UE status",
        0x0018 => "Reliable Data Service request indicator",
        0x8021 => "IPCP",
        0xC021 => "LCP",
        0xC023 => "PAP",
        0xC223 => "CHAP",
        _ => "Unknown",
    }
}

/// Push the contents of a specific PCO protocol entry.
fn push_pco_protocol_contents<'pkt>(
    protocol_id: u16,
    data: &'pkt [u8],
    entry_offset: usize,
    entry_end: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    match protocol_id {
        // PPP sub-protocols — delegate to packet-dissector-ppp.
        // parse_protocol pushes its own Object container for the contents.
        0x8021 | 0xC021 | 0xC023 | 0xC223 => {
            let contents_idx = buf.begin_container(
                &FD_INLINE_CONTENTS,
                FieldValue::Object(0..0),
                entry_offset..entry_end,
            );
            packet_dissector_ppp::parse_protocol(protocol_id, data, entry_offset, buf);
            buf.end_container(contents_idx);
        }
        // P-CSCF IPv6 Address
        0x0001 if data.len() == 16 => {
            buf.push_field(
                &FD_INLINE_CONTENTS,
                FieldValue::Ipv6Addr(read_ipv6_addr(data, 0).unwrap_or_default()),
                entry_offset..entry_end,
            );
        }
        // DNS Server IPv6 Address
        0x0003 if data.len() == 16 => {
            buf.push_field(
                &FD_INLINE_CONTENTS,
                FieldValue::Ipv6Addr(read_ipv6_addr(data, 0).unwrap_or_default()),
                entry_offset..entry_end,
            );
        }
        // P-CSCF IPv4 Address
        0x000C if data.len() == 4 => {
            buf.push_field(
                &FD_INLINE_CONTENTS,
                FieldValue::Ipv4Addr(read_ipv4_addr(data, 0).unwrap_or_default()),
                entry_offset..entry_end,
            );
        }
        // DNS Server IPv4 Address
        0x000D if data.len() == 4 => {
            buf.push_field(
                &FD_INLINE_CONTENTS,
                FieldValue::Ipv4Addr(read_ipv4_addr(data, 0).unwrap_or_default()),
                entry_offset..entry_end,
            );
        }
        // IPv4 Link MTU
        0x0010 if data.len() >= 2 => {
            buf.push_field(
                &FD_INLINE_CONTENTS,
                FieldValue::U16(read_be_u16(data, 0).unwrap_or_default()),
                entry_offset..entry_end,
            );
        }
        _ => {
            buf.push_field(
                &FD_INLINE_CONTENTS,
                FieldValue::Bytes(data),
                entry_offset..entry_end,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;

    static FD_TEST_VALUE: FieldDescriptor =
        FieldDescriptor::new("value", "Value", FieldType::Bytes);

    fn push_pco_test<'a>(data: &'a [u8], base_offset: usize) -> DissectBuffer<'a> {
        let mut buf = DissectBuffer::new();
        let range = base_offset..base_offset + data.len();
        push_pco(data, base_offset, &FD_TEST_VALUE, &range, &mut buf);
        buf
    }

    fn obj_field_value<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        obj_range: &core::ops::Range<u32>,
        name: &str,
    ) -> Option<&'a FieldValue<'pkt>> {
        buf.nested_fields(obj_range)
            .iter()
            .find(|f| f.name() == name)
            .map(|f| &f.value)
    }

    fn get_protocols_array<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
    ) -> Option<core::ops::Range<u32>> {
        let FieldValue::Object(ref obj_r) = buf.fields()[0].value else {
            return None;
        };
        let protocols_field = buf
            .nested_fields(obj_r)
            .iter()
            .find(|f| f.name() == "protocols")?;
        match &protocols_field.value {
            FieldValue::Array(r) => Some(r.clone()),
            _ => None,
        }
    }

    fn get_protocol_entry<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        index: usize,
    ) -> Option<core::ops::Range<u32>> {
        let arr_range = get_protocols_array(buf)?;
        let fields = buf.nested_fields(&arr_range);
        let mut found = 0;
        let mut i = 0;
        while i < fields.len() {
            if let FieldValue::Object(ref r) = fields[i].value {
                if found == index {
                    return Some(r.clone());
                }
                found += 1;
                i = (r.end - arr_range.start) as usize;
            } else {
                i += 1;
            }
        }
        None
    }

    fn count_protocol_entries(buf: &DissectBuffer<'_>) -> usize {
        let Some(arr_range) = get_protocols_array(buf) else {
            return 0;
        };
        // Count only top-level Objects (skip over their children).
        let fields = buf.nested_fields(&arr_range);
        let mut count = 0;
        let mut i = 0;
        while i < fields.len() {
            if let FieldValue::Object(ref r) = fields[i].value {
                count += 1;
                // Skip to end of this Object's children (relative to arr_range.start)
                i = (r.end - arr_range.start) as usize;
            } else {
                i += 1;
            }
        }
        count
    }

    #[test]
    fn empty_data_returns_bytes() {
        let buf = push_pco_test(&[], 0);
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(&[]));
    }

    #[test]
    fn header_only_returns_config_protocol_and_empty_protocols() {
        let data = [0x80];
        let buf = push_pco_test(&data, 0);
        let FieldValue::Object(ref obj_r) = buf.fields()[0].value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_value(&buf, obj_r, "configuration_protocol"),
            Some(&FieldValue::U8(0))
        );
        assert_eq!(count_protocol_entries(&buf), 0);
    }

    #[test]
    fn dns_ipv4_entry() {
        let data = [0x80, 0x00, 0x0D, 0x04, 8, 8, 8, 8];
        let buf = push_pco_test(&data, 0);
        assert_eq!(count_protocol_entries(&buf), 1);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "protocol_id"),
            Some(&FieldValue::U16(0x000D))
        );
        assert_eq!(
            obj_field_value(&buf, &entry, "contents"),
            Some(&FieldValue::Ipv4Addr([8, 8, 8, 8]))
        );
    }

    #[test]
    fn dns_ipv6_entry() {
        let mut data = vec![0x80, 0x00, 0x03, 0x10];
        let ipv6_bytes: [u8; 16] = [
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x88, 0x88,
        ];
        data.extend_from_slice(&ipv6_bytes);
        let buf = push_pco_test(&data, 0);
        assert_eq!(count_protocol_entries(&buf), 1);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "protocol_id"),
            Some(&FieldValue::U16(0x0003))
        );
        assert_eq!(
            obj_field_value(&buf, &entry, "contents"),
            Some(&FieldValue::Ipv6Addr(ipv6_bytes))
        );
    }

    #[test]
    fn ipv4_link_mtu_entry() {
        let data = [0x80, 0x00, 0x10, 0x02, 0x05, 0xDC];
        let buf = push_pco_test(&data, 0);
        assert_eq!(count_protocol_entries(&buf), 1);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "protocol_id"),
            Some(&FieldValue::U16(0x0010))
        );
        assert_eq!(
            obj_field_value(&buf, &entry, "contents"),
            Some(&FieldValue::U16(1500))
        );
    }

    #[test]
    fn unknown_protocol_returns_bytes() {
        let data = [0x80, 0x00, 0xFF, 0x03, 0xAA, 0xBB, 0xCC];
        let buf = push_pco_test(&data, 0);
        assert_eq!(count_protocol_entries(&buf), 1);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "protocol_id"),
            Some(&FieldValue::U16(0x00FF))
        );
        assert_eq!(
            obj_field_value(&buf, &entry, "contents"),
            Some(&FieldValue::Bytes(&[0xAA, 0xBB, 0xCC]))
        );
    }

    #[test]
    fn pap_protocol_delegation() {
        let data = [0x80, 0xC0, 0x23, 0x04, 0x01, 0x01, 0x00, 0x04];
        let buf = push_pco_test(&data, 0);
        assert_eq!(count_protocol_entries(&buf), 1);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "protocol_id"),
            Some(&FieldValue::U16(0xC023))
        );
        assert_eq!(
            buf.resolve_nested_display_name(&entry, "protocol_id_name"),
            Some("PAP")
        );
        assert!(matches!(
            obj_field_value(&buf, &entry, "contents"),
            Some(FieldValue::Object(_))
        ));
    }

    #[test]
    fn chap_protocol_delegation() {
        let data = [0x80, 0xC2, 0x23, 0x04, 0x03, 0x01, 0x00, 0x04];
        let buf = push_pco_test(&data, 0);
        assert_eq!(count_protocol_entries(&buf), 1);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "protocol_id"),
            Some(&FieldValue::U16(0xC223))
        );
        assert_eq!(
            buf.resolve_nested_display_name(&entry, "protocol_id_name"),
            Some("CHAP")
        );
        assert!(matches!(
            obj_field_value(&buf, &entry, "contents"),
            Some(FieldValue::Object(_))
        ));
    }

    #[test]
    fn pcscf_ipv6_address_entry() {
        let mut data = vec![0x80, 0x00, 0x01, 0x10];
        let ipv6_bytes: [u8; 16] = [
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        data.extend_from_slice(&ipv6_bytes);
        let buf = push_pco_test(&data, 0);
        assert_eq!(count_protocol_entries(&buf), 1);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "protocol_id"),
            Some(&FieldValue::U16(0x0001))
        );
        assert_eq!(
            buf.resolve_nested_display_name(&entry, "protocol_id_name"),
            Some("P-CSCF IPv6 Address Request")
        );
        assert_eq!(
            obj_field_value(&buf, &entry, "contents"),
            Some(&FieldValue::Ipv6Addr(ipv6_bytes))
        );
    }

    #[test]
    fn pcscf_ipv4_address_entry() {
        let data = [0x80, 0x00, 0x0C, 0x04, 192, 168, 1, 100];
        let buf = push_pco_test(&data, 0);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "contents"),
            Some(&FieldValue::Ipv4Addr([192, 168, 1, 100]))
        );
    }

    #[test]
    fn different_config_protocol_values() {
        let data = [0x83];
        let buf = push_pco_test(&data, 0);
        let FieldValue::Object(ref obj_r) = buf.fields()[0].value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_value(&buf, obj_r, "configuration_protocol"),
            Some(&FieldValue::U8(3))
        );

        let data = [0x87];
        let buf = push_pco_test(&data, 0);
        let FieldValue::Object(ref obj_r) = buf.fields()[0].value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_value(&buf, obj_r, "configuration_protocol"),
            Some(&FieldValue::U8(7))
        );

        let data = [0x00];
        let buf = push_pco_test(&data, 0);
        let FieldValue::Object(ref obj_r) = buf.fields()[0].value else {
            panic!("expected Object")
        };
        assert_eq!(
            obj_field_value(&buf, obj_r, "configuration_protocol"),
            Some(&FieldValue::U8(0))
        );
    }

    #[test]
    fn ipv6_address_wrong_length_returns_bytes() {
        let data = [0x80, 0x00, 0x01, 0x04, 0x01, 0x02, 0x03, 0x04];
        let buf = push_pco_test(&data, 0);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "contents"),
            Some(&FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04]))
        );
    }

    #[test]
    fn zero_length_protocol_entry() {
        let data = [0x80, 0x00, 0x09, 0x00];
        let buf = push_pco_test(&data, 0);
        assert_eq!(count_protocol_entries(&buf), 1);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "protocol_id"),
            Some(&FieldValue::U16(0x0009))
        );
        assert_eq!(
            buf.resolve_nested_display_name(&entry, "protocol_id_name"),
            Some("IP address allocation via NAS signalling")
        );
        assert_eq!(
            obj_field_value(&buf, &entry, "contents"),
            Some(&FieldValue::Bytes(&[]))
        );
    }

    #[test]
    fn multiple_protocol_entries() {
        let data = [
            0x80, 0x00, 0x0D, 0x04, 8, 8, 8, 8, 0x00, 0x10, 0x02, 0x05, 0xDC,
        ];
        let buf = push_pco_test(&data, 0);
        assert_eq!(count_protocol_entries(&buf), 2);
    }

    #[test]
    fn lcp_protocol_delegation() {
        let data = [0x80, 0xC0, 0x21, 0x04, 0x01, 0x01, 0x00, 0x04];
        let buf = push_pco_test(&data, 0);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "protocol_id"),
            Some(&FieldValue::U16(0xC021))
        );
        assert_eq!(
            buf.resolve_nested_display_name(&entry, "protocol_id_name"),
            Some("LCP")
        );
        assert!(matches!(
            obj_field_value(&buf, &entry, "contents"),
            Some(FieldValue::Object(_))
        ));
    }

    #[test]
    fn ipcp_protocol_delegation() {
        let data = [0x80, 0x80, 0x21, 0x04, 0x01, 0x01, 0x00, 0x04];
        let buf = push_pco_test(&data, 0);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "protocol_id"),
            Some(&FieldValue::U16(0x8021))
        );
        assert_eq!(
            buf.resolve_nested_display_name(&entry, "protocol_id_name"),
            Some("IPCP")
        );
        assert!(matches!(
            obj_field_value(&buf, &entry, "contents"),
            Some(FieldValue::Object(_))
        ));
    }

    #[test]
    fn dns_ipv6_wrong_length_returns_bytes() {
        let data = [0x80, 0x00, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04];
        let buf = push_pco_test(&data, 0);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "contents"),
            Some(&FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04]))
        );
    }

    #[test]
    fn dns_ipv4_wrong_length_returns_bytes() {
        let data = [0x80, 0x00, 0x0D, 0x02, 0x08, 0x08];
        let buf = push_pco_test(&data, 0);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "contents"),
            Some(&FieldValue::Bytes(&[0x08, 0x08]))
        );
    }

    #[test]
    fn pcscf_ipv4_wrong_length_returns_bytes() {
        let data = [0x80, 0x00, 0x0C, 0x02, 0x0A, 0x01];
        let buf = push_pco_test(&data, 0);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "contents"),
            Some(&FieldValue::Bytes(&[0x0A, 0x01]))
        );
    }

    #[test]
    fn ipv4_link_mtu_short_returns_bytes() {
        let data = [0x80, 0x00, 0x10, 0x01, 0x05];
        let buf = push_pco_test(&data, 0);
        let entry = get_protocol_entry(&buf, 0).unwrap();
        assert_eq!(
            obj_field_value(&buf, &entry, "contents"),
            Some(&FieldValue::Bytes(&[0x05]))
        );
    }

    #[test]
    fn multiple_protocols_mixed_types() {
        let data = [
            0x80, 0x80, 0x21, 0x04, 0x01, 0x01, 0x00, 0x04, 0x00, 0x0C, 0x04, 10, 0, 0, 1, 0x00,
            0x09, 0x00,
        ];
        let buf = push_pco_test(&data, 0);
        assert_eq!(count_protocol_entries(&buf), 3);
    }

    #[test]
    fn pco_protocol_name_coverage() {
        assert_eq!(pco_protocol_name(0x0001), "P-CSCF IPv6 Address Request");
        assert_eq!(pco_protocol_name(0x0002), "IM CN Subsystem Signaling Flag");
        assert_eq!(pco_protocol_name(0x0003), "DNS Server IPv6 Address Request");
        assert_eq!(pco_protocol_name(0x0004), "Not Supported");
        assert_eq!(
            pco_protocol_name(0x0005),
            "MS Support of Network Requested Bearer Control indicator"
        );
        assert_eq!(
            pco_protocol_name(0x0006),
            "DSMIPv6 Home Agent Address Request"
        );
        assert_eq!(
            pco_protocol_name(0x0007),
            "DSMIPv6 Home Network Prefix Request"
        );
        assert_eq!(
            pco_protocol_name(0x0008),
            "DSMIPv6 IPv4 Home Agent Address Request"
        );
        assert_eq!(
            pco_protocol_name(0x0009),
            "IP address allocation via NAS signalling"
        );
        assert_eq!(
            pco_protocol_name(0x000A),
            "IPv4 address allocation via DHCPv4"
        );
        assert_eq!(pco_protocol_name(0x000C), "P-CSCF IPv4 Address Request");
        assert_eq!(pco_protocol_name(0x000D), "DNS Server IPv4 Address Request");
        assert_eq!(pco_protocol_name(0x000E), "MSISDN Request");
        assert_eq!(pco_protocol_name(0x000F), "IFOM Support Request");
        assert_eq!(pco_protocol_name(0x0010), "IPv4 Link MTU Request");
        assert_eq!(
            pco_protocol_name(0x0011),
            "MS support of Local address in TFT indicator"
        );
        assert_eq!(pco_protocol_name(0x0012), "P-CSCF Re-selection Support");
        assert_eq!(pco_protocol_name(0x0013), "NBIFOM request indicator");
        assert_eq!(pco_protocol_name(0x0014), "NBIFOM mode");
        assert_eq!(pco_protocol_name(0x0015), "Non-IP Link MTU Request");
        assert_eq!(
            pco_protocol_name(0x0016),
            "APN rate control support indicator"
        );
        assert_eq!(pco_protocol_name(0x0017), "3GPP PS data off UE status");
        assert_eq!(
            pco_protocol_name(0x0018),
            "Reliable Data Service request indicator"
        );
        assert_eq!(pco_protocol_name(0x8021), "IPCP");
        assert_eq!(pco_protocol_name(0xC021), "LCP");
        assert_eq!(pco_protocol_name(0xC023), "PAP");
        assert_eq!(pco_protocol_name(0xC223), "CHAP");
        assert_eq!(pco_protocol_name(0xFFFF), "Unknown");
    }

    #[test]
    fn truncated_entry_breaks_loop() {
        let data = [0x80, 0x00, 0x0D, 0x04, 0x08, 0x08];
        let buf = push_pco_test(&data, 0);
        assert_eq!(count_protocol_entries(&buf), 0);
    }
}
