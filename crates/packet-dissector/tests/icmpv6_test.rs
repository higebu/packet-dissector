//! # RFC 4443 (ICMPv6) Coverage
//!
//! | RFC Section       | Description                          | Test                                              |
//! |-------------------|--------------------------------------|-------------------------------------------------  |
//! | 3.1               | Destination Unreachable (Type 1)     | parse_icmpv6_destination_unreachable               |
//! | 3.2               | Packet Too Big (Type 2)              | parse_icmpv6_packet_too_big                        |
//! | 3.3               | Time Exceeded (Type 3)               | parse_icmpv6_time_exceeded                         |
//! | 3.4               | Parameter Problem (Type 4)           | parse_icmpv6_parameter_problem                     |
//! | 4.1               | Echo Request (Type 128)              | parse_icmpv6_echo_request                          |
//! | 4.2               | Echo Reply (Type 129)                | parse_icmpv6_echo_reply                            |
//! | 4.1               | Echo Request with data payload       | parse_icmpv6_echo_request_with_data                |
//! | —                 | Truncated header                     | parse_icmpv6_truncated                             |
//! | —                 | Offset handling                      | parse_icmpv6_with_offset                           |
//! | —                 | Dissector metadata                   | icmpv6_dissector_metadata                          |
//! | —                 | Unknown type (no type-specific parse) | parse_icmpv6_unknown_type                         |
//!
//! # RFC 4884 (Extended ICMP Multi-Part Messages — updates RFC 4443) Coverage
//!
//! | RFC Section       | Description                          | Test                                                        |
//! |-------------------|--------------------------------------|-------------------------------------------------------------|
//! | §4                | Length field (Type 1, non-zero)      | parse_icmpv6_destination_unreachable_rfc4884_length         |
//! | §4                | Length=0 not emitted (Type 1)        | parse_icmpv6_destination_unreachable_rfc4884_length_zero    |
//! | §4                | Length field (Type 3, non-zero)      | parse_icmpv6_time_exceeded_rfc4884_length                   |
//!
//! # RFC 4861 (Neighbor Discovery) Coverage
//!
//! | RFC Section       | Description                          | Test                                              |
//! |-------------------|--------------------------------------|-------------------------------------------------  |
//! | 4.1               | Router Solicitation (Type 133)       | parse_icmpv6_router_solicitation                   |
//! | 4.1               | RS with options                      | parse_icmpv6_router_solicitation_with_options       |
//! | 4.2               | Router Advertisement (Type 134)      | parse_icmpv6_router_advertisement                  |
//! | 4.2               | RA with Prefix Info option           | parse_icmpv6_router_advertisement_with_prefix_info |
//! | 4.2               | RA truncated                         | parse_icmpv6_router_advertisement_truncated        |
//! | 4.3               | Neighbor Solicitation (Type 135)     | parse_icmpv6_neighbor_solicitation                 |
//! | 4.3               | NS with options                      | parse_icmpv6_neighbor_solicitation_with_options     |
//! | 4.3               | NS truncated                         | parse_icmpv6_neighbor_solicitation_truncated        |
//! | 4.4               | Neighbor Advertisement (Type 136)    | parse_icmpv6_neighbor_advertisement                |
//! | 4.4               | NA with options                      | parse_icmpv6_neighbor_advertisement_with_options   |
//! | 4.5               | Redirect (Type 137)                  | parse_icmpv6_redirect                              |
//! | 4.5               | Redirect with options                | parse_icmpv6_redirect_with_options                 |
//! | 4.5               | Redirect truncated                   | parse_icmpv6_redirect_truncated                    |
//! | 4.6               | NDP Option: Source Link-Layer        | parse_icmpv6_ndp_option_source_link_layer          |
//! | 4.6               | NDP Option: Prefix Information       | parse_icmpv6_ndp_option_prefix_info                |
//! | 4.6               | NDP Option: MTU                      | parse_icmpv6_ndp_option_mtu                        |
//! | 4.6               | NDP Option: Unknown                  | parse_icmpv6_ndp_option_unknown                    |
//! | 4.6               | NDP Option: Zero length              | parse_icmpv6_ndp_option_zero_length                |
//!
//! # RFC 4191 (Route Information Option) Coverage
//!
//! | RFC Section       | Description                          | Test                                              |
//! |-------------------|--------------------------------------|-------------------------------------------------  |
//! | §2.3              | Route Info Option (Type 24)          | parse_icmpv6_ndp_option_route_info                 |
//! | §2.3              | Route Info short prefix (len=2)      | parse_icmpv6_ndp_option_route_info_short_prefix    |
//!
//! # RFC 8106 (RDNSS + DNSSL) Coverage
//!
//! | RFC Section       | Description                          | Test                                              |
//! |-------------------|--------------------------------------|-------------------------------------------------  |
//! | §5.1              | RDNSS Option (Type 25)               | parse_icmpv6_ndp_option_rdnss                      |
//! | §5.1              | RDNSS multiple addresses             | parse_icmpv6_ndp_option_rdnss_multiple             |
//! | §5.2              | DNSSL Option (Type 31)               | parse_icmpv6_ndp_option_dnssl                      |
//! | §5.2              | DNSSL multiple domains               | parse_icmpv6_ndp_option_dnssl_multiple             |
//! | §5.2              | DNSSL truncated label (no loop)      | parse_icmpv6_ndp_option_dnssl_truncated_label      |
//!
//! # RFC 8781 (PREF64) Coverage
//!
//! | RFC Section       | Description                          | Test                                              |
//! |-------------------|--------------------------------------|-------------------------------------------------  |
//! | §4                | PREF64 Option (Type 38, /64)         | parse_icmpv6_ndp_option_pref64                     |
//! | §4                | PREF64 Option (Type 38, /96)         | parse_icmpv6_ndp_option_pref64_96                  |
//!
//! # RFC 8335 (Extended Echo) Coverage
//!
//! | RFC Section       | Description                          | Test                                              |
//! |-------------------|--------------------------------------|-------------------------------------------------  |
//! | §2.1              | Extended Echo Request (Type 160)     | parse_icmpv6_extended_echo_request                 |
//! | §2.2              | Extended Echo Reply (Type 161)       | parse_icmpv6_extended_echo_reply                   |
//!
//! # RFC 2710 / RFC 3810 (MLD) Coverage
//!
//! | RFC Section       | Description                          | Test                                              |
//! |-------------------|--------------------------------------|-------------------------------------------------  |
//! | RFC 2710 §3.6     | MLDv1 Query (Type 130)               | parse_icmpv6_mld_query_v1                          |
//! | RFC 3810 §5.1     | MLDv2 Query (Type 130)               | parse_icmpv6_mld_query_v2                          |
//! | RFC 3810 §5.1     | MLDv2 Query with sources             | parse_icmpv6_mld_query_v2_with_sources             |
//! | RFC 2710 §3.7     | MLDv1 Report (Type 131)              | parse_icmpv6_mld_report_v1                         |
//! | RFC 2710 §3.8     | MLDv1 Done (Type 132)                | parse_icmpv6_mld_done                              |
//! | —                 | MLD Query truncated                  | parse_icmpv6_mld_query_truncated                   |
//! | RFC 3810 §5.1     | MLDv2 Query partial extension (no panic) | parse_icmpv6_mldv2_query_partial_extension_not_panic |
//! | RFC 3810 §5.2     | MLDv2 Report (Type 143)              | parse_icmpv6_mldv2_report                          |
//! | RFC 3810 §5.2     | MLDv2 Report multiple records        | parse_icmpv6_mldv2_report_multiple_records         |
//! | RFC 3810 §5.2     | MLDv2 Report with sources            | parse_icmpv6_mldv2_report_with_sources             |
//! | RFC 3810 §5.2     | MLDv2 Report truncated               | parse_icmpv6_mldv2_report_truncated                |
//!
//! # RFC 4286 (Multicast Router Discovery) Coverage
//!
//! | RFC Section       | Description                          | Test                                              |
//! |-------------------|--------------------------------------|-------------------------------------------------  |
//! | §3                | MR Advertisement (Type 151)          | parse_icmpv6_multicast_router_advertisement        |
//! | §3                | MR Solicitation (Type 152)           | parse_icmpv6_multicast_router_solicitation          |
//! | §3                | MR Termination (Type 153)            | parse_icmpv6_multicast_router_termination           |
//!
//! # RFC 6275 (Mobile IPv6) Coverage
//!
//! | RFC Section       | Description                          | Test                                              |
//! |-------------------|--------------------------------------|-------------------------------------------------  |
//! | §6.5              | HA Discovery Request (Type 144)      | parse_icmpv6_home_agent_request                    |
//! | §6.5              | HA Discovery Reply (Type 145)        | parse_icmpv6_home_agent_reply                      |
//! | §6.5              | HA Reply multiple addresses          | parse_icmpv6_home_agent_reply_multiple_addresses   |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::field::FieldValue;
use packet_dissector::packet::DissectBuffer;

use packet_dissector::dissectors::icmpv6::Icmpv6Dissector;

/// Build a minimal ICMPv6 header (8 bytes).
fn build_icmpv6_packet(icmpv6_type: u8, code: u8, rest: [u8; 4]) -> Vec<u8> {
    let mut pkt = vec![0u8; 8];
    pkt[0] = icmpv6_type;
    pkt[1] = code;
    // Checksum = 0 for testing
    pkt[2] = 0x00;
    pkt[3] = 0x00;
    pkt[4..8].copy_from_slice(&rest);
    pkt
}

#[test]
fn parse_icmpv6_echo_request() {
    // RFC 4443, Section 4.1 — Type 128, Code 0
    let id: u16 = 0x1234;
    let seq: u16 = 0x0001;
    let rest = {
        let mut r = [0u8; 4];
        r[0..2].copy_from_slice(&id.to_be_bytes());
        r[2..4].copy_from_slice(&seq.to_be_bytes());
        r
    };
    let data = build_icmpv6_packet(128, 0, rest);
    let mut buf = DissectBuffer::new();
    let result = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 8);
    assert_eq!(result.next, DispatchHint::End);

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(layer.name, "ICMPv6");
    assert_eq!(layer.range, 0..8);

    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(128)
    );
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "checksum").unwrap().value,
        FieldValue::U16(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(0x1234)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U16(0x0001)
    );
    assert!(buf.field_by_name(layer, "data").is_none());
}

#[test]
fn parse_icmpv6_echo_reply() {
    // RFC 4443, Section 4.2 — Type 129, Code 0
    let rest = {
        let mut r = [0u8; 4];
        r[0..2].copy_from_slice(&0xABCDu16.to_be_bytes());
        r[2..4].copy_from_slice(&0x0005u16.to_be_bytes());
        r
    };
    let data = build_icmpv6_packet(129, 0, rest);
    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(129)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(0xABCD)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U16(5)
    );
}

#[test]
fn parse_icmpv6_echo_request_with_data() {
    let rest = [0x00, 0x01, 0x00, 0x01]; // id=1, seq=1
    let mut data = build_icmpv6_packet(128, 0, rest);
    data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // payload

    let mut buf = DissectBuffer::new();
    let result = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, 12);

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "data").unwrap().value,
        FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
    );
    assert_eq!(buf.field_by_name(layer, "data").unwrap().range, 8..12);
}

#[test]
fn parse_icmpv6_destination_unreachable() {
    // RFC 4443, Section 3.1 — Type 1, Code 4 (Port Unreachable)
    let data = build_icmpv6_packet(1, 4, [0x00, 0x00, 0x00, 0x00]);
    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(4)
    );
    // No MTU or pointer field for Destination Unreachable
    assert!(buf.field_by_name(layer, "mtu").is_none());
    assert!(buf.field_by_name(layer, "pointer").is_none());
}

#[test]
fn parse_icmpv6_packet_too_big() {
    // RFC 4443, Section 3.2 — Type 2, Code 0
    let mtu: u32 = 1280;
    let data = build_icmpv6_packet(2, 0, mtu.to_be_bytes());
    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(layer, "mtu").unwrap().value,
        FieldValue::U32(1280)
    );
    assert_eq!(buf.field_by_name(layer, "mtu").unwrap().range, 4..8);
}

#[test]
fn parse_icmpv6_time_exceeded() {
    // RFC 4443, Section 3.3 — Type 3, Code 0 (Hop limit exceeded)
    let data = build_icmpv6_packet(3, 0, [0x00, 0x00, 0x00, 0x00]);
    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(3)
    );
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(0)
    );
    // No type-specific fields for Time Exceeded
    assert!(buf.field_by_name(layer, "mtu").is_none());
    assert!(buf.field_by_name(layer, "pointer").is_none());
}

#[test]
fn parse_icmpv6_parameter_problem() {
    // RFC 4443, Section 3.4 — Type 4, Code 1 (Unrecognized Next Header)
    let pointer: u32 = 40; // Offset to the erroneous field
    let data = build_icmpv6_packet(4, 1, pointer.to_be_bytes());
    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(4)
    );
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "pointer").unwrap().value,
        FieldValue::U32(40)
    );
    assert_eq!(buf.field_by_name(layer, "pointer").unwrap().range, 4..8);
}

#[test]
fn parse_icmpv6_truncated() {
    let data = [0u8; 4]; // Only 4 bytes, need 8
    let mut buf = DissectBuffer::new();
    let err = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 8,
            actual: 4
        }
    ));
}

#[test]
fn parse_icmpv6_with_offset() {
    let data = build_icmpv6_packet(128, 0, [0x00, 0x01, 0x00, 0x02]);
    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 54).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(layer.range, 54..62);
    assert_eq!(buf.field_by_name(layer, "type").unwrap().range, 54..55);
    assert_eq!(buf.field_by_name(layer, "code").unwrap().range, 55..56);
    assert_eq!(buf.field_by_name(layer, "checksum").unwrap().range, 56..58);
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().range,
        58..60
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().range,
        60..62
    );
}

#[test]
fn icmpv6_dissector_metadata() {
    let d = Icmpv6Dissector;
    assert_eq!(d.name(), "Internet Control Message Protocol v6");
    assert_eq!(d.short_name(), "ICMPv6");
}

#[test]
fn parse_icmpv6_unknown_type() {
    // An unrecognized type should still parse the common header without error
    let data = build_icmpv6_packet(200, 0, [0x00, 0x00, 0x00, 0x00]);
    let mut buf = DissectBuffer::new();
    let result = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 8);
    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(200)
    );
    // Only 3 common header fields, no type-specific fields
    assert_eq!(buf.layer_fields(layer).len(), 3);
}

// ---------------------------------------------------------------------------
// Helper: Build NDP option with proper 8-byte alignment
// ---------------------------------------------------------------------------

/// Build an NDP option. `opt_type` is the option type, `data` is the option
/// value (without type/length header). Pads to 8-byte boundary.
fn build_ndp_option(opt_type: u8, data: &[u8]) -> Vec<u8> {
    let total = 2 + data.len(); // type + length + data
    let padded = total.div_ceil(8) * 8; // round up to 8-byte boundary
    let length_units = (padded / 8) as u8;
    let mut opt = vec![0u8; padded];
    opt[0] = opt_type;
    opt[1] = length_units;
    opt[2..2 + data.len()].copy_from_slice(data);
    opt
}

// ---------------------------------------------------------------------------
// RFC 4861 — Neighbor Discovery Protocol
// ---------------------------------------------------------------------------

#[test]
fn parse_icmpv6_router_solicitation() {
    // RFC 4861, Section 4.1 — Type 133, Code 0
    // 8 bytes: type(1) + code(1) + checksum(2) + reserved(4)
    let data = build_icmpv6_packet(133, 0, [0x00, 0x00, 0x00, 0x00]);
    let mut buf = DissectBuffer::new();
    let result = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 8);
    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(133)
    );
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(0)
    );
    assert!(buf.field_by_name(layer, "options").is_none()); // no options
}

#[test]
fn parse_icmpv6_router_solicitation_with_options() {
    // RS with Source Link-Layer Address option
    let mut data = build_icmpv6_packet(133, 0, [0x00, 0x00, 0x00, 0x00]);
    // NDP Option Type 1 (Source Link-Layer Address): 6 bytes MAC
    let opt = build_ndp_option(1, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    data.extend_from_slice(&opt);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options_all = buf.nested_fields(options_range);
    let options: Vec<_> = options_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(options.len(), 1);

    let FieldValue::Object(ref opt_obj_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt_obj = buf.nested_fields(opt_obj_range);
    let opt_type_field = opt_obj.iter().find(|f| f.name() == "type").unwrap();
    assert_eq!(opt_type_field.value, FieldValue::U8(1));
    let addr_field = opt_obj
        .iter()
        .find(|f| f.name() == "link_layer_address")
        .unwrap();
    assert_eq!(
        addr_field.value,
        FieldValue::Bytes(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
}

#[test]
fn parse_icmpv6_router_advertisement() {
    // RFC 4861, Section 4.2 — Type 134, Code 0
    // 16 bytes: type(1) + code(1) + checksum(2) + cur_hop_limit(1) + flags(1) +
    //           router_lifetime(2) + reachable_time(4) + retrans_timer(4)
    let mut data = vec![0u8; 16];
    data[0] = 134; // type
    data[1] = 0; // code
    // checksum = 0
    data[4] = 64; // cur_hop_limit
    data[5] = 0xC0; // flags: M=1, O=1
    data[6..8].copy_from_slice(&1800u16.to_be_bytes()); // router_lifetime
    data[8..12].copy_from_slice(&30000u32.to_be_bytes()); // reachable_time
    data[12..16].copy_from_slice(&1000u32.to_be_bytes()); // retrans_timer

    let mut buf = DissectBuffer::new();
    let result = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 16);
    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(134)
    );
    assert_eq!(
        buf.field_by_name(layer, "cur_hop_limit").unwrap().value,
        FieldValue::U8(64)
    );
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0xC0)
    );
    assert_eq!(
        buf.field_by_name(layer, "router_lifetime").unwrap().value,
        FieldValue::U16(1800)
    );
    assert_eq!(
        buf.field_by_name(layer, "reachable_time").unwrap().value,
        FieldValue::U32(30000)
    );
    assert_eq!(
        buf.field_by_name(layer, "retrans_timer").unwrap().value,
        FieldValue::U32(1000)
    );
}

#[test]
fn parse_icmpv6_router_advertisement_with_prefix_info() {
    // RA with Prefix Information option (NDP Option Type 3, length=4 → 32 bytes)
    let mut data = vec![0u8; 16];
    data[0] = 134;
    data[1] = 0;
    data[4] = 64;
    data[5] = 0x80; // M flag
    data[6..8].copy_from_slice(&1800u16.to_be_bytes());

    // Prefix Information option: type=3, length=4 (32 bytes)
    let mut prefix_opt = vec![0u8; 32];
    prefix_opt[0] = 3; // type
    prefix_opt[1] = 4; // length (4 * 8 = 32 bytes)
    prefix_opt[2] = 64; // prefix_length
    prefix_opt[3] = 0xC0; // flags: L=1, A=1
    prefix_opt[4..8].copy_from_slice(&2592000u32.to_be_bytes()); // valid_lifetime
    prefix_opt[8..12].copy_from_slice(&604800u32.to_be_bytes()); // preferred_lifetime
    // bytes 12-15: reserved
    // bytes 16-31: prefix (2001:db8::)
    prefix_opt[16] = 0x20;
    prefix_opt[17] = 0x01;
    prefix_opt[18] = 0x0d;
    prefix_opt[19] = 0xb8;

    data.extend_from_slice(&prefix_opt);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options_all = buf.nested_fields(options_range);
    let options: Vec<_> = options_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(options.len(), 1);

    let FieldValue::Object(ref opt_obj_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt_obj = buf.nested_fields(opt_obj_range);
    let opt_type = opt_obj.iter().find(|f| f.name() == "type").unwrap();
    assert_eq!(opt_type.value, FieldValue::U8(3));
    let prefix_len = opt_obj
        .iter()
        .find(|f| f.name() == "prefix_length")
        .unwrap();
    assert_eq!(prefix_len.value, FieldValue::U8(64));
    let flags = opt_obj.iter().find(|f| f.name() == "flags").unwrap();
    assert_eq!(flags.value, FieldValue::U8(0xC0));
    let valid = opt_obj
        .iter()
        .find(|f| f.name() == "valid_lifetime")
        .unwrap();
    assert_eq!(valid.value, FieldValue::U32(2592000));
    let preferred = opt_obj
        .iter()
        .find(|f| f.name() == "preferred_lifetime")
        .unwrap();
    assert_eq!(preferred.value, FieldValue::U32(604800));
    let prefix = opt_obj.iter().find(|f| f.name() == "prefix").unwrap();
    let mut expected_prefix = [0u8; 16];
    expected_prefix[0] = 0x20;
    expected_prefix[1] = 0x01;
    expected_prefix[2] = 0x0d;
    expected_prefix[3] = 0xb8;
    assert_eq!(prefix.value, FieldValue::Ipv6Addr(expected_prefix));
}

#[test]
fn parse_icmpv6_router_advertisement_truncated() {
    // RA requires 16 bytes, provide only 12
    let data = vec![134, 0, 0, 0, 64, 0x80, 0x07, 0x08, 0, 0, 0, 0];
    let mut buf = DissectBuffer::new();
    let err = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated { .. }
    ));
}

#[test]
fn parse_icmpv6_ndp_option_source_link_layer() {
    // RS with Source Link-Layer Address option (Type 1)
    let mut data = build_icmpv6_packet(133, 0, [0x00; 4]);
    let opt = build_ndp_option(1, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    data.extend_from_slice(&opt);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = buf.nested_fields(options_range);
    let FieldValue::Object(ref opt_obj_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt_obj = buf.nested_fields(opt_obj_range);
    let addr = opt_obj
        .iter()
        .find(|f| f.name() == "link_layer_address")
        .unwrap();
    assert_eq!(
        addr.value,
        FieldValue::Bytes(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    );
}

#[test]
fn parse_icmpv6_ndp_option_prefix_info() {
    // RA with Prefix Information option (Type 3, length=4)
    let mut data = vec![0u8; 16];
    data[0] = 134;
    data[4] = 64;

    let mut prefix_opt = vec![0u8; 32];
    prefix_opt[0] = 3;
    prefix_opt[1] = 4; // 4 * 8 = 32 bytes
    prefix_opt[2] = 48; // prefix_length
    prefix_opt[3] = 0x80; // L flag
    prefix_opt[4..8].copy_from_slice(&3600u32.to_be_bytes());
    prefix_opt[8..12].copy_from_slice(&1800u32.to_be_bytes());
    // prefix: fe80::
    prefix_opt[16] = 0xfe;
    prefix_opt[17] = 0x80;
    data.extend_from_slice(&prefix_opt);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = buf.nested_fields(options_range);
    let FieldValue::Object(ref opt_obj_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt_obj = buf.nested_fields(opt_obj_range);
    assert_eq!(
        opt_obj
            .iter()
            .find(|f| f.name() == "prefix_length")
            .unwrap()
            .value,
        FieldValue::U8(48)
    );
    assert_eq!(
        opt_obj
            .iter()
            .find(|f| f.name() == "valid_lifetime")
            .unwrap()
            .value,
        FieldValue::U32(3600)
    );
}

#[test]
fn parse_icmpv6_ndp_option_mtu() {
    // RA with MTU option (Type 5, length=1 → 8 bytes)
    let mut data = vec![0u8; 16];
    data[0] = 134;
    data[4] = 64;

    // MTU option: type=5, length=1 (8 bytes), reserved(2), mtu(4)
    let mut mtu_opt = vec![0u8; 8];
    mtu_opt[0] = 5; // type
    mtu_opt[1] = 1; // length = 1 * 8 = 8 bytes
    // bytes 2-3: reserved
    mtu_opt[4..8].copy_from_slice(&1500u32.to_be_bytes()); // mtu
    data.extend_from_slice(&mtu_opt);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = buf.nested_fields(options_range);
    let FieldValue::Object(ref opt_obj_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt_obj = buf.nested_fields(opt_obj_range);
    assert_eq!(
        opt_obj.iter().find(|f| f.name() == "type").unwrap().value,
        FieldValue::U8(5)
    );
    assert_eq!(
        opt_obj.iter().find(|f| f.name() == "mtu").unwrap().value,
        FieldValue::U32(1500)
    );
}

#[test]
fn parse_icmpv6_ndp_option_unknown() {
    // RS with unknown NDP option (type=99)
    let mut data = build_icmpv6_packet(133, 0, [0x00; 4]);
    let opt = build_ndp_option(99, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    data.extend_from_slice(&opt);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = buf.nested_fields(options_range);
    let FieldValue::Object(ref opt_obj_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt_obj = buf.nested_fields(opt_obj_range);
    assert_eq!(
        opt_obj.iter().find(|f| f.name() == "type").unwrap().value,
        FieldValue::U8(99)
    );
    // Unknown options store value as raw bytes
    assert!(
        opt_obj
            .iter()
            .find(|f| f.name() == "value")
            .unwrap()
            .value
            .as_bytes()
            .is_some()
    );
}

#[test]
fn parse_icmpv6_ndp_option_zero_length() {
    // NDP option with length=0 must be rejected to prevent infinite loop
    let mut data = build_icmpv6_packet(133, 0, [0x00; 4]);
    data.extend_from_slice(&[1, 0]); // type=1, length=0

    let mut buf = DissectBuffer::new();
    let err = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidHeader(_)
    ));
}

// ---------------------------------------------------------------------------
// RFC 4861 — Neighbor Solicitation / Neighbor Advertisement / Redirect
// ---------------------------------------------------------------------------

#[test]
fn parse_icmpv6_neighbor_solicitation() {
    // RFC 4861, Section 4.3 — Type 135, Code 0
    // 24 bytes: type(1) + code(1) + checksum(2) + reserved(4) + target_address(16)
    let mut data = vec![0u8; 24];
    data[0] = 135;
    // target_address = fe80::1
    data[8] = 0xfe;
    data[9] = 0x80;
    data[23] = 0x01;

    let mut buf = DissectBuffer::new();
    let result = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, 24);

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(135)
    );
    let mut expected_target = [0u8; 16];
    expected_target[0] = 0xfe;
    expected_target[1] = 0x80;
    expected_target[15] = 0x01;
    assert_eq!(
        buf.field_by_name(layer, "target_address").unwrap().value,
        FieldValue::Ipv6Addr(expected_target)
    );
    assert_eq!(
        buf.field_by_name(layer, "target_address").unwrap().range,
        8..24
    );
}

#[test]
fn parse_icmpv6_neighbor_solicitation_with_options() {
    // NS with Target Link-Layer Address option (NDP Option Type 2)
    let mut data = vec![0u8; 24];
    data[0] = 135;
    data[8] = 0xfe;
    data[9] = 0x80;
    data[23] = 0x01;

    let opt = build_ndp_option(2, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    data.extend_from_slice(&opt);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options_all = buf.nested_fields(options_range);
    let options: Vec<_> = options_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(options.len(), 1);

    let FieldValue::Object(ref opt_obj_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt_obj = buf.nested_fields(opt_obj_range);
    assert_eq!(
        opt_obj.iter().find(|f| f.name() == "type").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        opt_obj
            .iter()
            .find(|f| f.name() == "link_layer_address")
            .unwrap()
            .value,
        FieldValue::Bytes(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    );
}

#[test]
fn parse_icmpv6_neighbor_solicitation_truncated() {
    // NS requires 24 bytes, provide only 16
    let data = vec![135, 0, 0, 0, 0, 0, 0, 0, 0xfe, 0x80, 0, 0, 0, 0, 0, 0];
    let mut buf = DissectBuffer::new();
    let err = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 24,
            actual: 16
        }
    ));
}

#[test]
fn parse_icmpv6_neighbor_advertisement() {
    // RFC 4861, Section 4.4 — Type 136, Code 0
    // 24 bytes: type(1) + code(1) + checksum(2) + flags(1) + reserved(3) + target_address(16)
    let mut data = vec![0u8; 24];
    data[0] = 136;
    data[4] = 0xE0; // R=1, S=1, O=1
    // target_address = 2001:db8::1
    data[8] = 0x20;
    data[9] = 0x01;
    data[10] = 0x0d;
    data[11] = 0xb8;
    data[23] = 0x01;

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(136)
    );
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0xE0)
    );
    assert_eq!(buf.field_by_name(layer, "flags").unwrap().range, 4..5);

    let mut expected_target = [0u8; 16];
    expected_target[0] = 0x20;
    expected_target[1] = 0x01;
    expected_target[2] = 0x0d;
    expected_target[3] = 0xb8;
    expected_target[15] = 0x01;
    assert_eq!(
        buf.field_by_name(layer, "target_address").unwrap().value,
        FieldValue::Ipv6Addr(expected_target)
    );
}

#[test]
fn parse_icmpv6_neighbor_advertisement_with_options() {
    // NA with Target Link-Layer Address option
    let mut data = vec![0u8; 24];
    data[0] = 136;
    data[4] = 0x60; // S=1, O=1
    data[8] = 0x20;
    data[9] = 0x01;
    data[10] = 0x0d;
    data[11] = 0xb8;
    data[23] = 0x02;

    let opt = build_ndp_option(2, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    data.extend_from_slice(&opt);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options_all = buf.nested_fields(options_range);
    let options: Vec<_> = options_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(options.len(), 1);
    let FieldValue::Object(ref opt_obj_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt_obj = buf.nested_fields(opt_obj_range);
    assert_eq!(
        opt_obj.iter().find(|f| f.name() == "type").unwrap().value,
        FieldValue::U8(2)
    );
}

#[test]
fn parse_icmpv6_redirect() {
    // RFC 4861, Section 4.5 — Type 137, Code 0
    // 40 bytes: type(1) + code(1) + checksum(2) + reserved(4) +
    //           target_address(16) + destination_address(16)
    let mut data = vec![0u8; 40];
    data[0] = 137;
    // target_address = fe80::1 (at bytes 8-23)
    data[8] = 0xfe;
    data[9] = 0x80;
    data[23] = 0x01;
    // destination_address = 2001:db8::1 (at bytes 24-39)
    data[24] = 0x20;
    data[25] = 0x01;
    data[26] = 0x0d;
    data[27] = 0xb8;
    data[39] = 0x01;

    let mut buf = DissectBuffer::new();
    let result = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, 40);

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(137)
    );

    let mut expected_target = [0u8; 16];
    expected_target[0] = 0xfe;
    expected_target[1] = 0x80;
    expected_target[15] = 0x01;
    assert_eq!(
        buf.field_by_name(layer, "target_address").unwrap().value,
        FieldValue::Ipv6Addr(expected_target)
    );
    assert_eq!(
        buf.field_by_name(layer, "target_address").unwrap().range,
        8..24
    );

    let mut expected_dest = [0u8; 16];
    expected_dest[0] = 0x20;
    expected_dest[1] = 0x01;
    expected_dest[2] = 0x0d;
    expected_dest[3] = 0xb8;
    expected_dest[15] = 0x01;
    assert_eq!(
        buf.field_by_name(layer, "destination_address")
            .unwrap()
            .value,
        FieldValue::Ipv6Addr(expected_dest)
    );
    assert_eq!(
        buf.field_by_name(layer, "destination_address")
            .unwrap()
            .range,
        24..40
    );
}

#[test]
fn parse_icmpv6_redirect_with_options() {
    // Redirect with Redirected Header option (NDP Option Type 4)
    let mut data = vec![0u8; 40];
    data[0] = 137;
    data[8] = 0xfe;
    data[9] = 0x80;
    data[23] = 0x01;
    data[24] = 0x20;
    data[25] = 0x01;

    // Redirected Header option: type=4, data = some payload
    let opt = build_ndp_option(4, &[0x00; 6]); // 6 bytes reserved + data
    data.extend_from_slice(&opt);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options_all = buf.nested_fields(options_range);
    let options: Vec<_> = options_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(options.len(), 1);
    let FieldValue::Object(ref opt_obj_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt_obj = buf.nested_fields(opt_obj_range);
    assert_eq!(
        opt_obj.iter().find(|f| f.name() == "type").unwrap().value,
        FieldValue::U8(4)
    );
    // Redirected Header stores raw value
    assert!(
        opt_obj
            .iter()
            .find(|f| f.name() == "value")
            .unwrap()
            .value
            .as_bytes()
            .is_some()
    );
}

#[test]
fn parse_icmpv6_redirect_truncated() {
    // Redirect requires 40 bytes, provide only 30
    let data = vec![
        137, 0, 0, 0, 0, 0, 0, 0, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x20,
        0x01, 0x0d, 0xb8, 0, 0,
    ];
    let mut buf = DissectBuffer::new();
    let err = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 40,
            actual: 30
        }
    ));
}

// ---------------------------------------------------------------------------
// RFC 2710 / RFC 3810 — Multicast Listener Discovery
// ---------------------------------------------------------------------------

/// Build a 24-byte MLD message (MLDv1 format).
fn build_mld_v1(icmpv6_type: u8, max_response_delay: u16, multicast: [u8; 16]) -> Vec<u8> {
    let mut data = vec![0u8; 24];
    data[0] = icmpv6_type;
    data[1] = 0; // code
    // checksum = 0
    data[4..6].copy_from_slice(&max_response_delay.to_be_bytes());
    // bytes 6-7: reserved
    data[8..24].copy_from_slice(&multicast);
    data
}

#[test]
fn parse_icmpv6_mld_query_v1() {
    // RFC 2710, Section 3.6 — Type 130, MLDv1 (exactly 24 bytes)
    let multicast = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    let data = build_mld_v1(130, 10000, multicast);

    let mut buf = DissectBuffer::new();
    let result = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, 24);

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(130)
    );
    assert_eq!(
        buf.field_by_name(layer, "max_response_delay")
            .unwrap()
            .value,
        FieldValue::U16(10000)
    );
    assert_eq!(
        buf.field_by_name(layer, "multicast_address").unwrap().value,
        FieldValue::Ipv6Addr(multicast)
    );
    // No MLDv2 fields for exactly 24-byte query
    assert!(buf.field_by_name(layer, "s_flag").is_none());
    assert!(buf.field_by_name(layer, "qrv").is_none());
}

#[test]
fn parse_icmpv6_mld_query_v2() {
    // RFC 3810, Section 5.1 — Type 130, MLDv2 (>24 bytes, no sources)
    let multicast = [0u8; 16]; // General Query
    let mut data = build_mld_v1(130, 5000, multicast);
    // MLDv2 additional fields: S(1 bit) + QRV(3 bits), QQIC, num_sources
    data.push(0x0A); // S=1 (bit 3), QRV=2 (bits 0-2)
    data.push(125); // QQIC
    data.extend_from_slice(&0u16.to_be_bytes()); // num_sources = 0

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(130)
    );
    assert_eq!(
        buf.field_by_name(layer, "s_flag").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "qrv").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(layer, "qqic").unwrap().value,
        FieldValue::U8(125)
    );
    assert_eq!(
        buf.field_by_name(layer, "num_sources").unwrap().value,
        FieldValue::U16(0)
    );
}

#[test]
fn parse_icmpv6_mld_query_v2_with_sources() {
    // MLDv2 Query with 2 source addresses
    let multicast = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    let mut data = build_mld_v1(130, 1000, multicast);
    data.push(0x03); // S=0, QRV=3
    data.push(60); // QQIC
    data.extend_from_slice(&2u16.to_be_bytes()); // num_sources = 2
    // Source 1: 2001:db8::1
    let src1 = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    data.extend_from_slice(&src1);
    // Source 2: 2001:db8::2
    let src2 = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];
    data.extend_from_slice(&src2);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "num_sources").unwrap().value,
        FieldValue::U16(2)
    );
    let FieldValue::Array(ref sources_range) = buf.field_by_name(layer, "sources").unwrap().value
    else {
        panic!("expected Array")
    };
    let sources = buf.nested_fields(sources_range);
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].value, FieldValue::Ipv6Addr(src1));
    assert_eq!(sources[1].value, FieldValue::Ipv6Addr(src2));
}

#[test]
fn parse_icmpv6_mld_report_v1() {
    // RFC 2710, Section 3.7 — Type 131
    let multicast = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    let data = build_mld_v1(131, 0, multicast);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(131)
    );
    assert_eq!(
        buf.field_by_name(layer, "multicast_address").unwrap().value,
        FieldValue::Ipv6Addr(multicast)
    );
}

#[test]
fn parse_icmpv6_mld_done() {
    // RFC 2710, Section 3.8 — Type 132
    let multicast = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    let data = build_mld_v1(132, 0, multicast);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(132)
    );
    assert_eq!(
        buf.field_by_name(layer, "multicast_address").unwrap().value,
        FieldValue::Ipv6Addr(multicast)
    );
}

#[test]
fn parse_icmpv6_mld_query_truncated() {
    // MLD requires 24 bytes, provide only 16
    let data = vec![130, 0, 0, 0, 0x27, 0x10, 0, 0, 0xff, 0x02, 0, 0, 0, 0, 0, 0];
    let mut buf = DissectBuffer::new();
    let err = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 24,
            actual: 16
        }
    ));
}

// ---------------------------------------------------------------------------
// RFC 3810 — MLDv2 Report (Type 143)
// ---------------------------------------------------------------------------

#[test]
fn parse_icmpv6_mldv2_report() {
    // RFC 3810, Section 5.2 — Type 143
    // Header: type(1) + code(1) + checksum(2) + reserved(2) + num_records(2)
    // Record: record_type(1) + aux_data_len(1) + num_sources(2) + multicast(16)
    let multicast = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    let mut data = vec![0u8; 8];
    data[0] = 143; // type
    // reserved = 0
    data[6..8].copy_from_slice(&1u16.to_be_bytes()); // num_records = 1

    // Record: MODE_IS_INCLUDE (1), no sources, no aux
    data.push(1); // record_type
    data.push(0); // aux_data_len
    data.extend_from_slice(&0u16.to_be_bytes()); // num_sources = 0
    data.extend_from_slice(&multicast);

    let mut buf = DissectBuffer::new();
    let result = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, data.len());

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(143)
    );
    assert_eq!(
        buf.field_by_name(layer, "num_records").unwrap().value,
        FieldValue::U16(1)
    );

    let FieldValue::Array(ref records_range) = buf.field_by_name(layer, "records").unwrap().value
    else {
        panic!("expected Array")
    };
    let records_all = buf.nested_fields(records_range);
    let records: Vec<_> = records_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(records.len(), 1);
    let FieldValue::Object(ref rec_range) = records[0].value else {
        panic!("expected Object")
    };
    let rec = buf.nested_fields(rec_range);
    assert_eq!(
        rec.iter()
            .find(|f| f.name() == "record_type")
            .unwrap()
            .value,
        FieldValue::U8(1)
    );
    assert_eq!(
        rec.iter()
            .find(|f| f.name() == "multicast_address")
            .unwrap()
            .value,
        FieldValue::Ipv6Addr(multicast)
    );
}

#[test]
fn parse_icmpv6_mldv2_report_multiple_records() {
    let mc1 = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    let mc2 = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

    let mut data = vec![0u8; 8];
    data[0] = 143;
    data[6..8].copy_from_slice(&2u16.to_be_bytes()); // 2 records

    // Record 1
    data.push(1); // MODE_IS_INCLUDE
    data.push(0);
    data.extend_from_slice(&0u16.to_be_bytes());
    data.extend_from_slice(&mc1);

    // Record 2
    data.push(2); // MODE_IS_EXCLUDE
    data.push(0);
    data.extend_from_slice(&0u16.to_be_bytes());
    data.extend_from_slice(&mc2);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref records_range) = buf.field_by_name(layer, "records").unwrap().value
    else {
        panic!("expected Array")
    };
    let records_all = buf.nested_fields(records_range);
    let records: Vec<_> = records_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(records.len(), 2);

    let FieldValue::Object(ref rec1_range) = records[0].value else {
        panic!("expected Object")
    };
    let rec1 = buf.nested_fields(rec1_range);
    assert_eq!(
        rec1.iter()
            .find(|f| f.name() == "record_type")
            .unwrap()
            .value,
        FieldValue::U8(1)
    );
    let FieldValue::Object(ref rec2_range) = records[1].value else {
        panic!("expected Object")
    };
    let rec2 = buf.nested_fields(rec2_range);
    assert_eq!(
        rec2.iter()
            .find(|f| f.name() == "record_type")
            .unwrap()
            .value,
        FieldValue::U8(2)
    );
    assert_eq!(
        rec2.iter()
            .find(|f| f.name() == "multicast_address")
            .unwrap()
            .value,
        FieldValue::Ipv6Addr(mc2)
    );
}

#[test]
fn parse_icmpv6_mldv2_report_with_sources() {
    let multicast = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    let src1 = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];

    let mut data = vec![0u8; 8];
    data[0] = 143;
    data[6..8].copy_from_slice(&1u16.to_be_bytes()); // 1 record

    // Record with 1 source
    data.push(3); // CHANGE_TO_INCLUDE_MODE
    data.push(0); // aux_data_len
    data.extend_from_slice(&1u16.to_be_bytes()); // num_sources = 1
    data.extend_from_slice(&multicast);
    data.extend_from_slice(&src1);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref records_range) = buf.field_by_name(layer, "records").unwrap().value
    else {
        panic!("expected Array")
    };
    let records = buf.nested_fields(records_range);
    let FieldValue::Object(ref rec_range) = records[0].value else {
        panic!("expected Object")
    };
    let rec = buf.nested_fields(rec_range);
    assert_eq!(
        rec.iter()
            .find(|f| f.name() == "num_sources")
            .unwrap()
            .value,
        FieldValue::U16(1)
    );
    let sources_field = rec.iter().find(|f| f.name() == "sources").unwrap();
    let FieldValue::Array(ref sources_range) = sources_field.value else {
        panic!("expected Array")
    };
    let sources = buf.nested_fields(sources_range);
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].value, FieldValue::Ipv6Addr(src1));
}

#[test]
fn parse_icmpv6_mldv2_report_truncated() {
    // MLDv2 Report needs at least 8 bytes + record data
    // Provide header claiming 1 record but no record data
    let mut data = vec![0u8; 8];
    data[0] = 143;
    data[6..8].copy_from_slice(&1u16.to_be_bytes()); // claims 1 record

    let mut buf = DissectBuffer::new();
    let err = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated { .. }
    ));
}

// ---------------------------------------------------------------------------
// RFC 4286 — Multicast Router Discovery
// ---------------------------------------------------------------------------

#[test]
fn parse_icmpv6_multicast_router_advertisement() {
    // Type 151: query_interval(2) + robustness_variable(2)
    let mut rest = [0u8; 4];
    rest[0..2].copy_from_slice(&125u16.to_be_bytes()); // query_interval
    rest[2..4].copy_from_slice(&2u16.to_be_bytes()); // robustness_variable
    let data = build_icmpv6_packet(151, 0, rest);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(151)
    );
    assert_eq!(
        buf.field_by_name(layer, "query_interval").unwrap().value,
        FieldValue::U16(125)
    );
    assert_eq!(
        buf.field_by_name(layer, "robustness_variable")
            .unwrap()
            .value,
        FieldValue::U16(2)
    );
}

#[test]
fn parse_icmpv6_multicast_router_solicitation() {
    // Type 152: reserved only
    let data = build_icmpv6_packet(152, 0, [0x00; 4]);
    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(152)
    );
    // Only common header fields
    assert_eq!(buf.layer_fields(layer).len(), 3);
}

#[test]
fn parse_icmpv6_multicast_router_termination() {
    // Type 153: reserved only
    let data = build_icmpv6_packet(153, 0, [0x00; 4]);
    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(153)
    );
    assert_eq!(buf.layer_fields(layer).len(), 3);
}

// ---------------------------------------------------------------------------
// RFC 6275 — Mobile IPv6 (Home Agent Discovery)
// ---------------------------------------------------------------------------

#[test]
fn parse_icmpv6_home_agent_request() {
    // Type 144: identifier(2) + reserved(2)
    let mut rest = [0u8; 4];
    rest[0..2].copy_from_slice(&0xABCDu16.to_be_bytes());
    let data = build_icmpv6_packet(144, 0, rest);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(144)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(0xABCD)
    );
}

#[test]
fn parse_icmpv6_home_agent_reply() {
    // Type 145: identifier(2) + reserved(2) + addresses
    let mut rest = [0u8; 4];
    rest[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
    let mut data = build_icmpv6_packet(145, 0, rest);
    let addr = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    data.extend_from_slice(&addr);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(145)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(0x1234)
    );
    let FieldValue::Array(ref addrs_range) = buf
        .field_by_name(layer, "home_agent_addresses")
        .unwrap()
        .value
    else {
        panic!("expected Array")
    };
    let addrs = buf.nested_fields(addrs_range);
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].value, FieldValue::Ipv6Addr(addr));
}

#[test]
fn parse_icmpv6_home_agent_reply_multiple_addresses() {
    let mut rest = [0u8; 4];
    rest[0..2].copy_from_slice(&0x5678u16.to_be_bytes());
    let mut data = build_icmpv6_packet(145, 0, rest);
    let addr1 = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let addr2 = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];
    data.extend_from_slice(&addr1);
    data.extend_from_slice(&addr2);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref addrs_range) = buf
        .field_by_name(layer, "home_agent_addresses")
        .unwrap()
        .value
    else {
        panic!("expected Array")
    };
    let addrs = buf.nested_fields(addrs_range);
    assert_eq!(addrs.len(), 2);
    assert_eq!(addrs[0].value, FieldValue::Ipv6Addr(addr1));
    assert_eq!(addrs[1].value, FieldValue::Ipv6Addr(addr2));
}

// ---------------------------------------------------------------------------
// RFC 4191 — Route Information Option (NDP Option Type 24)
// ---------------------------------------------------------------------------

#[test]
fn parse_icmpv6_ndp_option_route_info() {
    // RFC 4191, Section 2.3 — Route Information Option (Type 24)
    // Length=3 (24 bytes): prefix_length(1) + flags(1) + route_lifetime(4) + prefix(16)
    let mut data = vec![0u8; 16]; // RA header
    data[0] = 134; // type
    // Route Information option: type=24, length=3 (24 bytes)
    let prefix = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    data.push(24); // type
    data.push(3); // length (3 * 8 = 24 bytes)
    data.push(64); // prefix_length = /64
    data.push(0x08); // flags: Prf = 00 (medium), bits 4-3 = 01 → 0x08
    data.extend_from_slice(&0x0000_0E10u32.to_be_bytes()); // route_lifetime = 3600
    data.extend_from_slice(&prefix); // 16-byte prefix

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options_all = buf.nested_fields(options_range);
    let options: Vec<_> = options_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(options.len(), 1);

    let FieldValue::Object(ref opt_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt = buf.nested_fields(opt_range);
    let get = |name: &str| opt.iter().find(|f| f.name() == name).unwrap();

    assert_eq!(get("type").value, FieldValue::U8(24));
    assert_eq!(get("length").value, FieldValue::U8(3));
    assert_eq!(get("prefix_length").value, FieldValue::U8(64));
    assert_eq!(get("flags").value, FieldValue::U8(0x08));
    assert_eq!(get("route_lifetime").value, FieldValue::U32(3600));
    assert_eq!(get("prefix").value, FieldValue::Ipv6Addr(prefix));
}

#[test]
fn parse_icmpv6_ndp_option_route_info_short_prefix() {
    // RFC 4191, Section 2.3 — Route Information with length=2 (16 bytes)
    // When prefix_length <= 64, length can be 2 (prefix is 8 bytes, zero-padded to 16)
    let mut data = vec![0u8; 16]; // RA header
    data[0] = 134; // type
    // Route Information option: type=24, length=2 (16 bytes)
    data.push(24); // type
    data.push(2); // length (2 * 8 = 16 bytes)
    data.push(48); // prefix_length = /48
    data.push(0x18); // flags: Prf = 11 (low)
    data.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // route_lifetime = infinity
    // Only 8 bytes of prefix (rest zero-padded internally)
    data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00]);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options_all = buf.nested_fields(options_range);
    let options: Vec<_> = options_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(options.len(), 1);

    let FieldValue::Object(ref opt_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt = buf.nested_fields(opt_range);
    let get = |name: &str| opt.iter().find(|f| f.name() == name).unwrap();

    assert_eq!(get("type").value, FieldValue::U8(24));
    assert_eq!(get("prefix_length").value, FieldValue::U8(48));
    assert_eq!(get("flags").value, FieldValue::U8(0x18));
    assert_eq!(get("route_lifetime").value, FieldValue::U32(0xFFFF_FFFF));
    // Prefix should be zero-padded to 16 bytes
    let expected_prefix = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(get("prefix").value, FieldValue::Ipv6Addr(expected_prefix));
}

// ---------------------------------------------------------------------------
// RFC 8106 — RDNSS (NDP Option Type 25) + DNSSL (NDP Option Type 31)
// ---------------------------------------------------------------------------

#[test]
fn parse_icmpv6_ndp_option_rdnss() {
    // RFC 8106, Section 5.1 — RDNSS Option (Type 25)
    // Length=3 (24 bytes): reserved(2) + lifetime(4) + 1 address(16)
    let mut data = vec![0u8; 16]; // RA header
    data[0] = 134;
    data.push(25); // type
    data.push(3); // length (3 * 8 = 24)
    data.extend_from_slice(&[0x00, 0x00]); // reserved
    data.extend_from_slice(&0x0000_0E10u32.to_be_bytes()); // lifetime = 3600
    let dns_addr = [
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88,
        0x88,
    ];
    data.extend_from_slice(&dns_addr);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options_all = buf.nested_fields(options_range);
    let options: Vec<_> = options_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(options.len(), 1);

    let FieldValue::Object(ref opt_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt = buf.nested_fields(opt_range);
    let get = |name: &str| opt.iter().find(|f| f.name() == name).unwrap();

    assert_eq!(get("type").value, FieldValue::U8(25));
    assert_eq!(get("lifetime").value, FieldValue::U32(3600));
    let FieldValue::Array(ref addrs_range) = get("addresses").value else {
        panic!("expected Array")
    };
    let addrs = buf.nested_fields(addrs_range);
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].value, FieldValue::Ipv6Addr(dns_addr));
}

#[test]
fn parse_icmpv6_ndp_option_rdnss_multiple() {
    // RFC 8106, Section 5.1 — RDNSS with 2 addresses, length=5 (40 bytes)
    let mut data = vec![0u8; 16]; // RA header
    data[0] = 134;
    data.push(25); // type
    data.push(5); // length (5 * 8 = 40)
    data.extend_from_slice(&[0x00, 0x00]); // reserved
    data.extend_from_slice(&0x0000_1C20u32.to_be_bytes()); // lifetime = 7200
    let addr1 = [
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88,
        0x88,
    ];
    let addr2 = [
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84,
        0x44,
    ];
    data.extend_from_slice(&addr1);
    data.extend_from_slice(&addr2);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = buf.nested_fields(options_range);
    let FieldValue::Object(ref opt_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt = buf.nested_fields(opt_range);
    let get = |name: &str| opt.iter().find(|f| f.name() == name).unwrap();

    assert_eq!(get("lifetime").value, FieldValue::U32(7200));
    let FieldValue::Array(ref addrs_range) = get("addresses").value else {
        panic!("expected Array")
    };
    let addrs = buf.nested_fields(addrs_range);
    assert_eq!(addrs.len(), 2);
    assert_eq!(addrs[0].value, FieldValue::Ipv6Addr(addr1));
    assert_eq!(addrs[1].value, FieldValue::Ipv6Addr(addr2));
}

#[test]
fn parse_icmpv6_ndp_option_dnssl() {
    // RFC 8106, Section 5.2 — DNSSL Option (Type 31)
    // Domain: "example.com" encoded as [7]example[3]com[0] = 13 bytes
    // Total value: reserved(2) + lifetime(4) + domain(13) = 19 bytes
    // Option total: type(1) + length(1) + 19 = 21 → padded to 24 (length=3)
    let mut data = vec![0u8; 16]; // RA header
    data[0] = 134;
    data.push(31); // type
    data.push(3); // length (3 * 8 = 24)
    data.extend_from_slice(&[0x00, 0x00]); // reserved
    data.extend_from_slice(&0x0000_0E10u32.to_be_bytes()); // lifetime = 3600
    // "example.com" in DNS label format
    data.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
    data.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
    // Padding to reach 24 bytes total (24 - 2 - 6 - 13 = 3 bytes padding)
    data.extend_from_slice(&[0, 0, 0]);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = buf.nested_fields(options_range);
    let FieldValue::Object(ref opt_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt = buf.nested_fields(opt_range);
    let get = |name: &str| opt.iter().find(|f| f.name() == name).unwrap();

    assert_eq!(get("type").value, FieldValue::U8(31));
    assert_eq!(get("lifetime").value, FieldValue::U32(3600));
    let FieldValue::Array(ref domains_range) = get("domain_names").value else {
        panic!("expected Array")
    };
    let domains = buf.nested_fields(domains_range);
    assert_eq!(domains.len(), 1);
    // DNS label format: [7]example[3]com[0]
    assert_eq!(
        domains[0].value,
        FieldValue::Bytes(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
        ])
    );
}

#[test]
fn parse_icmpv6_ndp_option_dnssl_multiple() {
    // RFC 8106, Section 5.2 — DNSSL with 2 domains
    // "example.com" = 13 bytes, "test.org" = 10 bytes → 23 bytes
    // Total value: reserved(2) + lifetime(4) + domains(23) = 29 bytes
    // Option total: type(1) + length(1) + 29 = 31 → padded to 32 (length=4)
    let mut data = vec![0u8; 16]; // RA header
    data[0] = 134;
    data.push(31); // type
    data.push(4); // length (4 * 8 = 32)
    data.extend_from_slice(&[0x00, 0x00]); // reserved
    data.extend_from_slice(&0x0000_0E10u32.to_be_bytes()); // lifetime = 3600
    // "example.com"
    data.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
    data.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
    // "test.org"
    data.extend_from_slice(&[4, b't', b'e', b's', b't']);
    data.extend_from_slice(&[3, b'o', b'r', b'g', 0]);
    // Padding to reach 32 bytes total (32 - 2 - 6 - 23 = 1 byte)
    data.push(0);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = buf.nested_fields(options_range);
    let FieldValue::Object(ref opt_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt = buf.nested_fields(opt_range);
    let get = |name: &str| opt.iter().find(|f| f.name() == name).unwrap();

    let FieldValue::Array(ref domains_range) = get("domain_names").value else {
        panic!("expected Array")
    };
    let domains = buf.nested_fields(domains_range);
    assert_eq!(domains.len(), 2);
    // DNS label format
    assert_eq!(
        domains[0].value,
        FieldValue::Bytes(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
        ])
    );
    assert_eq!(
        domains[1].value,
        FieldValue::Bytes(&[4, b't', b'e', b's', b't', 3, b'o', b'r', b'g', 0])
    );
}

// ---------------------------------------------------------------------------
// RFC 8781 — PREF64 (NDP Option Type 38)
// ---------------------------------------------------------------------------

#[test]
fn parse_icmpv6_ndp_option_pref64() {
    // RFC 8781, Section 4 — PREF64 Option (Type 38)
    // Length=2 (16 bytes): scaled_lifetime+plc(2) + prefix(12)
    // Scaled Lifetime = 600/8 = 75, PLC = 1 (/64)
    // 16-bit field: (75 << 3) | 1 = 601 = 0x0259
    let mut data = vec![0u8; 16]; // RA header
    data[0] = 134;
    data.push(38); // type
    data.push(2); // length (2 * 8 = 16)
    data.extend_from_slice(&0x0259u16.to_be_bytes()); // scaled_lifetime=75, plc=1
    // 96 bits (12 bytes) of prefix: 64:ff9b::
    data.extend_from_slice(&[
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options_all = buf.nested_fields(options_range);
    let options: Vec<_> = options_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(options.len(), 1);

    let FieldValue::Object(ref opt_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt = buf.nested_fields(opt_range);
    let get = |name: &str| opt.iter().find(|f| f.name() == name).unwrap();

    assert_eq!(get("type").value, FieldValue::U8(38));
    assert_eq!(get("scaled_lifetime").value, FieldValue::U16(75));
    assert_eq!(get("plc").value, FieldValue::U8(1));
    assert_eq!(get("prefix_length").value, FieldValue::U8(64));
    // Prefix zero-padded to 16 bytes
    let expected_prefix = [
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    assert_eq!(get("prefix").value, FieldValue::Ipv6Addr(expected_prefix));
}

#[test]
fn parse_icmpv6_ndp_option_pref64_96() {
    // RFC 8781, Section 4 — PREF64 with /96 prefix (PLC=0)
    // Scaled Lifetime = 300/8 = 37, PLC = 0
    // 16-bit field: (37 << 3) | 0 = 296 = 0x0128
    let mut data = vec![0u8; 16]; // RA header
    data[0] = 134;
    data.push(38); // type
    data.push(2); // length
    data.extend_from_slice(&0x0128u16.to_be_bytes()); // scaled_lifetime=37, plc=0
    // 96 bits of prefix: 64:ff9b::
    data.extend_from_slice(&[
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = buf.nested_fields(options_range);
    let FieldValue::Object(ref opt_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt = buf.nested_fields(opt_range);
    let get = |name: &str| opt.iter().find(|f| f.name() == name).unwrap();

    assert_eq!(get("scaled_lifetime").value, FieldValue::U16(37));
    assert_eq!(get("plc").value, FieldValue::U8(0));
    assert_eq!(get("prefix_length").value, FieldValue::U8(96));
}

// ---------------------------------------------------------------------------
// RFC 8335 — Extended Echo Request/Reply (Types 160/161)
// ---------------------------------------------------------------------------

#[test]
fn parse_icmpv6_extended_echo_request() {
    // RFC 8335, Section 2.1 — Extended Echo Request (Type 160)
    // Bytes 4-5: identifier, byte 6: sequence, byte 7: reserved+L
    let rest = {
        let mut r = [0u8; 4];
        r[0..2].copy_from_slice(&0x1234u16.to_be_bytes()); // identifier
        r[2] = 0x05; // sequence number
        r[3] = 0x01; // L bit set
        r
    };
    let data = build_icmpv6_packet(160, 0, rest);
    let mut buf = DissectBuffer::new();
    let result = Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 8);
    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(160)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(0x1234)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U8(0x05)
    );
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0x01)
    );
}

#[test]
fn parse_icmpv6_extended_echo_reply() {
    // RFC 8335, Section 2.2 — Extended Echo Reply (Type 161)
    let rest = {
        let mut r = [0u8; 4];
        r[0..2].copy_from_slice(&0x1234u16.to_be_bytes()); // identifier
        r[2] = 0x05; // sequence number
        r[3] = 0xA1; // state=5(bits7-5=101), A=0, 4=0, 6=1
        r
    };
    let data = build_icmpv6_packet(161, 0, rest);
    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(161)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(0x1234)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U8(0x05)
    );
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0xA1)
    );
}

// ---------------------------------------------------------------------------
// RFC 4884 — Extended ICMP Multi-Part Messages (updates RFC 4443)
// ---------------------------------------------------------------------------

#[test]
fn parse_icmpv6_destination_unreachable_rfc4884_length() {
    // RFC 4884, Section 4 — Length field at byte 4 of Type 1.
    // A non-zero Length value means the 'original datagram' field is
    // zero-padded and its size is Length * 8 bytes.
    let data = build_icmpv6_packet(1, 0, [0x05, 0x00, 0x00, 0x00]); // length=5
    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "length").unwrap().value,
        FieldValue::U8(5)
    );
    assert_eq!(buf.field_by_name(layer, "length").unwrap().range, 4..5);
}

#[test]
fn parse_icmpv6_destination_unreachable_rfc4884_length_zero() {
    // RFC 4884, Section 4 — Length=0 means no extension structure;
    // the field should not be emitted.
    let data = build_icmpv6_packet(1, 0, [0x00, 0x00, 0x00, 0x00]);
    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert!(buf.field_by_name(layer, "length").is_none());
}

#[test]
fn parse_icmpv6_time_exceeded_rfc4884_length() {
    // RFC 4884, Section 4 — Length field at byte 4 of Type 3.
    let data = build_icmpv6_packet(3, 0, [0x03, 0x00, 0x00, 0x00]); // length=3
    let mut buf = DissectBuffer::new();
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(3)
    );
    assert_eq!(
        buf.field_by_name(layer, "length").unwrap().value,
        FieldValue::U8(3)
    );
    assert_eq!(buf.field_by_name(layer, "length").unwrap().range, 4..5);
}

// ---------------------------------------------------------------------------
// Regression: MLDv2 Query with 25–27 bytes must not panic
// ---------------------------------------------------------------------------

#[test]
fn parse_icmpv6_mldv2_query_partial_extension_not_panic() {
    // RFC 3810, Section 5.1 — MLDv2 extension starts at byte 24.
    // Providing 25–27 bytes (beyond the 24-byte MLDv1 base but less than
    // the full 28-byte MLDv2 minimum) must not panic; it should be treated
    // as a plain MLDv1 query (no MLDv2 fields emitted).
    for extra in 1u8..=3 {
        let mut data = vec![
            130, 0, 0, 0, // type, code, checksum
            0x00, 0x64, // max_response_delay = 100
            0x00, 0x00, // reserved
        ];
        data.extend_from_slice(&[0u8; 16]); // multicast address
        // Append `extra` bytes but fewer than the 4 needed for the MLDv2 fields
        data.resize(data.len() + extra as usize, 0xAA);
        assert_eq!(data.len(), 24 + extra as usize);

        let mut buf = DissectBuffer::new();
        Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ICMPv6").unwrap();
        // MLDv2-specific fields must NOT appear — not enough data
        assert!(
            buf.field_by_name(layer, "s_flag").is_none(),
            "extra={extra}: s_flag should not appear"
        );
        assert!(
            buf.field_by_name(layer, "qrv").is_none(),
            "extra={extra}: qrv should not appear"
        );
    }
}

// ---------------------------------------------------------------------------
// Regression: DNSSL option with truncated label must not infinite-loop
// ---------------------------------------------------------------------------

#[test]
fn parse_icmpv6_ndp_option_dnssl_truncated_label() {
    // RFC 8106, Section 5.2 — A label whose claimed length overruns the
    // option buffer must not cause an infinite loop; the parser should
    // stop gracefully and return whatever it already collected (nothing here).
    // Option (16 bytes, length=2): type(1)+length(1)+reserved(2)+lifetime(4)+label_data(8)
    // label_data: first byte = 0xFF (label length 255) — far exceeds remaining 7 bytes.
    let mut data = vec![0u8; 16]; // RA header
    data[0] = 134;
    data.push(31); // DNSSL option type
    data.push(2); // length = 2 (2 * 8 = 16 bytes total for option)
    data.extend_from_slice(&[0x00, 0x00]); // reserved
    data.extend_from_slice(&300u32.to_be_bytes()); // lifetime
    data.push(0xFF); // label length = 255 — truncated (only 7 bytes follow)
    data.extend_from_slice(b"abcdefg"); // 7 bytes

    let mut buf = DissectBuffer::new();
    // Must return Ok (no panic, no infinite loop)
    Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMPv6").unwrap();
    let FieldValue::Array(ref options_range) = buf.field_by_name(layer, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = buf.nested_fields(options_range);
    // The DNSSL option is present but domain_names is absent (nothing could be parsed)
    let FieldValue::Object(ref opt_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt = buf.nested_fields(opt_range);
    let has_domains = opt.iter().any(|f| f.name() == "domain_names");
    assert!(
        !has_domains,
        "no domain should be emitted for a truncated label"
    );
}
