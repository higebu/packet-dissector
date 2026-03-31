//! # ICMP Coverage (RFC 792 + related RFCs)
//!
//! | RFC         | Section  | Description                        | Test                                          |
//! |-------------|----------|------------------------------------|-----------------------------------------------|
//! | RFC 792     | p.14     | Echo Request (Type 8)              | parse_icmp_echo_request                       |
//! | RFC 792     | p.14     | Echo Reply (Type 0)                | parse_icmp_echo_reply                         |
//! | RFC 792     | p.4      | Destination Unreachable (Type 3)   | parse_icmp_destination_unreachable             |
//! | RFC 792     | p.4      | Dest Unreachable + invoking_packet | parse_icmp_destination_unreachable_with_invoking_packet |
//! | RFC 792     | p.5      | Source Quench (Type 4)             | parse_icmp_source_quench                      |
//! | RFC 792     | p.12     | Redirect (Type 5)                  | parse_icmp_redirect                           |
//! | RFC 792     | p.12     | Redirect + invoking_packet         | parse_icmp_redirect_with_invoking_packet       |
//! | RFC 792     | p.8      | Parameter Problem (Type 12)        | parse_icmp_parameter_problem                  |
//! | RFC 792     | p.10     | Time Exceeded (Type 11)            | parse_icmp_time_exceeded                      |
//! | RFC 792     | p.10     | Time Exceeded + invoking_packet    | parse_icmp_time_exceeded_with_invoking_packet  |
//! | RFC 792     | p.16     | Timestamp (Type 13)                | parse_icmp_timestamp_request                  |
//! | RFC 792     | p.16     | Timestamp Reply (Type 14)          | parse_icmp_timestamp_reply                    |
//! | RFC 792     | p.16     | Timestamp truncated                | parse_icmp_timestamp_truncated                |
//! | RFC 792     | p.15     | Information Request (Type 15)      | parse_icmp_information_request                |
//! | RFC 792     | p.15     | Information Reply (Type 16)        | parse_icmp_information_reply                  |
//! | RFC 950     | App.     | Address Mask Request (Type 17)     | parse_icmp_address_mask_request               |
//! | RFC 950     | App.     | Address Mask Reply (Type 18)       | parse_icmp_address_mask_reply                 |
//! | RFC 950     | App.     | Address Mask truncated             | parse_icmp_address_mask_truncated             |
//! | RFC 1191    | §4       | Dest Unreach Code 4 next_hop_mtu   | parse_icmp_dest_unreachable_fragmentation_needed |
//! | RFC 1191    | §5       | Code 4 zero MTU                    | parse_icmp_dest_unreachable_code4_zero_mtu    |
//! | RFC 1256    | §3       | Router Advertisement (Type 9)      | parse_icmp_router_advertisement               |
//! | RFC 1256    | §3       | Router Adv. multiple entries       | parse_icmp_router_advertisement_multiple_entries |
//! | RFC 1256    | §3       | Router Solicitation (Type 10)      | parse_icmp_router_solicitation                |
//! | RFC 2521    | §1       | Photuris Bad SPI (Type 40)         | parse_icmp_photuris_bad_spi                   |
//! | RFC 2521    | §1       | Photuris Need Auth (Type 40)       | parse_icmp_photuris_need_authentication       |
//! | RFC 4065    | §3       | Experimental Mobility (Type 41)    | parse_icmp_experimental_mobility              |
//! | RFC 4884    | §5.1     | Extended length (Type 3)           | parse_icmp_dest_unreachable_with_rfc4884_length |
//! | RFC 4884    | §5.1     | Extended length (Type 11)          | parse_icmp_time_exceeded_with_rfc4884_length  |
//! | RFC 6918    | §3       | Deprecated Type 6                  | parse_icmp_alternate_host_address              |
//! | RFC 6918    | §3       | Deprecated Type 30                 | parse_icmp_deprecated_type30_traceroute        |
//! | RFC 8335    | §2       | Extended Echo Request (Type 42)    | parse_icmp_extended_echo_request              |
//! | RFC 8335    | §2       | Extended Echo Request L=1          | parse_icmp_extended_echo_request_local_bit     |
//! | RFC 8335    | §3       | Extended Echo Reply (Type 43)      | parse_icmp_extended_echo_reply                |
//! | RFC 8335    | §3       | Extended Echo Reply codes          | parse_icmp_extended_echo_reply_malformed_query |
//! | —           | —        | Error msg no invoking_packet       | parse_icmp_error_no_invoking_packet_when_only_header |
//! | —           | —        | Unknown type                       | parse_icmp_unknown_type                       |
//! | —           | —        | Truncated packet                   | parse_icmp_truncated                          |
//! | —           | —        | Offset handling                    | parse_icmp_with_offset                        |
//! | —           | —        | Dissector metadata                 | icmp_dissector_metadata                       |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::dissectors::icmp::IcmpDissector;
use packet_dissector::error::PacketError;
use packet_dissector::field::FieldValue;
use packet_dissector::packet::DissectBuffer;

// --- Echo Request (Type 8, Code 0) ---
// RFC 792, p.14:
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Identifier          |        Sequence Number        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Data ...
//  +-+-+-+-+-

#[test]
fn parse_icmp_echo_request() {
    let data: &[u8] = &[
        0x08, // Type: Echo Request (8)
        0x00, // Code: 0
        0xf7, 0xff, // Checksum
        0x00, 0x01, // Identifier: 1
        0x00, 0x01, // Sequence Number: 1
        0x61, 0x62, 0x63, 0x64, // Data: "abcd"
    ];

    let mut buf = DissectBuffer::new();
    let result = IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 12);
    assert_eq!(result.next, DispatchHint::End);

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(8)
    );
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "checksum").unwrap().value,
        FieldValue::U16(0xf7ff)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "data").unwrap().value,
        FieldValue::Bytes(&[0x61, 0x62, 0x63, 0x64])
    );
}

#[test]
fn parse_icmp_echo_reply() {
    let data: &[u8] = &[
        0x00, // Type: Echo Reply (0)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x12, 0x34, // Identifier: 0x1234
        0x00, 0x05, // Sequence Number: 5
    ];

    let mut buf = DissectBuffer::new();
    let result = IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 8);
    assert_eq!(result.next, DispatchHint::End);

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(0x1234)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U16(5)
    );
    // No data field when there's no payload
    assert!(buf.field_by_name(layer, "data").is_none());
}

// --- Destination Unreachable (Type 3) ---
// RFC 792, p.4:
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                             unused                            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |      Internet Header + 64 bits of Original Data Datagram      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[test]
fn parse_icmp_destination_unreachable() {
    let data: &[u8] = &[
        0x03, // Type: Destination Unreachable (3)
        0x01, // Code: Host Unreachable (1)
        0x00, 0x00, // Checksum
        0x00, 0x00, 0x00, 0x00, // Unused
        // Original datagram snippet (8 bytes)
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
    ];

    let mut buf = DissectBuffer::new();
    let result = IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 16);

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(3)
    );
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(1)
    );
    // Type 3 should not have identifier/sequence_number fields
    assert!(buf.field_by_name(layer, "identifier").is_none());
    assert!(buf.field_by_name(layer, "sequence_number").is_none());
}

// --- Time Exceeded (Type 11) ---
// RFC 792, p.10: Same format as Destination Unreachable (unused 4 bytes + original datagram)

#[test]
fn parse_icmp_time_exceeded() {
    let data: &[u8] = &[
        0x0b, // Type: Time Exceeded (11)
        0x00, // Code: TTL exceeded in transit (0)
        0x00, 0x00, // Checksum
        0x00, 0x00, 0x00, 0x00, // Unused
        // Original datagram snippet
        0x45, 0x00, 0x00, 0x28, 0xab, 0xcd, 0x00, 0x00,
    ];

    let mut buf = DissectBuffer::new();
    let result = IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 16);

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(11)
    );
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(0)
    );
}

// --- Redirect (Type 5) ---
// RFC 792, p.12:
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                 Gateway Internet Address                      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |      Internet Header + 64 bits of Original Data Datagram      |

#[test]
fn parse_icmp_redirect() {
    let data: &[u8] = &[
        0x05, // Type: Redirect (5)
        0x01, // Code: Redirect for Host (1)
        0x00, 0x00, // Checksum
        0xc0, 0xa8, 0x01, 0x01, // Gateway: 192.168.1.1
        // Original datagram snippet
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
    ];

    let mut buf = DissectBuffer::new();
    let result = IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 16);

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(5)
    );
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "gateway").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 1])
    );
}

#[test]
fn parse_icmp_truncated() {
    // Less than 8 bytes (minimum ICMP header)
    let data: &[u8] = &[0x08, 0x00, 0x00];
    let mut buf = DissectBuffer::new();

    let err = IcmpDissector.dissect(data, &mut buf, 0).unwrap_err();
    assert_eq!(
        err,
        PacketError::Truncated {
            expected: 8,
            actual: 3
        }
    );
}

#[test]
fn parse_icmp_with_offset() {
    let data: &[u8] = &[
        0x08, 0x00, 0x00, 0x00, // Type 8, Code 0, Checksum 0
        0x00, 0x01, 0x00, 0x01, // Identifier 1, Sequence 1
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 34).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(layer.range, 34..42);
    assert_eq!(buf.field_by_name(layer, "type").unwrap().range, 34..35);
    assert_eq!(buf.field_by_name(layer, "checksum").unwrap().range, 36..38);
}

// --- Source Quench (Type 4, Code 0) ---
// RFC 792, p.5 / RFC 6633 (deprecated):
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                             unused                            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |      Internet Header + 64 bits of Original Data Datagram      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[test]
fn parse_icmp_source_quench() {
    let data: &[u8] = &[
        0x04, // Type: Source Quench (4)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x00, 0x00, 0x00, 0x00, // Unused
        // Original datagram: IPv4 header (20 bytes) + 8 bytes payload
        0x45, 0x00, 0x00, 0x3c, // Version=4, IHL=5, TotalLen=60
        0x1c, 0x46, 0x40, 0x00, // ID, Flags, FragOff
        0x40, 0x06, 0x00, 0x00, // TTL=64, Protocol=TCP(6), Checksum
        0xc0, 0xa8, 0x01, 0x0a, // Src: 192.168.1.10
        0x0a, 0x00, 0x00, 0x01, // Dst: 10.0.0.1
        0x00, 0x50, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00, // 8 bytes of original payload
    ];

    let mut buf = DissectBuffer::new();
    let result = IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 36);

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(4)
    );
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(0)
    );

    // invoking_packet should be an Object with sub-parsed IP header fields
    let invoking = buf.field_by_name(layer, "invoking_packet").unwrap();
    let FieldValue::Object(ref obj_range) = invoking.value else {
        panic!("expected Object")
    };
    let obj = buf.nested_fields(obj_range);
    assert_eq!(
        obj.iter().find(|f| f.name() == "version").unwrap().value,
        FieldValue::U8(4)
    );
    assert_eq!(
        obj.iter().find(|f| f.name() == "ihl").unwrap().value,
        FieldValue::U8(5)
    );
    assert_eq!(
        obj.iter()
            .find(|f| f.name() == "total_length")
            .unwrap()
            .value,
        FieldValue::U16(60)
    );
    assert_eq!(
        obj.iter().find(|f| f.name() == "protocol").unwrap().value,
        FieldValue::U8(6)
    );
    assert_eq!(
        obj.iter().find(|f| f.name() == "src").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 10])
    );
    assert_eq!(
        obj.iter().find(|f| f.name() == "dst").unwrap().value,
        FieldValue::Ipv4Addr([10, 0, 0, 1])
    );
}

#[test]
fn parse_icmp_destination_unreachable_with_invoking_packet() {
    let data: &[u8] = &[
        0x03, // Type: Destination Unreachable (3)
        0x01, // Code: Host Unreachable (1)
        0x00, 0x00, // Checksum
        0x00, 0x00, 0x00, 0x00, // Unused
        // Original datagram: minimal IPv4 header (20 bytes)
        0x45, 0x00, 0x00, 0x28, // Version=4, IHL=5, TotalLen=40
        0xab, 0xcd, 0x00, 0x00, // ID, Flags, FragOff
        0x40, 0x11, 0x00, 0x00, // TTL=64, Protocol=UDP(17), Checksum
        0x0a, 0x01, 0x02, 0x03, // Src: 10.1.2.3
        0xac, 0x10, 0x00, 0x01, // Dst: 172.16.0.1
        0x00, 0x50, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00, // 8 bytes of original payload
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    let invoking = buf.field_by_name(layer, "invoking_packet").unwrap();
    let FieldValue::Object(ref obj_range) = invoking.value else {
        panic!("expected Object")
    };
    let obj = buf.nested_fields(obj_range);
    assert_eq!(
        obj.iter().find(|f| f.name() == "protocol").unwrap().value,
        FieldValue::U8(17)
    );
    assert_eq!(
        obj.iter().find(|f| f.name() == "src").unwrap().value,
        FieldValue::Ipv4Addr([10, 1, 2, 3])
    );
    assert_eq!(
        obj.iter().find(|f| f.name() == "dst").unwrap().value,
        FieldValue::Ipv4Addr([172, 16, 0, 1])
    );
}

#[test]
fn parse_icmp_time_exceeded_with_invoking_packet() {
    let data: &[u8] = &[
        0x0b, // Type: Time Exceeded (11)
        0x00, // Code: TTL exceeded in transit (0)
        0x00, 0x00, // Checksum
        0x00, 0x00, 0x00, 0x00, // Unused
        // Original datagram: IPv4 header (20 bytes) + 8 bytes
        0x45, 0x00, 0x00, 0x54, // Version=4, IHL=5, TotalLen=84
        0x12, 0x34, 0x40, 0x00, // ID, Flags, FragOff
        0x01, 0x01, 0x00, 0x00, // TTL=1, Protocol=ICMP(1), Checksum
        0xc0, 0xa8, 0x00, 0x01, // Src: 192.168.0.1
        0x08, 0x08, 0x08, 0x08, // Dst: 8.8.8.8
        0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, // 8 bytes of original payload
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    let invoking = buf.field_by_name(layer, "invoking_packet").unwrap();
    let FieldValue::Object(ref obj_range) = invoking.value else {
        panic!("expected Object")
    };
    let obj = buf.nested_fields(obj_range);
    assert_eq!(
        obj.iter().find(|f| f.name() == "src").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 0, 1])
    );
    assert_eq!(
        obj.iter().find(|f| f.name() == "dst").unwrap().value,
        FieldValue::Ipv4Addr([8, 8, 8, 8])
    );
}

#[test]
fn parse_icmp_error_no_invoking_packet_when_only_header() {
    // Error message with no data beyond the 8-byte ICMP header
    let data: &[u8] = &[
        0x03, // Type: Destination Unreachable (3)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x00, 0x00, 0x00, 0x00, // Unused
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    // No invoking_packet when there's no data after header
    assert!(buf.field_by_name(layer, "invoking_packet").is_none());
}

// --- Destination Unreachable Code 4 (Fragmentation Needed) ---
// RFC 1191 — Path MTU Discovery:
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           unused              |         Next-Hop MTU          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[test]
fn parse_icmp_dest_unreachable_fragmentation_needed() {
    let data: &[u8] = &[
        0x03, // Type: Destination Unreachable (3)
        0x04, // Code: Fragmentation Needed (4)
        0x00, 0x00, // Checksum
        0x00, 0x00, // Unused
        0x05, 0xdc, // Next-Hop MTU: 1500
        // Original datagram: IPv4 header (20 bytes)
        0x45, 0x00, 0x05, 0xdc, // Version=4, IHL=5, TotalLen=1500
        0x12, 0x34, 0x40, 0x00, // ID, DF=1, FragOff=0
        0x40, 0x06, 0x00, 0x00, // TTL=64, Protocol=TCP(6), Checksum
        0xc0, 0xa8, 0x01, 0x01, // Src: 192.168.1.1
        0x0a, 0x00, 0x00, 0x01, // Dst: 10.0.0.1
        0x00, 0x50, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00, // 8 bytes payload
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(3)
    );
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(4)
    );
    assert_eq!(
        buf.field_by_name(layer, "next_hop_mtu").unwrap().value,
        FieldValue::U16(1500)
    );

    // invoking_packet should still be present
    assert!(buf.field_by_name(layer, "invoking_packet").is_some());
}

#[test]
fn parse_icmp_dest_unreachable_code4_zero_mtu() {
    let data: &[u8] = &[
        0x03, // Type: Destination Unreachable (3)
        0x04, // Code: Fragmentation Needed (4)
        0x00, 0x00, // Checksum
        0x00, 0x00, // Unused
        0x00, 0x00, // Next-Hop MTU: 0 (older router, RFC 1191 Section 5)
        // Minimal original datagram
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00,
        0x01, 0x0a, 0x00, 0x00, 0x02, 0x00, 0x50, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "next_hop_mtu").unwrap().value,
        FieldValue::U16(0)
    );
}

// --- RFC 4884 Extended ICMP: length field ---
// RFC 4884, Section 5.1: For Type 3, 11, 12 the byte at offset 4
// contains the length of the original datagram in 32-bit words.
// When non-zero, it indicates RFC 4884 compliant format.

#[test]
fn parse_icmp_dest_unreachable_with_rfc4884_length() {
    // RFC 4884, §5 — Type 3 layout:
    //   byte 4: unused
    //   byte 5: Length (original datagram in 32-bit words)
    //   bytes 6-7: Next-Hop MTU (or unused for non-Code-4)
    let data: &[u8] = &[
        0x03, // Type: Destination Unreachable (3)
        0x01, // Code: Host Unreachable (1)
        0x00, 0x00, // Checksum
        0x00, // Unused (byte 4)
        0x07, // Length: 7 (= 28 bytes of original datagram, RFC 4884 byte 5)
        0x00, 0x00, // Unused (for non-Code-4, bytes 6-7)
        // Original datagram: 28 bytes (7 * 4)
        0x45, 0x00, 0x00, 0x28, 0xab, 0xcd, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0a, 0x01, 0x02,
        0x03, 0xac, 0x10, 0x00, 0x01, 0x00, 0x50, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00,
        // Extension structure (follows original datagram)
        0x20, 0x00, 0xab, 0xcd, // Extension header (version=2, checksum)
        0x00, 0x08, 0x01, 0x01, // Object: length=8, class=1, c-type=1
        0x0a, 0x00, 0x00, 0x01, // Object data
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "length").unwrap().value,
        FieldValue::U8(7)
    );
    assert!(buf.field_by_name(layer, "invoking_packet").is_some());
}

#[test]
fn parse_icmp_time_exceeded_with_rfc4884_length() {
    // RFC 4884, §5 — Type 11 layout:
    //   byte 4: unused
    //   byte 5: Length (original datagram in 32-bit words)
    //   bytes 6-7: unused
    let data: &[u8] = &[
        0x0b, // Type: Time Exceeded (11)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x00, // Unused (byte 4)
        0x05, // Length: 5 (= 20 bytes of original datagram, RFC 4884 byte 5)
        0x00, 0x00, // Unused (bytes 6-7)
        // Original datagram: 20 bytes (5 * 4)
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x01, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x00,
        0x01, 0x08, 0x08, 0x08, 0x08,
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "length").unwrap().value,
        FieldValue::U8(5)
    );
}

// --- Parameter Problem (Type 12) ---
// RFC 792, p.8:
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |    Pointer    |                 unused                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |      Internet Header + 64 bits of Original Data Datagram      |

#[test]
fn parse_icmp_parameter_problem() {
    let data: &[u8] = &[
        0x0c, // Type: Parameter Problem (12)
        0x00, // Code: Pointer indicates the error (0)
        0x00, 0x00, // Checksum
        0x05, // Pointer: byte 5 (points to offending octet)
        0x00, 0x00, 0x00, // Unused
        // Original datagram: IPv4 header (20 bytes)
        0x45, 0x00, 0x00, 0x28, // Version=4, IHL=5, TotalLen=40
        0xab, 0xcd, 0x00, 0x00, // ID, Flags, FragOff
        0x40, 0x06, 0x00, 0x00, // TTL=64, Protocol=TCP(6), Checksum
        0xc0, 0xa8, 0x01, 0x01, // Src: 192.168.1.1
        0x0a, 0x00, 0x00, 0x01, // Dst: 10.0.0.1
        0x00, 0x50, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00, // 8 bytes payload
    ];

    let mut buf = DissectBuffer::new();
    let result = IcmpDissector.dissect(data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, 36);

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(12)
    );
    assert_eq!(
        buf.field_by_name(layer, "pointer").unwrap().value,
        FieldValue::U8(5)
    );

    // invoking_packet should be sub-parsed
    let invoking = buf.field_by_name(layer, "invoking_packet").unwrap();
    let FieldValue::Object(ref obj_range) = invoking.value else {
        panic!("expected Object")
    };
    let obj = buf.nested_fields(obj_range);
    assert_eq!(
        obj.iter().find(|f| f.name() == "protocol").unwrap().value,
        FieldValue::U8(6)
    );
}

#[test]
fn parse_icmp_redirect_with_invoking_packet() {
    let data: &[u8] = &[
        0x05, // Type: Redirect (5)
        0x01, // Code: Redirect for Host (1)
        0x00, 0x00, // Checksum
        0xc0, 0xa8, 0x01, 0x01, // Gateway: 192.168.1.1
        // Original datagram: IPv4 header (20 bytes) + 8 bytes
        0x45, 0x00, 0x00, 0x3c, // Version=4, IHL=5, TotalLen=60
        0x1c, 0x46, 0x40, 0x00, // ID, Flags, FragOff
        0x40, 0x06, 0x00, 0x00, // TTL=64, Protocol=TCP(6), Checksum
        0xac, 0x10, 0x00, 0x01, // Src: 172.16.0.1
        0x0a, 0x00, 0x00, 0x02, // Dst: 10.0.0.2
        0x00, 0x50, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00, // 8 bytes payload
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "gateway").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 1])
    );

    let invoking = buf.field_by_name(layer, "invoking_packet").unwrap();
    let FieldValue::Object(ref obj_range) = invoking.value else {
        panic!("expected Object")
    };
    let obj = buf.nested_fields(obj_range);
    assert_eq!(
        obj.iter().find(|f| f.name() == "src").unwrap().value,
        FieldValue::Ipv4Addr([172, 16, 0, 1])
    );
    assert_eq!(
        obj.iter().find(|f| f.name() == "dst").unwrap().value,
        FieldValue::Ipv4Addr([10, 0, 0, 2])
    );
}

// --- Timestamp (Type 13) / Timestamp Reply (Type 14) ---
// RFC 792, p.16:
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |      Code     |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Identifier          |        Sequence Number        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Originate Timestamp                                       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Receive Timestamp                                         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Transmit Timestamp                                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[test]
fn parse_icmp_timestamp_request() {
    let data: &[u8] = &[
        0x0d, // Type: Timestamp (13)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x00, 0x01, // Identifier: 1
        0x00, 0x01, // Sequence Number: 1
        0x00, 0x01, 0x51, 0x80, // Originate Timestamp: 86400 (ms since midnight)
        0x00, 0x00, 0x00, 0x00, // Receive Timestamp: 0
        0x00, 0x00, 0x00, 0x00, // Transmit Timestamp: 0
    ];

    let mut buf = DissectBuffer::new();
    let result = IcmpDissector.dissect(data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, 20);

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(13)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "originate_timestamp")
            .unwrap()
            .value,
        FieldValue::U32(86400)
    );
    assert_eq!(
        buf.field_by_name(layer, "receive_timestamp").unwrap().value,
        FieldValue::U32(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "transmit_timestamp")
            .unwrap()
            .value,
        FieldValue::U32(0)
    );
}

#[test]
fn parse_icmp_timestamp_reply() {
    let data: &[u8] = &[
        0x0e, // Type: Timestamp Reply (14)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x12, 0x34, // Identifier: 0x1234
        0x00, 0x02, // Sequence Number: 2
        0x00, 0x01, 0x51, 0x80, // Originate: 86400
        0x00, 0x01, 0x51, 0x81, // Receive: 86401
        0x00, 0x01, 0x51, 0x82, // Transmit: 86402
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(14)
    );
    assert_eq!(
        buf.field_by_name(layer, "originate_timestamp")
            .unwrap()
            .value,
        FieldValue::U32(86400)
    );
    assert_eq!(
        buf.field_by_name(layer, "receive_timestamp").unwrap().value,
        FieldValue::U32(86401)
    );
    assert_eq!(
        buf.field_by_name(layer, "transmit_timestamp")
            .unwrap()
            .value,
        FieldValue::U32(86402)
    );
}

#[test]
fn parse_icmp_timestamp_truncated() {
    // Timestamp requires 20 bytes minimum
    let data: &[u8] = &[
        0x0d, 0x00, 0x00, 0x00, // Type 13, Code 0, Checksum 0
        0x00, 0x01, 0x00, 0x01, // Identifier 1, Seq 1
        0x00, 0x00, 0x00, 0x00, // Only originate (missing receive + transmit)
    ];

    let mut buf = DissectBuffer::new();
    let err = IcmpDissector.dissect(data, &mut buf, 0).unwrap_err();
    assert_eq!(
        err,
        PacketError::Truncated {
            expected: 20,
            actual: 12
        }
    );
}

// --- Information Request (Type 15) / Information Reply (Type 16) ---
// RFC 792, p.15 / RFC 6918 (deprecated):
//  Same format as Echo: Identifier + Sequence Number

#[test]
fn parse_icmp_information_request() {
    let data: &[u8] = &[
        0x0f, // Type: Information Request (15)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x00, 0x01, // Identifier: 1
        0x00, 0x01, // Sequence Number: 1
    ];

    let mut buf = DissectBuffer::new();
    let result = IcmpDissector.dissect(data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, 8);

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(15)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U16(1)
    );
}

#[test]
fn parse_icmp_information_reply() {
    let data: &[u8] = &[
        0x10, // Type: Information Reply (16)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0xab, 0xcd, // Identifier: 0xabcd
        0x00, 0x05, // Sequence Number: 5
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(16)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(0xabcd)
    );
}

// --- Address Mask Request (Type 17) / Address Mask Reply (Type 18) ---
// RFC 950 / RFC 6918 (deprecated):
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |      Code     |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Identifier          |        Sequence Number        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                        Address Mask                           |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[test]
fn parse_icmp_address_mask_request() {
    let data: &[u8] = &[
        0x11, // Type: Address Mask Request (17)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x00, 0x01, // Identifier: 1
        0x00, 0x01, // Sequence Number: 1
        0xff, 0xff, 0xff, 0x00, // Address Mask: 255.255.255.0
    ];

    let mut buf = DissectBuffer::new();
    let result = IcmpDissector.dissect(data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, 12);

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(17)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "address_mask").unwrap().value,
        FieldValue::Ipv4Addr([255, 255, 255, 0])
    );
}

#[test]
fn parse_icmp_address_mask_reply() {
    let data: &[u8] = &[
        0x12, // Type: Address Mask Reply (18)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x00, 0x01, // Identifier: 1
        0x00, 0x01, // Sequence Number: 1
        0xff, 0xff, 0x00, 0x00, // Address Mask: 255.255.0.0
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(18)
    );
    assert_eq!(
        buf.field_by_name(layer, "address_mask").unwrap().value,
        FieldValue::Ipv4Addr([255, 255, 0, 0])
    );
}

#[test]
fn parse_icmp_address_mask_truncated() {
    // Address Mask requires 12 bytes minimum
    let data: &[u8] = &[
        0x11, 0x00, 0x00, 0x00, // Type 17, Code 0, Checksum
        0x00, 0x01, 0x00, 0x01, // Identifier, Sequence
        0xff, 0xff, // Only 2 bytes of mask (need 4)
    ];

    let mut buf = DissectBuffer::new();
    let err = IcmpDissector.dissect(data, &mut buf, 0).unwrap_err();
    assert_eq!(
        err,
        PacketError::Truncated {
            expected: 12,
            actual: 10
        }
    );
}

// --- Router Advertisement (Type 9) / Router Solicitation (Type 10) ---
// RFC 1256, Section 3:
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |           Checksum            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Num Addrs   |Addr Entry Size|           Lifetime            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                       Router Address[1]                       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                      Preference Level[1]                      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[test]
fn parse_icmp_router_advertisement() {
    let data: &[u8] = &[
        0x09, // Type: Router Advertisement (9)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x01, // Num Addrs: 1
        0x02, // Addr Entry Size: 2 (in 32-bit words)
        0x00, 0x78, // Lifetime: 120 seconds
        0xc0, 0xa8, 0x01, 0x01, // Router Address: 192.168.1.1
        0x00, 0x00, 0x00, 0x00, // Preference Level: 0
    ];

    let mut buf = DissectBuffer::new();
    let result = IcmpDissector.dissect(data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, 16);

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(9)
    );
    assert_eq!(
        buf.field_by_name(layer, "num_addrs").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "addr_entry_size").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(layer, "lifetime").unwrap().value,
        FieldValue::U16(120)
    );

    let entries = buf.field_by_name(layer, "entries").unwrap();
    let FieldValue::Array(ref arr_range) = entries.value else {
        panic!("expected Array")
    };
    let arr = buf.nested_fields(arr_range);
    // In the flat buffer, the array contains: Object + its children. Count top-level Objects.
    let objects: Vec<_> = arr.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(objects.len(), 1);

    let FieldValue::Object(ref entry_range) = objects[0].value else {
        panic!("expected Object")
    };
    let entry = buf.nested_fields(entry_range);
    assert_eq!(
        entry
            .iter()
            .find(|f| f.name() == "router_address")
            .unwrap()
            .value,
        FieldValue::Ipv4Addr([192, 168, 1, 1])
    );
    assert_eq!(
        entry
            .iter()
            .find(|f| f.name() == "preference_level")
            .unwrap()
            .value,
        FieldValue::U32(0)
    );
}

#[test]
fn parse_icmp_router_advertisement_multiple_entries() {
    let data: &[u8] = &[
        0x09, // Type: Router Advertisement (9)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x02, // Num Addrs: 2
        0x02, // Addr Entry Size: 2
        0x01, 0x2c, // Lifetime: 300 seconds
        // Entry 1
        0xc0, 0xa8, 0x01, 0x01, // Router: 192.168.1.1
        0x00, 0x00, 0x00, 0x0a, // Preference: 10
        // Entry 2
        0xc0, 0xa8, 0x01, 0x02, // Router: 192.168.1.2
        0xff, 0xff, 0xff, 0xf6, // Preference: -10 (0xFFFFFFF6 as U32)
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    let entries = buf.field_by_name(layer, "entries").unwrap();
    let FieldValue::Array(ref arr_range) = entries.value else {
        panic!("expected Array")
    };
    let arr = buf.nested_fields(arr_range);
    let objects: Vec<_> = arr.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(objects.len(), 2);

    let FieldValue::Object(ref entry2_range) = objects[1].value else {
        panic!("expected Object")
    };
    let entry2 = buf.nested_fields(entry2_range);
    assert_eq!(
        entry2
            .iter()
            .find(|f| f.name() == "router_address")
            .unwrap()
            .value,
        FieldValue::Ipv4Addr([192, 168, 1, 2])
    );
    assert_eq!(
        entry2
            .iter()
            .find(|f| f.name() == "preference_level")
            .unwrap()
            .value,
        FieldValue::U32(0xFFFFFFF6)
    );
}

#[test]
fn parse_icmp_router_solicitation() {
    let data: &[u8] = &[
        0x0a, // Type: Router Solicitation (10)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x00, 0x00, 0x00, 0x00, // Reserved
    ];

    let mut buf = DissectBuffer::new();
    let result = IcmpDissector.dissect(data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, 8);

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(10)
    );
}

// --- Photuris / Security Failures (Type 40) ---
// RFC 2521:
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Reserved            |          Pointer              |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |      Internet Header + 64 bits of Original Data Datagram      |

#[test]
fn parse_icmp_photuris_bad_spi() {
    let data: &[u8] = &[
        0x28, // Type: Photuris (40)
        0x00, // Code: Bad SPI (0)
        0x00, 0x00, // Checksum
        0x00, 0x00, // Reserved
        0x00, 0x1e, // Pointer: 30 (offset to SPI)
        // Original datagram
        0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x32, 0x00, 0x00, 0xc0, 0xa8, 0x01,
        0x01, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(40)
    );
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "pointer").unwrap().value,
        FieldValue::U16(30)
    );
    assert!(buf.field_by_name(layer, "invoking_packet").is_some());
}

#[test]
fn parse_icmp_photuris_need_authentication() {
    let data: &[u8] = &[
        0x28, // Type: Photuris (40)
        0x04, // Code: Need Authentication (4)
        0x00, 0x00, // Checksum
        0x00, 0x00, // Reserved
        0x00, 0x00, // Pointer: 0
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(40)
    );
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(4)
    );
    assert_eq!(
        buf.field_by_name(layer, "pointer").unwrap().value,
        FieldValue::U16(0)
    );
}

// --- Experimental Mobility / Seamoby (Type 41) ---
// RFC 4065:
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Subtype     |            Reserved                           |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[test]
fn parse_icmp_experimental_mobility() {
    let data: &[u8] = &[
        0x29, // Type: Experimental Mobility (41)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x00, // Subtype: 0 (CARD)
        0x00, 0x00, 0x00, // Reserved
        0xde, 0xad, 0xbe, 0xef, // Options data
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(41)
    );
    assert_eq!(
        buf.field_by_name(layer, "subtype").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "data").unwrap().value,
        FieldValue::Bytes(&[0xde, 0xad, 0xbe, 0xef])
    );
}

// --- Extended Echo Request (Type 42) / Extended Echo Reply (Type 43) ---
// RFC 8335:
// Type 42 (Request):
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Identifier          |Sequence Number|   Reserved  |L|
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[test]
fn parse_icmp_extended_echo_request() {
    // RFC 8335, §2 — Type 42 layout:
    //   bytes 4-5: Identifier (16-bit)
    //   byte 6:   Sequence Number (8-bit)
    //   byte 7:   Reserved (7 bits) | L (1 bit)
    let data: &[u8] = &[
        0x2a, // Type: Extended Echo Request (42)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x00, 0x01, // Identifier: 1 (16-bit, bytes 4-5)
        0x01, // Sequence Number: 1 (byte 6)
        0x00, // Reserved=0, L=0 (byte 7)
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(42)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "local").unwrap().value,
        FieldValue::U8(0)
    );
}

#[test]
fn parse_icmp_extended_echo_request_local_bit() {
    // RFC 8335, §2 — Type 42 layout:
    //   bytes 4-5: Identifier (16-bit)
    //   byte 6:   Sequence Number (8-bit)
    //   byte 7:   Reserved (7 bits) | L (1 bit)
    let data: &[u8] = &[
        0x2a, // Type: Extended Echo Request (42)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x00, 0x05, // Identifier: 5 (16-bit, bytes 4-5)
        0x03, // Sequence Number: 3 (byte 6)
        0x01, // Reserved=0, L=1 (byte 7)
        0xaa, 0xbb, // Extension data
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(5)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U16(3)
    );
    assert_eq!(
        buf.field_by_name(layer, "local").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "data").unwrap().value,
        FieldValue::Bytes(&[0xaa, 0xbb])
    );
}

// Type 43 (Reply):
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Identifier          |Sequence Number|State|Res|A|4|6|
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[test]
fn parse_icmp_extended_echo_reply() {
    // RFC 8335, §3 — Type 43 layout:
    //   bytes 4-5: Identifier (16-bit)
    //   byte 6:   Sequence Number (8-bit)
    //   byte 7:   State(3 bits) | Res(2 bits) | A(1) | 4(1) | 6(1)
    // State=2 (Active), A=1, 4=1, 6=0
    // Byte 7: State(3) | Res(2) | A(1) | 4(1) | 6(1) = 010_00_1_1_0 = 0x46
    let data: &[u8] = &[
        0x2b, // Type: Extended Echo Reply (43)
        0x00, // Code: No Error (0)
        0x00, 0x00, // Checksum
        0x00, 0x01, // Identifier: 1 (16-bit, bytes 4-5)
        0x01, // Sequence Number: 1 (byte 6)
        0x46, // State=2, A=1, 4=1, 6=0 (byte 7)
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(43)
    );
    assert_eq!(
        buf.field_by_name(layer, "identifier").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "state").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(layer, "active").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "ipv4").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "ipv6").unwrap().value,
        FieldValue::U8(0)
    );
}

#[test]
fn parse_icmp_extended_echo_reply_malformed_query() {
    // RFC 8335, §3 — Type 43 layout:
    //   bytes 4-5: Identifier (16-bit), byte 6: Sequence Number, byte 7: State+flags
    let data: &[u8] = &[
        0x2b, // Type: Extended Echo Reply (43)
        0x01, // Code: Malformed Query (1)
        0x00, 0x00, // Checksum
        0x00, 0x01, // Identifier: 1 (16-bit, bytes 4-5)
        0x01, // Sequence Number: 1 (byte 6)
        0x00, // State=0, all flags 0 (byte 7)
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "code").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "state").unwrap().value,
        FieldValue::U8(0)
    );
}

// --- Deprecated Types (6, 30-39) ---
// RFC 6918: These types are formally deprecated.
// We parse only common header + remaining data as bytes.

#[test]
fn parse_icmp_alternate_host_address() {
    let data: &[u8] = &[
        0x06, // Type: Alternate Host Address (6)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x01, 0x02, 0x03, 0x04, // Type-specific data
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(6)
    );
    // No type-specific fields for deprecated types without defined format
}

#[test]
fn parse_icmp_deprecated_type30_traceroute() {
    let data: &[u8] = &[
        0x1e, // Type: Traceroute (30)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x00, 0x00, 0x00, 0x00, // Type-specific data
        0xab, 0xcd, // Extra data
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(30)
    );
}

// Unknown type falls through to default handler
#[test]
fn parse_icmp_unknown_type() {
    let data: &[u8] = &[
        0xfe, // Type: 254 (experimental)
        0x00, // Code: 0
        0x00, 0x00, // Checksum
        0x00, 0x00, 0x00, 0x00, // Data
    ];

    let mut buf = DissectBuffer::new();
    IcmpDissector.dissect(data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "type").unwrap().value,
        FieldValue::U8(254)
    );
}

#[test]
fn icmp_dissector_metadata() {
    let d = IcmpDissector;
    assert_eq!(d.name(), "Internet Control Message Protocol");
    assert_eq!(d.short_name(), "ICMP");
}
