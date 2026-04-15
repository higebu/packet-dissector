//! # RFC 791 (IPv4) Coverage
//!
//! References:
//! - RFC 791: <https://www.rfc-editor.org/rfc/rfc791>
//! - RFC 2474 (DSCP, updates RFC 791 ToS field): <https://www.rfc-editor.org/rfc/rfc2474>
//! - RFC 3168 (ECN): <https://www.rfc-editor.org/rfc/rfc3168>
//! - RFC 6864 (updates RFC 791 Identification field): <https://www.rfc-editor.org/rfc/rfc6864>
//!
//! | RFC Section    | Description                     | Test                                |
//! |----------------|---------------------------------|-------------------------------------|
//! | 791 §3.1       | Version, IHL                    | parse_ipv4_basic                    |
//! | 791 §3.1       | IHL < 5 invalid                 | parse_ipv4_invalid_ihl              |
//! | 791 §3.1       | IHL = 15 (max header, 60 bytes) | parse_ipv4_max_ihl                  |
//! | 2474 §3        | DSCP (6 bits, class selector)   | parse_ipv4_dscp_ecn                 |
//! | 3168 §5        | ECN (2 bits, CE codepoint)      | parse_ipv4_dscp_ecn                 |
//! | 791 §3.1       | Total Length                    | parse_ipv4_basic                    |
//! | 791 §3.1       | Identification                  | parse_ipv4_basic                    |
//! | 6864 §4        | Atomic datagram ID tolerated    | parse_ipv4_atomic_identification    |
//! | 791 §3.1       | Flags (DF)                      | parse_ipv4_basic                    |
//! | 791 §3.1       | Flags (MF) + Fragment Offset    | parse_ipv4_fragmented               |
//! | 791 §3.1       | Flags byte range is byte 6 only | parse_ipv4_field_byte_ranges        |
//! | 791 §3.1       | TTL                             | parse_ipv4_basic                    |
//! | 791 §3.1       | Protocol (TCP=6)                | parse_ipv4_basic                    |
//! | 791 §3.1       | Protocol (UDP=17)               | parse_ipv4_udp_protocol             |
//! | 791 §3.1       | Header Checksum                 | parse_ipv4_basic                    |
//! | 791 §3.1       | Source / Destination Address    | parse_ipv4_basic                    |
//! | 791 §3.1       | Options (IHL > 5)               | parse_ipv4_with_options             |
//! | —              | Truncated header                | parse_ipv4_truncated                |
//! | —              | Truncated with options          | parse_ipv4_truncated_with_options   |
//! | 791 §3.1       | Version must be 4               | parse_ipv4_invalid_version          |
//! | 791 §3.1       | Total Length < IHL*4 invalid    | parse_ipv4_total_length_too_small   |
//! | 791 §3.1       | Total Length > data truncated   | parse_ipv4_total_length_exceeds_data|
//! | —              | Offset handling                 | parse_ipv4_with_offset              |
//! | —              | Dissector metadata              | ipv4_dissector_metadata             |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::field::FieldValue;
use packet_dissector::packet::DissectBuffer;

use packet_dissector::dissectors::ipv4::Ipv4Dissector;

/// Build a valid IPv4 packet (header + zero-filled payload to match total_length).
fn build_ipv4_packet(protocol: u8, src: [u8; 4], dst: [u8; 4], total_length: u16) -> Vec<u8> {
    let len = (total_length as usize).max(20);
    let mut pkt = vec![0u8; len];
    // RFC 791, Section 3.1
    pkt[0] = 0x45; // Version=4, IHL=5
    pkt[1] = 0x00; // DSCP=0, ECN=0
    pkt[2..4].copy_from_slice(&total_length.to_be_bytes()); // Total Length
    pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // Identification
    pkt[6] = 0x40; // Flags: Don't Fragment
    pkt[7] = 0x00; // Fragment Offset: 0
    pkt[8] = 64; // TTL
    pkt[9] = protocol; // Protocol
    pkt[10..12].copy_from_slice(&[0x00, 0x00]); // Checksum (0 for test)
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt
}

#[test]
fn parse_ipv4_basic() {
    let data = build_ipv4_packet(6, [192, 168, 1, 1], [10, 0, 0, 1], 40);
    let mut buf = DissectBuffer::new();
    let result = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 20);
    assert_eq!(result.next, DispatchHint::ByIpProtocol(6)); // TCP

    let layer = buf.layer_by_name("IPv4").unwrap();
    assert_eq!(layer.name, "IPv4");
    assert_eq!(layer.range, 0..20);

    assert_eq!(
        buf.field_by_name(layer, "version").unwrap().value,
        FieldValue::U8(4)
    );
    assert_eq!(
        buf.field_by_name(layer, "ihl").unwrap().value,
        FieldValue::U8(5)
    );
    assert_eq!(
        buf.field_by_name(layer, "dscp").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "ecn").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "total_length").unwrap().value,
        FieldValue::U16(40)
    );
    assert_eq!(
        buf.field_by_name(layer, "identification").unwrap().value,
        FieldValue::U16(0x1234)
    );
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0x02)
    ); // DF bit
    assert_eq!(
        buf.field_by_name(layer, "fragment_offset").unwrap().value,
        FieldValue::U16(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "ttl").unwrap().value,
        FieldValue::U8(64)
    );
    assert_eq!(
        buf.field_by_name(layer, "protocol").unwrap().value,
        FieldValue::U8(6)
    );
    assert_eq!(
        buf.field_by_name(layer, "src").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 1])
    );
    assert_eq!(
        buf.field_by_name(layer, "dst").unwrap().value,
        FieldValue::Ipv4Addr([10, 0, 0, 1])
    );
}

#[test]
fn parse_ipv4_udp_protocol() {
    let data = build_ipv4_packet(17, [0; 4], [0; 4], 28);
    let mut buf = DissectBuffer::new();
    let result = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.next, DispatchHint::ByIpProtocol(17)); // UDP
}

#[test]
fn parse_ipv4_with_options() {
    // IHL=6 means 24 bytes header (4 bytes of options)
    let mut data = vec![0u8; 48];
    data[0] = 0x46; // Version=4, IHL=6
    data[2..4].copy_from_slice(&48u16.to_be_bytes());
    data[8] = 128; // TTL
    data[9] = 1; // ICMP
    data[12..16].copy_from_slice(&[10, 0, 0, 1]);
    data[16..20].copy_from_slice(&[10, 0, 0, 2]);
    // Options at 20..24
    data[20..24].copy_from_slice(&[0x01, 0x01, 0x01, 0x01]); // NOP padding

    let mut buf = DissectBuffer::new();
    let result = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 24);
    assert_eq!(result.next, DispatchHint::ByIpProtocol(1));

    let layer = buf.layer_by_name("IPv4").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "ihl").unwrap().value,
        FieldValue::U8(6)
    );
    assert_eq!(layer.range, 0..24);

    // Options field should contain the 4 option bytes
    assert_eq!(
        buf.field_by_name(layer, "options").unwrap().value,
        FieldValue::Bytes(&[0x01, 0x01, 0x01, 0x01])
    );
}

#[test]
fn parse_ipv4_truncated() {
    let data = [0x45, 0x00, 0x00]; // Only 3 bytes
    let mut buf = DissectBuffer::new();
    let err = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 20,
            actual: 3
        }
    ));
}

#[test]
fn parse_ipv4_truncated_with_options() {
    // IHL=7 (28 bytes) but only 20 bytes available
    let mut data = [0u8; 20];
    data[0] = 0x47; // Version=4, IHL=7
    let mut buf = DissectBuffer::new();
    let err = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 28,
            actual: 20
        }
    ));
}

#[test]
fn parse_ipv4_invalid_ihl() {
    // IHL < 5 is invalid
    let mut data = [0u8; 20];
    data[0] = 0x43; // Version=4, IHL=3
    let mut buf = DissectBuffer::new();
    let err = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidFieldValue { field: "ihl", .. }
    ));
}

#[test]
fn parse_ipv4_with_offset() {
    let data = build_ipv4_packet(6, [0; 4], [0; 4], 20);
    let mut buf = DissectBuffer::new();
    Ipv4Dissector.dissect(&data, &mut buf, 14).unwrap();

    let layer = buf.layer_by_name("IPv4").unwrap();
    assert_eq!(layer.range, 14..34);
    assert_eq!(buf.field_by_name(layer, "version").unwrap().range, 14..15);
    assert_eq!(buf.field_by_name(layer, "src").unwrap().range, 26..30);
    assert_eq!(buf.field_by_name(layer, "dst").unwrap().range, 30..34);
}

#[test]
fn parse_ipv4_fragmented() {
    let mut data = build_ipv4_packet(6, [0; 4], [0; 4], 40);
    // Flags: MF=1, Fragment Offset: 185 (185 * 8 = 1480 bytes)
    data[6] = 0x20; // MF bit set
    data[7] = 0xB9; // Fragment offset = 185
    // Combined: 0x20B9

    let mut buf = DissectBuffer::new();
    Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("IPv4").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0x01)
    ); // MF
    assert_eq!(
        buf.field_by_name(layer, "fragment_offset").unwrap().value,
        FieldValue::U16(185)
    );
}

#[test]
fn parse_ipv4_invalid_version() {
    // RFC 791, Section 3.1 — Version must be 4
    let mut data = [0u8; 20];
    data[0] = 0x65; // Version=6, IHL=5
    data[2..4].copy_from_slice(&20u16.to_be_bytes());
    let mut buf = DissectBuffer::new();
    let err = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidFieldValue {
            field: "version",
            ..
        }
    ));
}

#[test]
fn parse_ipv4_total_length_too_small() {
    // RFC 791, Section 3.1 — Total Length must be >= IHL * 4
    let mut data = [0u8; 20];
    data[0] = 0x45; // Version=4, IHL=5
    data[2..4].copy_from_slice(&10u16.to_be_bytes()); // Total Length = 10 < header = 20
    let mut buf = DissectBuffer::new();
    let err = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidFieldValue {
            field: "total_length",
            ..
        }
    ));
}

#[test]
fn parse_ipv4_total_length_exceeds_data() {
    // RFC 791, Section 3.1 — Total Length says 100 but only 20 bytes available
    let mut data = [0u8; 20];
    data[0] = 0x45; // Version=4, IHL=5
    data[2..4].copy_from_slice(&100u16.to_be_bytes()); // Total Length = 100
    let mut buf = DissectBuffer::new();
    let err = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated { .. }
    ));
}

#[test]
fn ipv4_dissector_metadata() {
    let d = Ipv4Dissector;
    assert_eq!(d.name(), "Internet Protocol version 4");
    assert_eq!(d.short_name(), "IPv4");
}

#[test]
fn parse_ipv4_dscp_ecn() {
    // RFC 2474, Section 3 — DSCP occupies bits 0-5 of the DS Field (formerly ToS).
    // RFC 3168, Section 5 — ECN occupies bits 6-7.
    // DSCP = 0x2E (EF PHB), ECN = 0x03 (CE codepoint) → byte 1 = 0xBB.
    let mut data = build_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], 20);
    data[1] = 0xBB;
    let mut buf = DissectBuffer::new();
    Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("IPv4").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "dscp").unwrap().value,
        FieldValue::U8(0x2E)
    );
    assert_eq!(
        buf.field_by_name(layer, "ecn").unwrap().value,
        FieldValue::U8(0x03)
    );
}

#[test]
fn parse_ipv4_max_ihl() {
    // RFC 791, Section 3.1 — IHL is a 4-bit field; max = 15 → 60-byte header.
    let mut data = vec![0u8; 60];
    data[0] = 0x4F; // Version=4, IHL=15
    data[2..4].copy_from_slice(&60u16.to_be_bytes()); // Total Length = 60
    data[8] = 64; // TTL
    data[9] = 6; // Protocol = TCP
    data[12..16].copy_from_slice(&[10, 0, 0, 1]);
    data[16..20].copy_from_slice(&[10, 0, 0, 2]);
    // Options (40 bytes): pad with NOP (0x01)
    for b in data.iter_mut().take(60).skip(20) {
        *b = 0x01;
    }

    let mut buf = DissectBuffer::new();
    let result = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, 60);

    let layer = buf.layer_by_name("IPv4").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "ihl").unwrap().value,
        FieldValue::U8(15)
    );
    assert_eq!(layer.range, 0..60);
    let options = buf.field_by_name(layer, "options").unwrap();
    assert_eq!(options.range, 20..60);
}

#[test]
fn parse_ipv4_field_byte_ranges() {
    // RFC 791, Section 3.1 — verify each field highlights exactly the bytes it occupies.
    // Flags (3 bits) live entirely in bits 0-2 of byte 6, so its range must be byte 6 alone,
    // while Fragment Offset (13 bits) spans bytes 6-7.
    let data = build_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], 20);
    let mut buf = DissectBuffer::new();
    Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("IPv4").unwrap();

    assert_eq!(buf.field_by_name(layer, "version").unwrap().range, 0..1);
    assert_eq!(buf.field_by_name(layer, "ihl").unwrap().range, 0..1);
    assert_eq!(buf.field_by_name(layer, "dscp").unwrap().range, 1..2);
    assert_eq!(buf.field_by_name(layer, "ecn").unwrap().range, 1..2);
    assert_eq!(
        buf.field_by_name(layer, "total_length").unwrap().range,
        2..4
    );
    assert_eq!(
        buf.field_by_name(layer, "identification").unwrap().range,
        4..6
    );
    // Flags lives in bits 0-2 of byte 6; range must not extend into byte 7.
    assert_eq!(buf.field_by_name(layer, "flags").unwrap().range, 6..7);
    // Fragment offset occupies bits 3-15 of bytes 6-7.
    assert_eq!(
        buf.field_by_name(layer, "fragment_offset").unwrap().range,
        6..8
    );
    assert_eq!(buf.field_by_name(layer, "ttl").unwrap().range, 8..9);
    assert_eq!(buf.field_by_name(layer, "protocol").unwrap().range, 9..10);
    assert_eq!(buf.field_by_name(layer, "checksum").unwrap().range, 10..12);
    assert_eq!(buf.field_by_name(layer, "src").unwrap().range, 12..16);
    assert_eq!(buf.field_by_name(layer, "dst").unwrap().range, 16..20);
}

#[test]
fn parse_ipv4_atomic_identification() {
    // RFC 6864, Section 4 — atomic datagrams (DF=1, MF=0, frag_offset=0) MAY carry
    // any Identification value; the dissector MUST parse it verbatim and not reject it.
    let mut data = build_ipv4_packet(6, [10, 0, 0, 1], [10, 0, 0, 2], 20);
    data[4..6].copy_from_slice(&0u16.to_be_bytes()); // ID = 0 (legal for atomic datagrams)
    data[6] = 0x40; // DF=1, MF=0
    data[7] = 0x00; // Fragment Offset = 0
    let mut buf = DissectBuffer::new();
    Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("IPv4").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "identification").unwrap().value,
        FieldValue::U16(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0x02)
    );
    assert_eq!(
        buf.field_by_name(layer, "fragment_offset").unwrap().value,
        FieldValue::U16(0)
    );
}
