//! # RFC 791 (IPv4) Coverage
//!
//! References:
//! - RFC 791: <https://www.rfc-editor.org/rfc/rfc791>
//! - RFC 2474 (DSCP, updates RFC 791 ToS field): <https://www.rfc-editor.org/rfc/rfc2474>
//! - RFC 3168 (ECN): <https://www.rfc-editor.org/rfc/rfc3168>
//! - RFC 6864 (updates RFC 791 Identification field): <https://www.rfc-editor.org/rfc/rfc6864>
//! - RFC 1108 (DoD Basic Security option): <https://www.rfc-editor.org/rfc/rfc1108>
//! - RFC 2113 (Router Alert option): <https://www.rfc-editor.org/rfc/rfc2113>
//! - RFC 4782 (Quick-Start option): <https://www.rfc-editor.org/rfc/rfc4782>
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
//! | 791 §3.2       | Non-initial fragment ends chain | parse_ipv4_non_initial_fragment_ends_chain |
//! | 791 §3.2       | First fragment reassembly context | parse_ipv4_first_fragment_context |
//! | 791 §3.2       | Whole datagram has no fragment context | parse_ipv4_whole_datagram_no_fragment_context |
//! | 791 §3.1       | Flags byte range is byte 6 only | parse_ipv4_field_byte_ranges        |
//! | 791 §3.1       | TTL                             | parse_ipv4_basic                    |
//! | 791 §3.1       | Protocol (TCP=6)                | parse_ipv4_basic                    |
//! | 791 §3.1       | Protocol (UDP=17)               | parse_ipv4_udp_protocol             |
//! | 791 §3.1       | Header Checksum                 | parse_ipv4_basic                    |
//! | 791 §3.1       | Source / Destination Address    | parse_ipv4_basic                    |
//! | 791 §3.1       | Options (IHL > 5), No Operation | parse_ipv4_with_options             |
//! | 791 §3.1       | Option-type copied/class/number | parse_ipv4_option_type_bits         |
//! | 791 §3.1       | End of Option List stops walk   | parse_ipv4_option_end_of_list       |
//! | 791 §3.1       | Record Route                    | parse_ipv4_option_record_route      |
//! | 791 §3.1       | Loose Source and Record Route   | parse_ipv4_option_lsrr              |
//! | 791 §3.1       | Strict Source and Record Route  | parse_ipv4_option_ssrr              |
//! | 791 §3.1       | Stream Identifier               | parse_ipv4_option_stream_id         |
//! | 791 §3.1       | Internet Timestamp (flag 0)     | parse_ipv4_option_timestamp_only    |
//! | 791 §3.1       | Internet Timestamp (flag 1/3)   | parse_ipv4_option_timestamp_with_address |
//! | 1108 §2        | DoD Basic Security              | parse_ipv4_option_basic_security    |
//! | 2113 §2.1      | Router Alert                    | parse_ipv4_option_router_alert      |
//! | 4782 §3.1      | Quick-Start Rate Request        | parse_ipv4_option_quick_start_request |
//! | 4782 §3.1      | Quick-Start Report of Approved Rate | parse_ipv4_option_quick_start_report |
//! | 791 §3.1       | Unknown option keeps raw value  | parse_ipv4_option_unknown           |
//! | 791 §3.1       | Timestamp with undefined flag   | parse_ipv4_option_timestamp_undefined_flag |
//! | IANA registry  | Option names                    | parse_ipv4_option_names             |
//! | 791 §3.1       | Option length past header       | parse_ipv4_option_length_past_end   |
//! | 791 §3.1       | Option length < 2               | parse_ipv4_option_length_too_small  |
//! | 791 §3.1       | Length octet missing            | parse_ipv4_option_missing_length    |
//! | 791 §3.1       | Fixed-length option wrong size  | parse_ipv4_option_router_alert_bad_length |
//! | —              | Truncated header                | parse_ipv4_truncated                |
//! | —              | Truncated with options          | parse_ipv4_truncated_with_options   |
//! | 791 §3.1       | Version must be 4               | parse_ipv4_invalid_version          |
//! | 791 §3.1       | Total Length < IHL*4 invalid    | parse_ipv4_total_length_too_small   |
//! | 791 §3.1       | Total Length > data (snaplen) accepted | parse_ipv4_total_length_exceeds_data_accepted |
//! | 791 §3.1       | Payload ends at Total Length    | parse_ipv4_payload_len_from_total_length |
//! | 791 §3.1       | Payload length excludes options | parse_ipv4_payload_len_with_options |
//! | —              | Offset handling                 | parse_ipv4_with_offset              |
//! | —              | Dissector metadata              | ipv4_dissector_metadata             |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::field::{Field, FieldValue};
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

    // RFC 791, Section 3.1 — four single-octet No Operation options.
    let options = buf.field_by_name(layer, "options").unwrap();
    assert!(options.value.is_array());
    assert_eq!(options.range, 20..24);
    let opts = option_objects(&buf, &options.value);
    assert_eq!(opts.len(), 4);
    for (i, (range, opt)) in opts.iter().enumerate() {
        assert_eq!(child(opt, "type"), Some(&FieldValue::U8(1)));
        assert_eq!(child(opt, "length"), None);
        assert_eq!(*range, 20 + i..21 + i);
    }
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
fn parse_ipv4_non_initial_fragment_ends_chain() {
    // RFC 791, Section 3.2 — the Fragment Offset "identifies the fragment
    // location, relative to the beginning of the original unfragmented
    // datagram", so a fragment with a non-zero offset carries no upper-layer
    // header and must not be dispatched.
    // https://www.rfc-editor.org/rfc/rfc791#section-3.2
    let mut data = build_ipv4_packet(17, [10, 0, 0, 1], [10, 0, 0, 2], 28);
    data[4..6].copy_from_slice(&0x002au16.to_be_bytes());
    data[6..8].copy_from_slice(&0x0001u16.to_be_bytes()); // MF=0, offset=1
    let mut buf = DissectBuffer::new();
    let result = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.next, DispatchHint::End);
    assert_eq!(result.payload_len, Some(8));
    let ctx = result.ip_fragment_context.expect("fragment context");
    assert_eq!(
        ctx.frag_key,
        (
            // IPv4-mapped IPv6 addresses (RFC 4291, Section 2.5.5.2).
            // https://www.rfc-editor.org/rfc/rfc4291#section-2.5.5.2
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2],
            17,
            0x2a
        )
    );
    assert_eq!(ctx.protocol, 17);
    assert_eq!(ctx.offset_bytes, 8);
    assert!(!ctx.more_fragments);
    assert_eq!(ctx.payload_len, 8);
    assert_eq!(ctx.unfragmentable_len, 20);
}

#[test]
fn parse_ipv4_first_fragment_context() {
    // RFC 791, Section 3.2 — MF=1 with offset 0 is the first fragment: it
    // starts with the upper-layer header, so it is still dispatched.
    // https://www.rfc-editor.org/rfc/rfc791#section-3.2
    let mut data = build_ipv4_packet(17, [10, 0, 0, 1], [10, 0, 0, 2], 36);
    data[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // MF=1, offset=0
    let mut buf = DissectBuffer::new();
    let result = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.next, DispatchHint::ByIpProtocol(17));
    let ctx = result.ip_fragment_context.expect("fragment context");
    assert!(ctx.is_first());
    assert!(ctx.more_fragments);
    assert_eq!(ctx.payload_len, 16);
}

#[test]
fn parse_ipv4_whole_datagram_no_fragment_context() {
    // RFC 791, Section 3.2 — "a whole datagram (that is both the fragment
    // offset and the more fragments fields are zero)"; DF does not matter
    // (RFC 6864, Section 4 — atomic datagrams).
    // https://www.rfc-editor.org/rfc/rfc791#section-3.2
    // https://www.rfc-editor.org/rfc/rfc6864#section-4
    for flags_frag in [0x0000u16, 0x4000] {
        let mut data = build_ipv4_packet(6, [0; 4], [0; 4], 40);
        data[6..8].copy_from_slice(&flags_frag.to_be_bytes());
        let mut buf = DissectBuffer::new();
        let result = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.next, DispatchHint::ByIpProtocol(6));
        assert_eq!(result.ip_fragment_context, None);
    }
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
fn parse_ipv4_total_length_exceeds_data_accepted() {
    // RFC 791, Section 3.1 — Total Length is the length of the datagram; it
    // says nothing about how much of it a capture holds. A snaplen-limited
    // capture keeps fewer bytes, so the header is still dissected and the
    // declared payload length is reported (the dispatch loop clamps it to the
    // captured bytes).
    // https://www.rfc-editor.org/rfc/rfc791#section-3.1
    let mut data = [0u8; 24];
    data[0] = 0x45; // Version=4, IHL=5
    data[2..4].copy_from_slice(&100u16.to_be_bytes()); // Total Length = 100
    let mut buf = DissectBuffer::new();
    let result = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 20);
    assert_eq!(result.payload_len, Some(80));
    let layer = buf.layer_by_name("IPv4").unwrap();
    assert_eq!(layer.range, 0..20);
    assert_eq!(
        buf.field_by_name(layer, "total_length").unwrap().value,
        FieldValue::U16(100)
    );
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

#[test]
fn parse_ipv4_payload_len_from_total_length() {
    // RFC 791, Section 3.1 — "Total Length is the length of the datagram,
    // measured in octets, including internet header and data."
    // Bytes past Total Length (e.g. Ethernet padding) are not IP payload.
    // https://www.rfc-editor.org/rfc/rfc791#section-3.1
    let mut data = build_ipv4_packet(1, [10, 0, 0, 1], [10, 0, 0, 2], 28);
    data.resize(46, 0x00); // 18 bytes of trailing link-layer padding
    let mut buf = DissectBuffer::new();
    let result = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 20);
    assert_eq!(result.payload_len, Some(8));
}

#[test]
fn parse_ipv4_payload_len_with_options() {
    // RFC 791, Section 3.1 — the payload is Total Length minus IHL * 4.
    // https://www.rfc-editor.org/rfc/rfc791#section-3.1
    let mut data = build_ipv4_packet(17, [10, 0, 0, 1], [10, 0, 0, 2], 36);
    data[0] = 0x46; // IHL = 6 (4 bytes of options)
    let mut buf = DissectBuffer::new();
    let result = Ipv4Dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 24);
    assert_eq!(result.payload_len, Some(12));
}

// ---------------------------------------------------------------------------
// Options (RFC 791, Section 3.1)
// ---------------------------------------------------------------------------

/// Build an IPv4 header whose options area is `options` (padded with zero
/// octets, i.e. End of Option List, to a multiple of 4).
fn build_ipv4_with_options(options: &[u8]) -> Vec<u8> {
    let opt_len = options.len().div_ceil(4) * 4;
    let header_len = 20 + opt_len;
    let mut pkt = build_ipv4_packet(253, [192, 168, 0, 1], [224, 0, 0, 22], header_len as u16);
    pkt[0] = 0x40 | (header_len / 4) as u8;
    pkt[20..20 + options.len()].copy_from_slice(options);
    pkt
}

/// Return every option object in the `options` array as its byte range and
/// its nested fields.
fn option_objects<'a, 'pkt>(
    buf: &'a DissectBuffer<'pkt>,
    array: &FieldValue<'pkt>,
) -> Vec<(std::ops::Range<usize>, &'a [Field<'pkt>])> {
    let FieldValue::Array(range) = array else {
        panic!("options must be an array, got {array:?}");
    };
    let children = buf.nested_fields(range);
    let mut out = Vec::new();
    let mut i = 0;
    while i < children.len() {
        let FieldValue::Object(obj) = &children[i].value else {
            panic!("option entries must be objects");
        };
        out.push((children[i].range.clone(), buf.nested_fields(obj)));
        i = (obj.end - range.start) as usize;
    }
    out
}

fn child<'a, 'pkt>(fields: &'a [Field<'pkt>], name: &str) -> Option<&'a FieldValue<'pkt>> {
    fields.iter().find(|f| f.name() == name).map(|f| &f.value)
}

fn dissect_options(pkt: &[u8]) -> (DissectBuffer<'_>, FieldValue<'_>) {
    let mut buf = DissectBuffer::new();
    Ipv4Dissector.dissect(pkt, &mut buf, 0).unwrap();
    let layer = buf.layer_by_name("IPv4").unwrap();
    let options = buf.field_by_name(layer, "options").unwrap().value.clone();
    (buf, options)
}

/// Collect the elements of a nested array child.
fn array_values<'a, 'pkt>(
    buf: &'a DissectBuffer<'pkt>,
    fields: &[Field<'pkt>],
    name: &str,
) -> Vec<&'a FieldValue<'pkt>> {
    let Some(FieldValue::Array(range)) = child(fields, name) else {
        panic!("{name} must be an array");
    };
    let children = buf.nested_fields(range);
    let mut out = Vec::new();
    let mut i = 0;
    while i < children.len() {
        out.push(&children[i].value);
        i = match &children[i].value {
            FieldValue::Object(obj) => (obj.end - range.start) as usize,
            _ => i + 1,
        };
    }
    out
}

#[test]
fn parse_ipv4_option_type_bits() {
    // RFC 791, Section 3.1 — "1 bit copied flag, 2 bits option class,
    // 5 bits option number". 0x94 (Router Alert) = 1 00 10100.
    let pkt = build_ipv4_with_options(&[0x94, 0x04, 0x00, 0x00]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    let (_, opt) = &opts[0];
    assert_eq!(child(opt, "type"), Some(&FieldValue::U8(0x94)));
    assert_eq!(child(opt, "copied"), Some(&FieldValue::U8(1)));
    assert_eq!(child(opt, "class"), Some(&FieldValue::U8(0)));
    assert_eq!(child(opt, "number"), Some(&FieldValue::U8(20)));

    // 0x44 (Timestamp) = 0 10 00100 → class 2 (debugging and measurement).
    let pkt = build_ipv4_with_options(&[0x44, 0x04, 0x05, 0x00]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    let (_, opt) = &opts[0];
    assert_eq!(child(opt, "copied"), Some(&FieldValue::U8(0)));
    assert_eq!(child(opt, "class"), Some(&FieldValue::U8(2)));
    assert_eq!(child(opt, "number"), Some(&FieldValue::U8(4)));
}

#[test]
fn parse_ipv4_option_end_of_list() {
    // RFC 791, Section 3.1 — End of Option List "is used at the end of all
    // options"; the octets after it are header padding, not options.
    let pkt = build_ipv4_with_options(&[0x01, 0x00, 0x07, 0x07]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    assert_eq!(opts.len(), 2);
    assert_eq!(child(opts[0].1, "type"), Some(&FieldValue::U8(1)));
    assert_eq!(child(opts[1].1, "type"), Some(&FieldValue::U8(0)));
    assert_eq!(opts[1].0, 21..22);
}

#[test]
fn parse_ipv4_option_record_route() {
    // RFC 791, Section 3.1 — Record Route: type 7, length, pointer, route data.
    let pkt = build_ipv4_with_options(&[
        0x07, 0x0B, 0x08, // type, length 11, pointer 8
        10, 0, 0, 1, // recorded address
        0, 0, 0, 0,    // free slot
        0x00, // EOL
    ]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    let (range, opt) = &opts[0];
    assert_eq!(*range, 20..31);
    assert_eq!(child(opt, "length"), Some(&FieldValue::U8(11)));
    assert_eq!(child(opt, "pointer"), Some(&FieldValue::U8(8)));
    assert_eq!(
        array_values(&buf, opt, "route"),
        vec![
            &FieldValue::Ipv4Addr([10, 0, 0, 1]),
            &FieldValue::Ipv4Addr([0, 0, 0, 0])
        ]
    );
    let layer = buf.layer_by_name("IPv4").unwrap();
    let idx = buf
        .fields()
        .iter()
        .position(|f| f.name() == "option")
        .unwrap() as u32;
    assert_eq!(
        buf.resolve_container_display_name(idx),
        Some("Record Route")
    );
    assert!(buf.field_by_name(layer, "route").is_some());
}

#[test]
fn parse_ipv4_option_lsrr() {
    // RFC 791, Section 3.1 — Loose Source and Record Route: type 131.
    let pkt = build_ipv4_with_options(&[0x83, 0x07, 0x04, 192, 0, 2, 1, 0x00]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    let (_, opt) = &opts[0];
    assert_eq!(child(opt, "copied"), Some(&FieldValue::U8(1)));
    assert_eq!(child(opt, "pointer"), Some(&FieldValue::U8(4)));
    assert_eq!(
        array_values(&buf, opt, "route"),
        vec![&FieldValue::Ipv4Addr([192, 0, 2, 1])]
    );
}

#[test]
fn parse_ipv4_option_ssrr() {
    // RFC 791, Section 3.1 — Strict Source and Record Route: type 137.
    let pkt = build_ipv4_with_options(&[0x89, 0x0B, 0x08, 192, 0, 2, 1, 192, 0, 2, 2, 0x00]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    let (_, opt) = &opts[0];
    assert_eq!(child(opt, "type"), Some(&FieldValue::U8(137)));
    assert_eq!(
        array_values(&buf, opt, "route"),
        vec![
            &FieldValue::Ipv4Addr([192, 0, 2, 1]),
            &FieldValue::Ipv4Addr([192, 0, 2, 2])
        ]
    );
}

#[test]
fn parse_ipv4_option_stream_id() {
    // RFC 791, Section 3.1 — Stream Identifier: type 136, length 4.
    let pkt = build_ipv4_with_options(&[0x88, 0x04, 0x12, 0x34]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    assert_eq!(
        child(opts[0].1, "stream_id"),
        Some(&FieldValue::U16(0x1234))
    );
}

#[test]
fn parse_ipv4_option_timestamp_only() {
    // RFC 791, Section 3.1 — Internet Timestamp, flag 0: timestamps only.
    let pkt = build_ipv4_with_options(&[
        0x44, 0x0C, 0x09, 0x10, // type 68, length 12, pointer 9, oflw 1 / flg 0
        0x00, 0x00, 0x03, 0xE8, // timestamp 1000
        0x00, 0x00, 0x00, 0x00, // free slot
    ]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    let (_, opt) = &opts[0];
    assert_eq!(child(opt, "pointer"), Some(&FieldValue::U8(9)));
    assert_eq!(child(opt, "overflow"), Some(&FieldValue::U8(1)));
    assert_eq!(child(opt, "flag"), Some(&FieldValue::U8(0)));
    let entries = array_values(&buf, opt, "entries");
    assert_eq!(entries.len(), 2);
    let FieldValue::Object(first) = entries[0] else {
        panic!("entry must be an object")
    };
    let first = buf.nested_fields(first);
    assert_eq!(child(first, "timestamp"), Some(&FieldValue::U32(1000)));
    assert_eq!(child(first, "address"), None);
}

#[test]
fn parse_ipv4_option_timestamp_with_address() {
    // RFC 791, Section 3.1 — flag 1: "each timestamp is preceded with
    // internet address of the registering entity"; flag 3 is prespecified.
    for flag in [1u8, 3u8] {
        let pkt = build_ipv4_with_options(&[
            0x44, 0x0C, 0x0D, flag, // type 68, length 12, pointer 13
            10, 0, 0, 1, // address
            0x80, 0x00, 0x00, 0x01, // non-standard timestamp (high bit set)
        ]);
        let (buf, options) = dissect_options(&pkt);
        let opts = option_objects(&buf, &options);
        let (_, opt) = &opts[0];
        assert_eq!(child(opt, "flag"), Some(&FieldValue::U8(flag)));
        let entries = array_values(&buf, opt, "entries");
        assert_eq!(entries.len(), 1);
        let FieldValue::Object(first) = entries[0] else {
            panic!("entry must be an object")
        };
        let first = buf.nested_fields(first);
        assert_eq!(
            child(first, "address"),
            Some(&FieldValue::Ipv4Addr([10, 0, 0, 1]))
        );
        assert_eq!(
            child(first, "timestamp"),
            Some(&FieldValue::U32(0x8000_0001))
        );
    }
}

#[test]
fn parse_ipv4_option_basic_security() {
    // RFC 1108, Section 2 — DoD Basic Security: type 130, classification
    // level, protection authority flags.
    let pkt = build_ipv4_with_options(&[0x82, 0x04, 0xAB, 0x01]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    let (_, opt) = &opts[0];
    assert_eq!(
        child(opt, "classification_level"),
        Some(&FieldValue::U8(0xAB))
    );
    assert_eq!(
        child(opt, "protection_authority"),
        Some(&FieldValue::Bytes(&[0x01]))
    );
}

#[test]
fn parse_ipv4_option_router_alert() {
    // RFC 2113, Section 2.1 — Router Alert: type 148, length 4, value 0.
    // Example from the issue: IGMP-style header with IHL=6.
    let pkt = [
        0x46, 0x00, 0x00, 0x18, 0x00, 0x01, 0x00, 0x00, 0x01, 0xfd, 0x00, 0x00, //
        0xc0, 0xa8, 0x00, 0x01, 0xe0, 0x00, 0x00, 0x16, //
        0x94, 0x04, 0x00, 0x00,
    ];
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    assert_eq!(opts.len(), 1);
    let (range, opt) = &opts[0];
    assert_eq!(*range, 20..24);
    assert_eq!(child(opt, "length"), Some(&FieldValue::U8(4)));
    assert_eq!(child(opt, "router_alert"), Some(&FieldValue::U16(0)));
    let layer = buf.layer_by_name("IPv4").unwrap();
    assert!(buf.field_by_name(layer, "router_alert").is_some());
    let idx = buf
        .fields()
        .iter()
        .position(|f| f.name() == "option")
        .unwrap() as u32;
    assert_eq!(
        buf.resolve_container_display_name(idx),
        Some("Router Alert")
    );
}

#[test]
fn parse_ipv4_option_router_alert_bad_length() {
    // RFC 2113, Section 2.1 — Length is 4. Another length keeps the raw
    // value instead of misreading it.
    let pkt = build_ipv4_with_options(&[0x94, 0x03, 0x00, 0x00]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    let (_, opt) = &opts[0];
    assert_eq!(child(opt, "router_alert"), None);
    assert_eq!(child(opt, "value"), Some(&FieldValue::Bytes(&[0x00])));
}

#[test]
fn parse_ipv4_option_quick_start_request() {
    // RFC 4782, Section 3.1 — Function 0000 (Rate Request), Rate Request,
    // QS TTL, 30-bit QS Nonce + 2-bit Reserved.
    let pkt = build_ipv4_with_options(&[0x19, 0x08, 0x05, 0x40, 0x12, 0x34, 0x56, 0x7B]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    let (_, opt) = &opts[0];
    assert_eq!(child(opt, "qs_function"), Some(&FieldValue::U8(0)));
    assert_eq!(child(opt, "qs_rate"), Some(&FieldValue::U8(5)));
    assert_eq!(child(opt, "qs_ttl"), Some(&FieldValue::U8(0x40)));
    assert_eq!(
        child(opt, "qs_nonce"),
        Some(&FieldValue::U32(0x1234_567B >> 2))
    );
}

#[test]
fn parse_ipv4_option_quick_start_report() {
    // RFC 4782, Section 3.1 — Function 1000 (Report of Approved Rate): the
    // fourth byte is not used, so no QS TTL is reported.
    let pkt = build_ipv4_with_options(&[0x19, 0x08, 0x83, 0xFF, 0x00, 0x00, 0x00, 0x04]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    let (_, opt) = &opts[0];
    assert_eq!(child(opt, "qs_function"), Some(&FieldValue::U8(8)));
    assert_eq!(child(opt, "qs_rate"), Some(&FieldValue::U8(3)));
    assert_eq!(child(opt, "qs_ttl"), None);
    assert_eq!(child(opt, "qs_nonce"), Some(&FieldValue::U32(1)));
}

#[test]
fn parse_ipv4_option_unknown() {
    // RFC 791, Section 3.1 — options this dissector does not decode keep
    // their data as raw bytes.
    let pkt = build_ipv4_with_options(&[0x9E, 0x04, 0xDE, 0xAD]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    let (_, opt) = &opts[0];
    assert_eq!(child(opt, "type"), Some(&FieldValue::U8(0x9E)));
    assert_eq!(child(opt, "value"), Some(&FieldValue::Bytes(&[0xDE, 0xAD])));
}

#[test]
fn parse_ipv4_option_length_past_end() {
    // RFC 791, Section 3.1 — the option-length octet counts the whole
    // option. A length that runs past the header is reported as malformed
    // and the rest of the options area is kept as raw bytes.
    let pkt = build_ipv4_with_options(&[0x01, 0x07, 0x09, 0x04]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    assert_eq!(opts.len(), 2);
    let (range, opt) = &opts[1];
    assert_eq!(*range, 21..24);
    assert_eq!(child(opt, "type"), Some(&FieldValue::U8(7)));
    assert_eq!(child(opt, "length"), Some(&FieldValue::U8(9)));
    assert_eq!(child(opt, "malformed"), Some(&FieldValue::Bytes(&[0x04])));
    assert_eq!(child(opt, "pointer"), None);
}

#[test]
fn parse_ipv4_option_length_too_small() {
    // RFC 791, Section 3.1 — the length counts the type and length octets,
    // so a value below 2 is malformed (and would otherwise loop forever).
    let pkt = build_ipv4_with_options(&[0x94, 0x01, 0x00, 0x00]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    assert_eq!(opts.len(), 1);
    let (range, opt) = &opts[0];
    assert_eq!(*range, 20..24);
    assert_eq!(child(opt, "length"), Some(&FieldValue::U8(1)));
    assert_eq!(
        child(opt, "malformed"),
        Some(&FieldValue::Bytes(&[0x00, 0x00]))
    );
}

#[test]
fn parse_ipv4_option_missing_length() {
    // A multi-octet option type in the last octet of the header has no
    // length octet.
    let pkt = build_ipv4_with_options(&[0x01, 0x01, 0x01, 0x94]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    assert_eq!(opts.len(), 4);
    let (range, opt) = &opts[3];
    assert_eq!(*range, 23..24);
    assert_eq!(child(opt, "type"), Some(&FieldValue::U8(0x94)));
    assert_eq!(child(opt, "length"), None);
    assert_eq!(child(opt, "malformed"), Some(&FieldValue::Bytes(&[])));
}

#[test]
fn parse_ipv4_option_timestamp_undefined_flag() {
    // RFC 791, Section 3.1 defines flags 0, 1 and 3 only; other flags keep
    // the timestamp area raw.
    let pkt = build_ipv4_with_options(&[0x44, 0x08, 0x05, 0x02, 1, 2, 3, 4]);
    let (buf, options) = dissect_options(&pkt);
    let opts = option_objects(&buf, &options);
    let (_, opt) = &opts[0];
    assert_eq!(child(opt, "flag"), Some(&FieldValue::U8(2)));
    assert_eq!(child(opt, "entries"), None);
    assert_eq!(child(opt, "value"), Some(&FieldValue::Bytes(&[1, 2, 3, 4])));
}

#[test]
fn parse_ipv4_option_names() {
    // Option names from the IANA "IP Option Numbers" registry, resolved
    // both on the option object and on its `type` field.
    let cases: &[(&[u8], &str)] = &[
        (&[0x00], "End of Option List"),
        (&[0x01], "No Operation"),
        (&[0x07, 0x03, 0x04], "Record Route"),
        (&[0x19, 0x02], "Quick-Start"),
        (&[0x44, 0x04, 0x05, 0x00], "Internet Timestamp"),
        (&[0x82, 0x03, 0x01], "Basic Security"),
        (&[0x83, 0x03, 0x04], "Loose Source and Record Route"),
        (&[0x88, 0x04, 0x00, 0x01], "Stream Identifier"),
        (&[0x89, 0x03, 0x04], "Strict Source and Record Route"),
        (&[0x94, 0x04, 0x00, 0x00], "Router Alert"),
    ];
    for &(bytes, name) in cases {
        let pkt = build_ipv4_with_options(bytes);
        let mut buf = DissectBuffer::new();
        Ipv4Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let idx = buf
            .fields()
            .iter()
            .position(|f| f.name() == "option")
            .unwrap() as u32;
        assert_eq!(buf.resolve_container_display_name(idx), Some(name));
        let FieldValue::Object(range) = &buf.fields()[idx as usize].value else {
            panic!("option must be an object");
        };
        assert_eq!(
            buf.resolve_nested_display_name(range, "type_name"),
            Some(name)
        );
    }
    let pkt = build_ipv4_with_options(&[0x9E, 0x02]);
    let mut buf = DissectBuffer::new();
    Ipv4Dissector.dissect(&pkt, &mut buf, 0).unwrap();
    let idx = buf
        .fields()
        .iter()
        .position(|f| f.name() == "option")
        .unwrap() as u32;
    assert_eq!(buf.resolve_container_display_name(idx), None);
}
