//! # RFC 826 / RFC 5227 / RFC 5494 (ARP) Coverage
//!
//! | RFC          | Description                               | Test                                    |
//! |--------------|-------------------------------------------|-----------------------------------------|
//! | RFC 826      | Full ARP Request parsing                  | parse_arp_request                       |
//! | RFC 826      | Full ARP Reply parsing                    | parse_arp_reply                         |
//! | RFC 826      | HTYPE, PTYPE, HLEN, PLEN fields           | parse_arp_request                       |
//! | RFC 826      | SHA, SPA, THA, TPA fields                 | parse_arp_request                       |
//! | RFC 826      | Non-IPv4 protocol addresses (plen≠4)      | parse_arp_non_ipv4_protocol_address     |
//! | RFC 826      | Non-Ethernet hardware addresses (hlen≠6)  | parse_arp_non_ethernet_hardware_address |
//! | RFC 826      | Truncated fixed header (<8 bytes)         | parse_arp_truncated_fixed_header        |
//! | RFC 826      | Truncated addresses                       | parse_arp_truncated_addresses           |
//! | RFC 826      | Offset handling                           | parse_arp_with_offset                   |
//! | RFC 826      | Dissector metadata                        | arp_dissector_metadata                  |
//! | RFC 5227     | ARP Probe (SPA=0.0.0.0)                   | parse_arp_probe                         |
//! | RFC 5494     | Reserved OPER values (0, 65535) — comment | parse_arp_request (oper field present)  |
//!
//! Note: RFC 826 does not define numbered sections. The entire RFC describes
//! a single packet format, so coverage is tracked by field/behavior.
//! RFC 5227 and RFC 5494 do not change the wire format; RFC 5494 reserves
//! OPER/HTYPE values 0 and 65535 (noted in comments; accepted per Postel's law).

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::field::FieldValue;
use packet_dissector::packet::DissectBuffer;

use packet_dissector::dissectors::arp::ArpDissector;
use packet_dissector::field::MacAddr;

/// Build a standard ARP packet for IPv4 over Ethernet.
/// opcode: 1=Request, 2=Reply
fn build_arp_packet(
    opcode: u16,
    sha: [u8; 6],
    spa: [u8; 4],
    tha: [u8; 6],
    tpa: [u8; 4],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&1u16.to_be_bytes()); // HTYPE: Ethernet (1)
    pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // PTYPE: IPv4
    pkt.push(6); // HLEN: 6
    pkt.push(4); // PLEN: 4
    pkt.extend_from_slice(&opcode.to_be_bytes()); // OPER
    pkt.extend_from_slice(&sha); // SHA
    pkt.extend_from_slice(&spa); // SPA
    pkt.extend_from_slice(&tha); // THA
    pkt.extend_from_slice(&tpa); // TPA
    pkt
}

#[test]
fn parse_arp_request() {
    let data = build_arp_packet(
        1, // Request
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [192, 168, 1, 1],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [192, 168, 1, 2],
    );
    let mut buf = DissectBuffer::new();
    let result = ArpDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 28);
    assert_eq!(result.next, DispatchHint::End);

    let layer = buf.layer_by_name("ARP").unwrap();
    assert_eq!(layer.name, "ARP");
    assert_eq!(layer.range, 0..28);

    assert_eq!(
        buf.field_by_name(layer, "htype").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "ptype").unwrap().value,
        FieldValue::U16(0x0800)
    );
    assert_eq!(
        buf.field_by_name(layer, "hlen").unwrap().value,
        FieldValue::U8(6)
    );
    assert_eq!(
        buf.field_by_name(layer, "plen").unwrap().value,
        FieldValue::U8(4)
    );
    assert_eq!(
        buf.field_by_name(layer, "oper").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "sha").unwrap().value,
        FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    );
    assert_eq!(
        buf.field_by_name(layer, "spa").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 1])
    );
    assert_eq!(
        buf.field_by_name(layer, "tha").unwrap().value,
        FieldValue::MacAddr(MacAddr([0x00; 6]))
    );
    assert_eq!(
        buf.field_by_name(layer, "tpa").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 2])
    );
}

#[test]
fn parse_arp_reply() {
    let data = build_arp_packet(
        2, // Reply
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [10, 0, 0, 1],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        [10, 0, 0, 2],
    );
    let mut buf = DissectBuffer::new();
    let result = ArpDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 28);

    let layer = buf.layer_by_name("ARP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "oper").unwrap().value,
        FieldValue::U16(2)
    );
    assert_eq!(
        buf.field_by_name(layer, "spa").unwrap().value,
        FieldValue::Ipv4Addr([10, 0, 0, 1])
    );
    assert_eq!(
        buf.field_by_name(layer, "tpa").unwrap().value,
        FieldValue::Ipv4Addr([10, 0, 0, 2])
    );
}

#[test]
fn parse_arp_truncated_fixed_header() {
    let data = [0u8; 6]; // Too short for even the 8-byte fixed header
    let mut buf = DissectBuffer::new();
    let err = ArpDissector.dissect(&data, &mut buf, 0).unwrap_err();

    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 8,
            actual: 6
        }
    ));
}

#[test]
fn parse_arp_truncated_addresses() {
    // Fixed header with hlen=6, plen=4 but not enough data for addresses
    let mut data = [0u8; 20];
    data[0] = 0x00;
    data[1] = 0x01; // HTYPE
    data[2] = 0x08;
    data[3] = 0x00; // PTYPE
    data[4] = 6; // HLEN
    data[5] = 4; // PLEN
    // Total needed: 8 + 2*6 + 2*4 = 28, but only 20 bytes provided
    let mut buf = DissectBuffer::new();
    let err = ArpDissector.dissect(&data, &mut buf, 0).unwrap_err();

    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 28,
            actual: 20
        }
    ));
}

#[test]
fn parse_arp_with_offset() {
    let data = build_arp_packet(1, [0; 6], [0; 4], [0; 6], [0; 4]);
    let mut buf = DissectBuffer::new();
    ArpDissector.dissect(&data, &mut buf, 14).unwrap();

    let layer = buf.layer_by_name("ARP").unwrap();
    assert_eq!(layer.range, 14..42);
    // RFC 826 — HTYPE at offset 0..2
    assert_eq!(buf.field_by_name(layer, "htype").unwrap().range, 14..16);
}

#[test]
fn parse_arp_non_ipv4_protocol_address() {
    // ARP with plen=6 (not IPv4) — protocol addresses should be Bytes, not Ipv4Addr
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&1u16.to_be_bytes()); // HTYPE: Ethernet
    pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // PTYPE
    pkt.push(6); // HLEN: 6
    pkt.push(6); // PLEN: 6 (not 4, so not IPv4)
    pkt.extend_from_slice(&1u16.to_be_bytes()); // OPER: Request
    pkt.extend_from_slice(&[0x01; 6]); // SHA
    pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // SPA (6 bytes)
    pkt.extend_from_slice(&[0x02; 6]); // THA
    pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // TPA (6 bytes)

    let mut buf = DissectBuffer::new();
    let result = ArpDissector.dissect(&pkt, &mut buf, 0).unwrap();

    // 8 + 2*6 + 2*6 = 32
    assert_eq!(result.bytes_consumed, 32);

    let layer = buf.layer_by_name("ARP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "plen").unwrap().value,
        FieldValue::U8(6)
    );
    assert_eq!(
        buf.field_by_name(layer, "spa").unwrap().value,
        FieldValue::Bytes(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    );
    assert_eq!(
        buf.field_by_name(layer, "tpa").unwrap().value,
        FieldValue::Bytes(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    );
}

#[test]
fn arp_dissector_metadata() {
    let d = ArpDissector;
    assert_eq!(d.name(), "Address Resolution Protocol");
    assert_eq!(d.short_name(), "ARP");
}

#[test]
fn parse_arp_non_ethernet_hardware_address() {
    // ARP with hlen=2 (non-Ethernet) — hardware addresses should be Bytes, not MacAddr
    // RFC 826 — ar$hln determines hardware address size; htype≠1 means non-Ethernet
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&2u16.to_be_bytes()); // HTYPE: 2 (Experimental Ethernet)
    pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // PTYPE: IPv4
    pkt.push(2); // HLEN: 2 (non-Ethernet)
    pkt.push(4); // PLEN: 4 (IPv4)
    pkt.extend_from_slice(&1u16.to_be_bytes()); // OPER: Request
    pkt.extend_from_slice(&[0xAB, 0xCD]); // SHA (2 bytes)
    pkt.extend_from_slice(&[10, 0, 0, 1]); // SPA
    pkt.extend_from_slice(&[0x00, 0x00]); // THA (2 bytes)
    pkt.extend_from_slice(&[10, 0, 0, 2]); // TPA

    let mut buf = DissectBuffer::new();
    let result = ArpDissector.dissect(&pkt, &mut buf, 0).unwrap();

    // 8 + 2*2 + 2*4 = 20
    assert_eq!(result.bytes_consumed, 20);

    let layer = buf.layer_by_name("ARP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "htype").unwrap().value,
        FieldValue::U16(2)
    );
    assert_eq!(
        buf.field_by_name(layer, "hlen").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(layer, "sha").unwrap().value,
        FieldValue::Bytes(&[0xAB, 0xCD])
    );
    assert_eq!(
        buf.field_by_name(layer, "tha").unwrap().value,
        FieldValue::Bytes(&[0x00, 0x00])
    );
    assert_eq!(
        buf.field_by_name(layer, "spa").unwrap().value,
        FieldValue::Ipv4Addr([10, 0, 0, 1])
    );
}

#[test]
fn parse_arp_probe() {
    // RFC 5227 — ARP Probe: SPA=0.0.0.0, TPA=address-being-probed
    // The dissector must accept probes without error and parse SPA as all-zero IPv4
    let data = build_arp_packet(
        1, // Request
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0, 0, 0, 0], // SPA = 0.0.0.0 per RFC 5227 probe
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [192, 168, 1, 100], // TPA = address being probed
    );
    let mut buf = DissectBuffer::new();
    let result = ArpDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 28);

    let layer = buf.layer_by_name("ARP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "spa").unwrap().value,
        FieldValue::Ipv4Addr([0, 0, 0, 0])
    );
    assert_eq!(
        buf.field_by_name(layer, "tpa").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 100])
    );
}
