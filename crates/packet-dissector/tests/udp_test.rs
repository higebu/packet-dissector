//! # RFC 768 (UDP) Coverage
//!
//! RFC 768 is a 3-page document with no numbered sections; citations reference
//! the field description paragraphs by field name.
//!
//! | RFC 768 Field / Rule                         | Test                              |
//! |----------------------------------------------|-----------------------------------|
//! | Source Port field (16 bits)                  | parse_udp_basic                   |
//! | Destination Port field (16 bits)             | parse_udp_basic                   |
//! | Length field (16 bits)                       | parse_udp_basic                   |
//! | Checksum field (16 bits)                     | parse_udp_basic                   |
//! | Checksum = 0 means "not computed"            | parse_udp_no_checksum             |
//! | Minimum Length = 8 (header only)            | parse_udp_length_too_small        |
//! | Length must not exceed available data        | parse_udp_length_exceeds_data     |
//! | Truncated header (< 8 bytes)                 | parse_udp_truncated               |
//! | Byte offset correctness                      | parse_udp_with_offset             |
//! | Dissector metadata                           | udp_dissector_metadata            |
//! | Next dissector selected by port              | parse_udp_next_dissector_by_port  |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::field::FieldValue;
use packet_dissector::packet::DissectBuffer;

use packet_dissector::dissectors::udp::UdpDissector;

/// Build a UDP datagram whose buffer size matches the declared `length`.
/// The payload area (after the 8-byte header) is filled with zeros.
fn build_udp_packet(src_port: u16, dst_port: u16, length: u16) -> Vec<u8> {
    let buf_len = (length as usize).max(8);
    let mut pkt = vec![0u8; buf_len];
    pkt[0..2].copy_from_slice(&src_port.to_be_bytes());
    pkt[2..4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[4..6].copy_from_slice(&length.to_be_bytes());
    pkt[6..8].copy_from_slice(&0xABCDu16.to_be_bytes()); // Checksum
    pkt
}

#[test]
fn parse_udp_basic() {
    let data = build_udp_packet(12345, 53, 20); // DNS query
    let mut buf = DissectBuffer::new();
    let result = UdpDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 8);

    let layer = buf.layer_by_name("UDP").unwrap();
    assert_eq!(layer.name, "UDP");
    assert_eq!(layer.range, 0..8);

    assert_eq!(
        buf.field_by_name(layer, "src_port").unwrap().value,
        FieldValue::U16(12345)
    );
    assert_eq!(
        buf.field_by_name(layer, "dst_port").unwrap().value,
        FieldValue::U16(53)
    );
    assert_eq!(
        buf.field_by_name(layer, "length").unwrap().value,
        FieldValue::U16(20)
    );
    assert_eq!(
        buf.field_by_name(layer, "checksum").unwrap().value,
        FieldValue::U16(0xABCD)
    );
}

#[test]
fn parse_udp_no_checksum() {
    let mut data = build_udp_packet(1234, 5678, 8);
    data[6] = 0x00;
    data[7] = 0x00; // Checksum = 0 (not computed)

    let mut buf = DissectBuffer::new();
    UdpDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("UDP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "checksum").unwrap().value,
        FieldValue::U16(0)
    );
}

#[test]
fn parse_udp_truncated() {
    let data = [0u8; 4]; // Only 4 bytes
    let mut buf = DissectBuffer::new();
    let err = UdpDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 8,
            actual: 4
        }
    ));
}

#[test]
fn parse_udp_with_offset() {
    let data = build_udp_packet(80, 443, 8);
    let mut buf = DissectBuffer::new();
    UdpDissector.dissect(&data, &mut buf, 42).unwrap();

    let layer = buf.layer_by_name("UDP").unwrap();
    assert_eq!(layer.range, 42..50);
    assert_eq!(buf.field_by_name(layer, "src_port").unwrap().range, 42..44);
    assert_eq!(buf.field_by_name(layer, "dst_port").unwrap().range, 44..46);
    assert_eq!(buf.field_by_name(layer, "length").unwrap().range, 46..48);
    assert_eq!(buf.field_by_name(layer, "checksum").unwrap().range, 48..50);
}

#[test]
fn parse_udp_next_dissector_by_port() {
    // Carries both src and dst ports; registry dispatches low→high
    let data = build_udp_packet(54321, 53, 20);
    let mut buf = DissectBuffer::new();
    let result = UdpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.next, DispatchHint::ByUdpPort(54321, 53));

    let data2 = build_udp_packet(53, 54321, 20);
    let mut buf2 = DissectBuffer::new();
    let result2 = UdpDissector.dissect(&data2, &mut buf2, 0).unwrap();
    assert_eq!(result2.next, DispatchHint::ByUdpPort(53, 54321));
}

#[test]
fn udp_dissector_metadata() {
    let d = UdpDissector;
    assert_eq!(d.name(), "User Datagram Protocol");
    assert_eq!(d.short_name(), "UDP");
}

#[test]
fn parse_udp_length_too_small() {
    // RFC 768: "The minimum value of the length is eight."
    // Length = 7 is invalid.
    let mut data = build_udp_packet(1234, 5678, 7);
    data[4] = 0x00;
    data[5] = 0x07; // Length = 7

    let mut buf = DissectBuffer::new();
    let err = UdpDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidFieldValue { .. }
    ));
}

#[test]
fn parse_udp_length_exceeds_data() {
    // RFC 768: Length includes the header + data.
    // If data buffer is shorter than the declared Length, the packet is truncated.
    let mut data = build_udp_packet(1234, 5678, 20); // claims 20 bytes total
    data.truncate(12); // only 12 bytes available

    let mut buf = DissectBuffer::new();
    let err = UdpDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 20,
            actual: 12
        }
    ));
}
