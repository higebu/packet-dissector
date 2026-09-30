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
//! | Length > data (snaplen) accepted             | parse_udp_length_exceeds_data_accepted |
//! | Truncated header (< 8 bytes)                 | parse_udp_truncated               |
//! | Byte offset correctness                      | parse_udp_with_offset             |
//! | Dissector metadata                           | udp_dissector_metadata            |
//! | Checksum over pseudo-header verified (good) | udp_checksum_status_good          |
//! | Checksum over pseudo-header verified (bad)  | udp_checksum_status_bad           |
//! | Checksum = 0 reported as not present       | udp_checksum_status_zero_not_present |
//! | Checksum covers Length only (RFC 9868 §8)  | udp_checksum_status_ignores_surplus_area |
//! | Truncated datagram / no IP layer unverified | udp_checksum_status_unverified   |
//! | No status unless verification on           | udp_checksum_status_absent_by_default |
//! | Next dissector selected by port              | parse_udp_next_dissector_by_port  |

use packet_dissector::checksum::{ChecksumStatus, internet_checksum};
use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::dissectors::ipv4::Ipv4Dissector;
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
fn parse_udp_length_exceeds_data_accepted() {
    // RFC 768: Length includes the header + data. A buffer shorter than the
    // declared Length is what a snaplen-limited capture holds, so the header
    // is still dissected; the dispatch loop clamps the payload to the
    // captured bytes.
    // https://www.rfc-editor.org/rfc/rfc768
    let mut data = build_udp_packet(1234, 5678, 20); // claims 20 bytes total
    data.truncate(12); // only 12 bytes available

    let mut buf = DissectBuffer::new();
    let result = UdpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, 8);
    assert_eq!(result.payload_len, Some(12));
    let layer = buf.layer_by_name("UDP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "length").unwrap().value,
        FieldValue::U16(20)
    );
}

/// The `checksum_status` of `layer`, if the dissector added one.
fn checksum_status(buf: &DissectBuffer<'_>, layer_name: &str) -> Option<ChecksumStatus> {
    let layer = buf.layer_by_name(layer_name).unwrap();
    buf.field_by_name(layer, "checksum_status")
        .map(|f| ChecksumStatus::from_u8(f.value.as_u8().unwrap()).unwrap())
}

/// IPv4 header (20 bytes, no fragmentation) for `payload_len` bytes of `protocol`.
fn ipv4_header(protocol: u8, payload_len: usize) -> Vec<u8> {
    let mut h = vec![0x45, 0x00];
    h.extend_from_slice(&((20 + payload_len) as u16).to_be_bytes());
    h.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, protocol, 0x00, 0x00]);
    h.extend_from_slice(&V4_SRC);
    h.extend_from_slice(&V4_DST);
    h
}

const V4_SRC: [u8; 4] = [192, 0, 2, 1];
const V4_DST: [u8; 4] = [198, 51, 100, 2];

/// Store the Internet checksum over `pseudo` + `message` at `at`.
fn fill_checksum(pseudo: &[u8], message: &mut [u8], at: usize) {
    message[at..at + 2].copy_from_slice(&[0, 0]);
    let c = internet_checksum(&[pseudo, message]);
    message[at..at + 2].copy_from_slice(&c.to_be_bytes());
}

/// IPv4 pseudo-header (RFC 9293, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>;
/// RFC 768 — <https://www.rfc-editor.org/rfc/rfc768>).
fn v4_pseudo(protocol: u8, len: usize) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&V4_SRC);
    p.extend_from_slice(&V4_DST);
    p.extend_from_slice(&[0, protocol]);
    p.extend_from_slice(&(len as u16).to_be_bytes());
    p
}

/// Dissect `ip_header` + `message` with verification on: IPv4 first, then
/// `dissector` at the message offset.
fn dissect_over_ipv4<'a>(dissector: &dyn Dissector, packet: &'a [u8], buf: &mut DissectBuffer<'a>) {
    buf.set_verify_checksums(true);
    Ipv4Dissector.dissect(packet, buf, 0).unwrap();
    dissector.dissect(&packet[20..], buf, 20).unwrap();
}

/// IPv4 + UDP datagram with correct checksums and `surplus` bytes after the
/// UDP Length.
fn ipv4_udp(payload: &[u8], surplus: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut udp = vec![0x30, 0x39, 0x00, 0x35];
    udp.extend_from_slice(&(len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    fill_checksum(&v4_pseudo(17, len), &mut udp, 6);
    udp.extend_from_slice(surplus);
    let mut pkt = ipv4_header(17, udp.len());
    pkt.extend_from_slice(&udp);
    pkt
}

#[test]
fn udp_checksum_status_absent_by_default() {
    let pkt = ipv4_udp(b"hello", &[]);
    let mut buf = DissectBuffer::new();
    Ipv4Dissector.dissect(&pkt, &mut buf, 0).unwrap();
    UdpDissector.dissect(&pkt[20..], &mut buf, 20).unwrap();
    assert_eq!(checksum_status(&buf, "UDP"), None);
}

#[test]
fn udp_checksum_status_good() {
    let pkt = ipv4_udp(b"hello", &[]);
    let mut buf = DissectBuffer::new();
    dissect_over_ipv4(&UdpDissector, &pkt, &mut buf);
    assert_eq!(checksum_status(&buf, "UDP"), Some(ChecksumStatus::Good));
    let layer = buf.layer_by_name("UDP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "checksum_status").unwrap().range,
        26..28
    );
}

#[test]
fn udp_checksum_status_bad() {
    let mut pkt = ipv4_udp(b"hello", &[]);
    let last = pkt.len() - 1;
    pkt[last] ^= 0x01;
    let mut buf = DissectBuffer::new();
    dissect_over_ipv4(&UdpDissector, &pkt, &mut buf);
    assert_eq!(checksum_status(&buf, "UDP"), Some(ChecksumStatus::Bad));
}

#[test]
fn udp_checksum_status_zero_not_present() {
    // RFC 768 — "An all zero transmitted checksum value means that the
    // transmitter generated no checksum".
    // https://www.rfc-editor.org/rfc/rfc768
    let mut pkt = ipv4_udp(b"hello", &[]);
    pkt[26..28].copy_from_slice(&[0, 0]);
    let mut buf = DissectBuffer::new();
    dissect_over_ipv4(&UdpDissector, &pkt, &mut buf);
    assert_eq!(
        checksum_status(&buf, "UDP"),
        Some(ChecksumStatus::NotPresent)
    );
}

#[test]
fn udp_checksum_status_ignores_surplus_area() {
    // RFC 9868, Section 8 — the surplus area "is not otherwise covered by
    // the UDP checksum".
    // https://www.rfc-editor.org/rfc/rfc9868#section-8
    let pkt = ipv4_udp(b"hi", &[0x01, 0x02, 0x03]);
    let mut buf = DissectBuffer::new();
    dissect_over_ipv4(&UdpDissector, &pkt, &mut buf);
    assert_eq!(checksum_status(&buf, "UDP"), Some(ChecksumStatus::Good));
}

#[test]
fn udp_checksum_status_unverified() {
    // Snaplen-truncated datagram: the checksum covers bytes not captured.
    let pkt = ipv4_udp(b"hello", &[]);
    let truncated = &pkt[..pkt.len() - 2];
    let mut buf = DissectBuffer::new();
    dissect_over_ipv4(&UdpDissector, truncated, &mut buf);
    assert_eq!(
        checksum_status(&buf, "UDP"),
        Some(ChecksumStatus::Unverified)
    );

    // No enclosing IP layer: the pseudo-header is unknown.
    let mut buf = DissectBuffer::new();
    buf.set_verify_checksums(true);
    UdpDissector.dissect(&pkt[20..], &mut buf, 0).unwrap();
    assert_eq!(
        checksum_status(&buf, "UDP"),
        Some(ChecksumStatus::Unverified)
    );
}
