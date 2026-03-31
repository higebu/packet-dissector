//! # RFC 9293 (TCP) Coverage
//!
//! | RFC Section | Description                                    | Test                                    |
//! |-------------|------------------------------------------------|-----------------------------------------|
//! | 3.1         | Source Port, Destination Port                  | parse_tcp_basic                         |
//! | 3.1         | Sequence Number                                | parse_tcp_basic                         |
//! | 3.1         | Acknowledgment Number                          | parse_tcp_basic                         |
//! | 3.1         | Data Offset                                    | parse_tcp_basic                         |
//! | 3.1         | Reserved (4 bits, ignored in received segments)| parse_tcp_basic, parse_tcp_nonzero_reserved_ignored |
//! | 3.1         | Flags (CWR,ECE,URG,ACK,PSH,RST,SYN,FIN)       | parse_tcp_syn, parse_tcp_all_flags      |
//! | 3.1         | Window                                         | parse_tcp_basic                         |
//! | 3.1         | Checksum                                       | parse_tcp_basic                         |
//! | 3.1         | Urgent Pointer                                 | parse_tcp_urgent                        |
//! | 3.1         | Options (Data Offset > 5)                      | parse_tcp_with_options                  |
//! | —           | Truncated header                               | parse_tcp_truncated                     |
//! | —           | Data Offset < 5 invalid                        | parse_tcp_invalid_data_offset           |
//! | —           | Truncated with options                         | parse_tcp_truncated_with_options        |
//! | —           | Offset handling                                | parse_tcp_with_offset                   |
//! | —           | Dissector metadata                             | tcp_dissector_metadata                  |
//! | —           | Next dissector by port                         | parse_tcp_next_dissector_by_port        |
//! | —           | Stream ID (sequential) with IPv4               | tcp_stream_id_present_ipv4              |
//! | —           | Stream ID consistent for same 4-tuple          | tcp_stream_id_consistent                |
//! | —           | Stream ID differs for different 4-tuples       | tcp_stream_id_different                 |
//! | —           | Stream ID absent without IP layer              | tcp_stream_id_absent_without_ip         |
//! | —           | Stream ID with IPv6                            | tcp_stream_id_present_ipv6              |
//! | —           | Stream ID (bidirectional)                      | tcp_stream_id_bidirectional             |
//! | —           | Stream ID is sequential                        | tcp_stream_id_sequential                |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::field::FieldValue;
use packet_dissector::packet::DissectBuffer;

use packet_dissector::dissectors::tcp::TcpDissector;

/// Create a leaked static FieldDescriptor for tests.
#[cfg(test)]
fn test_desc(
    name: &'static str,
    display_name: &'static str,
) -> &'static packet_dissector::field::FieldDescriptor {
    Box::leak(Box::new(packet_dissector::field::FieldDescriptor {
        name,
        display_name,
        field_type: packet_dissector::field::FieldType::U8, // placeholder
        optional: false,
        children: None,
        display_fn: None,
        format_fn: None,
    }))
}

/// Build a minimal valid TCP header (20 bytes, no options).
fn build_tcp_packet(src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 20];
    // RFC 9293, Section 3.1
    pkt[0..2].copy_from_slice(&src_port.to_be_bytes()); // Source Port
    pkt[2..4].copy_from_slice(&dst_port.to_be_bytes()); // Destination Port
    pkt[4..8].copy_from_slice(&seq.to_be_bytes()); // Sequence Number
    pkt[8..12].copy_from_slice(&ack.to_be_bytes()); // Acknowledgment Number
    pkt[12] = 0x50; // Data Offset = 5, Reserved = 0
    pkt[13] = flags; // Flags
    pkt[14..16].copy_from_slice(&8192u16.to_be_bytes()); // Window = 8192
    pkt[16..18].copy_from_slice(&[0x00, 0x00]); // Checksum (0 for test)
    pkt[18..20].copy_from_slice(&[0x00, 0x00]); // Urgent Pointer
    pkt
}

#[test]
fn parse_tcp_basic() {
    let data = build_tcp_packet(12345, 80, 0x01020304, 0x05060708, 0x10); // ACK
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    let result = dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 20);

    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(layer.name, "TCP");
    assert_eq!(layer.range, 0..20);

    assert_eq!(
        buf.field_by_name(layer, "src_port").unwrap().value,
        FieldValue::U16(12345)
    );
    assert_eq!(
        buf.field_by_name(layer, "dst_port").unwrap().value,
        FieldValue::U16(80)
    );
    assert_eq!(
        buf.field_by_name(layer, "seq").unwrap().value,
        FieldValue::U32(0x01020304)
    );
    assert_eq!(
        buf.field_by_name(layer, "ack").unwrap().value,
        FieldValue::U32(0x05060708)
    );
    assert_eq!(
        buf.field_by_name(layer, "data_offset").unwrap().value,
        FieldValue::U8(5)
    );
    assert_eq!(
        buf.field_by_name(layer, "reserved").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0x10)
    );
    assert_eq!(
        buf.field_by_name(layer, "window").unwrap().value,
        FieldValue::U16(8192)
    );
    assert_eq!(
        buf.field_by_name(layer, "checksum").unwrap().value,
        FieldValue::U16(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "urgent_pointer").unwrap().value,
        FieldValue::U16(0)
    );
}

#[test]
fn parse_tcp_syn() {
    let data = build_tcp_packet(54321, 443, 0xAABBCCDD, 0, 0x02); // SYN
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0x02)
    ); // SYN
}

#[test]
fn parse_tcp_all_flags() {
    // CWR=0x80, ECE=0x40, URG=0x20, ACK=0x10, PSH=0x08, RST=0x04, SYN=0x02, FIN=0x01
    let data = build_tcp_packet(1, 2, 0, 0, 0xFF); // All flags set
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0xFF)
    );
}

#[test]
fn parse_tcp_urgent() {
    let mut data = build_tcp_packet(1, 2, 0, 0, 0x20); // URG flag
    data[18..20].copy_from_slice(&100u16.to_be_bytes()); // Urgent Pointer = 100
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0x20)
    ); // URG
    assert_eq!(
        buf.field_by_name(layer, "urgent_pointer").unwrap().value,
        FieldValue::U16(100)
    );
}

#[test]
fn parse_tcp_with_options() {
    // Data Offset = 8 means 32 bytes header (12 bytes of options)
    let mut data = vec![0u8; 32];
    data[0..2].copy_from_slice(&8080u16.to_be_bytes());
    data[2..4].copy_from_slice(&80u16.to_be_bytes());
    data[12] = 0x80; // Data Offset = 8
    data[20..32].copy_from_slice(&[
        0x02, 0x04, 0x05, 0xB4, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x01, 0x01,
    ]);

    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    let result = dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 32);

    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "data_offset").unwrap().value,
        FieldValue::U8(8)
    );
    assert_eq!(
        buf.field_by_name(layer, "options").unwrap().value,
        FieldValue::Bytes(&[
            0x02, 0x04, 0x05, 0xB4, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x01, 0x01
        ])
    );
}

#[test]
fn parse_tcp_truncated() {
    let data = [0u8; 10]; // Too short for 20-byte header
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    let err = dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 20,
            actual: 10
        }
    ));
}

#[test]
fn parse_tcp_invalid_data_offset() {
    let mut data = build_tcp_packet(1, 2, 0, 0, 0);
    data[12] = 0x30; // Data Offset = 3 (< 5)
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    let err = dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidFieldValue {
            field: "data_offset",
            ..
        }
    ));
}

#[test]
fn parse_tcp_truncated_with_options() {
    // Data Offset = 8 means 32 bytes header, but only 24 available
    let mut data = vec![0u8; 24];
    data[12] = 0x80; // Data Offset = 8
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    let err = dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 32,
            actual: 24
        }
    ));
}

#[test]
fn parse_tcp_with_offset() {
    let data = build_tcp_packet(1234, 5678, 0, 0, 0);
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    dissector.dissect(&data, &mut buf, 34).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(layer.range, 34..54);
    assert_eq!(buf.field_by_name(layer, "src_port").unwrap().range, 34..36);
    assert_eq!(buf.field_by_name(layer, "dst_port").unwrap().range, 36..38);
}

#[test]
fn tcp_dissector_metadata() {
    let d = TcpDissector::new();
    assert_eq!(d.name(), "Transmission Control Protocol");
    assert_eq!(d.short_name(), "TCP");
}

#[test]
fn parse_tcp_next_dissector_by_port() {
    let data = build_tcp_packet(54321, 80, 0, 0, 0x10);
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    let result = dissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.next, DispatchHint::ByTcpPort(54321, 80));
}

/// RFC 9293, Section 3.1: Reserved bits "MUST be zero when sent and MUST be
/// ignored when received".
/// A dissector must accept segments with non-zero Reserved bits without error.
#[test]
fn parse_tcp_nonzero_reserved_ignored() {
    let mut data = build_tcp_packet(1234, 80, 0, 0, 0x02); // SYN
    // Set Reserved nibble to 0xF (all 4 bits set) while keeping Data Offset = 5
    data[12] = 0x5F; // Data Offset = 5 (high nibble), Reserved = 0xF (low nibble)
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    let result = dissector.dissect(&data, &mut buf, 0);
    assert!(
        result.is_ok(),
        "Non-zero Reserved bits must be ignored per RFC 9293 Section 3.1"
    );
    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "data_offset").unwrap().value,
        FieldValue::U8(5)
    );
    assert_eq!(
        buf.field_by_name(layer, "reserved").unwrap().value,
        FieldValue::U8(0x0F)
    );
}

/// Add a pre-populated IPv4 layer to a DissectBuffer for stream_id tests.
fn add_ipv4_layer(buf: &mut DissectBuffer<'_>, src_ip: [u8; 4], dst_ip: [u8; 4]) {
    buf.begin_layer("IPv4", None, &[], 0..20);
    buf.push_field(
        test_desc("src", "Source Address"),
        FieldValue::Ipv4Addr(src_ip),
        12..16,
    );
    buf.push_field(
        test_desc("dst", "Destination Address"),
        FieldValue::Ipv4Addr(dst_ip),
        16..20,
    );
    buf.end_layer();
}

/// Add a pre-populated IPv6 layer to a DissectBuffer for stream_id tests.
fn add_ipv6_layer(buf: &mut DissectBuffer<'_>, src_ip: [u8; 16], dst_ip: [u8; 16]) {
    buf.begin_layer("IPv6", None, &[], 0..40);
    buf.push_field(
        test_desc("src", "Source Address"),
        FieldValue::Ipv6Addr(src_ip),
        8..24,
    );
    buf.push_field(
        test_desc("dst", "Destination Address"),
        FieldValue::Ipv6Addr(dst_ip),
        24..40,
    );
    buf.end_layer();
}

#[test]
fn tcp_stream_id_present_ipv4() {
    let tcp_data = build_tcp_packet(12345, 80, 0, 0, 0x02);
    let mut buf = DissectBuffer::new();
    add_ipv4_layer(&mut buf, [10, 0, 0, 1], [10, 0, 0, 2]);
    let dissector = TcpDissector::new();
    dissector.dissect(&tcp_data, &mut buf, 20).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    let stream_id = buf.field_by_name(layer, "stream_id");
    assert!(stream_id.is_some(), "stream_id should be present with IPv4");
    assert!(
        matches!(stream_id.unwrap().value, FieldValue::U32(_)),
        "stream_id should be U32"
    );
}

#[test]
fn tcp_stream_id_consistent() {
    let dissector = TcpDissector::new();

    let tcp_data = build_tcp_packet(12345, 80, 100, 0, 0x10);
    let mut buf1 = DissectBuffer::new();
    add_ipv4_layer(&mut buf1, [10, 0, 0, 1], [10, 0, 0, 2]);
    dissector.dissect(&tcp_data, &mut buf1, 20).unwrap();

    let tcp_data2 = build_tcp_packet(12345, 80, 200, 100, 0x10);
    let mut buf2 = DissectBuffer::new();
    add_ipv4_layer(&mut buf2, [10, 0, 0, 1], [10, 0, 0, 2]);
    dissector.dissect(&tcp_data2, &mut buf2, 20).unwrap();

    let sid1 = buf1
        .layer_by_name("TCP")
        .and_then(|l| buf1.field_by_name(l, "stream_id"))
        .unwrap();
    let sid2 = buf2
        .layer_by_name("TCP")
        .and_then(|l| buf2.field_by_name(l, "stream_id"))
        .unwrap();
    assert_eq!(
        sid1.value, sid2.value,
        "same 4-tuple must produce the same stream_id"
    );
}

#[test]
fn tcp_stream_id_different() {
    let dissector = TcpDissector::new();

    let tcp_data1 = build_tcp_packet(12345, 80, 0, 0, 0x02);
    let mut buf1 = DissectBuffer::new();
    add_ipv4_layer(&mut buf1, [10, 0, 0, 1], [10, 0, 0, 2]);
    dissector.dissect(&tcp_data1, &mut buf1, 20).unwrap();

    // Different source IP
    let tcp_data2 = build_tcp_packet(12345, 80, 0, 0, 0x02);
    let mut buf2 = DissectBuffer::new();
    add_ipv4_layer(&mut buf2, [10, 0, 0, 3], [10, 0, 0, 2]);
    dissector.dissect(&tcp_data2, &mut buf2, 20).unwrap();

    let sid1 = buf1
        .layer_by_name("TCP")
        .and_then(|l| buf1.field_by_name(l, "stream_id"))
        .unwrap();
    let sid2 = buf2
        .layer_by_name("TCP")
        .and_then(|l| buf2.field_by_name(l, "stream_id"))
        .unwrap();
    assert_ne!(
        sid1.value, sid2.value,
        "different 4-tuples must produce different stream_ids"
    );
}

#[test]
fn tcp_stream_id_absent_without_ip() {
    let tcp_data = build_tcp_packet(12345, 80, 0, 0, 0x02);
    let mut buf = DissectBuffer::new(); // No IP layer
    let dissector = TcpDissector::new();
    dissector.dissect(&tcp_data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    assert!(
        buf.field_by_name(layer, "stream_id").is_none(),
        "stream_id should be absent without IP layer"
    );
}

#[test]
fn tcp_stream_id_present_ipv6() {
    let tcp_data = build_tcp_packet(12345, 80, 0, 0, 0x02);
    let mut src_ip = [0u8; 16];
    src_ip[15] = 1; // ::1
    let mut dst_ip = [0u8; 16];
    dst_ip[15] = 2; // ::2
    let mut buf = DissectBuffer::new();
    add_ipv6_layer(&mut buf, src_ip, dst_ip);
    let dissector = TcpDissector::new();
    dissector.dissect(&tcp_data, &mut buf, 40).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    let stream_id = buf.field_by_name(layer, "stream_id");
    assert!(stream_id.is_some(), "stream_id should be present with IPv6");
    assert!(matches!(stream_id.unwrap().value, FieldValue::U32(_)));
}

/// Both directions of the same TCP connection must map to the same stream_id
/// (canonicalized 4-tuple).
#[test]
fn tcp_stream_id_bidirectional() {
    let dissector = TcpDissector::new();

    // Forward: 10.0.0.1:12345 -> 10.0.0.2:80
    let tcp_fwd = build_tcp_packet(12345, 80, 100, 0, 0x02);
    let mut buf_fwd = DissectBuffer::new();
    add_ipv4_layer(&mut buf_fwd, [10, 0, 0, 1], [10, 0, 0, 2]);
    dissector.dissect(&tcp_fwd, &mut buf_fwd, 20).unwrap();

    // Reverse: 10.0.0.2:80 -> 10.0.0.1:12345
    let tcp_rev = build_tcp_packet(80, 12345, 200, 101, 0x12);
    let mut buf_rev = DissectBuffer::new();
    add_ipv4_layer(&mut buf_rev, [10, 0, 0, 2], [10, 0, 0, 1]);
    dissector.dissect(&tcp_rev, &mut buf_rev, 20).unwrap();

    let sid_fwd = buf_fwd
        .layer_by_name("TCP")
        .and_then(|l| buf_fwd.field_by_name(l, "stream_id"))
        .unwrap();
    let sid_rev = buf_rev
        .layer_by_name("TCP")
        .and_then(|l| buf_rev.field_by_name(l, "stream_id"))
        .unwrap();
    assert_eq!(
        sid_fwd.value, sid_rev.value,
        "reverse direction must produce the same stream_id"
    );
}

#[test]
fn tcp_stream_id_sequential() {
    let dissector = TcpDissector::new();

    // First stream: 10.0.0.1:12345 -> 10.0.0.2:80
    let tcp_data1 = build_tcp_packet(12345, 80, 0, 0, 0x02);
    let mut buf1 = DissectBuffer::new();
    add_ipv4_layer(&mut buf1, [10, 0, 0, 1], [10, 0, 0, 2]);
    dissector.dissect(&tcp_data1, &mut buf1, 20).unwrap();

    // Second stream: 10.0.0.3:54321 -> 10.0.0.4:443
    let tcp_data2 = build_tcp_packet(54321, 443, 0, 0, 0x02);
    let mut buf2 = DissectBuffer::new();
    add_ipv4_layer(&mut buf2, [10, 0, 0, 3], [10, 0, 0, 4]);
    dissector.dissect(&tcp_data2, &mut buf2, 20).unwrap();

    let sid1 = buf1
        .layer_by_name("TCP")
        .and_then(|l| buf1.field_by_name(l, "stream_id"))
        .unwrap()
        .value
        .as_u32()
        .unwrap();
    let sid2 = buf2
        .layer_by_name("TCP")
        .and_then(|l| buf2.field_by_name(l, "stream_id"))
        .unwrap()
        .value
        .as_u32()
        .unwrap();

    assert_eq!(sid1, 0, "first stream should get id 0");
    assert_eq!(sid2, 1, "second stream should get id 1");
}
