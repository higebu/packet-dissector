//! Zero-allocation dissection tests for the TCP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_tcp::TcpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_tcp() {
    // Minimal TCP header: 20 bytes (data offset = 5, no options).
    let raw: &[u8] = &[
        0xd4, 0x31, // src port = 54321
        0x00, 0x50, // dst port = 80
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x00, // acknowledgment number
        0x50, // data offset = 5 (20 bytes), reserved = 0
        0x02, // flags: SYN
        0xff, 0xff, // window size
        0x00, 0x00, // checksum (unchecked)
        0x00, 0x00, // urgent pointer
    ];
    let dissector = TcpDissector::default();
    let mut buf = DissectBuffer::new();

    // First call initializes LazyLock for TCP_FLAGS_NAMES.
    buf.clear();
    dissector.dissect(raw, &mut buf, 0).unwrap();

    // Second call must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "TCP dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "TCP");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 11); // 11 fields (no options, no stream_id without IP layer)
    assert_eq!(fields[0].value, FieldValue::U16(54321)); // src_port
    assert_eq!(fields[1].value, FieldValue::U16(80)); // dst_port
    assert_eq!(fields[7].value, FieldValue::U8(0x02)); // flags: SYN
}

#[test]
fn zero_alloc_dissect_tcp_options() {
    // SYN with MSS, SACK-Permitted, Timestamps, NOP, Window Scale, then an
    // ACK-style SACK option with two blocks (data offset = 15, 40 bytes).
    let raw: &[u8] = &[
        0xd4, 0x31, 0x00, 0x50, // ports
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x00, // acknowledgment number
        0xf1, // data offset = 15, AE = 1
        0xc2, // flags: CWR, ECE, SYN
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00, // window, checksum, urgent
        0x02, 0x04, 0x05, 0xb4, // MSS 1460
        0x04, 0x02, // SACK Permitted
        0x08, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // Timestamps
        0x01, // NOP
        0x03, 0x03, 0x07, // Window Scale 7
        0x01, 0x01, // NOP NOP
        0x05, 0x12, // SACK, 2 blocks
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, //
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, //
    ];
    let dissector = TcpDissector::default();
    let mut buf = DissectBuffer::new();

    // Warm up: grows the DissectBuffer to its steady-state capacity.
    buf.clear();
    dissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "TCP options dissect allocated {allocs} times");

    let layer = &buf.layers()[0];
    let options = buf
        .layer_fields(layer)
        .iter()
        .find(|f| f.name() == "options")
        .unwrap();
    assert!(options.value.is_array());
}
