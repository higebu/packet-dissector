//! Zero-allocation dissection tests for the ICMPv6 dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_icmpv6::Icmpv6Dissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_icmpv6_echo() {
    // ICMPv6 Echo Request: type(1)+code(1)+checksum(2)+id(2)+seq(2) = 8 bytes.
    let raw: &[u8] = &[
        0x80, // type = 128 (Echo Request)
        0x00, // code = 0
        0x00, 0x00, // checksum (unchecked)
        0x56, 0x78, // identifier
        0x00, 0x2a, // sequence = 42
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Icmpv6Dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "ICMPv6 dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "ICMPv6");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields[0].value, FieldValue::U8(128)); // type
    assert_eq!(fields[3].value, FieldValue::U16(0x5678)); // identifier
}

#[test]
fn zero_alloc_dissect_icmpv6_neighbor_solicitation() {
    // ICMPv6 Neighbor Solicitation: type(1)+code(1)+checksum(2)+reserved(4)+target(16) = 24 bytes.
    let raw: &[u8] = &[
        0x87, // type = 135 (Neighbor Solicitation)
        0x00, // code = 0
        0x00, 0x00, // checksum
        0x00, 0x00, 0x00, 0x00, // reserved
        // target: fe80::1
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Icmpv6Dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "ICMPv6 NS dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "ICMPv6");
}

#[test]
fn zero_alloc_dissect_icmpv6_router_advertisement() {
    // ICMPv6 Router Advertisement: type(1)+code(1)+checksum(2)+cur_hop(1)+flags(1)+
    // router_lifetime(2)+reachable_time(4)+retrans_timer(4) = 16 bytes.
    let raw: &[u8] = &[
        0x86, // type = 134 (Router Advertisement)
        0x00, // code = 0
        0x00, 0x00, // checksum
        0x40, // current hop limit = 64
        0xC0, // flags: M=1, O=1
        0x07, 0x08, // router lifetime = 1800s
        0x00, 0x00, 0x00, 0x00, // reachable time
        0x00, 0x00, 0x00, 0x00, // retrans timer
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Icmpv6Dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "ICMPv6 RA dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "ICMPv6");
}

#[test]
fn zero_alloc_dissect_icmpv6_new_decoders() {
    // Neighbor Solicitation with Nonce (RFC 3971) and PvD ID (RFC 8801)
    // options, an RPL DIO with a DODAG Configuration option (RFC 6550) and a
    // Time Exceeded with an RFC 4884 Extension Structure.
    let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
    ns.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    ns.extend_from_slice(&[0x0e, 0x01, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]);
    ns.extend_from_slice(&[21, 3, 0x80, 0x01, 0x00, 0x7B]);
    ns.extend_from_slice(b"\x07example\x03org\x00\x00\x00\x00\x00\x00");

    let mut dio = vec![
        155, 0x01, 0, 0, 0x1E, 0x02, 0x01, 0x00, 0x8B, 0x05, 0x00, 0x00,
    ];
    dio.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    dio.extend_from_slice(&[
        0x04, 0x0E, 0x09, 0x08, 0x0C, 0x0A, 0x08, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x1E, 0x00,
        0x3C,
    ]);

    let mut te = vec![3, 0, 0, 0, 16, 0, 0, 0];
    let mut original = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
    original.resize(40, 0);
    original.extend_from_slice(&[0x30, 0x39, 0x82, 0x9A, 0, 8, 0, 0]);
    original.resize(128, 0);
    te.extend_from_slice(&original);
    te.extend_from_slice(&[0x20, 0, 0, 0, 0, 8, 1, 1, 0x12, 0x34, 0x5B, 0x40]);

    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so field capacity is allocated.
    for pkt in [&ns, &dio, &te] {
        buf.clear();
        Icmpv6Dissector.dissect(pkt, &mut buf, 0).unwrap();
    }

    let allocs = count_allocs(|| {
        for pkt in [&ns, &dio, &te] {
            buf.clear();
            Icmpv6Dissector.dissect(pkt, &mut buf, 0).unwrap();
        }
    });
    assert_eq!(allocs, 0, "ICMPv6 dissect allocated {allocs} times");
}
