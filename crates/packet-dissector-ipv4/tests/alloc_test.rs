//! Zero-allocation dissection tests for the IPv4 dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ipv4::Ipv4Dissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_ipv4() {
    // Minimal IPv4 header: 20 bytes (IHL=5, no options).
    let raw: &[u8] = &[
        0x45, // version=4, IHL=5
        0x00, // DSCP/ECN
        0x00, 0x14, // total length = 20
        0x00, 0x01, // identification
        0x00, 0x00, // flags + fragment offset
        0x40, // TTL = 64
        0x06, // protocol = TCP
        0x00, 0x00, // header checksum (unchecked)
        0xc0, 0xa8, 0x01, 0x64, // src: 192.168.1.100
        0x08, 0x08, 0x08, 0x08, // dst: 8.8.8.8
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Ipv4Dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "IPv4 dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "IPv4");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 13); // 13 fields (no options)
    assert_eq!(fields[0].value, FieldValue::U8(4)); // version
    assert_eq!(fields[11].value, FieldValue::Ipv4Addr([192, 168, 1, 100])); // src
    assert_eq!(fields[12].value, FieldValue::Ipv4Addr([8, 8, 8, 8])); // dst
}
