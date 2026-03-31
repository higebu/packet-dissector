//! Zero-allocation dissection tests for the IPv6 dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ipv6::Ipv6Dissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_ipv6() {
    // Minimal IPv6 header: 40 bytes fixed.
    let raw: &[u8] = &[
        0x60, 0x00, 0x00, 0x00, // version=6, TC=0, flow label=0
        0x00, 0x14, // payload length = 20
        0x06, // next header = TCP
        0x40, // hop limit = 64
        // src: 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // dst: 2001:db8::2
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Ipv6Dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "IPv6 dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "IPv6");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 8);
    assert_eq!(fields[0].value, FieldValue::U8(6)); // version
    assert_eq!(fields[4].value, FieldValue::U8(6)); // next_header = TCP
}
