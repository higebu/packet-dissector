//! Zero-allocation dissection tests for the LDP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ldp::LdpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Asserts that dissecting `raw` allocates nothing and decodes the field
/// `decoded` (so the intended path is exercised).
fn assert_zero_alloc(raw: &[u8], what: &str, decoded: &str) {
    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so capacity is allocated.
    LdpDissector.dissect(raw, &mut buf, 0).unwrap();
    assert!(
        buf.fields().iter().any(|f| f.name() == decoded),
        "LDP {what}: {decoded} not decoded"
    );

    let allocs = count_allocs(|| {
        buf.clear();
        LdpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "LDP {what} dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_ldp_hello() {
    let raw: &[u8] = &[
        0, 1, 0, 30, 10, 0, 0, 1, 0, 0, // PDU header
        0x01, 0x00, 0, 20, 0, 0, 0, 1, // Hello, Message ID 1
        0x04, 0x00, 0, 4, 0, 15, 0, 0, // Common Hello Parameters
        0x04, 0x01, 0, 4, 10, 0, 0, 1, // IPv4 Transport Address
    ];
    assert_zero_alloc(raw, "Hello", "transport_address");
}

#[test]
fn zero_alloc_dissect_ldp_label_mapping_pwid() {
    let raw: &[u8] = &[
        0, 1, 0, 42, 10, 0, 0, 1, 0, 0, // PDU header
        0x04, 0x00, 0, 32, 0, 0, 0, 7, // Label Mapping
        0x01, 0x00, 0, 16, // FEC TLV
        0x80, 0x80, 0x05, 8, 0, 0, 0, 1, 0, 0, 0, 100, 1, 4, 5, 0xDC, // PWid + MTU
        0x02, 0x00, 0, 4, 0, 1, 0, 0, // Generic Label
    ];
    assert_zero_alloc(raw, "Label Mapping", "mtu");
}
