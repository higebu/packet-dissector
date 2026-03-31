//! Zero-allocation dissection tests for the GENEVE dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_geneve::GeneveDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_geneve_basic() {
    // Minimal GENEVE header: no options, Protocol Type = Transparent Ethernet Bridging.
    let raw: &[u8] = &[
        0x00, // Ver=0, OptLen=0
        0x00, // O=0, C=0
        0x65, 0x58, // Protocol Type
        0x00, 0x00, 0x01, // VNI = 1
        0x00, // Reserved
    ];

    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        GeneveDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "GENEVE dissect allocated {allocs} times, expected 0"
    );

    // Verify the dissected data is correct.
    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "GENEVE");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 8);
    assert_eq!(fields[0].value, FieldValue::U8(0)); // version
    assert_eq!(fields[5].value, FieldValue::U16(0x6558)); // protocol_type
}

#[test]
fn zero_alloc_dissect_geneve_with_options() {
    // GENEVE with OptLen=1 (4 bytes of options).
    let raw: &[u8] = &[
        0x01, // Ver=0, OptLen=1
        0x00, // O=0, C=0
        0x65, 0x58, // Protocol Type
        0x00, 0x00, 0x01, // VNI = 1
        0x00, // Reserved
        0xAA, 0xBB, 0xCC, 0xDD, // Options (4 bytes)
    ];

    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        GeneveDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "GENEVE with options dissect allocated {allocs} times, expected 0"
    );

    // Verify the dissected data is correct.
    assert_eq!(buf.layers().len(), 1);
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 9); // 8 fixed + 1 options
}
