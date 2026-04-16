//! Zero-allocation dissection tests for the GRE dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_gre::GreDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_gre_basic() {
    // Minimal GRE header: no optional fields, Protocol Type = IPv4.
    let raw: &[u8] = &[
        0x00, 0x00, // flags=0, version=0
        0x08, 0x00, // Protocol Type: IPv4
    ];

    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        GreDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "GRE basic dissect allocated {allocs} times, expected 0"
    );

    // Verify the dissected data is correct.
    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "GRE");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 6);
    assert_eq!(fields[0].value, FieldValue::U8(0)); // checksum_present
    assert_eq!(fields[5].value, FieldValue::U16(0x0800)); // protocol_type
}

#[test]
fn zero_alloc_dissect_gre_all_options() {
    // GRE with C=1, K=1, S=1 (16-byte header).
    let raw: &[u8] = &[
        0xB0, 0x00, // C=1, K=1, S=1
        0x08, 0x00, // Protocol Type: IPv4
        0x12, 0x34, // Checksum
        0x00, 0x00, // Reserved1
        0xDE, 0xAD, 0xBE, 0xEF, // Key
        0x00, 0x00, 0x00, 0x01, // Sequence Number
    ];

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        GreDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "GRE all-options dissect allocated {allocs} times, expected 0"
    );

    assert_eq!(buf.layers().len(), 1);
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 10);
}
