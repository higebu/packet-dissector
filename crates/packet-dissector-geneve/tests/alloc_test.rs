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
    // GENEVE with OptLen=2: one option with 4 bytes of data (RFC 8926 §3.5 —
    // https://www.rfc-editor.org/rfc/rfc8926#section-3.5).
    let raw: &[u8] = &[
        0x02, // Ver=0, OptLen=2
        0x00, // O=0, C=0
        0x65, 0x58, // Protocol Type
        0x00, 0x00, 0x01, // VNI = 1
        0x00, // Reserved
        0x01, 0x02, 0x80, 0x01, // Option: class 0x0102, type 0x80, length 1
        0xDE, 0xAD, 0xBE, 0xEF, // Option data
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
    // 8 fixed + options + tunnel_options array + 1 option object with 6 fields
    assert_eq!(fields.len(), 17);
}
