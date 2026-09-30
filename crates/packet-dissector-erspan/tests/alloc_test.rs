//! Zero-allocation dissection tests for the ERSPAN dissectors.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_erspan::{ErspanDissector, ErspanType3Dissector};
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_erspan_type2() {
    // Type II header (Ver=1, VLAN=100, Session ID=0x155, Index=0xABCDE).
    let raw: &[u8] = &[0x10, 0x64, 0xB5, 0x55, 0x00, 0x0A, 0xBC, 0xDE];
    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so capacity is allocated
    ErspanDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        ErspanDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "ERSPAN Type II dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_erspan_type3_subheader() {
    // Type III header (Ver=2, FT=0, O=1) followed by a Platf ID 0x3
    // sub-header.
    let raw: &[u8] = &[
        0x21, 0x23, 0x6A, 0xAA, 0x01, 0x02, 0x03, 0x04, 0xBE, 0xEF, 0x82, 0xAD, 0x0C, 0x00, 0x01,
        0x02, 0xDE, 0xAD, 0xBE, 0xEF,
    ];
    let mut buf = DissectBuffer::new();
    ErspanType3Dissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        ErspanType3Dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "ERSPAN Type III dissect allocated {allocs} times"
    );
}
