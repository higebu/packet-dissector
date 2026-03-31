//! Zero-allocation dissection tests for the MPLS dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_mpls::MplsDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Build a single MPLS label stack entry.
fn mpls_entry(label: u32, tc: u8, s: u8, ttl: u8) -> [u8; 4] {
    let word: u32 =
        (label << 12) | ((tc as u32 & 0x07) << 9) | ((s as u32 & 0x01) << 8) | ttl as u32;
    word.to_be_bytes()
}

#[test]
fn zero_alloc_dissect_mpls_single_label() {
    let raw = mpls_entry(100, 0, 1, 64);

    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        MplsDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "MPLS single-label dissect allocated {allocs} times, expected 0"
    );

    // Verify the dissected data is correct.
    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "MPLS");
}

#[test]
fn zero_alloc_dissect_mpls_two_labels() {
    let outer = mpls_entry(200, 5, 0, 128);
    let inner = mpls_entry(300, 3, 1, 64);
    let mut raw = Vec::new();
    raw.extend_from_slice(&outer);
    raw.extend_from_slice(&inner);

    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        MplsDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "MPLS two-label dissect allocated {allocs} times, expected 0"
    );

    // Verify the dissected data is correct.
    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "MPLS");
}
