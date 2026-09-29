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

#[test]
fn zero_alloc_dissect_mpls_gal_ach() {
    // RFC 5586 — GAL followed by an ACH with channel type 0x0007.
    // https://www.rfc-editor.org/rfc/rfc5586#section-4
    let mut raw = mpls_entry(13, 0, 1, 1).to_vec();
    raw.extend_from_slice(&[0x10, 0x00, 0x00, 0x07]);

    let mut buf = DissectBuffer::new();
    let allocs = count_allocs(|| {
        buf.clear();
        MplsDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "MPLS GAL/ACH dissect allocated {allocs} times, expected 0"
    );
    assert_eq!(buf.layers().len(), 2);
}

#[test]
fn zero_alloc_dissect_mpls_pw_control_word() {
    // RFC 4385 §3 — control word followed by an Ethernet header.
    // https://www.rfc-editor.org/rfc/rfc4385#section-3
    let mut raw = mpls_entry(16, 0, 1, 64).to_vec();
    raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    raw.extend_from_slice(&[0x02; 12]);
    raw.extend_from_slice(&[0x08, 0x00]);

    let mut buf = DissectBuffer::new();
    let allocs = count_allocs(|| {
        buf.clear();
        MplsDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "MPLS PW-CW dissect allocated {allocs} times, expected 0"
    );
    assert_eq!(buf.layers().len(), 2);
}
