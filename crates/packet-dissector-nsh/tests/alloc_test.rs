//! Zero-allocation dissection tests for the NSH dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_nsh::NshDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

fn check(raw: &[u8]) {
    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so capacity is allocated
    NshDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        NshDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "NSH dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_nsh_md_type1() {
    // RFC 8300, Section 2.4 — MD Type 1 with a 16-byte context.
    // https://www.rfc-editor.org/rfc/rfc8300#section-2.4
    let mut raw = vec![0x0F, 0xC6, 0x01, 0x03, 0x12, 0x34, 0x56, 0xFF];
    raw.extend_from_slice(&[0u8; 16]);
    check(&raw);
}

#[test]
fn zero_alloc_dissect_nsh_md_type2() {
    // RFC 8300, Section 2.5.1 — MD Type 2 with two Context Headers.
    // https://www.rfc-editor.org/rfc/rfc8300#section-2.5.1
    let raw: &[u8] = &[
        0x0F, 0xC5, 0x02, 0x01, // Ver 0, TTL 63, Length 5, MD Type 2, NP IPv4
        0x12, 0x34, 0x56, 0xFF, // SPI, SI
        0x00, 0x00, 0x04, 0x03, 0xAA, 0xBB, 0xCC, 0x00, // Class 0, Type 4, Len 3
        0x02, 0x00, 0x01, 0x00, // Class 0x0200, Type 1, Len 0
    ];
    check(raw);
}
