//! Zero-allocation dissection tests for the PPP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ppp::PppDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_ppp_ipv4() {
    let raw: &[u8] = &[0x00, 0x21, 0x45, 0x00, 0x00, 0x14];
    let mut buf = DissectBuffer::new();
    PppDissector.dissect(raw, &mut buf, 0).unwrap();
    let allocs = count_allocs(|| {
        buf.clear();
        PppDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "PPP dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_ppp_lcp() {
    let raw: &[u8] = &[0xC0, 0x21, 0x01, 0x01, 0x00, 0x08, 1, 4, 0x05, 0xDC];
    let mut buf = DissectBuffer::new();
    PppDissector.dissect(raw, &mut buf, 0).unwrap();
    let allocs = count_allocs(|| {
        buf.clear();
        PppDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "PPP LCP dissect allocated {allocs} times");
}
