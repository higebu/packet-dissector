//! Zero-allocation dissection tests for the BGP dissector.

use packet_dissector_bgp::BgpDissector;
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_bgp_keepalive() {
    let mut raw = vec![0xFF; 16]; // Marker
    raw.extend_from_slice(&19u16.to_be_bytes()); // Length
    raw.push(4); // Type = KEEPALIVE

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "BGP keepalive dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_bgp_open() {
    let mut raw = vec![0xFF; 16]; // Marker
    raw.extend_from_slice(&29u16.to_be_bytes()); // Length
    raw.push(1); // Type = OPEN
    raw.push(4); // Version
    raw.extend_from_slice(&65001u16.to_be_bytes()); // My AS
    raw.extend_from_slice(&180u16.to_be_bytes()); // Hold Time
    raw.extend_from_slice(&[10, 0, 0, 1]); // BGP Identifier
    raw.push(0); // Opt Params Len

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "BGP open dissect allocated {allocs} times");
}
