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

#[test]
fn zero_alloc_dissect_bgp_update_add_path() {
    // UPDATE with RFC 7911 ADD-PATH withdrawn routes and NLRI
    // (https://www.rfc-editor.org/rfc/rfc7911#section-3), which exercises the
    // per-entry Object containers and the ADD-PATH detection heuristic.
    let withdrawn = [0, 0, 0, 1, 8, 10, 0, 0, 0, 2, 8, 10];
    let nlri = [0, 0, 0, 1, 24, 192, 168, 1, 0, 0, 0, 2, 24, 192, 168, 1];

    let mut raw = vec![0xFF; 16]; // Marker
    let total_len = 19 + 2 + withdrawn.len() + 2 + nlri.len();
    raw.extend_from_slice(&(total_len as u16).to_be_bytes()); // Length
    raw.push(2); // Type = UPDATE
    raw.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
    raw.extend_from_slice(&withdrawn);
    raw.extend_from_slice(&0u16.to_be_bytes()); // Total Path Attribute Length
    raw.extend_from_slice(&nlri);

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "BGP ADD-PATH update dissect allocated {allocs} times"
    );
}
