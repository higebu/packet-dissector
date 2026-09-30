//! Zero-allocation dissection tests for the BMP dissector.

use packet_dissector_bmp::BmpDissector;
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Common header followed by `rest`.
fn bmp(msg_type: u8, rest: &[u8]) -> Vec<u8> {
    let mut v = vec![3];
    v.extend_from_slice(&((6 + rest.len()) as u32).to_be_bytes());
    v.push(msg_type);
    v.extend_from_slice(rest);
    v
}

/// Per-peer header of an IPv4 Global Instance Peer.
fn per_peer_header() -> Vec<u8> {
    let mut v = vec![0, 0];
    v.extend_from_slice(&[0; 8]);
    v.extend_from_slice(&[0; 12]);
    v.extend_from_slice(&[192, 0, 2, 1]);
    v.extend_from_slice(&65001u32.to_be_bytes());
    v.extend_from_slice(&[192, 0, 2, 1]);
    v.extend_from_slice(&[0; 8]);
    v
}

fn bgp(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF; 16];
    v.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    v.push(msg_type);
    v.extend_from_slice(body);
    v
}

fn assert_zero_alloc(raw: &[u8], what: &str) {
    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so capacity is allocated.
    BmpDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        BmpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "BMP {what} dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_bmp_route_monitoring() {
    let mut rest = per_peer_header();
    let attrs: &[u8] = &[0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xFD, 0xE9];
    let mut body = vec![0, 0];
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(attrs);
    body.extend_from_slice(&[24, 198, 51, 100]);
    rest.extend_from_slice(&bgp(2, &body));
    assert_zero_alloc(&bmp(0, &rest), "Route Monitoring");
}

#[test]
fn zero_alloc_dissect_bmp_peer_up() {
    let mut rest = per_peer_header();
    rest.extend_from_slice(&[0; 12]);
    rest.extend_from_slice(&[192, 0, 2, 2, 0, 179, 0xC3, 0x50]);
    let open = bgp(1, &[4, 0xFD, 0xE9, 0, 180, 10, 0, 0, 1, 0]);
    rest.extend_from_slice(&open);
    rest.extend_from_slice(&open);
    rest.extend_from_slice(&[0, 0, 0, 4, b'p', b'e', b'e', b'r']);
    assert_zero_alloc(&bmp(3, &rest), "Peer Up");
}

#[test]
fn zero_alloc_dissect_bmp_stats_report() {
    let mut rest = per_peer_header();
    rest.extend_from_slice(&2u32.to_be_bytes());
    rest.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 7]);
    rest.extend_from_slice(&[0, 9, 0, 11, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 42]);
    assert_zero_alloc(&bmp(1, &rest), "Stats Report");
}

#[test]
fn zero_alloc_dissect_bmp_initiation() {
    let rest = [0, 2, 0, 2, b'r', b'1', 0, 1, 0, 2, b'o', b's'];
    assert_zero_alloc(&bmp(4, &rest), "Initiation");
}
