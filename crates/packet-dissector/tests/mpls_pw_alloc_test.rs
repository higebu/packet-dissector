//! Zero-allocation tests for MPLS label decode-as rules.
//!
//! # API Behavior Coverage
//!
//! | Behavior | Test |
//! |----------|------|
//! | Dissecting through an MPLS label rule is zero-allocation | zero_alloc_dissect_mpls_label_rule |

#![cfg(all(feature = "mpls", feature = "ethernet", feature = "ipv4"))]

use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Ethernet → MPLS (label 16) → Ethernet PW without a control word → IPv4.
fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x00; 12]);
    pkt.extend_from_slice(&0x8847u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01, 0x01, 0x40]); // label 16, S=1, TTL 64
    pkt.extend_from_slice(&[0x40, 0x11, 0x22, 0x33, 0x44, 0x55]); // DA, nibble 4
    pkt.extend_from_slice(&[0x66; 6]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    pkt.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0xff, 0x00, 0x00, 10, 0, 0, 1, 10, 0,
        0, 2,
    ]);
    pkt
}

#[test]
fn zero_alloc_dissect_mpls_label_rule() {
    let mut reg = DissectorRegistry::default();
    let pw_eth = reg.create_dissector_by_name("pw-eth").unwrap();
    reg.register_by_mpls_label(16, pw_eth).unwrap();
    let pkt = build_packet();
    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so capacity is allocated
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers()[2].name, "Ethernet");

    let allocs = count_allocs(|| {
        buf.clear();
        reg.dissect(&pkt, &mut buf).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "MPLS label rule dissect allocated {allocs} times"
    );
}
