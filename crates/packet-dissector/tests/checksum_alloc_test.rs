//! Zero-allocation tests for checksum verification.
//!
//! Checksum verification (`DissectorRegistry::set_verify_checksums`) must
//! keep full dissection free of heap allocations.
//!
//! # API Behavior Coverage
//!
//! | Behavior | Test |
//! |----------|------|
//! | IPv4 + UDP + DNS with verification is zero-allocation | zero_alloc_verify_checksums_ipv4_udp |
//! | IPv4 + ICMP with verification is zero-allocation | zero_alloc_verify_checksums_ipv4_icmp |
//! | IPv6 + ICMPv6 with verification is zero-allocation | zero_alloc_verify_checksums_ipv6_icmpv6 |
//! | IPv4 + TCP with verification is zero-allocation | zero_alloc_verify_checksums_ipv4_tcp |

use packet_dissector::checksum::internet_checksum;
use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

const SRC4: [u8; 4] = [192, 0, 2, 1];
const DST4: [u8; 4] = [198, 51, 100, 2];

/// Ethernet + IPv4 carrying `l4`, with the Header Checksum and the upper-layer
/// checksum at `csum_at` filled in (pseudo-header unless `protocol` is ICMP).
fn eth_ipv4(protocol: u8, mut l4: Vec<u8>, csum_at: usize) -> Vec<u8> {
    let mut pseudo = Vec::new();
    if protocol != 1 {
        pseudo.extend_from_slice(&SRC4);
        pseudo.extend_from_slice(&DST4);
        pseudo.extend_from_slice(&[0, protocol]);
        pseudo.extend_from_slice(&(l4.len() as u16).to_be_bytes());
    }
    let c = internet_checksum(&[&pseudo, &l4]);
    l4[csum_at..csum_at + 2].copy_from_slice(&c.to_be_bytes());

    let mut pkt = vec![0x02; 12];
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    let mut ip = vec![0x45, 0x00];
    ip.extend_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, protocol, 0, 0]);
    ip.extend_from_slice(&SRC4);
    ip.extend_from_slice(&DST4);
    let c = internet_checksum(&[&ip]);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&l4);
    pkt
}

/// Dissect `pkt` once to warm up, then assert that dissecting it again
/// allocates nothing and reports `layer`'s checksum as good.
fn assert_zero_alloc_good(pkt: &[u8], layer: &str) {
    let mut registry = DissectorRegistry::default();
    registry.set_verify_checksums(true);
    let mut buf = DissectBuffer::new();
    registry.dissect(pkt, &mut buf).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        registry.dissect(pkt, &mut buf).unwrap();
    });
    assert_eq!(allocs, 0, "{layer}: dissect allocated {allocs} times");

    let l = buf.layer_by_name(layer).unwrap();
    assert_eq!(
        buf.field_by_name(l, "checksum_status").unwrap().value,
        FieldValue::U8(1),
        "{layer}"
    );
}

#[test]
fn zero_alloc_verify_checksums_ipv4_udp() {
    let mut udp = vec![0x30, 0x39, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00];
    // DNS query for example.com A.
    udp.extend_from_slice(&[0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    udp.push(7);
    udp.extend_from_slice(b"example");
    udp.push(3);
    udp.extend_from_slice(b"com");
    udp.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]);
    let len = udp.len() as u16;
    udp[4..6].copy_from_slice(&len.to_be_bytes());
    assert_zero_alloc_good(&eth_ipv4(17, udp, 6), "UDP");
}

#[test]
fn zero_alloc_verify_checksums_ipv4_icmp() {
    let icmp = vec![8, 0, 0, 0, 0x00, 0x01, 0x00, 0x02, b'p', b'i', b'n', b'g'];
    assert_zero_alloc_good(&eth_ipv4(1, icmp, 2), "ICMP");
}

#[test]
fn zero_alloc_verify_checksums_ipv4_tcp() {
    let tcp = vec![
        0x9C, 0x40, 0x00, 0x09, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xFF, 0xFF, 0, 0, 0, 0,
    ];
    assert_zero_alloc_good(&eth_ipv4(6, tcp, 16), "TCP");
}

#[test]
fn zero_alloc_verify_checksums_ipv6_icmpv6() {
    let src: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let mut icmp = vec![128, 0, 0, 0, 0x00, 0x01, 0x00, 0x02, b'a'];
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    let c = internet_checksum(&[&pseudo, &icmp]);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());

    let mut pkt = vec![0x02; 12];
    pkt.extend_from_slice(&0x86DDu16.to_be_bytes());
    pkt.extend_from_slice(&[0x60, 0, 0, 0]);
    pkt.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&[58, 64]);
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(&icmp);
    assert_zero_alloc_good(&pkt, "ICMPv6");
}
