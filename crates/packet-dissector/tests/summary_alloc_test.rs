//! Zero-allocation tests for the shallow dissection APIs.
//!
//! `dissect_summary` and `dissect_projected` must preserve the
//! zero-copy / zero-allocation property of `DissectBuffer` when the buffer
//! is reused across packets.

use packet_dissector::registry::DissectorRegistry;
use packet_dissector::summary::FieldProjection;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Ethernet(14) + IPv4(20) + UDP(8) + DNS header(12) + query.
fn build_eth_ipv4_udp_dns() -> Vec<u8> {
    let mut pkt = Vec::new();

    // Ethernet
    pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());

    // IPv4
    let ipv4_start = pkt.len();
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&0u16.to_be_bytes()); // total len (placeholder)
    pkt.extend_from_slice(&[0x00; 4]);
    pkt.push(64);
    pkt.push(17); // UDP
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&[192, 168, 1, 1]);
    pkt.extend_from_slice(&[8, 8, 8, 8]);

    // UDP
    let udp_start = pkt.len();
    pkt.extend_from_slice(&12345u16.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes()); // DNS
    pkt.extend_from_slice(&0u16.to_be_bytes()); // length (placeholder)
    pkt.extend_from_slice(&[0x00; 2]);

    // DNS query for example.com A
    pkt.extend_from_slice(&0xABCDu16.to_be_bytes()); // id
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    pkt.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    pkt.extend_from_slice(&[0x00; 6]); // ancount, nscount, arcount
    pkt.push(7);
    pkt.extend_from_slice(b"example");
    pkt.push(3);
    pkt.extend_from_slice(b"com");
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    // Fix lengths
    let total_len = (pkt.len() - ipv4_start) as u16;
    pkt[ipv4_start + 2..ipv4_start + 4].copy_from_slice(&total_len.to_be_bytes());
    let udp_len = (pkt.len() - udp_start) as u16;
    pkt[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());

    pkt
}

/// Ethernet(14) + IPv4(20) + TCP(20) — TCP SYN to port 443 (TLS).
fn build_eth_ipv4_tcp() -> Vec<u8> {
    let mut pkt = Vec::new();

    // Ethernet
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());

    // IPv4
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&40u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 4]);
    pkt.push(64);
    pkt.push(6); // TCP
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);

    // TCP
    pkt.extend_from_slice(&54321u16.to_be_bytes());
    pkt.extend_from_slice(&443u16.to_be_bytes());
    pkt.extend_from_slice(&1u32.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.push(0x50);
    pkt.push(0x02); // SYN
    pkt.extend_from_slice(&65535u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&[0x00; 2]);

    pkt
}

#[test]
fn zero_alloc_dissect_summary_udp() {
    let registry = DissectorRegistry::default();
    let pkt = build_eth_ipv4_udp_dns();
    let mut buf = DissectBuffer::new();

    // Warm up once so Vec capacities are grown before counting.
    registry.dissect_summary(&pkt, &mut buf).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        registry.dissect_summary(&pkt, &mut buf).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "dissect_summary allocated {allocs} times, expected 0"
    );

    assert_eq!(buf.layers().len(), 3);
}

#[test]
fn zero_alloc_dissect_summary_tcp() {
    let registry = DissectorRegistry::default();
    let pkt = build_eth_ipv4_tcp();
    let mut buf = DissectBuffer::new();

    registry.dissect_summary(&pkt, &mut buf).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        registry.dissect_summary(&pkt, &mut buf).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "dissect_summary allocated {allocs} times, expected 0"
    );

    assert_eq!(buf.layers().len(), 3);
}

#[test]
fn zero_alloc_dissect_projected() {
    let registry = DissectorRegistry::default();
    let pkt = build_eth_ipv4_udp_dns();
    let mut buf = DissectBuffer::new();
    // Building the projection may allocate (setup cost, once per session).
    let mut projection = FieldProjection::new([
        ("IPv4", "src"),
        ("IPv4", "dst"),
        ("UDP", "src_port"),
        ("UDP", "dst_port"),
    ]);

    registry
        .dissect_projected(&pkt, &mut buf, &mut projection)
        .unwrap();

    // Per-packet dissection with a reused projection must not allocate.
    let allocs = count_allocs(|| {
        buf.clear();
        registry
            .dissect_projected(&pkt, &mut buf, &mut projection)
            .unwrap();
    });
    assert_eq!(
        allocs, 0,
        "dissect_projected allocated {allocs} times, expected 0"
    );

    assert!(projection.is_satisfied());
    assert_eq!(buf.layers().len(), 3);
}
