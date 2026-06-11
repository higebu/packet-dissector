//! Tests for the shallow dissection APIs:
//! [`DissectorRegistry::dissect_summary`] and
//! [`DissectorRegistry::dissect_projected`].
//!
//! These APIs stop the dispatch loop early so that row summaries
//! (src/dst/protocol) and targeted field extraction do not pay the cost of
//! building the full field tree for application-layer protocols.

use packet_dissector::registry::DissectorRegistry;
use packet_dissector::summary::FieldProjection;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;

/// Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes — a minimal TCP SYN packet.
fn build_eth_ipv4_tcp(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut pkt = Vec::new();

    // Ethernet
    pkt.extend_from_slice(&[0x00; 6]); // dst
    pkt.extend_from_slice(&[0x00; 6]); // src
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());

    // IPv4
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&40u16.to_be_bytes()); // total len
    pkt.extend_from_slice(&[0x00; 4]); // id, flags, frag
    pkt.push(64); // ttl
    pkt.push(6); // TCP
    pkt.extend_from_slice(&[0x00; 2]); // checksum
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);

    // TCP
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&1u32.to_be_bytes()); // seq
    pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
    pkt.push(0x50); // data offset = 5
    pkt.push(0x02); // SYN
    pkt.extend_from_slice(&65535u16.to_be_bytes()); // window
    pkt.extend_from_slice(&[0x00; 2]); // checksum
    pkt.extend_from_slice(&[0x00; 2]); // urgent

    pkt
}

/// Ethernet(14) + IPv4(20) + UDP(8) + DNS query = ~55 bytes.
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
    // QNAME: example.com
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

/// Ethernet(14) + ARP(28) = 42 bytes.
fn build_eth_arp() -> Vec<u8> {
    let mut pkt = Vec::new();

    // Ethernet
    pkt.extend_from_slice(&[0xff; 6]); // broadcast
    pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    pkt.extend_from_slice(&0x0806u16.to_be_bytes());

    // ARP
    pkt.extend_from_slice(&1u16.to_be_bytes()); // HTYPE
    pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // PTYPE
    pkt.push(6);
    pkt.push(4);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // request
    pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    pkt.extend_from_slice(&[192, 168, 1, 1]);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[192, 168, 1, 2]);

    pkt
}

fn layer_names(buf: &DissectBuffer<'_>) -> Vec<&'static str> {
    buf.layers().iter().map(|l| l.name).collect()
}

// ---------------------------------------------------------------------------
// dissect_summary
// ---------------------------------------------------------------------------

#[test]
fn summary_stops_before_udp_application_layer() {
    let registry = DissectorRegistry::default();
    let pkt = build_eth_ipv4_udp_dns();
    let mut buf = DissectBuffer::new();

    let summary = registry.dissect_summary(&pkt, &mut buf).unwrap();

    // The DNS layer must NOT be dissected; only L2–L4 layers are present.
    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4", "UDP"]);
    // The next protocol's name is still resolved for display purposes.
    assert_eq!(summary.next_protocol, Some("DNS"));

    // src/dst/ports are available for row summaries.
    let ipv4 = buf.layer_by_name("IPv4").unwrap();
    assert_eq!(
        buf.field_by_name(ipv4, "src").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 1])
    );
    let udp = buf.layer_by_name("UDP").unwrap();
    assert_eq!(buf.field_u16(udp, "dst_port"), Some(53));
}

#[test]
fn summary_stops_before_tcp_application_layer() {
    let registry = DissectorRegistry::default();
    let pkt = build_eth_ipv4_tcp(54321, 443);
    let mut buf = DissectBuffer::new();

    let summary = registry.dissect_summary(&pkt, &mut buf).unwrap();

    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4", "TCP"]);
    assert_eq!(summary.next_protocol, Some("TLS"));
}

#[test]
fn summary_reports_no_next_protocol_for_unregistered_ports() {
    let registry = DissectorRegistry::default();
    let pkt = build_eth_ipv4_tcp(54321, 49999);
    let mut buf = DissectBuffer::new();

    let summary = registry.dissect_summary(&pkt, &mut buf).unwrap();

    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4", "TCP"]);
    assert_eq!(summary.next_protocol, None);
}

#[test]
fn summary_dissects_port_less_chains_fully() {
    let registry = DissectorRegistry::default();
    let pkt = build_eth_arp();
    let mut buf = DissectBuffer::new();

    let summary = registry.dissect_summary(&pkt, &mut buf).unwrap();

    // ARP terminates the chain without a port-based hint, so the result is
    // identical to a full dissect.
    assert_eq!(layer_names(&buf), ["Ethernet", "ARP"]);
    assert_eq!(summary.next_protocol, None);
}

#[test]
fn summary_with_link_type_uses_link_type_table() {
    let registry = DissectorRegistry::default();
    let pkt = build_eth_ipv4_udp_dns();
    let mut buf = DissectBuffer::new();

    // LINKTYPE_ETHERNET (1) is not registered in the link-type table, so it
    // falls back to the default entry dissector — same result as above.
    let summary = registry
        .dissect_summary_with_link_type(&pkt, 1, &mut buf)
        .unwrap();

    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4", "UDP"]);
    assert_eq!(summary.next_protocol, Some("DNS"));
}

// ---------------------------------------------------------------------------
// dissect_projected
// ---------------------------------------------------------------------------

#[test]
fn projection_stops_at_first_layer_when_satisfied() {
    let registry = DissectorRegistry::default();
    let pkt = build_eth_ipv4_udp_dns();
    let mut buf = DissectBuffer::new();
    let mut projection = FieldProjection::new([("Ethernet", "src"), ("Ethernet", "dst")]);

    registry
        .dissect_projected(&pkt, &mut buf, &mut projection)
        .unwrap();

    assert!(projection.is_satisfied());
    // Only the entry layer was dissected.
    assert_eq!(layer_names(&buf), ["Ethernet"]);
}

#[test]
fn projection_stops_after_transport_layer() {
    let registry = DissectorRegistry::default();
    let pkt = build_eth_ipv4_udp_dns();
    let mut buf = DissectBuffer::new();
    let mut projection = FieldProjection::new([
        ("IPv4", "src"),
        ("IPv4", "dst"),
        ("UDP", "src_port"),
        ("UDP", "dst_port"),
    ]);

    registry
        .dissect_projected(&pkt, &mut buf, &mut projection)
        .unwrap();

    assert!(projection.is_satisfied());
    assert!(projection.is_found("UDP", "src_port"));
    // DNS is never dissected.
    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4", "UDP"]);

    let udp = buf.layer_by_name("UDP").unwrap();
    assert_eq!(buf.field_u16(udp, "src_port"), Some(12345));
}

#[test]
fn projection_falls_back_to_full_dissect_when_unsatisfied() {
    let registry = DissectorRegistry::default();
    let pkt = build_eth_ipv4_udp_dns();
    let mut buf = DissectBuffer::new();
    let mut projection = FieldProjection::new([("DNS", "no_such_field")]);

    registry
        .dissect_projected(&pkt, &mut buf, &mut projection)
        .unwrap();

    assert!(!projection.is_satisfied());
    assert!(!projection.is_found("DNS", "no_such_field"));
    // The chain ran to completion, exactly like a full dissect.
    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4", "UDP", "DNS"]);
}

#[test]
fn projection_is_reusable_across_packets() {
    let registry = DissectorRegistry::default();
    let dns_pkt = build_eth_ipv4_udp_dns();
    let arp_pkt = build_eth_arp();
    let mut projection = FieldProjection::new([("IPv4", "src")]);

    let mut buf = DissectBuffer::new();
    registry
        .dissect_projected(&dns_pkt, &mut buf, &mut projection)
        .unwrap();
    assert!(projection.is_satisfied());

    // Reuse on a packet without IPv4 — found state must be reset internally.
    let mut buf2 = DissectBuffer::new();
    registry
        .dissect_projected(&arp_pkt, &mut buf2, &mut projection)
        .unwrap();
    assert!(!projection.is_satisfied());
    assert!(!projection.is_found("IPv4", "src"));

    // And again on a matching packet.
    let mut buf3 = DissectBuffer::new();
    registry
        .dissect_projected(&dns_pkt, &mut buf3, &mut projection)
        .unwrap();
    assert!(projection.is_satisfied());
}

#[test]
fn projection_with_link_type_uses_link_type_table() {
    let registry = DissectorRegistry::default();
    let pkt = build_eth_ipv4_udp_dns();
    let mut buf = DissectBuffer::new();
    let mut projection = FieldProjection::new([("IPv4", "src")]);

    registry
        .dissect_projected_with_link_type(&pkt, 1, &mut buf, &mut projection)
        .unwrap();

    assert!(projection.is_satisfied());
    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4"]);
}

#[test]
fn empty_projection_stops_after_entry_layer() {
    let registry = DissectorRegistry::default();
    let pkt = build_eth_ipv4_udp_dns();
    let mut buf = DissectBuffer::new();
    let mut projection = FieldProjection::new(std::iter::empty::<(&str, &str)>());

    registry
        .dissect_projected(&pkt, &mut buf, &mut projection)
        .unwrap();

    // An empty projection is trivially satisfied, so only the entry layer
    // is dissected.
    assert!(projection.is_satisfied());
    assert_eq!(layer_names(&buf), ["Ethernet"]);
}
