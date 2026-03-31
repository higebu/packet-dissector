use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::packet::DissectBuffer;
use std::hint::black_box;

/// Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes — a minimal TCP SYN packet.
fn build_eth_ipv4_tcp() -> Vec<u8> {
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
    pkt.extend_from_slice(&54321u16.to_be_bytes()); // src port
    pkt.extend_from_slice(&80u16.to_be_bytes()); // dst port
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

fn bench_dissect(c: &mut Criterion) {
    let registry = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();

    let tcp_pkt = build_eth_ipv4_tcp();
    let dns_pkt = build_eth_ipv4_udp_dns();
    let arp_pkt = build_eth_arp();

    let mut group = c.benchmark_group("dissect");

    // Ethernet → IPv4 → TCP (3 layers)
    group.throughput(Throughput::Bytes(tcp_pkt.len() as u64));
    group.bench_function("eth_ipv4_tcp", |b| {
        b.iter(|| {
            buf.clear();
            registry.dissect(black_box(&tcp_pkt), &mut buf).unwrap();
        });
    });

    // Ethernet → IPv4 → UDP → DNS (4 layers)
    group.throughput(Throughput::Bytes(dns_pkt.len() as u64));
    group.bench_function("eth_ipv4_udp_dns", |b| {
        b.iter(|| {
            buf.clear();
            registry.dissect(black_box(&dns_pkt), &mut buf).unwrap();
        });
    });

    // Ethernet → ARP (2 layers)
    group.throughput(Throughput::Bytes(arp_pkt.len() as u64));
    group.bench_function("eth_arp", |b| {
        b.iter(|| {
            buf.clear();
            registry.dissect(black_box(&arp_pkt), &mut buf).unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
