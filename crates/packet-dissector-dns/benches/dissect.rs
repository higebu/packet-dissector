use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_dns::DnsDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Transaction ID: 0xABCD
    pkt.extend_from_slice(&0xABCDu16.to_be_bytes());
    // Flags: 0x0100 (RD=1)
    pkt.extend_from_slice(&0x0100u16.to_be_bytes());
    // QDCOUNT: 1
    pkt.extend_from_slice(&1u16.to_be_bytes());
    // ANCOUNT: 0
    pkt.extend_from_slice(&0u16.to_be_bytes());
    // NSCOUNT: 0
    pkt.extend_from_slice(&0u16.to_be_bytes());
    // ARCOUNT: 0
    pkt.extend_from_slice(&0u16.to_be_bytes());
    // QNAME: 7 "example" 3 "com" 0
    pkt.push(7);
    pkt.extend_from_slice(b"example");
    pkt.push(3);
    pkt.extend_from_slice(b"com");
    pkt.push(0);
    // QTYPE: 1 (A)
    pkt.extend_from_slice(&1u16.to_be_bytes());
    // QCLASS: 1 (IN)
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = DnsDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("dns", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
