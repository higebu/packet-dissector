use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ipv4::Ipv4Dissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Version=4, IHL=5
    pkt.push(0x45);
    // DSCP=0, ECN=0
    pkt.push(0x00);
    // Total length: 40 (20 IP + 20 payload)
    pkt.extend_from_slice(&40u16.to_be_bytes());
    // Identification
    pkt.extend_from_slice(&1u16.to_be_bytes());
    // Flags=0, Fragment offset=0
    pkt.extend_from_slice(&0u16.to_be_bytes());
    // TTL
    pkt.push(64);
    // Protocol: TCP
    pkt.push(6);
    // Checksum
    pkt.extend_from_slice(&0u16.to_be_bytes());
    // Source: 10.0.0.1
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    // Destination: 10.0.0.2
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    // Dummy payload (20 bytes)
    pkt.extend_from_slice(&[0x00; 20]);
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = Ipv4Dissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("ipv4", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
