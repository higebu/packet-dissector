use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ipv6::Ipv6Dissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Version=6, Traffic Class=0, Flow Label=0
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    // Payload length: 20
    pkt.extend_from_slice(&20u16.to_be_bytes());
    // Next header: 6 (TCP)
    pkt.push(6);
    // Hop limit: 64
    pkt.push(64);
    // Source: 2001:db8::1
    pkt.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    // Destination: 2001:db8::2
    pkt.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    // Dummy payload (20 bytes)
    pkt.extend_from_slice(&[0x00; 20]);
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = Ipv6Dissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("ipv6", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
