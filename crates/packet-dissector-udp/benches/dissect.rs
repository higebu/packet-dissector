use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_udp::UdpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Source port: 12345
    pkt.extend_from_slice(&12345u16.to_be_bytes());
    // Destination port: 53
    pkt.extend_from_slice(&53u16.to_be_bytes());
    // Length: 8 (header only)
    pkt.extend_from_slice(&8u16.to_be_bytes());
    // Checksum: 0
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = UdpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("udp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
