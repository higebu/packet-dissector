use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_radius::RadiusDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Code: 1 (Access-Request)
    pkt.push(1);
    // Identifier: 0x42
    pkt.push(0x42);
    // Length: 20 (minimum header)
    pkt.extend_from_slice(&20u16.to_be_bytes());
    // Authenticator: 16 bytes of 0
    pkt.extend_from_slice(&[0u8; 16]);
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = RadiusDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("radius", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
