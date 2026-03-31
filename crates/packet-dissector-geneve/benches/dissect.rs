use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_geneve::GeneveDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    vec![
        0x00, // Ver=0, OptLen=0
        0x00, // O=0, C=0, Rsvd=0
        0x65, 0x58, // Protocol Type: Transparent Ethernet Bridging
        0x00, 0x12, 0x34, // VNI = 0x001234
        0x00, // Reserved
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = GeneveDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("geneve", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
