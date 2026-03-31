use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_gre::GreDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    vec![
        0x00, 0x00, // flags: no C/K/S bits, version 0
        0x08, 0x00, // protocol_type: IPv4
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = GreDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("gre", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
