use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_l2tpv3::L2tpv3Dissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x56, 0x78, // Session ID (non-zero = data message)
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = L2tpv3Dissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("l2tpv3", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
