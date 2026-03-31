use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_vxlan::VxlanDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    vec![
        0x08, 0x00, 0x00, 0x00, // flags: I flag set + reserved
        0x00, 0x12, 0x34, 0x00, // VNI: 0x001234 + reserved
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = VxlanDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("vxlan", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
