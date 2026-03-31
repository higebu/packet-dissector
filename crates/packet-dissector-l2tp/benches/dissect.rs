use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_l2tp::L2tpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    vec![
        0x00, 0x02, // flags: T=0, L=0, S=0, O=0, P=0, Ver=2
        0x00, 0x01, // Tunnel ID = 1
        0x00, 0x02, // Session ID = 2
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = L2tpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("l2tp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
