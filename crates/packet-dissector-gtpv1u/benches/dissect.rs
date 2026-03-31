use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_gtpv1u::Gtpv1uDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    vec![
        0x30, // flags: version=1, PT=1, no E/S/PN
        0xFF, // message type: T-PDU (G-PDU)
        0x00, 0x00, // length: 0
        0x00, 0x00, 0x00, 0x01, // TEID = 1
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = Gtpv1uDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("gtpv1u", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
