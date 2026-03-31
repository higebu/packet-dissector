use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_gtpv2c::Gtpv2cDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    vec![
        0x40, // flags: version=2, P=0, T=0, MP=0
        0x01, // message type: Echo Request
        0x00, 0x04, // length: 4 (Seq + Spare)
        0x00, 0x00, 0x01, // sequence number = 1
        0x00, // spare
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = Gtpv2cDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("gtpv2c", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
