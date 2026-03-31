use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_pfcp::PfcpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    vec![
        0x20, // version=1, S=0, MP=0, FO=0
        0x01, // message type: Heartbeat Request
        0x00, 0x04, // length: 4 (Seq + Spare)
        0x00, 0x00, 0x01, // sequence number = 1
        0x00, // spare
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = PfcpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("pfcp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
