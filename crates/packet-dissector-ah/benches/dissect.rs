use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_ah::AhDissector;
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    vec![
        0x04, // Next Header: IPv4 (4)
        0x01, // Payload Length: 1 (total = (1+2)*4 = 12 bytes)
        0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x01, // SPI = 1
        0x00, 0x00, 0x00, 0x01, // Sequence Number = 1
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = AhDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("ah", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
