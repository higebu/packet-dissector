use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_esp::EspDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    vec![
        0x00, 0x00, 0x00, 0x01, // SPI = 1
        0x00, 0x00, 0x00, 0x01, // Sequence Number = 1
        0xDE, 0xAD, 0xBE, 0xEF, // encrypted payload bytes
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = EspDissector::new();
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("esp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
