use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ieee80211::Ieee80211Dissector;
use std::hint::black_box;

fn bench_dissect(c: &mut Criterion) {
    let dissector = Ieee80211Dissector;
    // QoS Data (To DS) with an LLC/SNAP header for IPv4.
    #[rustfmt::skip]
    let data = [
        0x88, 0x01, 0x2C, 0x00,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01,
        0x10, 0x00, 0x05, 0x00,
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00,
    ];
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("ieee80211", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
