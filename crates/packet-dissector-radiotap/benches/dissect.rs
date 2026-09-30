use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_radiotap::RadiotapDissector;
use std::hint::black_box;

fn bench_dissect(c: &mut Criterion) {
    let dissector = RadiotapDissector;
    // TSFT, Flags, Rate, Channel, antenna signal and antenna.
    #[rustfmt::skip]
    let data = [
        0x00, 0x00, 0x18, 0x00, 0x2F, 0x08, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x10, 0x0C, 0x85, 0x09, 0xA0, 0x00, 0xD8, 0x01,
    ];
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("radiotap", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
