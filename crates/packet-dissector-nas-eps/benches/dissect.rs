use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_nas_eps::NasEpsDissector;
use std::hint::black_box;

/// Attach Request carrying a PDN Connectivity Request in its ESM message
/// container.
fn build_packet() -> Vec<u8> {
    vec![
        0x07, 0x41, // plain EMM, Attach request
        0x71, // NAS KSI 7, EPS attach type 1
        0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, // EPS mobile identity (IMSI)
        0x02, 0xE0, 0xE0, // UE network capability
        0x00, 0x04, 0x02, 0x01, 0xD0, 0x11, // ESM message container: PDN connectivity request
        0x52, 0x00, 0xF1, 0x10, 0x00, 0x01, // Last visited registered TAI
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = NasEpsDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("nas_eps", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
