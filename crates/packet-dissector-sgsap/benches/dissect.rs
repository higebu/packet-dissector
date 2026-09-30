use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_sgsap::SgsapDissector;
use std::hint::black_box;

/// SGsAP-LOCATION-UPDATE-REQUEST (3GPP TS 29.118, Section 8.11).
fn build_packet() -> Vec<u8> {
    vec![
        0x09, // SGsAP-LOCATION-UPDATE-REQUEST
        0x01, 0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, // IMSI
        0x09, 0x0D, 0x04, b'm', b'm', b'e', b'1', 0x03, b'e', b'p', b'c', 0x03, b'o', b'r',
        b'g', // MME name
        0x0A, 0x01, 0x01, // EPS location update type
        0x04, 0x05, 0x00, 0xF1, 0x10, 0x00, 0x01, // LAI
        0x23, 0x05, 0x00, 0xF1, 0x10, 0x00, 0x07, // TAI
        0x24, 0x07, 0x00, 0xF1, 0x10, 0x01, 0x23, 0x45, 0x67, // E-CGI
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = SgsapDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("sgsap", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
