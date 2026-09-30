use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_nsh::NshDissector;
use std::hint::black_box;

/// MD Type 2 NSH (RFC 8300, Section 2.5 —
/// <https://www.rfc-editor.org/rfc/rfc8300#section-2.5>) with one 4-byte
/// Context Header.
fn build_packet() -> Vec<u8> {
    vec![
        0x0F, 0xC4, 0x02, 0x01, // Ver 0, TTL 63, Length 4, MD Type 2, NP IPv4
        0x12, 0x34, 0x56, 0xFF, // SPI 0x123456, SI 255
        0x00, 0x00, 0x04, 0x04, // MD Class 0, Type 4, Length 4
        0xAA, 0xBB, 0xCC, 0xDD, // Metadata
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("nsh", |b| {
        b.iter(|| {
            buf.clear();
            NshDissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
