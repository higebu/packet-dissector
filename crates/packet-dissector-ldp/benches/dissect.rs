use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ldp::LdpDissector;
use std::hint::black_box;

/// LDP PDU with a Label Mapping message: Prefix FEC 10.0.0.0/24 and a
/// Generic Label.
fn build_packet() -> Vec<u8> {
    vec![
        0, 1, 0, 33, // Version 1, PDU Length 33
        10, 0, 0, 1, 0, 0, // LDP Identifier 10.0.0.1:0
        0x04, 0x00, 0, 23, 0, 0, 0, 7, // Label Mapping, Length 23, Message ID 7
        0x01, 0x00, 0, 7, 2, 0, 1, 24, 10, 0, 0, // FEC TLV: Prefix 10.0.0.0/24
        0x02, 0x00, 0, 4, 0, 0, 0x3E, 0x80, // Generic Label 16000
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = LdpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("ldp_label_mapping", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
