use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_sctp::SctpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Source port: 36412
    pkt.extend_from_slice(&36412u16.to_be_bytes());
    // Destination port: 36412
    pkt.extend_from_slice(&36412u16.to_be_bytes());
    // Verification tag: 0xAABBCCDD
    pkt.extend_from_slice(&0xAABBCCDDu32.to_be_bytes());
    // Checksum: 0
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = SctpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("sctp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
