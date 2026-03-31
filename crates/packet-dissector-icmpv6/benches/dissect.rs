use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_icmpv6::Icmpv6Dissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Type: 128 (Echo Request)
    pkt.push(128);
    // Code: 0
    pkt.push(0);
    // Checksum: 0
    pkt.extend_from_slice(&0u16.to_be_bytes());
    // Identifier: 0x5678
    pkt.extend_from_slice(&0x5678u16.to_be_bytes());
    // Sequence number: 42
    pkt.extend_from_slice(&42u16.to_be_bytes());
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = Icmpv6Dissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("icmpv6", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
