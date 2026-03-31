use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_icmp::IcmpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Type: 8 (Echo Request)
    pkt.push(8);
    // Code: 0
    pkt.push(0);
    // Checksum: 0
    pkt.extend_from_slice(&0u16.to_be_bytes());
    // Identifier: 0x1234
    pkt.extend_from_slice(&0x1234u16.to_be_bytes());
    // Sequence number: 1
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = IcmpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("icmp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
