use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_bgp::BgpDissector;
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut buf = vec![0xFF; 16]; // Marker (all 1s)
    buf.extend_from_slice(&29u16.to_be_bytes()); // Length = 29 (minimum OPEN)
    buf.push(1); // Type = OPEN
    buf.push(4); // Version = 4
    buf.extend_from_slice(&65001u16.to_be_bytes()); // My AS = 65001
    buf.extend_from_slice(&180u16.to_be_bytes()); // Hold Time = 180
    buf.extend_from_slice(&[10, 0, 0, 1]); // BGP Identifier
    buf.push(0); // Opt Params Len = 0
    buf
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = BgpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("bgp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
