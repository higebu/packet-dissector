use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_bfd::BfdDissector;
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = vec![
        0x20, // Version=1 (3 bits), Diag=0 (5 bits)
        0xC0, // State=3/Up (2 bits), flags=0 (6 bits)
        3,    // Detect Mult
        24,   // Length
    ];
    pkt.extend_from_slice(&1u32.to_be_bytes()); // My Discriminator
    pkt.extend_from_slice(&2u32.to_be_bytes()); // Your Discriminator
    pkt.extend_from_slice(&1_000_000u32.to_be_bytes()); // Desired Min TX Interval
    pkt.extend_from_slice(&1_000_000u32.to_be_bytes()); // Required Min RX Interval
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Required Min Echo RX Interval
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = BfdDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("bfd", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
