use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_mpls::MplsDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    // MPLS label: label=1000, TC=0, S=1 (bottom of stack), TTL=64
    let word: u32 = (1000 << 12) | (1 << 8) | 64;
    word.to_be_bytes().to_vec()
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = MplsDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("mpls", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
