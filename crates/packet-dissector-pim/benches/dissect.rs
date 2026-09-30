use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_pim::PimDissector;
use std::hint::black_box;

/// PIMv2 Join/Prune: upstream neighbor, one group with a (*,G) join and an
/// (S,G,rpt) prune.
fn build_packet() -> Vec<u8> {
    vec![
        0x23, 0x00, 0x00, 0x00, // Ver 2, Type 3, Flags, Checksum
        1, 0, 10, 0, 0, 2, // Upstream Neighbor 10.0.0.2
        0, 1, 0, 210, // Reserved, Num Groups 1, Holdtime 210
        1, 0, 0, 32, 239, 1, 1, 1, // Group 239.1.1.1/32
        0, 1, 0, 1, // 1 joined, 1 pruned
        1, 0, 7, 32, 10, 0, 0, 100, // (*,G) join, RP 10.0.0.100
        1, 0, 5, 32, 192, 0, 2, 1, // (S,G,rpt) prune, S 192.0.2.1
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = PimDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("pim_join_prune", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
