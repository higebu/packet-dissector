use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_vrrp::VrrpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    vec![
        0x31, // Version=3, Type=1 (Advertisement)
        0x01, // VRID=1
        0x64, // Priority=100
        0x01, // Count=1
        0x00, 0x64, // Rsvd=0, MaxAdvInt=100
        0xA8, 0xFD, // Checksum
        192, 168, 1, 1, // IPv4 address
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = VrrpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("vrrp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
