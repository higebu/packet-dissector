use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ethernet::EthernetDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // dst MAC
    pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    // src MAC
    pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    // EtherType: IPv4
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    // Dummy payload
    pkt.extend_from_slice(&[0x00; 46]);
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = EthernetDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("ethernet", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
