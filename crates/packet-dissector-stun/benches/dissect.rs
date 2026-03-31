use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_stun::StunDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Message Type: Binding Request (0x0001)
    pkt.extend_from_slice(&0x0001u16.to_be_bytes());
    // Message Length: 12 (one attribute)
    pkt.extend_from_slice(&0x000Cu16.to_be_bytes());
    // Magic Cookie
    pkt.extend_from_slice(&0x2112_A442u32.to_be_bytes());
    // Transaction ID: 12 bytes
    pkt.extend_from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    ]);
    // XOR-MAPPED-ADDRESS attribute: type(2) + length(2) + value(8) = 12 bytes
    pkt.extend_from_slice(&0x0020u16.to_be_bytes()); // Type
    pkt.extend_from_slice(&0x0008u16.to_be_bytes()); // Length
    pkt.extend_from_slice(&[0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43]); // Value
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = StunDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("stun", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
