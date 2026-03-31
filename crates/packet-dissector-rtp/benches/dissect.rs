use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_rtp::RtpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // V=2, P=0, X=0, CC=0 => 0x80
    pkt.push(0x80);
    // M=0, PT=0 => 0x00
    pkt.push(0x00);
    // Sequence number: 1
    pkt.extend_from_slice(&1u16.to_be_bytes());
    // Timestamp: 160
    pkt.extend_from_slice(&160u32.to_be_bytes());
    // SSRC: 0x12345678
    pkt.extend_from_slice(&0x12345678u32.to_be_bytes());
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = RtpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("rtp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
