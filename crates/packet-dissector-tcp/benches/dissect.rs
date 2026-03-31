use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_tcp::TcpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Source port: 54321
    pkt.extend_from_slice(&54321u16.to_be_bytes());
    // Destination port: 80
    pkt.extend_from_slice(&80u16.to_be_bytes());
    // Sequence number: 1
    pkt.extend_from_slice(&1u32.to_be_bytes());
    // Acknowledgment number: 0
    pkt.extend_from_slice(&0u32.to_be_bytes());
    // Data offset: 5 (0x50), Reserved + flags: SYN (0x02)
    pkt.push(0x50);
    pkt.push(0x02);
    // Window: 65535
    pkt.extend_from_slice(&65535u16.to_be_bytes());
    // Checksum: 0
    pkt.extend_from_slice(&0u16.to_be_bytes());
    // Urgent pointer: 0
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = TcpDissector::new();
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("tcp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
