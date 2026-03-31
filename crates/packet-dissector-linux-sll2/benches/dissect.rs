use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_linux_sll2::LinuxSll2Dissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    buf.extend_from_slice(&0x0800u16.to_be_bytes()); // Protocol Type = IPv4
    buf.extend_from_slice(&0u16.to_be_bytes()); // Reserved
    buf.extend_from_slice(&1u32.to_be_bytes()); // Interface Index = 1
    buf.extend_from_slice(&1u16.to_be_bytes()); // ARPHRD Type = 1 (Ethernet)
    buf.push(0); // Packet Type = 0 (unicast to us)
    buf.push(6); // LL Addr Len = 6
    buf.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // LL Addr
    buf.extend_from_slice(&[0x00, 0x00]); // Padding to 8 bytes
    buf
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = LinuxSll2Dissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("linux_sll2", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
