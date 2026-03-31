use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_stp::StpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = vec![0u8; 35];
    // Protocol ID = 0x0000
    pkt[0] = 0x00;
    pkt[1] = 0x00;
    // Version = 0 (STP)
    pkt[2] = 0x00;
    // BPDU Type = 0x00 (Configuration)
    pkt[3] = 0x00;
    // Flags: TC=1, TCA=1
    pkt[4] = 0x81;
    // Root Bridge ID: priority=0x8000, MAC=00:11:22:33:44:55
    pkt[5] = 0x80;
    pkt[6] = 0x00;
    pkt[7..13].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // Root Path Cost = 4
    pkt[13..17].copy_from_slice(&4u32.to_be_bytes());
    // Bridge ID: priority=0x8001, MAC=AA:BB:CC:DD:EE:FF
    pkt[17] = 0x80;
    pkt[18] = 0x01;
    pkt[19..25].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    // Port ID = 0x8002
    pkt[25..27].copy_from_slice(&0x8002u16.to_be_bytes());
    // Message Age = 256 (1 second)
    pkt[27..29].copy_from_slice(&256u16.to_be_bytes());
    // Max Age = 5120 (20 seconds)
    pkt[29..31].copy_from_slice(&5120u16.to_be_bytes());
    // Hello Time = 512 (2 seconds)
    pkt[31..33].copy_from_slice(&512u16.to_be_bytes());
    // Forward Delay = 3840 (15 seconds)
    pkt[33..35].copy_from_slice(&3840u16.to_be_bytes());
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = StpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("stp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
