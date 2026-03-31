use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ospf::Ospfv2Dissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut buf = Vec::new();
    // OSPFv2 common header (24 bytes)
    buf.push(2); // Version
    buf.push(1); // Type = Hello
    buf.extend_from_slice(&44u16.to_be_bytes()); // Packet Length
    buf.extend_from_slice(&[1, 1, 1, 1]); // Router ID
    buf.extend_from_slice(&[0, 0, 0, 0]); // Area ID
    buf.extend_from_slice(&[0x00, 0x00]); // Checksum
    buf.extend_from_slice(&[0x00, 0x00]); // Auth Type
    buf.extend_from_slice(&[0u8; 8]); // Authentication
    // Hello body (20 bytes, no neighbors)
    buf.extend_from_slice(&[255, 255, 255, 0]); // Network Mask
    buf.extend_from_slice(&[0, 10]); // Hello Interval = 10
    buf.push(0x02); // Options
    buf.push(1); // Router Priority
    buf.extend_from_slice(&[0, 0, 0, 40]); // Router Dead Interval = 40
    buf.extend_from_slice(&[10, 0, 0, 1]); // DR
    buf.extend_from_slice(&[10, 0, 0, 2]); // BDR
    buf
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = Ospfv2Dissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("ospf", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
