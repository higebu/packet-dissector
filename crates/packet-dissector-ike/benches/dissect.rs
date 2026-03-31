use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ike::IkeDissector;
use std::hint::black_box;

/// IKEv2 IKE_SA_INIT request (28-byte header, no payloads).
fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Initiator SPI (8 bytes)
    pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    // Responder SPI (8 bytes, zeros for initial)
    pkt.extend_from_slice(&[0x00; 8]);
    // Next Payload: 0 (no payloads)
    pkt.push(0x00);
    // Version: 2.0
    pkt.push(0x20);
    // Exchange Type: 34 (IKE_SA_INIT)
    pkt.push(34);
    // Flags: 0x08 (Initiator)
    pkt.push(0x08);
    // Message ID: 0
    pkt.extend_from_slice(&0u32.to_be_bytes());
    // Length: 28 (header only)
    pkt.extend_from_slice(&28u32.to_be_bytes());
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = IkeDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("ike", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
