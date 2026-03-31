use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_isis::IsisDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    // Minimal L1 LAN IS-IS Hello (27 bytes, no TLVs)
    let pdu_len: u16 = 27;
    let mut pdu = Vec::with_capacity(pdu_len as usize);
    pdu.extend_from_slice(&[
        0x83, // NLPID
        27,   // Header Length
        0x01, // Version
        0x00, // ID Length
        15,   // PDU Type = L1 LAN IIH
        0x01, // Version
        0x00, // Reserved
        0x00, // Max Area Addresses
        0x01, // Circuit Type: L1
    ]);
    pdu.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // Source ID
    pdu.extend_from_slice(&30u16.to_be_bytes()); // Holding Time
    pdu.extend_from_slice(&pdu_len.to_be_bytes()); // PDU Length
    pdu.push(0x40); // Priority
    pdu.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01]); // LAN ID
    pdu
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = IsisDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("isis", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
