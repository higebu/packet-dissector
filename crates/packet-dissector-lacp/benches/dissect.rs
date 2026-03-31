use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_lacp::LacpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pdu = vec![0u8; 110];
    // Subtype = LACP (0x01)
    pdu[0] = 0x01;
    // Version Number = 1
    pdu[1] = 0x01;
    // Actor Information TLV
    pdu[2] = 0x01; // TLV Type = Actor Information
    pdu[3] = 0x14; // Information Length = 20
    pdu[4] = 0x80; // Actor System Priority (high byte)
    pdu[5] = 0x00;
    pdu[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Actor System
    pdu[12..14].copy_from_slice(&1u16.to_be_bytes()); // Actor Key
    pdu[14..16].copy_from_slice(&128u16.to_be_bytes()); // Actor Port Priority
    pdu[16..18].copy_from_slice(&1u16.to_be_bytes()); // Actor Port
    pdu[18] = 0x3D; // Actor State
    // Partner Information TLV
    pdu[22] = 0x02;
    pdu[23] = 0x14;
    pdu[24] = 0x80;
    pdu[25] = 0x00;
    pdu[26..32].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    pdu[32..34].copy_from_slice(&2u16.to_be_bytes());
    pdu[34..36].copy_from_slice(&128u16.to_be_bytes());
    pdu[36..38].copy_from_slice(&2u16.to_be_bytes());
    pdu[38] = 0x3F;
    // Collector Information TLV
    pdu[42] = 0x03;
    pdu[43] = 0x10;
    pdu[44..46].copy_from_slice(&50000u16.to_be_bytes());
    pdu
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = LacpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("lacp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
