use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_dhcpv6::Dhcpv6Dissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // msg_type: 1 (Solicit) + transaction_id: 0xABCDEF
    pkt.push(1);
    pkt.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
    // Option 1 (Client ID): code=0x0001, len=14
    pkt.extend_from_slice(&0x0001u16.to_be_bytes());
    pkt.extend_from_slice(&14u16.to_be_bytes());
    pkt.extend_from_slice(&[
        0x00, 0x01, 0x00, 0x01, 0x1c, 0x39, 0xcf, 0x88, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    ]);
    // Option 8 (Elapsed Time): code=0x0008, len=2
    pkt.extend_from_slice(&0x0008u16.to_be_bytes());
    pkt.extend_from_slice(&2u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = Dhcpv6Dissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("dhcpv6", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
