use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_arp::ArpDissector;
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    // HTYPE: 1 (Ethernet)
    pkt.extend_from_slice(&1u16.to_be_bytes());
    // PTYPE: 0x0800 (IPv4)
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    // HLEN: 6
    pkt.push(6);
    // PLEN: 4
    pkt.push(4);
    // OPER: 1 (Request)
    pkt.extend_from_slice(&1u16.to_be_bytes());
    // SHA
    pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    // SPA
    pkt.extend_from_slice(&[192, 168, 1, 1]);
    // THA
    pkt.extend_from_slice(&[0x00; 6]);
    // TPA
    pkt.extend_from_slice(&[192, 168, 1, 2]);
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = ArpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("arp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
