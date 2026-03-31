use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_dhcp::DhcpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = vec![0u8; 236];
    pkt[0] = 1;
    pkt[1] = 1;
    pkt[2] = 6;
    pkt[3] = 0;
    pkt[4..8].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
    pkt[28] = 0xaa;
    pkt[29] = 0xbb;
    pkt[30] = 0xcc;
    pkt[31] = 0xdd;
    pkt[32] = 0xee;
    pkt[33] = 0xff;
    pkt.extend_from_slice(&[99, 130, 83, 99]);
    pkt.extend_from_slice(&[53, 1, 1]);
    pkt.push(255);
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = DhcpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("dhcp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
