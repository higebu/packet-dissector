use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_sccp::SccpDissector;
use std::hint::black_box;

/// SCCP UDT with GTI 0100 called and calling party addresses
/// (ITU-T Q.713, clause 4.10).
fn build_packet() -> Vec<u8> {
    let called = [0x12, 0x06, 0x00, 0x12, 0x04, 0x21, 0x43, 0x65, 0x87];
    let calling = [0x12, 0x07, 0x00, 0x11, 0x04, 0x89, 0x67, 0x05];
    let user = [0u8; 40];
    let mut pkt = vec![
        0x09,
        0x80,
        3,
        3 + called.len() as u8,
        3 + (called.len() + calling.len()) as u8,
    ];
    pkt.push(called.len() as u8);
    pkt.extend_from_slice(&called);
    pkt.push(calling.len() as u8);
    pkt.extend_from_slice(&calling);
    pkt.push(user.len() as u8);
    pkt.extend_from_slice(&user);
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = SccpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("sccp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
