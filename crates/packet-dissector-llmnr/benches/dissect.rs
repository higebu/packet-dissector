use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_llmnr::LlmnrDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    vec![
        0x12, 0x34, // Transaction ID
        0x00, 0x00, // Flags: QR=0 (query), C=0, TC=0, T=0
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // QNAME: host1
        0x05, b'h', b'o', b's', b't', b'1', // "host1"
        0x00, // root label
        0x00, 0x01, // QTYPE = A
        0x00, 0x01, // QCLASS = IN
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = LlmnrDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("llmnr", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
