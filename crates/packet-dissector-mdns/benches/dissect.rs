use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_mdns::MdnsDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    vec![
        0x00, 0x00, // Transaction ID (typically 0 for mDNS)
        0x00, 0x00, // Flags: QR=0 (query)
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // QNAME: _http._tcp.local
        0x05, b'_', b'h', b't', b't', b'p', // "_http"
        0x04, b'_', b't', b'c', b'p', // "_tcp"
        0x05, b'l', b'o', b'c', b'a', b'l', // "local"
        0x00, // root label
        0x00, 0x0c, // QTYPE = PTR (12)
        0x00, 0x01, // QCLASS = IN
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = MdnsDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("mdns", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
