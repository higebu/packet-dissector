use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_http::HttpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".to_vec()
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = HttpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("http", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
