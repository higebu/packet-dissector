use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_http2::Http2Dissector;
use std::hint::black_box;

/// Build a HEADERS frame with HPACK-encoded `:method GET`, `:path /`.
/// Uses static table indexed representations (compact, 1 byte each).
fn build_headers_frame() -> Vec<u8> {
    // HPACK payload: indexed header field representations
    // 0x82 = index 2 (:method GET)
    // 0x84 = index 4 (:path /)
    // 0x86 = index 6 (:scheme https)
    let hpack_payload: &[u8] = &[0x82, 0x84, 0x86];
    let len = hpack_payload.len() as u32;

    let mut frame = Vec::with_capacity(9 + hpack_payload.len());
    // Length (24-bit)
    frame.push((len >> 16) as u8);
    frame.push((len >> 8) as u8);
    frame.push(len as u8);
    // Type: HEADERS (0x01)
    frame.push(0x01);
    // Flags: END_HEADERS (0x04)
    frame.push(0x04);
    // Stream ID: 1
    frame.extend_from_slice(&1u32.to_be_bytes());
    // HPACK payload
    frame.extend_from_slice(hpack_payload);
    frame
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = Http2Dissector;
    let data = build_headers_frame();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("http2", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
