use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_rsvp::RsvpDissector;
use std::hint::black_box;

/// RSVP-TE Path message: LSP_TUNNEL_IPv4 SESSION, RSVP_HOP, TIME_VALUES,
/// LABEL_REQUEST, EXPLICIT_ROUTE with two subobjects and SENDER_TEMPLATE.
fn build_packet() -> Vec<u8> {
    let objects: &[&[u8]] = &[
        &[0, 16, 1, 7, 10, 0, 0, 9, 0, 0, 0, 1, 10, 0, 0, 1],
        &[0, 12, 3, 1, 10, 0, 0, 1, 0, 0, 0, 0],
        &[0, 8, 5, 1, 0, 0, 0x75, 0x30],
        &[0, 8, 19, 1, 0, 0, 0x08, 0x00],
        &[
            0, 20, 20, 1, 0x01, 8, 10, 0, 0, 2, 32, 0, 0x81, 8, 10, 0, 0, 9, 32, 0,
        ],
        &[0, 12, 11, 7, 10, 0, 0, 1, 0, 0, 0, 1],
    ];
    let body: Vec<u8> = objects.concat();
    let mut msg = vec![0x10, 1, 0, 0, 255, 0];
    msg.extend_from_slice(&((8 + body.len()) as u16).to_be_bytes());
    msg.extend_from_slice(&body);
    msg
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = RsvpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("rsvp_path", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
