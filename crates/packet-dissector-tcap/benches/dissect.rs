use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_tcap::TcapDissector;
use std::hint::black_box;

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag, content.len() as u8];
    v.extend_from_slice(content);
    v
}

/// TCAP Begin with an AARQ dialogue portion and one Invoke
/// (ITU-T Q.773, clause 3.1).
fn build_packet() -> Vec<u8> {
    let ac = [0x04, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03];
    let dialogue_as = [0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01];
    let aarq = tlv(
        0x60,
        &[tlv(0x80, &[0x07, 0x80]), tlv(0xa1, &tlv(0x06, &ac))].concat(),
    );
    let external = tlv(0x28, &[tlv(0x06, &dialogue_as), tlv(0xa0, &aarq)].concat());
    let invoke = tlv(
        0xa1,
        &[
            tlv(0x02, &[1]),
            tlv(0x02, &[2]),
            tlv(0x30, &tlv(0x04, &[0x99; 8])),
        ]
        .concat(),
    );
    tlv(
        0x62,
        &[
            tlv(0x48, &[1, 2, 3, 4]),
            tlv(0x6b, &external),
            tlv(0x6c, &invoke),
        ]
        .concat(),
    )
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = TcapDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("tcap", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
