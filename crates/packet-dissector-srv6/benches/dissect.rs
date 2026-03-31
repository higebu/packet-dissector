use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_srv6::Srv6Dissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    // SRH with 1 segment, no TLVs
    let segment: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    let total_len = 8 + 16; // SRH fixed header + 1 segment
    let hdr_ext_len = (total_len / 8) - 1;

    let mut data = Vec::with_capacity(total_len);
    data.push(59); // Next Header = No Next Header
    data.push(hdr_ext_len as u8); // Hdr Ext Len
    data.push(4); // Routing Type = 4 (SRH)
    data.push(0); // Segments Left = 0
    data.push(0); // Last Entry = 0
    data.push(0); // Flags
    data.extend_from_slice(&0u16.to_be_bytes()); // Tag
    data.extend_from_slice(&segment);
    data
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = Srv6Dissector::new();
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("srv6", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
