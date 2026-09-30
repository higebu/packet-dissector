use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_cdp::CdpDissector;
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use std::hint::black_box;

fn tlv(tlv_type: u16, value: &[u8]) -> Vec<u8> {
    let mut t = tlv_type.to_be_bytes().to_vec();
    t.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
    t.extend_from_slice(value);
    t
}

fn build_packet() -> Vec<u8> {
    let mut raw = vec![0x02, 0xB4, 0x00, 0x00];
    raw.extend(tlv(0x0001, b"switch1.example"));
    raw.extend(tlv(0x0002, &[0, 0, 0, 1, 1, 1, 0xCC, 0, 4, 192, 0, 2, 1]));
    raw.extend(tlv(0x0003, b"GigabitEthernet0/1"));
    raw.extend(tlv(0x0004, &[0, 0, 0, 0x29]));
    raw.extend(tlv(0x0006, b"cisco WS-C2960-24TT-L"));
    raw.extend(tlv(0x000A, &[0, 1]));
    raw.extend(tlv(0x000B, &[1]));
    raw
}

fn bench_dissect(c: &mut Criterion) {
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("cdp", |b| {
        b.iter(|| {
            buf.clear();
            CdpDissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
