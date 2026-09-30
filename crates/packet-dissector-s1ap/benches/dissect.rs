use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_s1ap::S1apDissector;
use std::hint::black_box;

/// InitialUEMessage: eNB-UE-S1AP-ID, NAS-PDU (Attach request), TAI,
/// EUTRAN-CGI and RRC-Establishment-Cause.
fn build_packet() -> Vec<u8> {
    let nas: &[u8] = &[
        0x07, 0x41, 0x71, 0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x02, 0xE0, 0xE0,
        0x00, 0x04, 0x02, 0x01, 0xD0, 0x11,
    ];
    let mut ies = vec![0x00, 0x00, 0x05];
    ies.extend_from_slice(&[0x00, 0x08, 0x00, 0x02, 0x00, 0x05]);
    ies.extend_from_slice(&[0x00, 0x1A, 0x00, nas.len() as u8 + 1, nas.len() as u8]);
    ies.extend_from_slice(nas);
    ies.extend_from_slice(&[0x00, 0x43, 0x00, 0x06, 0x00, 0x00, 0xF1, 0x10, 0x00, 0x01]);
    ies.extend_from_slice(&[
        0x00, 0x64, 0x40, 0x08, 0x00, 0x00, 0xF1, 0x10, 0x12, 0x34, 0x56, 0x70,
    ]);
    ies.extend_from_slice(&[0x00, 0x86, 0x40, 0x01, 0x30]);
    let mut pkt = vec![0x00, 0x0C, 0x40, ies.len() as u8];
    pkt.extend_from_slice(&ies);
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = S1apDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();
    dissector.dissect(&data, &mut buf, 0).unwrap();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("s1ap", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
