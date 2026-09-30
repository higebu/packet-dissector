use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_eap::{EapDissector, EapolDissector};
use std::hint::black_box;

fn build_eapol_identity() -> Vec<u8> {
    vec![
        0x02, 0x00, 0x00, 0x0A, // EAPOL-EAP, body 10
        0x02, 0x01, 0x00, 0x0A, 0x01, b'a', b'l', b'i', b'c', b'e',
    ]
}

fn build_aka_challenge() -> Vec<u8> {
    let mut raw = vec![0x01, 0x21, 0x00, 0x44, 0x17, 0x01, 0x00, 0x00];
    for t in [1u8, 2, 11] {
        raw.extend_from_slice(&[t, 5, 0, 0]);
        raw.extend_from_slice(&[t; 16]);
    }
    raw
}

fn bench_dissect(c: &mut Criterion) {
    let eapol = build_eapol_identity();
    let aka = build_aka_challenge();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(eapol.len() as u64));
    group.bench_function("eapol_eap_identity", |b| {
        b.iter(|| {
            buf.clear();
            EapolDissector
                .dissect(black_box(&eapol), &mut buf, 0)
                .unwrap();
        });
    });
    group.throughput(Throughput::Bytes(aka.len() as u64));
    group.bench_function("eap_aka_challenge", |b| {
        b.iter(|| {
            buf.clear();
            EapDissector.dissect(black_box(&aka), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
