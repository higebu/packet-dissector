use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_pppoe::{PppoeDiscoveryDissector, PppoeSessionDissector};
use std::hint::black_box;

fn build_pado() -> Vec<u8> {
    vec![
        0x11, 0x07, 0x00, 0x00, 0x00, 0x14, // PADO, LEN 20
        0x01, 0x02, 0x00, 0x04, b'B', b'R', b'A', b'S', // AC-Name
        0x01, 0x01, 0x00, 0x00, // Service-Name
        0x01, 0x03, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, // Host-Uniq
    ]
}

fn build_session() -> Vec<u8> {
    vec![
        0x11, 0x00, 0x00, 0x11, 0x00, 0x0A, // Session, LEN 10
        0xC0, 0x21, 0x09, 0x02, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78,
    ]
}

fn bench_dissect(c: &mut Criterion) {
    let pado = build_pado();
    let session = build_session();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(pado.len() as u64));
    group.bench_function("pppoe_discovery", |b| {
        b.iter(|| {
            buf.clear();
            PppoeDiscoveryDissector
                .dissect(black_box(&pado), &mut buf, 0)
                .unwrap();
        });
    });
    group.throughput(Throughput::Bytes(session.len() as u64));
    group.bench_function("pppoe_session", |b| {
        b.iter(|| {
            buf.clear();
            PppoeSessionDissector
                .dissect(black_box(&session), &mut buf, 0)
                .unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
