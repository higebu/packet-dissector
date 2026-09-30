use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_erspan::{ErspanDissector, ErspanType3Dissector};
use std::hint::black_box;

fn bench_dissect(c: &mut Criterion) {
    // Type II header (Ver=1, VLAN=100, Session ID=0x155, Index=0xABCDE).
    let type2: &[u8] = &[0x10, 0x64, 0xB5, 0x55, 0x00, 0x0A, 0xBC, 0xDE];
    // Type III header (Ver=2, FT=0, O=0).
    let type3: &[u8] = &[
        0x21, 0x23, 0x6A, 0xAA, 0x01, 0x02, 0x03, 0x04, 0xBE, 0xEF, 0x82, 0xAC,
    ];
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(type2.len() as u64));
    group.bench_function("erspan_type2", |b| {
        b.iter(|| {
            buf.clear();
            ErspanDissector
                .dissect(black_box(type2), &mut buf, 0)
                .unwrap();
        });
    });
    group.throughput(Throughput::Bytes(type3.len() as u64));
    group.bench_function("erspan_type3", |b| {
        b.iter(|| {
            buf.clear();
            ErspanType3Dissector
                .dissect(black_box(type3), &mut buf, 0)
                .unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
