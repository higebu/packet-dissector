use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_snmp::SnmpDissector;
use std::hint::black_box;

/// SNMPv2c GetResponse with sysDescr.0 = "Linux" and sysUpTime.0.
const RESPONSE: &[u8] = &[
    0x30, 0x3a, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa2, 0x2d, 0x02,
    0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x22, 0x30, 0x11, 0x06, 0x08, 0x2b, 0x06,
    0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x04, 0x05, b'L', b'i', b'n', b'u', b'x', 0x30, 0x0d, 0x06,
    0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43, 0x01, 0x10,
];

fn bench_dissect(c: &mut Criterion) {
    let mut buf = DissectBuffer::new();
    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(RESPONSE.len() as u64));
    group.bench_function("snmp", |b| {
        b.iter(|| {
            buf.clear();
            SnmpDissector
                .dissect(black_box(RESPONSE), &mut buf, 0)
                .unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
