use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_m3ua::M3uaDissector;
use std::hint::black_box;

/// M3UA DATA with Routing Context and a Protocol Data parameter carrying
/// 20 octets of SCCP (RFC 4666, Section 3.3.1).
fn build_packet() -> Vec<u8> {
    let mut pkt = vec![1, 0, 1, 1, 0, 0, 0, 0];
    pkt.extend_from_slice(&[0x00, 0x06, 0x00, 0x08, 0, 0, 0, 1]); // Routing Context
    pkt.extend_from_slice(&[0x02, 0x10, 0x00, 36]); // Protocol Data, length 36
    pkt.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2, 3, 2, 0, 5]);
    pkt.extend_from_slice(&[0u8; 20]);
    let len = pkt.len() as u32;
    pkt[4..8].copy_from_slice(&len.to_be_bytes());
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = M3uaDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("m3ua", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
