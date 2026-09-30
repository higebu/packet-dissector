use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_gtpv1c::Gtpv1cDissector;
use std::hint::black_box;

/// Create PDP Context Request with a typical set of IEs.
fn build_packet() -> Vec<u8> {
    let body: &[u8] = &[
        2, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xF5, // IMSI
        3, 0x62, 0xF2, 0x10, 0x12, 0x34, 0x56, // RAI
        14, 0x01, // Recovery
        15, 0xFC, // Selection Mode
        16, 0x00, 0x00, 0x00, 0x01, // TEID Data I
        17, 0x00, 0x00, 0x00, 0x02, // TEID Control Plane
        20, 0x05, // NSAPI
        128, 0x00, 0x02, 0xF1, 0x21, // End User Address
        131, 0x00, 0x09, 8, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't', // APN
        133, 0x00, 0x04, 10, 0, 0, 1, // GSN Address
        133, 0x00, 0x04, 10, 0, 0, 2, // GSN Address
        134, 0x00, 0x07, 0x91, 0x94, 0x71, 0x00, 0x10, 0x32, 0xF4, // MSISDN
        135, 0x00, 0x04, 0x02, 0x23, 0x92, 0x1F, // QoS Profile
        151, 0x00, 0x01, 0x01, // RAT Type
    ];
    let mut pkt = vec![0x32, 16];
    pkt.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0, 0, 0, 0, 0x00, 0x01, 0, 0]);
    pkt.extend_from_slice(body);
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = Gtpv1cDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("gtpv1c", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
