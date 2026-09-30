use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_bmp::BmpDissector;
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use std::hint::black_box;

/// BMP Route Monitoring (IPv4 global peer) carrying a BGP UPDATE with ORIGIN,
/// AS_PATH and NEXT_HOP and one IPv4 prefix.
fn build_packet() -> Vec<u8> {
    let mut update = vec![0xFF; 16];
    update.extend_from_slice(&[0, 0, 2]); // Length (patched below), Type = UPDATE
    update.extend_from_slice(&[0, 0]); // Withdrawn Routes Length
    let attrs: &[u8] = &[
        0x40, 1, 1, 0, // ORIGIN IGP
        0x40, 2, 6, 2, 1, 0, 0, 0xFD, 0xE9, // AS_PATH { 65001 }
        0x40, 3, 4, 192, 0, 2, 1, // NEXT_HOP
    ];
    update.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    update.extend_from_slice(attrs);
    update.extend_from_slice(&[24, 198, 51, 100]); // 198.51.100.0/24
    let len = update.len() as u16;
    update[16..18].copy_from_slice(&len.to_be_bytes());

    let mut msg = vec![3, 0, 0, 0, 0, 0]; // Version, Length (patched), Route Monitoring
    msg.extend_from_slice(&[0, 0]); // Global Instance Peer, no flags
    msg.extend_from_slice(&[0; 8]); // Peer Distinguisher
    msg.extend_from_slice(&[0; 12]);
    msg.extend_from_slice(&[192, 0, 2, 1]); // Peer Address
    msg.extend_from_slice(&65001u32.to_be_bytes()); // Peer AS
    msg.extend_from_slice(&[192, 0, 2, 1]); // Peer BGP ID
    msg.extend_from_slice(&[0; 8]); // Timestamp
    msg.extend_from_slice(&update);
    let len = msg.len() as u32;
    msg[1..5].copy_from_slice(&len.to_be_bytes());
    msg
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = BmpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("bmp_route_monitoring", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
