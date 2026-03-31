use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_tls::TlsDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    // --- Handshake payload (ClientHello) ---
    let mut handshake = vec![
        0x03, 0x03, // Client version: TLS 1.2
    ];
    handshake.extend_from_slice(&[0u8; 32]); // Random
    handshake.push(0); // Session ID length: 0
    handshake.extend_from_slice(&2u16.to_be_bytes()); // Cipher suites length: 2
    handshake.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    handshake.push(1); // Compression methods length: 1
    handshake.push(0); // Compression method: null
    handshake.extend_from_slice(&0u16.to_be_bytes()); // Extensions length: 0

    // Handshake header: type=1 (ClientHello)
    let hs_len = handshake.len() as u32;
    let mut hs_record = vec![
        1, // HandshakeType::ClientHello
        (hs_len >> 16) as u8,
        (hs_len >> 8) as u8,
        hs_len as u8,
    ];
    hs_record.extend_from_slice(&handshake);

    // TLS record header
    let mut pkt = vec![
        22, // ContentType: Handshake
        0x03, 0x01, // Version: TLS 1.0
    ];
    pkt.extend_from_slice(&(hs_record.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&hs_record);
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = TlsDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("tls", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
