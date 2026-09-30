use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_tls::{DtlsDissector, TlsDissector};
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

/// A DTLS 1.2 datagram: a ClientHello with a cookie (RFC 6347, Section 4.2.1 —
/// <https://www.rfc-editor.org/rfc/rfc6347#section-4.2.1>).
fn build_dtls_packet() -> Vec<u8> {
    let mut body = vec![0xFE, 0xFD]; // client_version: DTLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id length
    body.push(16); // cookie length
    body.extend_from_slice(&[0xAB; 16]); // cookie
    body.extend_from_slice(&[0x00, 0x02, 0xC0, 0x2B]); // cipher_suites
    body.extend_from_slice(&[0x01, 0x00]); // compression_methods
    body.extend_from_slice(&0u16.to_be_bytes()); // extensions length

    let len = (body.len() as u32).to_be_bytes();
    // msg_type, length, message_seq, fragment_offset, fragment_length
    let mut hs = vec![
        1, len[1], len[2], len[3], 0, 0, 0, 0, 0, len[1], len[2], len[3],
    ];
    hs.extend_from_slice(&body);

    // type, version, epoch, sequence_number (48-bit), length
    let mut pkt = vec![22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0];
    pkt.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&hs);
    pkt
}

fn bench_dissect_dtls(c: &mut Criterion) {
    let dissector = DtlsDissector;
    let data = build_dtls_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("dtls", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect, bench_dissect_dtls);
criterion_main!(benches);
