use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_diameter::DiameterDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let origin_host = b"host.example.com";
    // AVP: Origin-Host (264), no vendor flag
    // AVP header: code(4) + flags(1) + length(3) = 8 bytes
    let avp_data_len = origin_host.len();
    let avp_len = 8 + avp_data_len; // 8 + 16 = 24
    let avp_padded = (avp_len + 3) & !3; // 24 (already aligned)
    let msg_len = 20 + avp_padded;

    let mut pkt = vec![
        1, // Version
        (msg_len >> 16) as u8,
        (msg_len >> 8) as u8,
        msg_len as u8, // Message Length
        0x80,          // Flags: Request
        0,
        1,
        1, // Command Code: 257 (CER)
    ];
    // Application-ID: 0
    pkt.extend_from_slice(&0u32.to_be_bytes());
    // Hop-by-Hop Identifier: 1
    pkt.extend_from_slice(&1u32.to_be_bytes());
    // End-to-End Identifier: 1
    pkt.extend_from_slice(&1u32.to_be_bytes());

    // Origin-Host AVP (code=264)
    pkt.extend_from_slice(&264u32.to_be_bytes());
    // Flags: 0x40 (Mandatory)
    pkt.push(0x40);
    // AVP Length: 3 bytes
    pkt.push((avp_len >> 16) as u8);
    pkt.push((avp_len >> 8) as u8);
    pkt.push(avp_len as u8);
    // AVP Data
    pkt.extend_from_slice(origin_host);
    // Padding
    let pad = avp_padded - avp_len;
    pkt.extend_from_slice(&vec![0u8; pad]);

    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = DiameterDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("diameter", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
