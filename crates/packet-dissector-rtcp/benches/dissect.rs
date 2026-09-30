use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_rtcp::RtcpDissector;
use std::hint::black_box;

/// Compound RTCP packet: SR with one report block followed by SDES CNAME.
fn build_packet() -> Vec<u8> {
    let mut pkt = vec![0x81, 200, 0x00, 0x0C];
    pkt.extend_from_slice(&0x1111_1111u32.to_be_bytes()); // SSRC of sender
    pkt.extend_from_slice(&0xB44D_B705_2000_0000u64.to_be_bytes()); // NTP
    pkt.extend_from_slice(&160u32.to_be_bytes()); // RTP timestamp
    pkt.extend_from_slice(&10u32.to_be_bytes()); // packet count
    pkt.extend_from_slice(&1600u32.to_be_bytes()); // octet count
    pkt.extend_from_slice(&0x2222_2222u32.to_be_bytes()); // report block SSRC
    pkt.extend_from_slice(&[0, 0, 0, 0]); // fraction lost, cumulative lost
    pkt.extend_from_slice(&[0; 16]); // ext seq, jitter, LSR, DLSR
    pkt.extend_from_slice(&[0x81, 202, 0x00, 0x03]);
    pkt.extend_from_slice(&0x1111_1111u32.to_be_bytes());
    pkt.extend_from_slice(&[1, 4, b'u', b'@', b'h', b'x', 0, 0]);
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = RtcpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("rtcp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
