use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_sip::SipDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    b"INVITE sip:bob@example.com SIP/2.0\r\n\
      Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776\r\n\
      From: <sip:alice@example.com>;tag=1928301774\r\n\
      To: <sip:bob@example.com>\r\n\
      Call-ID: a84b4c76e66710@192.168.1.1\r\n\
      CSeq: 314159 INVITE\r\n\
      Content-Length: 0\r\n\r\n"
        .to_vec()
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = SipDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("sip", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
