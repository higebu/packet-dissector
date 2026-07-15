use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_sdp::SdpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    b"v=0\r\n\
      o=alice 2890844526 2890844527 IN IP4 host.example.com\r\n\
      s=Call to Bob\r\n\
      c=IN IP4 198.51.100.1\r\n\
      t=0 0\r\n\
      a=recvonly\r\n\
      m=audio 49170 RTP/AVP 0 8 97\r\n\
      a=rtpmap:0 PCMU/8000\r\n\
      m=video 51372 RTP/AVP 99\r\n\
      a=rtpmap:99 h263-1998/90000\r\n"
        .to_vec()
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = SdpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("sdp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
