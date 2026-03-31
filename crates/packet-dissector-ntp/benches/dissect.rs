use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ntp::NtpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut pkt = vec![0u8; 48];
    // li_vn_mode: LI=0, VN=4, Mode=3 (client) => 0x23
    pkt[0] = 0x23;
    // stratum: 0
    pkt[1] = 0;
    // poll: 6
    pkt[2] = 6;
    // precision: -20 (0xEC)
    pkt[3] = 0xEC;
    // root_delay, root_dispersion, reference_id, timestamps: all 0 (already zeroed)
    pkt
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = NtpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("ntp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
