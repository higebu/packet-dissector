use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_lldp::LldpDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    let mut data = Vec::new();
    // Chassis ID TLV: type=1, len=7, subtype=4(MAC), value=11:22:33:44:55:66
    data.extend_from_slice(&0x0207u16.to_be_bytes());
    data.push(4); // subtype: MAC address
    data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    // Port ID TLV: type=2, len=2, subtype=7(local), value="1"
    data.extend_from_slice(&0x0402u16.to_be_bytes());
    data.push(7); // subtype: Locally assigned
    data.push(b'1');
    // TTL TLV: type=3, len=2, value=120
    data.extend_from_slice(&0x0602u16.to_be_bytes());
    data.extend_from_slice(&120u16.to_be_bytes());
    // End TLV: type=0, len=0
    data.extend_from_slice(&0x0000u16.to_be_bytes());
    data
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = LldpDissector;
    let data = build_packet();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("lldp", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
