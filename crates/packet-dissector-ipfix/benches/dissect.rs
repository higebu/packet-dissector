use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ipfix::IpfixDissector;
use std::hint::black_box;

/// IPFIX Message with a Template Set (Template 256: sourceIPv4Address,
/// destinationIPv4Address, octetDeltaCount, protocolIdentifier) followed by
/// a Data Set with ten records.
fn build_message() -> Vec<u8> {
    let mut sets = Vec::new();
    // Template Set.
    sets.extend_from_slice(&[0, 2, 0, 24, 1, 0, 0, 4]);
    for (id, len) in [(8u16, 4u16), (12, 4), (1, 8), (4, 1)] {
        sets.extend_from_slice(&id.to_be_bytes());
        sets.extend_from_slice(&len.to_be_bytes());
    }
    // Data Set.
    let records = 10;
    let set_len = 4 + records * 17;
    sets.extend_from_slice(&256u16.to_be_bytes());
    sets.extend_from_slice(&(set_len as u16).to_be_bytes());
    for i in 0..records {
        sets.extend_from_slice(&[10, 0, 0, i as u8, 10, 0, 1, i as u8]);
        sets.extend_from_slice(&1500u64.to_be_bytes());
        sets.push(6);
    }
    let mut msg = Vec::new();
    msg.extend_from_slice(&10u16.to_be_bytes());
    msg.extend_from_slice(&((16 + sets.len()) as u16).to_be_bytes());
    msg.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    msg.extend_from_slice(&1u32.to_be_bytes());
    msg.extend_from_slice(&0u32.to_be_bytes());
    msg.extend_from_slice(&sets);
    msg
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = IpfixDissector::new();
    let data = build_message();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("ipfix", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
