use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ngap::NgapDissector;
use std::hint::black_box;

fn build_packet() -> Vec<u8> {
    // initiatingMessage (pdu_type=0), NGSetup (proc_code=21), reject (crit=0)
    // with an empty IE container
    let mut pdu = Vec::new();
    // Byte 0: extension(0) | pdu_type(2 bits=0) | padding(5 bits)
    pdu.push(0x00);
    // Byte 1: procedure code = 21
    pdu.push(21);
    // Byte 2: criticality(2 bits=0) | padding(6 bits)
    pdu.push(0x00);

    // Value: empty IE container = SEQUENCE preamble (1) + IE count (2) = 3 bytes
    let container = vec![0x00, 0x00, 0x00];

    // Value length determinant (< 128)
    pdu.push(container.len() as u8);
    pdu.extend_from_slice(&container);
    pdu
}

/// Build an NGAP InitialUEMessage with a NAS-PDU IE containing a plain 5GMM
/// Registration Request (EPD=0x7E, security=0, type=0x41).
fn build_packet_with_nas() -> Vec<u8> {
    // NAS-PDU payload: plain 5GMM Registration Request
    let nas_pdu: &[u8] = &[
        0x7E, // EPD: 5GS Mobility Management
        0x00, // Security header: plain
        0x41, // Message type: Registration Request
        0x01, // 5GS registration type
        0x00, 0x00, 0x00, 0x00, 0x00, // 5GS mobile identity (minimal)
    ];

    // IE: id=38 (NAS-PDU), criticality=reject(0), value=nas_pdu
    let mut ie = Vec::new();
    ie.extend_from_slice(&38u16.to_be_bytes()); // IE id
    ie.push(0x00); // criticality = reject
    ie.push(nas_pdu.len() as u8); // value length
    ie.extend_from_slice(nas_pdu);

    // NGAP: initiatingMessage, proc=15 (InitialUEMessage), criticality=ignore
    let mut pdu = Vec::new();
    pdu.push(0x00); // pdu_type = initiatingMessage
    pdu.push(15); // procedure code = InitialUEMessage
    pdu.push(0x40); // criticality = ignore

    // Value: SEQUENCE preamble (1) + IE count (2) + IEs
    let mut container = Vec::new();
    container.push(0x00); // preamble
    container.extend_from_slice(&1u16.to_be_bytes()); // 1 IE
    container.extend_from_slice(&ie);

    pdu.push(container.len() as u8); // value length
    pdu.extend_from_slice(&container);
    pdu
}

fn bench_dissect(c: &mut Criterion) {
    let dissector = NgapDissector;
    let data = build_packet();
    let data_nas = build_packet_with_nas();
    let mut buf = DissectBuffer::new();

    let mut group = c.benchmark_group("dissect");

    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("ngap", |b| {
        b.iter(|| {
            buf.clear();
            dissector.dissect(black_box(&data), &mut buf, 0).unwrap();
        });
    });

    group.throughput(Throughput::Bytes(data_nas.len() as u64));
    group.bench_function("ngap_with_nas", |b| {
        b.iter(|| {
            buf.clear();
            dissector
                .dissect(black_box(&data_nas), &mut buf, 0)
                .unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, bench_dissect);
criterion_main!(benches);
