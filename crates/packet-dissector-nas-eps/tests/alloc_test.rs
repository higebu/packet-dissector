//! Zero-allocation dissection tests for the EPS NAS dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_nas_eps::NasEpsDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Integrity protected Attach request whose ESM message container carries a
/// PDN connectivity request, exercising the nested decoders.
fn message() -> Vec<u8> {
    let esm: &[u8] = &[0x02, 0x01, 0xD0, 0x31, 0x28, 0x04, 0x03, b'a', b'p', b'n'];
    let mut v = vec![0x17, 0x01, 0x02, 0x03, 0x04, 0x00]; // integrity protected
    v.extend_from_slice(&[
        0x07, 0x41, 0x71, // Attach request, KSI 7, EPS attach
        0x0B, 0xF6, 0x00, 0xF1, 0x10, 0x80, 0x01, 0x02, 0xC0, 0x00, 0x00, 0x01, // GUTI
        0x05, 0xE0, 0xE0, 0xC0, 0x40, 0x10, // UE network capability
    ]);
    v.extend_from_slice(&(esm.len() as u16).to_be_bytes());
    v.extend_from_slice(esm);
    v.extend_from_slice(&[
        0x52, 0x00, 0xF1, 0x10, 0x00, 0x01, // Last visited registered TAI
        0x13, 0x00, 0xF1, 0x10, 0x12, 0x34, // Old LAI
        0x91, // TMSI status
    ]);
    v
}

#[test]
fn zero_alloc_dissect_nas_eps_attach_request() {
    let raw = message();
    let mut buf = DissectBuffer::new();
    NasEpsDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        NasEpsDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "NAS-EPS dissect allocated {allocs} times");
}
