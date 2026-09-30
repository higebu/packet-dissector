//! Zero-allocation dissection tests for the S1AP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_s1ap::S1apDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// InitialContextSetupRequest with two E-RAB items (one carrying a NAS-PDU)
/// and UE security capabilities, exercising the nested decoders.
fn message() -> Vec<u8> {
    hex(
        "0009005d0000050000000200010008000200050042000a1805f5e1006002faf0800018\
         0033010034001c4500093d0f80c0000201000000010d5201c10109010005010a000001\
         0034000e0500093d0f80c000020100000001006b00051c000c0000",
    )
}

#[test]
fn zero_alloc_dissect_s1ap_initial_context_setup_request() {
    let raw = message();
    let mut buf = DissectBuffer::new();
    S1apDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        S1apDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "S1AP dissect allocated {allocs} times");
}
