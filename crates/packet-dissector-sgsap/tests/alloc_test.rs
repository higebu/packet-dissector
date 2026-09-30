//! Zero-allocation dissection tests for the SGsAP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_sgsap::SgsapDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// SGsAP-PAGING-REQUEST with an IMSI, VLR name, service indicator, TMSI,
/// CLI, LAI and an unknown IE (3GPP TS 29.118, Section 8.14).
fn message() -> Vec<u8> {
    vec![
        0x01, // SGsAP-PAGING-REQUEST
        0x01, 0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, // IMSI
        0x02, 0x05, 0x03, b'v', b'l', b'r', 0x00, // VLR name
        0x20, 0x01, 0x01, // Service indicator
        0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, // TMSI
        0x1C, 0x04, 0x91, 0x21, 0x43, 0xF5, // CLI
        0x04, 0x05, 0x00, 0xF1, 0x10, 0x00, 0x01, // LAI
        0x0E, 0x05, 0xF4, 0x01, 0x02, 0x03, 0x04, // Mobile identity (TMSI)
        0xEE, 0x01, 0x00, // unknown IE
    ]
}

#[test]
fn zero_alloc_dissect_sgsap_paging_request() {
    let raw = message();
    let mut buf = DissectBuffer::new();
    SgsapDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        SgsapDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "SGsAP dissect allocated {allocs} times");
}
