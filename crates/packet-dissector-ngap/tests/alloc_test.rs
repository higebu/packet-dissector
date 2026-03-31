//! Zero-allocation dissection tests for the NGAP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ngap::NgapDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_ngap() {
    // NGAP NGSetupRequest: initiatingMessage, proc=21, criticality=reject,
    // 1 IE (GlobalRANNodeID id=27, raw value).
    //
    // 3GPP TS 38.413, Section 9.4.
    let raw: &[u8] = &[
        0x00, 0x15, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x00, 0x1a, 0x00, 0x05, 0x00, 0x02, 0xf8, 0x39,
        0x10,
    ];

    let mut buf = DissectBuffer::new();
    NgapDissector.dissect(raw, &mut buf, 0).unwrap();
    let allocs = count_allocs(|| {
        buf.clear();
        NgapDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "NGAP dissect allocated {allocs} times");
}
