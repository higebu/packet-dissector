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

#[test]
fn zero_alloc_dissect_ngap_pdu_session_resource_setup_request() {
    // PDUSessionResourceSetupRequest with a PDUSessionResourceSetupListSUReq
    // item carrying a NAS-PDU and a PDUSessionResourceSetupRequestTransfer
    // (3GPP TS 38.413, Section 9.4.5).
    let raw: &[u8] = &[
        0x00, 0x1d, 0x00, 0x55, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, 0x00, 0x55,
        0x00, 0x02, 0x00, 0x01, 0x00, 0x4a, 0x00, 0x42, 0x00, 0x40, 0x01, 0x0c, 0x7e, 0x00, 0x68,
        0x01, 0x00, 0x06, 0x2e, 0x05, 0x01, 0xc2, 0x12, 0x00, 0x00, 0x20, 0x2f, 0x00, 0x00, 0x04,
        0x00, 0x82, 0x00, 0x0a, 0x0c, 0x3b, 0x9a, 0xca, 0x00, 0x30, 0x1d, 0xcd, 0x65, 0x00, 0x00,
        0x8b, 0x00, 0x0a, 0x01, 0xf0, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x86,
        0x00, 0x01, 0x00, 0x00, 0x88, 0x00, 0x07, 0x00, 0x09, 0x00, 0x00, 0x09, 0x1c, 0x00,
    ];

    let mut buf = DissectBuffer::new();
    NgapDissector.dissect(raw, &mut buf, 0).unwrap();
    let allocs = count_allocs(|| {
        buf.clear();
        NgapDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "NGAP PDUSessionResourceSetupRequest dissect allocated {allocs} times"
    );
}
