//! Zero-allocation dissection tests for the NAS 5G dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_nas5g::Nas5gDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_nas5g_plain_5gmm() {
    // Plain 5GMM Registration Request (3GPP TS 24.501).
    let raw: &[u8] = &[
        0x7E, // EPD: 5GMM
        0x00, // Security header: plain
        0x41, // Message type: Registration request
    ];

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Nas5gDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "NAS5G plain 5GMM dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_nas5g_5gsm() {
    // 5GSM PDU session establishment request (3GPP TS 24.501).
    let raw: &[u8] = &[
        0x2E, // EPD: 5GSM
        0x01, // PDU session ID
        0x00, // PTI
        0xC1, // Message type: PDU session establishment request
    ];

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Nas5gDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "NAS5G 5GSM dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_nas5g_ciphered_5gmm() {
    // Security protected 5GMM, integrity protected and ciphered
    // (3GPP TS 24.501, Section 4.4.5).
    let raw: &[u8] = &[
        0x7E, // EPD: 5GMM
        0x02, // Security header: integrity protected and ciphered
        0x12, 0x34, 0x56, 0x78, // MAC
        0x03, // Sequence number
        0x2E, 0x9A, 0x41, 0xC7, // Ciphered payload
    ];

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Nas5gDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "NAS5G ciphered 5GMM dissect allocated {allocs} times"
    );
}
