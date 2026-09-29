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

/// Dissect `raw` once to size the buffer, then count the allocations of a
/// second dissection into the reused buffer.
fn allocs_after_warm_up(raw: &'static [u8]) -> usize {
    let mut buf = DissectBuffer::new();
    Nas5gDissector.dissect(raw, &mut buf, 0).unwrap();
    count_allocs(|| {
        buf.clear();
        Nas5gDissector.dissect(raw, &mut buf, 0).unwrap();
    })
}

#[test]
fn zero_alloc_dissect_nas5g_registration_request_ies() {
    // Registration request with a SUCI and optional IEs
    // (3GPP TS 24.501, Section 8.2.6).
    let raw: &'static [u8] = &[
        0x7e, 0x00, 0x41, 0x79, // Registration request, initial, no key
        0x00, 0x0d, 0x01, 0x00, 0xf1, 0x10, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, // SUCI
        0x2e, 0x04, 0xf0, 0xf0, 0x80, 0x40, // UE security capability
        0x2f, 0x05, 0x04, 0x01, 0x00, 0x00, 0x01, // Requested NSSAI
        0x52, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x2a, // Last visited registered TAI
    ];
    let allocs = allocs_after_warm_up(raw);
    assert_eq!(
        allocs, 0,
        "NAS5G registration request dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_nas5g_ul_nas_transport_n1_sm() {
    // UL NAS transport with an N1 SM payload container
    // (3GPP TS 24.501, Sections 8.2.10 and 9.11.3.39).
    let raw: &'static [u8] = &[
        0x7e, 0x00, 0x67, 0x01, 0x00, 0x06, 0x2e, 0x01, 0x01, 0xc1, 0xff, 0xff, 0x12, 0x01, 0x81,
        0x25, 0x09, 0x08, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't',
    ];
    let allocs = allocs_after_warm_up(raw);
    assert_eq!(
        allocs, 0,
        "NAS5G UL NAS transport dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_nas5g_pdu_session_establishment_accept() {
    // PDU session establishment accept with QoS rules and QoS flow
    // descriptions (3GPP TS 24.501, Section 8.3.2).
    let raw: &'static [u8] = &[
        0x2e, 0x05, 0x01, 0xc2, 0x11, 0x00, 0x09, 0x01, 0x00, 0x06, 0x31, 0x31, 0x01, 0x01, 0xff,
        0x09, // Authorized QoS rules
        0x06, 0x06, 0x03, 0xe8, 0x06, 0x01, 0xf4, // Session-AMBR
        0x29, 0x05, 0x01, 0x0a, 0x2d, 0x00, 0x01, // PDU address
        0x79, 0x00, 0x06, 0x09, 0x20, 0x41, 0x01, 0x01, 0x09, // QoS flow descriptions
    ];
    let allocs = allocs_after_warm_up(raw);
    assert_eq!(
        allocs, 0,
        "NAS5G PDU session establishment accept dissect allocated {allocs} times"
    );
}
