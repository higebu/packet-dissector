//! Zero-allocation dissection tests for the IKE dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ike::IkeDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_ike() {
    // IKEv2 IKE_SA_INIT header (28 bytes) with one SA payload (8 bytes)
    let raw: &[u8] = &[
        // Initiator SPI
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Responder SPI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, // Next Payload = 33 (SA)
        0x20, // Version: Major=2, Minor=0
        0x22, // Exchange Type = 34 (IKE_SA_INIT)
        0x08, // Flags: Initiator
        0x00, 0x00, 0x00, 0x00, // Message ID = 0
        0x00, 0x00, 0x00, 0x24, // Length = 36 (28 header + 8 payload)
        // SA Payload: next=0, critical=0, length=8, data=[0xAA, 0xBB, 0xCC, 0xDD]
        0x00, 0x00, 0x00, 0x08, 0xAA, 0xBB, 0xCC, 0xDD,
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        IkeDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "IKE dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "IKE");
}

#[test]
fn zero_alloc_dissect_ikev2_payload_bodies() {
    // IKE_SA_INIT with SA (1 proposal, 2 transforms + attribute), KE, Nonce
    // and a NAT_DETECTION_SOURCE_IP Notify.
    let mut sa = vec![0, 0, 0, 28, 1, 1, 0, 2];
    sa.extend_from_slice(&[3, 0, 0, 12, 1, 0, 0, 12, 0x80, 14, 1, 0]);
    sa.extend_from_slice(&[0, 0, 0, 8, 4, 0, 0, 31]);
    let mut ke = vec![0, 31, 0, 0];
    ke.extend_from_slice(&[0xab; 32]);
    let nonce = vec![7u8; 16];
    let mut notify = vec![0, 0, 0x40, 0x04];
    notify.extend_from_slice(&[0x5a; 20]);
    let payloads = [(33u8, sa), (34, ke), (40, nonce), (41, notify)];
    let mut body = Vec::new();
    for (i, (_, b)) in payloads.iter().enumerate() {
        body.push(payloads.get(i + 1).map(|p| p.0).unwrap_or(0));
        body.push(0);
        body.extend_from_slice(&((b.len() + 4) as u16).to_be_bytes());
        body.extend_from_slice(b);
    }
    let mut raw = vec![0x11; 8];
    raw.extend_from_slice(&[0; 8]);
    raw.extend_from_slice(&[33, 0x20, 34, 0x08, 0, 0, 0, 0]);
    raw.extend_from_slice(&((28 + body.len()) as u32).to_be_bytes());
    raw.extend_from_slice(&body);

    let mut buf = DissectBuffer::new();
    IkeDissector.dissect(&raw, &mut buf, 0).unwrap();
    let allocs = count_allocs(|| {
        buf.clear();
        IkeDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "IKEv2 payload body dissect allocated {allocs} times"
    );
}

#[cfg(feature = "eap")]
#[test]
fn zero_alloc_dissect_ike_eap_payload() {
    // IKEv2 IKE_AUTH header with one EAP payload (48) carrying an EAP
    // Request/Identity (RFC 7296, Section 3.16 —
    // https://www.rfc-editor.org/rfc/rfc7296#section-3.16).
    let raw: &[u8] = &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Initiator SPI
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // Responder SPI
        0x30, // Next Payload = 48 (EAP)
        0x20, // Version 2.0
        0x23, // Exchange Type = 35 (IKE_AUTH)
        0x20, // Flags: Response
        0x00, 0x00, 0x00, 0x01, // Message ID
        0x00, 0x00, 0x00, 0x25, // Length = 37
        0x00, 0x00, 0x00, 0x09, // EAP payload header, length 9
        0x01, 0x05, 0x00, 0x05, 0x01, // EAP Request/Identity
    ];
    let mut buf = DissectBuffer::new();
    IkeDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        IkeDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "IKE EAP payload dissect allocated {allocs} times"
    );
    assert!(buf.fields().iter().any(|f| f.name() == "eap"));
}
