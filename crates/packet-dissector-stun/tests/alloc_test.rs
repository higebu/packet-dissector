//! Zero-allocation dissection tests for the STUN dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_stun::StunDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_stun_binding_request() {
    // STUN Binding Request with no attributes.
    let raw: &[u8] = &[
        0x00, 0x01, // Message Type: Binding Request
        0x00, 0x00, // Message Length: 0
        0x21, 0x12, 0xA4, 0x42, // Magic Cookie
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Transaction ID (12 bytes)
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        StunDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "STUN dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "STUN");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields[0].value, FieldValue::U16(0x0001)); // message_type
}

#[test]
fn zero_alloc_dissect_stun_binding_response() {
    // STUN Binding Success Response with XOR-MAPPED-ADDRESS.
    let raw: &[u8] = &[
        0x01, 0x01, // Message Type: Binding Success Response
        0x00, 0x0C, // Message Length: 12
        0x21, 0x12, 0xA4, 0x42, // Magic Cookie
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Transaction ID
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, // XOR-MAPPED-ADDRESS attribute
        0x00, 0x20, // Type: XOR-MAPPED-ADDRESS
        0x00, 0x08, // Length: 8
        0x00, 0x01, 0xA1, 0x47, // Value (8 bytes)
        0xE1, 0x12, 0xA6, 0x43,
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        StunDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "STUN dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "STUN");
}

#[test]
fn zero_alloc_dissect_turn_channeldata() {
    // TURN ChannelData with padding (RFC 8656, Section 12.4 —
    // https://www.rfc-editor.org/rfc/rfc8656#section-12.4).
    let raw: &[u8] = &[0x40, 0x01, 0x00, 0x02, 0x11, 0x22, 0x00, 0x00];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        StunDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "TURN ChannelData dissect allocated {allocs} times"
    );
    assert_eq!(buf.layers()[0].name, "TURN-ChannelData");
}

#[test]
fn zero_alloc_dissect_classic_stun() {
    // Classic STUN Binding Request without magic cookie (RFC 5389,
    // Section 12 — https://www.rfc-editor.org/rfc/rfc5389#section-12).
    let mut raw = [0x5Au8; 20];
    raw[..4].copy_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        StunDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "classic STUN dissect allocated {allocs} times");
    assert_eq!(buf.layers()[0].name, "STUN");
}

#[test]
fn zero_alloc_dissect_stun_decoded_attributes() {
    // RFC 5769, Section 2.3 IPv6 response followed by ERROR-CODE,
    // UNKNOWN-ATTRIBUTES and PASSWORD-ALGORITHMS
    // (https://www.rfc-editor.org/rfc/rfc5769#section-2.3,
    // https://www.rfc-editor.org/rfc/rfc8489#section-14).
    let raw: &[u8] = &[
        0x01, 0x11, 0x00, 0x44, // Binding Error Response, length 68
        0x21, 0x12, 0xA4, 0x42, // Magic Cookie
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00,
        0x0b, // SOFTWARE, length 11
        0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00,
        0x14, // XOR-MAPPED-ADDRESS (IPv6)
        0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4,
        0xb5, 0xbe, 0xd2, 0xb9, 0xd9, 0x00, 0x09, 0x00, 0x04, 0x00, 0x00, 0x04,
        0x14, // ERROR-CODE 420
        0x00, 0x0A, 0x00, 0x02, 0x00, 0x1A, 0x00, 0x00, // UNKNOWN-ATTRIBUTES
        0x80, 0x02, 0x00, 0x08, // PASSWORD-ALGORITHMS
        0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        StunDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "STUN attribute decode allocated {allocs} times");
    assert!(
        buf.fields()
            .iter()
            .any(|f| f.name() == "address" && matches!(f.value, FieldValue::Ipv6Addr(_)))
    );
}
