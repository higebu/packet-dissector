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
