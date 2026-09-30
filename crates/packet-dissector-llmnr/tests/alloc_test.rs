//! Zero-allocation dissection tests for the LLMNR dissectors.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_llmnr::{LlmnrDissector, LlmnrTcpDissector};
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// LLMNR response (QR=1, C=1) for host1 A IN with one answer
/// (RFC 4795, Section 2.1.1 — https://www.rfc-editor.org/rfc/rfc4795#section-2.1.1).
const RESPONSE: &[u8] = &[
    0x12, 0x34, // transaction ID
    0x84, 0x00, // flags: QR=1, C=1
    0x00, 0x01, // QDCOUNT = 1
    0x00, 0x01, // ANCOUNT = 1
    0x00, 0x00, // NSCOUNT = 0
    0x00, 0x00, // ARCOUNT = 0
    0x05, b'h', b'o', b's', b't', b'1', 0x00, // QNAME: host1
    0x00, 0x01, 0x00, 0x01, // QTYPE = A, QCLASS = IN
    0xC0, 0x0C, // NAME: pointer to host1
    0x00, 0x01, 0x00, 0x01, // TYPE = A, CLASS = IN
    0x00, 0x00, 0x00, 0x1E, // TTL = 30
    0x00, 0x04, 192, 0, 2, 1, // RDLENGTH = 4, RDATA
];

#[test]
fn zero_alloc_dissect_llmnr_response() {
    let mut buf = DissectBuffer::new();
    LlmnrDissector.dissect(RESPONSE, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        LlmnrDissector.dissect(RESPONSE, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "LLMNR dissect allocated {allocs} times");
    assert_eq!(buf.layers()[0].name, "LLMNR");
}

#[test]
fn zero_alloc_dissect_llmnr_tcp_response() {
    let mut raw = (RESPONSE.len() as u16).to_be_bytes().to_vec();
    raw.extend_from_slice(RESPONSE);
    let mut buf = DissectBuffer::new();
    LlmnrTcpDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        LlmnrTcpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "LLMNR over TCP dissect allocated {allocs} times");
    assert_eq!(buf.layers()[0].name, "LLMNR");
}
