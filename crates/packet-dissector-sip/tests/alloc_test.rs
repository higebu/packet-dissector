//! Zero-allocation dissection tests for the SIP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_sip::SipDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_sip_invite() {
    let raw = b"INVITE sip:bob@example.net SIP/2.0\r\n\
                Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
                To: Bob <sip:bob@example.net>\r\n\
                From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                Call-ID: a84b4c76e66710@pc33.example.com\r\n\
                CSeq: 314159 INVITE\r\n\
                Contact: <sip:alice@pc33.example.com>\r\n\
                Content-Length: 0\r\n\r\n";
    let mut buf = DissectBuffer::new();
    // Warm up
    SipDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        SipDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "SIP dissect allocated {allocs} times");
}
