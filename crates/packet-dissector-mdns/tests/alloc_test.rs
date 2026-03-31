//! Zero-allocation dissection tests for the mDNS dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_mdns::MdnsDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_mdns_query() {
    // mDNS query for _http._tcp.local PTR IN.
    let raw: &[u8] = &[
        0x00, 0x00, // transaction ID (0 for mDNS)
        0x00, 0x00, // flags: QR=0 (query)
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // QNAME: _http._tcp.local
        0x05, b'_', b'h', b't', b't', b'p', // "_http"
        0x04, b'_', b't', b'c', b'p', // "_tcp"
        0x05, b'l', b'o', b'c', b'a', b'l', // "local"
        0x00, // root label
        0x00, 0x0c, // QTYPE = PTR
        0x00, 0x01, // QCLASS = IN
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        MdnsDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "mDNS query dissect allocated {allocs} times");
}
