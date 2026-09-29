//! Zero-allocation dissection tests for the DNS dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_dns::{DnsDissector, DnsTcpDissector};
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_dns_query() {
    // DNS query for example.com A IN (over UDP).
    let raw: &[u8] = &[
        0xab, 0xcd, // transaction ID
        0x01, 0x00, // flags: QR=0 (query), RD=1
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // QNAME: example.com
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
        0x03, b'c', b'o', b'm', // "com"
        0x00, // root label
        0x00, 0x01, // QTYPE = A
        0x00, 0x01, // QCLASS = IN
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        DnsDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "DNS query dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_dns_naptr() {
    // DNS response carrying a single NAPTR answer (RFC 3403) — regression
    // test: NAPTR parsing must not allocate (previously used `Vec::new()` to
    // collect the three character-string ranges).
    let raw: &[u8] = &[
        0xbe, 0xef, // txid
        0x84, 0x00, // flags: QR=1, AA=1
        0x00, 0x00, // QDCOUNT = 0
        0x00, 0x01, // ANCOUNT = 1
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // NAME: ex.test
        0x02, b'e', b'x', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x23, // TYPE = NAPTR (35)
        0x00, 0x01, // CLASS = IN
        0x00, 0x00, 0x00, 0x00, // TTL
        0x00, 0x18, // RDLENGTH = 24
        // RDATA: order(2) + preference(2) + "s"(2) + "SIP+D2U"(8) + ""(1) + "ex.test."(9)
        0x00, 0x64, // order = 100
        0x00, 0x0a, // preference = 10
        0x01, b's', // flags = "s"
        0x07, b'S', b'I', b'P', b'+', b'D', b'2', b'U', // services = "SIP+D2U"
        0x00, // regexp = ""
        0x02, b'e', b'x', 0x04, b't', b'e', b's', b't', 0x00, // replacement
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        DnsDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "DNS NAPTR dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_dns_tcp() {
    // DNS over TCP: 2-byte length prefix + DNS query.
    let dns_query: &[u8] = &[
        0xfa, 0xce, // transaction ID
        0x01, 0x00, // flags: RD=1
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
        0x01, // QTYPE = A
        0x00, 0x01, // QCLASS = IN
    ];
    let msg_len = dns_query.len() as u16;
    let mut raw = Vec::new();
    raw.extend_from_slice(&msg_len.to_be_bytes());
    raw.extend_from_slice(dns_query);

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        DnsTcpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "DNS TCP dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_dns_https_svcparams_and_edns_options() {
    // HTTPS answer with alpn/ipv4hint SvcParams and an OPT RR carrying
    // Client Subnet, COOKIE and Extended DNS Error options, plus an NSEC
    // record with a type bit map.
    let raw: &[u8] = &[
        0x12, 0x34, // txid
        0x81, 0x80, // flags: QR=1, RD=1, RA=1
        0x00, 0x00, // QDCOUNT = 0
        0x00, 0x02, // ANCOUNT = 2
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x01, // ARCOUNT = 1
        // HTTPS RR: owner ".", type 65, class IN, TTL 300, RDLENGTH 18
        0x00, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x12, //
        0x00, 0x01, 0x00, // priority 1, target "."
        0x00, 0x01, 0x00, 0x03, 0x02, b'h', b'2', // alpn=h2
        0x00, 0x04, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01, // ipv4hint=192.0.2.1
        // NSEC RR: owner ".", type 47, class IN, TTL 300, RDLENGTH 6
        0x00, 0x00, 0x2f, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x06, //
        0x00, 0x00, 0x03, 0x62, 0x00, 0x80, // next ".", A NS SOA RRSIG
        // OPT RR: owner ".", UDP 1232, TTL 0, RDLENGTH 31
        0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, //
        0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x18, 0x00, 0xc0, 0x00, 0x02, // ECS
        0x00, 0x0a, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, // COOKIE
        0x00, 0x0f, 0x00, 0x04, 0x00, 0x12, b'n', b'o', // EDE 18
    ];
    let mut buf = DissectBuffer::new();
    // Warm up: this message has more fields than the buffer's initial
    // capacity; steady-state dissection must not allocate.
    DnsDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        DnsDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "DNS HTTPS/EDNS dissect allocated {allocs} times");
}
