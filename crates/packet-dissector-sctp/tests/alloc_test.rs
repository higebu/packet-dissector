//! Zero-allocation dissection tests for the SCTP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_sctp::SctpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_sctp() {
    // SCTP common header: src_port(2)+dst_port(2)+verification_tag(4)+checksum(4) = 12 bytes.
    let raw: &[u8] = &[
        0x8e, 0x1c, // src port = 36412
        0x8e, 0x1c, // dst port = 36412
        0xaa, 0xbb, 0xcc, 0xdd, // verification tag
        0x00, 0x00, 0x00, 0x00, // checksum (unchecked)
    ];
    let mut buf = DissectBuffer::new();
    // Warm up
    SctpDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        SctpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "SCTP dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_sctp_bundled_data_chunks() {
    // Two bundled unfragmented DATA chunks each record an embedded payload
    // in the reused buffer.
    // RFC 9260, Section 6.10 — https://www.rfc-editor.org/rfc/rfc9260#section-6.10
    let raw: &[u8] = &[
        0xc0, 0x00, 0x0f, 0x1c, // ports 49152 -> 3868
        0x00, 0x00, 0x00, 0x01, // verification tag
        0x00, 0x00, 0x00, 0x00, // checksum
        0x00, 0x03, 0x00, 0x14, // DATA, B|E, length 20
        0x00, 0x00, 0x00, 0x01, // TSN 1
        0x00, 0x00, 0x00, 0x00, // SID 0, SSN 0
        0x00, 0x00, 0x00, 0x2e, // PPID 46
        0x01, 0x02, 0x03, 0x04, // user data
        0x00, 0x03, 0x00, 0x14, // DATA, B|E, length 20
        0x00, 0x00, 0x00, 0x02, // TSN 2
        0x00, 0x00, 0x00, 0x01, // SID 0, SSN 1
        0x00, 0x00, 0x00, 0x2e, // PPID 46
        0x05, 0x06, 0x07, 0x08, // user data
    ];
    let mut buf = DissectBuffer::new();
    // Warm up
    SctpDissector.dissect(raw, &mut buf, 0).unwrap();
    assert_eq!(buf.embedded_payloads().len(), 2);

    let allocs = count_allocs(|| {
        buf.clear();
        SctpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "SCTP dissect allocated {allocs} times");
}
