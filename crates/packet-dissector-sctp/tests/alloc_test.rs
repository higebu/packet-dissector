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

#[test]
fn zero_alloc_dissect_sctp_control_chunks() {
    // INIT with parameters, SACK with a gap block and a duplicate TSN, and
    // ABORT with an error cause.
    // RFC 9260, Sections 3.3.2, 3.3.4 and 3.3.7 —
    // https://www.rfc-editor.org/rfc/rfc9260#section-3.3
    let raw: &[u8] = &[
        0x13, 0x88, 0x0f, 0x1c, // ports 5000 -> 3868
        0x00, 0x00, 0x00, 0x00, // verification tag
        0x00, 0x00, 0x00, 0x00, // checksum
        0x01, 0x00, 0x00, 0x24, // INIT, length 36
        0x00, 0x00, 0x00, 0x01, // initiate tag
        0x00, 0x01, 0x00, 0x00, // a_rwnd
        0x00, 0x0a, 0x00, 0x0a, // OS, MIS
        0x00, 0x00, 0x00, 0x01, // initial TSN
        0x00, 0x05, 0x00, 0x08, 0xc0, 0x00, 0x02, 0x01, // IPv4 Address
        0x00, 0x0c, 0x00, 0x08, 0x00, 0x05, 0x00, 0x06, // Supported Address Types
        0x03, 0x00, 0x00, 0x18, // SACK, length 24
        0x00, 0x00, 0x00, 0x05, // cumulative TSN ack
        0x00, 0x01, 0x00, 0x00, // a_rwnd
        0x00, 0x01, 0x00, 0x01, // 1 gap block, 1 duplicate TSN
        0x00, 0x02, 0x00, 0x03, // gap block 2..3
        0x00, 0x00, 0x00, 0x04, // duplicate TSN 4
        0x06, 0x01, 0x00, 0x08, // ABORT, T bit, length 8
        0x00, 0x0c, 0x00, 0x04, // User-Initiated Abort, no info
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
