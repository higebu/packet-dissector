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
