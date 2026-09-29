//! Zero-allocation test for dispatching bundled SCTP DATA chunks.
//!
//! # RFC 9260 Coverage
//!
//! | RFC Section | Description                                         | Test                                     |
//! |-------------|-----------------------------------------------------|------------------------------------------|
//! | 6.10        | Bundled DATA chunks dispatched without allocation   | zero_alloc_dissect_sctp_bundled_diameter |

use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Ethernet → IPv4 → SCTP(49152 → 3868) with two unfragmented DATA chunks,
/// each carrying a 20-byte Diameter CER header.
///
/// RFC 9260, Section 6.10 — <https://www.rfc-editor.org/rfc/rfc9260#section-6.10>
/// RFC 6733, Section 3 — <https://www.rfc-editor.org/rfc/rfc6733#section-3>
#[rustfmt::skip]
const PACKET: [u8; 118] = [
    // Ethernet, EtherType IPv4
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00,
    // IPv4, total length 104, protocol 132 (SCTP)
    0x45, 0x00, 0x00, 0x68, 0x00, 0x01, 0x00, 0x00, 0x40, 0x84, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
    // SCTP common header
    0xc0, 0x00, 0x0f, 0x1c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    // DATA, B|E, length 36, TSN 1, SID 0, SSN 0, PPID 46
    0x00, 0x03, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x2e,
    // Diameter CER, hop-by-hop 1
    0x01, 0x00, 0x00, 0x14, 0x80, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    // DATA, B|E, length 36, TSN 2
    0x00, 0x03, 0x00, 0x24, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x2e,
    // Diameter CER, hop-by-hop 2
    0x01, 0x00, 0x00, 0x14, 0x80, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
];

#[test]
fn zero_alloc_dissect_sctp_bundled_diameter() {
    let registry = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    // Warm up
    registry.dissect(&PACKET, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "SCTP", "Diameter", "Diameter"]);

    let allocs = count_allocs(|| {
        buf.clear();
        registry.dissect(&PACKET, &mut buf).unwrap();
    });
    assert_eq!(allocs, 0, "bundled SCTP dissect allocated {allocs} times");
}
