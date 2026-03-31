//! Zero-allocation dissection tests for the LLDP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_lldp::LldpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_lldp() {
    // Minimal LLDP frame: Chassis ID (MAC) + Port ID + TTL + End
    let raw: &[u8] = &[
        // Chassis ID TLV: type=1, length=7
        0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        // Port ID TLV: type=2, length=4
        0x04, 0x04, 0x07, 0x67, 0x65, 0x30, // "ge0"
        // TTL TLV: type=3, length=2
        0x06, 0x02, 0x00, 0x78, // 120 seconds
        // End Of LLDPDU
        0x00, 0x00,
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        LldpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "LLDP dissect allocated {allocs} times");
}
