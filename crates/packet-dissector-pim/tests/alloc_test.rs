//! Zero-allocation dissection tests for the PIM dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_pim::PimDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

fn assert_zero_alloc(raw: &[u8], what: &str) {
    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so capacity is allocated.
    PimDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        PimDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "PIM {what} dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_pim_hello() {
    let raw: &[u8] = &[
        0x20, 0x00, 0x00, 0x00, // Ver 2, Hello
        0, 1, 0, 2, 0, 105, // Holdtime 105
        0, 19, 0, 4, 0, 0, 0, 1, // DR Priority 1
        0, 20, 0, 4, 0xDE, 0xAD, 0xBE, 0xEF, // Generation ID
        0, 24, 0, 6, 1, 0, 10, 0, 1, 1, // Address List
    ];
    assert_zero_alloc(raw, "Hello");
}

#[test]
fn zero_alloc_dissect_pim_join_prune() {
    let raw: &[u8] = &[
        0x23, 0x00, 0x00, 0x00, // Ver 2, Join/Prune
        1, 0, 10, 0, 0, 2, // Upstream Neighbor
        0, 1, 0, 210, // Num Groups 1, Holdtime 210
        1, 0, 0, 32, 239, 1, 1, 1, // Group
        0, 1, 0, 1, // 1 joined, 1 pruned
        1, 0, 7, 32, 10, 0, 0, 100, // (*,G)
        1, 0, 5, 32, 192, 0, 2, 1, // (S,G,rpt)
    ];
    assert_zero_alloc(raw, "Join/Prune");
}

#[test]
fn zero_alloc_dissect_pim_bootstrap() {
    let raw: &[u8] = &[
        0x24, 0x00, 0x00, 0x00, // Ver 2, Bootstrap
        0, 1, 30, 64, // Fragment Tag, Hash Mask Len, BSR Priority
        1, 0, 10, 0, 0, 9, // BSR Address
        1, 0, 0, 4, 224, 0, 0, 0, // Group 224.0.0.0/4
        1, 1, 0, 0, // RP Count, Frag RP Cnt
        1, 0, 10, 0, 0, 100, 0, 150, 0, 0, // RP, Holdtime, Priority
    ];
    assert_zero_alloc(raw, "Bootstrap");
}
