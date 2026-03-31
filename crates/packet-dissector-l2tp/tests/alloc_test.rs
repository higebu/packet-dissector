//! Zero-allocation dissection tests for the L2TP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_l2tp::L2tpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_l2tp_data() {
    // Minimal L2TP data message: T=0, L=0, S=0, O=0, Ver=2
    let raw: &[u8] = &[
        0x00, 0x02, // flags: Ver=2
        0x00, 0x01, // Tunnel ID = 1
        0x00, 0x02, // Session ID = 2
    ];

    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        L2tpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "L2TP data dissect allocated {allocs} times, expected 0"
    );

    // Verify the dissected data is correct.
    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "L2TP");
}

#[test]
fn zero_alloc_dissect_l2tp_control() {
    // L2TP control message: T=1, L=1, S=1, Ver=2
    let raw: &[u8] = &[
        0xC8, 0x02, // T=1, L=1, S=1, Ver=2
        0x00, 0x0C, // Length = 12
        0x00, 0x64, // Tunnel ID = 100
        0x00, 0x00, // Session ID = 0
        0x00, 0x00, // Ns = 0
        0x00, 0x00, // Nr = 0
    ];

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        L2tpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "L2TP control dissect allocated {allocs} times, expected 0"
    );

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "L2TP");
}
