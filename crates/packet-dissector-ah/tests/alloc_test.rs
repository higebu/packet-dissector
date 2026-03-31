//! Zero-allocation dissection tests for the AH dissector.

use packet_dissector_ah::AhDissector;
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_ah() {
    // AH header: payload_len=4 → total = (4+2)*4 = 24 bytes (12 bytes ICV)
    let raw: &[u8] = &[
        0x06, // next header = TCP
        0x04, // payload len = 4
        0x00, 0x00, // reserved
        0x00, 0x00, 0x10, 0x01, // SPI
        0x00, 0x00, 0x00, 0x01, // sequence number
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, // ICV (12 bytes)
        0x01, 0x02, 0x03, 0x04,
    ];

    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        AhDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "AH dissect allocated {allocs} times, expected 0");

    // Verify the dissected data is correct.
    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "AH");
}
