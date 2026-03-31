//! Zero-allocation dissection tests for the UDP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};
use packet_dissector_udp::UdpDissector;

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_udp() {
    // UDP header: src_port(2)+dst_port(2)+length(2)+checksum(2) = 8 bytes.
    let raw: &[u8] = &[
        0x30, 0x39, // src port = 12345
        0x00, 0x50, // dst port = 80
        0x00, 0x08, // length = 8 (header only)
        0x00, 0x00, // checksum (unchecked)
    ];

    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        UdpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "UDP dissect allocated {allocs} times, expected 0"
    );

    // Verify the dissected data is correct.
    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "UDP");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0].value, FieldValue::U16(12345));
    assert_eq!(fields[1].value, FieldValue::U16(80));
}
