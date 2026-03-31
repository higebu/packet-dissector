//! Zero-allocation dissection tests for the ICMP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_icmp::IcmpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_icmp_echo() {
    // ICMP Echo Request: type(1)+code(1)+checksum(2)+id(2)+seq(2) = 8 bytes.
    let raw: &[u8] = &[
        0x08, // type = 8 (Echo Request)
        0x00, // code = 0
        0x00, 0x00, // checksum (unchecked)
        0x12, 0x34, // identifier
        0x00, 0x01, // sequence number
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        IcmpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "ICMP dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "ICMP");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields[0].value, FieldValue::U8(8)); // type
    assert_eq!(fields[3].value, FieldValue::U16(0x1234)); // identifier
}
