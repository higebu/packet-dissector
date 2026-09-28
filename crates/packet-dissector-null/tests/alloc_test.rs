//! Zero-allocation dissection tests for the BSD loopback dissectors.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_null::{LoopDissector, NullDissector};
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_null() {
    // AF_INET6 (30, Darwin) in little-endian host order.
    let raw: &[u8] = &[0x1E, 0x00, 0x00, 0x00];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        NullDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "Null dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "Null");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].value, FieldValue::U32(30));
}

#[test]
fn zero_alloc_dissect_loop() {
    let raw: &[u8] = &[0x00, 0x00, 0x00, 0x02];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        LoopDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "Loop dissect allocated {allocs} times");

    assert_eq!(buf.layers()[0].name, "Loop");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields[0].value, FieldValue::U32(2));
}
