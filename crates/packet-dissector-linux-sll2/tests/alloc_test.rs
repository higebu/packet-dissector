//! Zero-allocation dissection tests for the Linux SLL2 dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_linux_sll2::LinuxSll2Dissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_sll2() {
    let raw: &[u8] = &[
        0x08, 0x00, // protocol_type: IPv4
        0x00, 0x00, // reserved
        0x00, 0x00, 0x00, 0x01, // interface_index: 1
        0x00, 0x01, // arphrd_type: ARPHRD_ETHER
        0x00, // packet_type: unicast to us
        0x06, // ll_addr_len: 6
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, // ll_addr
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        LinuxSll2Dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "SLL2 dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "SLL2");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 7);
    assert_eq!(fields[0].value, FieldValue::U16(0x0800));
}
