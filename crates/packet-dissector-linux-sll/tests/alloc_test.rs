//! Zero-allocation dissection tests for the Linux SLL dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_linux_sll::LinuxSllDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_sll() {
    let raw: &[u8] = &[
        0x00, 0x00, // packet_type: unicast to us
        0x00, 0x01, // arphrd_type: ARPHRD_ETHER
        0x00, 0x06, // ll_addr_len: 6
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, // ll_addr
        0x08, 0x00, // protocol_type: IPv4
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        LinuxSllDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "SLL dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "SLL");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 5);
    assert_eq!(fields[4].value, FieldValue::U16(0x0800));
}
