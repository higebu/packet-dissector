//! Zero-allocation dissection tests for the ARP dissector.

use packet_dissector_arp::ArpDissector;
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_arp() {
    // ARP request: HTYPE(2)+PTYPE(2)+HLEN(1)+PLEN(1)+OPER(2)+SHA(6)+SPA(4)+THA(6)+TPA(4) = 28 bytes.
    let raw: &[u8] = &[
        0x00, 0x01, // HTYPE: Ethernet
        0x08, 0x00, // PTYPE: IPv4
        0x06, // HLEN: 6
        0x04, // PLEN: 4
        0x00, 0x01, // OPER: request
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // SHA
        0xc0, 0xa8, 0x01, 0x01, // SPA: 192.168.1.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // THA: broadcast
        0xc0, 0xa8, 0x01, 0x02, // TPA: 192.168.1.2
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        ArpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "ARP dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "ARP");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 9);
    assert_eq!(fields[4].value, FieldValue::U16(1)); // OPER: request
    assert_eq!(fields[8].value, FieldValue::Ipv4Addr([192, 168, 1, 2])); // TPA
}
