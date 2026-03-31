//! Zero-allocation dissection tests for the Ethernet dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ethernet::EthernetDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_ethernet() {
    // Ethernet II frame header: dst(6) + src(6) + ethertype(2) = 14 bytes.
    let raw: &[u8] = &[
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // dst
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // src
        0x08, 0x00, // EtherType: IPv4
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        EthernetDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "Ethernet dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 3); // dst, src, ethertype
    assert_eq!(fields[2].value, FieldValue::U16(0x0800));
}

#[test]
fn zero_alloc_dissect_ethernet_vlan() {
    // 802.1Q VLAN-tagged frame: dst(6) + src(6) + 0x8100(2) + TCI(2) + inner ethertype(2) = 18 bytes.
    let raw: &[u8] = &[
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // dst
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // src
        0x81, 0x00, // TPID: 802.1Q
        0x00, 0x64, // TCI: PCP=0, DEI=0, VID=100
        0x08, 0x00, // inner EtherType: IPv4
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        EthernetDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "Ethernet VLAN dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 7); // dst, src, tpid, pcp, dei, vid, ethertype
    assert_eq!(fields[5].value, FieldValue::U16(100)); // VID
}
