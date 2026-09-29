//! Zero-allocation dissection tests for the LLDP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_lldp::LldpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_lldp() {
    // Minimal LLDP frame: Chassis ID (MAC) + Port ID + TTL + End
    let raw: &[u8] = &[
        // Chassis ID TLV: type=1, length=7
        0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        // Port ID TLV: type=2, length=4
        0x04, 0x04, 0x07, 0x67, 0x65, 0x30, // "ge0"
        // TTL TLV: type=3, length=2
        0x06, 0x02, 0x00, 0x78, // 120 seconds
        // End Of LLDPDU
        0x00, 0x00,
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        LldpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "LLDP dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_lldp_with_mgmt_address() {
    // Mandatory prefix + Management Address TLV (IPv4) + End Of LLDPDU.
    let raw: &[u8] = &[
        // Chassis ID TLV: type=1, length=7
        0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        // Port ID TLV: type=2, length=4
        0x04, 0x04, 0x07, 0x67, 0x65, 0x30, // "ge0"
        // TTL TLV: type=3, length=2
        0x06, 0x02, 0x00, 0x78, // 120 seconds
        // Management Address TLV: type=8, length=12
        0x10, 0x0c, // addr string length=5, subtype=1 (IPv4), addr=192.168.1.1
        0x05, 0x01, 0xc0, 0xa8, 0x01,
        0x01, // iface numbering subtype=2 (ifIndex), iface number=1
        0x02, 0x00, 0x00, 0x00, 0x01, // OID string length=0
        0x00, // End Of LLDPDU
        0x00, 0x00,
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        LldpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "LLDP dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_lldp_org_tlvs_and_capabilities() {
    let raw: &[u8] = &[
        // Chassis ID (network address, IPv4), Port ID, TTL
        0x02, 0x06, 0x05, 0x01, 192, 0, 2, 1, 0x04, 0x04, 0x07, b'g', b'e', b'0', 0x06, 0x02, 0x00,
        0x78, // System Capabilities: bridge + router
        0x0E, 0x04, 0x00, 0x14, 0x00, 0x14, // IEEE 802.1 Port VLAN ID 100
        0xFE, 0x06, 0x00, 0x80, 0xC2, 0x01, 0x00, 0x64,
        // IEEE 802.1 Application Priority, one entry
        0xFE, 0x08, 0x00, 0x80, 0xC2, 0x0C, 0x00, 0x61, 0x89, 0x06,
        // LLDP-MED Network Policy
        0xFE, 0x08, 0x00, 0x12, 0xBB, 0x02, 0x01, 0x40, 0xC9, 0x6E, // End
        0x00, 0x00,
    ];
    let mut buf = DissectBuffer::new();
    // Warm up so the buffer's field storage has grown to fit this LLDPDU.
    LldpDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        LldpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "LLDP org TLV dissect allocated {allocs} times");
}
