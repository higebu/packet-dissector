//! Zero-allocation dissection tests for the IS-IS dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_isis::IsisDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_isis_l1_lan_iih() {
    // L1 LAN IIH with Area Addresses and Protocols Supported TLVs.
    let raw: &[u8] = &[
        0x83, 27, 0x01, 0x00, 15, 0x01, 0x00, 0x00, // Common header (PDU type 15)
        0x01, // Circuit Type
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source ID
        0x00, 0x1E, // Holding Time = 30
        0x00, 0x24, // PDU Length = 36
        0x40, // Priority = 64
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, // LAN ID
        // TLV 1: Area Addresses (area 49.0001)
        0x01, 0x04, 0x03, 0x49, 0x00, 0x01, // TLV 129: Protocols Supported (IPv4)
        0x81, 0x01, 0xCC,
    ];

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        IsisDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "ISIS L1 LAN IIH dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_isis_l1_lsp() {
    // L1 LSP with Dynamic Hostname TLV.
    let raw: &[u8] = &[
        0x83, 27, 0x01, 0x00, 18, 0x01, 0x00, 0x00, // Common header (PDU type 18)
        0x00, 0x23, // PDU Length = 35
        0x04, 0xB0, // Remaining Lifetime = 1200
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00, // LSP ID
        0x00, 0x00, 0x00, 0x01, // Sequence Number = 1
        0xAB, 0xCD, // Checksum
        0x03, // Type Block
        // TLV 137: Dynamic Hostname "R1"
        0x89, 0x02, 0x52, 0x31, // TLV 129: Protocols Supported (IPv4, IPv6)
        0x81, 0x02, 0xCC, 0x8E,
    ];

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        IsisDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "ISIS L1 LSP dissect allocated {allocs} times");
}
