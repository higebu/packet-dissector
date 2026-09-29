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

#[test]
fn zero_alloc_dissect_isis_lsp_with_sub_tlvs() {
    // L1 LSP with TLV 22 (Adj-SID sub-TLV), TLV 135 (Prefix-SID sub-TLV)
    // and TLV 242 (SR-Capabilities sub-TLV).
    let tlvs: &[u8] = &[
        // TLV 22: neighbor, metric 10, sub-TLV Adj-SID (label 16000)
        22, 18, 1, 2, 3, 4, 5, 6, 0, 0, 0, 10, 7, 31, 5, 0x30, 1, 0, 0x3e, 0x80,
        // TLV 135: 10.0.0.1/32 metric 10, S bit, Prefix-SID index 101
        135, 18, 0, 0, 0, 10, 0x60, 10, 0, 0, 1, 8, 3, 6, 0x40, 0, 0, 0, 0, 0x65,
        // TLV 242: router ID, flags, SR-Capabilities with one range
        242, 16, 1, 1, 1, 1, 0, 2, 9, 0xC0, 0, 0x1f, 0x40, 1, 3, 0, 0x3e, 0x80,
    ];
    let mut raw = vec![0x83, 27, 0x01, 0x00, 18, 0x01, 0x00, 0x00];
    raw.extend_from_slice(&((27 + tlvs.len()) as u16).to_be_bytes());
    raw.extend_from_slice(&[
        0x04, 0xB0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 1, 0xAB, 0xCD, 3,
    ]);
    raw.extend_from_slice(tlvs);

    let mut buf = DissectBuffer::new();
    IsisDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        IsisDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "ISIS LSP with sub-TLVs allocated {allocs} times");
}
