//! Zero-allocation dissection tests for the OSPF dissectors.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ospf::{Ospfv2Dissector, Ospfv3Dissector};
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_ospfv2_hello() {
    // OSPFv2 Hello: 24-byte header + 20-byte hello body = 44 bytes, no neighbors.
    let mut raw = Vec::new();
    // Common header
    raw.push(2); // Version
    raw.push(1); // Type = Hello
    raw.extend_from_slice(&44u16.to_be_bytes()); // Packet Length
    raw.extend_from_slice(&[1, 1, 1, 1]); // Router ID
    raw.extend_from_slice(&[0, 0, 0, 0]); // Area ID
    raw.extend_from_slice(&[0x00, 0x00]); // Checksum
    raw.extend_from_slice(&[0x00, 0x00]); // Auth Type (Null)
    raw.extend_from_slice(&[0u8; 8]); // Authentication
    // Hello body
    raw.extend_from_slice(&[255, 255, 255, 0]); // Network Mask
    raw.extend_from_slice(&10u16.to_be_bytes()); // Hello Interval
    raw.push(0x02); // Options
    raw.push(1); // Router Priority
    raw.extend_from_slice(&40u32.to_be_bytes()); // Router Dead Interval
    raw.extend_from_slice(&[10, 0, 0, 1]); // DR
    raw.extend_from_slice(&[0, 0, 0, 0]); // BDR

    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so capacity is allocated
    Ospfv2Dissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Ospfv2Dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "OSPFv2 dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_ospfv3_hello() {
    // OSPFv3 Hello: 16-byte header + 20-byte hello body = 36 bytes, no neighbors.
    let mut raw = Vec::new();
    // Common header
    raw.push(3); // Version
    raw.push(1); // Type = Hello
    raw.extend_from_slice(&36u16.to_be_bytes()); // Packet Length
    raw.extend_from_slice(&[1, 1, 1, 1]); // Router ID
    raw.extend_from_slice(&[0, 0, 0, 0]); // Area ID
    raw.extend_from_slice(&[0x00, 0x00]); // Checksum
    raw.push(0); // Instance ID
    raw.push(0); // Reserved
    // Hello body
    raw.extend_from_slice(&[0, 0, 0, 1]); // Interface ID
    raw.push(1); // Router Priority
    raw.extend_from_slice(&[0x00, 0x00, 0x13]); // Options (24-bit)
    raw.extend_from_slice(&10u16.to_be_bytes()); // Hello Interval
    raw.extend_from_slice(&40u16.to_be_bytes()); // Router Dead Interval
    raw.extend_from_slice(&[10, 0, 0, 1]); // DR
    raw.extend_from_slice(&[0, 0, 0, 0]); // BDR

    let mut buf = DissectBuffer::new();
    // Warm up
    Ospfv3Dissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Ospfv3Dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "OSPFv3 dissect allocated {allocs} times");
}
