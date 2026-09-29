//! Zero-allocation dissection tests for the STP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_stp::StpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_stp_config() {
    // STP Configuration BPDU (35 bytes).
    let raw: &[u8] = &[
        0x00, 0x00, // Protocol ID
        0x00, // Version (STP)
        0x00, // Type (Configuration)
        0x01, // Flags: TC=1
        0x80, 0x00, // Root Priority
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Root MAC
        0x00, 0x00, 0x00, 0x04, // Root Path Cost = 4
        0x80, 0x01, // Bridge Priority
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Bridge MAC
        0x80, 0x02, // Port ID
        0x01, 0x00, // Message Age = 256
        0x14, 0x00, // Max Age = 5120
        0x02, 0x00, // Hello Time = 512
        0x0F, 0x00, // Forward Delay = 3840
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        StpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "STP config dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_stp_tcn() {
    // TCN BPDU (4 bytes).
    let raw: &[u8] = &[
        0x00, 0x00, // Protocol ID
        0x00, // Version
        0x80, // Type (TCN)
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        StpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "STP TCN dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_mst_with_msti() {
    // MST BPDU (IEEE 802.1Q-2022, Clause 14.4) with one MSTI message: 118 bytes.
    let mut raw = vec![0u8; 118];
    raw[2] = 0x03; // Version 3
    raw[3] = 0x02; // Type
    raw[36..38].copy_from_slice(&80u16.to_be_bytes()); // Version 3 Length
    raw[39..42].copy_from_slice(b"MST");
    raw[102] = 0x7C; // MSTI flags
    raw[103..105].copy_from_slice(&0x800Au16.to_be_bytes());
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        StpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "MST dissect allocated {allocs} times");
    assert_eq!(buf.layers()[0].range, 0..118);
}
