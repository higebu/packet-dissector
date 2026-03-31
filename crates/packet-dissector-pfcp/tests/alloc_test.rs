//! Zero-allocation dissection tests for the PFCP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_pfcp::PfcpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_pfcp() {
    // PFCP Association Setup Request (node-related, S=0) with Recovery Time Stamp IE.
    // Header: flags(1)+msg_type(1)+length(2)+seq(3)+spare(1) = 8 bytes.
    // Recovery Time Stamp IE: type(2)+length(2)+value(4) = 8 bytes.
    let recovery_ie: &[u8] = &[0x00, 0x60, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78];
    let msg_length = (4 + recovery_ie.len()) as u16;

    let mut raw = Vec::new();
    raw.push(0x20); // version=1, FO=0, MP=0, S=0
    raw.push(5); // message type = 5 (Association Setup Request)
    raw.extend_from_slice(&msg_length.to_be_bytes());
    raw.push(0x00); // sequence number (3 bytes)
    raw.push(0x00);
    raw.push(0x01);
    raw.push(0x00); // spare
    raw.extend_from_slice(recovery_ie);

    let mut buf = DissectBuffer::new();
    // Warm up
    PfcpDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        PfcpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "PFCP dissect allocated {allocs} times");
}
