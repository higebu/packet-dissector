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

#[test]
fn zero_alloc_dissect_pfcp_ue_ip_and_network_instance() {
    // PFCP Session Establishment Request with a Create PDR containing PDI
    // with a UE IP Address IE (V4=1) and a Network Instance IE
    // (FQDN-encoded). Exercises the new parsers and the FQDN decoder
    // (which writes into the scratch buffer) on the warm path.
    let mut ies = Vec::new();
    // UE IP Address (type=93), len=5, V4=1, IPv4=10.0.0.1
    ies.extend_from_slice(&[0x00, 0x5D, 0x00, 0x05, 0x02, 10, 0, 0, 1]);
    // Network Instance (type=22), len=8, "foo.bar" label-encoded with terminator
    ies.extend_from_slice(&[
        0x00, 0x16, 0x00, 0x09, 3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 0,
    ]);

    // Wrap in an S=1 (SEID) header for type=50 (Session Establishment Request).
    let mut raw = Vec::new();
    let msg_length = (12 + ies.len()) as u16; // SEID(8)+seq(3)+spare(1)+IEs
    raw.push(0x21); // version=1, S=1
    raw.push(50); // Session Establishment Request
    raw.extend_from_slice(&msg_length.to_be_bytes());
    raw.extend_from_slice(&0x0000000000000001u64.to_be_bytes()); // SEID
    raw.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // seq + spare
    raw.extend_from_slice(&ies);

    let mut buf = DissectBuffer::new();
    PfcpDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        PfcpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "PFCP dissect allocated {allocs} times");
}
