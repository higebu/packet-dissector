//! Zero-allocation dissection tests for the GTPv2-C dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_gtpv2c::Gtpv2cDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_gtpv2c() {
    // GTPv2-C Echo Request with TEID (3GPP TS 29.274).
    // Header: flags(1)+msg_type(1)+length(2)+teid(4)+seq(3)+spare(1) = 12 bytes.
    // Recovery IE (type=3, len=1, instance=0, value=5): 5 bytes.
    let recovery_ie: &[u8] = &[3, 0, 1, 0, 5]; // type=3, length=1, instance=0, value=5
    let msg_length = (8 + recovery_ie.len()) as u16; // length field excludes first 4 bytes

    let mut raw = Vec::new();
    raw.push(0x48); // version=2, P=0, T=1, MP=0
    raw.push(32); // message type = 32 (Create Session Request)
    raw.extend_from_slice(&msg_length.to_be_bytes());
    raw.extend_from_slice(&0x12345678u32.to_be_bytes()); // TEID
    raw.push(0x00); // sequence number (3 bytes)
    raw.push(0x00);
    raw.push(0x01);
    raw.push(0x00); // spare
    raw.extend_from_slice(recovery_ie);

    let mut buf = DissectBuffer::new();
    // Warm up
    Gtpv2cDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Gtpv2cDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "GTPv2-C dissect allocated {allocs} times");
}
