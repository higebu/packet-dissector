//! Zero-allocation dissection tests for the VRRP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};
use packet_dissector_vrrp::VrrpDissector;

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_vrrp_ipv4() {
    // VRRPv3 Advertisement with 1 IPv4 address
    let raw: &[u8] = &[
        0x31, // Version=3, Type=1
        0x01, // VRID=1
        0x64, // Priority=100
        0x01, // Count=1
        0x00, 0x64, // Rsvd=0, MaxAdvInt=100
        0x00, 0x00, // Checksum
        192, 168, 1, 1, // IPv4 address
    ];
    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so capacity is allocated
    buf.begin_layer("IPv4", None, &[], 0..20);
    buf.end_layer();
    VrrpDissector.dissect(raw, &mut buf, 20).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        buf.begin_layer("IPv4", None, &[], 0..20);
        buf.end_layer();
        VrrpDissector.dissect(raw, &mut buf, 20).unwrap();
    });
    assert_eq!(allocs, 0, "VRRP dissect allocated {allocs} times");
}
