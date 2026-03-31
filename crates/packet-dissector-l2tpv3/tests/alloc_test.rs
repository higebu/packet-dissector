//! Zero-allocation dissection tests for the L2TPv3 dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_l2tpv3::{L2tpv3Dissector, L2tpv3UdpDissector};
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_l2tpv3_ip_data() {
    let raw: &[u8] = &[0x12, 0x34, 0x56, 0x78];
    let mut buf = DissectBuffer::new();
    L2tpv3Dissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        L2tpv3Dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "L2TPv3 IP data dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_l2tpv3_ip_control() {
    let raw: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0xC8, 0x03, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    let mut buf = DissectBuffer::new();
    L2tpv3Dissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        L2tpv3Dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "L2TPv3 IP control dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_l2tpv3_udp_data() {
    let raw: &[u8] = &[0x00, 0x03, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
    let mut buf = DissectBuffer::new();
    L2tpv3UdpDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        L2tpv3UdpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "L2TPv3 UDP data dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_l2tpv3_udp_control() {
    let raw: &[u8] = &[
        0xC8, 0x03, 0x00, 0x14, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x80, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02,
    ];
    let mut buf = DissectBuffer::new();
    L2tpv3UdpDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        L2tpv3UdpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "L2TPv3 UDP control dissect allocated {allocs} times"
    );
}
