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

#[test]
fn zero_alloc_dissect_l2tpv3_typed_avps_and_payload() {
    // Control message with typed AVPs (Message Type, Local Session ID,
    // Pseudowire Type, Circuit Status, Pseudowire Capabilities List).
    let raw: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0xc8, 0x03, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, //
        0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, //
        0x80, 0x0a, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x07, //
        0x80, 0x08, 0x00, 0x00, 0x00, 0x44, 0x00, 0x05, //
        0x80, 0x08, 0x00, 0x00, 0x00, 0x47, 0x00, 0x03, //
        0x80, 0x0a, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x04, 0x00, 0x05,
    ];
    let mut buf = DissectBuffer::new();
    L2tpv3Dissector.dissect(raw, &mut buf, 0).unwrap();
    let allocs = count_allocs(|| {
        buf.clear();
        L2tpv3Dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "L2TPv3 typed AVP dissect allocated {allocs} times"
    );

    // Data message with a non-Ethernet payload.
    let raw: &[u8] = &[0x00, 0x00, 0x10, 0x01, 0xff, 0x03, 0xc0, 0x21];
    let allocs = count_allocs(|| {
        buf.clear();
        L2tpv3Dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "L2TPv3 data payload dissect allocated {allocs} times"
    );
}
