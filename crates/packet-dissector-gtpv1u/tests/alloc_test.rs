//! Zero-allocation dissection tests for the GTPv1-U dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_gtpv1u::Gtpv1uDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_gtpv1u_basic() {
    let mut raw = Vec::new();
    raw.push(0x30); // version=1, PT=1, E=0, S=0, PN=0
    raw.push(0xFF); // message type = 255 (G-PDU)
    raw.extend_from_slice(&20u16.to_be_bytes()); // length = 20
    raw.extend_from_slice(&0x12345678u32.to_be_bytes()); // TEID
    raw.extend_from_slice(&[0x45, 0x00, 0x00, 0x14]); // IPv4, Total Length = 20
    raw.extend_from_slice(&[0u8; 16]);

    let mut buf = DissectBuffer::new();
    Gtpv1uDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Gtpv1uDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "GTPv1-U basic dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_gtpv1u_with_ext_header() {
    let mut raw = Vec::new();
    raw.push(0x34); // version=1, PT=1, E=1
    raw.push(0xFF); // G-PDU
    raw.extend_from_slice(&28u16.to_be_bytes());
    raw.extend_from_slice(&0xCAFEBABEu32.to_be_bytes()); // TEID
    raw.extend_from_slice(&0u16.to_be_bytes()); // sequence number
    raw.push(0x00); // N-PDU number
    raw.push(0x85); // next extension header type
    raw.push(0x01); // length = 1 (4 bytes total)
    raw.extend_from_slice(&[0x00, 0x09]); // DL PDU SESSION INFORMATION, QFI 9
    raw.push(0x00); // no more extension headers
    raw.extend_from_slice(&[0x45, 0x00, 0x00, 0x14]); // IPv4, Total Length = 20
    raw.extend_from_slice(&[0u8; 16]);

    let mut buf = DissectBuffer::new();
    Gtpv1uDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Gtpv1uDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "GTPv1-U ext_header dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_gtpv1u_signalling_ies() {
    // Error Indication with a UDP Port extension header, TEID Data I,
    // GTP-U Peer Address and Private Extension IEs.
    let raw = [
        0x36, 0x1a, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, // header, Length = 26
        0x00, 0x00, 0x00, 0x40, // seq, N-PDU, next ext = UDP Port
        0x01, 0x08, 0x68, 0x00, // UDP Port 2152
        0x10, 0x00, 0x00, 0x00, 0x01, // TEID Data I
        0x85, 0x00, 0x04, 0xc0, 0xa8, 0x00, 0x01, // GTP-U Peer Address
        0xff, 0x00, 0x03, 0x00, 0x7b, 0xaa, // Private Extension
    ];

    let mut buf = DissectBuffer::new();
    Gtpv1uDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Gtpv1uDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "GTPv1-U signalling dissect allocated {allocs} times"
    );
}
