//! Zero-allocation dissection tests for the RADIUS dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_radius::RadiusDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Build a RADIUS packet from components.
fn build_radius(code: u8, id: u8, authenticator: &[u8; 16], attrs: &[u8]) -> Vec<u8> {
    let length = (20 + attrs.len()) as u16;
    let mut pkt = Vec::with_capacity(length as usize);
    pkt.push(code);
    pkt.push(id);
    pkt.extend_from_slice(&length.to_be_bytes());
    pkt.extend_from_slice(authenticator);
    pkt.extend_from_slice(attrs);
    pkt
}

/// Build a single RADIUS attribute.
fn build_attr(attr_type: u8, value: &[u8]) -> Vec<u8> {
    let len = (2 + value.len()) as u8;
    let mut attr = Vec::with_capacity(len as usize);
    attr.push(attr_type);
    attr.push(len);
    attr.extend_from_slice(value);
    attr
}

#[test]
fn zero_alloc_dissect_radius_access_request() {
    let user_name = build_attr(1, b"admin");
    let raw = build_radius(1, 42, &[0xAA; 16], &user_name);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        RadiusDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "RADIUS access request dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_radius_accounting() {
    let acct_status = build_attr(40, &1u32.to_be_bytes());
    let raw = build_radius(4, 10, &[0xBB; 16], &acct_status);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        RadiusDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "RADIUS accounting dissect allocated {allocs} times"
    );
}
