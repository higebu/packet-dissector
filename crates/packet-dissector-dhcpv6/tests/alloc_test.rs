//! Zero-allocation dissection tests for the DHCPv6 dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_dhcpv6::Dhcpv6Dissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Encode a DHCPv6 option: code(2)+length(2)+data.
fn dhcpv6_option(code: u16, data: &[u8]) -> Vec<u8> {
    let mut opt = Vec::new();
    opt.extend_from_slice(&code.to_be_bytes());
    opt.extend_from_slice(&(data.len() as u16).to_be_bytes());
    opt.extend_from_slice(data);
    opt
}

/// Build a DHCPv6 message: msg_type(1)+transaction_id(3)+options.
fn build_dhcpv6(msg_type: u8, txid: u32, options: &[u8]) -> Vec<u8> {
    let mut msg = vec![
        msg_type,
        ((txid >> 16) & 0xFF) as u8,
        ((txid >> 8) & 0xFF) as u8,
        (txid & 0xFF) as u8,
    ];
    msg.extend_from_slice(options);
    msg
}

#[test]
fn zero_alloc_dissect_dhcpv6_solicit() {
    let duid = [
        0x00, 0x01, 0x00, 0x01, 0x1c, 0x39, 0xcf, 0x88, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    ];
    let mut opts = Vec::new();
    opts.extend_from_slice(&dhcpv6_option(1, &duid)); // Client ID
    opts.extend_from_slice(&dhcpv6_option(8, &0u16.to_be_bytes())); // Elapsed Time

    let raw = build_dhcpv6(1, 0x123456, &opts);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Dhcpv6Dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "DHCPv6 solicit dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_dhcpv6_advertise() {
    let duid = [
        0x00, 0x01, 0x00, 0x01, 0x1c, 0x39, 0xcf, 0x88, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    ];
    let mut opts = Vec::new();
    opts.extend_from_slice(&dhcpv6_option(1, &duid)); // Client ID
    opts.extend_from_slice(&dhcpv6_option(2, &duid)); // Server ID
    let mut ia_na = Vec::new();
    ia_na.extend_from_slice(&1u32.to_be_bytes()); // IAID
    ia_na.extend_from_slice(&3600u32.to_be_bytes()); // T1
    ia_na.extend_from_slice(&5400u32.to_be_bytes()); // T2
    opts.extend_from_slice(&dhcpv6_option(3, &ia_na)); // IA_NA

    let raw = build_dhcpv6(2, 0x123456, &opts);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Dhcpv6Dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "DHCPv6 advertise dissect allocated {allocs} times"
    );
}
