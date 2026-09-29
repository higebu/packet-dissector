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

#[test]
fn zero_alloc_dissect_dhcpv6_extended_options() {
    let mut opts = Vec::new();
    // DUID-LLT, DUID-EN, DUID-UUID
    opts.extend_from_slice(&dhcpv6_option(
        1,
        &[0, 1, 0, 1, 0, 0, 0, 1, 0, 0x11, 0x22, 0x33, 0x44, 0x55],
    ));
    opts.extend_from_slice(&dhcpv6_option(2, &[0, 2, 0, 0, 0, 9, 1, 2]));
    let mut uuid = vec![0, 4];
    uuid.extend_from_slice(&[0xAB; 16]);
    opts.extend_from_slice(&dhcpv6_option(53, &uuid));
    let mut vendor = 4491u32.to_be_bytes().to_vec();
    vendor.extend_from_slice(&dhcpv6_option(1, b"ab"));
    opts.extend_from_slice(&dhcpv6_option(17, &vendor));
    opts.extend_from_slice(&dhcpv6_option(21, b"\x03sip\x07example\x00"));
    opts.extend_from_slice(&dhcpv6_option(22, &[0x20; 16]));
    opts.extend_from_slice(&dhcpv6_option(31, &[0x20; 16]));
    opts.extend_from_slice(&dhcpv6_option(32, &86400u32.to_be_bytes()));
    opts.extend_from_slice(&dhcpv6_option(37, &[0, 0, 0x0d, 0xe9, 1]));
    opts.extend_from_slice(&dhcpv6_option(38, b"sub"));
    opts.extend_from_slice(&dhcpv6_option(39, b"\x01\x04host\x00"));
    opts.extend_from_slice(&dhcpv6_option(56, &dhcpv6_option(3, b"\x03ntp\x00")));
    opts.extend_from_slice(&dhcpv6_option(59, b"tftp://x/boot"));
    opts.extend_from_slice(&dhcpv6_option(60, &[0, 1, b'q']));
    opts.extend_from_slice(&dhcpv6_option(61, &[0, 7]));
    opts.extend_from_slice(&dhcpv6_option(64, b"\x04aftr\x00"));
    opts.extend_from_slice(&dhcpv6_option(79, &[0, 1, 2, 0, 0, 0, 0, 1]));
    opts.extend_from_slice(&dhcpv6_option(82, &3600u32.to_be_bytes()));
    opts.extend_from_slice(&dhcpv6_option(83, &3600u32.to_be_bytes()));
    opts.extend_from_slice(&dhcpv6_option(88, &[0x20; 16]));
    let mut rule = vec![1, 16, 24, 192, 0, 2, 0, 32, 0x20, 0x01, 0x0d, 0xb8];
    rule.extend_from_slice(&dhcpv6_option(93, &[6, 8, 0, 0x34]));
    let mut mape = dhcpv6_option(89, &rule);
    mape.extend_from_slice(&dhcpv6_option(90, &[0x20; 16]));
    opts.extend_from_slice(&dhcpv6_option(94, &mape));
    opts.extend_from_slice(&dhcpv6_option(103, b"urn:x"));

    let raw = build_dhcpv6(7, 0x123456, &opts);
    let mut buf = DissectBuffer::new();
    // This message produces more fields than the buffer's default capacity;
    // warm the buffer once so the measurement covers the steady state
    // (`DissectBuffer::clear` keeps the capacity).
    Dhcpv6Dissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Dhcpv6Dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "DHCPv6 extended options dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_dhcpv4_query() {
    // RFC 7341 DHCPV4-QUERY: msg-type 20, flags, DHCPv4 Message option.
    let mut raw = vec![20, 0x80, 0, 0];
    raw.extend_from_slice(&dhcpv6_option(87, &[0u8; 240]));
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Dhcpv6Dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "DHCPv4-query dissect allocated {allocs} times");
}
