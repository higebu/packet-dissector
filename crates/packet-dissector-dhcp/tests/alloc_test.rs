//! Zero-allocation dissection tests for the DHCP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_dhcp::DhcpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

// DHCP magic cookie: 99.130.83.99
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Build a minimal DHCP message (236-byte fixed header + magic cookie + options).
fn build_dhcp(op: u8, xid: u32, yiaddr: [u8; 4], chaddr: [u8; 6], options: &[u8]) -> Vec<u8> {
    let mut msg = vec![0u8; 236];
    msg[0] = op; // op
    msg[1] = 1; // htype: Ethernet
    msg[2] = 6; // hlen: 6
    msg[4..8].copy_from_slice(&xid.to_be_bytes()); // xid
    msg[16..20].copy_from_slice(&yiaddr); // yiaddr
    msg[28..34].copy_from_slice(&chaddr); // chaddr
    msg.extend_from_slice(&MAGIC_COOKIE);
    msg.extend_from_slice(options);
    msg
}

#[test]
fn zero_alloc_dissect_dhcp_discover() {
    let chaddr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let mut opts = Vec::new();
    opts.extend_from_slice(&[53, 1, 1]); // option 53: DHCP Discover
    opts.extend_from_slice(&[50, 4, 192, 168, 1, 100]); // option 50: requested IP
    opts.push(255); // end

    let raw = build_dhcp(1, 0xDEADBEEF, [0; 4], chaddr, &opts);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        DhcpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "DHCP discover dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_dhcp_offer() {
    let chaddr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let mut opts = Vec::new();
    opts.extend_from_slice(&[53, 1, 2]); // option 53: DHCP Offer
    opts.extend_from_slice(&[54, 4, 192, 168, 1, 1]); // option 54: server ID
    opts.extend_from_slice(&[51, 4, 0, 1, 81, 128]); // option 51: lease time 86400s
    opts.extend_from_slice(&[1, 4, 255, 255, 255, 0]); // option 1: subnet mask
    opts.extend_from_slice(&[3, 4, 192, 168, 1, 1]); // option 3: router
    opts.extend_from_slice(&[6, 4, 8, 8, 8, 8]); // option 6: DNS
    opts.push(255); // end

    let raw = build_dhcp(2, 0xCAFEBABE, [192, 168, 1, 100], chaddr, &opts);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        DhcpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "DHCP offer dissect allocated {allocs} times");
}
