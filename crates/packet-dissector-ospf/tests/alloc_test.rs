//! Zero-allocation dissection tests for the OSPF dissectors.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ospf::{Ospfv2Dissector, Ospfv3Dissector};
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_ospfv2_hello() {
    // OSPFv2 Hello: 24-byte header + 20-byte hello body = 44 bytes, no neighbors.
    let mut raw = Vec::new();
    // Common header
    raw.push(2); // Version
    raw.push(1); // Type = Hello
    raw.extend_from_slice(&44u16.to_be_bytes()); // Packet Length
    raw.extend_from_slice(&[1, 1, 1, 1]); // Router ID
    raw.extend_from_slice(&[0, 0, 0, 0]); // Area ID
    raw.extend_from_slice(&[0x00, 0x00]); // Checksum
    raw.extend_from_slice(&[0x00, 0x00]); // Auth Type (Null)
    raw.extend_from_slice(&[0u8; 8]); // Authentication
    // Hello body
    raw.extend_from_slice(&[255, 255, 255, 0]); // Network Mask
    raw.extend_from_slice(&10u16.to_be_bytes()); // Hello Interval
    raw.push(0x02); // Options
    raw.push(1); // Router Priority
    raw.extend_from_slice(&40u32.to_be_bytes()); // Router Dead Interval
    raw.extend_from_slice(&[10, 0, 0, 1]); // DR
    raw.extend_from_slice(&[0, 0, 0, 0]); // BDR

    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so capacity is allocated
    Ospfv2Dissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Ospfv2Dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "OSPFv2 dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_ospfv3_hello() {
    // OSPFv3 Hello: 16-byte header + 20-byte hello body = 36 bytes, no neighbors.
    let mut raw = Vec::new();
    // Common header
    raw.push(3); // Version
    raw.push(1); // Type = Hello
    raw.extend_from_slice(&36u16.to_be_bytes()); // Packet Length
    raw.extend_from_slice(&[1, 1, 1, 1]); // Router ID
    raw.extend_from_slice(&[0, 0, 0, 0]); // Area ID
    raw.extend_from_slice(&[0x00, 0x00]); // Checksum
    raw.push(0); // Instance ID
    raw.push(0); // Reserved
    // Hello body
    raw.extend_from_slice(&[0, 0, 0, 1]); // Interface ID
    raw.push(1); // Router Priority
    raw.extend_from_slice(&[0x00, 0x00, 0x13]); // Options (24-bit)
    raw.extend_from_slice(&10u16.to_be_bytes()); // Hello Interval
    raw.extend_from_slice(&40u16.to_be_bytes()); // Router Dead Interval
    raw.extend_from_slice(&[10, 0, 0, 1]); // DR
    raw.extend_from_slice(&[0, 0, 0, 0]); // BDR

    let mut buf = DissectBuffer::new();
    // Warm up
    Ospfv3Dissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Ospfv3Dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "OSPFv3 dissect allocated {allocs} times");
}

/// Build a TLV (type, length, value) padded to a 4-octet boundary.
fn tlv(t: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&t.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// Build an LSA with a 20-byte header (LS Type as the 16-bit field at
/// offset 2) and the given body.
fn lsa(ls_type: [u8; 2], link_state_id: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 1, ls_type[0], ls_type[1]];
    out.extend_from_slice(&link_state_id);
    out.extend_from_slice(&[1, 1, 1, 1, 0x80, 0, 0, 1, 0, 0]);
    out.extend_from_slice(&((20 + body.len()) as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[test]
fn zero_alloc_dissect_ospfv2_lsu_with_bodies_and_digest() {
    // Router-LSA with one stub link.
    let router = lsa(
        [2, 1],
        [1, 1, 1, 1],
        &[0, 0, 0, 1, 10, 0, 0, 0, 255, 0, 0, 0, 3, 0, 0, 10],
    );
    // Router Information Opaque LSA with SR capabilities.
    let mut ri = tlv(8, &[0, 1]);
    let mut range = vec![0, 0x1f, 0x40, 0];
    range.extend(tlv(1, &[0, 0x3e, 0x80]));
    ri.extend(tlv(9, &range));
    let ri = lsa([2, 10], [4, 0, 0, 0], &ri);
    // Extended Prefix Opaque LSA with a Prefix-SID.
    let mut prefix = vec![1, 32, 0, 0x40, 10, 0, 0, 1];
    prefix.extend(tlv(2, &[0x40, 0, 0, 0, 0, 0, 0, 101]));
    let ext = lsa([2, 10], [7, 0, 0, 1], &tlv(1, &prefix));

    let total = 28 + router.len() + ri.len() + ext.len();
    let mut raw = vec![2, 4];
    raw.extend_from_slice(&(total as u16).to_be_bytes());
    raw.extend_from_slice(&[1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 2]);
    raw.extend_from_slice(&[0, 0, 1, 16, 0, 0, 0, 1]); // crypto auth
    raw.extend_from_slice(&3u32.to_be_bytes());
    raw.extend(router);
    raw.extend(ri);
    raw.extend(ext);
    raw.extend_from_slice(&[0xAA; 16]); // digest

    let mut buf = DissectBuffer::new();
    Ospfv2Dissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Ospfv2Dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "OSPFv2 LSU dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_ospfv3_lsu_with_extended_lsas_and_trailer() {
    // E-Router-LSA with a Router-Link TLV carrying an Adj-SID.
    let mut link = vec![1, 0, 0, 10, 0, 0, 0, 5, 0, 0, 0, 6, 2, 2, 2, 2];
    link.extend(tlv(5, &[0x60, 1, 0, 0, 0, 0x5d, 0xc0]));
    let mut body = vec![1, 0, 0, 0x13];
    body.extend(tlv(1, &link));
    let e_router = lsa([0xA0, 0x21], [0, 0, 0, 0], &body);
    // Intra-Area-Prefix-LSA with one /64.
    let mut iap = vec![0, 1, 0x20, 0x01, 0, 0, 0, 0, 1, 1, 1, 1, 64, 0, 0, 1];
    iap.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]);
    let iap = lsa([0x20, 0x09], [0, 0, 0, 1], &iap);

    let total = 20 + e_router.len() + iap.len();
    let mut raw = vec![3, 4];
    raw.extend_from_slice(&(total as u16).to_be_bytes());
    raw.extend_from_slice(&[1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
    raw.extend_from_slice(&2u32.to_be_bytes());
    raw.extend(e_router);
    raw.extend(iap);
    // Authentication Trailer (RFC 7166) with a 32-byte digest.
    // <https://www.rfc-editor.org/rfc/rfc7166>
    raw.extend_from_slice(&[0, 1, 0, 48, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]);
    raw.extend_from_slice(&[0xBB; 32]);

    let mut buf = DissectBuffer::new();
    Ospfv3Dissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Ospfv3Dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "OSPFv3 LSU dissect allocated {allocs} times");
}
