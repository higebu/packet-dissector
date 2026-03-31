//! Zero-allocation dissection tests for the SRv6 dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_srv6::{CsidFlavor, MobileSidEncoding, SidStructure, Srv6Dissector};
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Build an SRv6 Segment Routing Header.
///
/// RFC 8754, Section 2: next_header(1)+hdr_ext_len(1)+routing_type=4(1)+
/// segments_left(1)+last_entry(1)+flags(1)+tag(2)+segment_list(n*16).
fn build_srh(next_header: u8, segments_left: u8, segments: &[[u8; 16]]) -> Vec<u8> {
    let num_segs = segments.len();
    let total_len = 8 + num_segs * 16;
    let hdr_ext_len = (total_len / 8 - 1) as u8;
    let last_entry = if num_segs == 0 {
        0
    } else {
        (num_segs - 1) as u8
    };
    let mut hdr = vec![
        next_header,
        hdr_ext_len,
        4, // routing type = 4 (SRH)
        segments_left,
        last_entry,
        0, // flags
    ];
    hdr.extend_from_slice(&0u16.to_be_bytes()); // tag
    for seg in segments {
        hdr.extend_from_slice(seg);
    }
    hdr
}

const SID_A: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const SID_B: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];
const SID_C: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
];

#[test]
fn zero_alloc_dissect_srv6_single_segment() {
    let raw = build_srh(6 /* TCP */, 1, &[SID_A]);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Srv6Dissector::new().dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "expected zero allocations during dissection");
}

#[test]
fn zero_alloc_dissect_srv6_multi_segment() {
    let raw = build_srh(17 /* UDP */, 2, &[SID_A, SID_B, SID_C]);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Srv6Dissector::new().dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "expected zero allocations during dissection");
}

#[test]
fn zero_alloc_dissect_srv6_mobile_gtp6_e() {
    // End.M.GTP6.E with Args.Mob.Session in argument portion.
    let sid: [u8; 16] = [
        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x47, 0x24, 0x12, 0x34, 0x56, 0x78,
        0x00,
    ];
    let ss = SidStructure {
        locator_block_bits: 48,
        locator_node_bits: 16,
        function_bits: 16,
        argument_bits: 48,
        csid_flavor: CsidFlavor::Classic,
        mobile_encoding: Some(MobileSidEncoding::EndMGtp6E),
    };
    let dissector = Srv6Dissector::with_sid_structure(ss);
    let raw = build_srh(6, 1, &[sid]);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "expected zero allocations during dissection");
}

#[test]
fn zero_alloc_dissect_srv6_mobile_gtp4_e() {
    // End.M.GTP4.E with embedded IPv4 + Args.Mob.Session.
    let sid: [u8; 16] = [
        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x14, 0x00, 0x00, 0x00, 0x42,
        0x00,
    ];
    let ss = SidStructure {
        locator_block_bits: 32,
        locator_node_bits: 0,
        function_bits: 16,
        argument_bits: 80,
        csid_flavor: CsidFlavor::Classic,
        mobile_encoding: Some(MobileSidEncoding::EndMGtp4E {
            ipv4da_bits: 32,
            args_mob_session_bits: 40,
        }),
    };
    let dissector = Srv6Dissector::with_sid_structure(ss);
    let raw = build_srh(6, 1, &[sid]);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "expected zero allocations during dissection");
}
