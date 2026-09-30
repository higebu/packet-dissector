//! Zero-allocation dissection tests for the CDP dissector.

use packet_dissector_cdp::CdpDissector;
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

fn tlv(tlv_type: u16, value: &[u8]) -> Vec<u8> {
    let mut t = tlv_type.to_be_bytes().to_vec();
    t.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
    t.extend_from_slice(value);
    t
}

#[test]
fn zero_alloc_dissect_cdp() {
    let mut raw = vec![0x02, 0xB4, 0x00, 0x00];
    raw.extend(tlv(0x0001, b"sw1"));
    raw.extend(tlv(0x0002, &[0, 0, 0, 1, 1, 1, 0xCC, 0, 4, 192, 0, 2, 1]));
    raw.extend(tlv(0x0004, &[0, 0, 0, 0x29]));
    raw.extend(tlv(0x000A, &[0, 1]));
    raw.extend(tlv(0x000B, &[1]));
    raw.extend(tlv(0x7777, &[0xAB]));

    let mut buf = DissectBuffer::new();
    CdpDissector.dissect(&raw, &mut buf, 22).unwrap();
    let allocs = count_allocs(|| {
        buf.clear();
        CdpDissector.dissect(&raw, &mut buf, 22).unwrap();
    });
    assert_eq!(allocs, 0, "CDP dissect allocated {allocs} times");
}
