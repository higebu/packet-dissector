//! Zero-allocation dissection tests for the raw IP link-type dispatchers.

use packet_dissector_core::dissector::{DispatchHint, Dissector};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_raw_ip::{RawIpDissector, RawIpv4Dissector, RawIpv6Dissector};
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_raw_ip() {
    let v4: &[u8] = &[0x45, 0x00];
    let v6: &[u8] = &[0x60, 0x00];
    let mut buf = DissectBuffer::new();
    let mut hints = [
        DispatchHint::End,
        DispatchHint::End,
        DispatchHint::End,
        DispatchHint::End,
    ];

    let allocs = count_allocs(|| {
        buf.clear();
        hints[0] = RawIpDissector.dissect(v4, &mut buf, 0).unwrap().next;
        hints[1] = RawIpDissector.dissect(v6, &mut buf, 0).unwrap().next;
        hints[2] = RawIpv4Dissector.dissect(v4, &mut buf, 0).unwrap().next;
        hints[3] = RawIpv6Dissector.dissect(v6, &mut buf, 0).unwrap().next;
    });
    assert_eq!(allocs, 0, "raw IP dispatch allocated {allocs} times");

    assert!(buf.layers().is_empty());
    assert_eq!(hints[0], DispatchHint::ByEtherType(0x0800));
    assert_eq!(hints[1], DispatchHint::ByEtherType(0x86DD));
    assert_eq!(hints[2], DispatchHint::ByEtherType(0x0800));
    assert_eq!(hints[3], DispatchHint::ByEtherType(0x86DD));
}
