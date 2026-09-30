//! Zero-allocation dissection tests for the IPv6 dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ipv6::Ipv6Dissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_ipv6() {
    // Minimal IPv6 header: 40 bytes fixed.
    let raw: &[u8] = &[
        0x60, 0x00, 0x00, 0x00, // version=6, TC=0, flow label=0
        0x00, 0x14, // payload length = 20
        0x06, // next header = TCP
        0x40, // hop limit = 64
        // src: 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // dst: 2001:db8::2
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Ipv6Dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "IPv6 dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "IPv6");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 8);
    assert_eq!(fields[0].value, FieldValue::U8(6)); // version
    assert_eq!(fields[4].value, FieldValue::U8(6)); // next_header = TCP
}

#[test]
fn zero_alloc_dissect_ipv6_extension_options() {
    use packet_dissector_ipv6::{GenericRoutingDissector, HopByHopDissector, MobilityDissector};

    // Hop-by-Hop: Router Alert, Jumbo Payload, PadN (RFC 8200, Section 4.2).
    let hbh: &[u8] = &[
        0x3a, 0x01, 0x05, 0x02, 0x00, 0x00, 0xC2, 0x04, //
        0x00, 0x01, 0x11, 0x70, 0x01, 0x02, 0x00, 0x00,
    ];
    // Routing Type 3 (RFC 6554, Section 3): three compressed addresses.
    let rh3: &[u8] = &[
        59, 3, 3, 2, 0x8C, 0x40, 0x00, 0x00, 1, 1, 1, 1, 1, 1, 1, 1, //
        2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 0, 0, 0, 0,
    ];
    // Binding Acknowledgement with a Binding Refresh Advice (RFC 6275).
    let mh: &[u8] = &[
        59, 1, 6, 0, 0, 0, 0x00, 0x80, 0x12, 0x34, 0x00, 0x96, 0x02, 0x02, 0x00, 0x3C,
    ];
    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so field capacity is allocated.
    HopByHopDissector.dissect(hbh, &mut buf, 40).unwrap();
    GenericRoutingDissector.dissect(rh3, &mut buf, 56).unwrap();
    MobilityDissector.dissect(mh, &mut buf, 88).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        HopByHopDissector.dissect(hbh, &mut buf, 40).unwrap();
        GenericRoutingDissector.dissect(rh3, &mut buf, 56).unwrap();
        MobilityDissector.dissect(mh, &mut buf, 88).unwrap();
    });
    assert_eq!(allocs, 0, "IPv6 extension headers allocated {allocs} times");
    assert_eq!(buf.layers().len(), 3);
}

#[test]
fn zero_alloc_dissect_ipv6_fragment() {
    use packet_dissector_ipv6::FragmentDissector;

    // IPv6 header (Payload Length 16, Next Header 44) + Fragment header
    // (Fragment Offset 1, M=1) + 8 bytes (RFC 8200, Section 4.5). Building
    // the reassembly context must not allocate.
    let mut raw = vec![0x60, 0, 0, 0, 0x00, 0x10, 44, 64];
    raw.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    raw.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    raw.extend_from_slice(&[17, 0, 0x00, 0x09, 0, 0, 0, 1]);
    raw.extend_from_slice(&[0; 8]);
    let mut buf = DissectBuffer::new();

    let mut result = None;
    let allocs = count_allocs(|| {
        buf.clear();
        Ipv6Dissector.dissect(&raw, &mut buf, 0).unwrap();
        result = Some(FragmentDissector.dissect(&raw[40..], &mut buf, 40).unwrap());
    });
    assert_eq!(allocs, 0, "IPv6 fragment dissect allocated {allocs} times");
    assert!(result.unwrap().ip_fragment_context.is_some());
}
