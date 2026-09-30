//! Zero-allocation dissection tests for the IPv4 dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ipv4::Ipv4Dissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_ipv4() {
    // Minimal IPv4 header: 20 bytes (IHL=5, no options).
    let raw: &[u8] = &[
        0x45, // version=4, IHL=5
        0x00, // DSCP/ECN
        0x00, 0x14, // total length = 20
        0x00, 0x01, // identification
        0x00, 0x00, // flags + fragment offset
        0x40, // TTL = 64
        0x06, // protocol = TCP
        0x00, 0x00, // header checksum (unchecked)
        0xc0, 0xa8, 0x01, 0x64, // src: 192.168.1.100
        0x08, 0x08, 0x08, 0x08, // dst: 8.8.8.8
    ];
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        Ipv4Dissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "IPv4 dissect allocated {allocs} times");

    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "IPv4");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 13); // 13 fields (no options)
    assert_eq!(fields[0].value, FieldValue::U8(4)); // version
    assert_eq!(fields[11].value, FieldValue::Ipv4Addr([192, 168, 1, 100])); // src
    assert_eq!(fields[12].value, FieldValue::Ipv4Addr([8, 8, 8, 8])); // dst
}

#[test]
fn zero_alloc_dissect_ipv4_with_options() {
    // IHL=15: Router Alert, Record Route, Internet Timestamp (flag 1),
    // Quick-Start, NOP padding and End of Option List (RFC 791, Section 3.1).
    let mut raw = vec![
        0x4F, 0x00, 0x00, 0x3C, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, //
        0xc0, 0xa8, 0x01, 0x64, 0xe0, 0x00, 0x00, 0x16,
    ];
    raw.extend_from_slice(&[0x94, 0x04, 0x00, 0x00]); // Router Alert
    raw.extend_from_slice(&[0x07, 0x07, 0x04, 0, 0, 0, 0]); // Record Route
    raw.extend_from_slice(&[0x44, 0x0C, 0x05, 0x01, 10, 0, 0, 1, 0, 0, 0, 0]); // Timestamp
    raw.extend_from_slice(&[0x19, 0x08, 0x05, 0x40, 0x12, 0x34, 0x56, 0x78]); // Quick-Start
    raw.extend_from_slice(&[0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00]); // NOPs + EOL
    raw.push(0x00);
    assert_eq!(raw.len(), 60);
    let mut buf = DissectBuffer::new();
    // Warm up: the option objects need more field slots than the default
    // capacity, so fill the buffer once before counting.
    Ipv4Dissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        Ipv4Dissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "IPv4 dissect with options allocated {allocs} times"
    );
    assert_eq!(buf.layers().len(), 1);
}

#[test]
fn zero_alloc_dissect_ipv4_fragment() {
    // Non-initial fragment: MF=1, Fragment Offset=1 (RFC 791, Section 3.1).
    // Building the reassembly context must not allocate.
    let raw: &[u8] = &[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x2a, 0x20, 0x01, 0x40, 0x11, 0x00, 0x00, //
        0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, //
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x10, 0x00, 0x00,
    ];
    let mut buf = DissectBuffer::new();

    let mut result = None;
    let allocs = count_allocs(|| {
        buf.clear();
        result = Some(Ipv4Dissector.dissect(raw, &mut buf, 0).unwrap());
    });
    assert_eq!(allocs, 0, "IPv4 fragment dissect allocated {allocs} times");
    assert!(result.unwrap().ip_fragment_context.is_some());
}
