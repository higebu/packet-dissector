//! Zero-allocation dissection tests for the BFD dissector.

use packet_dissector_bfd::{BfdDissector, BfdEchoDissector};
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Build a minimal BFD packet.
fn build_bfd(state: u8, detect_mult: u8, my_disc: u32, your_disc: u32) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(24);
    let byte0 = 1u8 << 5; // version=1, diag=0
    let byte1 = state << 6; // state, all flags 0
    pkt.push(byte0);
    pkt.push(byte1);
    pkt.push(detect_mult);
    pkt.push(24); // length
    pkt.extend_from_slice(&my_disc.to_be_bytes());
    pkt.extend_from_slice(&your_disc.to_be_bytes());
    pkt.extend_from_slice(&1_000_000u32.to_be_bytes()); // desired min tx
    pkt.extend_from_slice(&1_000_000u32.to_be_bytes()); // required min rx
    pkt.extend_from_slice(&0u32.to_be_bytes()); // required min echo rx
    pkt
}

#[test]
fn zero_alloc_dissect_bfd_basic() {
    let raw = build_bfd(3, 3, 1, 2); // state=Up

    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        BfdDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "BFD dissect allocated {allocs} times, expected 0"
    );

    // Verify the dissected data is correct.
    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "BFD");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 16); // 16 mandatory fields
    assert_eq!(fields[0].value, FieldValue::U8(1)); // version
}

#[test]
fn zero_alloc_dissect_bfd_with_auth() {
    let mut pkt = Vec::with_capacity(33);
    let byte0 = 1u8 << 5; // version=1, diag=0
    let byte1 = (3u8 << 6) | (1 << 2); // state=Up, auth=1
    pkt.push(byte0);
    pkt.push(byte1);
    pkt.push(3); // detect mult
    pkt.push(33); // length: 24 + 9 (auth section)
    pkt.extend_from_slice(&1u32.to_be_bytes()); // my disc
    pkt.extend_from_slice(&2u32.to_be_bytes()); // your disc
    pkt.extend_from_slice(&1_000_000u32.to_be_bytes());
    pkt.extend_from_slice(&1_000_000u32.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());
    // Auth section: type=1 (Simple Password), len=9, key_id=1, password="secret"
    pkt.push(1); // auth type
    pkt.push(9); // auth len
    pkt.push(1); // key_id
    pkt.extend_from_slice(b"secret");

    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so capacity is allocated.
    BfdDissector.dissect(&pkt, &mut buf, 0).unwrap();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        BfdDissector.dissect(&pkt, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "BFD with auth dissect allocated {allocs} times, expected 0"
    );

    // Verify the dissected data is correct.
    assert_eq!(buf.layers().len(), 1);
    let fields = buf.layer_fields(&buf.layers()[0]);
    // 16 mandatory + auth_type + auth_len + auth_key_id + password
    assert_eq!(fields.len(), 20);
}

#[test]
fn zero_alloc_dissect_bfd_echo() {
    // Control-format Echo (RFC 9747) and opaque Echo (RFC 5880, Section 5).
    let control = build_bfd(1, 3, 1, 0); // state=Down
    let opaque: &[u8] = &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2a];

    let mut buf = DissectBuffer::new();
    BfdEchoDissector.dissect(&control, &mut buf, 0).unwrap();
    buf.clear();
    BfdEchoDissector.dissect(opaque, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        BfdEchoDissector.dissect(&control, &mut buf, 0).unwrap();
        buf.clear();
        BfdEchoDissector.dissect(opaque, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "BFD Echo dissect allocated {allocs} times");
    assert_eq!(buf.layers()[0].name, "BFD Echo");
}
