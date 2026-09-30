//! Zero-allocation dissection tests for the RSVP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_rsvp::RsvpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

fn message(msg_type: u8, objects: &[&[u8]]) -> Vec<u8> {
    let body = objects.concat();
    let mut v = vec![0x10, msg_type, 0, 0, 255, 0];
    v.extend_from_slice(&((8 + body.len()) as u16).to_be_bytes());
    v.extend_from_slice(&body);
    v
}

/// Asserts that dissecting `raw` allocates nothing and decodes the field
/// `decoded` (so the intended path is exercised).
fn assert_zero_alloc(raw: &[u8], what: &str, decoded: &str) {
    let mut buf = DissectBuffer::new();
    // Warm up: fill the buffer once so capacity is allocated.
    RsvpDissector.dissect(raw, &mut buf, 0).unwrap();
    assert!(
        buf.fields().iter().any(|f| f.name() == decoded),
        "RSVP {what}: {decoded} not decoded"
    );

    let allocs = count_allocs(|| {
        buf.clear();
        RsvpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "RSVP {what} dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_rsvp_path() {
    let raw = message(
        1,
        &[
            &[0, 16, 1, 7, 10, 0, 0, 9, 0, 0, 0, 1, 10, 0, 0, 1],
            &[0, 12, 3, 1, 10, 0, 0, 1, 0, 0, 0, 0],
            &[0, 8, 19, 1, 0, 0, 0x08, 0x00],
            &[
                0, 20, 20, 1, 0x01, 8, 10, 0, 0, 2, 32, 0, 0x81, 8, 10, 0, 0, 9, 32, 0,
            ],
            &[0, 12, 207, 7, 7, 7, 0, 4, b'l', b's', b'p', b'1'],
            &[0, 12, 11, 7, 10, 0, 0, 1, 0, 0, 0, 1],
        ],
    );
    assert_zero_alloc(&raw, "Path", "subobjects");
}

#[test]
fn zero_alloc_dissect_rsvp_resv() {
    let raw = message(
        2,
        &[
            &[0, 16, 1, 7, 10, 0, 0, 9, 0, 0, 0, 1, 10, 0, 0, 1],
            &[0, 8, 8, 1, 0, 0, 0, 0x12],
            &[0, 8, 16, 1, 0, 0, 0, 16],
            &[
                0, 20, 21, 1, 0x01, 8, 10, 0, 0, 2, 32, 1, 0x03, 8, 1, 1, 0, 0, 0, 16,
            ],
        ],
    );
    assert_zero_alloc(&raw, "Resv", "label");
}
