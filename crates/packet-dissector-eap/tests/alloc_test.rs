//! Zero-allocation dissection tests for the EAP and EAPOL dissectors.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_eap::{EapDissector, EapolDissector};
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

fn assert_zero_alloc(d: &dyn Dissector, raw: &[u8]) {
    let mut buf = DissectBuffer::new();
    d.dissect(raw, &mut buf, 14).unwrap();
    let allocs = count_allocs(|| {
        buf.clear();
        d.dissect(raw, &mut buf, 14).unwrap();
    });
    assert_eq!(
        allocs,
        0,
        "{} dissect allocated {allocs} times",
        d.short_name()
    );
}

#[test]
fn zero_alloc_dissect_eapol_eap_identity() {
    let raw: &[u8] = &[
        0x02, 0x00, 0x00, 0x0A, // EAPOL-EAP, body 10
        0x02, 0x01, 0x00, 0x0A, 0x01, b'a', b'l', b'i', b'c', b'e',
    ];
    assert_zero_alloc(&EapolDissector, raw);
}

#[test]
fn zero_alloc_dissect_eap_aka_challenge() {
    let mut raw = vec![0x01, 0x21, 0x00, 0x44, 0x17, 0x01, 0x00, 0x00];
    for t in [1u8, 2, 11] {
        raw.extend_from_slice(&[t, 5, 0, 0]);
        raw.extend_from_slice(&[t; 16]);
    }
    assert_zero_alloc(&EapDissector, &raw);
}

#[test]
fn zero_alloc_dissect_eap_tls_and_nak() {
    assert_zero_alloc(
        &EapDissector,
        &[
            0x02, 0x06, 0x00, 0x0D, 0x0D, 0xC0, 0x00, 0x00, 0x04, 0x00, 0x16, 0x03, 0x01,
        ],
    );
    assert_zero_alloc(&EapDissector, &[0x02, 0x02, 0x00, 0x07, 0x03, 13, 25]);
}
