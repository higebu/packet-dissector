//! BMP property-based tests.
//!
//! # RFC 7854 (BMP) Coverage
//!
//! | RFC Section | Description                                              | Test                              |
//! |-------------|----------------------------------------------------------|-----------------------------------|
//! | 4.1         | Message — never-panic on arbitrary bytes                 | bmp_no_panic_on_arbitrary_bytes   |
//! | 4.1-4.10    | Valid common header, arbitrary per-peer header and body  | bmp_no_panic_on_arbitrary_body    |
//!
//! References:
//! - RFC 7854, Section 4 — <https://www.rfc-editor.org/rfc/rfc7854#section-4>

use packet_dissector_bmp::BmpDissector;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

/// One TLV (Information, Stat or Route Mirroring) with an arbitrary,
/// possibly inconsistent, Length.
fn arb_tlv() -> impl Strategy<Value = Vec<u8>> {
    (
        0u16..8,
        any::<u16>(),
        prop::collection::vec(any::<u8>(), 0..32),
    )
        .prop_map(|(t, len, value)| {
            let mut v = t.to_be_bytes().to_vec();
            v.extend_from_slice(&(len % 40).to_be_bytes());
            v.extend_from_slice(&value);
            v
        })
}

/// A BGP message header (RFC 4271, Section 4.1) with an arbitrary Length and
/// Type, followed by arbitrary octets.
fn arb_bgp_message() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<u16>(),
        1u8..=5,
        prop::collection::vec(any::<u8>(), 0..48),
    )
        .prop_map(|(len, t, body)| {
            let mut v = vec![0xFF; 16];
            v.extend_from_slice(&(len % 80).to_be_bytes());
            v.push(t);
            v.extend_from_slice(&body);
            v
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn bmp_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&BmpDissector, &data);
    }

    /// A version 3 common header with a consistent Message Length, followed
    /// by an arbitrary per-peer header and a body of BGP messages and TLVs.
    #[test]
    fn bmp_no_panic_on_arbitrary_body(
        msg_type in 0u8..8,
        peer_type in 0u8..5,
        flags in any::<u8>(),
        peer_rest in prop::collection::vec(any::<u8>(), 40),
        prefix in prop::collection::vec(any::<u8>(), 0..24),
        bgp in prop::collection::vec(arb_bgp_message(), 0..3),
        tlvs in prop::collection::vec(arb_tlv(), 0..4),
    ) {
        let mut body = vec![peer_type, flags];
        body.extend_from_slice(&peer_rest);
        body.extend_from_slice(&prefix);
        for m in bgp {
            body.extend_from_slice(&m);
        }
        for t in tlvs {
            body.extend_from_slice(&t);
        }
        let mut data = vec![3];
        data.extend_from_slice(&((6 + body.len()) as u32).to_be_bytes());
        data.push(msg_type);
        data.extend_from_slice(&body);
        check_universal(&BmpDissector, &data);
    }
}
