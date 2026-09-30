//! LDP property-based tests.
//!
//! # RFC 5036 (LDP) Coverage
//!
//! | RFC Section | Description                                          | Test                             |
//! |-------------|------------------------------------------------------|----------------------------------|
//! | 3.1         | PDU — never-panic on arbitrary bytes                 | ldp_no_panic_on_arbitrary_bytes  |
//! | 3.1-3.5     | Valid PDU header, arbitrary messages and TLVs        | ldp_no_panic_on_arbitrary_body   |
//!
//! References:
//! - RFC 5036, Section 3 — <https://www.rfc-editor.org/rfc/rfc5036#section-3>

use packet_dissector_ldp::LdpDissector;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

/// A TLV biased towards the decoded types, with an arbitrary value.
fn arb_tlv() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            Just(0x0100u16),
            Just(0x0101),
            Just(0x0104),
            Just(0x0300),
            Just(0x0400),
            Just(0x0500),
            Just(0x096B),
            any::<u16>()
        ],
        prop::collection::vec(any::<u8>(), 0..40),
        any::<bool>(),
    )
        .prop_map(|(t, value, consistent)| {
            let mut v = t.to_be_bytes().to_vec();
            let len = if consistent {
                value.len() as u16
            } else {
                value.len() as u16 + 3
            };
            v.extend_from_slice(&len.to_be_bytes());
            v.extend_from_slice(&value);
            v
        })
}

/// A message with a consistent Message Length.
fn arb_message() -> impl Strategy<Value = Vec<u8>> {
    (any::<u16>(), prop::collection::vec(arb_tlv(), 0..4)).prop_map(|(t, tlvs)| {
        let body: Vec<u8> = tlvs.concat();
        let mut v = t.to_be_bytes().to_vec();
        v.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, 1]);
        v.extend_from_slice(&body);
        v
    })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn ldp_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&LdpDissector, &data);
    }

    /// A version 1 PDU header with a consistent PDU Length and arbitrary
    /// messages.
    #[test]
    fn ldp_no_panic_on_arbitrary_body(messages in prop::collection::vec(arb_message(), 0..4)) {
        let body: Vec<u8> = messages.concat();
        let mut data = vec![0, 1];
        data.extend_from_slice(&((6 + body.len()) as u16).to_be_bytes());
        data.extend_from_slice(&[10, 0, 0, 1, 0, 0]);
        data.extend_from_slice(&body);
        check_universal(&LdpDissector, &data);
    }
}
