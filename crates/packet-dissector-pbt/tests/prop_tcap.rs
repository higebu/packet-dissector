//! TCAP property-based tests.
//!
//! # ITU-T Q.773 (TCAP) Coverage
//!
//! | Clause  | Description                                         | Test                              |
//! |---------|-----------------------------------------------------|-----------------------------------|
//! | 3.1     | Message — never-panic on arbitrary bytes            | tcap_no_panic_on_arbitrary_bytes  |
//! | 3.1, 4  | Known message type tag + arbitrary BER contents     | tcap_no_panic_on_known_type       |
//!
//! References:
//! - ITU-T Q.773 (06/97) — <https://www.itu.int/rec/T-REC-Q.773>

use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_tcap::TcapDissector;
use proptest::prelude::*;

/// A BER element with a tag biased towards the TCAP tags and a length that
/// may be definite (possibly inconsistent) or indefinite.
fn arb_element() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            Just(0x48u8),
            Just(0x49),
            Just(0x4a),
            Just(0x6b),
            Just(0x6c),
            Just(0xa1),
            Just(0xa2),
            Just(0xa4),
            Just(0x02),
            Just(0x06),
            Just(0x28),
            any::<u8>()
        ],
        prop_oneof![Just(0x80u8), any::<u8>()],
        prop::collection::vec(any::<u8>(), 0..48),
    )
        .prop_map(|(tag, len, body)| {
            let mut e = vec![tag, len];
            e.extend_from_slice(&body);
            e
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn tcap_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&TcapDissector, &data);
    }

    /// A message type tag with a consistent length followed by arbitrary
    /// elements, so the transaction, dialogue and component decoding runs.
    #[test]
    fn tcap_no_panic_on_known_type(
        tag in prop_oneof![Just(0x61u8), Just(0x62), Just(0x64), Just(0x65), Just(0x67)],
        elements in prop::collection::vec(arb_element(), 0..6),
    ) {
        let body: Vec<u8> = elements.concat();
        let mut data = vec![tag, 0x82, (body.len() >> 8) as u8, body.len() as u8];
        data.extend_from_slice(&body);
        check_universal(&TcapDissector, &data);
    }
}
