//! RSVP property-based tests.
//!
//! # RFC 2205 (RSVP) Coverage
//!
//! | RFC Section | Description                                          | Test                              |
//! |-------------|------------------------------------------------------|-----------------------------------|
//! | 3.1         | Message — never-panic on arbitrary bytes             | rsvp_no_panic_on_arbitrary_bytes  |
//! | 3.1.2       | Valid header (incl. Bundle), objects of arbitrary class and C-Type | rsvp_no_panic_on_arbitrary_objects |
//!
//! References:
//! - RFC 2205, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc2205#section-3.1>

use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_rsvp::RsvpDissector;
use proptest::prelude::*;

/// An object biased towards the decoded classes, with contents padded to a
/// multiple of 4 or left unaligned.
fn arb_object() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            (1u8..=25),
            Just(63u8),
            Just(205u8),
            Just(207u8),
            any::<u8>()
        ],
        prop_oneof![1u8..=8, any::<u8>()],
        prop::collection::vec(any::<u8>(), 0..48),
        any::<bool>(),
    )
        .prop_map(|(class, ctype, mut contents, aligned)| {
            if aligned {
                contents.resize(contents.len().div_ceil(4) * 4, 0);
            }
            let mut v = ((4 + contents.len()) as u16).to_be_bytes().to_vec();
            v.push(class);
            v.push(ctype);
            v.extend_from_slice(&contents);
            v
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn rsvp_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&RsvpDissector, &data);
    }

    /// A version 1 header with a consistent RSVP Length followed by objects.
    #[test]
    fn rsvp_no_panic_on_arbitrary_objects(
        msg_type in prop_oneof![Just(12u8), any::<u8>()],
        objects in prop::collection::vec(arb_object(), 0..6),
    ) {
        let body = objects.concat();
        let mut data = vec![0x10, msg_type, 0, 0, 255, 0];
        data.extend_from_slice(&((8 + body.len()) as u16).to_be_bytes());
        data.extend_from_slice(&body);
        check_universal(&RsvpDissector, &data);
    }
}
