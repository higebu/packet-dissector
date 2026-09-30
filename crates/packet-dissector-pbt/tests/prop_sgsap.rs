//! SGsAP property-based tests.
//!
//! # 3GPP TS 29.118 (SGsAP) Coverage
//!
//! | Section | Description                                   | Test                               |
//! |---------|-----------------------------------------------|------------------------------------|
//! | 9       | Never-panic on arbitrary bytes                | sgsap_no_panic_on_arbitrary_bytes  |
//! | 9.3, 9.4 | Well-formed TLV IEs with arbitrary values    | sgsap_no_panic_on_arbitrary_ies    |
//!
//! References:
//! - 3GPP TS 29.118: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.118/>

use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_sgsap::SgsapDissector;
use proptest::prelude::*;

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn sgsap_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..256)) {
        check_universal(&SgsapDissector, &data);
    }

    /// A message type followed by well-framed IEs whose identifiers are
    /// biased to the assigned range and whose values are arbitrary.
    #[test]
    fn sgsap_no_panic_on_arbitrary_ies(
        message_type in any::<u8>(),
        ies in prop::collection::vec(
            (prop_oneof![1u8..=46, any::<u8>()], prop::collection::vec(any::<u8>(), 0..32)),
            0..8,
        ),
    ) {
        let mut data = vec![message_type];
        for (ie_type, value) in &ies {
            data.push(*ie_type);
            data.push(value.len() as u8);
            data.extend_from_slice(value);
        }
        check_universal(&SgsapDissector, &data);
    }
}
