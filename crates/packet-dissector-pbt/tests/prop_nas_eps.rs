//! EPS NAS property-based tests.
//!
//! # 3GPP TS 24.301 (EPS NAS) Coverage
//!
//! | Section  | Description                                          | Test                                  |
//! |----------|------------------------------------------------------|---------------------------------------|
//! | 9.1      | Never-panic on arbitrary bytes                       | nas_eps_no_panic_on_arbitrary_bytes   |
//! | 8, 9.9   | Valid EMM / ESM header + arbitrary IEs               | nas_eps_no_panic_on_arbitrary_body    |
//!
//! References:
//! - 3GPP TS 24.301: <https://www.3gpp.org/ftp/Specs/archive/24_series/24.301/>

use packet_dissector_nas_eps::NasEpsDissector;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn nas_eps_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..256)) {
        check_universal(&NasEpsDissector, &data);
    }

    /// A plain or integrity protected EMM header, or an ESM header, with a
    /// message type biased to the decoded tables and an arbitrary body.
    #[test]
    fn nas_eps_no_panic_on_arbitrary_body(
        esm in any::<bool>(),
        protected in any::<bool>(),
        message_type in prop_oneof![0x41u8..=0x69, 0xC1u8..=0xEB, any::<u8>()],
        body in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut data = Vec::new();
        if protected {
            data.extend_from_slice(&[0x17, 0, 0, 0, 0, 0]);
        }
        if esm {
            data.extend_from_slice(&[0x52, 0x01, message_type]);
        } else {
            data.extend_from_slice(&[0x07, message_type]);
        }
        data.extend_from_slice(&body);
        check_universal(&NasEpsDissector, &data);
    }
}
