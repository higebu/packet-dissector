//! SCCP property-based tests.
//!
//! # ITU-T Q.713 (SCCP) Coverage
//!
//! | Clause      | Description                                            | Test                               |
//! |-------------|--------------------------------------------------------|------------------------------------|
//! | 1, 2        | Message — never-panic on arbitrary bytes               | sccp_no_panic_on_arbitrary_bytes   |
//! | 1.4, 3.4    | Known message type + arbitrary pointers and parameters | sccp_no_panic_on_known_message_type |
//!
//! References:
//! - ITU-T Q.713 (03/2001) — <https://www.itu.int/rec/T-REC-Q.713>

use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_sccp::SccpDissector;
use proptest::prelude::*;

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn sccp_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&SccpDissector, &data);
    }

    /// Every defined message type code followed by arbitrary octets, so the
    /// pointer, address and optional-part decoding is exercised.
    #[test]
    fn sccp_no_panic_on_known_message_type(
        msg_type in 1u8..=0x14,
        body in prop::collection::vec(any::<u8>(), 0..300),
    ) {
        let mut data = vec![msg_type];
        data.extend_from_slice(&body);
        check_universal(&SccpDissector, &data);
    }
}
