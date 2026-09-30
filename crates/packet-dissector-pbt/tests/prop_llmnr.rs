//! LLMNR property-based tests.
//!
//! # RFC 4795 (LLMNR) Coverage
//!
//! | RFC Section       | Description                                  | Test                                  |
//! |-------------------|----------------------------------------------|---------------------------------------|
//! | 4795 §2.1         | Message — never-panic on arbitrary bytes     | llmnr_no_panic_on_arbitrary_bytes     |
//! | 4795 §2.1, 2.4    | TCP framing — never-panic                    | llmnr_no_panic_on_arbitrary_bytes     |
//! | 4795 §2.1.1       | Structured RRs with any header flags         | llmnr_no_panic_on_structured_messages |
//!
//! References:
//! - RFC 4795, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc4795#section-2.1>
//! - RFC 4795, Section 2.1.1 — <https://www.rfc-editor.org/rfc/rfc4795#section-2.1.1>
//! - RFC 1035, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc1035#section-4.2.2>

use packet_dissector_llmnr::{LlmnrDissector, LlmnrTcpDissector};
use packet_dissector_pbt::generators::dns::arb_malformed_dns_message;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn llmnr_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        check_universal(&LlmnrDissector, &data);
        check_universal(&LlmnrTcpDissector, &data);
    }

    /// DNS-format messages built from structured RRs, with arbitrary LLMNR
    /// header flags, over UDP and TCP framing.
    #[test]
    fn llmnr_no_panic_on_structured_messages(
        mut msg in arb_malformed_dns_message(),
        flags in any::<u16>(),
    ) {
        if msg.len() >= 4 {
            msg[2..4].copy_from_slice(&flags.to_be_bytes());
        }
        check_universal(&LlmnrDissector, &msg);
        let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&msg);
        check_universal(&LlmnrTcpDissector, &framed);
    }
}
