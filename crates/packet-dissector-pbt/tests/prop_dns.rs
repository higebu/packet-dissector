//! DNS property-based tests.
//!
//! # RFC 1035 (DNS) Coverage
//!
//! | RFC Section | Description                               | Test                                |
//! |-------------|-------------------------------------------|-------------------------------------|
//! | 4.1         | Message — never-panic on arbitrary bytes  | dns_no_panic_on_arbitrary_bytes     |
//! | 4.2.2       | TCP framing — never-panic                 | dns_tcp_no_panic_on_arbitrary_bytes |
//! | 3.2.1       | Structured RRs with any RDLENGTH          | dns_no_panic_on_structured_rrs      |
//!
//! References:
//! - RFC 1035, Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1>
//! - RFC 1035, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc1035#section-4.1>
//! - RFC 1035, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc1035#section-4.2.2>

use packet_dissector_dns::{DnsDissector, DnsTcpDissector};
use packet_dissector_mdns::MdnsDissector;
use packet_dissector_pbt::generators::dns::arb_dns_message;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn dns_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        check_universal(&DnsDissector, &data);
        check_universal(&MdnsDissector, &data);
    }

    /// Same for DNS over TCP, which adds a 2-octet length prefix
    /// (RFC 1035, Section 4.2.2 —
    /// <https://www.rfc-editor.org/rfc/rfc1035#section-4.2.2>).
    #[test]
    fn dns_tcp_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        check_universal(&DnsTcpDissector, &data);
    }

    /// Messages built from structured RRs of every decoded TYPE, with names
    /// and character-strings that may straddle RDLENGTH, must never panic
    /// (RFC 1035, Section 3.2.1 —
    /// <https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1>).
    #[test]
    fn dns_no_panic_on_structured_rrs(msg in arb_dns_message()) {
        check_universal(&DnsDissector, &msg);
        check_universal(&MdnsDissector, &msg);
        let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&msg);
        check_universal(&DnsTcpDissector, &framed);
    }
}
