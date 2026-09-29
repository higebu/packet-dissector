//! ICMP / ICMPv6 property-based tests.
//!
//! # RFC 792 / RFC 4443 / RFC 4884 Coverage
//!
//! | RFC Section          | Description                                 | Test                                  |
//! |----------------------|---------------------------------------------|---------------------------------------|
//! | 792, 4443 §2.1       | Any message — never-panic                   | icmp_no_panic_on_arbitrary_bytes      |
//! | 4443 §2.1            | Every ICMPv6 type with arbitrary body       | icmpv6_every_type_no_panic            |
//! | 4884 §4, §7          | Error messages with an Extension Structure  | icmpv6_error_with_extensions_no_panic |
//!
//! References:
//! - RFC 792 — <https://www.rfc-editor.org/rfc/rfc792>
//! - RFC 4443, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc4443#section-2.1>
//! - RFC 4884, Section 7 — <https://www.rfc-editor.org/rfc/rfc4884#section-7>

use packet_dissector_icmp::IcmpDissector;
use packet_dissector_icmpv6::Icmpv6Dissector;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn icmp_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&IcmpDissector, &data);
        check_universal(&Icmpv6Dissector, &data);
    }

    /// Every ICMPv6 type and code with an arbitrary body satisfies the
    /// universal invariants (the TLV walkers see every body shape).
    #[test]
    fn icmpv6_every_type_no_panic(
        icmp_type in any::<u8>(),
        code in any::<u8>(),
        body in prop::collection::vec(any::<u8>(), 4..256),
    ) {
        let mut data = vec![icmp_type, code, 0, 0];
        data.extend_from_slice(&body);
        check_universal(&Icmpv6Dissector, &data);
    }

    /// Destination Unreachable / Time Exceeded with a Length attribute and
    /// an arbitrary Extension Structure satisfy the universal invariants.
    #[test]
    fn icmpv6_error_with_extensions_no_panic(
        icmp_type in prop::sample::select(vec![1u8, 3u8]),
        length in 0u8..=40,
        body in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut data = vec![icmp_type, 0, 0, 0, length, 0, 0, 0];
        data.extend_from_slice(&body);
        check_universal(&Icmpv6Dissector, &data);
    }
}
