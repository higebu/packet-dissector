//! PIM property-based tests.
//!
//! # RFC 7761 (PIM-SM) Coverage
//!
//! | RFC Section | Description                                          | Test                             |
//! |-------------|------------------------------------------------------|----------------------------------|
//! | 4.9         | Message — never-panic on arbitrary bytes             | pim_no_panic_on_arbitrary_bytes  |
//! | 4.9.1-4.9.6 | PIMv2 header, arbitrary type and encoded addresses   | pim_no_panic_on_arbitrary_body   |
//!
//! References:
//! - RFC 7761, Section 4.9 — <https://www.rfc-editor.org/rfc/rfc7761#section-4.9>

use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_pim::PimDissector;
use proptest::prelude::*;

/// An encoded address (Unicast, Group or Source) biased towards IPv4 / IPv6
/// and encoding types 0 / 1, with an arbitrary tail.
fn arb_encoded() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![Just(1u8), Just(2), any::<u8>()],
        prop_oneof![Just(0u8), Just(1), any::<u8>()],
        any::<[u8; 2]>(),
        prop::collection::vec(any::<u8>(), 0..24),
    )
        .prop_map(|(family, encoding, flags, tail)| {
            let mut v = vec![family, encoding];
            v.extend_from_slice(&flags);
            v.extend_from_slice(&tail);
            v
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn pim_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&PimDissector, &data);
    }

    /// A PIMv2 header of any type followed by counts and encoded addresses.
    #[test]
    fn pim_no_panic_on_arbitrary_body(
        msg_type in 0u8..16,
        flags in any::<u8>(),
        counts in any::<[u8; 4]>(),
        addrs in prop::collection::vec(arb_encoded(), 0..6),
    ) {
        let mut data = vec![0x20 | msg_type, flags, 0, 0];
        data.extend_from_slice(&counts);
        for a in addrs {
            data.extend_from_slice(&a);
        }
        check_universal(&PimDissector, &data);
    }
}
