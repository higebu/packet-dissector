//! GTPv1-C property-based tests.
//!
//! # 3GPP TS 29.060 (GTPv1-C) Coverage
//!
//! | Section  | Description                                        | Test                                 |
//! |----------|----------------------------------------------------|--------------------------------------|
//! | 6        | Header — never-panic on arbitrary bytes            | gtpv1c_no_panic_on_arbitrary_bytes   |
//! | 6, 7.7   | Valid header + arbitrary extension headers and IEs | gtpv1c_no_panic_on_arbitrary_ies     |
//!
//! References:
//! - 3GPP TS 29.060: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.060/>

use packet_dissector_gtpv1c::Gtpv1cDissector;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

/// One IE with a type biased towards the decoded TV / TLV types and an
/// arbitrary (possibly inconsistent) body.
fn arb_ie() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            Just(1u8),
            Just(2),
            Just(3),
            Just(18),
            Just(128),
            Just(132),
            Just(133),
            Just(137),
            Just(152),
            Just(238),
            Just(255),
            any::<u8>()
        ],
        prop::collection::vec(any::<u8>(), 0..40),
    )
        .prop_map(|(ie_type, body)| {
            let mut ie = vec![ie_type];
            if ie_type & 0x80 != 0 {
                ie.extend_from_slice(&(body.len() as u16).to_be_bytes());
            }
            ie.extend_from_slice(&body);
            ie
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn gtpv1c_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&Gtpv1cDissector, &data);
    }

    /// A valid header (3GPP TS 29.060, Section 6) followed by an arbitrary
    /// extension header chain and IE list.
    #[test]
    fn gtpv1c_no_panic_on_arbitrary_ies(
        flags in 0u8..8,
        next_ext in any::<u8>(),
        ext in prop::collection::vec(any::<u8>(), 0..16),
        ies in prop::collection::vec(arb_ie(), 0..8),
        tail in prop::collection::vec(any::<u8>(), 0..8),
    ) {
        let mut body = Vec::new();
        if flags != 0 {
            body.extend_from_slice(&[0x00, 0x01, 0x00, next_ext]);
            body.extend_from_slice(&ext);
        }
        for ie in ies {
            body.extend_from_slice(&ie);
        }
        let mut data = vec![0x30 | flags, 16];
        data.extend_from_slice(&(body.len() as u16).to_be_bytes());
        data.extend_from_slice(&[0, 0, 0, 1]);
        data.extend_from_slice(&body);
        data.extend_from_slice(&tail);
        check_universal(&Gtpv1cDissector, &data);
    }
}
