//! Radiotap property-based tests.
//!
//! # Radiotap Coverage
//!
//! | Spec (radiotap.org)       | Description                                         | Test                                 |
//! |---------------------------|-----------------------------------------------------|--------------------------------------|
//! | Header                    | Never-panic on arbitrary bytes                      | radiotap_no_panic_on_arbitrary_bytes |
//! | Header, namespaces, TLVs  | Valid it_len with arbitrary presence words / fields | radiotap_no_panic_on_arbitrary_fields |
//!
//! References:
//! - Radiotap header format — <https://www.radiotap.org/>
//! - Defined fields — <https://www.radiotap.org/fields/defined>

use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_radiotap::RadiotapDissector;
use proptest::prelude::*;

/// A presence word biased towards defined fields, namespace switches and the
/// extension bit.
fn arb_present_word() -> impl Strategy<Value = u32> {
    prop_oneof![
        any::<u32>(),
        (any::<u32>(), 0u32..8).prop_map(|(w, top)| (w & 0x0FFF_FFFF) | (top << 28)),
    ]
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn radiotap_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..256)) {
        check_universal(&RadiotapDissector, &data);
    }

    /// A header whose it_len covers the presence words and arbitrary field
    /// octets, followed by arbitrary trailing (802.11) octets.
    #[test]
    fn radiotap_no_panic_on_arbitrary_fields(
        words in prop::collection::vec(arb_present_word(), 1..5),
        fields in prop::collection::vec(any::<u8>(), 0..96),
        tail in prop::collection::vec(any::<u8>(), 0..16),
    ) {
        let count = words.len();
        let mut data = vec![0u8, 0, 0, 0];
        for (i, word) in words.iter().enumerate() {
            // Chain the words with bit 31 so that all of them are used.
            let word = if i + 1 < count { word | 1 << 31 } else { word & !(1 << 31) };
            data.extend_from_slice(&word.to_le_bytes());
        }
        data.extend_from_slice(&fields);
        let it_len = data.len() as u16;
        data[2..4].copy_from_slice(&it_len.to_le_bytes());
        data.extend_from_slice(&tail);
        check_universal(&RadiotapDissector, &data);
    }
}
