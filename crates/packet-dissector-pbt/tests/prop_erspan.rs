//! ERSPAN property-based tests.
//!
//! # draft-foschiano-erspan-03 (ERSPAN) Coverage
//!
//! | Section | Description                                          | Test                                  |
//! |---------|------------------------------------------------------|---------------------------------------|
//! | 4.2     | Type II (Ver=1) — never-panic on arbitrary bytes     | erspan2_no_panic_on_arbitrary_bytes   |
//! | 4.3     | Type III — never-panic on arbitrary bytes            | erspan3_no_panic_on_arbitrary_bytes   |
//! | 4.3     | Type III header with O=1 and an arbitrary tail       | erspan3_no_panic_with_subheader       |
//!
//! References:
//! - draft-foschiano-erspan-03, Section 4 —
//!   <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4>

use packet_dissector_erspan::{ErspanDissector, ErspanType3Dissector};
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

proptest! {
    /// Arbitrary bytes after a Ver=1 nibble must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law). Without an
    /// enclosing GRE layer, the Ver nibble selects Type II; Type I pushes no
    /// layer by design (Section 4.1) and is covered by the crate's unit tests.
    #[test]
    fn erspan2_no_panic_on_arbitrary_bytes(
        low in 0u8..16,
        rest in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut data = vec![0x10 | low];
        data.extend_from_slice(&rest);
        check_universal(&ErspanDissector, &data);
    }

    /// Dissecting arbitrary byte sequences with the Type III dissector must
    /// never panic and must satisfy the universal invariants.
    #[test]
    fn erspan3_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..64)) {
        check_universal(&ErspanType3Dissector, &data);
    }

    /// A Type III header (Ver=2) with the O flag set and an arbitrary,
    /// possibly short, tail (draft-foschiano-erspan-03, Section 4.3 —
    /// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3>).
    #[test]
    fn erspan3_no_panic_with_subheader(
        head in prop::array::uniform12(any::<u8>()),
        tail in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let mut data = head.to_vec();
        data[0] = 0x20 | (data[0] & 0x0F);
        data[11] |= 0x01;
        data.extend_from_slice(&tail);
        check_universal(&ErspanType3Dissector, &data);
    }
}
