//! NSH property-based tests.
//!
//! # RFC 8300 (NSH) Coverage
//!
//! | RFC Section | Description                                            | Test                               |
//! |-------------|--------------------------------------------------------|------------------------------------|
//! | 2.2         | Base Header — never-panic on arbitrary bytes           | nsh_no_panic_on_arbitrary_bytes    |
//! | 2.5.1       | MD Type 2 with arbitrary Context Headers and Length    | nsh_no_panic_on_md2_context        |
//!
//! References:
//! - RFC 8300, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc8300#section-2.2>
//! - RFC 8300, Section 2.5.1 — <https://www.rfc-editor.org/rfc/rfc8300#section-2.5.1>

use packet_dissector_nsh::NshDissector;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn nsh_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..300)) {
        check_universal(&NshDissector, &data);
    }

    /// A version 0, MD Type 2 header with an arbitrary Length and arbitrary
    /// Context Header bytes (RFC 8300, Section 2.5.1 —
    /// <https://www.rfc-editor.org/rfc/rfc8300#section-2.5.1>).
    #[test]
    fn nsh_no_panic_on_md2_context(
        length in 0u8..64,
        next_protocol in any::<u8>(),
        body in prop::collection::vec(any::<u8>(), 0..260),
    ) {
        let w0: u32 = (63 << 22) | (u32::from(length) << 16) | (2 << 8) | u32::from(next_protocol);
        let mut data = w0.to_be_bytes().to_vec();
        data.extend_from_slice(&[0x00, 0x00, 0x01, 0xFF]);
        data.extend_from_slice(&body);
        check_universal(&NshDissector, &data);
    }
}
