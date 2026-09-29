//! IS-IS property-based tests.
//!
//! # ISO/IEC 10589 / IS-IS TLV Coverage
//!
//! | Spec Section                  | Description                           | Test                              |
//! |-------------------------------|---------------------------------------|-----------------------------------|
//! | ISO 10589 §9.5                | Common header — never-panic           | isis_no_panic_on_arbitrary_bytes  |
//! | ISO 10589 §9.9, RFC 5305 §3-4 | LSP with arbitrary TLVs and sub-TLVs  | isis_lsp_arbitrary_tlvs           |
//!
//! References:
//! - RFC 5305, Sections 3-4 — <https://www.rfc-editor.org/rfc/rfc5305#section-3>

use packet_dissector_isis::IsisDissector;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

/// An L1 LSP carrying `tlvs` as its TLV area.
fn lsp(tlvs: &[u8]) -> Vec<u8> {
    let mut pdu = vec![0x83, 27, 0x01, 0x00, 18, 0x01, 0x00, 0x00];
    pdu.extend_from_slice(&((27 + tlvs.len()) as u16).to_be_bytes());
    pdu.extend_from_slice(&[
        0x04, 0xB0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 1, 0xAB, 0xCD, 3,
    ]);
    pdu.extend_from_slice(tlvs);
    pdu
}

/// A single TLV with a type from the decoded set and an arbitrary value.
fn arb_tlv() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            Just(10u8),
            Just(22),
            Just(27),
            Just(128),
            Just(135),
            Just(149),
            Just(150),
            Just(211),
            Just(222),
            Just(229),
            Just(235),
            Just(236),
            Just(237),
            Just(240),
            Just(242),
            any::<u8>(),
        ],
        prop::collection::vec(any::<u8>(), 0..=255),
    )
        .prop_map(|(t, value)| {
            let mut out = vec![t, value.len() as u8];
            out.extend(value);
            out
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn isis_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        check_universal(&IsisDissector, &data);
    }

    /// Structurally valid LSPs whose TLVs carry arbitrary values (including
    /// malformed sub-TLVs) satisfy the universal invariants.
    #[test]
    fn isis_lsp_arbitrary_tlvs(tlvs in prop::collection::vec(arb_tlv(), 0..6)) {
        let area: Vec<u8> = tlvs.concat();
        check_universal(&IsisDissector, &lsp(&area));
    }
}
