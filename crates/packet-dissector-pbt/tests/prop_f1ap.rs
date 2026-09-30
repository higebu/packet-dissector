//! F1AP property-based tests.
//!
//! # 3GPP TS 38.473 (F1AP) Coverage
//!
//! | Spec Section | Description                                          | Test                                  |
//! |--------------|------------------------------------------------------|---------------------------------------|
//! | 9.4          | PDU — never-panic on arbitrary bytes                 | f1ap_no_panic_on_arbitrary_bytes      |
//! | 9.4          | ProtocolIE-Container with arbitrary decoded IE values | f1ap_no_panic_on_arbitrary_ie_values  |
//! | 9.4          | Mutated / truncated valid message                    | f1ap_no_panic_on_mutated_message      |
//!
//! References:
//! - 3GPP TS 38.473: <https://www.3gpp.org/ftp/Specs/archive/38_series/38.473/>
//! - ITU-T Rec. X.691 (APER): <https://www.itu.int/rec/T-REC-X.691>

use packet_dissector_f1ap::F1apDissector;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

/// IE IDs that have a structured value decoder.
const DECODED_IE_IDS: &[u16] = &[
    0, 20, 21, 26, 27, 28, 29, 40, 41, 42, 44, 45, 50, 63, 64, 77, 78, 82, 95, 111, 128, 165, 218,
    241,
];

/// A valid message (pycrate APER encoding).
const VALID: &[u8] = &[
    0x40, 0x05, 0x00, 0x45, 0x00, 0x00, 0x04, 0x00, 0x28, 0x00, 0x02, 0x00, 0x01, 0x00, 0x29, 0x00,
    0x02, 0x00, 0x07, 0x00, 0x27, 0x00, 0x04, 0x00, 0x02, 0x5c, 0x00, 0x00, 0x1b, 0x40, 0x2a, 0x04,
    0x00, 0x1a, 0x40, 0x0c, 0x40, 0x06, 0x00, 0x7c, 0x0a, 0x00, 0x00, 0x02, 0x00, 0x00, 0x10, 0x01,
    0x00, 0x1a, 0x40, 0x15, 0x00, 0xc0, 0x1f, 0x0a, 0x00, 0x00, 0x02, 0x00, 0x00, 0x10, 0x02, 0x00,
    0x7c, 0x0a, 0x00, 0x00, 0x03, 0x00, 0x00, 0x10, 0x03,
];

/// One ProtocolIE-Field with a decoded IE ID (or any ID) and an arbitrary
/// value of at most 127 octets (one-octet length determinant).
fn arb_ie() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            3 => prop::sample::select(DECODED_IE_IDS),
            1 => any::<u16>()
        ],
        0u8..3,
        prop::collection::vec(any::<u8>(), 0..127),
    )
        .prop_map(|(id, crit, value)| {
            let mut ie = id.to_be_bytes().to_vec();
            ie.push(crit << 6);
            ie.push(value.len() as u8);
            ie.extend_from_slice(&value);
            ie
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn f1ap_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&F1apDissector, &data);
    }

    /// A well-formed PDU header and IE container whose IE values are
    /// arbitrary, so that every value decoder sees malformed input.
    #[test]
    fn f1ap_no_panic_on_arbitrary_ie_values(
        pdu_type in 0u8..3,
        procedure_code in any::<u8>(),
        ies in prop::collection::vec(arb_ie(), 0..6),
    ) {
        let mut value = vec![0x00];
        value.extend_from_slice(&(ies.len() as u16).to_be_bytes());
        for ie in &ies {
            value.extend_from_slice(ie);
        }
        // F1AP-PDU has no extension marker: the 2-bit index leads the octet.
        let mut data = vec![pdu_type << 6, procedure_code, 0x00];
        let len = value.len() as u16;
        if len < 128 {
            data.push(len as u8);
        } else {
            data.extend_from_slice(&(0x8000 | len).to_be_bytes());
        }
        data.extend_from_slice(&value);
        check_universal(&F1apDissector, &data);
    }

    /// A valid message with arbitrary octets overwritten and truncated.
    #[test]
    fn f1ap_no_panic_on_mutated_message(
        edits in prop::collection::vec((0..VALID.len(), any::<u8>()), 0..8),
        len in 0..=VALID.len(),
    ) {
        let mut data = VALID.to_vec();
        for (pos, byte) in edits {
            data[pos] = byte;
        }
        data.truncate(len);
        check_universal(&F1apDissector, &data);
    }
}
