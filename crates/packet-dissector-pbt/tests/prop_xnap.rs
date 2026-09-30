//! XnAP property-based tests.
//!
//! # 3GPP TS 38.423 (XnAP) Coverage
//!
//! | Spec Section | Description                                          | Test                                  |
//! |--------------|------------------------------------------------------|---------------------------------------|
//! | 9.3          | PDU — never-panic on arbitrary bytes                 | xnap_no_panic_on_arbitrary_bytes      |
//! | 9.3          | ProtocolIE-Container with arbitrary decoded IE values | xnap_no_panic_on_arbitrary_ie_values  |
//! | 9.3          | Mutated / truncated valid message                    | xnap_no_panic_on_mutated_message      |
//!
//! References:
//! - 3GPP TS 38.423: <https://www.3gpp.org/ftp/Specs/archive/38_series/38.423/>
//! - ITU-T Rec. X.691 (APER): <https://www.itu.int/rec/T-REC-X.691>

use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_xnap::XnapDissector;
use proptest::prelude::*;

/// IE IDs that have a structured value decoder.
const DECODED_IE_IDS: &[u16] = &[7, 14, 23, 24, 42, 64, 72, 73, 76, 77, 78, 79, 130, 161, 254];

/// A valid message (pycrate APER encoding).
const VALID: &[u8] = &[
    0x20, 0x00, 0x00, 0x58, 0x00, 0x00, 0x04, 0x00, 0x49, 0x40, 0x02, 0x00, 0x64, 0x00, 0x4f, 0x40,
    0x02, 0x00, 0xc8, 0x00, 0x2a, 0x40, 0x3d, 0x01, 0x00, 0x01, 0x70, 0x10, 0x08, 0x08, 0x14, 0x0d,
    0x88, 0x08, 0xe0, 0x00, 0x20, 0x3e, 0x0a, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x50, 0x01, 0x01, 0xf0,
    0x0a, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x50, 0x02, 0x0a, 0x00, 0x03, 0xe0, 0x0a, 0x0a, 0x00, 0x03,
    0x00, 0x00, 0x50, 0x03, 0x20, 0x40, 0x7c, 0x0a, 0x0a, 0x00, 0x04, 0x00, 0x00, 0x50, 0x04, 0x00,
    0x02, 0x00, 0x00, 0x50, 0x00, 0x4d, 0x40, 0x04, 0x03, 0x0a, 0x0b, 0x0c,
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
    fn xnap_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&XnapDissector, &data);
    }

    /// A well-formed PDU header and IE container whose IE values are
    /// arbitrary, so that every value decoder sees malformed input.
    #[test]
    fn xnap_no_panic_on_arbitrary_ie_values(
        pdu_type in 0u8..3,
        procedure_code in any::<u8>(),
        ies in prop::collection::vec(arb_ie(), 0..6),
    ) {
        let mut value = vec![0x00];
        value.extend_from_slice(&(ies.len() as u16).to_be_bytes());
        for ie in &ies {
            value.extend_from_slice(ie);
        }
        // Extension bit 0, then the 2-bit index.
        let mut data = vec![pdu_type << 5, procedure_code, 0x00];
        let len = value.len() as u16;
        if len < 128 {
            data.push(len as u8);
        } else {
            data.extend_from_slice(&(0x8000 | len).to_be_bytes());
        }
        data.extend_from_slice(&value);
        check_universal(&XnapDissector, &data);
    }

    /// A valid message with arbitrary octets overwritten and truncated.
    #[test]
    fn xnap_no_panic_on_mutated_message(
        edits in prop::collection::vec((0..VALID.len(), any::<u8>()), 0..8),
        len in 0..=VALID.len(),
    ) {
        let mut data = VALID.to_vec();
        for (pos, byte) in edits {
            data[pos] = byte;
        }
        data.truncate(len);
        check_universal(&XnapDissector, &data);
    }
}
