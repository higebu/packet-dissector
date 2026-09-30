//! S1AP property-based tests.
//!
//! # 3GPP TS 36.413 (S1AP) Coverage
//!
//! | Section | Description                                          | Test                              |
//! |---------|------------------------------------------------------|-----------------------------------|
//! | 9.3     | Never-panic on arbitrary bytes                       | s1ap_no_panic_on_arbitrary_bytes  |
//! | 9.3.2, 9.3.7 | Valid PDU header + arbitrary IE values          | s1ap_no_panic_on_arbitrary_ies    |
//!
//! References:
//! - 3GPP TS 36.413: <https://www.3gpp.org/ftp/Specs/archive/36_series/36.413/>

use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_s1ap::S1apDissector;
use proptest::prelude::*;

/// IE ids with value decoders, plus arbitrary ids.
fn ie_id() -> impl Strategy<Value = u16> {
    prop_oneof![
        prop::sample::select(vec![
            0u16, 2, 8, 16, 17, 24, 26, 50, 51, 52, 59, 60, 61, 66, 67, 96, 100, 107, 134, 137,
        ]),
        any::<u16>(),
    ]
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn s1ap_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..256)) {
        check_universal(&S1apDissector, &data);
    }

    /// A well-formed S1AP-PDU and IE container whose IE values are arbitrary
    /// octets, so the value decoders see malformed input.
    #[test]
    fn s1ap_no_panic_on_arbitrary_ies(
        pdu_type in 0u8..3,
        procedure_code in any::<u8>(),
        ies in prop::collection::vec(
            (ie_id(), prop::collection::vec(any::<u8>(), 0..64)),
            0..6,
        ),
    ) {
        let mut value = vec![0x00];
        value.extend_from_slice(&(ies.len() as u16).to_be_bytes());
        for (id, v) in &ies {
            value.extend_from_slice(&id.to_be_bytes());
            value.push(0x40);
            value.push(v.len() as u8);
            value.extend_from_slice(v);
        }
        let mut data = vec![pdu_type << 5, procedure_code, 0x00];
        if value.len() < 128 {
            data.push(value.len() as u8);
        } else {
            data.extend_from_slice(&(0x8000u16 | value.len() as u16).to_be_bytes());
        }
        data.extend_from_slice(&value);
        check_universal(&S1apDissector, &data);
    }
}
