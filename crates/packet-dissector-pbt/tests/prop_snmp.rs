//! SNMP property-based tests.
//!
//! # RFC 3416 / RFC 3412 (SNMP) Coverage
//!
//! | RFC Section   | Description                                         | Test                              |
//! |---------------|-----------------------------------------------------|-----------------------------------|
//! | 3417 §8       | Never-panic on arbitrary bytes                      | snmp_no_panic_on_arbitrary_bytes  |
//! | 3416 §3       | Valid message framing + arbitrary BER PDU contents  | snmp_no_panic_on_arbitrary_pdu    |
//! | 3412 §6       | SNMPv3 framing + arbitrary header / parameters      | snmp_no_panic_on_arbitrary_v3     |
//!
//! References:
//! - RFC 3417, Section 8 — <https://www.rfc-editor.org/rfc/rfc3417#section-8>
//! - RFC 3416, Section 3 — <https://www.rfc-editor.org/rfc/rfc3416#section-3>
//! - RFC 3412, Section 6 — <https://www.rfc-editor.org/rfc/rfc3412#section-6>

use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_snmp::SnmpDissector;
use proptest::prelude::*;

/// A BER element with the given identifier and contents (definite length).
fn tlv(identifier: u8, value: &[u8]) -> Vec<u8> {
    let mut v = vec![identifier];
    if value.len() < 0x80 {
        v.push(value.len() as u8);
    } else {
        v.extend_from_slice(&[0x82, (value.len() >> 8) as u8, value.len() as u8]);
    }
    v.extend_from_slice(value);
    v
}

/// Random BER elements, biased towards the identifiers SNMP uses.
fn arb_elements() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        (
            prop_oneof![
                Just(0x02u8),
                Just(0x04),
                Just(0x05),
                Just(0x06),
                Just(0x30),
                Just(0x40),
                Just(0x41),
                Just(0x43),
                Just(0x46),
                Just(0x80),
                Just(0x82),
                any::<u8>()
            ],
            prop::collection::vec(any::<u8>(), 0..24),
        )
            .prop_map(|(id, value)| tlv(id, &value)),
        0..8,
    )
    .prop_map(|v| v.concat())
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn snmp_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..256)) {
        check_universal(&SnmpDissector, &data);
    }

    /// SNMPv1/v2c framing around a PDU whose contents are arbitrary BER
    /// elements (request-id, variable bindings, trap fields, ...).
    #[test]
    fn snmp_no_panic_on_arbitrary_pdu(
        version in 0u8..4,
        pdu_tag in 0xa0u8..0xaa,
        contents in arb_elements(),
        bindings in arb_elements(),
    ) {
        let mut pdu_body = contents;
        pdu_body.extend_from_slice(&tlv(0x30, &bindings));
        let body = [tlv(0x02, &[version]), tlv(0x04, b"public"), tlv(pdu_tag, &pdu_body)].concat();
        check_universal(&SnmpDissector, &tlv(0x30, &body));
    }

    /// SNMPv3 framing with arbitrary header data, security parameters and
    /// msgData.
    #[test]
    fn snmp_no_panic_on_arbitrary_v3(
        header in arb_elements(),
        params in arb_elements(),
        msg_data in arb_elements(),
    ) {
        let body = [
            tlv(0x02, &[3]),
            tlv(0x30, &header),
            tlv(0x04, &tlv(0x30, &params)),
            msg_data,
        ]
        .concat();
        check_universal(&SnmpDissector, &tlv(0x30, &body));
    }
}
