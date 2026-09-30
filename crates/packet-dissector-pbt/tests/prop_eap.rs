//! EAP / EAPOL property-based tests.
//!
//! # RFC 3748 (EAP) / IEEE 802.1X-2020 (EAPOL) Coverage
//!
//! | Section              | Description                                        | Test                              |
//! |----------------------|----------------------------------------------------|-----------------------------------|
//! | RFC 3748 §4          | EAP / EAPOL — never-panic on arbitrary bytes       | eap_no_panic_on_arbitrary_bytes   |
//! | RFC 3748 §4.1, §5    | Request/Response with arbitrary Type and Type-Data | eap_no_panic_on_type_data         |
//! | RFC 4187 §8.1        | EAP-SIM/AKA arbitrary attribute sequences          | eap_no_panic_on_sim_aka_attributes|
//! | IEEE 802.1X-2020 11.3| EAPOL header + arbitrary body and Body Length      | eapol_no_panic_on_body            |
//!
//! References:
//! - RFC 3748, Section 4 — <https://www.rfc-editor.org/rfc/rfc3748#section-4>
//! - RFC 4187, Section 8.1 — <https://www.rfc-editor.org/rfc/rfc4187#section-8.1>
//! - IEEE Std 802.1X-2020 — <https://standards.ieee.org/ieee/802.1X/7345/>

use packet_dissector_eap::{EapDissector, EapolDissector};
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

/// An EAP packet whose Length is either consistent or arbitrary.
fn eap_packet(code: u8, eap_type: u8, type_data: &[u8], length: Option<u16>) -> Vec<u8> {
    let length = length.unwrap_or((5 + type_data.len()) as u16);
    let mut p = vec![code, 0x01];
    p.extend_from_slice(&length.to_be_bytes());
    p.push(eap_type);
    p.extend_from_slice(type_data);
    p
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn eap_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..256)) {
        check_universal(&EapDissector, &data);
        check_universal(&EapolDissector, &data);
    }

    /// Requests and Responses with method types that have dedicated decoders.
    #[test]
    fn eap_no_panic_on_type_data(
        code in 1u8..=2,
        eap_type in prop_oneof![
            Just(1u8), Just(2), Just(3), Just(13), Just(18), Just(21), Just(23),
            Just(25), Just(50), Just(254), any::<u8>()
        ],
        type_data in prop::collection::vec(any::<u8>(), 0..64),
        length in prop::option::of(any::<u16>()),
        padding in prop::collection::vec(any::<u8>(), 0..8),
    ) {
        let mut data = eap_packet(code, eap_type, &type_data, length);
        data.extend_from_slice(&padding);
        check_universal(&EapDissector, &data);
    }

    /// EAP-SIM / AKA / AKA' with arbitrary attribute type/length pairs.
    #[test]
    fn eap_no_panic_on_sim_aka_attributes(
        eap_type in prop_oneof![Just(18u8), Just(23), Just(50)],
        attrs in prop::collection::vec((any::<u8>(), 0u8..6, prop::collection::vec(any::<u8>(), 0..20)), 0..5),
    ) {
        let mut td = vec![1, 0, 0];
        for (t, l, v) in attrs {
            td.push(t);
            td.push(l);
            td.extend_from_slice(&v);
        }
        let data = eap_packet(1, eap_type, &td, None);
        check_universal(&EapDissector, &data);
    }

    /// EAPOL header with an arbitrary Packet Type, Body Length and body.
    #[test]
    fn eapol_no_panic_on_body(
        version in 1u8..=3,
        packet_type in prop_oneof![Just(0u8), Just(1), Just(3), any::<u8>()],
        body in prop::collection::vec(any::<u8>(), 0..64),
        body_length in prop::option::of(any::<u16>()),
    ) {
        let len = body_length.unwrap_or(body.len() as u16);
        let mut data = vec![version, packet_type];
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(&body);
        check_universal(&EapolDissector, &data);
    }
}
