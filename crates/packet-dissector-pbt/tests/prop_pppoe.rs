//! PPPoE property-based tests.
//!
//! # RFC 2516 (PPPoE) Coverage
//!
//! | RFC Section | Description                                       | Test                                  |
//! |-------------|---------------------------------------------------|---------------------------------------|
//! | 4           | Header — never-panic on arbitrary bytes           | pppoe_no_panic_on_arbitrary_bytes     |
//! | 5, App. A   | Discovery header + arbitrary TAGs and LENGTH      | pppoe_discovery_no_panic_on_tags      |
//! | 6           | Session header + arbitrary LENGTH and payload     | pppoe_session_no_panic_on_payload     |
//!
//! References:
//! - RFC 2516, Section 4 — <https://www.rfc-editor.org/rfc/rfc2516#section-4>
//! - RFC 2516, Section 5 — <https://www.rfc-editor.org/rfc/rfc2516#section-5>
//! - RFC 2516, Section 6 — <https://www.rfc-editor.org/rfc/rfc2516#section-6>

use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_pppoe::{PppoeDiscoveryDissector, PppoeDissector, PppoeSessionDissector};
use proptest::prelude::*;

/// One TAG with a TAG_TYPE biased towards the RFC 2516 types and an
/// arbitrary (possibly inconsistent) TAG_LENGTH.
fn arb_tag() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            Just(0x0000u16),
            Just(0x0101),
            Just(0x0102),
            Just(0x0103),
            Just(0x0105),
            Just(0x0201),
            any::<u16>()
        ],
        prop_oneof![
            Just(None),
            (0u16..16).prop_map(Some),
            any::<u16>().prop_map(Some)
        ],
        prop::collection::vec(any::<u8>(), 0..24),
    )
        .prop_map(|(tag_type, length, value)| {
            let length = length.unwrap_or(value.len() as u16);
            let mut tag = tag_type.to_be_bytes().to_vec();
            tag.extend_from_slice(&length.to_be_bytes());
            tag.extend_from_slice(&value);
            tag
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn pppoe_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..256)) {
        check_universal(&PppoeDiscoveryDissector, &data);
        check_universal(&PppoeSessionDissector, &data);
        check_universal(&PppoeDissector, &data);
    }

    /// A valid Discovery header followed by arbitrary TAGs, with LENGTH either
    /// matching the TAGs or arbitrary.
    #[test]
    fn pppoe_discovery_no_panic_on_tags(
        code in prop_oneof![Just(0x07u8), Just(0x09), Just(0x19), Just(0x65), Just(0xA7), any::<u8>()],
        tags in prop::collection::vec(arb_tag(), 0..6),
        length in prop::option::of(any::<u16>()),
        padding in prop::collection::vec(any::<u8>(), 0..16),
    ) {
        let body: Vec<u8> = tags.concat();
        let length = length.unwrap_or(body.len() as u16);
        let mut data = vec![0x11, code, 0x00, 0x00];
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(&body);
        data.extend_from_slice(&padding);
        check_universal(&PppoeDiscoveryDissector, &data);
        check_universal(&PppoeDissector, &data);
    }

    /// A valid Session header with an arbitrary LENGTH and payload.
    #[test]
    fn pppoe_session_no_panic_on_payload(
        session_id in any::<u16>(),
        length in any::<u16>(),
        payload in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut data = vec![0x11, 0x00];
        data.extend_from_slice(&session_id.to_be_bytes());
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(&payload);
        check_universal(&PppoeSessionDissector, &data);
        check_universal(&PppoeDissector, &data);
    }
}
