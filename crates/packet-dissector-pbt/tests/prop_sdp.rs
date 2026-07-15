//! SDP property-based tests.
//!
//! # RFC 8866 (SDP) Coverage
//!
//! | RFC Section | Description                             | Test                              |
//! |-------------|-----------------------------------------|-----------------------------------|
//! | 5           | Session description — never-panic       | sdp_no_panic_on_arbitrary_bytes   |
//! | 5           | Valid session always parses             | sdp_valid_session_always_parses   |
//! | 5.1         | Protocol Version is always 0            | sdp_valid_session_always_parses   |
//! | 5.14        | Media Descriptions count is preserved   | sdp_valid_session_media_count     |
//!
//! References:
//! - RFC 8866, Section 5 — <https://www.rfc-editor.org/rfc/rfc8866#section-5>

use packet_dissector_core::dissector::{DispatchHint, Dissector};
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_pbt::generators::sdp::arb_valid_sdp_session;
use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_sdp::SdpDissector;
use proptest::prelude::*;

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn sdp_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        check_universal(&SdpDissector, &data);
    }

    /// Every structurally valid SDP session is accepted, consumes the whole
    /// message, ends dissection, and reports version 0
    /// (RFC 8866, Section 5.1 —
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.1>).
    #[test]
    fn sdp_valid_session_always_parses((session, _media_count) in arb_valid_sdp_session()) {
        let dissector = SdpDissector;
        check_universal(&dissector, &session);
        let mut buf = DissectBuffer::new();
        let result = dissector
            .dissect(&session, &mut buf, 0)
            .expect("valid generator must always parse");
        prop_assert_eq!(result.bytes_consumed, session.len());
        prop_assert_eq!(result.next, DispatchHint::End);
        let layer = buf.layer_by_name("SDP").expect("SDP layer must exist");
        let version = buf.field_by_name(layer, "version").expect("version field");
        prop_assert_eq!(&version.value, &FieldValue::U8(0));
    }

    /// The parsed `media_descriptions` Array has exactly one element per
    /// generated `m=` line (RFC 8866, Section 5.14 —
    /// <https://www.rfc-editor.org/rfc/rfc8866#section-5.14>).
    #[test]
    fn sdp_valid_session_media_count((session, media_count) in arb_valid_sdp_session()) {
        let mut buf = DissectBuffer::new();
        SdpDissector
            .dissect(&session, &mut buf, 0)
            .expect("valid generator must always parse");
        let layer = buf.layer_by_name("SDP").expect("SDP layer must exist");
        let actual = match buf.field_by_name(layer, "media_descriptions") {
            Some(field) => match &field.value {
                FieldValue::Array(r) => buf
                    .nested_fields(r)
                    .iter()
                    .filter(|f| f.value.is_object() && f.name() == "media_description")
                    .count(),
                _ => 0,
            },
            None => 0,
        };
        prop_assert_eq!(actual, media_count);
    }
}
