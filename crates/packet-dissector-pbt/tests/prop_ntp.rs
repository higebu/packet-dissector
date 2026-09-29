//! NTP property-based tests.
//!
//! # RFC 5905 / RFC 7822 / RFC 8915 (NTP) Coverage
//!
//! | RFC Section       | Description                                        | Test                                |
//! |-------------------|----------------------------------------------------|-------------------------------------|
//! | 5905 §7.3         | Packet — never-panic on arbitrary bytes            | ntp_no_panic_on_arbitrary_bytes     |
//! | 7822 §3, 8915 §5  | NTPv4 header + arbitrary EF / NTS / MAC trailer    | ntp_no_panic_on_arbitrary_trailer   |
//!
//! References:
//! - RFC 5905, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>
//! - RFC 7822, Section 3 — <https://www.rfc-editor.org/rfc/rfc7822#section-3>
//! - RFC 8915, Section 5 — <https://www.rfc-editor.org/rfc/rfc8915#section-5>

use packet_dissector_ntp::NtpDissector;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

/// One extension field with an arbitrary (possibly inconsistent) Length and
/// a Field Type biased towards the NTS types.
fn arb_extension_field() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            Just(0x0104u16),
            Just(0x0204),
            Just(0x0304),
            Just(0x0404),
            any::<u16>()
        ],
        any::<u16>(),
        prop::collection::vec(any::<u8>(), 0..96),
    )
        .prop_map(|(field_type, length, body)| {
            let mut ef = field_type.to_be_bytes().to_vec();
            ef.extend_from_slice(&length.to_be_bytes());
            ef.extend_from_slice(&body);
            ef
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn ntp_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&NtpDissector, &data);
    }

    /// A valid NTPv4 client header followed by arbitrary extension fields and
    /// trailing octets (RFC 7822, Section 3 —
    /// <https://www.rfc-editor.org/rfc/rfc7822#section-3>).
    #[test]
    fn ntp_no_panic_on_arbitrary_trailer(
        vn in 3u8..=4,
        efs in prop::collection::vec(arb_extension_field(), 0..4),
        tail in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let mut data = vec![0u8; 48];
        data[0] = (vn << 3) | 3; // LI 0, VN, mode 3 (client)
        for ef in efs {
            data.extend_from_slice(&ef);
        }
        data.extend_from_slice(&tail);
        check_universal(&NtpDissector, &data);
    }
}
