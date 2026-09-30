//! RTCP property-based tests.
//!
//! # RFC 3550 / RFC 4585 / RFC 3611 (RTCP) Coverage
//!
//! | RFC Section       | Description                                          | Test                              |
//! |-------------------|------------------------------------------------------|-----------------------------------|
//! | 3550 §6.4.1       | Common header — never-panic on arbitrary bytes       | rtcp_no_panic_on_arbitrary_bytes  |
//! | 3550 §6.1, 6.4-6.7| Compound of well-framed packets with arbitrary bodies| rtcp_no_panic_on_framed_compound  |
//! | 4585 §6, 3611 §3  | FB FCI / XR blocks with arbitrary contents           | rtcp_no_panic_on_framed_compound  |
//! | 5761 §4           | RTP dissector with RTCP packet types in octet 2      | rtp_mux_no_panic                  |
//!
//! References:
//! - RFC 3550, Section 6 — <https://www.rfc-editor.org/rfc/rfc3550#section-6>
//! - RFC 4585, Section 6 — <https://www.rfc-editor.org/rfc/rfc4585#section-6>
//! - RFC 3611, Section 3 — <https://www.rfc-editor.org/rfc/rfc3611#section-3>
//! - RFC 5761, Section 4 — <https://www.rfc-editor.org/rfc/rfc5761#section-4>

use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_rtcp::RtcpDissector;
use packet_dissector_rtp::RtpDissector;
use proptest::prelude::*;

/// One RTCP packet whose length field matches its (32-bit aligned) body, with
/// an arbitrary count / padding bit and a packet type biased towards the
/// types the dissector decodes.
fn arb_packet() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<bool>(),
        0u8..32,
        prop_oneof![200u8..=207, any::<u8>()],
        prop::collection::vec(any::<u8>(), 0..24).prop_map(|mut v| {
            v.truncate(v.len() / 4 * 4);
            v
        }),
    )
        .prop_map(|(padding, count, pt, body)| {
            let words = (body.len() / 4) as u16;
            let mut p = vec![0x80 | (u8::from(padding) << 5) | count, pt];
            p.extend_from_slice(&words.to_be_bytes());
            p.extend_from_slice(&body);
            p
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn rtcp_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..256)) {
        check_universal(&RtcpDissector, &data);
    }

    /// A compound of correctly framed packets with arbitrary bodies, followed
    /// by arbitrary trailing octets.
    #[test]
    fn rtcp_no_panic_on_framed_compound(
        packets in prop::collection::vec(arb_packet(), 1..5),
        tail in prop::collection::vec(any::<u8>(), 0..8),
    ) {
        let mut data: Vec<u8> = packets.concat();
        data.extend_from_slice(&tail);
        check_universal(&RtcpDissector, &data);
    }

    /// RTP input whose second octet is an RTCP packet type is either decoded
    /// as RTCP or falls back to RTP without violating the invariants.
    #[test]
    fn rtp_mux_no_panic(
        byte1 in 192u8..=223,
        rest in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut data = vec![0x80, byte1];
        data.extend_from_slice(&rest);
        check_universal(&RtpDissector, &data);
    }
}
