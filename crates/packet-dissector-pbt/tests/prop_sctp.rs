//! SCTP property-based tests.
//!
//! # RFC 9260 (SCTP) Coverage
//!
//! | RFC Section    | Description                                           | Test                               |
//! |----------------|-------------------------------------------------------|------------------------------------|
//! | 3              | Packet format — never-panic on arbitrary bytes        | sctp_no_panic_on_arbitrary_bytes   |
//! | 3.2, 3.2.1, 3.3| Well-framed chunks with arbitrary bodies always parse | sctp_framed_chunks_always_parse    |
//! | 3.3.1, 6.10    | Recorded payloads lie inside their DATA chunks        | sctp_framed_chunks_always_parse    |
//!
//! References:
//! - RFC 9260, Section 3 — <https://www.rfc-editor.org/rfc/rfc9260#section-3>
//! - RFC 9260, Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.2.1>
//! - RFC 8260, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc8260#section-2.1>

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_sctp::SctpDissector;
use proptest::prelude::*;

/// Chunk types with a body decoder, plus one without.
const CHUNK_TYPES: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 14, 64];

/// A common header followed by chunks whose Length fields match their
/// bodies (RFC 9260, Section 3.2), with arbitrary flags and body bytes.
fn arb_framed_sctp_packet() -> impl Strategy<Value = Vec<u8>> {
    let chunk = (
        prop::sample::select(CHUNK_TYPES),
        any::<u8>(),
        prop::collection::vec(any::<u8>(), 0..64),
    );
    (1u16.., 1u16.., prop::collection::vec(chunk, 0..6)).prop_map(|(src, dst, chunks)| {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&src.to_be_bytes());
        pkt.extend_from_slice(&dst.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 8]);
        for (ctype, flags, body) in chunks {
            pkt.push(ctype);
            pkt.push(flags);
            pkt.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
            pkt.extend_from_slice(&body);
            while pkt.len() % 4 != 0 {
                pkt.push(0);
            }
        }
        pkt
    })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn sctp_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&SctpDissector, &data);
    }

    /// Well-framed chunks always parse whatever their bodies hold, and every
    /// recorded user message lies inside the packet after the common header.
    #[test]
    fn sctp_framed_chunks_always_parse(packet in arb_framed_sctp_packet()) {
        check_universal(&SctpDissector, &packet);
        let mut buf = DissectBuffer::new();
        let result = SctpDissector
            .dissect(&packet, &mut buf, 0)
            .expect("well-framed chunks must always parse");
        prop_assert_eq!(result.bytes_consumed, packet.len());
        for payload in buf.embedded_payloads() {
            prop_assert!(payload.range.start >= 12 + 16);
            prop_assert!(payload.range.start < payload.range.end);
            prop_assert!(payload.range.end <= packet.len());
        }
    }
}
