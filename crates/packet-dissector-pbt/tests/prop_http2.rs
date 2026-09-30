//! HTTP/2 HPACK property-based tests.
//!
//! # RFC 9113 / RFC 7541 (HTTP/2, HPACK) Coverage
//!
//! | RFC Section       | Description                                          | Test                                   |
//! |-------------------|------------------------------------------------------|----------------------------------------|
//! | 9113 §6.2, 7541 §6 | HEADERS with an arbitrary header block (stateless)  | http2_headers_arbitrary_block          |
//! | 7541 §2.3, §4     | Arbitrary header blocks on one tracked connection    | http2_connection_arbitrary_blocks      |
//! | 9113 §4.3, §6.10  | Arbitrary HEADERS / CONTINUATION split of a block    | http2_connection_arbitrary_split       |
//!
//! References:
//! - RFC 9113, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc9113#section-4.3>
//! - RFC 9113, Section 6.2 — <https://www.rfc-editor.org/rfc/rfc9113#section-6.2>
//! - RFC 9113, Section 6.10 — <https://www.rfc-editor.org/rfc/rfc9113#section-6.10>
//! - RFC 7541, Section 2.3 — <https://www.rfc-editor.org/rfc/rfc7541#section-2.3>
//! - RFC 7541, Section 4 — <https://www.rfc-editor.org/rfc/rfc7541#section-4>
//! - RFC 7541, Section 6 — <https://www.rfc-editor.org/rfc/rfc7541#section-6>

use packet_dissector_core::dissector::{Dissector, TcpStreamContext};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_http2::{CONNECTION_PREFACE, Http2ConnectionDissector, Http2Dissector};
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

/// A frame of `frame_type` with `flags` on stream 1 carrying `payload`.
fn frame(frame_type: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    f.extend_from_slice(&[frame_type, flags, 0, 0, 0, 1]);
    f.extend_from_slice(payload);
    f
}

/// Header block octets biased towards HPACK representations that touch the
/// dynamic table (indexed fields past 61, incremental indexing, size
/// updates).
fn arb_block() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop_oneof![
            any::<u8>(),
            (62u8..=127).prop_map(|i| 0x80 | i),
            Just(0x40u8),
            Just(0x7e),
            Just(0x3f),
            Just(0x20),
        ],
        0..96,
    )
}

const END_HEADERS: u8 = 0x04;

proptest! {
    /// A HEADERS frame with an arbitrary header block satisfies the
    /// universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn http2_headers_arbitrary_block(block in arb_block()) {
        check_universal(&Http2Dissector, &frame(0x01, END_HEADERS, &block));
    }

    /// Arbitrary header blocks decoded in order on one tracked connection
    /// never panic and every frame is consumed whole.
    #[test]
    fn http2_connection_arbitrary_blocks(blocks in prop::collection::vec(arb_block(), 1..6)) {
        let d = Http2ConnectionDissector::new();
        let ctx = TcpStreamContext::new(([1; 16], [2; 16], 50000, 80), 0, 0, 0);
        let mut first = CONNECTION_PREFACE.to_vec();
        first.extend(frame(0x04, 0, &[]));
        let mut buf = DissectBuffer::new();
        d.dissect_tcp_stream(&first, &mut buf, 0, &ctx).unwrap();
        for block in &blocks {
            let data = frame(0x01, END_HEADERS, block);
            let mut buf = DissectBuffer::new();
            let result = d.dissect_tcp_stream(&data, &mut buf, 0, &ctx).unwrap();
            prop_assert_eq!(result.bytes_consumed, data.len());
        }
    }

    /// A header block split at an arbitrary point between HEADERS and
    /// CONTINUATION never panics.
    #[test]
    fn http2_connection_arbitrary_split(block in arb_block(), at in any::<prop::sample::Index>()) {
        let d = Http2ConnectionDissector::new();
        let ctx = TcpStreamContext::new(([1; 16], [2; 16], 50000, 80), 0, 0, 0);
        let split = at.index(block.len() + 1);
        let mut first = CONNECTION_PREFACE.to_vec();
        first.extend(frame(0x01, 0, &block[..split]));
        let mut buf = DissectBuffer::new();
        d.dissect_tcp_stream(&first, &mut buf, 0, &ctx).unwrap();
        let data = frame(0x09, END_HEADERS, &block[split..]);
        let mut buf = DissectBuffer::new();
        d.dissect_tcp_stream(&data, &mut buf, 0, &ctx).unwrap();
    }
}
