//! DTLS property-based tests.
//!
//! # RFC 9147 / RFC 6347 (DTLS) Coverage
//!
//! | RFC Section | Description                                        | Test                               |
//! |-------------|----------------------------------------------------|------------------------------------|
//! | 9147 §4.1   | Record demultiplexing — never-panic on any bytes   | dtls_no_panic_on_arbitrary_bytes   |
//! | 6347 §4.1   | DTLSPlaintext records with arbitrary payloads      | dtls_no_panic_on_plaintext_records |
//! | 6347 §4.2.2 | Handshake fragments with arbitrary header fields   | dtls_no_panic_on_handshake_records |
//! | 9147 §4     | Unified header with arbitrary flags and body       | dtls_no_panic_on_unified_header    |
//!
//! References:
//! - RFC 9147, Section 4 — <https://www.rfc-editor.org/rfc/rfc9147#section-4>
//! - RFC 9147, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc9147#section-4.1>
//! - RFC 6347, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc6347#section-4.1>
//! - RFC 6347, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc6347#section-4.2.2>

use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_tls::DtlsDissector;
use proptest::prelude::*;

/// A DTLSPlaintext record with a valid header around `payload`
/// (RFC 6347, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc6347#section-4.1>).
fn plaintext_record(ct: u8, epoch: u16, payload: &[u8]) -> Vec<u8> {
    let mut rec = vec![ct, 0xFE, 0xFD];
    rec.extend_from_slice(&epoch.to_be_bytes());
    rec.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
    rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    rec.extend_from_slice(payload);
    rec
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn dtls_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&DtlsDissector, &data);
    }

    /// Several well-framed plaintext records with arbitrary content types,
    /// epochs and payloads, followed by arbitrary trailing bytes.
    #[test]
    fn dtls_no_panic_on_plaintext_records(
        records in prop::collection::vec(
            (20u8..=26, 0u16..2, prop::collection::vec(any::<u8>(), 0..96)),
            1..4,
        ),
        tail in prop::collection::vec(any::<u8>(), 0..16),
    ) {
        let mut data = Vec::new();
        for (ct, epoch, payload) in records {
            data.extend_from_slice(&plaintext_record(ct, epoch, &payload));
        }
        data.extend_from_slice(&tail);
        check_universal(&DtlsDissector, &data);
    }

    /// A handshake record whose fragments have arbitrary `length`,
    /// `fragment_offset` and `fragment_length` values and bodies
    /// (RFC 6347, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc6347#section-4.2.2>).
    #[test]
    fn dtls_no_panic_on_handshake_records(
        fragments in prop::collection::vec(
            (
                prop_oneof![Just(1u8), Just(2), Just(3), Just(11), any::<u8>()],
                0u32..128,
                0u32..128,
                prop::collection::vec(any::<u8>(), 0..96),
                any::<bool>(),
            ),
            1..4,
        ),
    ) {
        let mut payload = Vec::new();
        for (msg_type, length, offset, body, whole) in fragments {
            let (length, offset) = if whole {
                (body.len() as u32, 0)
            } else {
                (length, offset)
            };
            payload.push(msg_type);
            payload.extend_from_slice(&length.to_be_bytes()[1..]);
            payload.extend_from_slice(&[0, 0]);
            payload.extend_from_slice(&offset.to_be_bytes()[1..]);
            payload.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
            payload.extend_from_slice(&body);
        }
        check_universal(&DtlsDissector, &plaintext_record(22, 0, &payload));
    }

    /// DTLS 1.3 unified headers with every flag combination
    /// (RFC 9147, Section 4 — <https://www.rfc-editor.org/rfc/rfc9147#section-4>).
    #[test]
    fn dtls_no_panic_on_unified_header(
        flags in 0u8..32,
        rest in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut data = vec![0x20 | flags];
        data.extend_from_slice(&rest);
        check_universal(&DtlsDissector, &data);
    }
}
