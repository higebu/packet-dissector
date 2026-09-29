//! Test vectors from RFC 9001, Appendix A and RFC 9369, Appendix A, stored
//! as hex text under `tests/data/`.
//!
//! - RFC 9001, Appendix A: <https://www.rfc-editor.org/rfc/rfc9001#appendix-A>
//! - RFC 9369, Appendix A: <https://www.rfc-editor.org/rfc/rfc9369#appendix-A>

/// Decode hex text, ignoring whitespace.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// RFC 9001, Appendix A.2 — protected client Initial (QUIC v1, 1200 bytes).
pub(crate) fn rfc9001_a2_client_initial() -> Vec<u8> {
    hex(include_str!("../tests/data/rfc9001_a2_client_initial.hex"))
}

/// RFC 9001, Appendix A.2 — the CRYPTO frame in the client Initial payload.
pub(crate) fn rfc9001_a2_crypto_frame() -> Vec<u8> {
    hex(include_str!("../tests/data/rfc9001_a2_crypto_frame.hex"))
}

/// RFC 9001, Appendix A.3 — protected server Initial (QUIC v1).
pub(crate) fn rfc9001_a3_server_initial() -> Vec<u8> {
    hex(include_str!("../tests/data/rfc9001_a3_server_initial.hex"))
}

/// RFC 9369, Appendix A.2 — protected client Initial (QUIC v2, 1200 bytes).
pub(crate) fn rfc9369_a2_client_initial() -> Vec<u8> {
    hex(include_str!("../tests/data/rfc9369_a2_client_initial.hex"))
}

/// RFC 9369, Appendix A.3 — protected server Initial (QUIC v2).
pub(crate) fn rfc9369_a3_server_initial() -> Vec<u8> {
    hex(include_str!("../tests/data/rfc9369_a3_server_initial.hex"))
}

/// The client-chosen Destination Connection ID used by all vectors.
pub(crate) const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
