//! IPv4 packet strategies.
//!
//! ## References
//! - RFC 791, Section 3.1 — Internet Header Format: <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
//! - RFC 2474, Section 3 — DSCP in the DS field: <https://www.rfc-editor.org/rfc/rfc2474#section-3>
//! - RFC 3168, Section 5 — ECN in the DS field: <https://www.rfc-editor.org/rfc/rfc3168#section-5>

use proptest::prelude::*;

prop_compose! {
    /// Generate a valid IPv4 packet whose header satisfies every constraint
    /// checked by the IPv4 dissector.
    ///
    /// Invariants of generated packets (RFC 791, Section 3.1):
    ///
    /// - `version == 4`
    /// - `ihl ∈ 5..=15`, hence header length is `ihl × 4 ∈ 20..=60`
    /// - `total_length == header_len + payload_len`, hence
    ///   `total_length >= header_len` and `data.len() >= total_length`
    /// - `dscp` is 6 bits (RFC 2474), `ecn` is 2 bits (RFC 3168)
    /// - `fragment_offset` is 13 bits (RFC 791, Section 3.1)
    ///
    /// The generator never produces truncated packets: dissection always
    /// succeeds and consumes exactly `ihl × 4` bytes.
    pub fn arb_valid_ipv4_packet()(
        ihl in 5u8..=15,
        dscp in 0u8..64,
        ecn in 0u8..4,
        identification in any::<u16>(),
        df in any::<bool>(),
        mf in any::<bool>(),
        fragment_offset in 0u16..8192,
        ttl in any::<u8>(),
        protocol in any::<u8>(),
        checksum in any::<u16>(),
        src in any::<[u8; 4]>(),
        dst in any::<[u8; 4]>(),
        options in prop::collection::vec(any::<u8>(), 40),
        payload in prop::collection::vec(any::<u8>(), 0..=512),
    ) -> Vec<u8> {
        let header_len = (ihl as usize) * 4;
        let options_len = header_len - 20;
        let total_len = (header_len + payload.len()) as u16;
        let mut buf = Vec::with_capacity(header_len + payload.len());
        buf.push((4u8 << 4) | ihl);
        buf.push((dscp << 2) | ecn);
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&identification.to_be_bytes());
        let flags: u16 = (u16::from(df) << 14) | (u16::from(mf) << 13);
        let flags_frag = flags | fragment_offset;
        buf.extend_from_slice(&flags_frag.to_be_bytes());
        buf.push(ttl);
        buf.push(protocol);
        buf.extend_from_slice(&checksum.to_be_bytes());
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&dst);
        buf.extend_from_slice(&options[..options_len]);
        buf.extend_from_slice(&payload);
        buf
    }
}
