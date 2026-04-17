//! TCP segment strategies.
//!
//! ## References
//! - RFC 9293, Section 3.1 — Header Format: <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>
//! - RFC 9293, Section 3.2 — Header Options: <https://www.rfc-editor.org/rfc/rfc9293#section-3.2>

use proptest::prelude::*;

/// Generate a single, well-formed TCP option TLV.
///
/// The strategy mixes the most common options so that a generated TCP
/// segment exercises the dissector's length-driven options skipping logic
/// across a representative TLV stream (RFC 9293, Section 3.2 —
/// <https://www.rfc-editor.org/rfc/rfc9293#section-3.2>):
///
/// | Kind | Length | Name                                    |
/// |------|--------|-----------------------------------------|
/// | `0`  | 1      | End of Option List (single byte)        |
/// | `1`  | 1      | No-Operation (single byte)              |
/// | `2`  | 4      | Maximum Segment Size                    |
/// | `3`  | 3      | Window Scale                            |
/// | `4`  | 2      | SACK Permitted                          |
fn arb_tcp_option() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(vec![0x01u8]),
        Just(vec![0x00u8]),
        any::<[u8; 2]>().prop_map(|b| vec![0x02u8, 0x04, b[0], b[1]]),
        any::<u8>().prop_map(|v| vec![0x03u8, 0x03, v]),
        Just(vec![0x04u8, 0x02]),
    ]
}

prop_compose! {
    /// Generate a valid TCP segment whose header satisfies every constraint
    /// checked by the TCP dissector.
    ///
    /// Invariants of generated segments (RFC 9293, Section 3.1 —
    /// <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>):
    ///
    /// - `data_offset ∈ 5..=15`, hence header length is
    ///   `data_offset × 4 ∈ 20..=60` bytes.
    /// - The 4-bit Reserved field (bits 4..8 of byte 12) is zero, matching
    ///   the sender requirement in RFC 9293, Section 3.1.
    /// - Every control-bit combination of the 8-bit Flags byte can be
    ///   produced (RFC 9293, Section 3.1 — CWR, ECE, URG, ACK, PSH, RST,
    ///   SYN, FIN).
    /// - The Options region has exactly `(data_offset - 5) × 4` bytes and
    ///   is populated by a well-formed TLV stream (RFC 9293, Section 3.2);
    ///   any remaining bytes are padded with No-Operation (`0x01`) as
    ///   suggested by RFC 9293, Section 3.1.
    /// - A payload of `0..=1024` arbitrary bytes follows the header.
    ///
    /// The generator never produces truncated segments: dissection always
    /// succeeds and consumes exactly `data_offset × 4` bytes.
    pub fn arb_valid_tcp_segment()(
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        seq in any::<u32>(),
        ack in any::<u32>(),
        data_offset in 5u8..=15,
        flags in any::<u8>(),
        window in any::<u16>(),
        checksum in any::<u16>(),
        urgent_pointer in any::<u16>(),
        options in prop::collection::vec(arb_tcp_option(), 0..=20),
        payload in prop::collection::vec(any::<u8>(), 0..=1024),
    ) -> Vec<u8> {
        let header_len = (data_offset as usize) * 4;
        let options_budget = header_len - 20;

        // Greedily pack well-formed option TLVs while they still fit in the
        // Options region, then pad any remaining bytes with No-Operation
        // (Kind = 1). RFC 9293, Section 3.1 —
        // <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>.
        let mut options_buf = Vec::with_capacity(options_budget);
        for opt in &options {
            if options_buf.len() + opt.len() > options_budget {
                continue;
            }
            options_buf.extend_from_slice(opt);
        }
        while options_buf.len() < options_budget {
            options_buf.push(0x01);
        }

        let mut buf = Vec::with_capacity(header_len + payload.len());
        buf.extend_from_slice(&src_port.to_be_bytes());
        buf.extend_from_slice(&dst_port.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&ack.to_be_bytes());
        // Data Offset occupies the high nibble; the low nibble is the
        // 4-bit Reserved field, which RFC 9293, Section 3.1 requires
        // senders to transmit as zero.
        buf.push(data_offset << 4);
        buf.push(flags);
        buf.extend_from_slice(&window.to_be_bytes());
        buf.extend_from_slice(&checksum.to_be_bytes());
        buf.extend_from_slice(&urgent_pointer.to_be_bytes());
        buf.extend_from_slice(&options_buf);
        buf.extend_from_slice(&payload);
        buf
    }
}
