//! TCP property-based tests.
//!
//! # RFC 9293 (TCP) Coverage
//!
//! | RFC Section | Description                                   | Test                                     |
//! |-------------|-----------------------------------------------|------------------------------------------|
//! | 3.1         | Header Format — never-panic                   | tcp_no_panic_on_arbitrary_bytes          |
//! | 3.1         | Header Format — valid segment parses          | tcp_valid_segment_always_parses          |
//! | 3.1         | Data Offset → consumed bytes == Data Offset×4 | tcp_valid_segment_consumes_data_offset   |
//! | 3.1         | Source/Destination Port → DispatchHint        | tcp_valid_segment_dispatch_hint          |
//! | 3.2         | Options region length matches (DO − 5) × 4    | tcp_valid_segment_options_fit_header     |
//!
//! References:
//! - RFC 9293, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>
//! - RFC 9293, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc9293#section-3.2>

use packet_dissector_core::dissector::{DispatchHint, Dissector};
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_pbt::generators::tcp::arb_valid_tcp_segment;
use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_tcp::TcpDissector;
use proptest::prelude::*;

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn tcp_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        check_universal(&TcpDissector::new(), &data);
    }

    /// Every structurally valid TCP segment is accepted and satisfies the
    /// universal invariants.
    #[test]
    fn tcp_valid_segment_always_parses(segment in arb_valid_tcp_segment()) {
        let dissector = TcpDissector::new();
        check_universal(&dissector, &segment);
        let mut buf = DissectBuffer::new();
        let result = dissector
            .dissect(&segment, &mut buf, 0)
            .expect("valid generator must always parse");
        let layer = &buf.layers()[0];
        prop_assert_eq!(
            layer.range.end - layer.range.start,
            result.bytes_consumed,
            "layer range width must equal bytes_consumed",
        );
    }

    /// `bytes_consumed` equals `Data Offset × 4` (RFC 9293, Section 3.1 —
    /// <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>).
    #[test]
    fn tcp_valid_segment_consumes_data_offset(segment in arb_valid_tcp_segment()) {
        let mut buf = DissectBuffer::new();
        let result = TcpDissector::new()
            .dissect(&segment, &mut buf, 0)
            .expect("valid generator must always parse");
        let data_offset = (segment[12] >> 4) as usize;
        prop_assert_eq!(result.bytes_consumed, data_offset * 4);
    }

    /// `DispatchHint::ByTcpPort(src_port, dst_port)` carries the header's
    /// port fields unchanged (RFC 9293, Section 3.1 —
    /// <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>).
    #[test]
    fn tcp_valid_segment_dispatch_hint(segment in arb_valid_tcp_segment()) {
        let mut buf = DissectBuffer::new();
        let result = TcpDissector::new()
            .dissect(&segment, &mut buf, 0)
            .expect("valid generator must always parse");
        let src_port = u16::from_be_bytes([segment[0], segment[1]]);
        let dst_port = u16::from_be_bytes([segment[2], segment[3]]);
        prop_assert_eq!(result.next, DispatchHint::ByTcpPort(src_port, dst_port));
    }

    /// The parsed Options field occupies exactly `(Data Offset − 5) × 4`
    /// bytes — the space between the fixed 20-byte header and the start of
    /// the payload (RFC 9293, Section 3.2 —
    /// <https://www.rfc-editor.org/rfc/rfc9293#section-3.2>).
    #[test]
    fn tcp_valid_segment_options_fit_header(segment in arb_valid_tcp_segment()) {
        let dissector = TcpDissector::new();
        let mut buf = DissectBuffer::new();
        dissector
            .dissect(&segment, &mut buf, 0)
            .expect("valid generator must always parse");
        let data_offset = (segment[12] >> 4) as usize;
        let expected_options_len = (data_offset - 5) * 4;

        let layer = &buf.layers()[0];
        let options_field = buf
            .layer_fields(layer)
            .iter()
            .find(|f| f.name() == "options");
        match options_field {
            Some(field) => match field.value {
                FieldValue::Bytes(b) => {
                    prop_assert_eq!(b.len(), expected_options_len);
                }
                _ => prop_assert!(false, "options field must be Bytes"),
            },
            None => {
                prop_assert_eq!(expected_options_len, 0, "options field missing but Data Offset > 5");
            }
        }
    }
}
