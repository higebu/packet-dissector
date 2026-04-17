//! IPv4 property-based tests.
//!
//! # RFC 791 (IPv4) Coverage
//!
//! | RFC Section | Description                         | Test                            |
//! |-------------|-------------------------------------|---------------------------------|
//! | 3.1         | Header Format — never-panic         | ipv4_no_panic_on_arbitrary_bytes |
//! | 3.1         | Header Format — valid packet parses | ipv4_valid_packet_always_parses  |
//! | 3.1         | IHL → consumed bytes == IHL × 4     | ipv4_valid_packet_consumes_ihl   |
//! | 3.1         | Protocol → DispatchHint             | ipv4_valid_packet_dispatch_hint  |
//!
//! References:
//! - RFC 791, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc791#section-3.1>

use packet_dissector_core::dissector::{DispatchHint, Dissector};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ipv4::Ipv4Dissector;
use packet_dissector_pbt::generators::ipv4::arb_valid_ipv4_packet;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn ipv4_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        check_universal(&Ipv4Dissector, &data);
    }

    /// Every structurally valid IPv4 packet is accepted and satisfies the
    /// universal invariants.
    #[test]
    fn ipv4_valid_packet_always_parses(packet in arb_valid_ipv4_packet()) {
        check_universal(&Ipv4Dissector, &packet);
        let mut buf = DissectBuffer::new();
        let result = Ipv4Dissector
            .dissect(&packet, &mut buf, 0)
            .expect("valid generator must always parse");
        let layer = &buf.layers()[0];
        prop_assert_eq!(
            layer.range.end - layer.range.start,
            result.bytes_consumed,
            "layer range width must equal bytes_consumed",
        );
    }

    /// `bytes_consumed` equals `IHL × 4` (RFC 791, Section 3.1).
    #[test]
    fn ipv4_valid_packet_consumes_ihl(packet in arb_valid_ipv4_packet()) {
        let mut buf = DissectBuffer::new();
        let result = Ipv4Dissector
            .dissect(&packet, &mut buf, 0)
            .expect("valid generator must always parse");
        let ihl = (packet[0] & 0x0F) as usize;
        prop_assert_eq!(result.bytes_consumed, ihl * 4);
    }

    /// `DispatchHint::ByIpProtocol` carries the header's Protocol byte
    /// unchanged (RFC 791, Section 3.1).
    #[test]
    fn ipv4_valid_packet_dispatch_hint(packet in arb_valid_ipv4_packet()) {
        let mut buf = DissectBuffer::new();
        let result = Ipv4Dissector
            .dissect(&packet, &mut buf, 0)
            .expect("valid generator must always parse");
        prop_assert_eq!(result.next, DispatchHint::ByIpProtocol(packet[9]));
    }
}
