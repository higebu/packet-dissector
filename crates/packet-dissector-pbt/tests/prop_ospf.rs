//! OSPFv2 / OSPFv3 property-based tests.
//!
//! # RFC 2328 / RFC 5340 (OSPF) Coverage
//!
//! | RFC Section          | Description                              | Test                              |
//! |----------------------|------------------------------------------|-----------------------------------|
//! | RFC 2328 A.3.1       | Common header — never-panic              | ospfv2_no_panic_on_arbitrary_bytes |
//! | RFC 5340 A.3.1       | Common header — never-panic              | ospfv3_no_panic_on_arbitrary_bytes |
//! | RFC 2328 A.3.5, A.4  | LSU with arbitrary LSA bodies and trailer | ospfv2_lsu_arbitrary_lsa_bodies   |
//! | RFC 5340 A.3.5, A.4  | LSU with arbitrary LSA bodies and trailer | ospfv3_lsu_arbitrary_lsa_bodies   |
//!
//! References:
//! - RFC 2328, Appendix A — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A>
//! - RFC 5340, Appendix A — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A>

use packet_dissector_ospf::{Ospfv2Dissector, Ospfv3Dissector};
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

/// An LSU packet whose single LSA has an arbitrary type and body, followed by
/// arbitrary trailing bytes (digest, LLS or Authentication Trailer).
fn lsu(version: u8, auth_type: u8, ls_type: [u8; 2], body: &[u8], trailer: &[u8]) -> Vec<u8> {
    let header_size = if version == 2 { 24 } else { 16 };
    let lsa_len = 20 + body.len();
    let total = header_size + 4 + lsa_len;
    let mut pkt = vec![version, 4];
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.extend_from_slice(&[1, 1, 1, 1, 0, 0, 0, 0, 0, 0]);
    if version == 2 {
        pkt.extend_from_slice(&[0, auth_type, 0, 0, 1, 16, 0, 0, 0, 1]);
    } else {
        pkt.extend_from_slice(&[0, 0]);
    }
    pkt.extend_from_slice(&1u32.to_be_bytes());
    pkt.extend_from_slice(&[0, 1, ls_type[0], ls_type[1], 4, 0, 0, 1, 1, 1, 1, 1]);
    pkt.extend_from_slice(&[0x80, 0, 0, 1, 0, 0]);
    pkt.extend_from_slice(&(lsa_len as u16).to_be_bytes());
    pkt.extend_from_slice(body);
    pkt.extend_from_slice(trailer);
    pkt
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn ospfv2_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        check_universal(&Ospfv2Dissector, &data);
    }

    #[test]
    fn ospfv3_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        check_universal(&Ospfv3Dissector, &data);
    }

    /// Structurally valid LSUs with arbitrary LSA types, bodies (including
    /// malformed TLVs) and trailers satisfy the universal invariants.
    #[test]
    fn ospfv2_lsu_arbitrary_lsa_bodies(
        ls_type in prop_oneof![1u8..=11, any::<u8>()],
        auth_type in 0u8..=2,
        body in prop::collection::vec(any::<u8>(), 0..256),
        trailer in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        check_universal(&Ospfv2Dissector, &lsu(2, auth_type, [0, ls_type], &body, &trailer));
    }

    #[test]
    fn ospfv3_lsu_arbitrary_lsa_bodies(
        function_code in prop_oneof![1u8..=42, any::<u8>()],
        scope in 0u8..=7,
        body in prop::collection::vec(any::<u8>(), 0..256),
        trailer in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let ls_type = [scope << 5, function_code];
        check_universal(&Ospfv3Dissector, &lsu(3, 0, ls_type, &body, &trailer));
    }
}
