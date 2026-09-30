//! MAP property-based tests.
//!
//! # 3GPP TS 29.002 (MAP) Coverage
//!
//! | Clause      | Description                                             | Test                             |
//! |-------------|---------------------------------------------------------|----------------------------------|
//! | 17          | TCAP/MAP message — never-panic on arbitrary bytes       | map_no_panic_on_arbitrary_bytes  |
//! | 17.6, 17.7  | Invoke of a decoded operation with an arbitrary argument | map_no_panic_on_arbitrary_argument |
//!
//! References:
//! - 3GPP TS 29.002, clause 17 — <https://www.3gpp.org/ftp/Specs/archive/29_series/29.002/>

use packet_dissector_map::MapDissector;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag, 0x81, content.len() as u8];
    v.extend_from_slice(content);
    v
}

/// A BER element with a tag biased towards the ones MAP arguments use.
fn arb_element() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            Just(0x04u8),
            Just(0x02),
            Just(0x30),
            Just(0x80),
            Just(0x81),
            Just(0x82),
            Just(0x84),
            Just(0x85),
            Just(0x8a),
            Just(0xa3),
            any::<u8>()
        ],
        prop::collection::vec(any::<u8>(), 0..24),
    )
        .prop_map(|(tag, body)| {
            let mut e = vec![tag, body.len() as u8];
            e.extend_from_slice(&body);
            e
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn map_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&MapDissector, &data);
    }

    /// A well-formed Invoke of a decoded operation whose argument is an
    /// arbitrary SEQUENCE (or other element).
    #[test]
    fn map_no_panic_on_arbitrary_argument(
        opcode in prop_oneof![
            Just(2u8), Just(3), Just(4), Just(7), Just(23), Just(44), Just(45), Just(46),
            Just(56), Just(67)
        ],
        outer in prop_oneof![Just(0x30u8), Just(0xa3), Just(0x04), any::<u8>()],
        elements in prop::collection::vec(arb_element(), 0..6),
    ) {
        let arg = tlv(outer, &elements.concat());
        let invoke = tlv(0xa1, &[vec![0x02, 0x01, 0x01, 0x02, 0x01, opcode], arg].concat());
        let data = tlv(0x62, &[vec![0x48, 0x01, 0x01], tlv(0x6c, &invoke)].concat());
        check_universal(&MapDissector, &data);
    }
}
