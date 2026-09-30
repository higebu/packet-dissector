//! CDP property-based tests.
//!
//! # CDP Coverage (Cisco CDP; Wireshark / tcpdump as secondary sources)
//!
//! | Item            | Description                                     | Test                             |
//! |-----------------|-------------------------------------------------|----------------------------------|
//! | Header          | Never-panic on arbitrary bytes                  | cdp_no_panic_on_arbitrary_bytes  |
//! | TLVs            | Header + arbitrary TLVs (types, lengths, values)| cdp_no_panic_on_tlvs             |
//! | Addresses TLV   | Arbitrary address entries and counts            | cdp_no_panic_on_addresses        |
//!
//! References:
//! - Wireshark `packet-cdp.c` —
//!   <https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-cdp.c>

use packet_dissector_cdp::CdpDissector;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

/// One TLV with a type biased towards decoded types and a Length that is
/// either consistent or arbitrary.
fn arb_tlv() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            Just(0x0001u16),
            Just(0x0002),
            Just(0x0004),
            Just(0x000A),
            Just(0x000B),
            Just(0x0016),
            any::<u16>()
        ],
        prop::option::of(any::<u16>()),
        prop::collection::vec(any::<u8>(), 0..32),
    )
        .prop_map(|(t, len, value)| {
            let len = len.unwrap_or((value.len() + 4) as u16);
            let mut tlv = t.to_be_bytes().to_vec();
            tlv.extend_from_slice(&len.to_be_bytes());
            tlv.extend_from_slice(&value);
            tlv
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn cdp_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..256)) {
        check_universal(&CdpDissector, &data);
    }

    /// A CDPv2 header followed by arbitrary TLVs.
    #[test]
    fn cdp_no_panic_on_tlvs(tlvs in prop::collection::vec(arb_tlv(), 0..8)) {
        let mut data = vec![0x02, 0xB4, 0x00, 0x00];
        for t in tlvs {
            data.extend_from_slice(&t);
        }
        check_universal(&CdpDissector, &data);
    }

    /// An Addresses TLV with an arbitrary count and entry bytes.
    #[test]
    fn cdp_no_panic_on_addresses(
        count in prop_oneof![0u32..4, any::<u32>()],
        entries in prop::collection::vec(any::<u8>(), 0..48),
    ) {
        let mut value = count.to_be_bytes().to_vec();
        value.extend_from_slice(&entries);
        let mut data = vec![0x02, 0xB4, 0x00, 0x00, 0x00, 0x02];
        data.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
        data.extend_from_slice(&value);
        check_universal(&CdpDissector, &data);
    }
}
