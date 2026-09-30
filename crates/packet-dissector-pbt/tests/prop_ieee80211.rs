//! IEEE 802.11 property-based tests.
//!
//! # IEEE Std 802.11-2020 Coverage
//!
//! | Clause            | Description                                           | Test                                   |
//! |-------------------|-------------------------------------------------------|----------------------------------------|
//! | 9.2, 9.3          | Never-panic on arbitrary bytes                        | ieee80211_no_panic_on_arbitrary_bytes  |
//! | 9.2.4.1, 9.3      | Every type / subtype / flag combination               | ieee80211_no_panic_on_any_frame_control |
//! | 9.3.3, 9.4.2      | Management frames with arbitrary element lists        | ieee80211_no_panic_on_arbitrary_elements |
//! | 9.2.4.8, radiotap | After radiotap with FCS / data-pad Flags              | ieee80211_no_panic_after_radiotap_flags |
//!
//! References:
//! - IEEE Std 802.11-2020 — <https://standards.ieee.org/ieee/802.11/7028/>
//! - Radiotap Flags field — <https://www.radiotap.org/fields/Flags>

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::error::PacketError;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ieee80211::Ieee80211Dissector;
use packet_dissector_pbt::invariants::check_universal;
use packet_dissector_radiotap::RadiotapDissector;
use proptest::prelude::*;

/// One element with an arbitrary (possibly inconsistent) Length and an
/// Element ID biased towards the decoded elements.
fn arb_element() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            Just(0u8),
            Just(1),
            Just(3),
            Just(48),
            Just(50),
            Just(221),
            Just(255),
            any::<u8>()
        ],
        any::<u8>(),
        prop::collection::vec(any::<u8>(), 0..48),
    )
        .prop_map(|(id, len, info)| {
            let mut e = vec![id, len];
            e.extend_from_slice(&info);
            e
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn ieee80211_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..256)) {
        check_universal(&Ieee80211Dissector, &data);
    }

    /// Protocol version 0 with every frame type, subtype and flag
    /// combination, followed by an arbitrary header and body.
    #[test]
    fn ieee80211_no_panic_on_any_frame_control(
        first in any::<u8>(),
        flags in any::<u8>(),
        rest in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut data = vec![first & 0xFC, flags];
        data.extend_from_slice(&rest);
        check_universal(&Ieee80211Dissector, &data);
    }

    /// Management frames of every subtype whose body is fixed-size octets
    /// followed by arbitrary elements.
    #[test]
    fn ieee80211_no_panic_on_arbitrary_elements(
        subtype in 0u8..16,
        fixed in prop::collection::vec(any::<u8>(), 0..14),
        elements in prop::collection::vec(arb_element(), 0..6),
    ) {
        let mut data = vec![subtype << 4, 0x00, 0x00, 0x00];
        data.extend_from_slice(&[0xFF; 6]);
        data.extend_from_slice(&[0x02; 6]);
        data.extend_from_slice(&[0x02; 6]);
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&fixed);
        for e in elements {
            data.extend_from_slice(&e);
        }
        check_universal(&Ieee80211Dissector, &data);
    }

    /// A frame that follows a radiotap header whose Flags say "FCS at end"
    /// and/or "data padding": the same invariants as `check_universal`,
    /// checked on the 802.11 input slice.
    #[test]
    fn ieee80211_no_panic_after_radiotap_flags(
        flags in prop_oneof![Just(0x10u8), Just(0x20), Just(0x30), any::<u8>()],
        frame in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        // Radiotap: it_len 9, Flags only.
        let mut data = vec![0x00, 0x00, 0x09, 0x00, 0x02, 0x00, 0x00, 0x00, flags];
        data.extend_from_slice(&frame);
        let mut buf = DissectBuffer::new();
        let rt = RadiotapDissector.dissect(&data, &mut buf, 0).unwrap();
        let wlan = &data[rt.bytes_consumed..];
        match Ieee80211Dissector.dissect(wlan, &mut buf, rt.bytes_consumed) {
            Ok(r) => {
                prop_assert!(r.bytes_consumed <= wlan.len());
                prop_assert!(r.bytes_consumed + r.payload_len.unwrap_or(0) <= wlan.len());
                prop_assert_eq!(buf.layers().len(), 2);
            }
            Err(PacketError::Truncated { expected, actual }) => {
                prop_assert_eq!(actual, wlan.len());
                prop_assert!(expected > actual);
            }
            Err(_) => {}
        }
    }
}
