//! NetFlow / IPFIX property-based tests.
//!
//! # RFC 7011 (IPFIX) / RFC 3954 (NetFlow v9) Coverage
//!
//! | RFC Section          | Description                                        | Test                                  |
//! |----------------------|----------------------------------------------------|---------------------------------------|
//! | 7011 §3.1, 3954 §5.1 | Never-panic on arbitrary bytes (all versions)      | netflow_no_panic_on_arbitrary_bytes   |
//! | 7011 §3.3-3.4, §7    | Valid header + arbitrary Sets, stateful templates  | ipfix_no_panic_on_arbitrary_sets      |
//! | 3954 §5-6            | Valid header + arbitrary FlowSets                  | v9_no_panic_on_arbitrary_flowsets     |
//!
//! References:
//! - RFC 7011, Section 3 — <https://www.rfc-editor.org/rfc/rfc7011#section-3>
//! - RFC 7011, Section 7 — <https://www.rfc-editor.org/rfc/rfc7011#section-7>
//! - RFC 3954, Section 5 — <https://www.rfc-editor.org/rfc/rfc3954#section-5>

use packet_dissector_ipfix::{
    IpfixDissector, NetflowDissector, NetflowV5Dissector, NetflowV9Dissector,
};
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

/// One Set with an ID biased towards Template, Options Template and a few
/// Data Set IDs, and a body of Field Specifier-like and random octets. The
/// Set Length is usually consistent, sometimes arbitrary.
fn arb_set(template_id: u16, options_id: u16) -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            Just(template_id),
            Just(options_id),
            256u16..260,
            any::<u16>()
        ],
        prop::collection::vec(
            prop_oneof![
                // Template Record header for IDs 256-259 with a small count.
                (256u16..260, 0u16..6).prop_map(|(id, n)| {
                    let mut v = id.to_be_bytes().to_vec();
                    v.extend_from_slice(&n.to_be_bytes());
                    v
                }),
                // Field Specifier, sometimes variable-length or enterprise.
                (any::<u16>(), prop_oneof![1u16..17, Just(65535u16)]).prop_map(|(id, len)| {
                    let mut v = id.to_be_bytes().to_vec();
                    v.extend_from_slice(&len.to_be_bytes());
                    v
                }),
                prop::collection::vec(any::<u8>(), 0..8),
            ],
            0..8,
        ),
        prop::option::weighted(0.1, any::<u16>()),
    )
        .prop_map(|(id, parts, length)| {
            let body = parts.concat();
            let length = length.unwrap_or((body.len() + 4) as u16);
            let mut s = id.to_be_bytes().to_vec();
            s.extend_from_slice(&length.to_be_bytes());
            s.extend_from_slice(&body);
            s
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn netflow_no_panic_on_arbitrary_bytes(
        version in prop_oneof![Just(5u16), Just(9), Just(10), any::<u16>()],
        rest in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut data = version.to_be_bytes().to_vec();
        data.extend_from_slice(&rest);
        check_universal(&NetflowDissector::new(), &data);
        check_universal(&IpfixDissector::new(), &data);
        check_universal(&NetflowV9Dissector::new(), &data);
        check_universal(&NetflowV5Dissector, &data);
    }

    /// A valid IPFIX Message Header followed by arbitrary Sets; the same
    /// dissector sees every message, so Templates from earlier messages
    /// are applied to later Data Sets.
    #[test]
    fn ipfix_no_panic_on_arbitrary_sets(
        messages in prop::collection::vec(
            (any::<u32>(), prop::collection::vec(arb_set(2, 3), 0..6)),
            1..4,
        ),
    ) {
        let d = IpfixDissector::new();
        for (domain, sets) in messages {
            let body = sets.concat();
            let mut data = 10u16.to_be_bytes().to_vec();
            data.extend_from_slice(&((16 + body.len()).min(65535) as u16).to_be_bytes());
            data.extend_from_slice(&[0; 8]);
            data.extend_from_slice(&(domain % 2).to_be_bytes());
            data.extend_from_slice(&body);
            check_universal(&d, &data);
        }
    }

    /// A valid NetFlow v9 Packet Header followed by arbitrary FlowSets.
    #[test]
    fn v9_no_panic_on_arbitrary_flowsets(
        packets in prop::collection::vec(prop::collection::vec(arb_set(0, 1), 0..6), 1..4),
    ) {
        let d = NetflowV9Dissector::new();
        for flowsets in packets {
            let mut data = 9u16.to_be_bytes().to_vec();
            data.extend_from_slice(&[0; 18]);
            data.extend_from_slice(&flowsets.concat());
            check_universal(&d, &data);
        }
    }
}
