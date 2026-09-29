//! IPv6 extension header property-based tests.
//!
//! # RFC 8200 / RFC 6275 Coverage
//!
//! | RFC Section    | Description                                | Test                                   |
//! |----------------|--------------------------------------------|----------------------------------------|
//! | 8200 §4.2-4.6  | Extension headers — never-panic            | ipv6_ext_no_panic_on_arbitrary_bytes   |
//! | 8200 §4.2      | Any Options area parses and is covered     | ipv6_options_area_always_parses        |
//! | 8200 §4.4      | Any Routing body parses                    | ipv6_routing_body_always_parses        |
//! | 6275 §6.1-6.2  | Any Mobility Header body parses            | ipv6_mobility_body_always_parses       |
//!
//! References:
//! - RFC 8200, Section 4 — <https://www.rfc-editor.org/rfc/rfc8200#section-4>
//! - RFC 6275, Section 6.1 — <https://www.rfc-editor.org/rfc/rfc6275#section-6.1>

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ipv6::{
    DestinationOptionsDissector, GenericRoutingDissector, HopByHopDissector, MobilityDissector,
};
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

/// Build an extension header of `(len + 1) * 8` octets whose first two
/// octets are `first` and `len`, followed by random octets.
fn arb_ext_header(first: u8) -> impl Strategy<Value = Vec<u8>> {
    (0u8..=8).prop_flat_map(move |len| {
        let body_len = (len as usize + 1) * 8 - 2;
        prop::collection::vec(any::<u8>(), body_len).prop_map(move |body| {
            let mut data = vec![first, len];
            data.extend_from_slice(&body);
            data
        })
    })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn ipv6_ext_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&HopByHopDissector, &data);
        check_universal(&DestinationOptionsDissector, &data);
        check_universal(&GenericRoutingDissector, &data);
        check_universal(&MobilityDissector, &data);
    }

    /// Any Options area inside a well-sized header parses, and the `options`
    /// array covers exactly the Options area (RFC 8200, Section 4.2).
    #[test]
    fn ipv6_options_area_always_parses(data in arb_ext_header(59)) {
        for dissector in [&HopByHopDissector as &dyn Dissector, &DestinationOptionsDissector] {
            let mut buf = DissectBuffer::new();
            let result = dissector
                .dissect(&data, &mut buf, 0)
                .expect("well-sized header must parse");
            prop_assert_eq!(result.bytes_consumed, data.len());
            let layer = &buf.layers()[0];
            let options = buf.field_by_name(layer, "options").expect("options present");
            prop_assert_eq!(options.range.clone(), 2..data.len());
            let FieldValue::Array(range) = &options.value else {
                panic!("options must be an array");
            };
            for field in buf.nested_fields(range) {
                prop_assert!(field.range.start >= 2 && field.range.end <= data.len());
            }
        }
    }

    /// Any Routing header body parses whatever the Routing Type.
    #[test]
    fn ipv6_routing_body_always_parses(data in arb_ext_header(59)) {
        check_universal(&GenericRoutingDissector, &data);
        let mut buf = DissectBuffer::new();
        let result = GenericRoutingDissector
            .dissect(&data, &mut buf, 0)
            .expect("well-sized header must parse");
        prop_assert_eq!(result.bytes_consumed, data.len());
        for field in buf.fields() {
            prop_assert!(field.range.end <= data.len());
        }
    }

    /// Any Mobility Header body parses whatever the MH Type.
    #[test]
    fn ipv6_mobility_body_always_parses(data in arb_ext_header(59)) {
        check_universal(&MobilityDissector, &data);
        let mut buf = DissectBuffer::new();
        let result = MobilityDissector
            .dissect(&data, &mut buf, 0)
            .expect("well-sized header must parse");
        prop_assert_eq!(result.bytes_consumed, data.len());
        for field in buf.fields() {
            prop_assert!(field.range.end <= data.len());
        }
    }
}
