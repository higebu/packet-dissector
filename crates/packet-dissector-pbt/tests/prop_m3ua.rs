//! M3UA property-based tests.
//!
//! # RFC 4666 (M3UA) Coverage
//!
//! | RFC Section | Description                                          | Test                              |
//! |-------------|------------------------------------------------------|-----------------------------------|
//! | 3.1         | Message — never-panic on arbitrary bytes             | m3ua_no_panic_on_arbitrary_bytes  |
//! | 3.2         | Valid header + arbitrary (nested) TLV parameters     | m3ua_no_panic_on_arbitrary_params |
//!
//! References:
//! - RFC 4666, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.1>
//! - RFC 4666, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.2>

use packet_dissector_m3ua::M3uaDissector;
use packet_dissector_pbt::invariants::check_universal;
use proptest::prelude::*;

/// One parameter with a tag biased towards the defined tags, an arbitrary
/// (possibly inconsistent) Length and an arbitrary value.
fn arb_parameter() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![
            Just(0x0004u16),
            Just(0x0006),
            Just(0x000b),
            Just(0x000d),
            Just(0x0012),
            Just(0x0204),
            Just(0x0207),
            Just(0x0208),
            Just(0x020c),
            Just(0x0210),
            any::<u16>()
        ],
        any::<u16>(),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(tag, length, value)| {
            let mut p = tag.to_be_bytes().to_vec();
            p.extend_from_slice(&length.to_be_bytes());
            p.extend_from_slice(&value);
            p
        })
}

proptest! {
    /// Dissecting arbitrary byte sequences must never panic and must satisfy
    /// the universal invariants (AGENTS.md — Postel's Law).
    #[test]
    fn m3ua_no_panic_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_universal(&M3uaDissector, &data);
    }

    /// A valid Common Message Header followed by arbitrary parameters.
    #[test]
    fn m3ua_no_panic_on_arbitrary_params(
        class in 0u8..10,
        msg_type in 0u8..8,
        params in prop::collection::vec(arb_parameter(), 0..6),
    ) {
        let mut data = vec![1, 0, class, msg_type, 0, 0, 0, 0];
        for p in params {
            data.extend_from_slice(&p);
        }
        let len = data.len() as u32;
        data[4..8].copy_from_slice(&len.to_be_bytes());
        check_universal(&M3uaDissector, &data);
    }
}
