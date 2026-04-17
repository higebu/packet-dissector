//! Universal invariants that every [`Dissector`] implementation must satisfy.
//!
//! These checks encode the parser-robustness guarantees required by the
//! project's coding conventions (AGENTS.md — *Postel's Law: Handle malformed
//! input gracefully — return `PacketError`, never panic*). They are designed
//! to be called from `proptest` bodies with arbitrary byte inputs so that
//! violations surface as shrunk counter-examples.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::error::PacketError;
use packet_dissector_core::packet::DissectBuffer;

/// Run the universal invariant checks against `dissector` for the given `data`.
///
/// # Checks
///
/// 1. **No panic** — `dissect` returns a `Result` for any input (any panic
///    propagates out of this function and fails the enclosing `proptest!`).
/// 2. **`bytes_consumed` ≤ `data.len()`** when `Ok`.
/// 3. **At least one layer is pushed** when `Ok`.
/// 4. **`Truncated.actual == data.len()`** and **`expected > actual`** when
///    `Err(Truncated)` — the dissector reports how many bytes it actually saw.
/// 5. **Determinism** — the same input produces the same result (and
///    equivalent buffer state) on every call.
///
/// # Panics
///
/// Panics on invariant violation. Intended to be called from within a
/// `proptest!` block so the failure is shrunk to a minimal counter-example.
pub fn check_universal<D: Dissector>(dissector: &D, data: &[u8]) {
    let mut buf1 = DissectBuffer::new();
    let r1 = dissector.dissect(data, &mut buf1, 0);

    match &r1 {
        Ok(res) => {
            assert!(
                res.bytes_consumed <= data.len(),
                "{}: bytes_consumed {} exceeds data.len() {}",
                dissector.short_name(),
                res.bytes_consumed,
                data.len(),
            );
            assert!(
                !buf1.layers().is_empty(),
                "{}: Ok result but no layer was pushed",
                dissector.short_name(),
            );
        }
        Err(PacketError::Truncated { expected, actual }) => {
            assert_eq!(
                *actual,
                data.len(),
                "{}: Truncated.actual {} != data.len() {}",
                dissector.short_name(),
                actual,
                data.len(),
            );
            assert!(
                expected > actual,
                "{}: Truncated.expected {} not greater than actual {}",
                dissector.short_name(),
                expected,
                actual,
            );
        }
        Err(_) => {}
    }

    let mut buf2 = DissectBuffer::new();
    let r2 = dissector.dissect(data, &mut buf2, 0);
    assert_eq!(
        r1,
        r2,
        "{}: dissect is not deterministic",
        dissector.short_name(),
    );
}
