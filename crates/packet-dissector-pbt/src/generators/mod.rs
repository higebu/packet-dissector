//! `proptest` strategies producing structured, valid protocol byte sequences.
//!
//! Generators in this module emit byte buffers that satisfy each protocol's
//! header invariants (correct version, length-field consistency, etc.), so
//! tests can assert stronger per-protocol properties (e.g. "a valid IPv4
//! header is always successfully parsed and the consumed length equals
//! `IHL × 4`").

pub mod ipv4;
pub mod tcp;
