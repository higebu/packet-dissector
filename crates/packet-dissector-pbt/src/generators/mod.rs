//! `proptest` strategies producing structured protocol byte sequences.
//!
//! Generators in this module emit byte buffers that satisfy each protocol's
//! header invariants (correct version, length-field consistency, etc.), so
//! tests can assert stronger per-protocol properties (e.g. "a valid IPv4
//! header is always successfully parsed and the consumed length equals
//! `IHL × 4`").
//!
//! Exception: [`dns::arb_malformed_dns_message`] deliberately produces
//! messages that may be malformed (short RDLENGTH, names straddling RDATA)
//! and is only suitable for no-panic / universal-invariant checks.

pub mod dns;
pub mod ipv4;
pub mod sdp;
pub mod tcp;
