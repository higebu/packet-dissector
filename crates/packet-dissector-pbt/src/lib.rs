//! Property-based testing helpers and generators for packet-dissector crates.
//!
//! This crate provides `proptest` strategies and invariant checkers that
//! exercise dissectors across a wide input space. It complements example-based
//! unit tests (in each per-protocol crate) and zero-allocation tests
//! (`packet-dissector-test-alloc`) by machine-checking the parser robustness
//! requirement stated in `AGENTS.md`:
//!
//! > Postel's Law: Handle malformed input gracefully — return `PacketError`,
//! > never panic.
//!
//! ## Layers
//!
//! - [`invariants`] — checkers that any [`Dissector`] implementation must
//!   satisfy for arbitrary input.
//! - [`generators`] — `proptest` strategies that produce structured, valid
//!   protocol byte sequences for asserting stronger per-protocol invariants.
//!
//! [`Dissector`]: packet_dissector_core::dissector::Dissector

#![deny(missing_docs)]

pub mod generators;
pub mod invariants;
