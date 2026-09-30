//! # packet-dissector-core
//!
//! Core types and traits for the `packet-dissector` ecosystem.
//!
//! This crate provides the foundational types that all protocol dissector
//! crates depend on:
//!
//! - [`Dissector`](dissector::Dissector) trait — the interface every protocol dissector implements
//! - [`DissectBuffer`](packet::DissectBuffer) and [`Layer`](packet::Layer) — parsed packet representation
//! - [`Field`](field::Field) and [`FieldValue`](field::FieldValue) — protocol field types
//! - [`PacketError`](error::PacketError) and [`RegistrationError`](error::RegistrationError) — error types
//! - [`ber`] — minimal ASN.1 BER tag-length-value walker shared by BER-based protocols

#![deny(missing_docs)]

pub mod ber;
pub mod checksum;
pub mod dissector;
pub mod error;
pub mod field;
pub mod icmp_extension;
pub mod lookup;
pub mod packet;
pub mod util;
