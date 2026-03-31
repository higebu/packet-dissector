//! Error types for packet dissection.

use thiserror::Error;

/// Errors that can occur during packet dissection.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    /// The packet data is too short to contain the expected header.
    #[error("packet truncated: expected at least {expected} bytes, got {actual}")]
    Truncated {
        /// Minimum number of bytes expected.
        expected: usize,
        /// Actual number of bytes available.
        actual: usize,
    },

    /// The packet header contains invalid or inconsistent values.
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),

    /// A specific field contains an invalid or unsupported value.
    #[error("invalid {field} value: {value}")]
    InvalidFieldValue {
        /// The field name (e.g., `"version"`, `"protocol"`).
        field: &'static str,
        /// The invalid value.
        value: u32,
    },

    /// No dissector is registered for the given protocol identifier.
    #[error("unknown protocol: {0}")]
    UnknownProtocol(u32),
}

/// Errors that can occur when registering a dissector.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistrationError {
    /// A dissector is already registered for this dispatch key.
    #[error(
        "duplicate registration: table '{table}', key {key:#06x} — '{existing}' would be replaced by '{new}'"
    )]
    DuplicateDispatchKey {
        /// The name of the lookup table (e.g., "ethertype", "ip_protocol").
        table: &'static str,
        /// The dispatch key that already has a registered dissector.
        key: u64,
        /// The short name of the currently registered dissector.
        existing: &'static str,
        /// The short name of the dissector that was attempted to register.
        new: &'static str,
    },

    /// A dissector is already registered for a string-keyed dispatch table entry.
    #[error(
        "duplicate registration: table '{table}', key '{key}' — '{existing}' would be replaced by '{new}'"
    )]
    DuplicateStringKey {
        /// The name of the lookup table (e.g., "content_type").
        table: &'static str,
        /// The dispatch key that already has a registered dissector.
        key: &'static str,
        /// The short name of the currently registered dissector.
        existing: &'static str,
        /// The short name of the dissector that was attempted to register.
        new: &'static str,
    },
}
