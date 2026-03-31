//! OSPF (Open Shortest Path First) dissectors for OSPFv2 and OSPFv3.
//!
//! ## References
//! - RFC 2328 (OSPFv2): <https://www.rfc-editor.org/rfc/rfc2328>
//! - RFC 5340 (OSPFv3): <https://www.rfc-editor.org/rfc/rfc5340>

#![deny(missing_docs)]

mod common;
pub mod v2;
pub mod v3;

pub use v2::Ospfv2Dissector;
pub use v3::Ospfv3Dissector;
