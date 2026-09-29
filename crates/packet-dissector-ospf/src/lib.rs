//! OSPF (Open Shortest Path First) dissectors for OSPFv2 and OSPFv3.
//!
//! ## References
//! - RFC 2328 (OSPFv2): <https://www.rfc-editor.org/rfc/rfc2328>
//! - RFC 5340 (OSPFv3): <https://www.rfc-editor.org/rfc/rfc5340>
//! - RFC 3101 (NSSA): <https://www.rfc-editor.org/rfc/rfc3101>
//! - RFC 3630 (Traffic Engineering): <https://www.rfc-editor.org/rfc/rfc3630>
//! - RFC 5250 (Opaque LSAs): <https://www.rfc-editor.org/rfc/rfc5250>
//! - RFC 5613 (Link-Local Signaling): <https://www.rfc-editor.org/rfc/rfc5613>
//! - RFC 7166 (OSPFv3 Authentication Trailer): <https://www.rfc-editor.org/rfc/rfc7166>
//! - RFC 7684 (OSPFv2 Prefix/Link Attributes): <https://www.rfc-editor.org/rfc/rfc7684>
//! - RFC 7770 (Router Information): <https://www.rfc-editor.org/rfc/rfc7770>
//! - RFC 8362 (OSPFv3 Extended LSAs): <https://www.rfc-editor.org/rfc/rfc8362>
//! - RFC 8665 (OSPFv2 Segment Routing): <https://www.rfc-editor.org/rfc/rfc8665>
//! - RFC 8666 (OSPFv3 Segment Routing): <https://www.rfc-editor.org/rfc/rfc8666>
//! - RFC 9513 (OSPFv3 SRv6): <https://www.rfc-editor.org/rfc/rfc9513>
//!
//! ## RFC Coverage
//!
//! | RFC        | Section           | Description                              |
//! |------------|-------------------|------------------------------------------|
//! | RFC 2328   | Appendix A.3.1-6  | OSPFv2 packets                           |
//! | RFC 2328   | Appendix A.4.1-5  | OSPFv2 LSA header and LSA types 1-5      |
//! | RFC 2328   | Appendix D.3      | OSPFv2 cryptographic authentication      |
//! | RFC 3101   | Appendix C        | NSSA-LSA (type 7)                        |
//! | RFC 5250   | Section 3         | Opaque LSAs (types 9-11)                 |
//! | RFC 3630   | Sections 2.4-2.5  | TE LSA TLVs                              |
//! | RFC 7770   | Section 2         | Router Information LSA (v2 and v3)       |
//! | RFC 7684   | Sections 2-3      | OSPFv2 Extended Prefix / Link LSAs       |
//! | RFC 8665   | Sections 2-6      | OSPFv2 SR TLVs and sub-TLVs              |
//! | RFC 5340   | Appendix A.3.1-6  | OSPFv3 packets                           |
//! | RFC 5340   | Appendix A.4.1-10 | OSPFv3 LSA header and LSA bodies         |
//! | RFC 8362   | Sections 3-4      | OSPFv3 Extended LSAs and TLVs            |
//! | RFC 8666   | Sections 3, 6, 7  | OSPFv3 SR sub-TLVs                       |
//! | RFC 9513   | Sections 2, 7-9   | OSPFv3 SRv6 Locator LSA and SID sub-TLVs |
//! | RFC 5613   | Section 2         | LLS data block (v2 and v3)               |
//! | RFC 7166   | Section 4.1       | OSPFv3 Authentication Trailer            |

#![deny(missing_docs)]

mod common;
mod tlv;
mod trailer;
pub mod v2;
mod v2_lsa;
pub mod v3;
mod v3_lsa;

pub use v2::Ospfv2Dissector;
pub use v3::Ospfv3Dissector;
