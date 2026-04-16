//! OSPF (Open Shortest Path First) dissectors for OSPFv2 and OSPFv3.
//!
//! ## References
//! - RFC 2328 (OSPFv2): <https://www.rfc-editor.org/rfc/rfc2328>
//! - RFC 5340 (OSPFv3): <https://www.rfc-editor.org/rfc/rfc5340>
//!
//! ## RFC Coverage
//!
//! | RFC        | Section        | Description                  |
//! |------------|----------------|------------------------------|
//! | RFC 2328   | Appendix A.3.1 | OSPFv2 common header         |
//! | RFC 2328   | Appendix A.3.2 | OSPFv2 Hello packet          |
//! | RFC 2328   | Appendix A.3.3 | OSPFv2 Database Description  |
//! | RFC 2328   | Appendix A.3.4 | OSPFv2 Link State Request    |
//! | RFC 2328   | Appendix A.3.5 | OSPFv2 Link State Update     |
//! | RFC 2328   | Appendix A.3.6 | OSPFv2 Link State Ack        |
//! | RFC 2328   | Appendix A.4.1 | OSPFv2 LSA header            |
//! | RFC 5340   | Appendix A.3.1 | OSPFv3 common header         |
//! | RFC 5340   | Appendix A.3.2 | OSPFv3 Hello packet          |
//! | RFC 5340   | Appendix A.3.3 | OSPFv3 Database Description  |
//! | RFC 5340   | Appendix A.3.4 | OSPFv3 Link State Request    |
//! | RFC 5340   | Appendix A.3.5 | OSPFv3 Link State Update     |
//! | RFC 5340   | Appendix A.3.6 | OSPFv3 Link State Ack        |
//! | RFC 5340   | Appendix A.4.2 | OSPFv3 LSA header            |

#![deny(missing_docs)]

mod common;
pub mod v2;
pub mod v3;

pub use v2::Ospfv2Dissector;
pub use v3::Ospfv3Dissector;
