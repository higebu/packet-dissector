//! The APER reader, shared with the other 3GPP application protocol
//! dissectors through `packet-dissector-aper`.
//!
//! ## References
//! - ITU-T Rec. X.691 (02/2021): <https://www.itu.int/rec/T-REC-X.691>

pub(crate) use packet_dissector_aper::{AperReader, Extent, read_extent};
