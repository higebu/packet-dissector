//! ASN.1 ALIGNED PER (APER) decoding shared by the 3GPP application
//! protocol dissectors.
//!
//! - [`AperReader`]: a bit cursor over an APER encoding.
//! - [`helpers`]: open types, extensible SEQUENCEs and the protocol
//!   extension containers common to every 3GPP application protocol.
//! - [`ies`]: decoders for IE types common to XnAP, F1AP and E1AP.
//! - [`ap`]: the PDU and ProtocolIE-Container framing of XnAP, F1AP and
//!   E1AP.
//!
//! ## References
//! - ITU-T Rec. X.691 (02/2021): <https://www.itu.int/rec/T-REC-X.691>
//! - 3GPP TS 38.413 (NGAP): <https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/>
//! - 3GPP TS 38.423 (XnAP): <https://www.3gpp.org/ftp/Specs/archive/38_series/38.423/>
//! - 3GPP TS 38.473 (F1AP): <https://www.3gpp.org/ftp/Specs/archive/38_series/38.473/>
//! - 3GPP TS 37.483 (E1AP): <https://www.3gpp.org/ftp/Specs/archive/37_series/37.483/>

#![deny(missing_docs)]

pub mod ap;
pub mod helpers;
pub mod ies;
mod reader;

pub use reader::{AperReader, Extent, read_extent};
