//! IEEE 802.2 LLC header parsing shared by link-layer dissectors.
//!
//! The Ethernet dissector (IEEE 802.3 length frames) and the Linux cooked
//! capture dissectors (protocol type 0x0004) both carry an IEEE 802.2 LLC PDU.
//! This module decodes its header — DSAP, SSAP and the 1- or 2-octet control
//! field — and decides which dispatch hint the information field gets.
//!
//! ## References
//! - IEEE 802.2-1998 (ISO/IEC 8802-2), Section 5 (LLC PDU structure and
//!   control field formats): <https://standards.ieee.org/ieee/802.2/1048/>
//! - RFC 1042 (LLC Type 1 UI frames with SNAP): <https://www.rfc-editor.org/rfc/rfc1042>

use packet_dissector_core::dissector::DispatchHint;
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

/// DSAP/SSAP octets plus a 1-octet control field (U-format).
const U_FORMAT_HEADER_SIZE: usize = 3;

/// DSAP/SSAP octets plus a 2-octet control field (I- and S-format).
const IS_FORMAT_HEADER_SIZE: usize = 4;

/// The SNAP SAP value — RFC 1042, "The K1 value is 170 (decimal)."
/// (<https://www.rfc-editor.org/rfc/rfc1042>)
pub const SAP_SNAP: u8 = 0xAA;

/// Field descriptor for the DSAP octet; include it in the layer's
/// descriptor table and pass it to [`LlcHeader::push_fields`].
pub const DSAP_FIELD: FieldDescriptor =
    FieldDescriptor::new("llc_dsap", "LLC DSAP", FieldType::U8).optional();
/// Field descriptor for the SSAP octet.
pub const SSAP_FIELD: FieldDescriptor =
    FieldDescriptor::new("llc_ssap", "LLC SSAP", FieldType::U8).optional();
/// Field descriptor for the first control octet.
pub const CONTROL_FIELD: FieldDescriptor =
    FieldDescriptor::new("llc_control", "LLC Control", FieldType::U8).optional();
/// Field descriptor for the second control octet (I- and S-format PDUs).
pub const CONTROL_EXT_FIELD: FieldDescriptor = FieldDescriptor::new(
    "llc_control_ext",
    "LLC Control (second octet)",
    FieldType::U8,
)
.optional();

/// Control field format of an LLC PDU.
///
/// IEEE 802.2-1998, Section 5.4 — the low-order bits of the first control
/// octet select the format: `x0` Information, `01` Supervisory,
/// `11` Unnumbered. I- and S-format control fields are two octets long,
/// U-format control fields one octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlcFormat {
    /// I-format PDU (LLC type 2 information transfer).
    Information,
    /// S-format PDU (LLC type 2 supervisory, no information field).
    Supervisory,
    /// U-format PDU (UI, XID, TEST, …).
    Unnumbered,
}

/// A decoded IEEE 802.2 LLC header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LlcHeader {
    /// Destination Service Access Point.
    pub dsap: u8,
    /// Source Service Access Point.
    pub ssap: u8,
    /// First (or only) control octet.
    pub control: u8,
    /// Second control octet, present for I- and S-format PDUs.
    pub control_ext: Option<u8>,
}

impl LlcHeader {
    /// Decode the LLC header at the start of `data`.
    ///
    /// Returns [`PacketError::Truncated`] when `data` is shorter than the
    /// header the control field format requires.
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < U_FORMAT_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: U_FORMAT_HEADER_SIZE,
                actual: data.len(),
            });
        }
        let control = data[2];
        let control_ext = if format_of(control) == LlcFormat::Unnumbered {
            None
        } else {
            let ext = data.get(3).ok_or(PacketError::Truncated {
                expected: IS_FORMAT_HEADER_SIZE,
                actual: data.len(),
            })?;
            Some(*ext)
        };
        Ok(Self {
            dsap: data[0],
            ssap: data[1],
            control,
            control_ext,
        })
    }

    /// Decode the LLC header occupying `data[start..end]` (`end` is clamped
    /// to `data.len()`), e.g. an IEEE 802.3 LLC PDU bounded by the Length
    /// field. A truncation error reports offsets within `data`.
    pub fn parse_at(data: &[u8], start: usize, end: usize) -> Result<Self, PacketError> {
        let end = end.min(data.len());
        let pdu = data.get(start..end).unwrap_or_default();
        Self::parse(pdu).map_err(|e| match e {
            PacketError::Truncated { expected, actual } => PacketError::Truncated {
                expected: start + expected,
                actual: start + actual,
            },
            other => other,
        })
    }

    /// Push the header fields using `fields` — the layer's copies of
    /// [`DSAP_FIELD`], [`SSAP_FIELD`], [`CONTROL_FIELD`] and
    /// [`CONTROL_EXT_FIELD`], in that order. `start` is the absolute offset
    /// of the header.
    pub fn push_fields(
        &self,
        buf: &mut DissectBuffer<'_>,
        fields: [&'static FieldDescriptor; 4],
        start: usize,
    ) {
        let [dsap, ssap, control, control_ext] = fields;
        buf.push_field(dsap, FieldValue::U8(self.dsap), start..start + 1);
        buf.push_field(ssap, FieldValue::U8(self.ssap), start + 1..start + 2);
        buf.push_field(control, FieldValue::U8(self.control), start + 2..start + 3);
        if let Some(ext) = self.control_ext {
            buf.push_field(control_ext, FieldValue::U8(ext), start + 3..start + 4);
        }
    }

    /// Length of the LLC header in octets (3 or 4).
    pub fn header_len(&self) -> usize {
        if self.control_ext.is_some() {
            IS_FORMAT_HEADER_SIZE
        } else {
            U_FORMAT_HEADER_SIZE
        }
    }

    /// Control field format.
    pub fn format(&self) -> LlcFormat {
        format_of(self.control)
    }

    /// Whether this is an Unnumbered Information (UI) PDU.
    ///
    /// IEEE 802.2-1998, Section 5.4 — UI is the U-format command whose
    /// modifier bits are all zero: `0x03`, with the P/F bit (`0x10`)
    /// ignored. RFC 1042 (<https://www.rfc-editor.org/rfc/rfc1042>): "The
    /// control value is 3 (Unnumbered Information)."
    pub fn is_ui(&self) -> bool {
        self.control & !0x10 == 0x03
    }

    /// Dispatch hint for the LLC information field.
    ///
    /// UI PDUs (LLC type 1) and I-format PDUs (LLC type 2) carry data for
    /// the protocol at the DSAP, so they dispatch [`DispatchHint::ByLlcSap`].
    /// S-format PDUs have no information field, and the other U-format PDUs
    /// (XID, TEST, SABME, …) carry LLC's own data, so they end the chain.
    pub fn next_hint(&self) -> DispatchHint {
        if self.is_ui() || self.format() == LlcFormat::Information {
            DispatchHint::ByLlcSap(self.dsap)
        } else {
            DispatchHint::End
        }
    }
}

/// Control field format from the first control octet.
fn format_of(control: u8) -> LlcFormat {
    if control & 0x01 == 0 {
        LlcFormat::Information
    } else if control & 0x03 == 0x01 {
        LlcFormat::Supervisory
    } else {
        LlcFormat::Unnumbered
    }
}

#[cfg(test)]
mod tests {
    //! # IEEE 802.2 LLC Header Coverage
    //!
    //! | Section | Description                         | Test                        |
    //! |---------|-------------------------------------|-----------------------------|
    //! | 5.4     | I/S/U format from control bits      | llc_formats                 |
    //! | 5.4.3   | UI with and without P/F bit         | llc_ui_detection            |
    //! | 5.4     | Truncated 3-octet / 4-octet header  | llc_truncated               |
    //! | 5.4     | Header bounded by an end offset     | llc_parse_at                |
    //! | —       | Field push incl. second control octet | llc_push_fields           |

    use super::*;

    #[test]
    fn llc_formats() {
        let i = LlcHeader::parse(&[0xF0, 0xF0, 0x0A, 0x04]).unwrap();
        assert_eq!(i.format(), LlcFormat::Information);
        assert_eq!(i.control_ext, Some(0x04));
        assert_eq!(i.header_len(), 4);
        assert_eq!(i.next_hint(), DispatchHint::ByLlcSap(0xF0));

        let s = LlcHeader::parse(&[0xF0, 0xF0, 0x09, 0x04]).unwrap();
        assert_eq!(s.format(), LlcFormat::Supervisory);
        assert_eq!(s.header_len(), 4);
        assert_eq!(s.next_hint(), DispatchHint::End);

        let u = LlcHeader::parse(&[0x42, 0x42, 0x03]).unwrap();
        assert_eq!(u.format(), LlcFormat::Unnumbered);
        assert_eq!(u.control_ext, None);
        assert_eq!(u.header_len(), 3);
        assert_eq!(u.next_hint(), DispatchHint::ByLlcSap(0x42));

        let xid = LlcHeader::parse(&[0x00, 0x01, 0xAF]).unwrap();
        assert_eq!(xid.format(), LlcFormat::Unnumbered);
        assert_eq!(xid.next_hint(), DispatchHint::End);
    }

    #[test]
    fn llc_ui_detection() {
        assert!(LlcHeader::parse(&[0xAA, 0xAA, 0x03]).unwrap().is_ui());
        assert!(LlcHeader::parse(&[0xAA, 0xAA, 0x13]).unwrap().is_ui());
        assert!(!LlcHeader::parse(&[0xAA, 0xAA, 0xE3]).unwrap().is_ui());
    }

    #[test]
    fn llc_parse_at() {
        let data = [0xFF, 0xF0, 0xF0, 0x00, 0x02];
        let h = LlcHeader::parse_at(&data, 1, 5).unwrap();
        assert_eq!(h.control_ext, Some(0x02));
        // The end bound (e.g. an 802.3 Length of 3) hides the second octet.
        assert_eq!(
            LlcHeader::parse_at(&data, 1, 4),
            Err(PacketError::Truncated {
                expected: 5,
                actual: 4
            })
        );
        assert_eq!(
            LlcHeader::parse_at(&data, 6, 9),
            Err(PacketError::Truncated {
                expected: 9,
                actual: 6
            })
        );
    }

    static FIELDS: [FieldDescriptor; 4] =
        [DSAP_FIELD, SSAP_FIELD, CONTROL_FIELD, CONTROL_EXT_FIELD];

    #[test]
    fn llc_push_fields() {
        let h = LlcHeader::parse(&[0xF0, 0xF1, 0x00, 0x02]).unwrap();
        let mut buf = DissectBuffer::new();
        h.push_fields(
            &mut buf,
            [&FIELDS[0], &FIELDS[1], &FIELDS[2], &FIELDS[3]],
            10,
        );
        let fields = buf.fields();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].name(), "llc_dsap");
        assert_eq!(fields[1].value, FieldValue::U8(0xF1));
        assert_eq!(fields[3].name(), "llc_control_ext");
        assert_eq!(fields[3].range, 13..14);
    }

    #[test]
    fn llc_truncated() {
        assert_eq!(
            LlcHeader::parse(&[0x42, 0x42]),
            Err(PacketError::Truncated {
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(
            LlcHeader::parse(&[0xF0, 0xF0, 0x00]),
            Err(PacketError::Truncated {
                expected: 4,
                actual: 3
            })
        );
    }
}
