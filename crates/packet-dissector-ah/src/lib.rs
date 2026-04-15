//! IP Authentication Header (AH) dissector.
//!
//! ## References
//! - RFC 4302: IP Authentication Header: <https://www.rfc-editor.org/rfc/rfc4302>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::lookup::ip_protocol_name;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Fixed portion of the AH header: Next Header (1) + Payload Len (1) + Reserved (2) +
/// SPI (4) + Sequence Number (4) = 12 bytes.
///
/// RFC 4302, Section 2: <https://www.rfc-editor.org/rfc/rfc4302#section-2>
const HEADER_MIN_SIZE: usize = 12;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 4302, Section 2.1 — Next Header
    // <https://www.rfc-editor.org/rfc/rfc4302#section-2.1>
    FieldDescriptor {
        name: "next_header",
        display_name: "Next Header",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(p) => ip_protocol_name(*p),
            _ => None,
        }),
        format_fn: None,
    },
    // RFC 4302, Section 2.2 — Payload Length
    // <https://www.rfc-editor.org/rfc/rfc4302#section-2.2>
    FieldDescriptor::new("payload_len", "Payload Length", FieldType::U8),
    // RFC 4302, Section 2.3 — Reserved
    // <https://www.rfc-editor.org/rfc/rfc4302#section-2.3>
    FieldDescriptor::new("reserved", "Reserved", FieldType::U16),
    // RFC 4302, Section 2.4 — Security Parameters Index (SPI)
    // <https://www.rfc-editor.org/rfc/rfc4302#section-2.4>
    FieldDescriptor::new("spi", "Security Parameters Index", FieldType::U32),
    // RFC 4302, Section 2.5 — Sequence Number
    // <https://www.rfc-editor.org/rfc/rfc4302#section-2.5>
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U32),
    // RFC 4302, Section 2.6 — Integrity Check Value (ICV)
    // <https://www.rfc-editor.org/rfc/rfc4302#section-2.6>
    FieldDescriptor::new("icv", "Integrity Check Value", FieldType::Bytes).optional(),
];

const FD_NEXT_HEADER: usize = 0;
const FD_PAYLOAD_LEN: usize = 1;
const FD_RESERVED: usize = 2;
const FD_SPI: usize = 3;
const FD_SEQUENCE_NUMBER: usize = 4;
const FD_ICV: usize = 5;

/// AH dissector.
///
/// Parses the IP Authentication Header (protocol 51) as defined in
/// RFC 4302. The AH provides data integrity and optional authentication
/// for IP packets.
pub struct AhDissector;

impl Dissector for AhDissector {
    fn name(&self) -> &'static str {
        "Authentication Header"
    }

    fn short_name(&self) -> &'static str {
        "AH"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < HEADER_MIN_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_MIN_SIZE,
                actual: data.len(),
            });
        }

        // RFC 4302, Section 2.1 — Next Header
        // <https://www.rfc-editor.org/rfc/rfc4302#section-2.1>
        let next_header = data[0];

        // RFC 4302, Section 2.2 — Payload Len
        // <https://www.rfc-editor.org/rfc/rfc4302#section-2.2>
        // "This 8-bit field specifies the length of AH in 32-bit words
        //  (4-byte units), minus 2."
        let payload_len = data[1];
        let total_len = (payload_len as usize + 2) * 4;

        if total_len < HEADER_MIN_SIZE {
            return Err(PacketError::InvalidHeader(
                "AH payload length yields total length below minimum",
            ));
        }

        if data.len() < total_len {
            return Err(PacketError::Truncated {
                expected: total_len,
                actual: data.len(),
            });
        }

        // RFC 4302, Section 2.3 — Reserved
        // <https://www.rfc-editor.org/rfc/rfc4302#section-2.3>
        let reserved = read_be_u16(data, 2)?;

        // RFC 4302, Section 2.4 — Security Parameters Index (SPI)
        // <https://www.rfc-editor.org/rfc/rfc4302#section-2.4>
        let spi = read_be_u32(data, 4)?;

        // RFC 4302, Section 2.5 — Sequence Number
        // <https://www.rfc-editor.org/rfc/rfc4302#section-2.5>
        let sequence_number = read_be_u32(data, 8)?;

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_len,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_NEXT_HEADER],
            FieldValue::U8(next_header),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PAYLOAD_LEN],
            FieldValue::U8(payload_len),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_RESERVED],
            FieldValue::U16(reserved),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SPI],
            FieldValue::U32(spi),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
            FieldValue::U32(sequence_number),
            offset + 8..offset + 12,
        );

        // RFC 4302, Section 2.6 — ICV (Integrity Check Value)
        // <https://www.rfc-editor.org/rfc/rfc4302#section-2.6>
        if total_len > HEADER_MIN_SIZE {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_ICV],
                FieldValue::Bytes(&data[HEADER_MIN_SIZE..total_len]),
                offset + HEADER_MIN_SIZE..offset + total_len,
            );
        }

        buf.end_layer();

        Ok(DissectResult::new(
            total_len,
            DispatchHint::ByIpProtocol(next_header),
        ))
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 4302 (AH) Coverage
    //!
    //! | RFC Section | Description                           | Test                                         |
    //! |-------------|---------------------------------------|----------------------------------------------|
    //! | 2           | Header format & dispatch              | parse_ah_basic, offset_applied_correctly     |
    //! | 2.1         | Next Header (known name)              | parse_ah_basic                               |
    //! | 2.1         | Next Header (unknown name)            | unknown_next_header_no_name                  |
    //! | 2.2         | Payload Length (formula, 96-bit ICV)  | parse_ah_basic, parse_ah_with_icv            |
    //! | 2.2         | Payload Length below fixed header     | payload_len_too_small                        |
    //! | 2.3         | Reserved MUST be 0, SHOULD be ignored | parse_ah_basic, reserved_nonzero_is_ignored  |
    //! | 2.4         | SPI (any 32-bit value)                | parse_ah_basic                               |
    //! | 2.4         | SPI = 0 (reserved, lenient parse)     | spi_zero_parsed_per_postel                   |
    //! | 2.5         | Sequence Number                       | parse_ah_basic                               |
    //! | 2.6         | ICV present (96-bit / 12 octets)      | parse_ah_with_icv                            |
    //! | 2.6         | ICV absent (minimum header only)      | parse_ah_no_icv                              |
    //! | —           | Truncated below minimum header        | truncated_header                             |
    //! | —           | Truncated after declared length       | truncated_after_length                       |
    //! | —           | Field descriptor schema               | field_descriptors_match                      |

    use super::*;

    /// Build a minimal AH header (12 bytes, payload_len=1, no ICV).
    fn make_ah_header(next_header: u8, payload_len: u8, spi: u32, seq: u32) -> Vec<u8> {
        let mut hdr = Vec::new();
        hdr.push(next_header);
        hdr.push(payload_len);
        hdr.extend_from_slice(&[0x00, 0x00]); // Reserved
        hdr.extend_from_slice(&spi.to_be_bytes());
        hdr.extend_from_slice(&seq.to_be_bytes());
        hdr
    }

    fn dissect(data: &[u8]) -> Result<(DissectBuffer<'_>, DissectResult), PacketError> {
        let mut buf = DissectBuffer::new();
        let result = AhDissector.dissect(data, &mut buf, 0)?;
        Ok((buf, result))
    }

    #[test]
    fn parse_ah_basic() {
        // payload_len=1 → total = (1+2)*4 = 12 bytes (no ICV)
        let data = make_ah_header(6, 1, 0x1234_5678, 42);
        let (buf, result) = dissect(&data).unwrap();

        assert_eq!(result.bytes_consumed, 12);
        assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

        let layer = buf.layer_by_name("AH").unwrap();
        assert_eq!(layer.name, "AH");
        assert_eq!(
            buf.field_by_name(layer, "next_header").unwrap().value,
            FieldValue::U8(6)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "next_header_name"),
            Some("TCP")
        );
        assert_eq!(
            buf.field_by_name(layer, "payload_len").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "reserved").unwrap().value,
            FieldValue::U16(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "spi").unwrap().value,
            FieldValue::U32(0x1234_5678)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_number").unwrap().value,
            FieldValue::U32(42)
        );
        assert!(buf.field_by_name(layer, "icv").is_none());
    }

    #[test]
    fn parse_ah_with_icv() {
        // payload_len=4 → total = (4+2)*4 = 24 bytes → 12 bytes ICV
        let mut data = make_ah_header(17, 4, 0xABCD_EF01, 100);
        let icv = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04,
        ];
        data.extend_from_slice(&icv);

        let (buf, result) = dissect(&data).unwrap();

        assert_eq!(result.bytes_consumed, 24);
        assert_eq!(result.next, DispatchHint::ByIpProtocol(17));

        let layer = buf.layer_by_name("AH").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "icv").unwrap().value,
            FieldValue::Bytes(&icv)
        );
    }

    #[test]
    fn parse_ah_no_icv() {
        // payload_len=1 → total = 12 bytes, exactly the fixed header size
        let data = make_ah_header(58, 1, 0x0000_0001, 1);
        let (buf, _result) = dissect(&data).unwrap();

        let layer = buf.layer_by_name("AH").unwrap();
        assert!(buf.field_by_name(layer, "icv").is_none());
    }

    #[test]
    fn truncated_header() {
        let data = [0u8; 11]; // Less than 12 bytes
        let mut buf = DissectBuffer::new();
        let err = AhDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 12,
                actual: 11
            }
        ));
    }

    #[test]
    fn truncated_after_length() {
        // payload_len=4 → expects 24 bytes but only 12 provided
        let data = make_ah_header(6, 4, 0x0000_0001, 1);
        let mut buf = DissectBuffer::new();
        let err = AhDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 24,
                actual: 12
            }
        ));
    }

    #[test]
    fn payload_len_too_small() {
        // payload_len=0 → total = (0+2)*4 = 8, less than minimum 12
        let data = make_ah_header(6, 0, 0x0000_0001, 1);
        let mut buf = DissectBuffer::new();
        let err = AhDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn offset_applied_correctly() {
        let data = make_ah_header(6, 1, 0x0000_0001, 1);
        let mut buf = DissectBuffer::new();
        AhDissector.dissect(&data, &mut buf, 100).unwrap();

        let layer = buf.layer_by_name("AH").unwrap();
        assert_eq!(layer.range, 100..112);
        assert_eq!(
            buf.field_by_name(layer, "next_header").unwrap().range,
            100..101
        );
        assert_eq!(buf.field_by_name(layer, "spi").unwrap().range, 104..108);
    }

    #[test]
    fn unknown_next_header_no_name() {
        // RFC 4302, Section 2.1 — Next Header values come from the IANA
        // IP protocol-numbers registry. For protocol numbers that have
        // no registered name, the `next_header_name` virtual display
        // field resolves to `None` rather than surfacing a placeholder.
        // <https://www.rfc-editor.org/rfc/rfc4302#section-2.1>
        let data = make_ah_header(255, 1, 0x0000_0001, 1);
        let (buf, _) = dissect(&data).unwrap();

        let layer = buf.layer_by_name("AH").unwrap();
        assert!(
            buf.resolve_display_name(layer, "next_header_name")
                .is_none()
        );
    }

    #[test]
    fn reserved_nonzero_is_ignored() {
        // RFC 4302, Section 2.3 — "This 16-bit field is reserved for
        // future use. It MUST be set to zero by the sender, and it
        // SHOULD be ignored by the recipient." The dissector therefore
        // accepts a non-zero Reserved value and surfaces it verbatim so
        // operators can observe protocol violations.
        // <https://www.rfc-editor.org/rfc/rfc4302#section-2.3>
        let mut data = make_ah_header(6, 1, 0x1234_5678, 1);
        data[2] = 0xAB;
        data[3] = 0xCD;
        let (buf, _) = dissect(&data).unwrap();

        let layer = buf.layer_by_name("AH").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "reserved").unwrap().value,
            FieldValue::U16(0xABCD)
        );
    }

    #[test]
    fn spi_zero_parsed_per_postel() {
        // RFC 4302, Section 2.4 — "The SPI value of zero (0) is
        // reserved for local, implementation-specific use and MUST NOT
        // be sent on the wire." Per Postel's Law the dissector still
        // parses packets carrying the reserved value so observers can
        // see the malformed SPI instead of discarding the packet.
        // <https://www.rfc-editor.org/rfc/rfc4302#section-2.4>
        let data = make_ah_header(6, 1, 0, 1);
        let (buf, result) = dissect(&data).unwrap();

        assert_eq!(result.bytes_consumed, 12);
        let layer = buf.layer_by_name("AH").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "spi").unwrap().value,
            FieldValue::U32(0)
        );
    }

    #[test]
    fn field_descriptors_match() {
        let descriptors = AhDissector.field_descriptors();
        assert_eq!(descriptors.len(), 6);
        assert_eq!(descriptors[0].name, "next_header");
        assert!(descriptors[0].display_fn.is_some());
        assert_eq!(descriptors[1].name, "payload_len");
        assert_eq!(descriptors[2].name, "reserved");
        assert_eq!(descriptors[3].name, "spi");
        assert_eq!(descriptors[4].name, "sequence_number");
        assert_eq!(descriptors[5].name, "icv");
    }
}
