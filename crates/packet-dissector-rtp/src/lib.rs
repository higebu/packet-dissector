//! RTP (Real-time Transport Protocol) dissector.
//!
//! ## References
//! - RFC 3550, Section 5.1 — RTP Fixed Header Fields:
//!   <https://www.rfc-editor.org/rfc/rfc3550#section-5.1>
//! - RFC 3550, Section 5.3.1 — RTP Header Extension:
//!   <https://www.rfc-editor.org/rfc/rfc3550#section-5.3.1>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Minimum RTP header size in bytes (fixed header without CSRC list or extension).
/// RFC 3550, Section 5.1 — "The first twelve octets are present in every RTP packet"
/// <https://www.rfc-editor.org/rfc/rfc3550#section-5.1>
const MIN_HEADER_SIZE: usize = 12;

/// RTP version defined by RFC 3550.
/// RFC 3550, Section 5.1 — "The version defined by this specification is two (2)."
/// <https://www.rfc-editor.org/rfc/rfc3550#section-5.1>
const RTP_VERSION: u8 = 2;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_VERSION: usize = 0;
const FD_PADDING: usize = 1;
const FD_EXTENSION: usize = 2;
const FD_CSRC_COUNT: usize = 3;
const FD_MARKER: usize = 4;
const FD_PAYLOAD_TYPE: usize = 5;
const FD_SEQUENCE_NUMBER: usize = 6;
const FD_TIMESTAMP: usize = 7;
const FD_SSRC: usize = 8;
const FD_CSRC_LIST: usize = 9;
const FD_PADDING_LENGTH: usize = 10;
const FD_EXT_PROFILE: usize = 11;
const FD_EXT_LENGTH: usize = 12;
const FD_EXT_DATA: usize = 13;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("padding", "Padding", FieldType::U8),
    FieldDescriptor::new("extension", "Extension", FieldType::U8),
    FieldDescriptor::new("csrc_count", "CSRC Count", FieldType::U8),
    FieldDescriptor::new("marker", "Marker", FieldType::U8),
    FieldDescriptor::new("payload_type", "Payload Type", FieldType::U8),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U16),
    FieldDescriptor::new("timestamp", "Timestamp", FieldType::U32),
    FieldDescriptor::new("ssrc", "SSRC", FieldType::U32),
    FieldDescriptor::new("csrc_list", "CSRC List", FieldType::Array).optional(),
    FieldDescriptor::new("padding_length", "Padding Length", FieldType::U8).optional(),
    FieldDescriptor::new("ext_profile", "Extension Profile", FieldType::U16).optional(),
    FieldDescriptor::new("ext_length", "Extension Length", FieldType::U16).optional(),
    FieldDescriptor::new("ext_data", "Extension Data", FieldType::Bytes).optional(),
];

/// RTP dissector.
pub struct RtpDissector;

impl Dissector for RtpDissector {
    fn name(&self) -> &'static str {
        "Real-time Transport Protocol"
    }

    fn short_name(&self) -> &'static str {
        "RTP"
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
        // RFC 3550, Section 5.1 — minimum 12-byte fixed header
        // https://www.rfc-editor.org/rfc/rfc3550#section-5.1
        if data.len() < MIN_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 3550, Section 5.1 — Fixed header fields
        // https://www.rfc-editor.org/rfc/rfc3550#section-5.1
        let byte0 = data[0];
        let version = (byte0 >> 6) & 0x03;
        let padding = (byte0 >> 5) & 0x01;
        let extension_bit = (byte0 >> 4) & 0x01;
        let cc = byte0 & 0x0F;

        // RFC 3550, Section 5.1 — "The version defined by this specification is two (2)."
        // https://www.rfc-editor.org/rfc/rfc3550#section-5.1
        if version != RTP_VERSION {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: version as u32,
            });
        }

        let byte1 = data[1];
        let marker = (byte1 >> 7) & 0x01;
        let payload_type = byte1 & 0x7F;
        let sequence_number = read_be_u16(data, 2)?;
        let timestamp = read_be_u32(data, 4)?;
        let ssrc = read_be_u32(data, 8)?;

        let csrc_end = MIN_HEADER_SIZE + (cc as usize) * 4;
        if data.len() < csrc_end {
            return Err(PacketError::Truncated {
                expected: csrc_end,
                actual: data.len(),
            });
        }

        // Compute header_end before begin_layer so we can set the correct range.
        // We need to check extension and padding sizes first.
        let mut header_end = csrc_end;

        // RFC 3550, Section 5.3.1 — Header Extension
        // https://www.rfc-editor.org/rfc/rfc3550#section-5.3.1
        let ext_info = if extension_bit == 1 {
            let ext_header_start = csrc_end;

            // Need at least 4 bytes for extension header (profile + length)
            if data.len() < ext_header_start + 4 {
                return Err(PacketError::Truncated {
                    expected: ext_header_start + 4,
                    actual: data.len(),
                });
            }

            let ext_profile = read_be_u16(data, ext_header_start)?;

            // RFC 3550, Section 5.3.1 — length counts 32-bit words, excluding
            // the 4-byte extension header itself (zero is valid).
            // https://www.rfc-editor.org/rfc/rfc3550#section-5.3.1
            let ext_length = read_be_u16(data, ext_header_start + 2)?;

            let ext_data_bytes = (ext_length as usize) * 4;
            let ext_total = 4 + ext_data_bytes;

            if data.len() < ext_header_start + ext_total {
                return Err(PacketError::Truncated {
                    expected: ext_header_start + ext_total,
                    actual: data.len(),
                });
            }

            header_end = ext_header_start + ext_total;
            Some((
                ext_header_start,
                ext_profile,
                ext_length,
                ext_data_bytes,
                ext_total,
            ))
        } else {
            None
        };

        // RFC 3550, Section 5.1 — "If the padding bit is set, the packet
        // contains one or more additional padding octets at the end which are
        // not part of the payload. The last octet of the padding contains a
        // count of how many padding octets should be ignored, including itself."
        // https://www.rfc-editor.org/rfc/rfc3550#section-5.1
        let pad_count = if padding == 1 {
            if data.len() <= header_end {
                return Err(PacketError::InvalidHeader(
                    "RTP padding bit set but no payload/padding bytes present",
                ));
            }
            let pc = data[data.len() - 1];
            if pc == 0 {
                return Err(PacketError::InvalidHeader(
                    "RTP padding count must be >= 1 (includes the count byte itself)",
                ));
            }
            if (pc as usize) > data.len() - header_end {
                return Err(PacketError::InvalidHeader(
                    "RTP padding count exceeds available payload bytes",
                ));
            }
            Some(pc)
        } else {
            None
        };

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + header_end,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PADDING],
            FieldValue::U8(padding),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_EXTENSION],
            FieldValue::U8(extension_bit),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CSRC_COUNT],
            FieldValue::U8(cc),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MARKER],
            FieldValue::U8(marker),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PAYLOAD_TYPE],
            FieldValue::U8(payload_type),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
            FieldValue::U16(sequence_number),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TIMESTAMP],
            FieldValue::U32(timestamp),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SSRC],
            FieldValue::U32(ssrc),
            offset + 8..offset + 12,
        );

        if cc > 0 {
            let array_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_CSRC_LIST],
                FieldValue::Array(0..0),
                (offset + MIN_HEADER_SIZE)..(offset + csrc_end),
            );
            for i in 0..cc as usize {
                let csrc_offset = MIN_HEADER_SIZE + i * 4;
                let csrc_val = read_be_u32(data, csrc_offset)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_CSRC_LIST],
                    FieldValue::U32(csrc_val),
                    (offset + csrc_offset)..(offset + csrc_offset + 4),
                );
            }
            buf.end_container(array_idx);
        }

        if let Some((ext_header_start, ext_profile, ext_length, ext_data_bytes, ext_total)) =
            ext_info
        {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_EXT_PROFILE],
                FieldValue::U16(ext_profile),
                (offset + ext_header_start)..(offset + ext_header_start + 2),
            );

            buf.push_field(
                &FIELD_DESCRIPTORS[FD_EXT_LENGTH],
                FieldValue::U16(ext_length),
                (offset + ext_header_start + 2)..(offset + ext_header_start + 4),
            );

            if ext_data_bytes > 0 {
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_EXT_DATA],
                    FieldValue::Bytes(&data[ext_header_start + 4..ext_header_start + ext_total]),
                    (offset + ext_header_start + 4)..(offset + ext_header_start + ext_total),
                );
            }
        }

        if let Some(pc) = pad_count {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_PADDING_LENGTH],
                FieldValue::U8(pc),
                (offset + data.len() - 1)..(offset + data.len()),
            );
        }

        buf.end_layer();

        // RTP payload is audio/video data — no further protocol dissection.
        Ok(DissectResult::new(header_end, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 3550 (RTP) Coverage
    //
    // | RFC Section | Description                | Test                                   |
    // |-------------|----------------------------|----------------------------------------|
    // | 5.1         | Fixed Header Fields        | parse_rtp_basic                        |
    // | 5.1         | Version validation         | parse_rtp_invalid_version              |
    // | 5.1         | Padding bit                | parse_rtp_with_padding                 |
    // | 5.1         | Padding — no payload       | parse_rtp_padding_no_payload           |
    // | 5.1         | Padding — count zero       | parse_rtp_padding_count_zero           |
    // | 5.1         | Padding — count overflow   | parse_rtp_padding_count_exceeds_payload|
    // | 5.1         | Marker bit                 | parse_rtp_marker_set                   |
    // | 5.1         | CSRC list                  | parse_rtp_with_csrc                    |
    // | 5.1         | Truncated header           | parse_rtp_truncated                    |
    // | 5.1         | Truncated CSRC             | parse_rtp_truncated_csrc               |
    // | 5.3.1       | Header Extension           | parse_rtp_with_extension               |
    // | 5.3.1       | Zero-length extension      | parse_rtp_zero_length_extension        |
    // | 5.1 + 5.3.1 | CSRC + Extension           | parse_rtp_with_csrc_and_extension      |
    // | 5.3.1       | Truncated extension header | parse_rtp_truncated_extension_header   |
    // | 5.3.1       | Truncated extension data   | parse_rtp_truncated_extension_data     |

    /// Build a minimal RTP header (12 bytes): V=2, P=0, X=0, CC=0, M=0, PT=0.
    fn minimal_rtp_header(pt: u8, seq: u16, ts: u32, ssrc: u32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        // byte 0: V=2, P=0, X=0, CC=0
        buf.push(0x80);
        // byte 1: M=0, PT
        buf.push(pt & 0x7F);
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&ts.to_be_bytes());
        buf.extend_from_slice(&ssrc.to_be_bytes());
        buf
    }

    #[test]
    fn parse_rtp_basic() {
        let data = minimal_rtp_header(111, 1000, 160_000, 0x12345678);
        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 12);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(buf.layers().len(), 1);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "RTP");
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "padding").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "extension").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "csrc_count").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "marker").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "payload_type").unwrap().value,
            FieldValue::U8(111)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_number").unwrap().value,
            FieldValue::U16(1000)
        );
        assert_eq!(
            buf.field_by_name(layer, "timestamp").unwrap().value,
            FieldValue::U32(160_000)
        );
        assert_eq!(
            buf.field_by_name(layer, "ssrc").unwrap().value,
            FieldValue::U32(0x12345678)
        );
        assert!(buf.field_by_name(layer, "csrc_list").is_none());
    }

    #[test]
    fn parse_rtp_with_padding() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set P=1
        data[0] |= 0x20;
        // Append payload + padding: 4 bytes audio data + 4 bytes padding (last byte = count)
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // payload
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // 4 bytes padding, count=4

        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 12);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "padding").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "padding_length").unwrap().value,
            FieldValue::U8(4)
        );
    }

    #[test]
    fn parse_rtp_padding_no_payload() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set P=1 but no trailing bytes
        data[0] |= 0x20;
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(err, PacketError::InvalidHeader(_)),
            "expected InvalidHeader for P=1 with no payload, got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_padding_count_zero() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        data[0] |= 0x20;
        // Last byte = 0 is invalid (count must include itself, so >= 1)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(err, PacketError::InvalidHeader(_)),
            "expected InvalidHeader for padding count 0, got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_padding_count_exceeds_payload() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        data[0] |= 0x20;
        // Only 2 bytes of payload but padding count says 10
        data.extend_from_slice(&[0x00, 0x0A]);
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(err, PacketError::InvalidHeader(_)),
            "expected InvalidHeader for excessive padding count, got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_marker_set() {
        let mut data = minimal_rtp_header(96, 500, 8000, 0x11223344);
        // Set M=1
        data[1] |= 0x80;
        let mut buf = DissectBuffer::new();
        RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "marker").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "payload_type").unwrap().value,
            FieldValue::U8(96)
        );
    }

    #[test]
    fn parse_rtp_with_csrc() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set CC=2
        data[0] = (data[0] & 0xF0) | 0x02;
        // Append 2 CSRC entries
        data.extend_from_slice(&0x11111111u32.to_be_bytes());
        data.extend_from_slice(&0x22222222u32.to_be_bytes());

        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 20); // 12 + 2*4
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "csrc_count").unwrap().value,
            FieldValue::U8(2)
        );

        let csrc_list = buf.field_by_name(layer, "csrc_list").unwrap();
        let range = match &csrc_list.value {
            FieldValue::Array(r) => r.clone(),
            _ => panic!("expected Array"),
        };
        let elements = buf.nested_fields(&range);
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0].value, FieldValue::U32(0x11111111));
        assert_eq!(elements[1].value, FieldValue::U32(0x22222222));
    }

    #[test]
    fn parse_rtp_with_extension() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set X=1
        data[0] |= 0x10;
        // Extension header: profile=0xBEDE, length=1 (1 × 32-bit word = 4 bytes)
        data.extend_from_slice(&0xBEDEu16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        // Extension data: 4 bytes
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 20); // 12 + 4 (ext header) + 4 (ext data)
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "extension").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "ext_profile").unwrap().value,
            FieldValue::U16(0xBEDE)
        );
        assert_eq!(
            buf.field_by_name(layer, "ext_length").unwrap().value,
            FieldValue::U16(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "ext_data").unwrap().value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04])
        );
    }

    #[test]
    fn parse_rtp_zero_length_extension() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set X=1
        data[0] |= 0x10;
        // Extension header: profile=0x1234, length=0 (zero is valid per RFC 3550)
        data.extend_from_slice(&0x1234u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());

        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 16); // 12 + 4 (ext header only)
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "ext_profile").unwrap().value,
            FieldValue::U16(0x1234)
        );
        assert_eq!(
            buf.field_by_name(layer, "ext_length").unwrap().value,
            FieldValue::U16(0)
        );
        assert!(buf.field_by_name(layer, "ext_data").is_none());
    }

    #[test]
    fn parse_rtp_with_csrc_and_extension() {
        let mut data = minimal_rtp_header(8, 42, 320_000, 0xDEADBEEF);
        // Set CC=1, X=1
        data[0] = (data[0] & 0xE0) | 0x11; // V=2, P=0, X=1, CC=1
        // CSRC entry
        data.extend_from_slice(&0xCAFEBABEu32.to_be_bytes());
        // Extension header: profile=0xABCD, length=2
        data.extend_from_slice(&0xABCDu16.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes());
        // Extension data: 8 bytes
        data.extend_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);

        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        // 12 (fixed) + 4 (1 CSRC) + 4 (ext header) + 8 (ext data) = 28
        assert_eq!(result.bytes_consumed, 28);

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "csrc_count").unwrap().value,
            FieldValue::U8(1)
        );
        let csrc_list = buf.field_by_name(layer, "csrc_list").unwrap();
        let range = match &csrc_list.value {
            FieldValue::Array(r) => r.clone(),
            _ => panic!("expected Array"),
        };
        let elements = buf.nested_fields(&range);
        assert_eq!(elements.len(), 1);
        assert_eq!(elements[0].value, FieldValue::U32(0xCAFEBABE));

        assert_eq!(
            buf.field_by_name(layer, "ext_profile").unwrap().value,
            FieldValue::U16(0xABCD)
        );
        assert_eq!(
            buf.field_by_name(layer, "ext_length").unwrap().value,
            FieldValue::U16(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "ext_data").unwrap().value,
            FieldValue::Bytes(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
        );
    }

    #[test]
    fn parse_rtp_truncated() {
        let data = [0x80, 0x00, 0x00]; // Only 3 bytes
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PacketError::Truncated {
                    expected: 12,
                    actual: 3
                }
            ),
            "expected Truncated, got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_invalid_version() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set version to 3
        data[0] = (3 << 6) | (data[0] & 0x3F);
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PacketError::InvalidFieldValue {
                    field: "version",
                    value: 3
                }
            ),
            "expected InvalidFieldValue for version, got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_truncated_csrc() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set CC=3 but don't add any CSRC data
        data[0] = (data[0] & 0xF0) | 0x03;
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PacketError::Truncated {
                    expected: 24,
                    actual: 12
                }
            ),
            "expected Truncated(24, 12), got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_truncated_extension_header() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set X=1 but don't add extension header bytes
        data[0] |= 0x10;
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PacketError::Truncated {
                    expected: 16,
                    actual: 12
                }
            ),
            "expected Truncated(16, 12), got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_truncated_extension_data() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set X=1
        data[0] |= 0x10;
        // Extension header: profile=0x0000, length=2 (needs 8 bytes of data)
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes());
        // Only add 4 bytes instead of 8
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PacketError::Truncated {
                    expected: 24,
                    actual: 20
                }
            ),
            "expected Truncated(24, 20), got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_with_offset() {
        let mut data = vec![0xFF; 10]; // 10 bytes of prefix
        data.extend_from_slice(&minimal_rtp_header(96, 100, 3200, 0xABCDEF01));
        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data[10..], &mut buf, 10).unwrap();

        assert_eq!(result.bytes_consumed, 12);
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 10..22);
        assert_eq!(buf.field_by_name(layer, "ssrc").unwrap().range, 18..22);
    }

    #[test]
    fn field_descriptors_complete() {
        let descriptors = RtpDissector.field_descriptors();
        assert_eq!(descriptors.len(), 14);
        assert_eq!(descriptors[0].name, "version");
        assert_eq!(descriptors[9].name, "csrc_list");
        assert!(descriptors[9].optional);
        assert_eq!(descriptors[10].name, "padding_length");
        assert!(descriptors[10].optional);
        assert_eq!(descriptors[11].name, "ext_profile");
        assert!(descriptors[11].optional);
    }

    #[test]
    fn name_and_short_name() {
        assert_eq!(RtpDissector.name(), "Real-time Transport Protocol");
        assert_eq!(RtpDissector.short_name(), "RTP");
    }
}
