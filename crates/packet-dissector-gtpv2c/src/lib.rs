//! GTPv2-C (GPRS Tunnelling Protocol Control Plane v2) dissector.
//!
//! ## References
//! - 3GPP TS 29.274: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.274/>

#![deny(missing_docs)]

pub mod ie;
pub mod ie_parsers;
pub mod message_type;
pub mod pco;

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24, read_be_u32};

/// Minimum GTPv2-C header size (without TEID).
///
/// 3GPP TS 29.274, Section 5.1 — The mandatory header is 8 bytes when T=0
/// (no TEID present): Version(3) + P(1) + T(1) + MP(1) + Spare(2) +
/// Message Type(8) + Message Length(16) + Sequence Number(24) + Spare(8).
const MIN_HEADER_SIZE: usize = 8;

/// GTPv2-C header size when TEID is present (T=1).
///
/// 3GPP TS 29.274, Section 5.1 — 12 bytes: the mandatory 8 bytes plus
/// the 4-byte TEID field inserted before Sequence Number.
const HEADER_SIZE_WITH_TEID: usize = 12;

const FD_VERSION: usize = 0;
const FD_PIGGYBACK: usize = 1;
const FD_TEID_FLAG: usize = 2;
const FD_MP: usize = 3;
const FD_MESSAGE_TYPE: usize = 4;
const FD_LENGTH: usize = 5;
const FD_TEID: usize = 6;
const FD_SEQUENCE_NUMBER: usize = 7;
const FD_MESSAGE_PRIORITY: usize = 8;
const FD_IES: usize = 9;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("piggyback", "Piggybacked Message (P)", FieldType::U8),
    FieldDescriptor::new("teid_flag", "TEID Flag (T)", FieldType::U8),
    FieldDescriptor::new("mp", "Message Priority (MP)", FieldType::U8),
    FieldDescriptor {
        name: "message_type",
        display_name: "Message Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => Some(message_type::message_type_name(*t)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Message Length", FieldType::U16),
    FieldDescriptor::new("teid", "Tunnel Endpoint Identifier", FieldType::U32).optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U32),
    FieldDescriptor::new("message_priority", "Message Priority Value", FieldType::U8).optional(),
    FieldDescriptor::new("ies", "Information Elements", FieldType::Array)
        .optional()
        .with_children(ie::IE_CHILD_FIELDS),
];

/// GTPv2-C dissector.
///
/// Parses GTPv2-C headers as defined in 3GPP TS 29.274.
/// Supports both formats: with TEID (T=1) and without TEID (T=0).
/// The dissector parses all Information Elements (IEs) in the message body.
pub struct Gtpv2cDissector;

impl Dissector for Gtpv2cDissector {
    fn name(&self) -> &'static str {
        "GPRS Tunnelling Protocol Control Plane v2"
    }

    fn short_name(&self) -> &'static str {
        "GTPv2-C"
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
        // 3GPP TS 29.274, Section 5.1 — minimum 8 bytes
        if data.len() < MIN_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // 3GPP TS 29.274, Section 5.1 — Octet 1: flags
        let version = (data[0] >> 5) & 0x07;
        let p_flag = (data[0] >> 4) & 0x01;
        let t_flag = (data[0] >> 3) & 0x01;
        let mp_flag = (data[0] >> 2) & 0x01;

        // TS 29.274 requires Version = 2 for GTPv2-C common header
        if version != 2 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }

        // 3GPP TS 29.274, Section 5.1 — Octet 2: Message Type
        let msg_type = data[1];

        // 3GPP TS 29.274, Section 5.1 — Octets 3-4: Message Length
        // (everything after the first 4 mandatory octets)
        let msg_length = read_be_u16(data, 2)? as usize;

        // The Message Length field gives the length of the remainder of the message
        // following the first 4 octets (3GPP TS 29.274, Section 5.1).
        let expected_total_size = 4 + msg_length;

        let min_header_size = if t_flag == 1 {
            HEADER_SIZE_WITH_TEID
        } else {
            MIN_HEADER_SIZE
        };

        // Ensure the total size implied by Message Length is at least the header size.
        if expected_total_size < min_header_size {
            return Err(PacketError::InvalidHeader(
                "GTPv2-C message length shorter than minimum header size",
            ));
        }

        // Ensure we have all bytes claimed by Message Length.
        if expected_total_size > data.len() {
            return Err(PacketError::Truncated {
                expected: expected_total_size,
                actual: data.len(),
            });
        }

        let header_size = if t_flag == 1 {
            // 3GPP TS 29.274, Section 5.1 — T=1: TEID present
            if data.len() < HEADER_SIZE_WITH_TEID {
                return Err(PacketError::Truncated {
                    expected: HEADER_SIZE_WITH_TEID,
                    actual: data.len(),
                });
            }
            HEADER_SIZE_WITH_TEID
        } else {
            MIN_HEADER_SIZE
        };

        // Parse Information Elements from the message body
        let ie_start = header_size;
        let msg_end = 4 + msg_length;
        let ie_end = msg_end.min(data.len());
        let total_consumed = msg_end.min(data.len());

        // 3GPP TS 29.274, Section 5.1 — Common header fields
        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_consumed,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PIGGYBACK],
            FieldValue::U8(p_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TEID_FLAG],
            FieldValue::U8(t_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MP],
            FieldValue::U8(mp_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_TYPE],
            FieldValue::U8(msg_type),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LENGTH],
            FieldValue::U16(msg_length as u16),
            offset + 2..offset + 4,
        );

        if t_flag == 1 {
            // Octets 5-8: TEID
            let teid = read_be_u32(data, 4)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_TEID],
                FieldValue::U32(teid),
                offset + 4..offset + 8,
            );

            // Octets 9-11: Sequence Number (24 bits)
            let seq = read_be_u24(data, 8)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                FieldValue::U32(seq),
                offset + 8..offset + 11,
            );

            // Octet 12: Spare or Message Priority
            if mp_flag == 1 {
                let priority = (data[11] >> 4) & 0x0F;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_MESSAGE_PRIORITY],
                    FieldValue::U8(priority),
                    offset + 11..offset + 12,
                );
            }
        } else {
            // 3GPP TS 29.274, Section 5.1 — T=0: No TEID
            // Octets 5-7: Sequence Number (24 bits)
            let seq = read_be_u24(data, 4)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                FieldValue::U32(seq),
                offset + 4..offset + 7,
            );

            // Octet 8: Spare or Message Priority when MP=1
            if mp_flag == 1 {
                let priority = data[7];
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_MESSAGE_PRIORITY],
                    FieldValue::U8(priority),
                    offset + 7..offset + 8,
                );
            }
        };

        // msg_length covers bytes after the first 4 mandatory octets,
        // so IE data starts at header_size and extends for
        // (4 + msg_length - header_size) bytes.
        if ie_start < ie_end {
            let ie_data = &data[ie_start..ie_end];
            let array_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_IES],
                FieldValue::Array(0..0),
                offset + ie_start..offset + ie_end,
            );
            ie::parse_ies(ie_data, offset + ie_start, buf);
            buf.end_container(array_idx);

            // If no IEs were actually parsed, remove the empty array.
            let arr = &buf.fields()[array_idx as usize];
            if let FieldValue::Array(ref r) = arr.value {
                if r.start == r.end {
                    buf.truncate_fields(array_idx as usize);
                }
            }
        }

        buf.end_layer();

        // GTPv2-C is a control plane protocol — no inner payload to dispatch.
        Ok(DissectResult::new(total_consumed, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # 3GPP TS 29.274 (GTPv2-C) Coverage
    //
    // | Section   | Description                | Test                              |
    // |-----------|----------------------------|-----------------------------------|
    // | 5.1       | Header Format (T=1)        | parse_gtpv2c_with_teid            |
    // | 5.1       | Header Format (T=0)        | parse_gtpv2c_without_teid         |
    // | 5.1       | Truncated header           | parse_gtpv2c_truncated            |
    // | 5.1       | Truncated header (T=1)     | parse_gtpv2c_truncated_with_teid  |
    // | 8.2.1     | IE parsing                 | parse_gtpv2c_with_ies             |
    // | 5.1       | Echo Request (no TEID)     | parse_gtpv2c_echo_request         |

    /// Helper to build a GTPv2-C header with T=1 (TEID present).
    fn make_gtpv2c_with_teid(msg_type: u8, teid: u32, seq: u32, ies: &[u8]) -> Vec<u8> {
        let msg_length = (8 + ies.len()) as u16; // TEID(4) + Seq(3) + Spare(1) + IEs
        let mut pkt = Vec::new();
        // Octet 1: version=2, P=0, T=1, MP=0, spare=0
        pkt.push(0x48);
        // Octet 2: message type
        pkt.push(msg_type);
        // Octets 3-4: message length
        pkt.extend_from_slice(&msg_length.to_be_bytes());
        // Octets 5-8: TEID
        pkt.extend_from_slice(&teid.to_be_bytes());
        // Octets 9-11: Sequence Number (24 bits)
        pkt.push(((seq >> 16) & 0xFF) as u8);
        pkt.push(((seq >> 8) & 0xFF) as u8);
        pkt.push((seq & 0xFF) as u8);
        // Octet 12: Spare
        pkt.push(0x00);
        // IEs
        pkt.extend_from_slice(ies);
        pkt
    }

    /// Helper to build a GTPv2-C header with T=0 (no TEID).
    fn make_gtpv2c_without_teid(msg_type: u8, seq: u32, ies: &[u8]) -> Vec<u8> {
        let msg_length = (4 + ies.len()) as u16; // Seq(3) + Spare(1) + IEs
        let mut pkt = Vec::new();
        // Octet 1: version=2, P=0, T=0, MP=0, spare=0
        pkt.push(0x40);
        // Octet 2: message type
        pkt.push(msg_type);
        // Octets 3-4: message length
        pkt.extend_from_slice(&msg_length.to_be_bytes());
        // Octets 5-7: Sequence Number (24 bits)
        pkt.push(((seq >> 16) & 0xFF) as u8);
        pkt.push(((seq >> 8) & 0xFF) as u8);
        pkt.push((seq & 0xFF) as u8);
        // Octet 8: Spare
        pkt.push(0x00);
        // IEs
        pkt.extend_from_slice(ies);
        pkt
    }

    fn dissect_ok(data: &[u8]) -> (DissectResult, DissectBuffer<'_>) {
        let mut buf = DissectBuffer::new();
        let result = Gtpv2cDissector.dissect(data, &mut buf, 0).unwrap();
        (result, buf)
    }

    fn get_field<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        name: &str,
    ) -> Option<&'a FieldValue<'pkt>> {
        let layer = buf.layers().first()?;
        buf.field_by_name(layer, name).map(|f| &f.value)
    }

    #[test]
    fn parse_gtpv2c_with_teid() {
        let data = make_gtpv2c_with_teid(32, 0x12345678, 0x000001, &[]);
        let (result, buf) = dissect_ok(&data);
        assert_eq!(result.bytes_consumed, 12);

        let layer = buf.layers().first().unwrap();
        assert_eq!(layer.name, "GTPv2-C");

        // version = 2
        assert_eq!(get_field(&buf, "version"), Some(&FieldValue::U8(2)));
        // T flag = 1
        assert_eq!(get_field(&buf, "teid_flag"), Some(&FieldValue::U8(1)));
        // message_type = 32 (Create Session Request)
        assert_eq!(get_field(&buf, "message_type"), Some(&FieldValue::U8(32)));
        // message_type_name via display_fn
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("Create Session Request")
        );
        // TEID
        assert_eq!(get_field(&buf, "teid"), Some(&FieldValue::U32(0x12345678)));
        // Sequence Number
        assert_eq!(
            get_field(&buf, "sequence_number"),
            Some(&FieldValue::U32(1))
        );
    }

    #[test]
    fn parse_gtpv2c_without_teid() {
        let data = make_gtpv2c_without_teid(1, 0x000042, &[]);
        let (result, buf) = dissect_ok(&data);
        assert_eq!(result.bytes_consumed, 8);

        let layer = buf.layers().first().unwrap();
        assert_eq!(layer.name, "GTPv2-C");

        // T flag = 0
        assert_eq!(get_field(&buf, "teid_flag"), Some(&FieldValue::U8(0)));
        // message_type = 1 (Echo Request)
        assert_eq!(get_field(&buf, "message_type"), Some(&FieldValue::U8(1)));
        // Sequence Number = 0x42
        assert_eq!(
            get_field(&buf, "sequence_number"),
            Some(&FieldValue::U32(0x42))
        );
    }

    #[test]
    fn parse_gtpv2c_truncated() {
        let data = [0x48, 0x20, 0x00]; // Only 3 bytes
        let mut buf = DissectBuffer::new();

        let result = Gtpv2cDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_gtpv2c_truncated_with_teid() {
        // T=1 header but only 10 bytes (need 12)
        let data = [0x48, 0x20, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00];
        let mut buf = DissectBuffer::new();

        let result = Gtpv2cDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_gtpv2c_with_ies() {
        // Recovery IE (type=3, length=1): value=5
        let recovery_ie = [
            3, // IE Type: Recovery
            0, 1, // IE Length: 1
            0, // Spare/Instance
            5, // Recovery restart counter value
        ];
        let data = make_gtpv2c_with_teid(2, 0x00000000, 0x000001, &recovery_ie);
        let (result, buf) = dissect_ok(&data);
        assert_eq!(result.bytes_consumed, 12 + recovery_ie.len());

        let layer = buf.layers().first().unwrap();
        // Check IEs field exists
        let ies_field = buf.field_by_name(layer, "ies");
        assert!(ies_field.is_some());
    }

    #[test]
    fn parse_gtpv2c_echo_request() {
        // Echo Request has no TEID (T=0), type=1
        let recovery_ie = [3, 0, 1, 0, 10];
        let data = make_gtpv2c_without_teid(1, 0x000001, &recovery_ie);
        let (result, buf) = dissect_ok(&data);
        assert_eq!(result.bytes_consumed, 8 + recovery_ie.len());

        let layer = buf.layers().first().unwrap();
        assert_eq!(get_field(&buf, "message_type"), Some(&FieldValue::U8(1)));
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("Echo Request")
        );
    }
}
