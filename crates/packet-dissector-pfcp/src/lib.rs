//! PFCP (Packet Forwarding Control Protocol) dissector.
//!
//! ## References
//! - 3GPP TS 29.244: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.244/>

#![deny(missing_docs)]

pub mod ie;
pub mod ie_parsers;
pub mod message_type;

#[cfg(test)]
pub(crate) mod test_utils;

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24, read_be_u64};

/// Minimum PFCP header size (S=0, node-related messages).
///
/// 3GPP TS 29.244, Section 7.2.2.2 — 8 bytes: Version/flags(1) +
/// Message Type(1) + Message Length(2) + Sequence Number(3) + Spare(1).
const MIN_HEADER_SIZE: usize = 8;

/// PFCP header size when SEID is present (S=1, session-related messages).
///
/// 3GPP TS 29.244, Section 7.2.2.3 — 16 bytes: Version/flags(1) +
/// Message Type(1) + Message Length(2) + SEID(8) + Sequence Number(3) + Spare(1).
const HEADER_SIZE_WITH_SEID: usize = 16;

const FD_VERSION: usize = 0;
const FD_S_FLAG: usize = 1;
const FD_MP_FLAG: usize = 2;
const FD_FO_FLAG: usize = 3;
const FD_MESSAGE_TYPE: usize = 4;
const FD_LENGTH: usize = 5;
const FD_SEID: usize = 6;
const FD_SEQUENCE_NUMBER: usize = 7;
const FD_MESSAGE_PRIORITY: usize = 8;
const FD_IES: usize = 9;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("s_flag", "SEID Flag (S)", FieldType::U8),
    FieldDescriptor::new("mp_flag", "Message Priority (MP)", FieldType::U8),
    FieldDescriptor::new("fo_flag", "Follow On (FO)", FieldType::U8),
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
    FieldDescriptor::new("seid", "Session Endpoint Identifier", FieldType::U64).optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U32),
    FieldDescriptor::new("message_priority", "Message Priority Value", FieldType::U8).optional(),
    FieldDescriptor::new("ies", "Information Elements", FieldType::Array)
        .optional()
        .with_children(ie::IE_CHILD_FIELDS),
];

/// PFCP dissector.
///
/// Parses PFCP headers as defined in 3GPP TS 29.244.
/// Supports both node-related messages (S=0) and session-related messages (S=1).
/// The dissector parses all Information Elements (IEs) in the message body.
pub struct PfcpDissector;

impl Dissector for PfcpDissector {
    fn name(&self) -> &'static str {
        "Packet Forwarding Control Protocol"
    }

    fn short_name(&self) -> &'static str {
        "PFCP"
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
        // 3GPP TS 29.244, Section 7.2.2 — minimum 8 bytes
        if data.len() < MIN_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // 3GPP TS 29.244, Section 7.2.2.1 — Octet 1: flags
        let version = (data[0] >> 5) & 0x07;
        let fo_flag = (data[0] >> 2) & 0x01;
        let mp_flag = (data[0] >> 1) & 0x01;
        let s_flag = data[0] & 0x01;

        // 3GPP TS 29.244 requires Version = 1
        if version != 1 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }

        // 3GPP TS 29.244, Section 7.2.2.1 — Octet 2: Message Type
        let msg_type = data[1];

        // 3GPP TS 29.244, Section 7.2.2.1 — Octets 3-4: Message Length
        // (everything after the first 4 mandatory octets)
        let msg_length = read_be_u16(data, 2)? as usize;

        let expected_total_size = 4 + msg_length;

        let min_header_size = if s_flag == 1 {
            HEADER_SIZE_WITH_SEID
        } else {
            MIN_HEADER_SIZE
        };

        // Ensure the total size implied by Message Length is at least the header size.
        if expected_total_size < min_header_size {
            return Err(PacketError::InvalidHeader(
                "PFCP message length shorter than minimum header size",
            ));
        }

        // Ensure we have all bytes claimed by Message Length.
        if expected_total_size > data.len() {
            return Err(PacketError::Truncated {
                expected: expected_total_size,
                actual: data.len(),
            });
        }

        let total_consumed = expected_total_size.min(data.len());

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_consumed,
        );

        // 3GPP TS 29.244, Section 7.2.2.1 — Common header fields
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_S_FLAG],
            FieldValue::U8(s_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MP_FLAG],
            FieldValue::U8(mp_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FO_FLAG],
            FieldValue::U8(fo_flag),
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

        let header_size = if s_flag == 1 {
            // 3GPP TS 29.244, Section 7.2.2.3 — S=1: SEID present
            // Note: data.len() >= HEADER_SIZE_WITH_SEID is guaranteed by the
            // prior checks (expected_total_size >= min_header_size and
            // data.len() >= expected_total_size).

            // Octets 5-12: SEID (64 bits)
            let seid = read_be_u64(data, 4)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_SEID],
                FieldValue::U64(seid),
                offset + 4..offset + 12,
            );

            // Octets 13-15: Sequence Number (24 bits)
            let seq = read_be_u24(data, 12)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                FieldValue::U32(seq),
                offset + 12..offset + 15,
            );

            // Octet 16: Message Priority (if MP=1, upper 4 bits) or Spare
            if mp_flag == 1 {
                let priority = (data[15] >> 4) & 0x0F;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_MESSAGE_PRIORITY],
                    FieldValue::U8(priority),
                    offset + 15..offset + 16,
                );
            }

            HEADER_SIZE_WITH_SEID
        } else {
            // 3GPP TS 29.244, Section 7.2.2.2 — S=0: No SEID
            // Octets 5-7: Sequence Number (24 bits)
            let seq = read_be_u24(data, 4)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                FieldValue::U32(seq),
                offset + 4..offset + 7,
            );

            // Octet 8: Spare
            MIN_HEADER_SIZE
        };

        // Parse Information Elements from the message body
        let ie_start = header_size;
        let msg_end = 4 + msg_length;
        let ie_end = msg_end.min(data.len());

        if ie_start < ie_end {
            let ie_data = &data[ie_start..ie_end];
            let array_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_IES],
                FieldValue::Array(0..0),
                offset + ie_start..offset + ie_end,
            );
            ie::parse_ies(ie_data, offset + ie_start, 0, buf)?;
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

        // PFCP is a control plane protocol — no inner payload to dispatch.
        Ok(DissectResult::new(total_consumed, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::packet::DissectBuffer;

    // # 3GPP TS 29.244 (PFCP) Coverage
    //
    // | Section   | Description                       | Test                                  |
    // |-----------|-----------------------------------|---------------------------------------|
    // | 7.2.2.3   | Header Format (S=1)               | parse_pfcp_with_seid                  |
    // | 7.2.2.2   | Header Format (S=0)               | parse_pfcp_without_seid               |
    // | 7.2.2.1   | Truncated header                  | parse_pfcp_truncated                  |
    // | 7.2.2.3   | Truncated header (S=1)            | parse_pfcp_truncated_with_seid        |
    // | 7.2.2.1   | Version check                     | parse_pfcp_invalid_version            |
    // | 8.1.1     | IE parsing                        | parse_pfcp_with_ies                   |
    // | 7.2.2.2   | Heartbeat Request (no SEID)       | parse_pfcp_heartbeat_request          |
    // | 7.2.2.3   | Session with MP flag              | parse_pfcp_with_message_priority      |
    // | 7.2.2.1   | FO flag                           | parse_pfcp_with_fo_flag               |
    // | 7.2.2.1   | Length shorter than header         | parse_pfcp_length_too_short           |
    // | 7.2.2.1   | Length exceeds available data      | parse_pfcp_length_exceeds_data        |

    /// Helper to build a PFCP header with S=1 (SEID present).
    fn make_pfcp_with_seid(msg_type: u8, seid: u64, seq: u32, ies: &[u8]) -> Vec<u8> {
        let msg_length = (12 + ies.len()) as u16; // SEID(8) + Seq(3) + Spare(1) + IEs
        let mut pkt = Vec::new();
        // Octet 1: version=1, Spare=0, Spare=0, FO=0, MP=0, S=1
        pkt.push(0x21);
        // Octet 2: message type
        pkt.push(msg_type);
        // Octets 3-4: message length
        pkt.extend_from_slice(&msg_length.to_be_bytes());
        // Octets 5-12: SEID
        pkt.extend_from_slice(&seid.to_be_bytes());
        // Octets 13-15: Sequence Number (24 bits)
        pkt.push(((seq >> 16) & 0xFF) as u8);
        pkt.push(((seq >> 8) & 0xFF) as u8);
        pkt.push((seq & 0xFF) as u8);
        // Octet 16: Spare
        pkt.push(0x00);
        // IEs
        pkt.extend_from_slice(ies);
        pkt
    }

    /// Helper to build a PFCP header with S=0 (no SEID).
    fn make_pfcp_without_seid(msg_type: u8, seq: u32, ies: &[u8]) -> Vec<u8> {
        let msg_length = (4 + ies.len()) as u16; // Seq(3) + Spare(1) + IEs
        let mut pkt = Vec::new();
        // Octet 1: version=1, Spare=0, Spare=0, FO=0, MP=0, S=0
        pkt.push(0x20);
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
        let dissector = PfcpDissector;
        let result = dissector.dissect(data, &mut buf, 0).unwrap();
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
    fn parse_pfcp_with_seid() {
        let data = make_pfcp_with_seid(50, 0x0123456789ABCDEF, 0x000001, &[]);
        let (result, buf) = dissect_ok(&data);
        assert_eq!(result.bytes_consumed, 16);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "PFCP");

        // version = 1
        assert_eq!(get_field(&buf, "version"), Some(&FieldValue::U8(1)));
        // S flag = 1
        assert_eq!(get_field(&buf, "s_flag"), Some(&FieldValue::U8(1)));
        // message_type = 50 (Session Establishment Request)
        assert_eq!(get_field(&buf, "message_type"), Some(&FieldValue::U8(50)));
        // message_type display name
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("Session Establishment Request")
        );
        // SEID
        assert_eq!(
            get_field(&buf, "seid"),
            Some(&FieldValue::U64(0x0123456789ABCDEF))
        );
        // Sequence Number
        assert_eq!(
            get_field(&buf, "sequence_number"),
            Some(&FieldValue::U32(1))
        );
    }

    #[test]
    fn parse_pfcp_without_seid() {
        let data = make_pfcp_without_seid(1, 0x000042, &[]);
        let (result, buf) = dissect_ok(&data);
        assert_eq!(result.bytes_consumed, 8);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "PFCP");

        // S flag = 0
        assert_eq!(get_field(&buf, "s_flag"), Some(&FieldValue::U8(0)));
        // message_type = 1 (Heartbeat Request)
        assert_eq!(get_field(&buf, "message_type"), Some(&FieldValue::U8(1)));
        // Sequence Number = 0x42
        assert_eq!(
            get_field(&buf, "sequence_number"),
            Some(&FieldValue::U32(0x42))
        );
    }

    #[test]
    fn parse_pfcp_truncated() {
        let data = [0x21, 0x32, 0x00]; // Only 3 bytes
        let dissector = PfcpDissector;
        let mut buf = DissectBuffer::new();

        let result = dissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_pfcp_truncated_with_seid() {
        // S=1 header but only 10 bytes (need 16)
        let data = [0x21, 0x32, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let dissector = PfcpDissector;
        let mut buf = DissectBuffer::new();

        let result = dissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_pfcp_invalid_version() {
        // version=2 instead of 1
        let data = [0x41, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
        let dissector = PfcpDissector;
        let mut buf = DissectBuffer::new();

        let result = dissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_pfcp_with_ies() {
        // Recovery Time Stamp IE: type=96, length=4, value=0x12345678
        let recovery_ie = [0x00, 0x60, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78];
        let data = make_pfcp_without_seid(5, 0x000001, &recovery_ie);
        let (result, buf) = dissect_ok(&data);
        assert_eq!(result.bytes_consumed, 8 + recovery_ie.len());

        let layer = &buf.layers()[0];
        // Check IEs field exists
        let ies_field = buf.field_by_name(layer, "ies");
        assert!(ies_field.is_some());
    }

    #[test]
    fn parse_pfcp_heartbeat_request() {
        // Heartbeat Request has no SEID (S=0), type=1
        let recovery_ie = [0x00, 0x60, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0A];
        let data = make_pfcp_without_seid(1, 0x000001, &recovery_ie);
        let (result, buf) = dissect_ok(&data);
        assert_eq!(result.bytes_consumed, 8 + recovery_ie.len());

        assert_eq!(get_field(&buf, "message_type"), Some(&FieldValue::U8(1)));
        let layer = buf.layers().first().unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("Heartbeat Request")
        );
    }

    #[test]
    fn parse_pfcp_with_message_priority() {
        // S=1, MP=1: version=1, FO=0, MP=1, S=1 → 0x23
        let msg_length = 12u16; // SEID(8) + Seq(3) + MP/Spare(1)
        let mut data = vec![0x23]; // version=1, FO=0, MP=1, S=1
        data.push(50); // Session Establishment Request
        data.extend_from_slice(&msg_length.to_be_bytes());
        data.extend_from_slice(&0x0000000000000001u64.to_be_bytes()); // SEID
        data.push(0x00); // seq byte 1
        data.push(0x00); // seq byte 2
        data.push(0x01); // seq byte 3
        data.push(0xA0); // Message Priority = 0xA (upper nibble)

        let (result, buf) = dissect_ok(&data);
        assert_eq!(result.bytes_consumed, 16);

        // MP flag = 1
        assert_eq!(get_field(&buf, "mp_flag"), Some(&FieldValue::U8(1)));
        // Message Priority = 0xA
        assert_eq!(
            get_field(&buf, "message_priority"),
            Some(&FieldValue::U8(0x0A))
        );
    }

    #[test]
    fn parse_pfcp_with_fo_flag() {
        // FO=1: version=1, FO=1, MP=0, S=0 → 0x24
        let data = [0x24, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
        let (result, buf) = dissect_ok(&data);
        assert_eq!(result.bytes_consumed, 8);

        // FO flag = 1
        assert_eq!(get_field(&buf, "fo_flag"), Some(&FieldValue::U8(1)));
    }

    #[test]
    fn parse_pfcp_length_too_short() {
        // S=1 but msg_length=2 (less than min header minus 4)
        let data = [0x21, 0x32, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00];
        let dissector = PfcpDissector;
        let mut buf = DissectBuffer::new();

        let result = dissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_pfcp_length_exceeds_data() {
        // msg_length=100 but we only have 8 bytes of data
        let data = [0x20, 0x01, 0x00, 0x64, 0x00, 0x00, 0x01, 0x00];
        let dissector = PfcpDissector;
        let mut buf = DissectBuffer::new();

        let result = dissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_pfcp_dispatch_hint_end() {
        let data = make_pfcp_without_seid(1, 0x000001, &[]);
        let (result, _buf) = dissect_ok(&data);
        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn parse_pfcp_with_nonzero_offset() {
        let data = make_pfcp_without_seid(1, 0x000001, &[]);
        let dissector = PfcpDissector;
        let mut buf = DissectBuffer::new();
        let base_offset = 42;

        let result = dissector.dissect(&data, &mut buf, base_offset).unwrap();
        assert_eq!(result.bytes_consumed, 8);

        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 42..50);
    }

    #[test]
    fn parse_pfcp_field_descriptors() {
        let dissector = PfcpDissector;
        let descs = dissector.field_descriptors();
        assert_eq!(descs.len(), 10);
        assert_eq!(descs[FD_VERSION].name, "version");
        assert_eq!(descs[FD_S_FLAG].name, "s_flag");
        assert_eq!(descs[FD_MP_FLAG].name, "mp_flag");
        assert_eq!(descs[FD_FO_FLAG].name, "fo_flag");
        assert_eq!(descs[FD_MESSAGE_TYPE].name, "message_type");
        assert_eq!(descs[FD_LENGTH].name, "length");
        assert_eq!(descs[FD_SEID].name, "seid");
        assert_eq!(descs[FD_SEQUENCE_NUMBER].name, "sequence_number");
        assert_eq!(descs[FD_MESSAGE_PRIORITY].name, "message_priority");
        assert_eq!(descs[FD_IES].name, "ies");
    }

    #[test]
    fn parse_pfcp_name_and_short_name() {
        let dissector = PfcpDissector;
        assert_eq!(dissector.name(), "Packet Forwarding Control Protocol");
        assert_eq!(dissector.short_name(), "PFCP");
    }
}
