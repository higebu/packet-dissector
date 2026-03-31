//! IPv4 (Internet Protocol version 4) dissector.
//!
//! ## References
//! - RFC 791: <https://www.rfc-editor.org/rfc/rfc791>
//! - RFC 2474 (DSCP, updates RFC 791 ToS field): <https://www.rfc-editor.org/rfc/rfc2474>
//! - RFC 3168 (ECN): <https://www.rfc-editor.org/rfc/rfc3168>
//! - RFC 6864 (updates RFC 791 Identification field): <https://www.rfc-editor.org/rfc/rfc6864>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::lookup::ip_protocol_name;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

/// Minimum IPv4 header size (no options).
const MIN_HEADER_SIZE: usize = 20;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_VERSION: usize = 0;
const FD_IHL: usize = 1;
const FD_DSCP: usize = 2;
const FD_ECN: usize = 3;
const FD_TOTAL_LENGTH: usize = 4;
const FD_IDENTIFICATION: usize = 5;
const FD_FLAGS: usize = 6;
const FD_FRAGMENT_OFFSET: usize = 7;
const FD_TTL: usize = 8;
const FD_PROTOCOL: usize = 9;
const FD_CHECKSUM: usize = 10;
const FD_SRC: usize = 11;
const FD_DST: usize = 12;
const FD_OPTIONS: usize = 13;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("ihl", "Internet Header Length", FieldType::U8),
    FieldDescriptor::new("dscp", "Differentiated Services Code Point", FieldType::U8),
    FieldDescriptor::new("ecn", "Explicit Congestion Notification", FieldType::U8),
    FieldDescriptor::new("total_length", "Total Length", FieldType::U16),
    FieldDescriptor::new("identification", "Identification", FieldType::U16),
    FieldDescriptor::new("flags", "Flags", FieldType::U8),
    FieldDescriptor::new("fragment_offset", "Fragment Offset", FieldType::U16),
    FieldDescriptor::new("ttl", "Time to Live", FieldType::U8),
    FieldDescriptor {
        name: "protocol",
        display_name: "Protocol",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(p) => ip_protocol_name(*p),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("checksum", "Header Checksum", FieldType::U16),
    FieldDescriptor::new("src", "Source Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("dst", "Destination Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("options", "Options", FieldType::Bytes).optional(),
];

/// IPv4 dissector.
pub struct Ipv4Dissector;

impl Dissector for Ipv4Dissector {
    fn name(&self) -> &'static str {
        "Internet Protocol version 4"
    }

    fn short_name(&self) -> &'static str {
        "IPv4"
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
        if data.len() < MIN_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 791, Section 3.1 — Internet Header Format
        let version = (data[0] >> 4) & 0x0F;
        let ihl = (data[0] & 0x0F) as usize;

        // RFC 791, Section 3.1 — Version must be 4
        if version != 4 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: version as u32,
            });
        }

        // RFC 791, Section 3.1 — IHL must be at least 5
        if ihl < 5 {
            return Err(PacketError::InvalidFieldValue {
                field: "ihl",
                value: ihl as u32,
            });
        }

        let header_len = ihl * 4;
        if data.len() < header_len {
            return Err(PacketError::Truncated {
                expected: header_len,
                actual: data.len(),
            });
        }

        // RFC 791, Section 3.1 — Total Length must be >= header length
        let total_length = read_be_u16(data, 2)?;
        if (total_length as usize) < header_len {
            return Err(PacketError::InvalidFieldValue {
                field: "total_length",
                value: total_length as u32,
            });
        }

        // RFC 791, Section 3.1 — Data must be large enough for Total Length
        if data.len() < total_length as usize {
            return Err(PacketError::Truncated {
                expected: total_length as usize,
                actual: data.len(),
            });
        }

        // RFC 2474 — DSCP (6 bits) + RFC 3168 — ECN (2 bits)
        let dscp = data[1] >> 2;
        let ecn = data[1] & 0x03;

        let identification = read_be_u16(data, 4)?;

        // RFC 791, Section 3.1 — Flags (3 bits) and Fragment Offset (13 bits)
        let flags_frag = read_be_u16(data, 6)?;
        let flags = ((flags_frag >> 13) & 0x07) as u8;
        let fragment_offset = flags_frag & 0x1FFF;

        let ttl = data[8];
        let protocol = data[9];
        let checksum = read_be_u16(data, 10)?;
        let src = [data[12], data[13], data[14], data[15]];
        let dst = [data[16], data[17], data[18], data[19]];

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + header_len,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_IHL],
            FieldValue::U8(ihl as u8),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DSCP],
            FieldValue::U8(dscp),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ECN],
            FieldValue::U8(ecn),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TOTAL_LENGTH],
            FieldValue::U16(total_length),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_IDENTIFICATION],
            FieldValue::U16(identification),
            offset + 4..offset + 6,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAGS],
            FieldValue::U8(flags),
            offset + 6..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FRAGMENT_OFFSET],
            FieldValue::U16(fragment_offset),
            offset + 6..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TTL],
            FieldValue::U8(ttl),
            offset + 8..offset + 9,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PROTOCOL],
            FieldValue::U8(protocol),
            offset + 9..offset + 10,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM],
            FieldValue::U16(checksum),
            offset + 10..offset + 12,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SRC],
            FieldValue::Ipv4Addr(src),
            offset + 12..offset + 16,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DST],
            FieldValue::Ipv4Addr(dst),
            offset + 16..offset + 20,
        );

        // RFC 791, Section 3.1 — Options (variable length, if IHL > 5)
        if header_len > MIN_HEADER_SIZE {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_OPTIONS],
                FieldValue::Bytes(&data[MIN_HEADER_SIZE..header_len]),
                offset + MIN_HEADER_SIZE..offset + header_len,
            );
        }

        buf.end_layer();

        Ok(DissectResult::new(
            header_len,
            DispatchHint::ByIpProtocol(protocol),
        ))
    }
}
