//! SCTP (Stream Control Transmission Protocol) dissector.
//!
//! Parses the SCTP common header (12 bytes) and individual chunks.
//! Each chunk is represented as a sub-layer with its type, flags, and value.
//!
//! ## References
//! - RFC 9260: <https://www.rfc-editor.org/rfc/rfc9260>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Minimum SCTP common header size (always 12 bytes).
/// RFC 9260, Section 3 — SCTP Packet Format.
const COMMON_HEADER_SIZE: usize = 12;

/// Minimum chunk header size (type + flags + length = 4 bytes).
/// RFC 9260, Section 3.2 — Chunk Field Descriptions.
const MIN_CHUNK_SIZE: usize = 4;

/// DATA chunk type identifier.
/// RFC 9260, Section 3.3.1 — Payload Data (DATA) (0).
const CHUNK_TYPE_DATA: u8 = 0;

/// DATA chunk header size: Type(1) + Flags(1) + Length(2) + TSN(4) +
/// Stream Identifier(2) + Stream Sequence Number(2) + Payload Protocol Identifier(4) = 16 bytes.
/// RFC 9260, Section 3.3.1.
const DATA_CHUNK_HEADER_SIZE: usize = 16;

/// Returns a human-readable name for SCTP chunk type values.
///
/// RFC 9260, Section 3.2 — Chunk Types.
fn sctp_chunk_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("DATA"),
        1 => Some("INIT"),
        2 => Some("INIT_ACK"),
        3 => Some("SACK"),
        4 => Some("HEARTBEAT"),
        5 => Some("HEARTBEAT_ACK"),
        6 => Some("ABORT"),
        7 => Some("SHUTDOWN"),
        8 => Some("SHUTDOWN_ACK"),
        9 => Some("ERROR"),
        10 => Some("COOKIE_ECHO"),
        11 => Some("COOKIE_ACK"),
        14 => Some("SHUTDOWN_COMPLETE"),
        _ => None,
    }
}

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_SRC_PORT: usize = 0;
const FD_DST_PORT: usize = 1;
const FD_VERIFICATION_TAG: usize = 2;
const FD_CHECKSUM: usize = 3;
const FD_CHUNKS: usize = 4;

/// Child field descriptor indices for [`CHUNK_CHILD_FIELDS`].
const CFD_TYPE: usize = 0;
const CFD_FLAGS: usize = 1;
const CFD_LENGTH: usize = 2;
const CFD_VALUE: usize = 3;

/// Child field descriptors for SCTP chunk entries within the `chunks` array.
static CHUNK_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Chunk Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => sctp_chunk_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("flags", "Chunk Flags", FieldType::U8),
    FieldDescriptor::new("length", "Chunk Length", FieldType::U16),
    FieldDescriptor::new("value", "Chunk Value", FieldType::Bytes).optional(),
];

/// Common header fields plus a `chunks` Array field whose child descriptors
/// describe each chunk's sub-fields (type, flags, length, value).
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("src_port", "Source Port", FieldType::U16),
    FieldDescriptor::new("dst_port", "Destination Port", FieldType::U16),
    FieldDescriptor::new("verification_tag", "Verification Tag", FieldType::U32),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U32),
    FieldDescriptor::new("chunks", "Chunks", FieldType::Array)
        .optional()
        .with_children(CHUNK_CHILD_FIELDS),
];

/// SCTP dissector.
pub struct SctpDissector;

impl Dissector for SctpDissector {
    fn name(&self) -> &'static str {
        "Stream Control Transmission Protocol"
    }

    fn short_name(&self) -> &'static str {
        "SCTP"
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
        if data.len() < COMMON_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: COMMON_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 9260, Section 3 — SCTP Common Header
        let src_port = read_be_u16(data, 0)?;
        let dst_port = read_be_u16(data, 2)?;
        let verification_tag = read_be_u32(data, 4)?;
        let checksum = read_be_u32(data, 8)?;

        // RFC 9260, Section 3.1 — Port number 0 MUST NOT be used.
        if src_port == 0 {
            return Err(PacketError::InvalidFieldValue {
                field: "src_port",
                value: 0,
            });
        }
        if dst_port == 0 {
            return Err(PacketError::InvalidFieldValue {
                field: "dst_port",
                value: 0,
            });
        }

        let total_consumed = data.len();

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_consumed,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SRC_PORT],
            FieldValue::U16(src_port),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DST_PORT],
            FieldValue::U16(dst_port),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERIFICATION_TAG],
            FieldValue::U32(verification_tag),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM],
            FieldValue::U32(checksum),
            offset + 8..offset + 12,
        );

        // RFC 9260, Section 3.2 — Parse chunks
        let mut pos = COMMON_HEADER_SIZE;
        let mut has_chunks = false;
        let mut array_idx = 0u32;
        // Track the first DATA chunk's user data range for upper-layer dispatch.
        let mut first_data_payload: Option<core::ops::Range<usize>> = None;

        while pos + MIN_CHUNK_SIZE <= data.len() {
            let chunk_type = data[pos];
            let chunk_flags = data[pos + 1];
            // RFC 9260, Section 3.2 — Chunk Length includes the 4-byte chunk header
            let chunk_length = read_be_u16(data, pos + 2)? as usize;

            if chunk_length < MIN_CHUNK_SIZE {
                return Err(PacketError::InvalidFieldValue {
                    field: "chunk_length",
                    value: chunk_length as u32,
                });
            }

            if pos + chunk_length > data.len() {
                return Err(PacketError::Truncated {
                    expected: pos + chunk_length,
                    actual: data.len(),
                });
            }

            if !has_chunks {
                has_chunks = true;
                array_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_CHUNKS],
                    FieldValue::Array(0..0),
                    offset + COMMON_HEADER_SIZE..offset + total_consumed,
                );
            }

            // RFC 9260, Section 3.3.1 — Track the first DATA chunk's user data
            // for embedded payload dispatch to upper-layer dissectors.
            if chunk_type == CHUNK_TYPE_DATA
                && first_data_payload.is_none()
                && chunk_length > DATA_CHUNK_HEADER_SIZE
            {
                let payload_start = offset + pos + DATA_CHUNK_HEADER_SIZE;
                let payload_end = offset + pos + chunk_length;
                first_data_payload = Some(payload_start..payload_end);
            }

            let obj_idx = buf.begin_container(
                &CHUNK_CHILD_FIELDS[CFD_TYPE],
                FieldValue::Object(0..0),
                offset + pos..offset + pos + chunk_length,
            );

            buf.push_field(
                &CHUNK_CHILD_FIELDS[CFD_TYPE],
                FieldValue::U8(chunk_type),
                offset + pos..offset + pos + 1,
            );
            buf.push_field(
                &CHUNK_CHILD_FIELDS[CFD_FLAGS],
                FieldValue::U8(chunk_flags),
                offset + pos + 1..offset + pos + 2,
            );
            buf.push_field(
                &CHUNK_CHILD_FIELDS[CFD_LENGTH],
                FieldValue::U16(chunk_length as u16),
                offset + pos + 2..offset + pos + 4,
            );
            if chunk_length > MIN_CHUNK_SIZE {
                buf.push_field(
                    &CHUNK_CHILD_FIELDS[CFD_VALUE],
                    FieldValue::Bytes(&data[pos + MIN_CHUNK_SIZE..pos + chunk_length]),
                    offset + pos + MIN_CHUNK_SIZE..offset + pos + chunk_length,
                );
            }

            buf.end_container(obj_idx);

            // RFC 9260, Section 3.2 — Chunks are padded to 4-byte boundaries.
            // The padding is NOT included in the Chunk Length field.
            let padded_length = (chunk_length + 3) & !3;
            pos += padded_length;
        }

        if has_chunks {
            buf.end_container(array_idx);
        }

        buf.end_layer();

        let hint = DispatchHint::BySctpPort(src_port, dst_port);
        if let Some(payload_range) = first_data_payload {
            Ok(DissectResult::with_embedded_payload(
                total_consumed,
                hint,
                payload_range,
            ))
        } else {
            Ok(DissectResult::new(total_consumed, hint))
        }
    }
}
