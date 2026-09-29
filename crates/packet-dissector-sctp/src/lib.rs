//! SCTP (Stream Control Transmission Protocol) dissector.
//!
//! Parses the SCTP common header (12 bytes) and individual chunks.
//! Each chunk is represented as an object with its type, flags, and value;
//! DATA chunks are decoded into their header fields and user data.
//!
//! The user data of every unfragmented DATA chunk in the packet is recorded
//! with [`DissectBuffer::push_embedded_payload`], so bundled user messages
//! (RFC 9260, Section 6.10) are each dispatched to the upper layer. Fragments
//! of a user message (B and E bits not both set, Section 6.9) are shown but
//! not dispatched.
//!
//! ## References
//! - RFC 9260: <https://www.rfc-editor.org/rfc/rfc9260>
//!   - Section 3.3.1 (DATA): <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1>
//!   - Section 6.9 (Fragmentation and Reassembly): <https://www.rfc-editor.org/rfc/rfc9260#section-6.9>
//!   - Section 6.10 (Bundling): <https://www.rfc-editor.org/rfc/rfc9260#section-6.10>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
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

/// DATA chunk flag bits.
/// RFC 9260, Section 3.3.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1>
/// `|  Res  |I|U|B|E|`
const DATA_FLAG_I: u8 = 0x08;
const DATA_FLAG_U: u8 = 0x04;
const DATA_FLAG_B: u8 = 0x02;
const DATA_FLAG_E: u8 = 0x01;

/// Returns a human-readable name for SCTP chunk type values.
///
/// RFC 9260, Section 3.2 — Chunk Types table.
/// Types 12 (ECNE) and 13 (CWR) are listed as "Reserved for Explicit
/// Congestion Notification Echo" and "Reserved for Congestion Window
/// Reduced" in the same table.
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
        12 => Some("ECNE"),
        13 => Some("CWR"),
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
const CFD_I: usize = 4;
const CFD_U: usize = 5;
const CFD_B: usize = 6;
const CFD_E: usize = 7;
const CFD_TSN: usize = 8;
const CFD_STREAM_ID: usize = 9;
const CFD_SSN: usize = 10;
const CFD_PPID: usize = 11;
const CFD_USER_DATA: usize = 12;

/// Container descriptor for a chunk Object.
///
/// The outer label resolves to the chunk name (e.g. `INIT`) by looking up
/// the inner `type` field, avoiding collision with the inner "Chunk Type"
/// label.
static FD_CHUNK: FieldDescriptor = FieldDescriptor {
    name: "chunk",
    display_name: "Chunk",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => sctp_chunk_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

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
    // RFC 9260, Section 3.3.1 — DATA chunk fields — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1
    FieldDescriptor::new("i", "I (Immediate)", FieldType::U8).optional(),
    FieldDescriptor::new("u", "U (Unordered)", FieldType::U8).optional(),
    FieldDescriptor::new("b", "B (Beginning Fragment)", FieldType::U8).optional(),
    FieldDescriptor::new("e", "E (Ending Fragment)", FieldType::U8).optional(),
    FieldDescriptor::new("tsn", "TSN", FieldType::U32).optional(),
    FieldDescriptor::new("stream_id", "Stream Identifier", FieldType::U16).optional(),
    FieldDescriptor::new("ssn", "Stream Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("ppid", "Payload Protocol Identifier", FieldType::U32).optional(),
    FieldDescriptor::new("user_data", "User Data", FieldType::Bytes).optional(),
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

/// Specification references for the SCTP dissector.
static REFERENCES: &[SpecReference] = &[SpecReference::new(
    "RFC 9260",
    "Stream Control Transmission Protocol",
    "https://www.rfc-editor.org/rfc/rfc9260",
)];

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

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Transport)
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

        // RFC 9260, Section 3.1 — SCTP Common Header Field Descriptions
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
        let hint = DispatchHint::BySctpPort(src_port, dst_port);

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

            let obj_idx = buf.begin_container(
                &FD_CHUNK,
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
            if chunk_type == CHUNK_TYPE_DATA && chunk_length >= DATA_CHUNK_HEADER_SIZE {
                push_data_chunk_fields(buf, &data[pos..pos + chunk_length], offset + pos, &hint)?;
            } else if chunk_length > MIN_CHUNK_SIZE {
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

        Ok(DissectResult::new(total_consumed, hint))
    }
}

/// Push the fields of a DATA chunk and record its user data for dispatch.
///
/// `chunk` spans the chunk from its Type byte to the end of User Data
/// (excluding padding) and is at least [`DATA_CHUNK_HEADER_SIZE`] bytes long;
/// `abs` is its absolute offset in the packet. Type, Flags and Length have
/// already been pushed.
///
/// RFC 9260, Section 3.3.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1>
fn push_data_chunk_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    chunk: &'pkt [u8],
    abs: usize,
    hint: &DispatchHint,
) -> Result<(), PacketError> {
    let flags = chunk[1];
    let tsn = read_be_u32(chunk, 4)?;
    let stream_id = read_be_u16(chunk, 8)?;
    let ssn = read_be_u16(chunk, 10)?;
    let ppid = read_be_u32(chunk, 12)?;
    let user_data = &chunk[DATA_CHUNK_HEADER_SIZE..];

    let flags_range = abs + 1..abs + 2;
    for (fd, mask) in [
        (CFD_I, DATA_FLAG_I),
        (CFD_U, DATA_FLAG_U),
        (CFD_B, DATA_FLAG_B),
        (CFD_E, DATA_FLAG_E),
    ] {
        buf.push_field(
            &CHUNK_CHILD_FIELDS[fd],
            FieldValue::U8(u8::from(flags & mask != 0)),
            flags_range.clone(),
        );
    }
    buf.push_field(
        &CHUNK_CHILD_FIELDS[CFD_TSN],
        FieldValue::U32(tsn),
        abs + 4..abs + 8,
    );
    buf.push_field(
        &CHUNK_CHILD_FIELDS[CFD_STREAM_ID],
        FieldValue::U16(stream_id),
        abs + 8..abs + 10,
    );
    buf.push_field(
        &CHUNK_CHILD_FIELDS[CFD_SSN],
        FieldValue::U16(ssn),
        abs + 10..abs + 12,
    );
    buf.push_field(
        &CHUNK_CHILD_FIELDS[CFD_PPID],
        FieldValue::U32(ppid),
        abs + 12..abs + 16,
    );

    // RFC 9260, Section 3.3.1 — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1
    // "L MUST be greater than 0". An empty User Data field is shown by its
    // absence and is not dispatched.
    if user_data.is_empty() {
        return Ok(());
    }
    let user_data_range = abs + DATA_CHUNK_HEADER_SIZE..abs + chunk.len();
    buf.push_field(
        &CHUNK_CHILD_FIELDS[CFD_USER_DATA],
        FieldValue::Bytes(user_data),
        user_data_range.clone(),
    );

    // RFC 9260, Section 3.3.1 — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1
    // "An unfragmented user message MUST have both the B and E bits set to
    // 1." Any other combination is one fragment of a user message that is
    // only complete after reassembly (Section 6.9 —
    // https://www.rfc-editor.org/rfc/rfc9260#section-6.9), so it is not
    // handed to the upper layer on its own.
    let unfragmented = DATA_FLAG_B | DATA_FLAG_E;
    if flags & unfragmented == unfragmented {
        buf.push_embedded_payload(user_data_range, hint.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::packet::Layer;

    // # RFC 9260 Coverage
    //
    // | RFC Section | Description                                    | Test                                  |
    // |-------------|------------------------------------------------|---------------------------------------|
    // | 3.1         | Common header fields parsed                    | parse_common_header                   |
    // | 3.1         | Source port 0 rejected                         | reject_source_port_zero               |
    // | 3.1         | Destination port 0 rejected                    | reject_destination_port_zero          |
    // | 3.1         | Truncated common header (< 12 bytes)           | truncated_common_header               |
    // | 3.2         | Chunk types 0..=14 name resolution             | chunk_type_names                      |
    // | 3.2         | Unassigned / reserved chunk types return None  | chunk_type_names                      |
    // | 3.2         | Generic chunk (type/flags/length/value)        | parse_init_chunk                      |
    // | 3.2         | Chunk padded to 4-byte boundary                | chunk_padding_not_counted_in_length   |
    // | 3.2         | chunk_length < 4 rejected                      | invalid_chunk_length_below_minimum    |
    // | 3.2         | Truncated chunk (pos + length > data)          | truncated_chunk_value                 |
    // | 3.2         | Multiple chunks in one packet                  | multiple_chunks                       |
    // | 3.3.1       | DATA chunk user data recorded as payload       | parse_data_chunk_embedded_payload     |
    // | 3.3.1       | DATA chunk header fields and I/U/B/E bits      | parse_data_chunk_fields               |
    // | 3.3.1       | DATA chunk with L == 0 does not dispatch       | empty_data_chunk_no_dispatch          |
    // | 3.3.1       | DATA chunk shorter than its header             | short_data_chunk_generic_value        |
    // | 3.3.1, 6.9  | Fragments (B/E not both set) not dispatched    | fragmented_data_chunks_not_dispatched |
    // | 6.10        | Every bundled DATA chunk recorded as payload   | bundled_data_chunks_each_dispatched   |
    // | ---         | No chunks => no `chunks` array field           | common_header_only_no_chunks_field    |
    // | ---         | Offset handling in byte ranges                 | dissect_with_offset                   |
    // | ---         | Field descriptors                              | field_descriptors_list                |

    fn build_common_header(src_port: u16, dst_port: u16, vt: u32, checksum: u32) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(COMMON_HEADER_SIZE);
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&vt.to_be_bytes());
        pkt.extend_from_slice(&checksum.to_be_bytes());
        pkt
    }

    /// Append a generic chunk (type/flags/length/value), 4-byte padded.
    fn push_chunk(pkt: &mut Vec<u8>, ctype: u8, flags: u8, value: &[u8]) {
        let chunk_len = MIN_CHUNK_SIZE + value.len();
        pkt.push(ctype);
        pkt.push(flags);
        pkt.extend_from_slice(&(chunk_len as u16).to_be_bytes());
        pkt.extend_from_slice(value);
        while pkt.len() % 4 != 0 {
            pkt.push(0);
        }
    }

    /// Append a DATA chunk per RFC 9260, Section 3.3.1.
    fn push_data_chunk(
        pkt: &mut Vec<u8>,
        flags: u8,
        tsn: u32,
        sid: u16,
        ssn: u16,
        ppi: u32,
        user_data: &[u8],
    ) {
        let chunk_len = DATA_CHUNK_HEADER_SIZE + user_data.len();
        pkt.push(CHUNK_TYPE_DATA);
        pkt.push(flags);
        pkt.extend_from_slice(&(chunk_len as u16).to_be_bytes());
        pkt.extend_from_slice(&tsn.to_be_bytes());
        pkt.extend_from_slice(&sid.to_be_bytes());
        pkt.extend_from_slice(&ssn.to_be_bytes());
        pkt.extend_from_slice(&ppi.to_be_bytes());
        pkt.extend_from_slice(user_data);
        while pkt.len() % 4 != 0 {
            pkt.push(0);
        }
    }

    #[test]
    fn parse_common_header() {
        // RFC 9260, Section 3.1 — Common Header Field Descriptions.
        let data = build_common_header(36412, 3868, 0xAABB_CCDD, 0x1234_5678);
        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, COMMON_HEADER_SIZE);
        assert_eq!(result.next, DispatchHint::BySctpPort(36412, 3868));
        assert!(result.embedded_payload.is_none());

        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "SCTP");
        assert_eq!(layer.range, 0..COMMON_HEADER_SIZE);

        assert_eq!(
            buf.field_by_name(layer, "src_port").unwrap().value,
            FieldValue::U16(36412)
        );
        assert_eq!(
            buf.field_by_name(layer, "dst_port").unwrap().value,
            FieldValue::U16(3868)
        );
        assert_eq!(
            buf.field_by_name(layer, "verification_tag").unwrap().value,
            FieldValue::U32(0xAABB_CCDD)
        );
        assert_eq!(
            buf.field_by_name(layer, "checksum").unwrap().value,
            FieldValue::U32(0x1234_5678)
        );
    }

    #[test]
    fn reject_source_port_zero() {
        // RFC 9260, Section 3.1 — "The Source Port Number 0 MUST NOT be used."
        let data = build_common_header(0, 3868, 0, 0);
        let mut buf = DissectBuffer::new();
        let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::InvalidFieldValue { field, value } => {
                assert_eq!(field, "src_port");
                assert_eq!(value, 0);
            }
            other => panic!("expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn reject_destination_port_zero() {
        // RFC 9260, Section 3.1 — "The Destination Port Number 0 MUST NOT be used."
        let data = build_common_header(3868, 0, 0, 0);
        let mut buf = DissectBuffer::new();
        let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::InvalidFieldValue { field, value } => {
                assert_eq!(field, "dst_port");
                assert_eq!(value, 0);
            }
            other => panic!("expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn truncated_common_header() {
        let data = [0u8; COMMON_HEADER_SIZE - 1];
        let mut buf = DissectBuffer::new();
        let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, COMMON_HEADER_SIZE);
                assert_eq!(actual, data.len());
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn chunk_type_names() {
        // RFC 9260, Section 3.2 — Chunk Types table (values 0..=14).
        let table = [
            (0u8, "DATA"),
            (1, "INIT"),
            (2, "INIT_ACK"),
            (3, "SACK"),
            (4, "HEARTBEAT"),
            (5, "HEARTBEAT_ACK"),
            (6, "ABORT"),
            (7, "SHUTDOWN"),
            (8, "SHUTDOWN_ACK"),
            (9, "ERROR"),
            (10, "COOKIE_ECHO"),
            (11, "COOKIE_ACK"),
            (12, "ECNE"),
            (13, "CWR"),
            (14, "SHUTDOWN_COMPLETE"),
        ];
        for (v, expected) in table {
            assert_eq!(sctp_chunk_type_name(v), Some(expected), "chunk type {v}");
        }
        // Unassigned / reserved values return None.
        assert_eq!(sctp_chunk_type_name(15), None);
        assert_eq!(sctp_chunk_type_name(63), None); // Reserved for IETF extensions
        assert_eq!(sctp_chunk_type_name(255), None);
    }

    /// Count top-level chunk Objects inside the `chunks` Array container.
    fn count_chunk_objects(buf: &DissectBuffer<'_>, layer: &Layer) -> usize {
        let chunks = buf.field_by_name(layer, "chunks").expect("chunks present");
        let range = match &chunks.value {
            FieldValue::Array(r) => r.clone(),
            other => panic!("expected Array, got {other:?}"),
        };
        let mut idx = range.start;
        let mut count = 0usize;
        while idx < range.end {
            let field = &buf.fields()[idx as usize];
            match &field.value {
                FieldValue::Object(inner) => {
                    count += 1;
                    // Skip over this object's children; they are laid out
                    // contiguously after the placeholder.
                    idx = inner.end;
                }
                _ => idx += 1,
            }
        }
        count
    }

    #[test]
    fn parse_init_chunk() {
        // INIT chunk (type=1) with minimal 16-byte fixed parameter body.
        let mut data = build_common_header(12345, 3868, 0, 0);
        let body = [0u8; 16];
        push_chunk(&mut data, 1, 0, &body);
        let total_len = data.len();

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, total_len);
        assert!(result.embedded_payload.is_none());

        let layer = &buf.layers()[0];
        assert_eq!(count_chunk_objects(&buf, layer), 1);
    }

    #[test]
    fn parse_data_chunk_embedded_payload() {
        // RFC 9260, Section 3.3.1 — DATA chunk User Data follows 16-byte header.
        let payload = b"ngap-payload";
        let mut data = build_common_header(36412, 36412, 0, 0);
        push_data_chunk(&mut data, 0x03, 1, 0, 0, 60, payload);

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(result.next, DispatchHint::BySctpPort(36412, 36412));
        assert!(result.embedded_payload.is_none());

        let payloads = buf.embedded_payloads();
        assert_eq!(payloads.len(), 1);
        let range = payloads[0].range.clone();
        assert_eq!(range.start, COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE);
        assert_eq!(range.end - range.start, payload.len());
        assert_eq!(&data[range], payload);
        assert_eq!(payloads[0].next, DispatchHint::BySctpPort(36412, 36412));
    }

    /// Return the direct children of the `index`-th chunk Object.
    fn chunk_children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        layer: &Layer,
        index: usize,
    ) -> &'a [packet_dissector_core::field::Field<'pkt>] {
        let chunks = buf.field_by_name(layer, "chunks").expect("chunks present");
        let FieldValue::Array(ref range) = chunks.value else {
            panic!("expected Array, got {:?}", chunks.value);
        };
        let mut idx = range.start;
        let mut seen = 0usize;
        while idx < range.end {
            let field = &buf.fields()[idx as usize];
            if let FieldValue::Object(ref inner) = field.value {
                if seen == index {
                    return buf.nested_fields(inner);
                }
                seen += 1;
                idx = inner.end;
            } else {
                idx += 1;
            }
        }
        panic!("chunk {index} not found");
    }

    fn child<'a, 'pkt>(
        fields: &'a [packet_dissector_core::field::Field<'pkt>],
        name: &str,
    ) -> Option<&'a FieldValue<'pkt>> {
        fields.iter().find(|f| f.name() == name).map(|f| &f.value)
    }

    #[test]
    fn parse_data_chunk_fields() {
        // RFC 9260, Section 3.3.1 — Type = 0 | Res | I | U | B | E | Length,
        // TSN, Stream Identifier S, Stream Sequence Number n, Payload
        // Protocol Identifier, User Data.
        let mut data = build_common_header(40000, 40001, 1, 0);
        // I=1, U=1, B=1, E=1 plus reserved bits set (ignored on receipt).
        push_data_chunk(&mut data, 0xFF, 0xDEAD_BEEF, 7, 9, 46, b"abcde");

        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let c = chunk_children(&buf, layer, 0);

        assert_eq!(child(c, "type"), Some(&FieldValue::U8(0)));
        assert_eq!(child(c, "flags"), Some(&FieldValue::U8(0xFF)));
        assert_eq!(child(c, "i"), Some(&FieldValue::U8(1)));
        assert_eq!(child(c, "u"), Some(&FieldValue::U8(1)));
        assert_eq!(child(c, "b"), Some(&FieldValue::U8(1)));
        assert_eq!(child(c, "e"), Some(&FieldValue::U8(1)));
        assert_eq!(child(c, "length"), Some(&FieldValue::U16(21)));
        assert_eq!(child(c, "tsn"), Some(&FieldValue::U32(0xDEAD_BEEF)));
        assert_eq!(child(c, "stream_id"), Some(&FieldValue::U16(7)));
        assert_eq!(child(c, "ssn"), Some(&FieldValue::U16(9)));
        assert_eq!(child(c, "ppid"), Some(&FieldValue::U32(46)));
        assert_eq!(
            child(c, "user_data"),
            Some(&FieldValue::Bytes(b"abcde".as_slice()))
        );
        // The decoded DATA chunk has no generic `value` field.
        assert_eq!(child(c, "value"), None);

        let tsn = c.iter().find(|f| f.name() == "tsn").unwrap();
        assert_eq!(tsn.range, 16..20);
        let user_data = c.iter().find(|f| f.name() == "user_data").unwrap();
        assert_eq!(user_data.range, 28..33);

        // B = 0, E = 0, U = 0, I = 0 (middle fragment of an ordered message).
        let mut data = build_common_header(40000, 40001, 1, 0);
        push_data_chunk(&mut data, 0x00, 1, 0, 0, 0, b"x");
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let c = chunk_children(&buf, layer, 0);
        for bit in ["i", "u", "b", "e"] {
            assert_eq!(child(c, bit), Some(&FieldValue::U8(0)), "bit {bit}");
        }
    }

    #[test]
    fn bundled_data_chunks_each_dispatched() {
        // RFC 9260, Section 6.10 — multiple DATA chunks bundled into one
        // SCTP packet each carry a complete user message.
        let mut data = build_common_header(49152, 3868, 1, 0);
        push_data_chunk(&mut data, 0x03, 1, 0, 0, 46, b"first");
        let second_chunk = data.len();
        push_data_chunk(&mut data, 0x03, 2, 0, 1, 46, b"second!!");

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        assert!(result.embedded_payload.is_none());

        let payloads = buf.embedded_payloads();
        assert_eq!(payloads.len(), 2);
        assert_eq!(&data[payloads[0].range.clone()], b"first");
        assert_eq!(&data[payloads[1].range.clone()], b"second!!");
        assert_eq!(
            payloads[1].range.start,
            second_chunk + DATA_CHUNK_HEADER_SIZE
        );
        for p in payloads {
            assert_eq!(p.next, DispatchHint::BySctpPort(49152, 3868));
        }
    }

    #[test]
    fn fragmented_data_chunks_not_dispatched() {
        // RFC 9260, Section 3.3.1 — "An unfragmented user message MUST have
        // both the B and E bits set to 1." First (B=1, E=0), middle (B=0,
        // E=0) and last (B=0, E=1) fragments carry only part of a user
        // message (Section 6.9) and must not reach the upper layer.
        let mut data = build_common_header(49152, 3868, 1, 0);
        push_data_chunk(&mut data, 0x02, 1, 0, 0, 46, b"first-fragment");
        push_data_chunk(&mut data, 0x00, 2, 0, 0, 46, b"middle");
        push_data_chunk(&mut data, 0x01, 3, 0, 0, 46, b"last");
        push_data_chunk(&mut data, 0x03, 4, 1, 0, 46, b"whole");

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());

        let payloads = buf.embedded_payloads();
        assert_eq!(payloads.len(), 1, "only the unfragmented chunk");
        assert_eq!(&data[payloads[0].range.clone()], b"whole");

        let layer = &buf.layers()[0];
        assert_eq!(count_chunk_objects(&buf, layer), 4);
        let first = chunk_children(&buf, layer, 0);
        assert_eq!(child(first, "b"), Some(&FieldValue::U8(1)));
        assert_eq!(child(first, "e"), Some(&FieldValue::U8(0)));
        assert_eq!(
            child(first, "user_data"),
            Some(&FieldValue::Bytes(b"first-fragment".as_slice()))
        );
    }

    #[test]
    fn short_data_chunk_generic_value() {
        // A DATA chunk whose Length is below the 16-byte DATA header cannot
        // hold TSN/SID/SSN/PPID; show its body as raw bytes and do not
        // dispatch it (Postel's Law).
        let mut data = build_common_header(49152, 3868, 1, 0);
        push_chunk(&mut data, CHUNK_TYPE_DATA, 0x03, &[0xAA; 8]);

        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(buf.embedded_payloads().is_empty());

        let layer = &buf.layers()[0];
        let c = chunk_children(&buf, layer, 0);
        assert_eq!(
            child(c, "value"),
            Some(&FieldValue::Bytes([0xAA; 8].as_slice()))
        );
        assert_eq!(child(c, "tsn"), None);
    }

    #[test]
    fn chunk_padding_not_counted_in_length() {
        // RFC 9260, Section 3.2 — Chunks are padded to a 4-byte boundary and
        // the padding is NOT included in the Chunk Length field. A chunk with
        // a 1-byte value has Length = 5 and consumes 8 bytes including pad.
        let mut data = build_common_header(12345, 3868, 0, 0);
        push_chunk(&mut data, 9, 0, &[0xAB]); // ERROR chunk, Length=5, 3 bytes padding
        assert_eq!(data.len(), COMMON_HEADER_SIZE + 8);

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());

        // The chunk_length field stores the RFC "Length" (not the padded size).
        let layer = &buf.layers()[0];
        let chunks_field = buf.field_by_name(layer, "chunks").unwrap();
        let children = match &chunks_field.value {
            FieldValue::Array(r) => r.clone(),
            other => panic!("expected Array, got {other:?}"),
        };
        // First child is the chunk object; find its "length" within.
        let chunk_obj = &buf.fields()[children.start as usize];
        let chunk_children = match &chunk_obj.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let length_field = buf
            .fields()
            .get(chunk_children.start as usize..chunk_children.end as usize)
            .unwrap()
            .iter()
            .find(|f| f.name() == "length")
            .unwrap();
        assert_eq!(length_field.value, FieldValue::U16(5));
    }

    #[test]
    fn invalid_chunk_length_below_minimum() {
        let mut data = build_common_header(12345, 3868, 0, 0);
        // Chunk header with Length=3 (< MIN_CHUNK_SIZE).
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]);
        let mut buf = DissectBuffer::new();
        let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::InvalidFieldValue { field, value } => {
                assert_eq!(field, "chunk_length");
                assert_eq!(value, 3);
            }
            other => panic!("expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn truncated_chunk_value() {
        let mut data = build_common_header(12345, 3868, 0, 0);
        // Chunk claims Length=100 but only 4 header bytes follow.
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]);
        let expected = COMMON_HEADER_SIZE + 100;
        let actual_len = data.len();
        let mut buf = DissectBuffer::new();
        let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::Truncated {
                expected: e,
                actual: a,
            } => {
                assert_eq!(e, expected);
                assert_eq!(a, actual_len);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn multiple_chunks() {
        let mut data = build_common_header(12345, 3868, 0, 0);
        push_chunk(&mut data, 3, 0, &[0u8; 12]); // SACK
        push_data_chunk(&mut data, 0x03, 7, 0, 0, 60, b"X"); // DATA
        push_chunk(&mut data, 6, 0, &[]); // ABORT (Length=4, no value)

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());

        let payloads = buf.embedded_payloads();
        assert_eq!(payloads.len(), 1);
        assert_eq!(&data[payloads[0].range.clone()], b"X");

        let layer = &buf.layers()[0];
        assert_eq!(count_chunk_objects(&buf, layer), 3);
    }

    #[test]
    fn empty_data_chunk_no_dispatch() {
        // RFC 9260, Section 3.3.1 — "L MUST be greater than 0". A DATA chunk
        // with Length == 16 violates this, but we parse it and decline to
        // expose an embedded payload (Postel's Law).
        let mut data = build_common_header(12345, 3868, 0, 0);
        data.push(CHUNK_TYPE_DATA);
        data.push(0x03); // B|E: unfragmented, so only L == 0 blocks dispatch
        data.extend_from_slice(&(DATA_CHUNK_HEADER_SIZE as u16).to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes()); // TSN
        data.extend_from_slice(&0u16.to_be_bytes()); // SID
        data.extend_from_slice(&0u16.to_be_bytes()); // SSN
        data.extend_from_slice(&0u32.to_be_bytes()); // PPI

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(result.embedded_payload.is_none());
        assert!(buf.embedded_payloads().is_empty());
    }

    #[test]
    fn common_header_only_no_chunks_field() {
        let data = build_common_header(12345, 3868, 0, 0);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "chunks").is_none());
    }

    #[test]
    fn dissect_with_offset() {
        let data = build_common_header(12345, 3868, 0, 0);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 100).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 100..100 + COMMON_HEADER_SIZE);
    }

    #[test]
    fn field_descriptors_list() {
        let descs = SctpDissector.field_descriptors();
        assert_eq!(descs.len(), 5);
        assert_eq!(descs[FD_SRC_PORT].name, "src_port");
        assert_eq!(descs[FD_DST_PORT].name, "dst_port");
        assert_eq!(descs[FD_VERIFICATION_TAG].name, "verification_tag");
        assert_eq!(descs[FD_CHECKSUM].name, "checksum");
        assert_eq!(descs[FD_CHUNKS].name, "chunks");
    }

    #[test]
    fn chunk_container_resolves_to_chunk_name() {
        // Single INIT chunk so the container label resolves to "INIT"
        // instead of duplicating the inner "Chunk Type" label.
        let mut pkt = build_common_header(36412, 3868, 0xAABB_CCDD, 0x1234_5678);
        push_chunk(&mut pkt, 1, 0, &[0u8; 16]); // INIT
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let (idx, field) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "chunk")
            .expect("chunk container not found");
        assert!(matches!(field.value, FieldValue::Object(_)));
        assert_eq!(field.display_name(), "Chunk");
        assert_eq!(buf.resolve_container_display_name(idx as u32), Some("INIT"));
    }

    #[test]
    fn references_and_layer() {
        let references = SctpDissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(SctpDissector.layer(), Some(ProtocolLayer::Transport));
    }
}
