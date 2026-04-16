//! HTTP/2 dissector.
//!
//! Parses HTTP/2 frames as defined in RFC 9113. Handles the connection preface
//! (24-byte client magic) and all standard frame types. HPACK header blocks
//! are decoded using the static table and literal representations (RFC 7541).
//! Dynamic table references are reported as unresolved since the dissector is
//! stateless.
//!
//! ## References
//! - RFC 9113: HTTP/2 <https://www.rfc-editor.org/rfc/rfc9113>
//! - RFC 7541: HPACK <https://www.rfc-editor.org/rfc/rfc7541>

#![deny(missing_docs)]

mod hpack;

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24, read_be_u32};

/// HTTP/2 connection preface sent by the client.
/// RFC 9113, Section 3.4 — <https://www.rfc-editor.org/rfc/rfc9113#section-3.4>
const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Minimum frame size: 9-byte frame header.
/// RFC 9113, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc9113#section-4.1>
const FRAME_HEADER_LEN: usize = 9;

// ---------------------------------------------------------------------------
// Frame type constants
// RFC 9113, Section 6 — <https://www.rfc-editor.org/rfc/rfc9113#section-6>
// ---------------------------------------------------------------------------

/// DATA frame type.
const FRAME_TYPE_DATA: u8 = 0x00;
/// HEADERS frame type.
const FRAME_TYPE_HEADERS: u8 = 0x01;
/// PRIORITY frame type.
const FRAME_TYPE_PRIORITY: u8 = 0x02;
/// RST_STREAM frame type.
const FRAME_TYPE_RST_STREAM: u8 = 0x03;
/// SETTINGS frame type.
const FRAME_TYPE_SETTINGS: u8 = 0x04;
/// PUSH_PROMISE frame type.
const FRAME_TYPE_PUSH_PROMISE: u8 = 0x05;
/// PING frame type.
const FRAME_TYPE_PING: u8 = 0x06;
/// GOAWAY frame type.
const FRAME_TYPE_GOAWAY: u8 = 0x07;
/// WINDOW_UPDATE frame type.
const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x08;
/// CONTINUATION frame type.
const FRAME_TYPE_CONTINUATION: u8 = 0x09;

// ---------------------------------------------------------------------------
// Frame flag constants
// RFC 9113, Section 6 — <https://www.rfc-editor.org/rfc/rfc9113#section-6>
// ---------------------------------------------------------------------------

/// ACK flag (SETTINGS, PING).
const FLAG_ACK: u8 = 0x01;
/// PADDED flag (DATA, HEADERS, PUSH_PROMISE).
const FLAG_PADDED: u8 = 0x08;
/// PRIORITY flag (HEADERS).
const FLAG_PRIORITY: u8 = 0x20;

// ---------------------------------------------------------------------------
// Field descriptors
// ---------------------------------------------------------------------------

const FD_MAGIC: usize = 0;
const FD_FRAME_LENGTH: usize = 1;
const FD_FRAME_TYPE: usize = 2;
const FD_FLAGS: usize = 3;
const FD_STREAM_ID: usize = 4;
const FD_PAYLOAD: usize = 5;
const FD_SETTINGS: usize = 6;
const FD_ERROR_CODE: usize = 7;
const FD_LAST_STREAM_ID: usize = 8;
const FD_WINDOW_SIZE_INCREMENT: usize = 9;
const FD_PROMISED_STREAM_ID: usize = 10;
const FD_HEADER_BLOCK_FRAGMENT: usize = 11;
const FD_PADDING_LENGTH: usize = 12;
const FD_OPAQUE_DATA: usize = 13;
const FD_DEBUG_DATA: usize = 14;
const FD_PRIORITY_EXCLUSIVE: usize = 15;
const FD_PRIORITY_STREAM_DEPENDENCY: usize = 16;
const FD_PRIORITY_WEIGHT: usize = 17;
const FD_HEADERS: usize = 18;

const SC_ID: usize = 0;
const SC_VALUE: usize = 1;

const HC_NAME: usize = 0;
const HC_VALUE: usize = 1;

/// Child descriptors for decoded header name/value pairs.
static HEADER_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("name", "Name", FieldType::Str),
    FieldDescriptor::new("value", "Value", FieldType::Str),
];

/// Child descriptors for each SETTINGS parameter entry.
static SETTINGS_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("id", "Identifier", FieldType::U16).with_display_fn(settings_id_name),
    FieldDescriptor::new("value", "Value", FieldType::U32),
];

/// All field descriptors for the HTTP/2 dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("magic", "Connection Preface", FieldType::U8),
    FieldDescriptor::new("frame_length", "Length", FieldType::U32),
    FieldDescriptor::new("frame_type", "Type", FieldType::U8).with_display_fn(frame_type_name),
    FieldDescriptor::new("flags", "Flags", FieldType::U8),
    FieldDescriptor::new("stream_id", "Stream Identifier", FieldType::U32),
    FieldDescriptor::new("payload", "Payload", FieldType::Bytes).optional(),
    FieldDescriptor::new("settings", "Settings", FieldType::Array)
        .optional()
        .with_children(SETTINGS_CHILDREN),
    FieldDescriptor::new("error_code", "Error Code", FieldType::U32)
        .optional()
        .with_display_fn(error_code_name),
    FieldDescriptor::new("last_stream_id", "Last Stream ID", FieldType::U32).optional(),
    FieldDescriptor::new(
        "window_size_increment",
        "Window Size Increment",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("promised_stream_id", "Promised Stream ID", FieldType::U32).optional(),
    FieldDescriptor::new(
        "header_block_fragment",
        "Header Block Fragment",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("padding_length", "Padding Length", FieldType::U8).optional(),
    FieldDescriptor::new("opaque_data", "Opaque Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("debug_data", "Debug Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("priority_exclusive", "Exclusive", FieldType::U8).optional(),
    FieldDescriptor::new(
        "priority_stream_dependency",
        "Stream Dependency",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("priority_weight", "Weight", FieldType::U8).optional(),
    FieldDescriptor::new("headers", "Decoded Headers", FieldType::Array)
        .optional()
        .with_children(HEADER_CHILDREN),
];

// ---------------------------------------------------------------------------
// Display functions
// ---------------------------------------------------------------------------

fn frame_type_name(
    value: &FieldValue,
    _siblings: &[packet_dissector_core::field::Field],
) -> Option<&'static str> {
    match value {
        FieldValue::U8(0x00) => Some("DATA"),
        FieldValue::U8(0x01) => Some("HEADERS"),
        FieldValue::U8(0x02) => Some("PRIORITY"),
        FieldValue::U8(0x03) => Some("RST_STREAM"),
        FieldValue::U8(0x04) => Some("SETTINGS"),
        FieldValue::U8(0x05) => Some("PUSH_PROMISE"),
        FieldValue::U8(0x06) => Some("PING"),
        FieldValue::U8(0x07) => Some("GOAWAY"),
        FieldValue::U8(0x08) => Some("WINDOW_UPDATE"),
        FieldValue::U8(0x09) => Some("CONTINUATION"),
        _ => None,
    }
}

fn settings_id_name(
    value: &FieldValue,
    _siblings: &[packet_dissector_core::field::Field],
) -> Option<&'static str> {
    match value {
        FieldValue::U16(0x01) => Some("HEADER_TABLE_SIZE"),
        FieldValue::U16(0x02) => Some("ENABLE_PUSH"),
        FieldValue::U16(0x03) => Some("MAX_CONCURRENT_STREAMS"),
        FieldValue::U16(0x04) => Some("INITIAL_WINDOW_SIZE"),
        FieldValue::U16(0x05) => Some("MAX_FRAME_SIZE"),
        FieldValue::U16(0x06) => Some("MAX_HEADER_LIST_SIZE"),
        _ => None,
    }
}

fn error_code_name(
    value: &FieldValue,
    _siblings: &[packet_dissector_core::field::Field],
) -> Option<&'static str> {
    match value {
        FieldValue::U32(0x00) => Some("NO_ERROR"),
        FieldValue::U32(0x01) => Some("PROTOCOL_ERROR"),
        FieldValue::U32(0x02) => Some("INTERNAL_ERROR"),
        FieldValue::U32(0x03) => Some("FLOW_CONTROL_ERROR"),
        FieldValue::U32(0x04) => Some("SETTINGS_TIMEOUT"),
        FieldValue::U32(0x05) => Some("STREAM_CLOSED"),
        FieldValue::U32(0x06) => Some("FRAME_SIZE_ERROR"),
        FieldValue::U32(0x07) => Some("REFUSED_STREAM"),
        FieldValue::U32(0x08) => Some("CANCEL"),
        FieldValue::U32(0x09) => Some("COMPRESSION_ERROR"),
        FieldValue::U32(0x0a) => Some("CONNECT_ERROR"),
        FieldValue::U32(0x0b) => Some("ENHANCE_YOUR_CALM"),
        FieldValue::U32(0x0c) => Some("INADEQUATE_SECURITY"),
        FieldValue::U32(0x0d) => Some("HTTP_1_1_REQUIRED"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Dissector
// ---------------------------------------------------------------------------

/// HTTP/2 dissector.
///
/// Parses HTTP/2 frames including the optional connection preface. The
/// dissector handles all standard frame types defined in RFC 9113 Section 6.
/// HPACK-compressed header blocks are decoded using the static table.
pub struct Http2Dissector;

impl Dissector for Http2Dissector {
    fn name(&self) -> &'static str {
        "HyperText Transfer Protocol version 2"
    }

    fn short_name(&self) -> &'static str {
        "HTTP2"
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
        let mut pos = 0;

        let has_preface = data.starts_with(CONNECTION_PREFACE);

        buf.begin_layer("HTTP2", None, FIELD_DESCRIPTORS, offset..offset);

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MAGIC],
            FieldValue::U8(u8::from(has_preface)),
            offset
                ..offset
                    + if has_preface {
                        CONNECTION_PREFACE.len()
                    } else {
                        0
                    },
        );
        if has_preface {
            pos += CONNECTION_PREFACE.len();
        }

        if data.len() < pos + FRAME_HEADER_LEN {
            if let Some(layer) = buf.last_layer_mut() {
                layer.range = offset..offset + pos;
            }
            buf.end_layer();
            return Err(PacketError::Truncated {
                expected: pos + FRAME_HEADER_LEN,
                actual: data.len(),
            });
        }

        let frame_data = &data[pos..];
        let frame_length = read_be_u24(frame_data, 0)?;
        let frame_type = frame_data[3];
        let flags = frame_data[4];
        let stream_id = read_be_u32(frame_data, 5)? & 0x7FFF_FFFF;

        let frame_header_offset = offset + pos;
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FRAME_LENGTH],
            FieldValue::U32(frame_length),
            frame_header_offset..frame_header_offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FRAME_TYPE],
            FieldValue::U8(frame_type),
            frame_header_offset + 3..frame_header_offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAGS],
            FieldValue::U8(flags),
            frame_header_offset + 4..frame_header_offset + 5,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_STREAM_ID],
            FieldValue::U32(stream_id),
            frame_header_offset + 5..frame_header_offset + 9,
        );

        pos += FRAME_HEADER_LEN;
        let payload_len = frame_length as usize;

        if data.len() < pos + payload_len {
            if let Some(layer) = buf.last_layer_mut() {
                layer.range = offset..offset + pos;
            }
            buf.end_layer();
            return Err(PacketError::Truncated {
                expected: pos + payload_len,
                actual: data.len(),
            });
        }

        let payload = &data[pos..pos + payload_len];
        let payload_offset = offset + pos;

        if !payload.is_empty() {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_PAYLOAD],
                FieldValue::Bytes(payload),
                payload_offset..payload_offset + payload_len,
            );
        }

        parse_frame_payload(frame_type, flags, payload, payload_offset, buf)?;

        let total = pos + payload_len;
        if let Some(layer) = buf.last_layer_mut() {
            layer.range = offset..offset + total;
        }
        buf.end_layer();

        Ok(DissectResult::new(total, DispatchHint::End))
    }
}

/// Parse frame-type-specific payload fields.
fn parse_frame_payload<'pkt>(
    frame_type: u8,
    flags: u8,
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    match frame_type {
        FRAME_TYPE_DATA => parse_data(flags, payload, payload_offset, buf),
        FRAME_TYPE_HEADERS => parse_headers(flags, payload, payload_offset, buf),
        FRAME_TYPE_PRIORITY => parse_priority(payload, payload_offset, buf),
        FRAME_TYPE_RST_STREAM => parse_rst_stream(payload, payload_offset, buf),
        FRAME_TYPE_SETTINGS => parse_settings(flags, payload, payload_offset, buf),
        FRAME_TYPE_PUSH_PROMISE => parse_push_promise(flags, payload, payload_offset, buf),
        FRAME_TYPE_PING => parse_ping(payload, payload_offset, buf),
        FRAME_TYPE_GOAWAY => parse_goaway(payload, payload_offset, buf),
        FRAME_TYPE_WINDOW_UPDATE => parse_window_update(payload, payload_offset, buf),
        FRAME_TYPE_CONTINUATION => parse_continuation(payload, payload_offset, buf),
        // Unknown frame types: payload already emitted as raw bytes
        _ => Ok(()),
    }
}

fn strip_padding<'pkt>(
    flags: u8,
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<&'pkt [u8], PacketError> {
    if flags & FLAG_PADDED == 0 {
        return Ok(payload);
    }
    if payload.is_empty() {
        return Err(PacketError::Truncated {
            expected: 1,
            actual: 0,
        });
    }
    let pad_length = payload[0] as usize;
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PADDING_LENGTH],
        FieldValue::U8(payload[0]),
        payload_offset..payload_offset + 1,
    );
    let overhead = 1 + pad_length;
    if payload.len() < overhead {
        return Err(PacketError::InvalidHeader(
            "padding length exceeds frame payload size",
        ));
    }
    Ok(&payload[1..payload.len() - pad_length])
}

// RFC 9113, Section 6.1 — DATA frame. <https://www.rfc-editor.org/rfc/rfc9113#section-6.1>
fn parse_data<'pkt>(
    flags: u8,
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    let _unpadded = strip_padding(flags, payload, payload_offset, buf)?;
    Ok(())
}

// RFC 9113, Section 6.2 — HEADERS frame. <https://www.rfc-editor.org/rfc/rfc9113#section-6.2>
fn parse_headers<'pkt>(
    flags: u8,
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    // When PADDED is set, `strip_padding` consumes the leading 1-octet Pad
    // Length field. Content (priority fields / header block fragment) begins
    // at `payload[1]`; trailing padding lives at the END of the payload. The
    // offset of `unpadded[0]` in the full packet is therefore
    // `payload_offset + unpadded_start` where `unpadded_start` is 1 if PADDED
    // is set, otherwise 0 — independent of pad length.
    let unpadded = strip_padding(flags, payload, payload_offset, buf)?;
    let unpadded_start = if flags & FLAG_PADDED != 0 { 1 } else { 0 };
    let mut inner_pos = unpadded_start;

    if flags & FLAG_PRIORITY != 0 {
        if unpadded.len() < 5 {
            return Err(PacketError::Truncated {
                expected: 5,
                actual: unpadded.len(),
            });
        }
        let dep_offset = payload_offset + inner_pos;
        push_priority_fields(unpadded, dep_offset, buf)?;
        inner_pos += 5;

        let fragment = &unpadded[5..];
        if !fragment.is_empty() {
            let frag_offset = payload_offset + inner_pos;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_HEADER_BLOCK_FRAGMENT],
                FieldValue::Bytes(fragment),
                frag_offset..frag_offset + fragment.len(),
            );
            push_decoded_headers(fragment, frag_offset, buf);
        }
    } else if !unpadded.is_empty() {
        let frag_offset = payload_offset + inner_pos;
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HEADER_BLOCK_FRAGMENT],
            FieldValue::Bytes(unpadded),
            frag_offset..frag_offset + unpadded.len(),
        );
        push_decoded_headers(unpadded, frag_offset, buf);
    }

    Ok(())
}

/// Resolve a HeaderString to a `&'pkt str` or `&'static str`.
/// For Huffman-encoded strings, we decode them and store in scratch buffer.
fn resolve_header_string<'pkt>(
    hs: &hpack::HeaderString,
    fragment: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    match hs {
        hpack::HeaderString::Static(s) => FieldValue::Str(s),
        hpack::HeaderString::Literal(start, end) => {
            // Direct slice from fragment as UTF-8
            match core::str::from_utf8(&fragment[*start..*end]) {
                Ok(s) => FieldValue::Str(s),
                Err(_) => FieldValue::Bytes(&fragment[*start..*end]),
            }
        }
        hpack::HeaderString::Huffman(start, end) => {
            // Decode Huffman and store in scratch buffer
            match hpack::huffman::huffman_decode(&fragment[*start..*end]) {
                Ok(decoded) => {
                    let range = buf.push_scratch(&decoded);
                    FieldValue::Scratch(range)
                }
                Err(_) => FieldValue::Bytes(&fragment[*start..*end]),
            }
        }
    }
}

/// Try to HPACK-decode a header block fragment and push the result as a
/// `headers` array field. Silently skips on decode failure.
fn push_decoded_headers<'pkt>(
    fragment: &'pkt [u8],
    frag_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    let Ok(decoded) = hpack::decode_header_block(fragment) else {
        return;
    };
    if decoded.is_empty() {
        return;
    }

    let frag_range = frag_offset..frag_offset + fragment.len();

    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_HEADERS],
        FieldValue::Array(0..0),
        frag_range.clone(),
    );

    for h in &decoded {
        match h {
            hpack::DecodedHeader::Resolved { name, value } => {
                let obj_idx = buf.begin_container(
                    &HEADER_CHILDREN[HC_NAME],
                    FieldValue::Object(0..0),
                    frag_range.clone(),
                );
                let name_val = resolve_header_string(name, fragment, buf);
                buf.push_field(&HEADER_CHILDREN[HC_NAME], name_val, frag_range.clone());
                let value_val = resolve_header_string(value, fragment, buf);
                buf.push_field(&HEADER_CHILDREN[HC_VALUE], value_val, frag_range.clone());
                buf.end_container(obj_idx);
            }
            hpack::DecodedHeader::Unresolved(_) => {}
        }
    }

    buf.end_container(array_idx);

    // If the array ended up empty (all unresolved), remove it
    let arr_field = &buf.fields()[array_idx as usize];
    if let FieldValue::Array(ref r) = arr_field.value {
        if r.start == r.end {
            // Remove the empty array
            buf.truncate_fields(array_idx as usize);
        }
    }
}

/// Push PRIORITY-specific fields (exclusive flag, stream dependency, weight).
/// Used by both PRIORITY frames and HEADERS frames with the PRIORITY flag.
/// RFC 9113, Section 6.3 — <https://www.rfc-editor.org/rfc/rfc9113#section-6.3>
///
/// Callers MUST ensure `data.len() >= 5` before invoking this helper.
fn push_priority_fields<'pkt>(
    data: &'pkt [u8],
    base_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    let dep_word = read_be_u32(data, 0)?;
    let exclusive = (dep_word >> 31) as u8;
    let stream_dep = dep_word & 0x7FFF_FFFF;
    let weight = data[4];

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PRIORITY_EXCLUSIVE],
        FieldValue::U8(exclusive),
        base_offset..base_offset + 4,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PRIORITY_STREAM_DEPENDENCY],
        FieldValue::U32(stream_dep),
        base_offset..base_offset + 4,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PRIORITY_WEIGHT],
        FieldValue::U8(weight),
        base_offset + 4..base_offset + 5,
    );
    Ok(())
}

// RFC 9113, Section 6.3 — PRIORITY frame. <https://www.rfc-editor.org/rfc/rfc9113#section-6.3>
// "A PRIORITY frame with a length other than 5 octets MUST be treated as a
// stream error (Section 5.4.2) of type FRAME_SIZE_ERROR."
fn parse_priority<'pkt>(
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    if payload.len() != 5 {
        return Err(PacketError::InvalidHeader(
            "PRIORITY frame length must be exactly 5 octets",
        ));
    }
    push_priority_fields(payload, payload_offset, buf)
}

// RFC 9113, Section 6.4 — RST_STREAM frame. <https://www.rfc-editor.org/rfc/rfc9113#section-6.4>
// "A RST_STREAM frame with a length other than 4 octets MUST be treated as a
// connection error (Section 5.4.1) of type FRAME_SIZE_ERROR."
fn parse_rst_stream<'pkt>(
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    if payload.len() != 4 {
        return Err(PacketError::InvalidHeader(
            "RST_STREAM frame length must be exactly 4 octets",
        ));
    }
    let error_code = read_be_u32(payload, 0)?;
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_ERROR_CODE],
        FieldValue::U32(error_code),
        payload_offset..payload_offset + 4,
    );
    Ok(())
}

// RFC 9113, Section 6.5 — SETTINGS frame. <https://www.rfc-editor.org/rfc/rfc9113#section-6.5>
// "A SETTINGS frame with a length other than a multiple of 6 octets MUST be
// treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR."
// A SETTINGS frame with the ACK flag set MUST have a length of 0; non-empty
// ACKs MUST be treated as FRAME_SIZE_ERROR.
fn parse_settings<'pkt>(
    flags: u8,
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    if flags & FLAG_ACK != 0 {
        if !payload.is_empty() {
            return Err(PacketError::InvalidHeader(
                "SETTINGS ACK frame must have empty payload",
            ));
        }
        return Ok(());
    }
    if payload.len() % 6 != 0 {
        return Err(PacketError::InvalidHeader(
            "SETTINGS payload length is not a multiple of 6",
        ));
    }

    if payload.is_empty() {
        return Ok(());
    }

    let first_start = payload_offset;
    let last_end = payload_offset + payload.len();

    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_SETTINGS],
        FieldValue::Array(0..0),
        first_start..last_end,
    );

    let mut pos = 0;
    while pos + 6 <= payload.len() {
        let id = read_be_u16(payload, pos)?;
        let value = read_be_u32(payload, pos + 2)?;
        let entry_offset = payload_offset + pos;
        let entry_range = entry_offset..entry_offset + 6;

        let obj_idx = buf.begin_container(
            &SETTINGS_CHILDREN[SC_ID],
            FieldValue::Object(0..0),
            entry_range.clone(),
        );
        buf.push_field(
            &SETTINGS_CHILDREN[SC_ID],
            FieldValue::U16(id),
            entry_range.clone(),
        );
        buf.push_field(
            &SETTINGS_CHILDREN[SC_VALUE],
            FieldValue::U32(value),
            entry_range,
        );
        buf.end_container(obj_idx);

        pos += 6;
    }

    buf.end_container(array_idx);

    Ok(())
}

// RFC 9113, Section 6.6 — PUSH_PROMISE frame.
// <https://www.rfc-editor.org/rfc/rfc9113#section-6.6>
fn parse_push_promise<'pkt>(
    flags: u8,
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    // See `parse_headers` for the unpadded-offset rationale: content begins
    // at `payload[1]` when PADDED is set, not past the trailing padding.
    let unpadded = strip_padding(flags, payload, payload_offset, buf)?;
    let unpadded_start = if flags & FLAG_PADDED != 0 { 1 } else { 0 };

    if unpadded.len() < 4 {
        return Err(PacketError::Truncated {
            expected: 4,
            actual: unpadded.len(),
        });
    }
    let promised_id = read_be_u32(unpadded, 0)? & 0x7FFF_FFFF;
    let id_offset = payload_offset + unpadded_start;
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PROMISED_STREAM_ID],
        FieldValue::U32(promised_id),
        id_offset..id_offset + 4,
    );

    let fragment = &unpadded[4..];
    if !fragment.is_empty() {
        let frag_offset = id_offset + 4;
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HEADER_BLOCK_FRAGMENT],
            FieldValue::Bytes(fragment),
            frag_offset..frag_offset + fragment.len(),
        );
        push_decoded_headers(fragment, frag_offset, buf);
    }

    Ok(())
}

// RFC 9113, Section 6.7 — PING frame. <https://www.rfc-editor.org/rfc/rfc9113#section-6.7>
// "Receipt of a PING frame with a length field value other than 8 MUST be
// treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR."
fn parse_ping<'pkt>(
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    if payload.len() != 8 {
        return Err(PacketError::InvalidHeader(
            "PING frame length must be exactly 8 octets",
        ));
    }
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_OPAQUE_DATA],
        FieldValue::Bytes(&payload[..8]),
        payload_offset..payload_offset + 8,
    );
    Ok(())
}

// RFC 9113, Section 6.8 — GOAWAY frame. <https://www.rfc-editor.org/rfc/rfc9113#section-6.8>
// "The GOAWAY frame applies to the connection, not a specific stream. An
// endpoint MUST treat a GOAWAY frame with a stream identifier other than
// 0x00 as a connection error (Section 5.4.1) of type PROTOCOL_ERROR."
// Payload has an 8-octet fixed portion followed by optional debug data.
fn parse_goaway<'pkt>(
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    if payload.len() < 8 {
        return Err(PacketError::Truncated {
            expected: 8,
            actual: payload.len(),
        });
    }
    let last_stream_id = read_be_u32(payload, 0)? & 0x7FFF_FFFF;
    let error_code = read_be_u32(payload, 4)?;

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_LAST_STREAM_ID],
        FieldValue::U32(last_stream_id),
        payload_offset..payload_offset + 4,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_ERROR_CODE],
        FieldValue::U32(error_code),
        payload_offset + 4..payload_offset + 8,
    );

    if payload.len() > 8 {
        let debug = &payload[8..];
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DEBUG_DATA],
            FieldValue::Bytes(debug),
            payload_offset + 8..payload_offset + payload.len(),
        );
    }

    Ok(())
}

// RFC 9113, Section 6.9 — WINDOW_UPDATE frame.
// <https://www.rfc-editor.org/rfc/rfc9113#section-6.9>
// "A WINDOW_UPDATE frame with a length other than 4 octets MUST be treated
// as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR."
fn parse_window_update<'pkt>(
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    if payload.len() != 4 {
        return Err(PacketError::InvalidHeader(
            "WINDOW_UPDATE frame length must be exactly 4 octets",
        ));
    }
    let increment = read_be_u32(payload, 0)? & 0x7FFF_FFFF;
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_WINDOW_SIZE_INCREMENT],
        FieldValue::U32(increment),
        payload_offset..payload_offset + 4,
    );
    Ok(())
}

// RFC 9113, Section 6.10 — CONTINUATION frame.
// <https://www.rfc-editor.org/rfc/rfc9113#section-6.10>
fn parse_continuation<'pkt>(
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    if !payload.is_empty() {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HEADER_BLOCK_FRAGMENT],
            FieldValue::Bytes(payload),
            payload_offset..payload_offset + payload.len(),
        );
        push_decoded_headers(payload, payload_offset, buf);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! # RFC 9113 (HTTP/2) and RFC 7541 (HPACK) Coverage
    //!
    //! | RFC Section       | Description                         | Test                                                  |
    //! |-------------------|-------------------------------------|-------------------------------------------------------|
    //! | 9113 §3.4         | Connection Preface                  | parse_connection_preface                              |
    //! | 9113 §4.1         | Frame Format                        | parse_settings_frame, parse_frame_with_offset         |
    //! | 9113 §6.1         | DATA                                | parse_data_frame, parse_data_frame_empty              |
    //! | 9113 §6.1         | DATA w/ padding                     | parse_data_frame_padded                               |
    //! | 9113 §6.1         | DATA invalid padding                | parse_data_frame_invalid_padding                      |
    //! | 9113 §6.2         | HEADERS                             | parse_headers_frame, parse_headers_frame_with_literal |
    //! | 9113 §6.2         | HEADERS w/ priority                 | parse_headers_frame_with_priority                     |
    //! | 9113 §6.2         | HEADERS w/ padding                  | parse_headers_frame_padded                            |
    //! | 9113 §6.2         | HEADERS padded byte ranges          | parse_headers_frame_padded_offsets_correct            |
    //! | 9113 §6.2         | HEADERS padded+priority ranges      | parse_headers_frame_padded_with_priority_offsets_correct |
    //! | 9113 §6.3         | PRIORITY                            | parse_priority_frame                                  |
    //! | 9113 §6.3         | PRIORITY length != 5 is FRAME_SIZE  | parse_priority_frame_invalid_length                   |
    //! | 9113 §6.4         | RST_STREAM                          | parse_rst_stream_frame                                |
    //! | 9113 §6.4         | RST_STREAM length != 4 is FRAME_SIZE| parse_rst_stream_frame_invalid_length                 |
    //! | 9113 §6.5         | SETTINGS                            | parse_settings_frame                                  |
    //! | 9113 §6.5         | SETTINGS ACK (empty)                | parse_settings_ack_frame                              |
    //! | 9113 §6.5         | SETTINGS length %6                  | parse_settings_invalid_length                         |
    //! | 9113 §6.5         | SETTINGS ACK with payload           | parse_settings_ack_with_payload_invalid               |
    //! | 9113 §6.6         | PUSH_PROMISE                        | parse_push_promise_frame                              |
    //! | 9113 §6.6         | PUSH_PROMISE padded byte ranges     | parse_push_promise_frame_padded_offsets_correct       |
    //! | 9113 §6.7         | PING                                | parse_ping_frame                                      |
    //! | 9113 §6.7         | PING length != 8 is FRAME_SIZE      | parse_ping_frame_invalid_length                       |
    //! | 9113 §6.8         | GOAWAY                              | parse_goaway_frame                                    |
    //! | 9113 §6.8         | GOAWAY w/ debug data                | parse_goaway_frame_with_debug                         |
    //! | 9113 §6.9         | WINDOW_UPDATE                       | parse_window_update_frame                             |
    //! | 9113 §6.9         | WINDOW_UPDATE length != 4           | parse_window_update_frame_invalid_length              |
    //! | 9113 §6.10        | CONTINUATION                        | parse_continuation_frame, parse_continuation_frame_with_hpack |
    //! | 9113 §7           | Error code display names            | display_fn_error_code                                 |
    //! | 7541 §5.1         | Integer encoding (HPACK module)     | hpack::integer::tests                                 |
    //! | 7541 §5.2         | String literal / Huffman            | hpack::huffman::tests                                 |
    //! | 7541 §6.1–6.3     | HPACK representations               | hpack::tests                                          |
    //! | -                 | Unknown frame type                  | parse_unknown_frame_type                              |
    //! | -                 | Truncated frame header              | parse_truncated_frame_header                          |
    //! | -                 | Truncated frame payload             | parse_truncated_frame_payload                         |
    //! | -                 | Dissector metadata                  | dissector_metadata                                    |

    use super::*;

    /// END_STREAM flag (DATA, HEADERS).
    const FLAG_END_STREAM: u8 = 0x01;
    /// END_HEADERS flag (HEADERS, PUSH_PROMISE, CONTINUATION).
    const FLAG_END_HEADERS: u8 = 0x04;

    fn dissect(data: &[u8]) -> Result<DissectBuffer<'_>, PacketError> {
        let dissector = Http2Dissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(data, &mut buf, 0)?;
        Ok(buf)
    }

    fn dissect_err(data: &[u8]) -> PacketError {
        let dissector = Http2Dissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(data, &mut buf, 0).unwrap_err()
    }

    /// Build a frame from header fields and payload.
    fn build_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        // Length (24-bit)
        frame.push((len >> 16) as u8);
        frame.push((len >> 8) as u8);
        frame.push(len as u8);
        // Type
        frame.push(frame_type);
        // Flags
        frame.push(flags);
        // Stream ID (31-bit, R bit = 0)
        frame.extend_from_slice(&stream_id.to_be_bytes());
        // Payload
        frame.extend_from_slice(payload);
        frame
    }

    /// Helper to get a header name/value pair from a decoded headers array.
    fn get_header_pair(
        buf: &DissectBuffer<'_>,
        layer: &packet_dissector_core::packet::Layer,
        index: usize,
    ) -> (String, String) {
        let headers_field = buf.field_by_name(layer, "headers").unwrap();
        let array_range = match &headers_field.value {
            FieldValue::Array(r) => r,
            _ => panic!("expected Array"),
        };
        let children = buf.nested_fields(array_range);
        let objects: Vec<_> = children.iter().filter(|f| f.value.is_object()).collect();
        let obj = objects[index];
        if let FieldValue::Object(ref r) = obj.value {
            let obj_fields = buf.nested_fields(r);
            let name = match &obj_fields[0].value {
                FieldValue::Str(s) => s.to_string(),
                FieldValue::Scratch(r) => {
                    String::from_utf8(buf.scratch()[r.start as usize..r.end as usize].to_vec())
                        .unwrap()
                }
                FieldValue::Bytes(b) => String::from_utf8_lossy(b).to_string(),
                _ => panic!("unexpected name type"),
            };
            let value = match &obj_fields[1].value {
                FieldValue::Str(s) => s.to_string(),
                FieldValue::Scratch(r) => {
                    String::from_utf8(buf.scratch()[r.start as usize..r.end as usize].to_vec())
                        .unwrap()
                }
                FieldValue::Bytes(b) => String::from_utf8_lossy(b).to_string(),
                _ => panic!("unexpected value type"),
            };
            (name, value)
        } else {
            panic!("expected Object");
        }
    }

    fn count_headers(
        buf: &DissectBuffer<'_>,
        layer: &packet_dissector_core::packet::Layer,
    ) -> usize {
        let Some(headers_field) = buf.field_by_name(layer, "headers") else {
            return 0;
        };
        let array_range = match &headers_field.value {
            FieldValue::Array(r) => r,
            _ => return 0,
        };
        let children = buf.nested_fields(array_range);
        children.iter().filter(|f| f.value.is_object()).count()
    }

    #[test]
    fn parse_settings_frame() {
        // SETTINGS with HEADER_TABLE_SIZE=4096, ENABLE_PUSH=0
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x0001u16.to_be_bytes()); // HEADER_TABLE_SIZE
        payload.extend_from_slice(&4096u32.to_be_bytes());
        payload.extend_from_slice(&0x0002u16.to_be_bytes()); // ENABLE_PUSH
        payload.extend_from_slice(&0u32.to_be_bytes());

        let data = build_frame(FRAME_TYPE_SETTINGS, 0x00, 0, &payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "frame_type").unwrap().value,
            FieldValue::U8(0x04)
        );
        assert_eq!(
            buf.field_by_name(layer, "frame_length").unwrap().value,
            FieldValue::U32(12)
        );
        assert_eq!(
            buf.field_by_name(layer, "stream_id").unwrap().value,
            FieldValue::U32(0)
        );

        let settings_field = buf.field_by_name(layer, "settings").unwrap();
        let array_range = match &settings_field.value {
            FieldValue::Array(r) => r,
            _ => panic!("expected Array"),
        };
        let children = buf.nested_fields(array_range);
        let objects: Vec<_> = children.iter().filter(|f| f.value.is_object()).collect();
        assert_eq!(objects.len(), 2);

        if let FieldValue::Object(ref r) = objects[0].value {
            let f = buf.nested_fields(r);
            assert_eq!(f[0].value, FieldValue::U16(0x01));
            assert_eq!(f[1].value, FieldValue::U32(4096));
        }
        if let FieldValue::Object(ref r) = objects[1].value {
            let f = buf.nested_fields(r);
            assert_eq!(f[0].value, FieldValue::U16(0x02));
            assert_eq!(f[1].value, FieldValue::U32(0));
        }
    }

    #[test]
    fn parse_settings_ack_frame() {
        let data = build_frame(FRAME_TYPE_SETTINGS, FLAG_ACK, 0, &[]);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "flags").unwrap().value,
            FieldValue::U8(FLAG_ACK)
        );
        assert!(buf.field_by_name(layer, "settings").is_none());
    }

    #[test]
    fn parse_settings_invalid_length() {
        let data = build_frame(FRAME_TYPE_SETTINGS, 0x00, 0, &[0; 7]);
        assert!(matches!(dissect_err(&data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_settings_ack_with_payload_invalid() {
        // RFC 9113, Section 6.5 — "Receipt of a SETTINGS frame with the ACK
        // flag set and a length field value other than 0 MUST be treated as
        // a connection error ... of type FRAME_SIZE_ERROR."
        let data = build_frame(FRAME_TYPE_SETTINGS, FLAG_ACK, 0, &[0; 6]);
        assert!(matches!(dissect_err(&data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_headers_frame() {
        // 0x82=:method GET, 0x86=:scheme http, 0x84=:path /
        let fragment = &[0x82, 0x86, 0x84];
        let data = build_frame(FRAME_TYPE_HEADERS, FLAG_END_HEADERS, 1, fragment);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "frame_type").unwrap().value,
            FieldValue::U8(0x01)
        );
        assert_eq!(
            buf.field_by_name(layer, "stream_id").unwrap().value,
            FieldValue::U32(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "header_block_fragment")
                .unwrap()
                .value,
            FieldValue::Bytes(fragment)
        );

        assert_eq!(count_headers(&buf, layer), 3);
        let (n0, v0) = get_header_pair(&buf, layer, 0);
        assert_eq!(n0, ":method");
        assert_eq!(v0, "GET");
        let (n1, _) = get_header_pair(&buf, layer, 1);
        assert_eq!(n1, ":scheme");
        let (n2, v2) = get_header_pair(&buf, layer, 2);
        assert_eq!(n2, ":path");
        assert_eq!(v2, "/");
    }

    #[test]
    fn parse_headers_frame_with_priority() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x8000_0000u32.to_be_bytes());
        payload.push(255); // weight
        payload.extend_from_slice(&[0x82, 0x86]); // fragment

        let data = build_frame(
            FRAME_TYPE_HEADERS,
            FLAG_END_HEADERS | FLAG_PRIORITY,
            1,
            &payload,
        );
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "priority_exclusive")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "priority_stream_dependency")
                .unwrap()
                .value,
            FieldValue::U32(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "priority_weight").unwrap().value,
            FieldValue::U8(255)
        );
        assert_eq!(
            buf.field_by_name(layer, "header_block_fragment")
                .unwrap()
                .value,
            FieldValue::Bytes(&[0x82, 0x86])
        );
        assert_eq!(count_headers(&buf, layer), 2);
    }

    #[test]
    fn parse_headers_frame_padded() {
        let mut payload = Vec::new();
        payload.push(2); // pad length
        payload.extend_from_slice(&[0x82, 0x86]); // fragment
        payload.extend_from_slice(&[0x00, 0x00]); // padding

        let data = build_frame(
            FRAME_TYPE_HEADERS,
            FLAG_END_HEADERS | FLAG_PADDED,
            1,
            &payload,
        );
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "padding_length").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "header_block_fragment")
                .unwrap()
                .value,
            FieldValue::Bytes(&[0x82, 0x86])
        );
        assert_eq!(count_headers(&buf, layer), 2);
    }

    #[test]
    fn parse_headers_frame_with_literal() {
        // Literal with incremental indexing: :authority = "example.com"
        let mut fragment = vec![0x41, 0x0b];
        fragment.extend_from_slice(b"example.com");

        let data = build_frame(FRAME_TYPE_HEADERS, FLAG_END_HEADERS, 1, &fragment);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        assert_eq!(count_headers(&buf, layer), 1);
        let (name, value) = get_header_pair(&buf, layer, 0);
        assert_eq!(name, ":authority");
        assert_eq!(value, "example.com");
    }

    #[test]
    fn parse_continuation_frame_with_hpack() {
        let fragment = &[0x82];
        let data = build_frame(FRAME_TYPE_CONTINUATION, FLAG_END_HEADERS, 1, fragment);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        assert_eq!(count_headers(&buf, layer), 1);
        let (name, _) = get_header_pair(&buf, layer, 0);
        assert_eq!(name, ":method");
    }

    #[test]
    fn parse_data_frame() {
        let body = b"hello";
        let data = build_frame(FRAME_TYPE_DATA, FLAG_END_STREAM, 1, body);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "frame_type").unwrap().value,
            FieldValue::U8(0x00)
        );
        assert_eq!(
            buf.field_by_name(layer, "stream_id").unwrap().value,
            FieldValue::U32(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "payload").unwrap().value,
            FieldValue::Bytes(b"hello")
        );
    }

    #[test]
    fn parse_data_frame_padded() {
        let mut payload = Vec::new();
        payload.push(3); // pad length
        payload.extend_from_slice(b"hi"); // data
        payload.extend_from_slice(&[0, 0, 0]); // padding

        let data = build_frame(FRAME_TYPE_DATA, FLAG_PADDED, 1, &payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "padding_length").unwrap().value,
            FieldValue::U8(3)
        );
    }

    #[test]
    fn parse_goaway_frame() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());

        let data = build_frame(FRAME_TYPE_GOAWAY, 0x00, 0, &payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "last_stream_id").unwrap().value,
            FieldValue::U32(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "error_code").unwrap().value,
            FieldValue::U32(0)
        );
        assert!(buf.field_by_name(layer, "debug_data").is_none());
    }

    #[test]
    fn parse_goaway_frame_with_debug() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&100u32.to_be_bytes());
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(b"oops");

        let data = build_frame(FRAME_TYPE_GOAWAY, 0x00, 0, &payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "last_stream_id").unwrap().value,
            FieldValue::U32(100)
        );
        assert_eq!(
            buf.field_by_name(layer, "error_code").unwrap().value,
            FieldValue::U32(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "debug_data").unwrap().value,
            FieldValue::Bytes(b"oops")
        );
    }

    #[test]
    fn parse_window_update_frame() {
        let payload = 65535u32.to_be_bytes();
        let data = build_frame(FRAME_TYPE_WINDOW_UPDATE, 0x00, 0, &payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "window_size_increment")
                .unwrap()
                .value,
            FieldValue::U32(65535)
        );
    }

    #[test]
    fn parse_ping_frame() {
        let opaque = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let data = build_frame(FRAME_TYPE_PING, 0x00, 0, &opaque);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "opaque_data").unwrap().value,
            FieldValue::Bytes(&opaque)
        );
    }

    #[test]
    fn parse_rst_stream_frame() {
        let payload = 8u32.to_be_bytes(); // CANCEL
        let data = build_frame(FRAME_TYPE_RST_STREAM, 0x00, 1, &payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "error_code").unwrap().value,
            FieldValue::U32(8)
        );
        assert_eq!(
            buf.field_by_name(layer, "stream_id").unwrap().value,
            FieldValue::U32(1)
        );
    }

    #[test]
    fn parse_push_promise_frame() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(&[0x82, 0x86]);

        let data = build_frame(FRAME_TYPE_PUSH_PROMISE, FLAG_END_HEADERS, 1, &payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "promised_stream_id")
                .unwrap()
                .value,
            FieldValue::U32(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "header_block_fragment")
                .unwrap()
                .value,
            FieldValue::Bytes(&[0x82, 0x86])
        );
    }

    #[test]
    fn parse_continuation_frame() {
        let fragment = &[0x82, 0x86, 0x84, 0x41];
        let data = build_frame(FRAME_TYPE_CONTINUATION, FLAG_END_HEADERS, 1, fragment);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "header_block_fragment")
                .unwrap()
                .value,
            FieldValue::Bytes(fragment)
        );
    }

    #[test]
    fn parse_priority_frame() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.push(15);

        let data = build_frame(FRAME_TYPE_PRIORITY, 0x00, 5, &payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "priority_exclusive")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "priority_stream_dependency")
                .unwrap()
                .value,
            FieldValue::U32(3)
        );
        assert_eq!(
            buf.field_by_name(layer, "priority_weight").unwrap().value,
            FieldValue::U8(15)
        );
    }

    #[test]
    fn parse_connection_preface() {
        let mut data = Vec::new();
        data.extend_from_slice(CONNECTION_PREFACE);

        let mut settings_payload = Vec::new();
        settings_payload.extend_from_slice(&0x0003u16.to_be_bytes());
        settings_payload.extend_from_slice(&100u32.to_be_bytes());
        data.extend_from_slice(&build_frame(
            FRAME_TYPE_SETTINGS,
            0x00,
            0,
            &settings_payload,
        ));

        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "magic").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "frame_type").unwrap().value,
            FieldValue::U8(0x04)
        );
    }

    #[test]
    fn parse_truncated_frame_header() {
        let data = &[0x00, 0x00];
        assert!(matches!(dissect_err(data), PacketError::Truncated { .. }));
    }

    #[test]
    fn parse_truncated_frame_payload() {
        let data = build_frame(FRAME_TYPE_DATA, 0x00, 1, &[]);
        let mut truncated = data[..FRAME_HEADER_LEN].to_vec();
        truncated[0] = 0;
        truncated[1] = 0;
        truncated[2] = 100;
        assert!(matches!(
            dissect_err(&truncated),
            PacketError::Truncated { .. }
        ));
    }

    #[test]
    fn parse_unknown_frame_type() {
        let payload = b"unknown";
        let data = build_frame(0xFF, 0x00, 0, payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "frame_type").unwrap().value,
            FieldValue::U8(0xFF)
        );
        assert_eq!(
            buf.field_by_name(layer, "payload").unwrap().value,
            FieldValue::Bytes(b"unknown")
        );
    }

    #[test]
    fn parse_frame_with_offset() {
        let data = build_frame(FRAME_TYPE_PING, 0x00, 0, &[0; 8]);
        let dissector = Http2Dissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 42).unwrap();

        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert_eq!(layer.range.start, 42);
        assert_eq!(layer.range.end, 42 + data.len());
        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn parse_data_frame_empty() {
        let data = build_frame(FRAME_TYPE_DATA, FLAG_END_STREAM, 1, &[]);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert!(buf.field_by_name(layer, "payload").is_none());
    }

    #[test]
    fn parse_data_frame_invalid_padding() {
        let mut payload = Vec::new();
        payload.push(10);
        payload.extend_from_slice(b"hi");

        let data = build_frame(FRAME_TYPE_DATA, FLAG_PADDED, 1, &payload);
        assert!(matches!(dissect_err(&data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn dissector_metadata() {
        let d = Http2Dissector;
        assert_eq!(d.name(), "HyperText Transfer Protocol version 2");
        assert_eq!(d.short_name(), "HTTP2");
        assert!(!d.field_descriptors().is_empty());
    }

    #[test]
    fn display_fn_frame_type() {
        let f = frame_type_name;
        assert_eq!(f(&FieldValue::U8(0x00), &[]), Some("DATA"));
        assert_eq!(f(&FieldValue::U8(0x01), &[]), Some("HEADERS"));
        assert_eq!(f(&FieldValue::U8(0xFF), &[]), None);
    }

    #[test]
    fn display_fn_settings_id() {
        let f = settings_id_name;
        assert_eq!(f(&FieldValue::U16(0x01), &[]), Some("HEADER_TABLE_SIZE"));
        assert_eq!(f(&FieldValue::U16(0xFF), &[]), None);
    }

    #[test]
    fn display_fn_error_code() {
        let f = error_code_name;
        assert_eq!(f(&FieldValue::U32(0x00), &[]), Some("NO_ERROR"));
        assert_eq!(f(&FieldValue::U32(0xFF), &[]), None);
    }

    // -------------------------------------------------------------------
    // Strict length validation per RFC 9113.
    // Frames with fixed-length payloads MUST be rejected when the length
    // field is wrong (FRAME_SIZE_ERROR).
    // -------------------------------------------------------------------

    #[test]
    fn parse_priority_frame_invalid_length() {
        // RFC 9113, Section 6.3 — PRIORITY length MUST be 5.
        let payload = [0u8; 6];
        let data = build_frame(FRAME_TYPE_PRIORITY, 0x00, 5, &payload);
        assert!(matches!(dissect_err(&data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_rst_stream_frame_invalid_length() {
        // RFC 9113, Section 6.4 — RST_STREAM length MUST be 4.
        let payload = [0u8; 5];
        let data = build_frame(FRAME_TYPE_RST_STREAM, 0x00, 1, &payload);
        assert!(matches!(dissect_err(&data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_window_update_frame_invalid_length() {
        // RFC 9113, Section 6.9 — WINDOW_UPDATE length MUST be 4.
        let payload = [0u8; 5];
        let data = build_frame(FRAME_TYPE_WINDOW_UPDATE, 0x00, 0, &payload);
        assert!(matches!(dissect_err(&data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_ping_frame_invalid_length() {
        // RFC 9113, Section 6.7 — PING length MUST be 8.
        let payload = [0u8; 9];
        let data = build_frame(FRAME_TYPE_PING, 0x00, 0, &payload);
        assert!(matches!(dissect_err(&data), PacketError::InvalidHeader(_)));
    }

    // -------------------------------------------------------------------
    // Byte range (offset) correctness for padded HEADERS / PUSH_PROMISE
    // frames. Content starts immediately after the 1-octet Pad Length
    // field, with padding at the END of the payload.
    // -------------------------------------------------------------------

    #[test]
    fn parse_headers_frame_padded_offsets_correct() {
        // RFC 9113, Section 6.2 — HEADERS w/ PADDED flag.
        // Payload layout: [PadLen=2, 0x82, 0x86, pad, pad]
        let mut payload = Vec::new();
        payload.push(2);
        payload.extend_from_slice(&[0x82, 0x86]);
        payload.extend_from_slice(&[0x00, 0x00]);

        let data = build_frame(
            FRAME_TYPE_HEADERS,
            FLAG_END_HEADERS | FLAG_PADDED,
            1,
            &payload,
        );
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        // Fragment bytes are at packet offset 9 (frame header) + 1 (pad len).
        let frag_field = buf.field_by_name(layer, "header_block_fragment").unwrap();
        assert_eq!(
            frag_field.range,
            (FRAME_HEADER_LEN + 1)..(FRAME_HEADER_LEN + 3)
        );
    }

    #[test]
    fn parse_headers_frame_padded_with_priority_offsets_correct() {
        // RFC 9113, Section 6.2 — HEADERS w/ PADDED + PRIORITY.
        // Payload: [PadLen=2, E|StreamDep(4), Weight(1), frag(2), pad(2)]
        let mut payload = Vec::new();
        payload.push(2); // pad length
        payload.extend_from_slice(&0x8000_0000u32.to_be_bytes()); // E=1, dep=0
        payload.push(15); // weight
        payload.extend_from_slice(&[0x82, 0x86]); // fragment
        payload.extend_from_slice(&[0x00, 0x00]); // padding

        let data = build_frame(
            FRAME_TYPE_HEADERS,
            FLAG_END_HEADERS | FLAG_PADDED | FLAG_PRIORITY,
            1,
            &payload,
        );
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        let dep_base = FRAME_HEADER_LEN + 1; // after the 1-octet pad length
        let dep_field = buf
            .field_by_name(layer, "priority_stream_dependency")
            .unwrap();
        assert_eq!(dep_field.range, dep_base..(dep_base + 4));

        let weight_field = buf.field_by_name(layer, "priority_weight").unwrap();
        assert_eq!(weight_field.range, (dep_base + 4)..(dep_base + 5));

        let frag_field = buf.field_by_name(layer, "header_block_fragment").unwrap();
        assert_eq!(frag_field.range, (dep_base + 5)..(dep_base + 7));
    }

    #[test]
    fn parse_push_promise_frame_padded_offsets_correct() {
        // RFC 9113, Section 6.6 — PUSH_PROMISE w/ PADDED.
        // Payload: [PadLen=2, PromisedID(4), frag(2), pad(2)]
        let mut payload = Vec::new();
        payload.push(2);
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(&[0x82, 0x86]);
        payload.extend_from_slice(&[0x00, 0x00]);

        let data = build_frame(
            FRAME_TYPE_PUSH_PROMISE,
            FLAG_END_HEADERS | FLAG_PADDED,
            1,
            &payload,
        );
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();

        let id_base = FRAME_HEADER_LEN + 1; // right after pad length byte
        let id_field = buf.field_by_name(layer, "promised_stream_id").unwrap();
        assert_eq!(id_field.range, id_base..(id_base + 4));

        let frag_field = buf.field_by_name(layer, "header_block_fragment").unwrap();
        assert_eq!(frag_field.range, (id_base + 4)..(id_base + 6));
    }
}
