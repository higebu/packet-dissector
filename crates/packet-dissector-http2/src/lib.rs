//! HTTP/2 dissector.
//!
//! Parses HTTP/2 frames as defined in RFC 9113. Handles the connection preface
//! (24-byte client magic), all standard frame types, and the ALTSVC, ORIGIN
//! and PRIORITY_UPDATE extension frames.
//!
//! [`Http2Dissector`] decodes each frame on its own: HPACK header blocks are
//! decoded with the static table and literal representations (RFC 7541), and
//! dynamic table references are reported as unresolved.
//! [`Http2ConnectionDissector`] keeps per-connection state for TCP streams:
//! one HPACK dynamic table per direction, and header blocks split across
//! HEADERS / PUSH_PROMISE and CONTINUATION frames are decoded as a whole.
//!
//! ## References
//! - RFC 9113: HTTP/2 <https://www.rfc-editor.org/rfc/rfc9113>
//! - RFC 7541: HPACK <https://www.rfc-editor.org/rfc/rfc7541>
//! - RFC 7838: HTTP Alternative Services (ALTSVC) <https://www.rfc-editor.org/rfc/rfc7838>
//! - RFC 8336: The ORIGIN HTTP/2 Frame <https://www.rfc-editor.org/rfc/rfc8336>
//! - RFC 8441: Bootstrapping WebSockets with HTTP/2 <https://www.rfc-editor.org/rfc/rfc8441>
//! - RFC 9218: Extensible Prioritization Scheme for HTTP <https://www.rfc-editor.org/rfc/rfc9218>

#![deny(missing_docs)]

mod connection;
mod hpack;

pub use connection::Http2ConnectionDissector;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24, read_be_u32};

/// Specification references for the HTTP/2 dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 9113",
        "HTTP/2",
        "https://www.rfc-editor.org/rfc/rfc9113",
    ),
    SpecReference::new(
        "RFC 7541",
        "HPACK: Header Compression for HTTP/2",
        "https://www.rfc-editor.org/rfc/rfc7541",
    ),
    SpecReference::new(
        "RFC 7838",
        "HTTP Alternative Services",
        "https://www.rfc-editor.org/rfc/rfc7838",
    ),
    SpecReference::new(
        "RFC 8336",
        "The ORIGIN HTTP/2 Frame",
        "https://www.rfc-editor.org/rfc/rfc8336",
    ),
    SpecReference::new(
        "RFC 8441",
        "Bootstrapping WebSockets with HTTP/2",
        "https://www.rfc-editor.org/rfc/rfc8441",
    ),
    SpecReference::new(
        "RFC 9218",
        "Extensible Prioritization Scheme for HTTP",
        "https://www.rfc-editor.org/rfc/rfc9218",
    ),
];

/// HTTP/2 client connection preface.
/// RFC 9113, Section 3.4 — <https://www.rfc-editor.org/rfc/rfc9113#section-3.4>
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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
/// ALTSVC frame type.
/// RFC 7838, Section 4 — <https://www.rfc-editor.org/rfc/rfc7838#section-4>
const FRAME_TYPE_ALTSVC: u8 = 0x0a;
/// ORIGIN frame type.
/// RFC 8336, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc8336#section-2.1>
const FRAME_TYPE_ORIGIN: u8 = 0x0c;
/// PRIORITY_UPDATE frame type.
/// RFC 9218, Section 7.1 — <https://www.rfc-editor.org/rfc/rfc9218#section-7.1>
const FRAME_TYPE_PRIORITY_UPDATE: u8 = 0x10;

// ---------------------------------------------------------------------------
// Frame flag constants
// RFC 9113, Section 6 — <https://www.rfc-editor.org/rfc/rfc9113#section-6>
// ---------------------------------------------------------------------------

/// ACK flag (SETTINGS, PING).
const FLAG_ACK: u8 = 0x01;
/// END_HEADERS flag (HEADERS, PUSH_PROMISE, CONTINUATION).
const FLAG_END_HEADERS: u8 = 0x04;
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
const FD_HPACK_ERROR: usize = 19;
const FD_PRIORITIZED_STREAM_ID: usize = 20;
const FD_PRIORITY_FIELD_VALUE: usize = 21;
const FD_ORIGINS: usize = 22;
const FD_ORIGIN: usize = 23;
const FD_ALT_SVC_FIELD_VALUE: usize = 24;

const SC_ID: usize = 0;
const SC_VALUE: usize = 1;

const HC_NAME: usize = 0;
const HC_VALUE: usize = 1;
const HC_INDEX: usize = 2;

/// Child descriptors for decoded header name/value pairs.
///
/// A header whose dynamic table entry is not known carries the HPACK
/// `index` of its name (or of the whole field) instead of the name
/// (RFC 7541, Section 2.3.3 —
/// <https://www.rfc-editor.org/rfc/rfc7541#section-2.3.3>).
static HEADER_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("name", "Name", FieldType::Str).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Str).optional(),
    FieldDescriptor::new("index", "Index", FieldType::U32).optional(),
];

/// Child descriptor for each ORIGIN frame entry.
static ORIGIN_CHILDREN: &[FieldDescriptor] =
    &[FieldDescriptor::new("origin", "Origin", FieldType::Str)];

/// Descriptor for the HTTP/2 header Object container.
///
/// The outer label ("Header") no longer collides with the inner `Name`
/// child. The header's own name is a borrowed string from the packet and
/// therefore cannot be returned through
/// [`DissectBuffer::resolve_container_display_name`], which requires a
/// `&'static str`.
static FD_HEADER: FieldDescriptor = FieldDescriptor {
    name: "header",
    display_name: "Header",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: None,
    format_fn: None,
};

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
    FieldDescriptor::new("hpack_error", "HPACK Decoding Error", FieldType::Str).optional(),
    FieldDescriptor::new(
        "prioritized_stream_id",
        "Prioritized Stream ID",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new(
        "priority_field_value",
        "Priority Field Value",
        FieldType::Str,
    )
    .optional(),
    FieldDescriptor::new("origins", "Origins", FieldType::Array)
        .optional()
        .with_children(ORIGIN_CHILDREN),
    FieldDescriptor::new("origin", "Origin", FieldType::Str).optional(),
    FieldDescriptor::new("alt_svc_field_value", "Alt-Svc Field Value", FieldType::Str).optional(),
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
        // RFC 7838, Section 4 — <https://www.rfc-editor.org/rfc/rfc7838#section-4>
        FieldValue::U8(0x0a) => Some("ALTSVC"),
        // RFC 8336, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc8336#section-2.1>
        FieldValue::U8(0x0c) => Some("ORIGIN"),
        // RFC 9218, Section 7.1 — <https://www.rfc-editor.org/rfc/rfc9218#section-7.1>
        FieldValue::U8(0x10) => Some("PRIORITY_UPDATE"),
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
        // RFC 8441, Section 3 — <https://www.rfc-editor.org/rfc/rfc8441#section-3>
        FieldValue::U16(0x08) => Some("ENABLE_CONNECT_PROTOCOL"),
        // RFC 9218, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc9218#section-2.1>
        FieldValue::U16(0x09) => Some("NO_RFC7540_PRIORITIES"),
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
// Frame header heuristic
// ---------------------------------------------------------------------------

/// Initial value of SETTINGS_MAX_FRAME_SIZE (2^14 octets).
/// RFC 9113, Section 6.5.2 — <https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2>
const DEFAULT_MAX_FRAME_SIZE: u32 = 1 << 14;

/// Whether `data` starts with a plausible HTTP/2 frame header.
///
/// Used to recognise HTTP/2 on a connection whose connection preface was
/// not seen (for example the server side, or a capture that starts after
/// the preface): RFC 9113, Section 3.4 — "The client sends the client
/// connection preface as the first application data octets of a
/// connection", so no later segment carries it —
/// <https://www.rfc-editor.org/rfc/rfc9113#section-3.4>.
///
/// The first 9 octets must form a frame header (RFC 9113, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc9113#section-4.1>) that a conforming
/// endpoint may send without knowing the peer's settings:
///
/// - the Type is one defined in RFC 9113, Section 6 (0x00–0x09);
/// - the Length is at most 16,384 ("Values greater than 2^14 (16,384) MUST
///   NOT be sent unless the receiver has set a larger value for
///   SETTINGS_MAX_FRAME_SIZE");
/// - the Reserved bit is unset ("MUST remain unset (0x00) when sending");
/// - the Stream Identifier is 0 for SETTINGS, PING and GOAWAY, non-zero for
///   DATA, HEADERS, PRIORITY, RST_STREAM, PUSH_PROMISE and CONTINUATION
///   (Sections 6.1–6.10);
/// - PRIORITY is 5 octets (Section 6.3), RST_STREAM and WINDOW_UPDATE are 4
///   (Sections 6.4, 6.9), PING is 8 (Section 6.7), GOAWAY is at least 8
///   (Section 6.8), SETTINGS is a multiple of 6 and empty with ACK
///   (Section 6.5).
///
/// An HTTP/1.x message never passes: it starts with a token or `HTTP/`,
/// whose first octet alone makes the Length exceed 16,384. Frames that fail
/// these checks can still be valid on a connection already known to be
/// HTTP/2 (unknown frame types, larger SETTINGS_MAX_FRAME_SIZE); the check
/// is meant only for a connection whose protocol is not yet known.
pub fn looks_like_frame_header(data: &[u8]) -> bool {
    let Some(header) = data.get(..FRAME_HEADER_LEN) else {
        return false;
    };
    let length = u32::from(header[0]) << 16 | u32::from(header[1]) << 8 | u32::from(header[2]);
    let frame_type = header[3];
    let flags = header[4];
    let stream_word = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
    if length > DEFAULT_MAX_FRAME_SIZE || stream_word & 0x8000_0000 != 0 {
        return false;
    }
    let on_stream = stream_word != 0;
    match frame_type {
        FRAME_TYPE_DATA
        | FRAME_TYPE_HEADERS
        | FRAME_TYPE_PUSH_PROMISE
        | FRAME_TYPE_CONTINUATION => on_stream,
        FRAME_TYPE_PRIORITY => on_stream && length == 5,
        FRAME_TYPE_RST_STREAM => on_stream && length == 4,
        FRAME_TYPE_SETTINGS => {
            !on_stream && length % 6 == 0 && (flags & FLAG_ACK == 0 || length == 0)
        }
        FRAME_TYPE_PING => !on_stream && length == 8,
        FRAME_TYPE_GOAWAY => !on_stream && length >= 8,
        FRAME_TYPE_WINDOW_UPDATE => length == 4,
        _ => false,
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

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        dissect_frame(data, buf, offset, None)
    }
}

/// Dissect the optional connection preface and one frame.
///
/// `state` is the decoding state of the frame's direction of a connection
/// ([`Http2ConnectionDissector`]); without it the frame is decoded on its
/// own. The state is changed only when the whole frame is available.
fn dissect_frame<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    mut state: Option<&mut connection::DirectionState>,
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

    let frame = Frame {
        frame_type,
        flags,
        stream_id,
    };
    if let Err(e) = parse_frame_payload(&frame, payload, payload_offset, buf, state.as_deref_mut())
    {
        // A header block that cannot be decoded may have changed the
        // encoder's dynamic table: stop following it.
        if let Some(state) = state {
            if matches!(
                frame_type,
                FRAME_TYPE_HEADERS | FRAME_TYPE_PUSH_PROMISE | FRAME_TYPE_CONTINUATION
            ) {
                state.desynchronize();
            }
        }
        return Err(e);
    }

    let total = pos + payload_len;
    if let Some(layer) = buf.last_layer_mut() {
        layer.range = offset..offset + total;
    }
    buf.end_layer();

    Ok(DissectResult::new(total, DispatchHint::End))
}

/// Frame header fields the payload parsers need.
struct Frame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
}

/// Parse frame-type-specific payload fields.
fn parse_frame_payload<'pkt>(
    frame: &Frame,
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
    mut state: Option<&mut connection::DirectionState>,
) -> Result<(), PacketError> {
    // RFC 9113, Section 4.3 — "Each field block is processed as a discrete
    // unit. Field blocks MUST be transmitted as a contiguous sequence of
    // frames, with no interleaved frames of any other type or from any
    // other stream." — <https://www.rfc-editor.org/rfc/rfc9113#section-4.3>
    if let Some(state) = state.as_deref_mut() {
        if frame.frame_type != FRAME_TYPE_CONTINUATION {
            state.interrupt_block();
        }
    }
    let flags = frame.flags;
    match frame.frame_type {
        FRAME_TYPE_DATA => parse_data(flags, payload, payload_offset, buf),
        FRAME_TYPE_HEADERS => parse_headers(frame, payload, payload_offset, buf, state),
        FRAME_TYPE_PRIORITY => parse_priority(payload, payload_offset, buf),
        FRAME_TYPE_RST_STREAM => parse_rst_stream(payload, payload_offset, buf),
        FRAME_TYPE_SETTINGS => parse_settings(flags, payload, payload_offset, buf),
        FRAME_TYPE_PUSH_PROMISE => parse_push_promise(frame, payload, payload_offset, buf, state),
        FRAME_TYPE_PING => parse_ping(payload, payload_offset, buf),
        FRAME_TYPE_GOAWAY => parse_goaway(payload, payload_offset, buf),
        FRAME_TYPE_WINDOW_UPDATE => parse_window_update(payload, payload_offset, buf),
        FRAME_TYPE_CONTINUATION => parse_continuation(frame, payload, payload_offset, buf, state),
        FRAME_TYPE_ALTSVC => {
            parse_altsvc(payload, payload_offset, buf);
            Ok(())
        }
        FRAME_TYPE_ORIGIN => {
            parse_origin(payload, payload_offset, buf);
            Ok(())
        }
        FRAME_TYPE_PRIORITY_UPDATE => parse_priority_update(payload, payload_offset, buf),
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
    frame: &Frame,
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
    state: Option<&mut connection::DirectionState>,
) -> Result<(), PacketError> {
    let flags = frame.flags;
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
    }

    let fragment = &unpadded[inner_pos - unpadded_start..];
    let frag_offset = payload_offset + inner_pos;
    if !fragment.is_empty() {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HEADER_BLOCK_FRAGMENT],
            FieldValue::Bytes(fragment),
            frag_offset..frag_offset + fragment.len(),
        );
    }
    start_header_block(frame, fragment, frag_offset, buf, state);

    Ok(())
}

/// Handle the first fragment of a header block (HEADERS or PUSH_PROMISE).
///
/// Without connection state the fragment is decoded on its own. With it, a
/// complete block (END_HEADERS set) is decoded in the direction's HPACK
/// context, and an incomplete one is kept until its CONTINUATION frames
/// arrive (RFC 9113, Section 4.3 —
/// <https://www.rfc-editor.org/rfc/rfc9113#section-4.3>).
fn start_header_block<'pkt>(
    frame: &Frame,
    fragment: &'pkt [u8],
    frag_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
    state: Option<&mut connection::DirectionState>,
) {
    let range = frag_offset..frag_offset + fragment.len();
    match state {
        None => {
            if !fragment.is_empty() {
                // Decoding errors are reported in the `hpack_error` field.
                let _ = push_decoded_headers(fragment, Some(fragment), range, None, buf);
            }
        }
        Some(state) if frame.flags & FLAG_END_HEADERS != 0 => {
            let result = push_decoded_headers(fragment, Some(fragment), range, state.table(), buf);
            if result.is_err() {
                state.desynchronize();
            }
        }
        Some(state) => state.begin_block(frame.stream_id, fragment),
    }
}

/// Field value of an HPACK string.
///
/// `packet_block` is the header block when it lies in the packet, so
/// literal strings can borrow from it; otherwise (a block reassembled from
/// several frames) they are copied to the scratch buffer, as are Huffman
/// decoded strings and dynamic table entries.
fn header_string_value<'pkt>(
    hs: &hpack::HeaderString<'_>,
    block: &[u8],
    packet_block: Option<&'pkt [u8]>,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    match *hs {
        hpack::HeaderString::Static(s) => FieldValue::Str(s),
        hpack::HeaderString::Literal(start, end) => match packet_block {
            Some(p) => str_or_bytes(&p[start..end]),
            None => FieldValue::Scratch(buf.push_scratch(&block[start..end])),
        },
        hpack::HeaderString::Huffman(start, end) => {
            match hpack::huffman::huffman_decode(&block[start..end]) {
                Ok(decoded) => FieldValue::Scratch(buf.push_scratch(&decoded)),
                Err(_) => match packet_block {
                    Some(p) => FieldValue::Bytes(&p[start..end]),
                    None => FieldValue::Scratch(buf.push_scratch(&block[start..end])),
                },
            }
        }
        hpack::HeaderString::Owned(bytes) => FieldValue::Scratch(buf.push_scratch(bytes)),
    }
}

/// HPACK-decode a header block and push the result as a `headers` array
/// field, with the `hpack_error` field when decoding fails.
///
/// `packet_block` is `block` when the block lies in the packet (see
/// [`header_string_value`]); `range` is the packet range every decoded
/// field is attributed to. Headers decoded before an error are kept.
fn push_decoded_headers<'pkt>(
    block: &[u8],
    packet_block: Option<&'pkt [u8]>,
    range: core::ops::Range<usize>,
    table: Option<&mut hpack::DynamicTable>,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), &'static str> {
    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_HEADERS],
        FieldValue::Array(0..0),
        range.clone(),
    );

    let result = hpack::decode_block(block, table, &mut |h| {
        let obj_idx = buf.begin_container(&FD_HEADER, FieldValue::Object(0..0), range.clone());
        match h {
            hpack::DecodedHeader::Resolved { name, value } => {
                let name = header_string_value(&name, block, packet_block, buf);
                buf.push_field(&HEADER_CHILDREN[HC_NAME], name, range.clone());
                let value = header_string_value(&value, block, packet_block, buf);
                buf.push_field(&HEADER_CHILDREN[HC_VALUE], value, range.clone());
            }
            hpack::DecodedHeader::UnresolvedName { index, value } => {
                let value = header_string_value(&value, block, packet_block, buf);
                buf.push_field(&HEADER_CHILDREN[HC_VALUE], value, range.clone());
                buf.push_field(
                    &HEADER_CHILDREN[HC_INDEX],
                    FieldValue::U32(index as u32),
                    range.clone(),
                );
            }
            hpack::DecodedHeader::Unresolved(index) => {
                buf.push_field(
                    &HEADER_CHILDREN[HC_INDEX],
                    FieldValue::U32(index as u32),
                    range.clone(),
                );
            }
        }
        buf.end_container(obj_idx);
    });

    buf.end_container(array_idx);

    // Drop the array when nothing was decoded (e.g. an empty block).
    if let FieldValue::Array(ref r) = buf.fields()[array_idx as usize].value {
        if r.start == r.end {
            buf.truncate_fields(array_idx as usize);
        }
    }

    if let Err(e) = result {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HPACK_ERROR],
            FieldValue::Str(e),
            range,
        );
    }
    result
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
    frame: &Frame,
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
    state: Option<&mut connection::DirectionState>,
) -> Result<(), PacketError> {
    let flags = frame.flags;
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
    let frag_offset = id_offset + 4;
    if !fragment.is_empty() {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HEADER_BLOCK_FRAGMENT],
            FieldValue::Bytes(fragment),
            frag_offset..frag_offset + fragment.len(),
        );
    }
    start_header_block(frame, fragment, frag_offset, buf, state);

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
//
// With connection state, the fragment is appended to the header block begun
// by the preceding HEADERS / PUSH_PROMISE frame; the whole block is decoded
// on the frame that sets END_HEADERS. RFC 9113, Section 6.10 — "Any number
// of CONTINUATION frames can be sent, as long as the preceding frame is on
// the same stream and is a HEADERS, PUSH_PROMISE, or CONTINUATION frame
// without the END_HEADERS flag set."
fn parse_continuation<'pkt>(
    frame: &Frame,
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
    state: Option<&mut connection::DirectionState>,
) -> Result<(), PacketError> {
    let range = payload_offset..payload_offset + payload.len();
    if !payload.is_empty() {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HEADER_BLOCK_FRAGMENT],
            FieldValue::Bytes(payload),
            range.clone(),
        );
    }
    let Some(state) = state else {
        if !payload.is_empty() {
            // Decoding errors are reported in the `hpack_error` field.
            let _ = push_decoded_headers(payload, Some(payload), range, None, buf);
        }
        return Ok(());
    };
    let end_headers = frame.flags & FLAG_END_HEADERS != 0;
    let Some(block) = state.continue_block(frame.stream_id, payload, end_headers) else {
        return Ok(());
    };
    let result = push_decoded_headers(&block, None, range, state.table(), buf);
    if result.is_err() {
        state.desynchronize();
    }
    Ok(())
}

// RFC 7838, Section 4 — ALTSVC frame.
// <https://www.rfc-editor.org/rfc/rfc7838#section-4>
//
// The frame is a non-critical extension ("Endpoints that do not support
// this frame will ignore it"), so a malformed payload is kept as raw bytes
// rather than failing the dissection.
fn parse_altsvc<'pkt>(payload: &'pkt [u8], payload_offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let Ok(origin_len) = read_be_u16(payload, 0) else {
        return;
    };
    let origin_end = 2 + usize::from(origin_len);
    let Some(origin) = payload.get(2..origin_end) else {
        return;
    };
    if !origin.is_empty() {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ORIGIN],
            str_or_bytes(origin),
            payload_offset + 2..payload_offset + origin_end,
        );
    }
    let value = &payload[origin_end..];
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_ALT_SVC_FIELD_VALUE],
        str_or_bytes(value),
        payload_offset + origin_end..payload_offset + payload.len(),
    );
}

// RFC 8336, Section 2.1 — ORIGIN frame: zero or more Origin-Entry fields,
// each an Origin-Len (16) followed by that many octets of ASCII-Origin.
// <https://www.rfc-editor.org/rfc/rfc8336#section-2.1>
//
// RFC 8336, Section 2.2 — "The ORIGIN frame is a non-critical extension to
// HTTP/2. Endpoints that do not support this frame can safely ignore it
// upon receipt." A truncated trailing entry ends the list without an error.
fn parse_origin<'pkt>(payload: &'pkt [u8], payload_offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_ORIGINS],
        FieldValue::Array(0..0),
        payload_offset..payload_offset + payload.len(),
    );
    let mut pos = 0;
    while let Ok(len) = read_be_u16(payload, pos) {
        let start = pos + 2;
        let end = start + usize::from(len);
        let Some(origin) = payload.get(start..end) else {
            break;
        };
        buf.push_field(
            &ORIGIN_CHILDREN[0],
            str_or_bytes(origin),
            payload_offset + start..payload_offset + end,
        );
        pos = end;
    }
    buf.end_container(array_idx);
}

// RFC 9218, Section 7.1 — PRIORITY_UPDATE frame: Reserved (1), Prioritized
// Stream ID (31), Priority Field Value (..).
// <https://www.rfc-editor.org/rfc/rfc9218#section-7.1>
fn parse_priority_update<'pkt>(
    payload: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    let Ok(word) = read_be_u32(payload, 0) else {
        return Err(PacketError::InvalidHeader(
            "PRIORITY_UPDATE frame shorter than 4 octets",
        ));
    };
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PRIORITIZED_STREAM_ID],
        FieldValue::U32(word & 0x7FFF_FFFF),
        payload_offset..payload_offset + 4,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PRIORITY_FIELD_VALUE],
        str_or_bytes(&payload[4..]),
        payload_offset + 4..payload_offset + payload.len(),
    );
    Ok(())
}

/// A string field value, or the raw bytes when they are not UTF-8.
fn str_or_bytes(bytes: &[u8]) -> FieldValue<'_> {
    match core::str::from_utf8(bytes) {
        Ok(s) => FieldValue::Str(s),
        Err(_) => FieldValue::Bytes(bytes),
    }
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
    //! | 9113 §4.1, §6     | Frame header heuristic accepts      | looks_like_frame_header_accepts_valid_headers         |
    //! | 9113 §4.1, §6     | Frame header heuristic rejects      | looks_like_frame_header_rejects_invalid_headers       |
    //! | 9113 §3.4         | Heuristic rejects preface/HTTP/1.1  | looks_like_frame_header_rejects_text                  |
    //! | 7541 §2.2, 9113 §4.3 | Per-connection HPACK / CONTINUATION | connection::tests                                  |
    //! | 7541 App. B       | Huffman code table                  | hpack::huffman::tests                                 |
    //! | 7541 App. C.3–C.6 | Request / response sequences        | hpack::tests::rfc7541_c3_… – rfc7541_c6_…             |
    //! | 7541 §2.3.3       | Unresolved dynamic index reported   | unresolved_dynamic_index_is_reported                  |
    //! | 7541 §2.3.3       | Unresolved dynamic name reported    | unresolved_dynamic_name_is_reported                   |
    //! | 7541 §3.1         | Decode error keeps earlier headers  | decode_error_keeps_earlier_headers                    |
    //! | 8441 §3, 9218 §2.1| SETTINGS 0x8 / 0x9 names            | display_fn_settings_id_extensions                     |
    //! | 7838 §4, 8336 §2, 9218 §7.1 | Extension frame type names | display_fn_frame_type_extensions                   |
    //! | 9218 §7.1         | PRIORITY_UPDATE                     | parse_priority_update_frame                           |
    //! | 9218 §7.1         | PRIORITY_UPDATE too short           | parse_priority_update_frame_too_short                 |
    //! | 8336 §2.1         | ORIGIN                              | parse_origin_frame                                    |
    //! | 8336 §2.1         | ORIGIN truncated entry              | parse_origin_frame_truncated_entry                    |
    //! | 7838 §4           | ALTSVC                              | parse_altsvc_frame, parse_altsvc_frame_on_stream      |
    //! | 7838 §4           | ALTSVC malformed                    | parse_altsvc_frame_malformed                          |
    //! | -                 | Unknown frame type                  | parse_unknown_frame_type                              |
    //! | -                 | Truncated frame header              | parse_truncated_frame_header                          |
    //! | -                 | Truncated frame payload             | parse_truncated_frame_payload                         |
    //! | -                 | Dissector metadata                  | dissector_metadata                                    |

    use super::*;

    /// END_STREAM flag (DATA, HEADERS).
    const FLAG_END_STREAM: u8 = 0x01;

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
    fn header_container_descriptor_distinct_from_inner_name() {
        // The per-header Object container must use a descriptor distinct
        // from the inner `name` child so that the outer display label does
        // not collide with the child's "Name" label.
        let fragment = &[0x82];
        let data = build_frame(FRAME_TYPE_HEADERS, FLAG_END_HEADERS, 1, fragment);
        let buf = dissect(&data).unwrap();

        let (idx, field) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "header")
            .expect("header container not found");
        assert!(matches!(field.value, FieldValue::Object(_)));
        assert_eq!(field.display_name(), "Header");
        assert_eq!(buf.resolve_container_display_name(idx as u32), None);
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

    #[test]
    fn test_references_and_layer() {
        let dissector = Http2Dissector;
        let refs = dissector.references();
        assert!(!refs.is_empty());
        for r in refs {
            assert!(!r.id.is_empty());
            assert!(r.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Application));
    }

    #[test]
    fn looks_like_frame_header_accepts_valid_headers() {
        let accepted = [
            build_frame(FRAME_TYPE_SETTINGS, 0, 0, &[]),
            build_frame(FRAME_TYPE_SETTINGS, FLAG_ACK, 0, &[]),
            build_frame(FRAME_TYPE_SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100]),
            build_frame(FRAME_TYPE_WINDOW_UPDATE, 0, 0, &[0, 0, 0xff, 0xff]),
            build_frame(FRAME_TYPE_WINDOW_UPDATE, 0, 3, &[0, 0, 0xff, 0xff]),
            build_frame(FRAME_TYPE_HEADERS, FLAG_END_HEADERS, 1, &[0x82]),
            build_frame(FRAME_TYPE_DATA, FLAG_END_STREAM, 1, &[]),
            build_frame(FRAME_TYPE_PRIORITY, 0, 3, &[0, 0, 0, 1, 16]),
            build_frame(FRAME_TYPE_RST_STREAM, 0, 1, &[0, 0, 0, 8]),
            build_frame(FRAME_TYPE_PUSH_PROMISE, 0, 1, &[0, 0, 0, 2]),
            build_frame(FRAME_TYPE_PING, 0, 0, &[0; 8]),
            build_frame(FRAME_TYPE_GOAWAY, 0, 0, &[0; 8]),
            build_frame(FRAME_TYPE_CONTINUATION, 0, 1, &[0x82]),
        ];
        for frame in &accepted {
            assert!(looks_like_frame_header(frame), "{frame:02x?}");
        }
        // Only the 9-octet header is examined: the payload may follow later.
        assert!(looks_like_frame_header(&accepted[5][..FRAME_HEADER_LEN]));
        // Length at the default SETTINGS_MAX_FRAME_SIZE.
        let mut max = build_frame(FRAME_TYPE_DATA, 0, 1, &[]);
        max[..3].copy_from_slice(&[0x00, 0x40, 0x00]);
        assert!(looks_like_frame_header(&max));
    }

    #[test]
    fn looks_like_frame_header_rejects_invalid_headers() {
        let mut too_long = build_frame(FRAME_TYPE_DATA, 0, 1, &[]);
        too_long[..3].copy_from_slice(&[0x00, 0x40, 0x01]);
        let mut reserved_bit = build_frame(FRAME_TYPE_HEADERS, 0, 1, &[0x82]);
        reserved_bit[5] |= 0x80;
        let rejected = [
            // Shorter than a frame header.
            build_frame(FRAME_TYPE_SETTINGS, 0, 0, &[])[..8].to_vec(),
            // Frame types not defined in RFC 9113.
            build_frame(0x0a, 0, 0, &[]),
            build_frame(0xfa, 0, 0, &[]),
            too_long,
            reserved_bit,
            // Connection-level frames on a stream.
            build_frame(FRAME_TYPE_SETTINGS, 0, 1, &[]),
            build_frame(FRAME_TYPE_PING, 0, 1, &[0; 8]),
            build_frame(FRAME_TYPE_GOAWAY, 0, 1, &[0; 8]),
            // Stream frames on stream 0.
            build_frame(FRAME_TYPE_DATA, 0, 0, &[]),
            build_frame(FRAME_TYPE_HEADERS, 0, 0, &[0x82]),
            build_frame(FRAME_TYPE_PRIORITY, 0, 0, &[0, 0, 0, 1, 16]),
            build_frame(FRAME_TYPE_RST_STREAM, 0, 0, &[0, 0, 0, 8]),
            build_frame(FRAME_TYPE_PUSH_PROMISE, 0, 0, &[0, 0, 0, 2]),
            build_frame(FRAME_TYPE_CONTINUATION, 0, 0, &[0x82]),
            // Fixed or minimum payload lengths.
            build_frame(FRAME_TYPE_PRIORITY, 0, 3, &[0, 0, 0, 1]),
            build_frame(FRAME_TYPE_RST_STREAM, 0, 1, &[0, 0, 8]),
            build_frame(FRAME_TYPE_SETTINGS, 0, 0, &[0, 3, 0, 0, 0]),
            build_frame(FRAME_TYPE_SETTINGS, FLAG_ACK, 0, &[0, 3, 0, 0, 0, 100]),
            build_frame(FRAME_TYPE_PING, 0, 0, &[0; 7]),
            build_frame(FRAME_TYPE_GOAWAY, 0, 0, &[0; 7]),
            build_frame(FRAME_TYPE_WINDOW_UPDATE, 0, 0, &[0, 0, 1]),
        ];
        for frame in &rejected {
            assert!(!looks_like_frame_header(frame), "{frame:02x?}");
        }
    }

    #[test]
    fn looks_like_frame_header_rejects_text() {
        assert!(!looks_like_frame_header(CONNECTION_PREFACE));
        assert!(!looks_like_frame_header(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!looks_like_frame_header(b"HTTP/1.1 200 OK\r\n\r\n"));
    }

    /// Every decoded header as `name: value`, `#index: value` (unknown
    /// name) or `#index` (unknown entry).
    fn header_list(
        buf: &DissectBuffer<'_>,
        layer: &packet_dissector_core::packet::Layer,
    ) -> Vec<String> {
        let Some(headers) = buf.field_by_name(layer, "headers") else {
            return Vec::new();
        };
        let FieldValue::Array(ref array) = headers.value else {
            panic!("expected Array");
        };
        let text = |v: &FieldValue<'_>| match v {
            FieldValue::Str(s) => s.to_string(),
            FieldValue::Scratch(r) => {
                String::from_utf8(buf.scratch()[r.start as usize..r.end as usize].to_vec()).unwrap()
            }
            FieldValue::Bytes(b) => String::from_utf8_lossy(b).to_string(),
            other => panic!("unexpected {other:?}"),
        };
        buf.nested_fields(array)
            .iter()
            .filter_map(|f| match f.value {
                FieldValue::Object(ref r) => Some(buf.nested_fields(r)),
                _ => None,
            })
            .map(|children| {
                let get = |n: &str| children.iter().find(|c| c.name() == n).map(|c| &c.value);
                match (get("name"), get("index"), get("value")) {
                    (Some(n), _, Some(v)) => format!("{}: {}", text(n), text(v)),
                    (None, Some(FieldValue::U32(i)), Some(v)) => format!("#{i}: {}", text(v)),
                    (None, Some(FieldValue::U32(i)), None) => format!("#{i}"),
                    other => panic!("unexpected header object {other:?}"),
                }
            })
            .collect()
    }

    #[test]
    fn unresolved_dynamic_index_is_reported() {
        let data = build_frame(FRAME_TYPE_HEADERS, FLAG_END_HEADERS, 1, &[0x82, 0xbe]);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert_eq!(header_list(&buf, layer), [":method: GET", "#62"]);
    }

    #[test]
    fn unresolved_dynamic_name_is_reported() {
        let data = build_frame(
            FRAME_TYPE_HEADERS,
            FLAG_END_HEADERS,
            1,
            &[0x7e, 0x03, b'f', b'o', b'o'],
        );
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert_eq!(header_list(&buf, layer), ["#62: foo"]);
    }

    #[test]
    fn decode_error_keeps_earlier_headers() {
        // :method GET, then a literal whose name runs past the fragment.
        let data = build_frame(
            FRAME_TYPE_HEADERS,
            FLAG_END_HEADERS,
            1,
            &[0x82, 0x04, 0x05, b'a'],
        );
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert_eq!(header_list(&buf, layer), [":method: GET"]);
        assert_eq!(
            buf.field_by_name(layer, "hpack_error").unwrap().value,
            FieldValue::Str("string length exceeds available data")
        );
    }

    #[test]
    fn display_fn_settings_id_extensions() {
        let f = settings_id_name;
        assert_eq!(
            f(&FieldValue::U16(0x08), &[]),
            Some("ENABLE_CONNECT_PROTOCOL")
        );
        assert_eq!(
            f(&FieldValue::U16(0x09), &[]),
            Some("NO_RFC7540_PRIORITIES")
        );
    }

    #[test]
    fn display_fn_frame_type_extensions() {
        let f = frame_type_name;
        assert_eq!(f(&FieldValue::U8(0x0a), &[]), Some("ALTSVC"));
        assert_eq!(f(&FieldValue::U8(0x0c), &[]), Some("ORIGIN"));
        assert_eq!(f(&FieldValue::U8(0x10), &[]), Some("PRIORITY_UPDATE"));
        assert_eq!(f(&FieldValue::U8(0x0b), &[]), None);
    }

    #[test]
    fn parse_priority_update_frame() {
        let mut payload = 0x8000_0005u32.to_be_bytes().to_vec();
        payload.extend_from_slice(b"u=1, i");
        let data = build_frame(FRAME_TYPE_PRIORITY_UPDATE, 0, 0, &payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        let id = buf.field_by_name(layer, "prioritized_stream_id").unwrap();
        assert_eq!(id.value, FieldValue::U32(5));
        assert_eq!(id.range, 9..13);
        let value = buf.field_by_name(layer, "priority_field_value").unwrap();
        assert_eq!(value.value, FieldValue::Str("u=1, i"));
        assert_eq!(value.range, 13..19);
    }

    #[test]
    fn parse_priority_update_frame_too_short() {
        let data = build_frame(FRAME_TYPE_PRIORITY_UPDATE, 0, 0, &[0, 0, 5]);
        assert!(matches!(dissect_err(&data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_origin_frame() {
        let mut payload = Vec::new();
        for origin in ["https://a.example", "https://b.example"] {
            payload.extend_from_slice(&(origin.len() as u16).to_be_bytes());
            payload.extend_from_slice(origin.as_bytes());
        }
        let data = build_frame(FRAME_TYPE_ORIGIN, 0, 0, &payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        let origins = buf.field_by_name(layer, "origins").unwrap();
        let FieldValue::Array(ref r) = origins.value else {
            panic!("expected Array");
        };
        let entries = buf.nested_fields(r);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].value, FieldValue::Str("https://a.example"));
        assert_eq!(entries[0].range, 11..28);
        assert_eq!(entries[1].value, FieldValue::Str("https://b.example"));
    }

    #[test]
    fn parse_origin_frame_truncated_entry() {
        // RFC 8336 §2.2 treats ORIGIN as non-critical: a malformed entry is
        // not a dissection error, the complete entries before it are kept.
        let payload = [0, 1, b'x', 0, 9, b'y'];
        let data = build_frame(FRAME_TYPE_ORIGIN, 0, 0, &payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        let FieldValue::Array(ref r) = buf.field_by_name(layer, "origins").unwrap().value else {
            panic!("expected Array");
        };
        assert_eq!(buf.nested_fields(r).len(), 1);
    }

    #[test]
    fn parse_altsvc_frame() {
        let origin = b"https://example.com";
        let value = b"h2=\":8000\"";
        let mut payload = (origin.len() as u16).to_be_bytes().to_vec();
        payload.extend_from_slice(origin);
        payload.extend_from_slice(value);
        let data = build_frame(FRAME_TYPE_ALTSVC, 0, 0, &payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        let o = buf.field_by_name(layer, "origin").unwrap();
        assert_eq!(o.value, FieldValue::Str("https://example.com"));
        assert_eq!(o.range, 11..30);
        let v = buf.field_by_name(layer, "alt_svc_field_value").unwrap();
        assert_eq!(v.value, FieldValue::Str("h2=\":8000\""));
        assert_eq!(v.range, 30..40);
    }

    #[test]
    fn parse_altsvc_frame_on_stream() {
        // An empty Origin: the service applies to the stream's origin.
        let mut payload = vec![0, 0];
        payload.extend_from_slice(b"clear");
        let data = build_frame(FRAME_TYPE_ALTSVC, 0, 3, &payload);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert!(buf.field_by_name(layer, "origin").is_none());
        assert_eq!(
            buf.field_by_name(layer, "alt_svc_field_value")
                .unwrap()
                .value,
            FieldValue::Str("clear")
        );
    }

    #[test]
    fn parse_altsvc_frame_malformed() {
        // Too short for Origin-Len, and an Origin-Len past the payload: the
        // raw payload is kept and nothing is decoded.
        for payload in [&[0u8][..], &[0, 9, b'a']] {
            let data = build_frame(FRAME_TYPE_ALTSVC, 0, 0, payload);
            let buf = dissect(&data).unwrap();
            let layer = buf.layer_by_name("HTTP2").unwrap();
            assert!(buf.field_by_name(layer, "alt_svc_field_value").is_none());
            assert!(buf.field_by_name(layer, "payload").is_some());
        }
    }
}
