//! HTTP/1.1 dissector.
//!
//! Parses HTTP/1.1 request and response messages as defined in RFC 9112.
//! Uses the [`httparse`] crate for robust, zero-copy start-line and header
//! parsing, then determines the message body length as specified in
//! RFC 9112, Section 6.3 (Content-Length, chunked transfer coding,
//! close-delimited responses, and status codes without a body).
//!
//! A stateless dissector does not know the request method of the response
//! it is parsing, so responses to HEAD (no body) and 2xx responses to
//! CONNECT (tunnel) are framed like any other response.
//!
//! ## References
//! - RFC 9112: HTTP/1.1 <https://www.rfc-editor.org/rfc/rfc9112>
//! - RFC 9110: HTTP Semantics <https://www.rfc-editor.org/rfc/rfc9110>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{intern_content_type, slice_offset, str_offset, trim_ows};

/// Specification references for the HTTP/1.1 dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 9112",
        "HTTP/1.1",
        "https://www.rfc-editor.org/rfc/rfc9112",
    ),
    SpecReference::new(
        "RFC 9110",
        "HTTP Semantics",
        "https://www.rfc-editor.org/rfc/rfc9110",
    ),
];

/// Number of HTTP header fields parsed with the first (small) stack array.
const MAX_HEADERS: usize = 64;

/// Number of HTTP header fields parsed with the retry stack array, used
/// when a message has more than [`MAX_HEADERS`] fields. Messages with more
/// fields are rejected.
const MAX_HEADERS_LARGE: usize = 1024;

/// Minimum valid start-line length: "GET / HTTP/1.1\r\n" = 16 bytes
const MIN_START_LINE_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Field descriptors
// ---------------------------------------------------------------------------

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_IS_RESPONSE: usize = 0;
const FD_METHOD: usize = 1;
const FD_URI: usize = 2;
const FD_VERSION: usize = 3;
const FD_STATUS_CODE: usize = 4;
const FD_REASON_PHRASE: usize = 5;
const FD_HEADERS: usize = 6;
const FD_CONTENT_LENGTH: usize = 7;
const FD_CONTENT_TYPE: usize = 8;
const FD_BODY_FRAMING: usize = 9;
const FD_CHUNK_COUNT: usize = 10;
const FD_CONTENT_LENGTH_OVERRIDDEN: usize = 11;

/// Child descriptor indices for [`HEADER_CHILDREN`].
const HC_NAME: usize = 0;
const HC_VALUE: usize = 1;

/// Child descriptors for each header entry object.
static HEADER_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("name", "Name", FieldType::Str),
    FieldDescriptor::new("value", "Value", FieldType::Str),
];

/// Descriptor for the HTTP header Object container.
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

/// All field descriptors for the HTTP dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 9112, Section 2.1 — distinguishes request from response
    FieldDescriptor::new("is_response", "Is Response", FieldType::U8),
    // RFC 9112, Section 3 — request-line method token
    FieldDescriptor::new("method", "Method", FieldType::Str).optional(),
    // RFC 9112, Section 3 — request-target
    FieldDescriptor::new("uri", "Request URI", FieldType::Str).optional(),
    // RFC 9112, Section 2.3 — HTTP-version
    FieldDescriptor::new("version", "Version", FieldType::Str),
    // RFC 9112, Section 4 — status-code (3DIGIT)
    FieldDescriptor::new("status_code", "Status Code", FieldType::U16).optional(),
    // RFC 9112, Section 4 — reason-phrase
    FieldDescriptor::new("reason_phrase", "Reason Phrase", FieldType::Str).optional(),
    // RFC 9112, Section 5 — header fields
    FieldDescriptor::new("headers", "Headers", FieldType::Array)
        .optional()
        .with_children(HEADER_CHILDREN),
    // RFC 9112, Section 6.2 — Content-Length
    FieldDescriptor::new("content_length", "Content Length", FieldType::U32).optional(),
    // RFC 9110, Section 8.3 — Content-Type
    // https://www.rfc-editor.org/rfc/rfc9110#section-8.3
    FieldDescriptor::new("content_type", "Content Type", FieldType::Str).optional(),
    // RFC 9112, Section 6.3 — how the message body length was determined:
    // "content-length", "chunked", "close-delimited" or "none"
    // https://www.rfc-editor.org/rfc/rfc9112#section-6.3
    FieldDescriptor::new("body_framing", "Body Framing", FieldType::Str).optional(),
    // RFC 9112, Section 7.1 — number of chunks with data (excluding the
    // last-chunk) https://www.rfc-editor.org/rfc/rfc9112#section-7.1
    FieldDescriptor::new("chunk_count", "Chunk Count", FieldType::U32).optional(),
    // RFC 9112, Section 6.3 rule 3 — both Transfer-Encoding and
    // Content-Length were present; Transfer-Encoding wins
    // https://www.rfc-editor.org/rfc/rfc9112#section-6.3
    FieldDescriptor::new(
        "content_length_overridden",
        "Content-Length Overridden by Transfer-Encoding",
        FieldType::U8,
    )
    .optional(),
];

/// HTTP/1.1 dissector.
///
/// Parses both request and response messages. The dissector detects whether the
/// message is a request or response by checking if the start-line begins with
/// `"HTTP/"` (response) or a method token (request).
pub struct HttpDissector;

impl Dissector for HttpDissector {
    fn name(&self) -> &'static str {
        "HyperText Transfer Protocol"
    }

    fn short_name(&self) -> &'static str {
        "HTTP"
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
        if data.len() < MIN_START_LINE_LEN {
            return Err(PacketError::Truncated {
                expected: MIN_START_LINE_LEN,
                actual: data.len(),
            });
        }

        // RFC 9112, Section 2.1 — detect request vs response
        let is_response = data.starts_with(b"HTTP/");

        buf.begin_layer("HTTP", None, FIELD_DESCRIPTORS, offset..offset);

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_IS_RESPONSE],
            FieldValue::U8(u8::from(is_response)),
            offset..offset + 1,
        );

        let (header_len, status) = if is_response {
            let (len, code) = parse_response(data, offset, buf)?;
            (len, Some(code))
        } else {
            (parse_request(data, offset, buf)?, None)
        };
        let header_range = offset..offset + header_len;

        let headers = scan_framing_headers(buf);
        let content_type = headers.content_type;

        if let Some(Ok(cl)) = headers.content_length {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_CONTENT_LENGTH],
                FieldValue::U32(u32::try_from(cl).unwrap_or(u32::MAX)),
                header_range.clone(),
            );
        }

        if let Some(ct) = content_type {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_CONTENT_TYPE],
                FieldValue::Str(ct),
                header_range.clone(),
            );
        }

        let framing = match body_framing(&headers, status, &data[header_len..]) {
            Ok(framing) => framing,
            Err(e) => {
                let e = match e {
                    PacketError::Truncated { expected, .. } => PacketError::Truncated {
                        expected: header_len.saturating_add(expected),
                        actual: data.len(),
                    },
                    e => e,
                };
                if let Some(layer) = buf.last_layer_mut() {
                    layer.range = header_range;
                }
                buf.end_layer();
                return Err(e);
            }
        };

        if headers.transfer_encoding.is_some()
            && headers.content_length.is_some()
            && framing != BodyFraming::None
        {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_CONTENT_LENGTH_OVERRIDDEN],
                FieldValue::U8(1),
                header_range.clone(),
            );
        }
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_BODY_FRAMING],
            FieldValue::Str(framing.name()),
            header_range.clone(),
        );
        if let BodyFraming::Chunked { chunks, .. } = framing {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_CHUNK_COUNT],
                FieldValue::U32(chunks),
                header_range.clone(),
            );
        }

        let body_len = framing.len();
        let total = header_len + body_len;

        // RFC 9110, Section 8.3 — dispatch body by Content-Type.
        // https://www.rfc-editor.org/rfc/rfc9110#section-8.3
        // When dispatching to a body dissector the registry advances offset by
        // bytes_consumed before calling the next dissector, so we consume only
        // the header section here and let the body dissector start at the body.
        // A chunked body is not contiguous (chunk-size lines are interleaved),
        // so it is not dispatched.
        if body_len > 0 && !matches!(framing, BodyFraming::Chunked { .. }) {
            if let Some(interned) = content_type.and_then(intern_content_type) {
                if let Some(layer) = buf.last_layer_mut() {
                    layer.range = header_range;
                }
                buf.end_layer();
                return Ok(
                    DissectResult::new(header_len, DispatchHint::ByContentType(interned))
                        .with_payload_len(body_len),
                );
            }
        }

        if let Some(layer) = buf.last_layer_mut() {
            layer.range = offset..offset + total;
        }
        buf.end_layer();

        Ok(DissectResult::new(total, DispatchHint::End))
    }
}

/// How the end of a message body was determined.
///
/// RFC 9112, Section 6.3 — <https://www.rfc-editor.org/rfc/rfc9112#section-6.3>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    /// No body (request without length, or a 1xx / 204 / 304 response).
    None,
    /// Content-Length octets.
    ContentLength(usize),
    /// Chunked transfer coding occupying `len` octets with `chunks` data chunks.
    Chunked { len: usize, chunks: u32 },
    /// Response body delimited by connection close: the rest of the input.
    CloseDelimited(usize),
}

impl BodyFraming {
    fn name(self) -> &'static str {
        match self {
            BodyFraming::None => "none",
            BodyFraming::ContentLength(_) => "content-length",
            BodyFraming::Chunked { .. } => "chunked",
            BodyFraming::CloseDelimited(_) => "close-delimited",
        }
    }

    /// Number of octets the body occupies after the header section.
    fn len(self) -> usize {
        match self {
            BodyFraming::None => 0,
            BodyFraming::ContentLength(n) | BodyFraming::CloseDelimited(n) => n,
            BodyFraming::Chunked { len, .. } => len,
        }
    }
}

/// Framing-related header fields of a message.
#[derive(Debug, Default)]
struct FramingHeaders<'pkt> {
    /// The first Content-Type field value.
    content_type: Option<&'pkt str>,
    /// The message is HTTP/1.0.
    http10: bool,
    /// Content-Length: `Ok` with the value when all field lines and list
    /// members carry the same valid value, `Err` otherwise.
    content_length: Option<Result<u64, ()>>,
    /// Transfer-Encoding: whether the final transfer coding is chunked.
    transfer_encoding: Option<bool>,
}

/// Collect the version, Content-Type, Content-Length and Transfer-Encoding
/// from the fields already pushed for the current layer.
fn scan_framing_headers<'pkt>(buf: &DissectBuffer<'pkt>) -> FramingHeaders<'pkt> {
    let mut out = FramingHeaders {
        http10: buf
            .layers()
            .last()
            .and_then(|layer| {
                buf.fields()[layer.field_range.start as usize..]
                    .iter()
                    .find(|f| f.name() == "version")
            })
            .is_some_and(|f| f.value == FieldValue::Str("HTTP/1.0")),
        ..FramingHeaders::default()
    };
    for_each_header(buf, |name, value| {
        if name.eq_ignore_ascii_case("Content-Type") {
            // RFC 9110, Section 8.3 — https://www.rfc-editor.org/rfc/rfc9110#section-8.3
            if out.content_type.is_none() {
                out.content_type = core::str::from_utf8(value).ok();
            }
        } else if name.eq_ignore_ascii_case("Content-Length") {
            // RFC 9112, Section 6.3 rule 5 — a comma-separated list is
            // valid when "all values in the list are valid, and all values
            // in the list are the same".
            // https://www.rfc-editor.org/rfc/rfc9112#section-6.3
            let parsed = parse_content_length(value);
            out.content_length = Some(match (out.content_length, parsed) {
                (None, v) => v,
                (Some(Ok(a)), Ok(b)) if a == b => Ok(a),
                _ => Err(()),
            });
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            // RFC 9112, Section 6.1 — the final (last listed) transfer coding
            // decides the framing. https://www.rfc-editor.org/rfc/rfc9112#section-6.1
            if let Some(last) = value
                .split(|&b| b == b',')
                .map(|coding| {
                    let name = coding.split(|&b| b == b';').next().unwrap_or(coding);
                    trim_ows(name)
                })
                .rfind(|c| !c.is_empty())
            {
                out.transfer_encoding = Some(last.eq_ignore_ascii_case(b"chunked"));
            } else if out.transfer_encoding.is_none() {
                // Present but empty: not chunked.
                out.transfer_encoding = Some(false);
            }
        }
    });
    out
}

/// Parse a Content-Length field value (possibly a comma-separated list of
/// identical values). RFC 9110, Section 8.6 — `Content-Length = 1*DIGIT`
/// <https://www.rfc-editor.org/rfc/rfc9110#section-8.6>.
fn parse_content_length(value: &[u8]) -> Result<u64, ()> {
    let mut result = None;
    for member in value.split(|&b| b == b',') {
        let digits = trim_ows(member);
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return Err(());
        }
        let mut n: u64 = 0;
        for &d in digits {
            n = n
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(d - b'0')))
                .ok_or(())?;
        }
        match result {
            Some(prev) if prev != n => return Err(()),
            _ => result = Some(n),
        }
    }
    result.ok_or(())
}

/// Determine the body framing per RFC 9112, Section 6.3
/// <https://www.rfc-editor.org/rfc/rfc9112#section-6.3>. `body` is the input
/// after the header section; `status` is `Some` for responses.
///
/// `Truncated` errors are relative to `body`.
fn body_framing(
    headers: &FramingHeaders,
    status: Option<u16>,
    body: &[u8],
) -> Result<BodyFraming, PacketError> {
    // Rule 1 — "any response with a 1xx (Informational), 204 (No Content),
    // or 304 (Not Modified) status code is always terminated by the first
    // empty line after the header fields"
    if let Some(code) = status {
        if (100..200).contains(&code) || code == 204 || code == 304 {
            return Ok(BodyFraming::None);
        }
    }

    // Rules 3 and 4 — Transfer-Encoding overrides Content-Length.
    if let Some(chunked) = headers.transfer_encoding {
        // RFC 9112, Section 6.1 — "A server or client that receives an
        // HTTP/1.0 message containing a Transfer-Encoding header field MUST
        // treat the message as if the framing is faulty, even if a
        // Content-Length is present, and close the connection after
        // processing the message."
        // https://www.rfc-editor.org/rfc/rfc9112#section-6.1
        // A response is then read until the connection closes; a request
        // cannot be framed.
        if headers.http10 {
            return if status.is_some() {
                Ok(BodyFraming::CloseDelimited(body.len()))
            } else {
                Err(PacketError::InvalidHeader(
                    "Transfer-Encoding in HTTP/1.0 request",
                ))
            };
        }
        if chunked {
            let (len, chunks) = chunked_body_len(body)?;
            return Ok(BodyFraming::Chunked { len, chunks });
        }
        if status.is_some() {
            // "the message body length is determined by reading the
            // connection until it is closed by the server"
            return Ok(BodyFraming::CloseDelimited(body.len()));
        }
        // "the message body length cannot be determined reliably"
        return Err(PacketError::InvalidHeader(
            "Transfer-Encoding in request does not end with chunked",
        ));
    }

    match headers.content_length {
        // Rule 6 — Content-Length defines the body length.
        Some(Ok(cl)) => {
            let cl = usize::try_from(cl).unwrap_or(usize::MAX);
            if cl > body.len() {
                return Err(PacketError::Truncated {
                    expected: cl,
                    actual: body.len(),
                });
            }
            Ok(BodyFraming::ContentLength(cl))
        }
        // Rule 5 — "the message framing is invalid and the recipient MUST
        // treat it as an unrecoverable error"
        Some(Err(())) => Err(PacketError::InvalidHeader("invalid Content-Length")),
        // Rule 7 — a request without a declared length has no body.
        None if status.is_none() => Ok(BodyFraming::None),
        // Rule 8 — a response without a declared length runs until the
        // connection closes; within the dissected input, to its end.
        None => Ok(BodyFraming::CloseDelimited(body.len())),
    }
}

/// Find the end of the line starting at `pos` (LF, optionally preceded by
/// CR). Returns `(line_content_end, next_line_start)`.
///
/// RFC 9112, Section 2.2 — "a recipient MAY recognize a single LF as a line
/// terminator" <https://www.rfc-editor.org/rfc/rfc9112#section-2.2>.
fn line_at(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let lf = pos + data[pos..].iter().position(|&b| b == b'\n')?;
    let content_end = if lf > pos && data[lf - 1] == b'\r' {
        lf - 1
    } else {
        lf
    };
    Some((content_end, lf + 1))
}

/// Walk a chunked body and return the octets it occupies (through the
/// final empty line) and the number of data chunks.
///
/// RFC 9112, Section 7.1 — <https://www.rfc-editor.org/rfc/rfc9112#section-7.1>
///
/// ```text
/// chunked-body   = *chunk
///                  last-chunk
///                  trailer-section
///                  CRLF
/// chunk          = chunk-size [ chunk-ext ] CRLF
///                  chunk-data CRLF
/// ```
fn chunked_body_len(data: &[u8]) -> Result<(usize, u32), PacketError> {
    let more = |expected: usize| PacketError::Truncated {
        expected,
        actual: data.len(),
    };
    let mut pos = 0;
    let mut chunks: u32 = 0;
    loop {
        let (line_end, next) = line_at(data, pos).ok_or(more(data.len() + 1))?;
        let line = &data[pos..line_end];
        // chunk-ext starts at ";" (Section 7.1.1); "A recipient MUST ignore
        // unrecognized chunk extensions." BWS may precede it.
        let size_field = line.split(|&b| b == b';').next().unwrap_or(line);
        let size_field = trim_ows(size_field);
        let size = parse_chunk_size(size_field)?;
        pos = next;
        if size == 0 {
            break;
        }
        // chunk-data CRLF
        let data_end = pos
            .checked_add(size)
            .ok_or(PacketError::InvalidHeader("invalid chunk size"))?;
        pos = match data.get(data_end..) {
            // At least a bare LF (Section 2.2) is still missing.
            None | Some([]) => return Err(more(data_end.saturating_add(1))),
            Some([b'\r']) => return Err(more(data_end + 2)),
            Some([b'\n', ..]) => data_end + 1,
            Some([b'\r', b'\n', ..]) => data_end + 2,
            Some(_) => {
                return Err(PacketError::InvalidHeader(
                    "chunk data not followed by CRLF",
                ));
            }
        };
        chunks = chunks.saturating_add(1);
    }
    // trailer-section = *( field-line CRLF ), then the final CRLF.
    loop {
        let (line_end, next) = line_at(data, pos).ok_or(more(data.len() + 1))?;
        let empty = line_end == pos;
        pos = next;
        if empty {
            return Ok((pos, chunks));
        }
    }
}

/// Parse `chunk-size = 1*HEXDIG`, rejecting values that overflow `usize`.
///
/// RFC 9112, Section 7.1 — "recipients MUST anticipate potentially large
/// hexadecimal numerals and prevent parsing errors due to integer
/// conversion overflows" <https://www.rfc-editor.org/rfc/rfc9112#section-7.1>.
fn parse_chunk_size(field: &[u8]) -> Result<usize, PacketError> {
    let invalid = PacketError::InvalidHeader("invalid chunk size");
    if field.is_empty() {
        return Err(invalid);
    }
    let mut size: usize = 0;
    for &b in field {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(invalid),
        };
        size = size
            .checked_mul(16)
            .and_then(|s| s.checked_add(usize::from(digit)))
            .ok_or(PacketError::InvalidHeader("invalid chunk size"))?;
    }
    Ok(size)
}

/// Convert httparse version number (0 = HTTP/1.0, 1 = HTTP/1.1) to string.
fn version_str(v: u8) -> &'static str {
    match v {
        0 => "HTTP/1.0",
        1 => "HTTP/1.1",
        _ => "HTTP/1.x",
    }
}

/// Map an `httparse` error to a [`PacketError`]; `invalid` names the
/// start-line kind for all errors other than a header count overflow.
fn map_httparse_error(e: httparse::Error, invalid: &'static str) -> PacketError {
    match e {
        httparse::Error::TooManyHeaders => {
            PacketError::InvalidHeader("too many HTTP header fields")
        }
        _ => PacketError::InvalidHeader(invalid),
    }
}

/// Parse an HTTP request using httparse, populating fields in the buffer.
/// Returns the total header length (including final CRLF).
///
/// A small stack array is tried first; a message with more than
/// [`MAX_HEADERS`] fields is parsed again with a larger stack array, so
/// dissection stays allocation-free.
fn parse_request<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<usize, PacketError> {
    match parse_request_with::<MAX_HEADERS>(data, offset, buf) {
        Err(httparse::Error::TooManyHeaders) => {
            parse_request_with::<MAX_HEADERS_LARGE>(data, offset, buf)
        }
        other => other,
    }
    .map_err(|e| map_httparse_error(e, "invalid HTTP request line"))?
}

/// [`parse_request`] with room for `N` header fields. The outer `Result`
/// carries `httparse` errors so the caller can retry on `TooManyHeaders`.
/// Never inlined, so the large array only occupies the stack when used.
#[inline(never)]
fn parse_request_with<'pkt, const N: usize>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<Result<usize, PacketError>, httparse::Error> {
    let mut headers_buf = [httparse::EMPTY_HEADER; N];
    let mut req = httparse::Request::new(&mut headers_buf);

    let header_len = match req.parse(data)? {
        httparse::Status::Complete(len) => len,
        httparse::Status::Partial => {
            return Ok(Err(PacketError::Truncated {
                expected: data.len() + 1,
                actual: data.len(),
            }));
        }
    };
    Ok(push_request_fields(data, offset, &req, header_len, buf).map(|()| header_len))
}

/// Push the request-line and header fields of a parsed request.
fn push_request_fields<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    req: &httparse::Request<'_, 'pkt>,
    header_len: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    // RFC 9112, Section 3 — method
    if let Some(method) = req.method {
        let start = str_offset(data, method)?;
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_METHOD],
            FieldValue::Str(method),
            offset + start..offset + start + method.len(),
        );
    }

    // RFC 9112, Section 3 — request-target
    if let Some(path) = req.path {
        let start = str_offset(data, path)?;
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_URI],
            FieldValue::Str(path),
            offset + start..offset + start + path.len(),
        );
    }

    // RFC 9112, Section 2.3 — HTTP-version
    if let Some(version) = req.version {
        let vs = version_str(version);
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::Str(vs),
            offset..offset + header_len,
        );
    }

    // RFC 9112, Section 5 — header fields
    build_header_fields(data, offset, req.headers, buf)
}

/// Parse an HTTP response using httparse, populating fields in the buffer.
/// Returns the total header length (including final CRLF) and the status
/// code. Retries with a larger header array like [`parse_request`].
fn parse_response<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(usize, u16), PacketError> {
    match parse_response_with::<MAX_HEADERS>(data, offset, buf) {
        Err(httparse::Error::TooManyHeaders) => {
            parse_response_with::<MAX_HEADERS_LARGE>(data, offset, buf)
        }
        other => other,
    }
    .map_err(|e| map_httparse_error(e, "invalid HTTP status line"))?
}

/// [`parse_response`] with room for `N` header fields.
#[inline(never)]
fn parse_response_with<'pkt, const N: usize>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<Result<(usize, u16), PacketError>, httparse::Error> {
    let mut headers_buf = [httparse::EMPTY_HEADER; N];
    let mut resp = httparse::Response::new(&mut headers_buf);

    let header_len = match resp.parse(data)? {
        httparse::Status::Complete(len) => len,
        httparse::Status::Partial => {
            return Ok(Err(PacketError::Truncated {
                expected: data.len() + 1,
                actual: data.len(),
            }));
        }
    };
    // A complete status-line always carries a status code.
    let code = resp.code.unwrap_or(0);
    Ok(push_response_fields(data, offset, &resp, header_len, buf).map(|()| (header_len, code)))
}

/// Push the status-line and header fields of a parsed response.
fn push_response_fields<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    resp: &httparse::Response<'_, 'pkt>,
    header_len: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    // RFC 9112, Section 2.3 — HTTP-version
    if let Some(version) = resp.version {
        let vs = version_str(version);
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::Str(vs),
            offset..offset + header_len,
        );
    }

    // RFC 9112, Section 4 — status-code
    if let Some(code) = resp.code {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_STATUS_CODE],
            FieldValue::U16(code),
            offset..offset + header_len,
        );
    }

    // RFC 9112, Section 4 — reason-phrase
    if let Some(reason) = resp.reason {
        if !reason.is_empty() {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_REASON_PHRASE],
                FieldValue::Str(reason),
                offset..offset + header_len,
            );
        }
    }

    // RFC 9112, Section 5 — header fields
    build_header_fields(data, offset, resp.headers, buf)
}

/// Convert httparse headers into container fields in the buffer, with OWS trimming.
fn build_header_fields<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    headers: &[httparse::Header<'pkt>],
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    if headers.is_empty() {
        return Ok(());
    }

    // Compute the overall headers range from first to last header
    // SAFETY of indexing: `is_empty()` check above guarantees at least one header.
    let first_header = &headers[0];
    let last_header = &headers[headers.len() - 1];
    let first_name_start = str_offset(data, first_header.name)? + offset;
    let last_value_end = slice_offset(data, last_header.value)? + last_header.value.len() + offset;

    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_HEADERS],
        FieldValue::Array(0..0),
        first_name_start..last_value_end,
    );

    for header in headers {
        let name = header.name;
        let trimmed_value = trim_ows(header.value);
        // RFC 9110, Section 5.5 — field values may contain obs-text
        // (%x80-FF) <https://www.rfc-editor.org/rfc/rfc9110#section-5.5>;
        // such values are kept as raw bytes.
        let value = match core::str::from_utf8(trimmed_value) {
            Ok(v) => FieldValue::Str(v),
            Err(_) => FieldValue::Bytes(trimmed_value),
        };

        // Compute byte range from the header name position in data
        let name_start = str_offset(data, name)?;
        let value_end = slice_offset(data, header.value)? + header.value.len();
        let header_range = offset + name_start..offset + value_end;

        let obj_idx =
            buf.begin_container(&FD_HEADER, FieldValue::Object(0..0), header_range.clone());
        buf.push_field(
            &HEADER_CHILDREN[HC_NAME],
            FieldValue::Str(name),
            header_range.clone(),
        );
        buf.push_field(&HEADER_CHILDREN[HC_VALUE], value, header_range);
        buf.end_container(obj_idx);
    }

    buf.end_container(array_idx);

    Ok(())
}

/// Call `f(name, value)` for every header field of the layer under
/// construction, in order. Values kept as raw bytes (obs-text) are passed
/// as-is.
fn for_each_header<'pkt>(buf: &DissectBuffer<'pkt>, mut f: impl FnMut(&'pkt str, &'pkt [u8])) {
    let Some(layer) = buf.layers().last() else {
        return;
    };
    let fields = &buf.fields()[layer.field_range.start as usize..];
    let Some(FieldValue::Array(array_range)) = fields
        .iter()
        .find(|f| f.name() == "headers")
        .map(|f| &f.value)
    else {
        return;
    };
    for field in buf.nested_fields(array_range) {
        let FieldValue::Object(ref obj_range) = field.value else {
            continue;
        };
        let obj_fields = buf.nested_fields(obj_range);
        let name = obj_fields.iter().find_map(|f| match f.value {
            FieldValue::Str(n) if f.name() == "name" => Some(n),
            _ => None,
        });
        let value = obj_fields.iter().find_map(|f| match f.value {
            FieldValue::Str(v) if f.name() == "value" => Some(v.as_bytes()),
            FieldValue::Bytes(v) if f.name() == "value" => Some(v),
            _ => None,
        });
        if let (Some(name), Some(value)) = (name, value) {
            f(name, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 9112 (HTTP/1.1) & RFC 9110 (HTTP Semantics) Coverage
    //
    // | RFC Section   | Description           | Test                                    |
    // |---------------|-----------------------|-----------------------------------------|
    // | 9112 2.1      | Message Format        | parse_http_request_basic                |
    // | 9112 2.2      | Bare LF terminators   | parse_http_request_bare_lf              |
    // | 9112 2.2      | Bare LF in response   | parse_http_response_bare_lf             |
    // | 9112 3        | Request Line          | parse_http_request_basic                |
    // | 9112 3        | Method token          | parse_http_post_request                 |
    // | 9112 4        | Status Line           | parse_http_response_basic               |
    // | 9112 4        | Reason Phrase          | parse_http_response_no_reason           |
    // | 9112 4        | Invalid status-line   | parse_http_response_invalid_status      |
    // | 9112 5        | Header Fields         | parse_http_request_with_headers         |
    // | 9112 5        | Empty header name     | parse_http_empty_header_name            |
    // | 9112 6.2      | Content-Length        | parse_http_request_with_body            |
    // | 9110 8.3      | CT dispatch (request) | parse_http_post_content_type_dispatch   |
    // | 9110 8.3      | CT dispatch (response)| parse_http_response_content_type_dispatch|
    // | 9110 8.3      | CT param stripping    | parse_http_content_type_with_params     |
    // | 9110 8.3      | CT case insensitive   | parse_http_content_type_case_insensitive|
    // | -             | No CT body fallback   | parse_http_no_content_type_with_body    |
    // | -             | No body w/ CT → End   | parse_http_no_body_with_content_type    |
    // | -             | Truncated             | parse_http_truncated                    |
    // | -             | Invalid header        | parse_http_invalid_request_line         |
    // | 9112 6.3 r1   | 1xx/204/304 no body   | bodyless_status_codes_ignore_content_length |
    // | 9112 6.3 r3   | TE overrides CL       | transfer_encoding_overrides_content_length |
    // | 9112 6.3 r4   | Chunked body          | chunked_body_single_chunk               |
    // | 9112 6.3 r4   | Chunked, hex size     | chunked_body_hex_size                   |
    // | 9112 7.1.1    | Chunk extensions      | chunked_body_with_extension_and_trailer |
    // | 9112 7.1.2    | Trailer section       | chunked_body_with_extension_and_trailer |
    // | 9112 7.1      | Incomplete chunked    | chunked_body_truncated                  |
    // | 9112 7.1      | Invalid chunk size    | chunked_body_invalid_size               |
    // | 9112 7.1      | Missing chunk CRLF    | chunked_body_missing_crlf               |
    // | 9112 6.3 r4   | Non-chunked TE (resp) | non_chunked_transfer_encoding_response_is_close_delimited |
    // | 9112 6.3 r4   | Non-chunked TE (req)  | non_chunked_transfer_encoding_request_is_error |
    // | 9112 6.3 r5   | Invalid Content-Length| invalid_content_length_is_error         |
    // | 9112 6.1      | TE in HTTP/1.0        | http10_transfer_encoding_is_faulty      |
    // | 9112 6.1      | Empty Transfer-Encoding| empty_transfer_encoding_is_not_chunked |
    // | 9112 6.3 r1   | 304 with TE and CL    | bodyless_status_does_not_flag_override  |
    // | 9112 7.1      | Huge sizes, no overflow| huge_lengths_do_not_overflow           |
    // | 9112 6.3 r5   | Same-valued CL list   | content_length_list_with_same_values    |
    // | 9112 6.3 r5   | Differing CL lines    | differing_content_length_lines_are_error|
    // | 9112 6.3 r7   | Request without length| request_without_length_has_no_body      |
    // | 9112 6.3 r8   | Close-delimited resp  | close_delimited_response_body_runs_to_end |
    // | 9112 6.3 r8   | Close-delimited + CT  | close_delimited_response_dispatches_content_type |
    // | 9110 5.5      | obs-text field value  | obs_text_header_value_is_kept           |
    // | 9112 5        | More than 64 headers  | many_headers_are_all_parsed             |
    // | 9112 5        | Header limit error    | too_many_headers_error                  |

    fn dissect(data: &[u8]) -> Result<DissectBuffer<'_>, PacketError> {
        let dissector = HttpDissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(data, &mut buf, 0)?;
        Ok(buf)
    }

    fn dissect_err(data: &[u8]) -> PacketError {
        let dissector = HttpDissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(data, &mut buf, 0).unwrap_err()
    }

    #[test]
    fn parse_http_request_basic() {
        let data = b"GET / HTTP/1.1\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "is_response").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "method").unwrap().value,
            FieldValue::Str("GET")
        );
        assert_eq!(
            buf.field_by_name(layer, "uri").unwrap().value,
            FieldValue::Str("/")
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::Str("HTTP/1.1")
        );
        assert!(buf.field_by_name(layer, "status_code").is_none());
    }

    #[test]
    fn header_container_descriptor_distinct_from_inner_name() {
        // The per-header Object container must use a descriptor distinct
        // from the inner `name` child so that the outer display label does
        // not collide with the child's "Name" label.
        let data = b"GET / HTTP/1.1\r\nContent-Type: text/html\r\n\r\n";
        let buf = dissect(data).unwrap();

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
    fn parse_http_post_request() {
        let body = b"key=value";
        let header = b"POST /submit HTTP/1.1\r\nContent-Length: 9\r\n\r\n";
        let mut data = Vec::new();
        data.extend_from_slice(header);
        data.extend_from_slice(body);

        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "method").unwrap().value,
            FieldValue::Str("POST")
        );
        assert_eq!(
            buf.field_by_name(layer, "uri").unwrap().value,
            FieldValue::Str("/submit")
        );
        assert_eq!(
            buf.field_by_name(layer, "content_length").unwrap().value,
            FieldValue::U32(9)
        );
        assert_eq!(layer.range, 0..data.len());
    }

    #[test]
    fn parse_http_response_basic() {
        let data = b"HTTP/1.1 200 OK\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "is_response").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::Str("HTTP/1.1")
        );
        assert_eq!(
            buf.field_by_name(layer, "status_code").unwrap().value,
            FieldValue::U16(200)
        );
        assert_eq!(
            buf.field_by_name(layer, "reason_phrase").unwrap().value,
            FieldValue::Str("OK")
        );
        assert!(buf.field_by_name(layer, "method").is_none());
    }

    #[test]
    fn parse_http_response_no_reason() {
        let data = b"HTTP/1.1 204\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "status_code").unwrap().value,
            FieldValue::U16(204)
        );
        assert!(buf.field_by_name(layer, "reason_phrase").is_none());
    }

    #[test]
    fn parse_http_request_with_headers() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();

        let headers_field = buf.field_by_name(layer, "headers").unwrap();
        let array_range = match &headers_field.value {
            FieldValue::Array(r) => r,
            _ => panic!("expected Array"),
        };

        let children = buf.nested_fields(array_range);
        // Find all Object entries
        let objects: Vec<_> = children.iter().filter(|f| f.value.is_object()).collect();
        assert_eq!(objects.len(), 2);

        if let FieldValue::Object(ref r) = objects[0].value {
            let obj_fields = buf.nested_fields(r);
            assert_eq!(obj_fields[0].value, FieldValue::Str("Host"));
            assert_eq!(obj_fields[1].value, FieldValue::Str("example.com"));
        }

        if let FieldValue::Object(ref r) = objects[1].value {
            let obj_fields = buf.nested_fields(r);
            assert_eq!(obj_fields[0].value, FieldValue::Str("Accept"));
            assert_eq!(obj_fields[1].value, FieldValue::Str("text/html"));
        }
    }

    #[test]
    fn parse_http_request_with_body() {
        let body = b"Hello, World!";
        let header = b"POST /api HTTP/1.1\r\nContent-Length: 13\r\n\r\n";
        let mut data = Vec::new();
        data.extend_from_slice(header);
        data.extend_from_slice(body);

        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "content_length").unwrap().value,
            FieldValue::U32(13)
        );
        // Layer range should encompass headers + body
        assert_eq!(layer.range, 0..data.len());
    }

    fn framing<'a>(buf: &'a DissectBuffer<'_>) -> Option<&'a str> {
        let layer = buf.layer_by_name("HTTP").unwrap();
        buf.field_str(layer, "body_framing")
    }

    fn consumed(data: &[u8]) -> usize {
        let mut buf = DissectBuffer::new();
        HttpDissector
            .dissect(data, &mut buf, 0)
            .unwrap()
            .bytes_consumed
    }

    #[test]
    fn bodyless_status_codes_ignore_content_length() {
        for status in ["100 Continue", "204 No Content", "304 Not Modified"] {
            let data = format!("HTTP/1.1 {status}\r\nContent-Length: 1234\r\n\r\n");
            let buf = dissect(data.as_bytes()).unwrap();
            assert_eq!(framing(&buf), Some("none"), "{status}");
            assert_eq!(consumed(data.as_bytes()), data.len(), "{status}");
        }
    }

    #[test]
    fn chunked_body_single_chunk() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let mut buf = DissectBuffer::new();
        let result = HttpDissector.dissect(data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(framing(&buf), Some("chunked"));
        let layer = buf.layer_by_name("HTTP").unwrap();
        assert_eq!(buf.field_u32(layer, "chunk_count"), Some(1));
        assert_eq!(layer.range, 0..data.len());
    }

    #[test]
    fn chunked_body_hex_size() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n\
                     1a\r\nabcdefghijklmnopqrstuvwxyz\r\nA\r\n0123456789\r\n0\r\n\r\n";
        assert_eq!(consumed(data), data.len());
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();
        assert_eq!(buf.field_u32(layer, "chunk_count"), Some(2));
    }

    #[test]
    fn chunked_body_with_extension_and_trailer() {
        let data = b"POST /u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                     3;name=\"v\"\r\nabc\r\n0 ; last\r\nX-Checksum: 1\r\nX-Other: 2\r\n\r\n";
        assert_eq!(consumed(data), data.len());
    }

    #[test]
    fn chunked_body_truncated() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut data = head.to_vec();
        data.extend_from_slice(b"10\r\nabc");
        let err = dissect_err(&data);
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: head.len() + 4 + 16 + 1,
                actual: data.len()
            }
        );
        for tail in [
            &b"5\r\nhello\r\n"[..],
            b"5\r\nhello\r\n0\r\n",
            b"5",
            b"5\r\nhello\r",
        ] {
            let mut data = head.to_vec();
            data.extend_from_slice(tail);
            let err = dissect_err(&data);
            assert!(
                matches!(err, PacketError::Truncated { actual, .. } if actual == data.len()),
                "{err:?}"
            );
        }
    }

    #[test]
    fn chunked_body_invalid_size() {
        for body in [&b"zz\r\n"[..], b"\r\n", b"fffffffffffffffffffff\r\n"] {
            let mut data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            data.extend_from_slice(body);
            assert_eq!(
                dissect_err(&data),
                PacketError::InvalidHeader("invalid chunk size")
            );
        }
    }

    #[test]
    fn chunked_body_missing_crlf() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n0\r\n\r\n";
        assert_eq!(
            dissect_err(data),
            PacketError::InvalidHeader("chunk data not followed by CRLF")
        );
    }

    #[test]
    fn transfer_encoding_overrides_content_length() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n\
                     5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(consumed(data), data.len());
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();
        assert_eq!(framing(&buf), Some("chunked"));
        assert_eq!(buf.field_u8(layer, "content_length_overridden"), Some(1));
    }

    #[test]
    fn non_chunked_transfer_encoding_response_is_close_delimited() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n\x1f\x8b\x08\x00";
        assert_eq!(consumed(data), data.len());
        let buf = dissect(data).unwrap();
        assert_eq!(framing(&buf), Some("close-delimited"));
    }

    #[test]
    fn non_chunked_transfer_encoding_request_is_error() {
        let data = b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\nxx";
        assert_eq!(
            dissect_err(data),
            PacketError::InvalidHeader("Transfer-Encoding in request does not end with chunked")
        );
    }

    #[test]
    fn invalid_content_length_is_error() {
        for cl in ["abc", "-1", "1 2", "99999999999999999999999", ""] {
            let data = format!("HTTP/1.1 200 OK\r\nContent-Length: {cl}\r\n\r\n");
            assert_eq!(
                dissect_err(data.as_bytes()),
                PacketError::InvalidHeader("invalid Content-Length"),
                "{cl}"
            );
        }
    }

    #[test]
    fn http10_transfer_encoding_is_faulty() {
        let data = b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\nrest";
        assert_eq!(consumed(data), data.len());
        let buf = dissect(data).unwrap();
        assert_eq!(framing(&buf), Some("close-delimited"));

        let req = b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert_eq!(
            dissect_err(req),
            PacketError::InvalidHeader("Transfer-Encoding in HTTP/1.0 request")
        );
    }

    #[test]
    fn empty_transfer_encoding_is_not_chunked() {
        let data = b"POST / HTTP/1.1\r\nTransfer-Encoding: ,\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(
            dissect_err(data),
            PacketError::InvalidHeader("Transfer-Encoding in request does not end with chunked")
        );
    }

    #[test]
    fn bodyless_status_does_not_flag_override() {
        let data = b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();
        assert!(
            buf.field_by_name(layer, "content_length_overridden")
                .is_none()
        );
        assert_eq!(framing(&buf), Some("none"));
    }

    #[test]
    fn huge_lengths_do_not_overflow() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n";
        assert!(matches!(
            dissect_err(data),
            PacketError::Truncated {
                expected: usize::MAX,
                ..
            }
        ));
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffed\r\n";
        assert!(matches!(dissect_err(data), PacketError::Truncated { .. }));
        // Bare-LF chunk data cut right after the data needs one more byte.
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut data = head.to_vec();
        data.extend_from_slice(b"5\nhello");
        assert_eq!(
            dissect_err(&data),
            PacketError::Truncated {
                expected: data.len() + 1,
                actual: data.len()
            }
        );
    }

    #[test]
    fn content_length_list_with_same_values() {
        let data = b"POST / HTTP/1.1\r\nContent-Length: 3, 3\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(consumed(data), data.len());
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();
        assert_eq!(buf.field_u32(layer, "content_length"), Some(3));
    }

    #[test]
    fn differing_content_length_lines_are_error() {
        let data = b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd";
        assert_eq!(
            dissect_err(data),
            PacketError::InvalidHeader("invalid Content-Length")
        );
    }

    #[test]
    fn request_without_length_has_no_body() {
        let data = b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\n\r\n";
        assert_eq!(consumed(data), 27);
        let buf = dissect(data).unwrap();
        assert_eq!(framing(&buf), Some("none"));
    }

    #[test]
    fn close_delimited_response_body_runs_to_end() {
        let data = b"HTTP/1.0 200 OK\r\nServer: x\r\n\r\nhello world body";
        assert_eq!(consumed(data), data.len());
        let buf = dissect(data).unwrap();
        assert_eq!(framing(&buf), Some("close-delimited"));
        let layer = buf.layer_by_name("HTTP").unwrap();
        assert_eq!(layer.range, 0..data.len());
    }

    #[test]
    fn close_delimited_response_dispatches_content_type() {
        let head = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n";
        let mut data = head.to_vec();
        data.extend_from_slice(b"{}");
        let mut buf = DissectBuffer::new();
        let result = HttpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, head.len());
        assert_eq!(result.next, DispatchHint::ByContentType("application/json"));
        assert_eq!(result.payload_len, Some(2));
    }

    #[test]
    fn obs_text_header_value_is_kept() {
        let data = b"HTTP/1.1 200 OK\r\nX-Name: caf\xe9\r\nContent-Length: 0\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();
        let FieldValue::Array(ref headers) = buf.field_by_name(layer, "headers").unwrap().value
        else {
            panic!("headers is not an array");
        };
        let values: Vec<_> = buf
            .nested_fields(headers)
            .iter()
            .filter(|f| f.name() == "value")
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(values[0], FieldValue::Bytes(b"caf\xe9"));
        assert_eq!(values[1], FieldValue::Str("0"));
        assert_eq!(buf.field_u32(layer, "content_length"), Some(0));
    }

    fn response_with_headers(n: usize) -> Vec<u8> {
        let mut data = b"HTTP/1.1 200 OK\r\n".to_vec();
        for i in 0..n {
            data.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
        }
        data.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        data
    }

    #[test]
    fn many_headers_are_all_parsed() {
        let data = response_with_headers(65);
        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();
        let FieldValue::Array(ref headers) = buf.field_by_name(layer, "headers").unwrap().value
        else {
            panic!("headers is not an array");
        };
        let count = buf
            .nested_fields(headers)
            .iter()
            .filter(|f| f.value.is_object())
            .count();
        assert_eq!(count, 66);
        assert_eq!(consumed(&data), data.len());

        let mut req = b"GET / HTTP/1.1\r\n".to_vec();
        req.extend_from_slice(&data[b"HTTP/1.1 200 OK\r\n".len()..]);
        assert_eq!(consumed(&req), req.len());
    }

    #[test]
    fn too_many_headers_error() {
        let data = response_with_headers(MAX_HEADERS_LARGE);
        assert_eq!(
            dissect_err(&data),
            PacketError::InvalidHeader("too many HTTP header fields")
        );
    }

    #[test]
    fn parse_http_truncated() {
        let data = b"GET /";
        assert!(matches!(dissect_err(data), PacketError::Truncated { .. }));
    }

    #[test]
    fn parse_http_truncated_headers() {
        // Start-line complete but headers not terminated
        let data = b"GET / HTTP/1.1\r\nHost: example.com";
        assert!(matches!(dissect_err(data), PacketError::Truncated { .. }));
    }

    #[test]
    fn parse_http_truncated_body() {
        // Headers indicate 100 bytes body but only 5 present
        let data = b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nHello";
        assert!(matches!(dissect_err(data), PacketError::Truncated { .. }));
    }

    #[test]
    fn parse_http_invalid_request_line() {
        // Missing SP between method and URI (must be >= MIN_START_LINE_LEN bytes)
        let data = b"INVALIDREQUESTLINE\r\n\r\n";
        assert!(matches!(dissect_err(data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_http_header_ows_trimming() {
        // RFC 9112, Section 5.1 — OWS around field-value
        let data = b"GET / HTTP/1.1\r\nHost:   example.com  \r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();

        let headers_field = buf.field_by_name(layer, "headers").unwrap();
        if let FieldValue::Array(ref r) = headers_field.value {
            let children = buf.nested_fields(r);
            let obj = children.iter().find(|f| f.value.is_object()).unwrap();
            if let FieldValue::Object(ref obj_r) = obj.value {
                let obj_fields = buf.nested_fields(obj_r);
                assert_eq!(obj_fields[1].value, FieldValue::Str("example.com"));
            }
        }
    }

    #[test]
    fn parse_http_response_with_body() {
        let body = b"<html></html>";
        let header = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n";
        let mut data = Vec::new();
        data.extend_from_slice(header);
        data.extend_from_slice(body);

        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "status_code").unwrap().value,
            FieldValue::U16(200)
        );
        assert_eq!(
            buf.field_by_name(layer, "content_length").unwrap().value,
            FieldValue::U32(13)
        );
        assert_eq!(layer.range, 0..data.len());
    }

    #[test]
    fn parse_http_with_offset() {
        let data = b"GET / HTTP/1.1\r\n\r\n";
        let dissector = HttpDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(data, &mut buf, 42).unwrap();

        let layer = buf.layer_by_name("HTTP").unwrap();
        assert_eq!(layer.range.start, 42);
        assert_eq!(layer.range.end, 42 + data.len());
        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn parse_http_request_bare_lf() {
        // RFC 9112, Section 2.2 — recipient MAY recognize bare LF as line terminator
        let data = b"GET / HTTP/1.1\nHost: example.com\n\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "method").unwrap().value,
            FieldValue::Str("GET")
        );
        let headers_field = buf.field_by_name(layer, "headers").unwrap();
        if let FieldValue::Array(ref r) = headers_field.value {
            let children = buf.nested_fields(r);
            let obj = children.iter().find(|f| f.value.is_object()).unwrap();
            if let FieldValue::Object(ref obj_r) = obj.value {
                let obj_fields = buf.nested_fields(obj_r);
                assert_eq!(obj_fields[1].value, FieldValue::Str("example.com"));
            }
        }
    }

    #[test]
    fn parse_http_response_bare_lf() {
        // RFC 9112, Section 2.2 — bare LF in response
        let data = b"HTTP/1.1 200 OK\nContent-Length: 2\n\nhi";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("HTTP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "status_code").unwrap().value,
            FieldValue::U16(200)
        );
        assert_eq!(
            buf.field_by_name(layer, "content_length").unwrap().value,
            FieldValue::U32(2)
        );
    }

    #[test]
    fn parse_http_response_invalid_status() {
        // "200OK" without SP after status-code should be rejected
        let data = b"HTTP/1.1 200OK\r\n\r\n";
        assert!(matches!(dissect_err(data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_http_empty_header_name() {
        // Empty header field name (colon at position 0) should be rejected per RFC 9112
        let data = b"GET / HTTP/1.1\r\n: value\r\n\r\n";
        assert!(matches!(dissect_err(data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_http_post_content_type_dispatch() {
        let body = b"{\"key\":\"value\"}";
        let header =
            b"POST /api HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n";
        let mut data = Vec::new();
        data.extend_from_slice(header);
        data.extend_from_slice(body);

        let dissector = HttpDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::ByContentType("application/json"));
        assert_eq!(result.bytes_consumed, header.len());

        let layer = buf.layer_by_name("HTTP").unwrap();
        assert_eq!(layer.range, 0..header.len());
        assert_eq!(
            buf.field_by_name(layer, "content_type").unwrap().value,
            FieldValue::Str("application/json")
        );
    }

    #[test]
    fn parse_http_response_content_type_dispatch() {
        let body = b"<html></html>";
        let header = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n";
        let mut data = Vec::new();
        data.extend_from_slice(header);
        data.extend_from_slice(body);

        let dissector = HttpDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::ByContentType("text/html"));
        assert_eq!(result.bytes_consumed, header.len());

        let layer = buf.layer_by_name("HTTP").unwrap();
        assert_eq!(layer.range, 0..header.len());
    }

    #[test]
    fn parse_http_content_type_with_params() {
        let body = b"{\"a\":1}";
        let header = b"POST /api HTTP/1.1\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 7\r\n\r\n";
        let mut data = Vec::new();
        data.extend_from_slice(header);
        data.extend_from_slice(body);

        let dissector = HttpDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        // Dispatch MIME has parameters stripped
        assert_eq!(result.next, DispatchHint::ByContentType("application/json"));

        // Field stores the raw value including parameters
        let layer = buf.layer_by_name("HTTP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "content_type").unwrap().value,
            FieldValue::Str("application/json; charset=utf-8")
        );
    }

    #[test]
    fn parse_http_content_type_case_insensitive() {
        let body = b"{\"a\":1}";
        let header =
            b"POST /api HTTP/1.1\r\nContent-Type: Application/JSON\r\nContent-Length: 7\r\n\r\n";
        let mut data = Vec::new();
        data.extend_from_slice(header);
        data.extend_from_slice(body);

        let dissector = HttpDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        // Dispatch MIME is interned to lowercase
        assert_eq!(result.next, DispatchHint::ByContentType("application/json"));
    }

    #[test]
    fn parse_http_no_content_type_with_body() {
        let body = b"key=value";
        let header = b"POST /submit HTTP/1.1\r\nContent-Length: 9\r\n\r\n";
        let mut data = Vec::new();
        data.extend_from_slice(header);
        data.extend_from_slice(body);

        let dissector = HttpDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(result.bytes_consumed, data.len());

        let layer = buf.layer_by_name("HTTP").unwrap();
        assert_eq!(layer.range, 0..data.len());
        assert!(buf.field_by_name(layer, "content_type").is_none());
    }

    #[test]
    fn parse_http_no_body_with_content_type() {
        let data = b"GET / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n";

        let dissector = HttpDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("HTTP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "content_type").unwrap().value,
            FieldValue::Str("text/plain")
        );
    }

    #[test]
    fn dissector_metadata() {
        let d = HttpDissector;
        assert_eq!(d.name(), "HyperText Transfer Protocol");
        assert_eq!(d.short_name(), "HTTP");
        assert!(!d.field_descriptors().is_empty());
    }

    #[test]
    fn test_references_and_layer() {
        let dissector = HttpDissector;
        let refs = dissector.references();
        assert!(!refs.is_empty());
        for r in refs {
            assert!(!r.id.is_empty());
            assert!(r.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Application));
    }
}
