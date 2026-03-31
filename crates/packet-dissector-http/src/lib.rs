//! HTTP/1.1 dissector.
//!
//! Parses HTTP/1.1 request and response messages as defined in RFC 9112.
//! Uses the [`httparse`] crate for robust, zero-copy start-line and header
//! parsing, then handles Content-Length body framing on top.
//!
//! ## References
//! - RFC 9112: HTTP/1.1 <https://www.rfc-editor.org/rfc/rfc9112>
//! - RFC 9110: HTTP Semantics <https://www.rfc-editor.org/rfc/rfc9110>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{intern_content_type, slice_offset, str_offset, trim_ows};

/// Maximum number of HTTP headers to parse.
const MAX_HEADERS: usize = 64;

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

/// Child descriptor indices for [`HEADER_CHILDREN`].
const HC_NAME: usize = 0;
const HC_VALUE: usize = 1;

/// Child descriptors for each header entry object.
static HEADER_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("name", "Name", FieldType::Str),
    FieldDescriptor::new("value", "Value", FieldType::Str),
];

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

        let header_len = if is_response {
            parse_response(data, offset, buf)?
        } else {
            parse_request(data, offset, buf)?
        };

        // Extract Content-Length and Content-Type from parsed headers
        let content_length =
            extract_header_value(buf, "Content-Length").and_then(|v| v.parse::<u32>().ok());
        let content_type = extract_header_value(buf, "Content-Type");

        if let Some(cl) = content_length {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_CONTENT_LENGTH],
                FieldValue::U32(cl),
                offset..offset + header_len,
            );
        }

        if let Some(ct) = content_type {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_CONTENT_TYPE],
                FieldValue::Str(ct),
                offset..offset + header_len,
            );
        }

        // Calculate total bytes consumed: headers + body
        let body_len = content_length.unwrap_or(0) as usize;
        let total = header_len + body_len;

        if total > data.len() {
            // End the layer before returning error
            if let Some(layer) = buf.last_layer_mut() {
                layer.range = offset..offset + header_len;
            }
            buf.end_layer();
            return Err(PacketError::Truncated {
                expected: total,
                actual: data.len(),
            });
        }

        // RFC 9110, Section 8.3 — dispatch body by Content-Type.
        // https://www.rfc-editor.org/rfc/rfc9110#section-8.3
        // When dispatching to a body dissector the registry advances offset by
        // bytes_consumed before calling the next dissector, so we consume only
        // the header section here and let the body dissector start at the body.
        if body_len > 0 {
            if let Some(ct) = extract_header_value(buf, "Content-Type") {
                if let Some(interned) = intern_content_type(ct) {
                    if let Some(layer) = buf.last_layer_mut() {
                        layer.range = offset..offset + header_len;
                    }
                    buf.end_layer();
                    return Ok(DissectResult::new(
                        header_len,
                        DispatchHint::ByContentType(interned),
                    ));
                }
            }
        }

        if let Some(layer) = buf.last_layer_mut() {
            layer.range = offset..offset + total;
        }
        buf.end_layer();

        Ok(DissectResult::new(total, DispatchHint::End))
    }
}

/// Convert httparse version number (0 = HTTP/1.0, 1 = HTTP/1.1) to string.
fn version_str(v: u8) -> &'static str {
    match v {
        0 => "HTTP/1.0",
        1 => "HTTP/1.1",
        _ => "HTTP/1.x",
    }
}

/// Parse an HTTP request using httparse, populating fields in the buffer.
/// Returns the total header length (including final CRLF).
fn parse_request<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<usize, PacketError> {
    let mut headers_buf = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers_buf);

    let header_len = match req.parse(data) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => {
            return Err(PacketError::Truncated {
                expected: data.len() + 1,
                actual: data.len(),
            });
        }
        Err(_) => {
            return Err(PacketError::InvalidHeader("invalid HTTP request line"));
        }
    };

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
    build_header_fields(data, offset, req.headers, buf)?;

    Ok(header_len)
}

/// Parse an HTTP response using httparse, populating fields in the buffer.
/// Returns the total header length (including final CRLF).
fn parse_response<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<usize, PacketError> {
    let mut headers_buf = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers_buf);

    let header_len = match resp.parse(data) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => {
            return Err(PacketError::Truncated {
                expected: data.len() + 1,
                actual: data.len(),
            });
        }
        Err(_) => {
            return Err(PacketError::InvalidHeader("invalid HTTP status line"));
        }
    };

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
    build_header_fields(data, offset, resp.headers, buf)?;

    Ok(header_len)
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
        let value_str = core::str::from_utf8(trimmed_value)
            .map_err(|_| PacketError::InvalidHeader("header value is not valid UTF-8"))?;

        // Compute byte range from the header name position in data
        let name_start = str_offset(data, name)?;
        let value_end = slice_offset(data, header.value)? + header.value.len();
        let header_range = offset + name_start..offset + value_end;

        let obj_idx = buf.begin_container(
            &HEADER_CHILDREN[HC_NAME], // placeholder descriptor for the Object — we reuse HC_NAME
            FieldValue::Object(0..0),
            header_range.clone(),
        );
        buf.push_field(
            &HEADER_CHILDREN[HC_NAME],
            FieldValue::Str(name),
            header_range.clone(),
        );
        buf.push_field(
            &HEADER_CHILDREN[HC_VALUE],
            FieldValue::Str(value_str),
            header_range,
        );
        buf.end_container(obj_idx);
    }

    buf.end_container(array_idx);

    Ok(())
}

/// Extract the value of a header by name from the buffer's fields during construction.
///
/// Performs case-insensitive matching on the header name.
/// Returns a `&'pkt str` borrowed directly from the packet data.
///
/// This function scans the fields in the buffer from the current layer's start
/// position, which works even before `end_layer()` has been called.
fn extract_header_value<'pkt>(buf: &DissectBuffer<'pkt>, header_name: &str) -> Option<&'pkt str> {
    // Find the "headers" array field in the current layer's fields
    let layer = buf.layers().last()?;
    let start = layer.field_range.start as usize;
    let fields = &buf.fields()[start..];
    let headers_field = fields.iter().find(|f| f.name() == "headers")?;
    let array_range = match &headers_field.value {
        FieldValue::Array(r) => r,
        _ => return None,
    };

    // Each child in the array is an Object containing "name" and "value" fields
    let children = buf.nested_fields(array_range);
    for field in children {
        if let FieldValue::Object(ref obj_range) = field.value {
            let obj_fields = buf.nested_fields(obj_range);
            let name_field = obj_fields.iter().find(|f| f.name() == "name")?;
            let value_field = obj_fields.iter().find(|f| f.name() == "value")?;
            if let FieldValue::Str(n) = &name_field.value {
                if n.eq_ignore_ascii_case(header_name) {
                    if let FieldValue::Str(v) = &value_field.value {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
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
}
