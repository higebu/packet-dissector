//! SIP (Session Initiation Protocol) dissector.
//!
//! Parses SIP request and response messages as defined in RFC 3261.
//! SIP reuses HTTP-like syntax (RFC 3261, Section 7). This dissector parses
//! the SIP start-line manually and uses the [`httparse`] crate for header parsing.
//!
//! ## References
//! - RFC 3261: SIP: Session Initiation Protocol <https://www.rfc-editor.org/rfc/rfc3261>
//! - RFC 3262: Reliability of Provisional Responses (PRACK) <https://www.rfc-editor.org/rfc/rfc3262>
//! - RFC 3265: SIP-Specific Event Notification (SUBSCRIBE/NOTIFY) <https://www.rfc-editor.org/rfc/rfc3265>
//! - RFC 3311: UPDATE Method <https://www.rfc-editor.org/rfc/rfc3311>
//! - RFC 3428: SIP Extension for Instant Messaging (MESSAGE) <https://www.rfc-editor.org/rfc/rfc3428>
//! - RFC 3515: Refer Method <https://www.rfc-editor.org/rfc/rfc3515>
//! - RFC 3903: SIP Extension for Event State Publication (PUBLISH) <https://www.rfc-editor.org/rfc/rfc3903>
//! - RFC 6086: INFO Method and Package Framework <https://www.rfc-editor.org/rfc/rfc6086>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{intern_content_type, slice_offset, str_offset, trim_ows};

/// Maximum number of SIP headers to parse.
const MAX_HEADERS: usize = 64;

/// Minimum valid SIP start-line length.
///
/// Shortest request:  `ACK sip:x SIP/2.0\r\n` = 19 bytes
/// Shortest response: `SIP/2.0 100 T\r\n`     = 15 bytes
const MIN_START_LINE_LEN: usize = 15;

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

/// Descriptor for the SIP header Object container.
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

/// All field descriptors for the SIP dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 3261, Section 7 — distinguishes request from response
    FieldDescriptor::new("is_response", "Is Response", FieldType::U8),
    // RFC 3261, Section 7.1 — request method
    FieldDescriptor::new("method", "Method", FieldType::Str).optional(),
    // RFC 3261, Section 7.1 — Request-URI
    FieldDescriptor::new("uri", "Request URI", FieldType::Str).optional(),
    // RFC 3261, Section 7 — SIP-Version
    FieldDescriptor::new("version", "Version", FieldType::Str),
    // RFC 3261, Section 7.2 — Status-Code
    FieldDescriptor::new("status_code", "Status Code", FieldType::U16).optional(),
    // RFC 3261, Section 7.2 — Reason-Phrase
    FieldDescriptor::new("reason_phrase", "Reason Phrase", FieldType::Str).optional(),
    // RFC 3261, Section 7.3 — Header fields
    FieldDescriptor::new("headers", "Headers", FieldType::Array)
        .optional()
        .with_children(HEADER_CHILDREN),
    // RFC 3261, Section 20.14 — Content-Length
    FieldDescriptor::new("content_length", "Content Length", FieldType::U32).optional(),
    // RFC 3261, Section 20.15 — Content-Type
    FieldDescriptor::new("content_type", "Content Type", FieldType::Str).optional(),
];

/// SIP dissector.
///
/// Parses both SIP request and response messages. The dissector detects
/// whether the message is a request or response by checking if the
/// start-line begins with `"SIP/"` (response) or a method token (request).
pub struct SipDissector;

impl Dissector for SipDissector {
    fn name(&self) -> &'static str {
        "Session Initiation Protocol"
    }

    fn short_name(&self) -> &'static str {
        "SIP"
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

        // RFC 3261, Section 7 — detect request vs response
        let is_response = data.starts_with(b"SIP/");

        buf.begin_layer("SIP", None, FIELD_DESCRIPTORS, offset..offset);

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
        let content_length = extract_header_value(buf, "Content-Length")
            .or_else(|| extract_header_value(buf, "l"))
            .and_then(|v| v.parse::<u32>().ok());
        let content_type =
            extract_header_value(buf, "Content-Type").or_else(|| extract_header_value(buf, "c"));

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

        let body_len = content_length.unwrap_or(0) as usize;
        let total = header_len + body_len;

        if total > data.len() {
            if let Some(layer) = buf.last_layer_mut() {
                layer.range = offset..offset + header_len;
            }
            buf.end_layer();
            return Err(PacketError::Truncated {
                expected: total,
                actual: data.len(),
            });
        }

        // RFC 3261, Section 7.4 — dispatch body by Content-Type.
        if body_len > 0 {
            if let Some(ct) =
                extract_header_value(buf, "Content-Type").or_else(|| extract_header_value(buf, "c"))
            {
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

// ---------------------------------------------------------------------------
// Start-line parsing helpers
// ---------------------------------------------------------------------------

/// Find the end of the first line (CRLF or LF), returning the position
/// after the line terminator. Returns `None` if no terminator is found.
fn find_line_end(data: &[u8]) -> Option<usize> {
    data.iter().position(|&b| b == b'\n').map(|i| i + 1)
}

/// Extract the first line from `data`, returning `(line_str, line_end)`.
///
/// `line_end` is the byte position after the CRLF/LF terminator.
/// `line_str` is the line content with the terminator stripped.
fn take_start_line(data: &[u8]) -> Result<(&str, usize), PacketError> {
    let line_end = find_line_end(data).ok_or(PacketError::Truncated {
        expected: data.len() + 1,
        actual: data.len(),
    })?;
    let line = &data[..line_end];
    let trimmed = if line.ends_with(b"\r\n") {
        &line[..line.len() - 2]
    } else {
        &line[..line.len() - 1]
    };
    let line_str = core::str::from_utf8(trimmed)
        .map_err(|_| PacketError::InvalidHeader("start-line is not valid UTF-8"))?;
    Ok((line_str, line_end))
}

/// Parse headers after the start-line and return total header section length.
fn parse_remaining_headers<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    line_end: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<usize, PacketError> {
    let header_len = parse_headers(&data[line_end..], offset, line_end, buf)?;
    Ok(line_end + header_len)
}

// ---------------------------------------------------------------------------
// Request / response parsing
// ---------------------------------------------------------------------------

/// Parse a SIP request start-line and headers, populating fields.
fn parse_request<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<usize, PacketError> {
    let (line_str, line_end) = take_start_line(data)?;

    // RFC 3261, Section 7.1 — Request-Line = Method SP Request-URI SP SIP-Version
    let first_sp = line_str
        .find(' ')
        .ok_or(PacketError::InvalidHeader("missing SP in request-line"))?;
    let method = &line_str[..first_sp];
    if method.is_empty() {
        return Err(PacketError::InvalidHeader("empty method in request-line"));
    }
    let rest = &line_str[first_sp + 1..];

    let last_sp = rest
        .rfind(' ')
        .ok_or(PacketError::InvalidHeader("missing SP before SIP-Version"))?;
    let uri = &rest[..last_sp];
    if uri.is_empty() {
        return Err(PacketError::InvalidHeader(
            "empty Request-URI in request-line",
        ));
    }
    let version = &rest[last_sp + 1..];

    if !version.starts_with("SIP/") {
        return Err(PacketError::InvalidHeader("invalid SIP version"));
    }

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_METHOD],
        FieldValue::Str(method),
        offset..offset + method.len(),
    );

    let uri_start = first_sp + 1;
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_URI],
        FieldValue::Str(uri),
        offset + uri_start..offset + uri_start + uri.len(),
    );

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_VERSION],
        FieldValue::Str(version),
        offset..offset + line_end,
    );

    parse_remaining_headers(data, offset, line_end, buf)
}

/// Parse a SIP response start-line and headers, populating fields.
fn parse_response<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<usize, PacketError> {
    let (line_str, line_end) = take_start_line(data)?;

    // RFC 3261, Section 7.2 — Status-Line = SIP-Version SP Status-Code SP Reason-Phrase
    let first_sp = line_str
        .find(' ')
        .ok_or(PacketError::InvalidHeader("missing SP in status-line"))?;
    let version = &line_str[..first_sp];
    let rest = &line_str[first_sp + 1..];

    if !version.starts_with("SIP/") {
        return Err(PacketError::InvalidHeader("invalid SIP version"));
    }

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_VERSION],
        FieldValue::Str(version),
        offset..offset + line_end,
    );

    // Status-Code (3 digits) and optional Reason-Phrase
    let (code_str, reason) = match rest.find(' ') {
        Some(sp) => (&rest[..sp], Some(&rest[sp + 1..])),
        None => (rest, None),
    };

    // RFC 3261, Section 7.2 — Status-Code is exactly 3 digits
    if code_str.len() != 3 || !code_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PacketError::InvalidHeader("invalid status code format"));
    }

    let code: u16 = code_str
        .parse()
        .map_err(|_| PacketError::InvalidHeader("invalid status code"))?;

    // Be conservative: only accept standard SIP/HTTP-style ranges
    if !(100..=699).contains(&code) {
        return Err(PacketError::InvalidHeader("status code out of range"));
    }

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_STATUS_CODE],
        FieldValue::U16(code),
        offset..offset + line_end,
    );

    if let Some(reason) = reason {
        if !reason.is_empty() {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_REASON_PHRASE],
                FieldValue::Str(reason),
                offset..offset + line_end,
            );
        }
    }

    parse_remaining_headers(data, offset, line_end, buf)
}

// ---------------------------------------------------------------------------
// Header helpers
// ---------------------------------------------------------------------------

/// Parse header fields using `httparse::parse_headers`.
fn parse_headers<'pkt>(
    header_data: &'pkt [u8],
    base_offset: usize,
    line_end: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<usize, PacketError> {
    let mut headers_buf = [httparse::EMPTY_HEADER; MAX_HEADERS];

    match httparse::parse_headers(header_data, &mut headers_buf) {
        Ok(httparse::Status::Complete((len, headers))) => {
            build_header_fields(header_data, base_offset + line_end, headers, buf)?;
            Ok(len)
        }
        Ok(httparse::Status::Partial) => Err(PacketError::Truncated {
            expected: header_data.len() + 1,
            actual: header_data.len(),
        }),
        Err(_) => Err(PacketError::InvalidHeader("invalid SIP header")),
    }
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

    // Compute the overall headers range
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

        // Compute byte range relative to data slice, then add offset
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

/// Extract the value of a named header from the buffer's fields during construction.
fn extract_header_value<'pkt>(buf: &DissectBuffer<'pkt>, header_name: &str) -> Option<&'pkt str> {
    let layer = buf.layers().last()?;
    let start = layer.field_range.start as usize;
    let fields = &buf.fields()[start..];
    let headers_field = fields.iter().find(|f| f.name() == "headers")?;
    let array_range = match &headers_field.value {
        FieldValue::Array(r) => r,
        _ => return None,
    };

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

    // # RFC 3261 (SIP) Coverage
    //
    // | RFC Section | Description             | Test                                    |
    // |-------------|-------------------------|-----------------------------------------|
    // | 7           | Message Format          | parse_sip_invite_request                |
    // | 7.1         | Request Line            | parse_sip_invite_request                |
    // | 7.1         | Method token            | parse_sip_register_request              |
    // | 7.1         | All standard methods    | parse_sip_methods_*                     |
    // | 7.2         | Status Line             | parse_sip_200_ok_response               |
    // | 7.2         | Reason Phrase            | parse_sip_trying_response               |
    // | 7.3         | Header Fields           | parse_sip_request_with_headers          |
    // | 7.3.1       | Header OWS trimming     | parse_sip_header_ows_trimming           |
    // | 7.4         | Message Body            | parse_sip_invite_with_sdp_body          |
    // | 20.14       | Content-Length           | parse_sip_invite_with_sdp_body          |
    // | 20.15       | Content-Type             | parse_sip_invite_with_sdp_body          |
    // | 7.3.3       | Compact header forms    | parse_sip_compact_content_length        |
    // | -           | Truncated               | parse_sip_truncated                     |
    // | -           | Invalid start-line      | parse_sip_invalid_request               |
    // | -           | Body dispatch hint      | parse_sip_content_type_dispatch         |
    // | -           | No body → End hint      | parse_sip_no_body_dispatch_end          |
    // | -           | Offset handling         | parse_sip_with_offset                   |
    // | -           | Dissector metadata       | dissector_metadata                      |

    fn dissect(data: &[u8]) -> Result<DissectBuffer<'_>, PacketError> {
        let dissector = SipDissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(data, &mut buf, 0)?;
        Ok(buf)
    }

    fn dissect_err(data: &[u8]) -> PacketError {
        let dissector = SipDissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(data, &mut buf, 0).unwrap_err()
    }

    #[test]
    fn parse_sip_invite_request() {
        let data = b"INVITE sip:bob@example.net SIP/2.0\r\n\
                     Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
                     To: Bob <sip:bob@example.net>\r\n\
                     From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                     Call-ID: a84b4c76e66710@pc33.example.com\r\n\
                     CSeq: 314159 INVITE\r\n\
                     Contact: <sip:alice@pc33.example.com>\r\n\
                     Content-Length: 0\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SIP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "is_response").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "method").unwrap().value,
            FieldValue::Str("INVITE")
        );
        assert_eq!(
            buf.field_by_name(layer, "uri").unwrap().value,
            FieldValue::Str("sip:bob@example.net")
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::Str("SIP/2.0")
        );
        assert!(buf.field_by_name(layer, "status_code").is_none());
    }

    #[test]
    fn parse_sip_register_request() {
        let data = b"REGISTER sip:registrar.example.net SIP/2.0\r\n\
                     Via: SIP/2.0/UDP bobspc.example.net:5060;branch=z9hG4bKnashds7\r\n\
                     To: Bob <sip:bob@example.net>\r\n\
                     From: Bob <sip:bob@example.net>;tag=456248\r\n\
                     Call-ID: 843817637684230@998sdasdh09\r\n\
                     CSeq: 1826 REGISTER\r\n\
                     Contact: <sip:bob@192.0.2.4>\r\n\
                     Content-Length: 0\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SIP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "method").unwrap().value,
            FieldValue::Str("REGISTER")
        );
        assert_eq!(
            buf.field_by_name(layer, "uri").unwrap().value,
            FieldValue::Str("sip:registrar.example.net")
        );
    }

    #[test]
    fn parse_sip_200_ok_response() {
        let data = b"SIP/2.0 200 OK\r\n\
                     Via: SIP/2.0/UDP server10.example.net;branch=z9hG4bKnashds8\r\n\
                     To: Bob <sip:bob@example.net>;tag=2493k59kd\r\n\
                     From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                     Call-ID: a84b4c76e66710@pc33.example.com\r\n\
                     CSeq: 314159 INVITE\r\n\
                     Contact: <sip:bob@192.0.2.4>\r\n\
                     Content-Length: 0\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SIP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "is_response").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::Str("SIP/2.0")
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
    fn parse_sip_trying_response() {
        let data = b"SIP/2.0 100 Trying\r\n\
                     Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
                     To: Bob <sip:bob@example.net>\r\n\
                     From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                     Call-ID: a84b4c76e66710@pc33.example.com\r\n\
                     CSeq: 314159 INVITE\r\n\
                     Content-Length: 0\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SIP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "status_code").unwrap().value,
            FieldValue::U16(100)
        );
        assert_eq!(
            buf.field_by_name(layer, "reason_phrase").unwrap().value,
            FieldValue::Str("Trying")
        );
    }

    #[test]
    fn parse_sip_request_with_headers() {
        let data = b"OPTIONS sip:carol@example.org SIP/2.0\r\n\
                     Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bKhjhs8ass877\r\n\
                     Max-Forwards: 70\r\n\
                     To: <sip:carol@example.org>\r\n\
                     From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                     Call-ID: testcallid@pc33.example.com\r\n\
                     CSeq: 63104 OPTIONS\r\n\
                     Contact: <sip:alice@pc33.example.com>\r\n\
                     Accept: application/sdp\r\n\
                     Content-Length: 0\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SIP").unwrap();

        let headers_field = buf.field_by_name(layer, "headers").unwrap();
        let array_range = match &headers_field.value {
            FieldValue::Array(r) => r,
            _ => panic!("expected Array"),
        };
        let children = buf.nested_fields(array_range);
        let objects: Vec<_> = children.iter().filter(|f| f.value.is_object()).collect();
        // Via, Max-Forwards, To, From, Call-ID, CSeq, Contact, Accept, Content-Length
        assert_eq!(objects.len(), 9);

        if let FieldValue::Object(ref r) = objects[0].value {
            let f = buf.nested_fields(r);
            assert_eq!(f[0].value, FieldValue::Str("Via"));
        }

        // Check Accept header
        if let FieldValue::Object(ref r) = objects[7].value {
            let f = buf.nested_fields(r);
            assert_eq!(f[0].value, FieldValue::Str("Accept"));
            assert_eq!(f[1].value, FieldValue::Str("application/sdp"));
        }
    }

    #[test]
    fn parse_sip_invite_with_sdp_body() {
        let sdp_body = b"v=0\r\n\
                         o=alice 2890844526 2890844526 IN IP4 host.example.com\r\n\
                         s=-\r\n\
                         c=IN IP4 host.example.com\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0\r\n\
                         a=rtpmap:0 PCMU/8000\r\n";
        let content_length = sdp_body.len();
        let header = format!(
            "INVITE sip:bob@example.net SIP/2.0\r\n\
             Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
             To: Bob <sip:bob@example.net>\r\n\
             From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
             Call-ID: a84b4c76e66710@pc33.example.com\r\n\
             CSeq: 314159 INVITE\r\n\
             Contact: <sip:alice@pc33.example.com>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {content_length}\r\n\r\n"
        );
        let mut data = Vec::new();
        data.extend_from_slice(header.as_bytes());
        data.extend_from_slice(sdp_body);

        let buf = dissect(&data).unwrap();
        let layer = buf.layer_by_name("SIP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "content_length").unwrap().value,
            FieldValue::U32(content_length as u32)
        );
        assert_eq!(
            buf.field_by_name(layer, "content_type").unwrap().value,
            FieldValue::Str("application/sdp")
        );
        // SIP layer covers headers only; body is left for the body dissector.
        let header_len = header.len();
        assert_eq!(layer.range, 0..header_len);
    }

    #[test]
    fn parse_sip_truncated() {
        let data = b"INVITE sip:";
        assert!(matches!(dissect_err(data), PacketError::Truncated { .. }));
    }

    #[test]
    fn parse_sip_truncated_headers() {
        // Start-line complete but headers not terminated
        let data = b"INVITE sip:bob@example.net SIP/2.0\r\nVia: SIP/2.0/UDP pc33.example.com";
        assert!(matches!(dissect_err(data), PacketError::Truncated { .. }));
    }

    #[test]
    fn parse_sip_truncated_body() {
        let data = b"INVITE sip:bob@example.net SIP/2.0\r\nContent-Length: 100\r\n\r\nShort";
        assert!(matches!(dissect_err(data), PacketError::Truncated { .. }));
    }

    #[test]
    fn parse_sip_invalid_request() {
        // Missing SP between method and URI (must be >= MIN_START_LINE_LEN bytes)
        let data = b"INVALIDREQUESTLIN\r\n\r\n";
        assert!(matches!(dissect_err(data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_sip_header_ows_trimming() {
        let data = b"OPTIONS sip:carol@example.org SIP/2.0\r\n\
                     Via:   SIP/2.0/UDP pc33.example.com  \r\n\
                     Content-Length: 0\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SIP").unwrap();

        let headers_field = buf.field_by_name(layer, "headers").unwrap();
        if let FieldValue::Array(ref r) = headers_field.value {
            let children = buf.nested_fields(r);
            let obj = children.iter().find(|f| f.value.is_object()).unwrap();
            if let FieldValue::Object(ref obj_r) = obj.value {
                let f = buf.nested_fields(obj_r);
                assert_eq!(f[1].value, FieldValue::Str("SIP/2.0/UDP pc33.example.com"));
            }
        }
    }

    #[test]
    fn parse_sip_content_type_dispatch() {
        let sdp = b"v=0\r\n";
        let cl = sdp.len();
        let header = format!(
            "INVITE sip:bob@example.net SIP/2.0\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {cl}\r\n\r\n"
        );
        let mut data = Vec::new();
        data.extend_from_slice(header.as_bytes());
        data.extend_from_slice(sdp);

        let dissector = SipDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::ByContentType("application/sdp"));
    }

    #[test]
    fn parse_sip_content_type_with_params_dispatch() {
        // Content-Type with parameters should strip them for dispatch
        let body = b"body";
        let cl = body.len();
        let header = format!(
            "INVITE sip:bob@example.net SIP/2.0\r\n\
             Content-Type: application/sdp; charset=utf-8\r\n\
             Content-Length: {cl}\r\n\r\n"
        );
        let mut data = Vec::new();
        data.extend_from_slice(header.as_bytes());
        data.extend_from_slice(body);

        let dissector = SipDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::ByContentType("application/sdp"));
    }

    #[test]
    fn parse_sip_no_body_dispatch_end() {
        let data = b"OPTIONS sip:carol@example.org SIP/2.0\r\n\
                     Content-Length: 0\r\n\r\n";
        let dissector = SipDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn parse_sip_with_offset() {
        let data = b"OPTIONS sip:carol@example.org SIP/2.0\r\n\
                     Content-Length: 0\r\n\r\n";
        let dissector = SipDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(data, &mut buf, 42).unwrap();

        let layer = buf.layer_by_name("SIP").unwrap();
        assert_eq!(layer.range.start, 42);
        assert_eq!(layer.range.end, 42 + data.len());
        assert_eq!(result.bytes_consumed, data.len());
    }

    #[test]
    fn parse_sip_compact_content_length() {
        // RFC 3261, Section 7.3.3 — compact form "l" for Content-Length
        let data = b"OPTIONS sip:carol@example.org SIP/2.0\r\n\
                     l: 0\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SIP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "content_length").unwrap().value,
            FieldValue::U32(0)
        );
    }

    #[test]
    fn parse_sip_methods_ack() {
        let data = b"ACK sip:bob@example.net SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SIP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "method").unwrap().value,
            FieldValue::Str("ACK")
        );
    }

    #[test]
    fn parse_sip_methods_bye() {
        let data = b"BYE sip:bob@example.net SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SIP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "method").unwrap().value,
            FieldValue::Str("BYE")
        );
    }

    #[test]
    fn parse_sip_methods_cancel() {
        let data = b"CANCEL sip:bob@example.net SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SIP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "method").unwrap().value,
            FieldValue::Str("CANCEL")
        );
    }

    #[test]
    fn parse_sip_response_no_reason() {
        // Some implementations may omit the reason phrase
        let data = b"SIP/2.0 200\r\nContent-Length: 0\r\n\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SIP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "status_code").unwrap().value,
            FieldValue::U16(200)
        );
        assert!(buf.field_by_name(layer, "reason_phrase").is_none());
    }

    #[test]
    fn dissector_metadata() {
        let d = SipDissector;
        assert_eq!(d.name(), "Session Initiation Protocol");
        assert_eq!(d.short_name(), "SIP");
        assert!(!d.field_descriptors().is_empty());
    }

    #[test]
    fn header_container_descriptor_distinct_from_inner_name() {
        // The per-header Object container must use a descriptor distinct
        // from the inner `name` child so that the outer display label does
        // not collide with the child's "Name" label.
        let data = b"OPTIONS sip:carol@example.com SIP/2.0\r\n\
                     Via: SIP/2.0/UDP pc.example.com\r\n\
                     Content-Length: 0\r\n\r\n";
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
}
