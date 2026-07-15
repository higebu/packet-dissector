//! SDP (Session Description Protocol) dissector.
//!
//! Parses SDP session descriptions as defined in RFC 8866. SDP is a
//! line-based text format carried as a message body — this dissector is
//! dispatched by MIME content type (`application/sdp`) from SIP or HTTP,
//! not by a transport port.
//!
//! Known gaps (documented follow-ups):
//! - No RTP conversation setup from `m=` / `a=rtpmap` lines (the registry
//!   is immutable during dissection; RTP remains decode-as only).
//! - `rtpmap` / `fmtp` values are exposed as raw attribute name/value
//!   pairs, not structured fields.
//! - Field values are exposed as zero-copy UTF-8 strings. A line whose
//!   value is not valid UTF-8 (legal per the RFC 8866, Section 9
//!   `byte-string`, e.g. ISO-8859-1 text selected via `a=charset:`) is
//!   skipped rather than decoded.
//! - `r=` / `z=` lines are kept as raw strings and are not associated
//!   with their preceding `t=` line.
//!
//! ## References
//! - RFC 8866: SDP: Session Description Protocol <https://www.rfc-editor.org/rfc/rfc8866>
//!   (obsoletes RFC 4566)

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

/// Minimum valid SDP length: the mandatory first line `v=0`.
const MIN_LEN: usize = 3;

// ---------------------------------------------------------------------------
// Field descriptors
// ---------------------------------------------------------------------------

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_VERSION: usize = 0;
const FD_ORIGIN: usize = 1;
const FD_SESSION_NAME: usize = 2;
const FD_SESSION_INFORMATION: usize = 3;
const FD_URI: usize = 4;
const FD_EMAILS: usize = 5;
const FD_PHONES: usize = 6;
const FD_CONNECTION: usize = 7;
const FD_BANDWIDTHS: usize = 8;
const FD_TIMES: usize = 9;
const FD_REPEAT_TIMES: usize = 10;
const FD_TIME_ZONES: usize = 11;
const FD_SESSION_ATTRIBUTES: usize = 12;
const FD_MEDIA_DESCRIPTIONS: usize = 13;

/// Child descriptor indices for [`ORIGIN_CHILDREN`].
const OC_USERNAME: usize = 0;
const OC_SESS_ID: usize = 1;
const OC_SESS_VERSION: usize = 2;
const OC_NETTYPE: usize = 3;
const OC_ADDRTYPE: usize = 4;
const OC_UNICAST_ADDRESS: usize = 5;

/// Child descriptors for the `o=` Origin object (RFC 8866, Section 5.2 —
/// <https://www.rfc-editor.org/rfc/rfc8866#section-5.2>).
static ORIGIN_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("username", "Username", FieldType::Str),
    FieldDescriptor::new("sess_id", "Session ID", FieldType::Str),
    FieldDescriptor::new("sess_version", "Session Version", FieldType::Str),
    FieldDescriptor::new("nettype", "Network Type", FieldType::Str),
    FieldDescriptor::new("addrtype", "Address Type", FieldType::Str),
    FieldDescriptor::new("unicast_address", "Unicast Address", FieldType::Str),
];

/// Child descriptor indices for [`CONNECTION_CHILDREN`].
const CC_NETTYPE: usize = 0;
const CC_ADDRTYPE: usize = 1;
const CC_ADDRESS: usize = 2;

/// Child descriptors for the `c=` Connection Information object
/// (RFC 8866, Section 5.7 — <https://www.rfc-editor.org/rfc/rfc8866#section-5.7>).
static CONNECTION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("nettype", "Network Type", FieldType::Str),
    FieldDescriptor::new("addrtype", "Address Type", FieldType::Str),
    FieldDescriptor::new("connection_address", "Connection Address", FieldType::Str),
];

/// Child descriptor indices for [`BANDWIDTH_CHILDREN`].
const BC_BWTYPE: usize = 0;
const BC_BANDWIDTH: usize = 1;

/// Child descriptors for each `b=` Bandwidth Information object
/// (RFC 8866, Section 5.8 — <https://www.rfc-editor.org/rfc/rfc8866#section-5.8>).
///
/// `<bandwidth>` is kept verbatim as a string: the RFC gives no length
/// limit for the digit sequence, so a fixed-width integer could not
/// represent every valid value.
static BANDWIDTH_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("bwtype", "Bandwidth Type", FieldType::Str),
    FieldDescriptor::new("bandwidth", "Bandwidth", FieldType::Str),
];

/// Child descriptor indices for [`TIME_CHILDREN`].
const TC_START_TIME: usize = 0;
const TC_STOP_TIME: usize = 1;

/// Child descriptors for each `t=` Time Active object
/// (RFC 8866, Section 5.9 — <https://www.rfc-editor.org/rfc/rfc8866#section-5.9>).
///
/// Times are kept verbatim as strings: RFC 8866, Section 5.9 — "The
/// representation is an unbounded length field", so a fixed-width integer
/// could not represent every valid value.
static TIME_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("start_time", "Start Time", FieldType::Str),
    FieldDescriptor::new("stop_time", "Stop Time", FieldType::Str),
];

/// Child descriptor indices for [`ATTRIBUTE_CHILDREN`].
const AC_NAME: usize = 0;
const AC_VALUE: usize = 1;

/// Child descriptors for each `a=` Attribute object
/// (RFC 8866, Section 5.13 — <https://www.rfc-editor.org/rfc/rfc8866#section-5.13>).
static ATTRIBUTE_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("name", "Name", FieldType::Str),
    FieldDescriptor::new("value", "Value", FieldType::Str).optional(),
];

/// Child descriptor indices for [`MEDIA_CHILDREN`].
const MC_MEDIA: usize = 0;
const MC_PORT: usize = 1;
const MC_NUM_PORTS: usize = 2;
const MC_PROTO: usize = 3;
const MC_FORMATS: usize = 4;
const MC_TITLE: usize = 5;
const MC_CONNECTION: usize = 6;
const MC_BANDWIDTHS: usize = 7;
const MC_ATTRIBUTES: usize = 8;

/// Child descriptors for each `m=` Media Description object
/// (RFC 8866, Section 5.14 — <https://www.rfc-editor.org/rfc/rfc8866#section-5.14>).
static MEDIA_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("media", "Media", FieldType::Str),
    FieldDescriptor::new("port", "Port", FieldType::U16),
    FieldDescriptor::new("num_ports", "Number of Ports", FieldType::U16).optional(),
    FieldDescriptor::new("proto", "Protocol", FieldType::Str),
    FieldDescriptor::new("formats", "Formats", FieldType::Str),
    FieldDescriptor::new("title", "Media Title", FieldType::Str).optional(),
    // RFC 8866, Section 5.7 — multiple c= lines MAY appear per media
    // description (layered encoding schemes)
    FieldDescriptor::new("connections", "Connection Information", FieldType::Array)
        .optional()
        .with_children(CONNECTION_CHILDREN),
    FieldDescriptor::new("bandwidths", "Bandwidth Information", FieldType::Array)
        .optional()
        .with_children(BANDWIDTH_CHILDREN),
    FieldDescriptor::new("attributes", "Attributes", FieldType::Array)
        .optional()
        .with_children(ATTRIBUTE_CHILDREN),
];

/// Descriptor for each element of the `emails` Array.
static FD_EMAIL_ITEM: FieldDescriptor =
    FieldDescriptor::new("email", "Email Address", FieldType::Str);

/// Descriptor for each element of the `phones` Array.
static FD_PHONE_ITEM: FieldDescriptor =
    FieldDescriptor::new("phone", "Phone Number", FieldType::Str);

/// Descriptor for each element of the `repeat_times` Array.
static FD_REPEAT_ITEM: FieldDescriptor =
    FieldDescriptor::new("repeat", "Repeat Time", FieldType::Str);

/// Descriptor for each `b=` element Object.
///
/// Named distinctly from the inner `bandwidth` child so the container's
/// display label does not collide with the child's label.
static FD_BANDWIDTH_ITEM: FieldDescriptor =
    FieldDescriptor::new("bandwidth_info", "Bandwidth Information", FieldType::Object)
        .with_children(BANDWIDTH_CHILDREN);

/// Descriptor for each `t=` element Object.
static FD_TIME_ITEM: FieldDescriptor =
    FieldDescriptor::new("time", "Time Description", FieldType::Object)
        .with_children(TIME_CHILDREN);

/// Descriptor for each element of the `time_zones` Array.
static FD_ZONE_ITEM: FieldDescriptor =
    FieldDescriptor::new("zone", "Time Zone Adjustment", FieldType::Str);

/// Descriptor for each media-level `c=` element Object.
static FD_CONNECTION_ITEM: FieldDescriptor =
    FieldDescriptor::new("connection", "Connection Information", FieldType::Object)
        .with_children(CONNECTION_CHILDREN);

/// Descriptor for each `a=` element Object.
static FD_ATTRIBUTE_ITEM: FieldDescriptor =
    FieldDescriptor::new("attribute", "Attribute", FieldType::Object)
        .with_children(ATTRIBUTE_CHILDREN);

/// Descriptor for each `m=` element Object.
static FD_MEDIA_ITEM: FieldDescriptor =
    FieldDescriptor::new("media_description", "Media Description", FieldType::Object)
        .with_children(MEDIA_CHILDREN);

/// All field descriptors for the SDP dissector.
///
/// Session-level field order follows RFC 8866, Section 5 —
/// <https://www.rfc-editor.org/rfc/rfc8866#section-5>.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 8866, Section 5.1 — Protocol Version ("v=")
    FieldDescriptor::new("version", "Protocol Version", FieldType::U8),
    // RFC 8866, Section 5.2 — Origin ("o=")
    FieldDescriptor::new("origin", "Origin", FieldType::Object)
        .optional()
        .with_children(ORIGIN_CHILDREN),
    // RFC 8866, Section 5.3 — Session Name ("s=")
    FieldDescriptor::new("session_name", "Session Name", FieldType::Str).optional(),
    // RFC 8866, Section 5.4 — Session Information ("i=")
    FieldDescriptor::new("session_information", "Session Information", FieldType::Str).optional(),
    // RFC 8866, Section 5.5 — URI ("u=")
    FieldDescriptor::new("uri", "URI", FieldType::Str).optional(),
    // RFC 8866, Section 5.6 — Email Address ("e=")
    FieldDescriptor::new("emails", "Email Addresses", FieldType::Array).optional(),
    // RFC 8866, Section 5.6 — Phone Number ("p=")
    FieldDescriptor::new("phones", "Phone Numbers", FieldType::Array).optional(),
    // RFC 8866, Section 5.7 — Connection Information ("c=")
    FieldDescriptor::new("connection", "Connection Information", FieldType::Object)
        .optional()
        .with_children(CONNECTION_CHILDREN),
    // RFC 8866, Section 5.8 — Bandwidth Information ("b=")
    FieldDescriptor::new("bandwidths", "Bandwidth Information", FieldType::Array)
        .optional()
        .with_children(BANDWIDTH_CHILDREN),
    // RFC 8866, Section 5.9 — Time Active ("t=")
    FieldDescriptor::new("times", "Time Active", FieldType::Array)
        .optional()
        .with_children(TIME_CHILDREN),
    // RFC 8866, Section 5.10 — Repeat Times ("r="), kept as raw strings
    FieldDescriptor::new("repeat_times", "Repeat Times", FieldType::Array).optional(),
    // RFC 8866, Section 5.11 — Time Zone Adjustment ("z="), kept as raw
    // strings; one z= per time description may appear
    FieldDescriptor::new("time_zones", "Time Zone Adjustment", FieldType::Array).optional(),
    // RFC 8866, Section 5.13 — Session Attributes ("a=")
    FieldDescriptor::new("session_attributes", "Session Attributes", FieldType::Array)
        .optional()
        .with_children(ATTRIBUTE_CHILDREN),
    // RFC 8866, Section 5.14 — Media Descriptions ("m=")
    FieldDescriptor::new("media_descriptions", "Media Descriptions", FieldType::Array)
        .optional()
        .with_children(MEDIA_CHILDREN),
];

/// SDP dissector.
///
/// Parses an SDP session description (RFC 8866). The message is identified
/// by its mandatory first line `v=0`; parsing of the remaining lines is
/// lenient (Postel's Law): unknown type characters (e.g. the obsolete `k=`
/// line or extensions), structurally broken lines (missing `=`, non-UTF-8
/// values), and malformed *optional* lines are skipped rather than failing
/// the layer. Only the `v=` line and `m=` lines — which define the message
/// identity and structure — are hard errors when malformed.
pub struct SdpDissector;

impl Dissector for SdpDissector {
    fn name(&self) -> &'static str {
        "Session Description Protocol"
    }

    fn short_name(&self) -> &'static str {
        "SDP"
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
        if data.len() < MIN_LEN {
            return Err(PacketError::Truncated {
                expected: MIN_LEN,
                actual: data.len(),
            });
        }

        // Validate every line and the mandatory first `v=` line before
        // opening the layer, so a non-SDP body never leaves a partial layer.
        let version = validate_message(data)?;

        buf.begin_layer("SDP", None, FIELD_DESCRIPTORS, offset..offset + data.len());

        let mut first_line = lines(data);
        if let Some(v_line) = first_line.next() {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_VERSION],
                FieldValue::U8(version),
                line_range(&v_line, offset),
            );
        }

        parse_session_section(data, buf, offset);
        parse_media_sections(data, buf, offset);

        buf.end_layer();

        // SDP is a terminal body layer: it consumes the whole message.
        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

// ---------------------------------------------------------------------------
// Line iteration
// ---------------------------------------------------------------------------

/// One SDP line: `<type-char>=<value>` (RFC 8866, Section 5 —
/// <https://www.rfc-editor.org/rfc/rfc8866#section-5>).
#[derive(Clone, Copy)]
struct Line<'a> {
    /// Byte offset of the line start within the SDP data.
    start: usize,
    /// Byte offset one past the line content (excluding CR/LF).
    end: usize,
    /// The type character before `=`.
    kind: u8,
    /// The value after `=`.
    value: &'a str,
}

/// Byte range of a full line, shifted by the layer offset.
fn line_range(line: &Line<'_>, offset: usize) -> core::ops::Range<usize> {
    offset + line.start..offset + line.end
}

/// Iterator over raw (start, content) line pairs.
///
/// Accepts CRLF and LF terminators and a final line without a terminator
/// (Postel's Law). Blank lines are skipped.
#[derive(Clone)]
struct RawLines<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for RawLines<'a> {
    type Item = (usize, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.data.len() {
            let start = self.pos;
            let rest = &self.data[start..];
            let (content_len, advance) = match rest.iter().position(|&b| b == b'\n') {
                Some(nl) => (nl, nl + 1),
                None => (rest.len(), rest.len()),
            };
            self.pos = start + advance;
            let mut content = &rest[..content_len];
            if content.ends_with(b"\r") {
                content = &content[..content.len() - 1];
            }
            if content.is_empty() {
                continue;
            }
            return Some((start, content));
        }
        None
    }
}

/// Parse a raw line into a [`Line`], enforcing `<type-char>=` structure
/// and UTF-8 validity of the value.
fn parse_line(start: usize, content: &[u8]) -> Result<Line<'_>, PacketError> {
    if content.len() < 2 || content[1] != b'=' {
        return Err(PacketError::InvalidHeader("SDP line missing '='"));
    }
    let value = core::str::from_utf8(&content[2..])
        .map_err(|_| PacketError::InvalidHeader("SDP line is not valid UTF-8"))?;
    Ok(Line {
        start,
        end: start + content.len(),
        kind: content[0],
        value,
    })
}

/// Iterator over validated lines. Only usable after [`validate_message`]
/// succeeded; lines that fail to parse are skipped defensively.
fn lines(data: &[u8]) -> impl Iterator<Item = Line<'_>> + Clone {
    RawLines { data, pos: 0 }.filter_map(|(start, content)| parse_line(start, content).ok())
}

/// Validate every line of the message and the mandatory `v=0` first line
/// (RFC 8866, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc8866#section-5.1>).
///
/// Returns the protocol version on success.
fn validate_message(data: &[u8]) -> Result<u8, PacketError> {
    let mut raw = RawLines { data, pos: 0 };

    let (start, content) = raw
        .next()
        .ok_or(PacketError::InvalidHeader("SDP message contains no lines"))?;
    let first = parse_line(start, content)?;
    if first.kind != b'v' {
        return Err(PacketError::InvalidHeader("SDP must start with a v= line"));
    }
    // RFC 8866, Section 5.1 — "This memo defines version 0."
    let version = match first.value.trim().parse::<u8>() {
        Ok(v) => v,
        Err(_) => return Err(PacketError::InvalidHeader("invalid SDP version")),
    };
    if version != 0 {
        return Err(PacketError::InvalidFieldValue {
            field: "version",
            value: u32::from(version),
        });
    }

    for (start, content) in raw {
        match parse_line(start, content) {
            Ok(line) => {
                // A malformed m= line is an error: it defines the structure
                // of everything that follows (RFC 8866, Section 5.14).
                if line.kind == b'm' {
                    parse_media_line(line.value)?;
                }
            }
            Err(e) => {
                // Structurally broken lines are skipped (Postel's Law)
                // unless they are m= lines, whose subfields are ASCII
                // tokens and whose loss would misattribute every
                // following line to the wrong section.
                if content.first() == Some(&b'm') && content.get(1) == Some(&b'=') {
                    return Err(e);
                }
            }
        }
    }

    Ok(version)
}

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

/// Split the next SP-delimited token off `s`, returning `(token, rest)`.
/// Returns `None` when no token remains.
///
/// Only the ASCII space (0x20) separates subfields: the RFC 8866,
/// Section 9 `non-ws-string` permits `%x80-FF` bytes, which include
/// Unicode whitespace codepoints that must stay inside a token.
fn take_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start_matches(' ');
    if s.is_empty() {
        return None;
    }
    match s.find(' ') {
        Some(i) => Some((&s[..i], &s[i..])),
        None => Some((s, "")),
    }
}

/// Iterate the SP-separated subfields of a line value (empty tokens from
/// repeated spaces are skipped leniently).
fn sp_tokens(value: &str) -> impl Iterator<Item = &str> + Clone {
    value.split(' ').filter(|t| !t.is_empty())
}

/// Returns `true` when `s` is a non-empty ASCII digit sequence.
fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// Session-level parsing
// ---------------------------------------------------------------------------

/// Lines of the session section: everything after the `v=` line up to the
/// first `m=` line (RFC 8866, Section 5 —
/// <https://www.rfc-editor.org/rfc/rfc8866#section-5>).
fn session_lines(data: &[u8]) -> impl Iterator<Item = Line<'_>> + Clone {
    lines(data).skip(1).take_while(|l| l.kind != b'm')
}

/// Parse all session-level lines into fields, in descriptor order.
fn parse_session_section<'pkt>(data: &'pkt [u8], buf: &mut DissectBuffer<'pkt>, offset: usize) {
    // RFC 8866, Section 5.2 — o=<username> <sess-id> <sess-version>
    // <nettype> <addrtype> <unicast-address>
    if let Some(line) = session_lines(data).find(|l| l.kind == b'o') {
        push_origin(buf, &line, offset);
    }

    push_scalar(buf, session_lines(data), b's', FD_SESSION_NAME, offset);
    push_scalar(
        buf,
        session_lines(data),
        b'i',
        FD_SESSION_INFORMATION,
        offset,
    );
    push_scalar(buf, session_lines(data), b'u', FD_URI, offset);

    push_str_array(
        buf,
        session_lines(data).filter(|l| l.kind == b'e'),
        &FIELD_DESCRIPTORS[FD_EMAILS],
        &FD_EMAIL_ITEM,
        offset,
    );
    push_str_array(
        buf,
        session_lines(data).filter(|l| l.kind == b'p'),
        &FIELD_DESCRIPTORS[FD_PHONES],
        &FD_PHONE_ITEM,
        offset,
    );

    if let Some(line) = session_lines(data).find(|l| l.kind == b'c') {
        push_connection(buf, &line, &FIELD_DESCRIPTORS[FD_CONNECTION], offset);
    }

    push_bandwidths(
        buf,
        session_lines(data),
        &FIELD_DESCRIPTORS[FD_BANDWIDTHS],
        offset,
    );
    push_times(buf, session_lines(data), offset);
    push_str_array(
        buf,
        session_lines(data).filter(|l| l.kind == b'r'),
        &FIELD_DESCRIPTORS[FD_REPEAT_TIMES],
        &FD_REPEAT_ITEM,
        offset,
    );
    push_str_array(
        buf,
        session_lines(data).filter(|l| l.kind == b'z'),
        &FIELD_DESCRIPTORS[FD_TIME_ZONES],
        &FD_ZONE_ITEM,
        offset,
    );
    push_attributes(
        buf,
        session_lines(data),
        &FIELD_DESCRIPTORS[FD_SESSION_ATTRIBUTES],
        offset,
    );
}

/// Push the first line of `kind` as a scalar Str field.
fn push_scalar<'pkt, I>(
    buf: &mut DissectBuffer<'pkt>,
    mut lines: I,
    kind: u8,
    fd_idx: usize,
    offset: usize,
) where
    I: Iterator<Item = Line<'pkt>>,
{
    if let Some(line) = lines.find(|l| l.kind == kind) {
        buf.push_field(
            &FIELD_DESCRIPTORS[fd_idx],
            FieldValue::Str(line.value),
            line_range(&line, offset),
        );
    }
}

/// Push the `o=` Origin object. A line with the wrong number of tokens is
/// skipped (Postel's Law).
fn push_origin<'pkt>(buf: &mut DissectBuffer<'pkt>, line: &Line<'pkt>, offset: usize) {
    let mut tokens = sp_tokens(line.value);
    let (Some(username), Some(sess_id), Some(sess_version)) =
        (tokens.next(), tokens.next(), tokens.next())
    else {
        return;
    };
    let (Some(nettype), Some(addrtype), Some(unicast_address)) =
        (tokens.next(), tokens.next(), tokens.next())
    else {
        return;
    };
    if tokens.next().is_some() {
        return;
    }

    let range = line_range(line, offset);
    let obj_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_ORIGIN],
        FieldValue::Object(0..0),
        range.clone(),
    );
    for (idx, value) in [
        (OC_USERNAME, username),
        (OC_SESS_ID, sess_id),
        (OC_SESS_VERSION, sess_version),
        (OC_NETTYPE, nettype),
        (OC_ADDRTYPE, addrtype),
        (OC_UNICAST_ADDRESS, unicast_address),
    ] {
        buf.push_field(&ORIGIN_CHILDREN[idx], FieldValue::Str(value), range.clone());
    }
    buf.end_container(obj_idx);
}

/// Parse a `c=` line value into its three subfields
/// (RFC 8866, Section 5.7 — <https://www.rfc-editor.org/rfc/rfc8866#section-5.7>).
fn connection_tokens(value: &str) -> Option<(&str, &str, &str)> {
    let mut tokens = sp_tokens(value);
    let (nettype, addrtype, address) = (tokens.next()?, tokens.next()?, tokens.next()?);
    if tokens.next().is_some() {
        return None;
    }
    Some((nettype, addrtype, address))
}

/// Push a `c=` Connection Information object under the given descriptor.
/// A line with the wrong number of tokens is skipped (Postel's Law).
fn push_connection<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    line: &Line<'pkt>,
    descriptor: &'static FieldDescriptor,
    offset: usize,
) {
    let Some((nettype, addrtype, address)) = connection_tokens(line.value) else {
        return;
    };

    let range = line_range(line, offset);
    let obj_idx = buf.begin_container(descriptor, FieldValue::Object(0..0), range.clone());
    for (idx, value) in [
        (CC_NETTYPE, nettype),
        (CC_ADDRTYPE, addrtype),
        (CC_ADDRESS, address),
    ] {
        buf.push_field(
            &CONNECTION_CHILDREN[idx],
            FieldValue::Str(value),
            range.clone(),
        );
    }
    buf.end_container(obj_idx);
}

/// Push an Array of media-level `c=` Connection Information objects.
///
/// RFC 8866, Section 5.7 — multiple `c=` lines MAY appear per media
/// description (layered encoding schemes). Malformed lines are skipped.
fn push_connections<'pkt, I>(
    buf: &mut DissectBuffer<'pkt>,
    lines: I,
    array_desc: &'static FieldDescriptor,
    offset: usize,
) where
    I: Iterator<Item = Line<'pkt>> + Clone,
{
    let items = lines.filter(|l| l.kind == b'c' && connection_tokens(l.value).is_some());
    let Some(range) = items_range(items.clone(), offset) else {
        return;
    };
    let array_idx = buf.begin_container(array_desc, FieldValue::Array(0..0), range);
    for line in items {
        push_connection(buf, &line, &FD_CONNECTION_ITEM, offset);
    }
    buf.end_container(array_idx);
}

/// Compute the byte range covering the first through last item lines.
fn items_range<'pkt, I>(items: I, offset: usize) -> Option<core::ops::Range<usize>>
where
    I: Iterator<Item = Line<'pkt>>,
{
    let mut range: Option<core::ops::Range<usize>> = None;
    for line in items {
        let r = line_range(&line, offset);
        range = Some(match range {
            Some(existing) => existing.start..r.end,
            None => r,
        });
    }
    range
}

/// Push an Array of raw Str items (e.g. `e=`, `p=`, `r=` lines).
fn push_str_array<'pkt, I>(
    buf: &mut DissectBuffer<'pkt>,
    items: I,
    array_desc: &'static FieldDescriptor,
    item_desc: &'static FieldDescriptor,
    offset: usize,
) where
    I: Iterator<Item = Line<'pkt>> + Clone,
{
    let Some(range) = items_range(items.clone(), offset) else {
        return;
    };
    let array_idx = buf.begin_container(array_desc, FieldValue::Array(0..0), range);
    for line in items {
        buf.push_field(
            item_desc,
            FieldValue::Str(line.value),
            line_range(&line, offset),
        );
    }
    buf.end_container(array_idx);
}

/// Parse a `b=` line value: `<bwtype>:<bandwidth>`
/// (RFC 8866, Section 5.8 — <https://www.rfc-editor.org/rfc/rfc8866#section-5.8>).
///
/// `<bandwidth>` is validated as digits but kept verbatim — the RFC gives
/// no length limit, so parsing into a fixed-width integer could drop a
/// valid line.
fn parse_bandwidth(value: &str) -> Option<(&str, &str)> {
    let (bwtype, bandwidth) = value.split_once(':')?;
    if bwtype.is_empty() || !is_digits(bandwidth) {
        return None;
    }
    Some((bwtype, bandwidth))
}

/// Push an Array of `b=` Bandwidth Information objects. Malformed lines
/// are skipped (Postel's Law).
fn push_bandwidths<'pkt, I>(
    buf: &mut DissectBuffer<'pkt>,
    lines: I,
    array_desc: &'static FieldDescriptor,
    offset: usize,
) where
    I: Iterator<Item = Line<'pkt>> + Clone,
{
    let items = lines.filter(|l| l.kind == b'b' && parse_bandwidth(l.value).is_some());
    let Some(range) = items_range(items.clone(), offset) else {
        return;
    };
    let array_idx = buf.begin_container(array_desc, FieldValue::Array(0..0), range);
    for line in items {
        let Some((bwtype, bandwidth)) = parse_bandwidth(line.value) else {
            continue;
        };
        let r = line_range(&line, offset);
        let obj_idx = buf.begin_container(&FD_BANDWIDTH_ITEM, FieldValue::Object(0..0), r.clone());
        buf.push_field(
            &BANDWIDTH_CHILDREN[BC_BWTYPE],
            FieldValue::Str(bwtype),
            r.clone(),
        );
        buf.push_field(
            &BANDWIDTH_CHILDREN[BC_BANDWIDTH],
            FieldValue::Str(bandwidth),
            r,
        );
        buf.end_container(obj_idx);
    }
    buf.end_container(array_idx);
}

/// Parse a `t=` line value: `<start-time> <stop-time>`
/// (RFC 8866, Section 5.9 — <https://www.rfc-editor.org/rfc/rfc8866#section-5.9>).
///
/// Times are validated as digits but kept verbatim — "The representation
/// is an unbounded length field", so parsing into a fixed-width integer
/// could drop a valid line.
fn parse_timing(value: &str) -> Option<(&str, &str)> {
    let mut tokens = sp_tokens(value);
    let (start, stop) = (tokens.next()?, tokens.next()?);
    if tokens.next().is_some() || !is_digits(start) || !is_digits(stop) {
        return None;
    }
    Some((start, stop))
}

/// Push the `times` Array of `t=` Timing objects. Malformed lines are
/// skipped (Postel's Law).
fn push_times<'pkt, I>(buf: &mut DissectBuffer<'pkt>, lines: I, offset: usize)
where
    I: Iterator<Item = Line<'pkt>> + Clone,
{
    let items = lines.filter(|l| l.kind == b't' && parse_timing(l.value).is_some());
    let Some(range) = items_range(items.clone(), offset) else {
        return;
    };
    let array_idx =
        buf.begin_container(&FIELD_DESCRIPTORS[FD_TIMES], FieldValue::Array(0..0), range);
    for line in items {
        let Some((start, stop)) = parse_timing(line.value) else {
            continue;
        };
        let r = line_range(&line, offset);
        let obj_idx = buf.begin_container(&FD_TIME_ITEM, FieldValue::Object(0..0), r.clone());
        buf.push_field(
            &TIME_CHILDREN[TC_START_TIME],
            FieldValue::Str(start),
            r.clone(),
        );
        buf.push_field(&TIME_CHILDREN[TC_STOP_TIME], FieldValue::Str(stop), r);
        buf.end_container(obj_idx);
    }
    buf.end_container(array_idx);
}

/// Push an Array of `a=` Attribute objects under the given descriptor.
///
/// RFC 8866, Section 5.13 — attributes are either properties (`a=<name>`)
/// or values (`a=<name>:<value>`), split at the first `:`.
fn push_attributes<'pkt, I>(
    buf: &mut DissectBuffer<'pkt>,
    lines: I,
    array_desc: &'static FieldDescriptor,
    offset: usize,
) where
    I: Iterator<Item = Line<'pkt>> + Clone,
{
    let items = lines.filter(|l| l.kind == b'a' && !l.value.is_empty());
    let Some(range) = items_range(items.clone(), offset) else {
        return;
    };
    let array_idx = buf.begin_container(array_desc, FieldValue::Array(0..0), range);
    for line in items {
        let (name, value) = match line.value.split_once(':') {
            Some((name, value)) => (name, Some(value)),
            None => (line.value, None),
        };
        if name.is_empty() {
            continue;
        }
        let r = line_range(&line, offset);
        let obj_idx = buf.begin_container(&FD_ATTRIBUTE_ITEM, FieldValue::Object(0..0), r.clone());
        buf.push_field(
            &ATTRIBUTE_CHILDREN[AC_NAME],
            FieldValue::Str(name),
            r.clone(),
        );
        if let Some(value) = value {
            buf.push_field(&ATTRIBUTE_CHILDREN[AC_VALUE], FieldValue::Str(value), r);
        }
        buf.end_container(obj_idx);
    }
    buf.end_container(array_idx);
}

// ---------------------------------------------------------------------------
// Media-section parsing
// ---------------------------------------------------------------------------

/// A parsed `m=` line (RFC 8866, Section 5.14 —
/// <https://www.rfc-editor.org/rfc/rfc8866#section-5.14>).
struct MediaLine<'a> {
    media: &'a str,
    port: u16,
    num_ports: Option<u16>,
    proto: &'a str,
    formats: &'a str,
}

/// Parse an `m=` line value:
/// `<media> <port>[/<number of ports>] <proto> <fmt> ...`.
///
/// Unlike the optional session lines, a malformed `m=` line is an error:
/// it defines the structure of everything that follows.
fn parse_media_line(value: &str) -> Result<MediaLine<'_>, PacketError> {
    const MALFORMED: PacketError = PacketError::InvalidHeader("malformed SDP media line");

    let (media, rest) = take_token(value).ok_or(MALFORMED)?;
    let (port_spec, rest) = take_token(rest).ok_or(MALFORMED)?;
    let (proto, rest) = take_token(rest).ok_or(MALFORMED)?;
    // RFC 8866, Section 9 — ABNF `1*(SP fmt)`: at least one <fmt> is required
    let formats = rest.trim_matches(' ');
    if formats.is_empty() {
        return Err(MALFORMED);
    }

    let (port_str, num_str) = match port_spec.split_once('/') {
        Some((port, num)) => (port, Some(num)),
        None => (port_spec, None),
    };
    let port_value: u32 = port_str
        .parse()
        .map_err(|_| PacketError::InvalidHeader("invalid SDP media port"))?;
    let port = u16::try_from(port_value).map_err(|_| PacketError::InvalidFieldValue {
        field: "port",
        value: port_value,
    })?;
    // A malformed port count is tolerated (Postel's Law)
    let num_ports = num_str.and_then(|s| s.parse::<u16>().ok());

    Ok(MediaLine {
        media,
        port,
        num_ports,
        proto,
        formats,
    })
}

/// Lines belonging to one media section: everything after the `m=` line
/// up to the next `m=` line.
fn media_section_lines<'a>(
    data: &'a [u8],
    m_line: Line<'a>,
) -> impl Iterator<Item = Line<'a>> + Clone {
    lines(data)
        .skip_while(move |l| l.start <= m_line.start)
        .take_while(|l| l.kind != b'm')
}

/// Parse all `m=` media sections into the `media_descriptions` Array.
///
/// All `m=` lines were already validated by [`validate_message`]; the
/// skip on parse failure here is purely defensive.
fn parse_media_sections<'pkt>(data: &'pkt [u8], buf: &mut DissectBuffer<'pkt>, offset: usize) {
    let m_lines = lines(data).filter(|l| l.kind == b'm');
    let Some(array_range) = items_range(m_lines.clone(), offset) else {
        return;
    };
    // The Array spans from the first m= line to the end of the message.
    let array_range = array_range.start..offset + data.len();

    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_MEDIA_DESCRIPTIONS],
        FieldValue::Array(0..0),
        array_range,
    );

    for m_line in m_lines {
        let Ok(media) = parse_media_line(m_line.value) else {
            continue;
        };

        let section = media_section_lines(data, m_line);
        let section_end = items_range(section.clone(), offset)
            .map(|r| r.end)
            .unwrap_or_else(|| line_range(&m_line, offset).end);
        let obj_range = line_range(&m_line, offset).start..section_end;
        let m_range = line_range(&m_line, offset);

        let obj_idx = buf.begin_container(&FD_MEDIA_ITEM, FieldValue::Object(0..0), obj_range);
        buf.push_field(
            &MEDIA_CHILDREN[MC_MEDIA],
            FieldValue::Str(media.media),
            m_range.clone(),
        );
        buf.push_field(
            &MEDIA_CHILDREN[MC_PORT],
            FieldValue::U16(media.port),
            m_range.clone(),
        );
        if let Some(num_ports) = media.num_ports {
            buf.push_field(
                &MEDIA_CHILDREN[MC_NUM_PORTS],
                FieldValue::U16(num_ports),
                m_range.clone(),
            );
        }
        buf.push_field(
            &MEDIA_CHILDREN[MC_PROTO],
            FieldValue::Str(media.proto),
            m_range.clone(),
        );
        buf.push_field(
            &MEDIA_CHILDREN[MC_FORMATS],
            FieldValue::Str(media.formats),
            m_range,
        );

        // RFC 8866, Section 5.4 — media-level i= is the media title
        if let Some(line) = section.clone().find(|l| l.kind == b'i') {
            buf.push_field(
                &MEDIA_CHILDREN[MC_TITLE],
                FieldValue::Str(line.value),
                line_range(&line, offset),
            );
        }
        push_connections(buf, section.clone(), &MEDIA_CHILDREN[MC_CONNECTION], offset);
        push_bandwidths(buf, section.clone(), &MEDIA_CHILDREN[MC_BANDWIDTHS], offset);
        push_attributes(buf, section, &MEDIA_CHILDREN[MC_ATTRIBUTES], offset);

        buf.end_container(obj_idx);
    }

    buf.end_container(array_idx);
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 8866 (SDP) Coverage
    //
    // | RFC Section | Description                     | Test                                    |
    // |-------------|---------------------------------|-----------------------------------------|
    // | 5           | Session description format     | parse_sdp_minimal_session               |
    // | 5.1         | Protocol Version (v=)          | parse_sdp_minimal_session               |
    // | 5.1         | Version must be 0              | parse_sdp_invalid_version               |
    // | 5.2         | Origin (o=)                    | parse_sdp_minimal_session               |
    // | 5.2         | Malformed origin skipped       | parse_sdp_malformed_origin_skipped      |
    // | 5.3         | Session Name (s=)              | parse_sdp_minimal_session               |
    // | 5.4         | Session Information (i=)       | parse_sdp_full_session                  |
    // | 5.5         | URI (u=)                       | parse_sdp_full_session                  |
    // | 5.6         | Email (e=) / Phone (p=)        | parse_sdp_emails_and_phones             |
    // | 5.7         | Connection Information (c=)    | parse_sdp_full_session                  |
    // | 5.7         | Media-level connection         | parse_sdp_full_session                  |
    // | 5.7         | Multiple media-level c=        | parse_sdp_media_multiple_connections    |
    // | 5.8         | Bandwidth (b=)                 | parse_sdp_full_session                  |
    // | 5.8         | Malformed bandwidth skipped    | parse_sdp_malformed_optional_lines      |
    // | 5.8         | Unbounded bandwidth value      | parse_sdp_unbounded_time_and_bandwidth  |
    // | 5.9         | Time Active (t=)               | parse_sdp_minimal_session               |
    // | 5.9         | Malformed timing skipped       | parse_sdp_malformed_optional_lines      |
    // | 5.9         | Unbounded time value           | parse_sdp_unbounded_time_and_bandwidth  |
    // | 5.10        | Repeat Times (r=)              | parse_sdp_repeat_and_zone               |
    // | 5.11        | Time Zone Adjustment (z=)      | parse_sdp_repeat_and_zone               |
    // | 5.12        | Obsolete key line (k=) skipped | parse_sdp_unknown_lines_skipped         |
    // | 5.13        | Attributes (a=)                | parse_sdp_attributes                    |
    // | 5.13        | Property vs value attributes   | parse_sdp_attributes                    |
    // | 5.14        | Media Descriptions (m=)        | parse_sdp_full_session                  |
    // | 5.14        | Port with count (49170/2)      | parse_sdp_media_port_with_count         |
    // | 5.14        | Malformed media line           | parse_sdp_malformed_media_line          |
    // | 5.14        | Media port out of range        | parse_sdp_media_port_out_of_range       |
    // | 5           | LF-only / missing final EOL    | parse_sdp_lf_only_no_trailing_newline   |
    // | 9           | non-ws-string with %x80-FF     | parse_sdp_origin_with_unicode_space     |
    // | -           | Truncated input                | parse_sdp_truncated                     |
    // | -           | First line not v=              | parse_sdp_missing_version               |
    // | -           | Line without '=' skipped       | parse_sdp_line_missing_equals_skipped   |
    // | -           | Non-UTF-8 line skipped         | parse_sdp_non_utf8_line_skipped         |
    // | -           | Non-UTF-8 m= line rejected     | parse_sdp_non_utf8_media_line           |
    // | -           | bytes_consumed / End hint      | parse_sdp_consumes_all_and_ends         |
    // | -           | Offset handling                | parse_sdp_with_offset                   |
    // | -           | Dissector metadata             | dissector_metadata                      |

    fn dissect(data: &[u8]) -> Result<DissectBuffer<'_>, PacketError> {
        let dissector = SdpDissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(data, &mut buf, 0)?;
        Ok(buf)
    }

    fn dissect_err(data: &[u8]) -> PacketError {
        let dissector = SdpDissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(data, &mut buf, 0).unwrap_err()
    }

    /// Return the direct Object elements (matched by item name) of an
    /// Array field. `nested_fields` is flat, so descendants of nested
    /// containers must be filtered out by the element descriptor name.
    fn array_objects<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        layer_field: &'a packet_dissector_core::field::Field<'pkt>,
        item_name: &str,
    ) -> Vec<&'a packet_dissector_core::field::Field<'pkt>> {
        let range = match &layer_field.value {
            FieldValue::Array(r) => r,
            other => panic!("expected Array, got {other:?}"),
        };
        buf.nested_fields(range)
            .iter()
            .filter(|f| f.value.is_object() && f.name() == item_name)
            .collect()
    }

    #[test]
    fn parse_sdp_minimal_session() {
        let data = b"v=0\r\n\
                     o=alice 2890844526 2890844527 IN IP4 host.example.com\r\n\
                     s=-\r\n\
                     t=0 0\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "session_name").unwrap().value,
            FieldValue::Str("-")
        );

        // RFC 8866, Section 5.2 — o= has six sub-fields
        let origin = buf.field_by_name(layer, "origin").unwrap();
        let origin_range = match &origin.value {
            FieldValue::Object(r) => r,
            other => panic!("expected Object, got {other:?}"),
        };
        let children = buf.nested_fields(origin_range);
        assert_eq!(children[0].value, FieldValue::Str("alice"));
        assert_eq!(children[1].value, FieldValue::Str("2890844526"));
        assert_eq!(children[2].value, FieldValue::Str("2890844527"));
        assert_eq!(children[3].value, FieldValue::Str("IN"));
        assert_eq!(children[4].value, FieldValue::Str("IP4"));
        assert_eq!(children[5].value, FieldValue::Str("host.example.com"));

        // RFC 8866, Section 5.9 — t= start/stop times (kept verbatim: the
        // ABNF `time` is an unbounded-length numeric field)
        let times = buf.field_by_name(layer, "times").unwrap();
        let objects = array_objects(&buf, times, "time");
        assert_eq!(objects.len(), 1);
        if let FieldValue::Object(ref r) = objects[0].value {
            let f = buf.nested_fields(r);
            assert_eq!(f[0].value, FieldValue::Str("0"));
            assert_eq!(f[1].value, FieldValue::Str("0"));
        }

        assert!(buf.field_by_name(layer, "media_descriptions").is_none());
    }

    #[test]
    fn parse_sdp_full_session() {
        let data = b"v=0\r\n\
                     o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1\r\n\
                     s=Call to John Smith\r\n\
                     i=SDP Offer #1\r\n\
                     u=http://www.jdoe.example.com/home.html\r\n\
                     c=IN IP4 198.51.100.1\r\n\
                     b=CT:64\r\n\
                     t=0 0\r\n\
                     a=recvonly\r\n\
                     m=audio 49170 RTP/AVP 0\r\n\
                     a=rtpmap:0 PCMU/8000\r\n\
                     m=video 51372 RTP/AVP 99\r\n\
                     i=Video feed\r\n\
                     c=IN IP4 198.51.100.2\r\n\
                     b=AS:256\r\n\
                     a=rtpmap:99 h263-1998/90000\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "session_name").unwrap().value,
            FieldValue::Str("Call to John Smith")
        );
        assert_eq!(
            buf.field_by_name(layer, "session_information")
                .unwrap()
                .value,
            FieldValue::Str("SDP Offer #1")
        );
        assert_eq!(
            buf.field_by_name(layer, "uri").unwrap().value,
            FieldValue::Str("http://www.jdoe.example.com/home.html")
        );

        // RFC 8866, Section 5.7 — session-level c=
        let conn = buf.field_by_name(layer, "connection").unwrap();
        if let FieldValue::Object(ref r) = conn.value {
            let f = buf.nested_fields(r);
            assert_eq!(f[0].value, FieldValue::Str("IN"));
            assert_eq!(f[1].value, FieldValue::Str("IP4"));
            assert_eq!(f[2].value, FieldValue::Str("198.51.100.1"));
        } else {
            panic!("expected Object");
        }

        // RFC 8866, Section 5.8 — session-level b=
        let bws = buf.field_by_name(layer, "bandwidths").unwrap();
        let bw_objects = array_objects(&buf, bws, "bandwidth_info");
        assert_eq!(bw_objects.len(), 1);
        if let FieldValue::Object(ref r) = bw_objects[0].value {
            let f = buf.nested_fields(r);
            assert_eq!(f[0].value, FieldValue::Str("CT"));
            assert_eq!(f[1].value, FieldValue::Str("64"));
        }

        // RFC 8866, Section 5.14 — two media descriptions
        let media = buf.field_by_name(layer, "media_descriptions").unwrap();
        let sections = array_objects(&buf, media, "media_description");
        assert_eq!(sections.len(), 2);

        // audio section
        if let FieldValue::Object(ref r) = sections[0].value {
            let f = buf.nested_fields(r);
            let by_name = |n: &str| f.iter().find(|x| x.name() == n);
            assert_eq!(by_name("media").unwrap().value, FieldValue::Str("audio"));
            assert_eq!(by_name("port").unwrap().value, FieldValue::U16(49170));
            assert_eq!(by_name("proto").unwrap().value, FieldValue::Str("RTP/AVP"));
            assert_eq!(by_name("formats").unwrap().value, FieldValue::Str("0"));
            assert!(by_name("num_ports").is_none());
            assert!(by_name("title").is_none());
            assert!(by_name("connections").is_none());
        }

        // video section: media-level i=, c=, b=, a=
        if let FieldValue::Object(ref r) = sections[1].value {
            let f = buf.nested_fields(r);
            let by_name = |n: &str| f.iter().find(|x| x.name() == n);
            assert_eq!(by_name("media").unwrap().value, FieldValue::Str("video"));
            assert_eq!(by_name("port").unwrap().value, FieldValue::U16(51372));
            assert_eq!(by_name("formats").unwrap().value, FieldValue::Str("99"));
            assert_eq!(
                by_name("title").unwrap().value,
                FieldValue::Str("Video feed")
            );
            let conns = by_name("connections").unwrap();
            let conn_range = conns.value.as_container_range().unwrap();
            let conn_obj = buf
                .nested_fields(conn_range)
                .iter()
                .find(|x| x.value.is_object())
                .cloned()
                .unwrap();
            if let FieldValue::Object(ref cr) = conn_obj.value {
                let cf = buf.nested_fields(cr);
                assert_eq!(cf[2].value, FieldValue::Str("198.51.100.2"));
            } else {
                panic!("expected Object");
            }
            let bw = by_name("bandwidths").unwrap();
            let bw_range = bw.value.as_container_range().unwrap();
            let bw_children = buf.nested_fields(bw_range);
            let bw_obj = bw_children.iter().find(|x| x.value.is_object()).unwrap();
            if let FieldValue::Object(ref br) = bw_obj.value {
                let bf = buf.nested_fields(br);
                assert_eq!(bf[0].value, FieldValue::Str("AS"));
                assert_eq!(bf[1].value, FieldValue::Str("256"));
            }
            let attrs = by_name("attributes").unwrap();
            let attr_range = attrs.value.as_container_range().unwrap();
            let attr_children = buf.nested_fields(attr_range);
            let attr_obj = attr_children.iter().find(|x| x.value.is_object()).unwrap();
            if let FieldValue::Object(ref ar) = attr_obj.value {
                let af = buf.nested_fields(ar);
                assert_eq!(af[0].value, FieldValue::Str("rtpmap"));
                assert_eq!(af[1].value, FieldValue::Str("99 h263-1998/90000"));
            }
        }
    }

    #[test]
    fn parse_sdp_attributes() {
        let data = b"v=0\r\n\
                     s=attrs\r\n\
                     a=recvonly\r\n\
                     a=rtpmap:96 opus/48000/2\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();

        let attrs = buf.field_by_name(layer, "session_attributes").unwrap();
        let objects = array_objects(&buf, attrs, "attribute");
        assert_eq!(objects.len(), 2);

        // RFC 8866, Section 5.13 — property attribute (no value)
        if let FieldValue::Object(ref r) = objects[0].value {
            let f = buf.nested_fields(r);
            assert_eq!(f.len(), 1);
            assert_eq!(f[0].value, FieldValue::Str("recvonly"));
        }

        // RFC 8866, Section 5.13 — value attribute, split at the first ':'
        if let FieldValue::Object(ref r) = objects[1].value {
            let f = buf.nested_fields(r);
            assert_eq!(f[0].value, FieldValue::Str("rtpmap"));
            assert_eq!(f[1].value, FieldValue::Str("96 opus/48000/2"));
        }
    }

    #[test]
    fn parse_sdp_emails_and_phones() {
        let data = b"v=0\r\n\
                     s=contact\r\n\
                     e=j.doe@example.com (Jane Doe)\r\n\
                     e=jane@example.org\r\n\
                     p=+1 617 555-6011\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();

        let emails = buf.field_by_name(layer, "emails").unwrap();
        let range = emails.value.as_container_range().unwrap();
        let items = buf.nested_fields(range);
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0].value,
            FieldValue::Str("j.doe@example.com (Jane Doe)")
        );
        assert_eq!(items[1].value, FieldValue::Str("jane@example.org"));

        let phones = buf.field_by_name(layer, "phones").unwrap();
        let range = phones.value.as_container_range().unwrap();
        let items = buf.nested_fields(range);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].value, FieldValue::Str("+1 617 555-6011"));
    }

    #[test]
    fn parse_sdp_repeat_and_zone() {
        // RFC 8866, Section 9 — each time-description may carry its own
        // repeat-description with a zone-field, so multiple z= lines can
        // appear in one session description.
        let data = b"v=0\r\n\
                     s=repeats\r\n\
                     t=3724394400 3724398000\r\n\
                     r=604800 3600 0 90000\r\n\
                     z=3730928400 -1h 3749680800 0\r\n\
                     t=3730000000 3730003600\r\n\
                     r=86400 1800 0\r\n\
                     z=3749680800 0\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();

        let repeats = buf.field_by_name(layer, "repeat_times").unwrap();
        let range = repeats.value.as_container_range().unwrap();
        let items = buf.nested_fields(range);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].value, FieldValue::Str("604800 3600 0 90000"));
        assert_eq!(items[1].value, FieldValue::Str("86400 1800 0"));

        let zones = buf.field_by_name(layer, "time_zones").unwrap();
        let range = zones.value.as_container_range().unwrap();
        let items = buf.nested_fields(range);
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0].value,
            FieldValue::Str("3730928400 -1h 3749680800 0")
        );
        assert_eq!(items[1].value, FieldValue::Str("3749680800 0"));
    }

    #[test]
    fn parse_sdp_unbounded_time_and_bandwidth() {
        // RFC 8866, Section 5.9 — "The representation is an unbounded
        // length field"; Section 5.8 gives no length limit for <bandwidth>.
        // Values beyond u64 must not be dropped.
        let data = b"v=0\r\n\
                     s=big numbers\r\n\
                     b=CT:99999999999999999999999\r\n\
                     t=111111111111111111111 222222222222222222222\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();

        let bws = buf.field_by_name(layer, "bandwidths").unwrap();
        let bw_objects = array_objects(&buf, bws, "bandwidth_info");
        assert_eq!(bw_objects.len(), 1);
        if let FieldValue::Object(ref r) = bw_objects[0].value {
            let f = buf.nested_fields(r);
            assert_eq!(f[1].value, FieldValue::Str("99999999999999999999999"));
        }

        let times = buf.field_by_name(layer, "times").unwrap();
        let objects = array_objects(&buf, times, "time");
        assert_eq!(objects.len(), 1);
        if let FieldValue::Object(ref r) = objects[0].value {
            let f = buf.nested_fields(r);
            assert_eq!(f[0].value, FieldValue::Str("111111111111111111111"));
            assert_eq!(f[1].value, FieldValue::Str("222222222222222222222"));
        }
    }

    #[test]
    fn parse_sdp_origin_with_unicode_space() {
        // RFC 8866, Section 9 — o= subfields are non-ws-string =
        // 1*(VCHAR/%x80-FF): bytes in %x80-FF (e.g. U+00A0 NO-BREAK SPACE)
        // are legal inside a username. Only the ASCII SP separates fields.
        let data = "v=0\r\n\
                    o=al\u{00A0}ice 1 2 IN IP4 host.example.com\r\n\
                    s=nbsp\r\n"
            .as_bytes();
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();

        let origin = buf.field_by_name(layer, "origin").unwrap();
        let origin_range = match &origin.value {
            FieldValue::Object(r) => r,
            other => panic!("expected Object, got {other:?}"),
        };
        let children = buf.nested_fields(origin_range);
        assert_eq!(children[0].value, FieldValue::Str("al\u{00A0}ice"));
        assert_eq!(children[5].value, FieldValue::Str("host.example.com"));
    }

    #[test]
    fn parse_sdp_media_multiple_connections() {
        // RFC 8866, Section 5.7 — "Multiple addresses or "c=" lines MAY be
        // specified on a per media description basis" (layered encoding).
        let data = b"v=0\r\n\
                     s=layered\r\n\
                     m=video 49170/2 RTP/AVP 31\r\n\
                     c=IN IP4 233.252.0.1/127\r\n\
                     c=IN IP4 233.252.0.2/127\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();

        let media = buf.field_by_name(layer, "media_descriptions").unwrap();
        let sections = array_objects(&buf, media, "media_description");
        assert_eq!(sections.len(), 1);
        if let FieldValue::Object(ref r) = sections[0].value {
            let f = buf.nested_fields(r);
            let conns = f.iter().find(|x| x.name() == "connections").unwrap();
            let conn_range = conns.value.as_container_range().unwrap();
            let objects: Vec<_> = buf
                .nested_fields(conn_range)
                .iter()
                .filter(|x| x.value.is_object() && x.name() == "connection")
                .cloned()
                .collect();
            assert_eq!(objects.len(), 2);
            if let FieldValue::Object(ref cr) = objects[1].value {
                let cf = buf.nested_fields(cr);
                assert_eq!(cf[2].value, FieldValue::Str("233.252.0.2/127"));
            }
        }
    }

    #[test]
    fn parse_sdp_media_port_with_count() {
        // RFC 8866, Section 5.14 — <port>/<number of ports>
        let data = b"v=0\r\n\
                     s=ports\r\n\
                     m=audio 49170/2 RTP/AVP 0 8 97\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();

        let media = buf.field_by_name(layer, "media_descriptions").unwrap();
        let sections = array_objects(&buf, media, "media_description");
        assert_eq!(sections.len(), 1);
        if let FieldValue::Object(ref r) = sections[0].value {
            let f = buf.nested_fields(r);
            let by_name = |n: &str| f.iter().find(|x| x.name() == n);
            assert_eq!(by_name("port").unwrap().value, FieldValue::U16(49170));
            assert_eq!(by_name("num_ports").unwrap().value, FieldValue::U16(2));
            assert_eq!(by_name("formats").unwrap().value, FieldValue::Str("0 8 97"));
        }
    }

    #[test]
    fn parse_sdp_lf_only_no_trailing_newline() {
        // LF-only line endings and a final line without a terminator
        let data = b"v=0\ns=lf only\nm=audio 49170 RTP/AVP 0";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();

        assert_eq!(
            buf.field_by_name(layer, "session_name").unwrap().value,
            FieldValue::Str("lf only")
        );
        let media = buf.field_by_name(layer, "media_descriptions").unwrap();
        let sections = array_objects(&buf, media, "media_description");
        assert_eq!(sections.len(), 1);
    }

    #[test]
    fn parse_sdp_unknown_lines_skipped() {
        // k= is obsolete (RFC 8866, Section 5.12); x= is an unknown extension
        let data = b"v=0\r\n\
                     s=unknown\r\n\
                     k=prompt\r\n\
                     x=extension value\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "session_name").unwrap().value,
            FieldValue::Str("unknown")
        );
    }

    #[test]
    fn parse_sdp_malformed_optional_lines() {
        // Malformed b= (no ':') and t= (non-numeric) lines are skipped
        let data = b"v=0\r\n\
                     s=lenient\r\n\
                     b=CT64\r\n\
                     b=CT:notanumber\r\n\
                     t=now later\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();
        assert!(buf.field_by_name(layer, "bandwidths").is_none());
        assert!(buf.field_by_name(layer, "times").is_none());
    }

    #[test]
    fn parse_sdp_malformed_origin_skipped() {
        // o= with fewer than six tokens is skipped, not an error
        let data = b"v=0\r\n\
                     o=alice 123\r\n\
                     s=lenient origin\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();
        assert!(buf.field_by_name(layer, "origin").is_none());
        assert_eq!(
            buf.field_by_name(layer, "session_name").unwrap().value,
            FieldValue::Str("lenient origin")
        );
    }

    #[test]
    fn parse_sdp_truncated() {
        assert!(matches!(
            dissect_err(b""),
            PacketError::Truncated {
                expected: MIN_LEN,
                actual: 0
            }
        ));
        assert!(matches!(
            dissect_err(b"v="),
            PacketError::Truncated {
                expected: MIN_LEN,
                actual: 2
            }
        ));
    }

    #[test]
    fn parse_sdp_missing_version() {
        let data = b"s=no version first\r\nv=0\r\n";
        assert!(matches!(dissect_err(data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_sdp_invalid_version() {
        // RFC 8866, Section 5.1 — this memo defines version 0
        assert!(matches!(
            dissect_err(b"v=1\r\ns=x\r\n"),
            PacketError::InvalidFieldValue {
                field: "version",
                value: 1
            }
        ));
        assert!(matches!(
            dissect_err(b"v=abc\r\ns=x\r\n"),
            PacketError::InvalidHeader(_)
        ));
    }

    #[test]
    fn parse_sdp_line_missing_equals_skipped() {
        // A structurally broken non-m= line is skipped (Postel's Law),
        // not a reason to reject the whole session description.
        let data = b"v=0\r\njunk line without equals\r\ns=still parsed\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "session_name").unwrap().value,
            FieldValue::Str("still parsed")
        );
    }

    #[test]
    fn parse_sdp_non_utf8_line_skipped() {
        // RFC 8866, Section 9 — text = byte-string permits any byte except
        // NUL/CR/LF (e.g. ISO-8859-1 via a=charset). Such a line must not
        // reject the whole message; the (undecodable) line is skipped.
        let data = b"v=0\r\ns=\xff\xfe\r\ni=utf8 info\r\n";
        let buf = dissect(data).unwrap();
        let layer = buf.layer_by_name("SDP").unwrap();
        assert!(buf.field_by_name(layer, "session_name").is_none());
        assert_eq!(
            buf.field_by_name(layer, "session_information")
                .unwrap()
                .value,
            FieldValue::Str("utf8 info")
        );
    }

    #[test]
    fn parse_sdp_non_utf8_media_line() {
        // m= subfields are ASCII tokens; a non-UTF-8 m= line is malformed
        // and rejects the message like any other malformed m= line.
        let data = b"v=0\r\ns=x\r\nm=audio 49170 RTP/AVP \xff\r\n";
        assert!(matches!(dissect_err(data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_sdp_malformed_media_line() {
        // RFC 8866, Section 5.14 — m= requires media, port, proto, fmt
        assert!(matches!(
            dissect_err(b"v=0\r\ns=x\r\nm=audio\r\n"),
            PacketError::InvalidHeader(_)
        ));
        assert!(matches!(
            dissect_err(b"v=0\r\ns=x\r\nm=audio 49170 RTP/AVP\r\n"),
            PacketError::InvalidHeader(_)
        ));
        assert!(matches!(
            dissect_err(b"v=0\r\ns=x\r\nm=audio portx RTP/AVP 0\r\n"),
            PacketError::InvalidHeader(_)
        ));
    }

    #[test]
    fn parse_sdp_media_port_out_of_range() {
        assert!(matches!(
            dissect_err(b"v=0\r\ns=x\r\nm=audio 99999 RTP/AVP 0\r\n"),
            PacketError::InvalidFieldValue {
                field: "port",
                value: 99999
            }
        ));
    }

    #[test]
    fn parse_sdp_consumes_all_and_ends() {
        let data = b"v=0\r\ns=end\r\nm=audio 49170 RTP/AVP 0\r\n";
        let dissector = SdpDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn parse_sdp_with_offset() {
        let data = b"v=0\r\ns=offset\r\n";
        let dissector = SdpDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(data, &mut buf, 42).unwrap();

        let layer = buf.layer_by_name("SDP").unwrap();
        assert_eq!(layer.range.start, 42);
        assert_eq!(layer.range.end, 42 + data.len());
        assert_eq!(result.bytes_consumed, data.len());

        let version = buf.field_by_name(layer, "version").unwrap();
        assert_eq!(version.range, 42..45);
    }

    #[test]
    fn dissector_metadata() {
        let d = SdpDissector;
        assert_eq!(d.name(), "Session Description Protocol");
        assert_eq!(d.short_name(), "SDP");
        assert!(!d.field_descriptors().is_empty());
    }
}
