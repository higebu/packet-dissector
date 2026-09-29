//! SvcParams decoding for the SVCB and HTTPS RRs.
//!
//! ## References
//! - RFC 9460, Section 2.2 (RDATA wire format): <https://www.rfc-editor.org/rfc/rfc9460#section-2.2>
//! - RFC 9460, Section 7 (initial SvcParamKeys): <https://www.rfc-editor.org/rfc/rfc9460#section-7>
//! - RFC 9460, Section 8 ("mandatory"): <https://www.rfc-editor.org/rfc/rfc9460#section-8>
//! - RFC 9848, Section 3 ("ech"): <https://www.rfc-editor.org/rfc/rfc9848#section-3>
//! - RFC 9461, Section 5 ("dohpath"): <https://www.rfc-editor.org/rfc/rfc9461#section-5>
//! - IANA Service Parameter Keys (SvcParamKeys): <https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

/// "mandatory" — RFC 9460, Section 8 — <https://www.rfc-editor.org/rfc/rfc9460#section-8>
const KEY_MANDATORY: u16 = 0;
/// "alpn" — RFC 9460, Section 7.1 — <https://www.rfc-editor.org/rfc/rfc9460#section-7.1>
const KEY_ALPN: u16 = 1;
/// "no-default-alpn" — RFC 9460, Section 7.1 — <https://www.rfc-editor.org/rfc/rfc9460#section-7.1>
const KEY_NO_DEFAULT_ALPN: u16 = 2;
/// "port" — RFC 9460, Section 7.2 — <https://www.rfc-editor.org/rfc/rfc9460#section-7.2>
const KEY_PORT: u16 = 3;
/// "ipv4hint" — RFC 9460, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc9460#section-7.3>
const KEY_IPV4HINT: u16 = 4;
/// "ech" — RFC 9848, Section 3 — <https://www.rfc-editor.org/rfc/rfc9848#section-3>
const KEY_ECH: u16 = 5;
/// "ipv6hint" — RFC 9460, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc9460#section-7.3>
const KEY_IPV6HINT: u16 = 6;
/// "dohpath" — RFC 9461, Section 5 — <https://www.rfc-editor.org/rfc/rfc9461#section-5>
const KEY_DOHPATH: u16 = 7;

/// Returns the registered name of a SvcParamKey.
///
/// Names follow the IANA "Service Parameter Keys (SvcParamKeys)" registry
/// (RFC 9460, Section 14.3.2 — <https://www.rfc-editor.org/rfc/rfc9460#section-14.3.2>).
pub(crate) fn svc_param_key_name(key: u16) -> Option<&'static str> {
    match key {
        KEY_MANDATORY => Some("mandatory"),
        KEY_ALPN => Some("alpn"),
        KEY_NO_DEFAULT_ALPN => Some("no-default-alpn"),
        KEY_PORT => Some("port"),
        KEY_IPV4HINT => Some("ipv4hint"),
        KEY_ECH => Some("ech"),
        KEY_IPV6HINT => Some("ipv6hint"),
        KEY_DOHPATH => Some("dohpath"),
        8 => Some("ohttp"),
        9 => Some("tls-supported-groups"),
        10 => Some("docpath"),
        11 => Some("pvd"),
        12 => Some("oots"),
        _ => None,
    }
}

// Indices into SVC_PARAM_CHILD_FIELDS.
const SPFD_KEY: usize = 0;
const SPFD_LENGTH: usize = 1;
const SPFD_MANDATORY: usize = 2;
const SPFD_ALPN: usize = 3;
const SPFD_PORT: usize = 4;
const SPFD_IPV4HINT: usize = 5;
const SPFD_ECH: usize = 6;
const SPFD_IPV6HINT: usize = 7;
const SPFD_DOHPATH: usize = 8;
const SPFD_VALUE: usize = 9;

/// Element descriptor for a key listed in "mandatory".
static FD_MANDATORY_KEY: FieldDescriptor = FieldDescriptor {
    name: "key",
    display_name: "Key",
    field_type: FieldType::U16,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U16(k) => svc_param_key_name(*k),
        _ => None,
    }),
    format_fn: None,
};

/// Element descriptor for one ALPN identifier.
static FD_ALPN_ID: FieldDescriptor =
    FieldDescriptor::new("alpn_id", "ALPN ID", FieldType::Bytes).with_format_fn(format_utf8_lossy);

/// Element descriptor for one "ipv4hint" address.
static FD_IPV4_HINT: FieldDescriptor =
    FieldDescriptor::new("address", "Address", FieldType::Ipv4Addr);

/// Element descriptor for one "ipv6hint" address.
static FD_IPV6_HINT: FieldDescriptor =
    FieldDescriptor::new("address", "Address", FieldType::Ipv6Addr);

/// Child field descriptors for one SvcParam entry.
///
/// RFC 9460, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc9460#section-2.2>
pub(crate) static SVC_PARAM_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "key",
        display_name: "SvcParamKey",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(k) => svc_param_key_name(*k),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("mandatory", "Mandatory Keys", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_MANDATORY_KEY)),
    FieldDescriptor::new("alpn", "ALPN IDs", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_ALPN_ID)),
    FieldDescriptor::new("port", "Port", FieldType::U16).optional(),
    FieldDescriptor::new("ipv4hint", "IPv4 Hints", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_IPV4_HINT)),
    FieldDescriptor::new("ech", "ECHConfigList", FieldType::Bytes).optional(),
    FieldDescriptor::new("ipv6hint", "IPv6 Hints", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_IPV6_HINT)),
    FieldDescriptor::new("dohpath", "DoH Path", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("value", "SvcParamValue", FieldType::Bytes).optional(),
];

/// Descriptor for one SvcParam Object; its label resolves to the key name.
pub(crate) static FD_SVC_PARAM: FieldDescriptor = FieldDescriptor {
    name: "svc_param",
    display_name: "SvcParam",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("key", FieldValue::U16(k)) => svc_param_key_name(*k),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Whether `params` is a sequence of complete SvcParams.
///
/// RFC 9460, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc9460#section-2.2>
/// lists three conditions under which clients "MUST consider an RR
/// malformed". Only the first, "the end of the RDATA occurs within a
/// SvcParam", stops the list from being decoded. Keys that are out of
/// order or repeated, and values without the expected format, are still
/// shown as they appear on the wire (a malformed value is kept as the raw
/// `value` field).
fn is_complete(params: &[u8]) -> bool {
    let mut pos = 0;
    while pos < params.len() {
        let Ok(len) = read_be_u16(params, pos + 2) else {
            return false;
        };
        pos += 4 + len as usize;
    }
    pos == params.len()
}

/// Whether `value` is a non-empty ALPN list that exactly fills the value.
///
/// RFC 9460, Section 7.1.1 — <https://www.rfc-editor.org/rfc/rfc9460#section-7.1.1>:
/// "The wire-format value for "alpn" consists of at least one alpn-id
/// prefixed by its length as a single octet, and these length-value pairs
/// are concatenated to form the SvcParamValue.  These pairs MUST exactly
/// fill the SvcParamValue; otherwise, the SvcParamValue is malformed."
/// An alpn-id is 1 to 255 octets.
fn is_alpn_list(value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut pos = 0;
    while pos < value.len() {
        let len = value[pos] as usize;
        if len == 0 || pos + 1 + len > value.len() {
            return false;
        }
        pos += 1 + len;
    }
    true
}

/// Push `rdata_svc_params_fd` as an Array of decoded SvcParams.
///
/// `params` is the SvcParams part of the RDATA, starting at absolute offset
/// `abs_offset`. Nothing is pushed if the list is malformed (the caller
/// already keeps the raw bytes). A value that does not have the format
/// defined for its key is kept as the raw `value` field.
pub(crate) fn push_svc_params<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    rdata_svc_params_fd: &'static FieldDescriptor,
    params: &'pkt [u8],
    abs_offset: usize,
) {
    if params.is_empty() || !is_complete(params) {
        return;
    }
    let arr = buf.begin_container(
        rdata_svc_params_fd,
        FieldValue::Array(0..0),
        abs_offset..abs_offset + params.len(),
    );
    let mut pos = 0;
    while pos + 4 <= params.len() {
        let key = read_be_u16(params, pos).unwrap_or_default();
        let len = read_be_u16(params, pos + 2).unwrap_or_default() as usize;
        let value = &params[pos + 4..pos + 4 + len];
        let start = abs_offset + pos;
        let obj = buf.begin_container(
            &FD_SVC_PARAM,
            FieldValue::Object(0..0),
            start..start + 4 + len,
        );
        buf.push_field(
            &SVC_PARAM_CHILD_FIELDS[SPFD_KEY],
            FieldValue::U16(key),
            start..start + 2,
        );
        buf.push_field(
            &SVC_PARAM_CHILD_FIELDS[SPFD_LENGTH],
            FieldValue::U16(len as u16),
            start + 2..start + 4,
        );
        if !push_value(buf, key, value, start + 4) {
            buf.push_field(
                &SVC_PARAM_CHILD_FIELDS[SPFD_VALUE],
                FieldValue::Bytes(value),
                start + 4..start + 4 + len,
            );
        }
        buf.end_container(obj);
        pos += 4 + len;
    }
    buf.end_container(arr);
}

/// Push a list of fixed-size elements as an Array.
fn push_list<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    array_fd: &'static FieldDescriptor,
    element_fd: &'static FieldDescriptor,
    value: &'pkt [u8],
    off: usize,
    size: usize,
    make: fn(&[u8]) -> FieldValue<'pkt>,
) {
    let arr = buf.begin_container(array_fd, FieldValue::Array(0..0), off..off + value.len());
    for (i, chunk) in value.chunks_exact(size).enumerate() {
        let at = off + i * size;
        buf.push_field(element_fd, make(chunk), at..at + size);
    }
    buf.end_container(arr);
}

/// Push the typed value of one SvcParam.
///
/// Returns `false` (having pushed nothing) if the key is not decoded or its
/// value does not have the expected format.
fn push_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    key: u16,
    value: &'pkt [u8],
    off: usize,
) -> bool {
    let end = off + value.len();
    match key {
        // RFC 9460, Section 8 — <https://www.rfc-editor.org/rfc/rfc9460#section-8>:
        // "In wire format, the keys are represented by their numeric values in
        // network byte order, concatenated in strictly increasing numeric
        // order."  The presentation value lists "one or more" keys.
        KEY_MANDATORY if !value.is_empty() && value.len() % 2 == 0 => {
            push_list(
                buf,
                &SVC_PARAM_CHILD_FIELDS[SPFD_MANDATORY],
                &FD_MANDATORY_KEY,
                value,
                off,
                2,
                |c| FieldValue::U16(u16::from_be_bytes([c[0], c[1]])),
            );
            true
        }
        KEY_ALPN if is_alpn_list(value) => {
            let arr = buf.begin_container(
                &SVC_PARAM_CHILD_FIELDS[SPFD_ALPN],
                FieldValue::Array(0..0),
                off..end,
            );
            let mut pos = 0;
            while pos < value.len() {
                let len = value[pos] as usize;
                buf.push_field(
                    &FD_ALPN_ID,
                    FieldValue::Bytes(&value[pos + 1..pos + 1 + len]),
                    off + pos + 1..off + pos + 1 + len,
                );
                pos += 1 + len;
            }
            buf.end_container(arr);
            true
        }
        // RFC 9460, Section 7.1.1 — <https://www.rfc-editor.org/rfc/rfc9460#section-7.1.1>:
        // "For "no-default-alpn", the presentation and wire-format values MUST
        // be empty."
        KEY_NO_DEFAULT_ALPN => value.is_empty(),
        // RFC 9460, Section 7.2 — <https://www.rfc-editor.org/rfc/rfc9460#section-7.2>:
        // "The wire format of the SvcParamValue is the corresponding 2-octet
        // numeric value in network byte order."
        KEY_PORT if value.len() == 2 => {
            buf.push_field(
                &SVC_PARAM_CHILD_FIELDS[SPFD_PORT],
                FieldValue::U16(u16::from_be_bytes([value[0], value[1]])),
                off..end,
            );
            true
        }
        // RFC 9460, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc9460#section-7.3>:
        // "The wire format for each parameter is a sequence of IP addresses in
        // network byte order (for the respective address family)." and "An
        // empty list of addresses is invalid."
        KEY_IPV4HINT if !value.is_empty() && value.len() % 4 == 0 => {
            push_list(
                buf,
                &SVC_PARAM_CHILD_FIELDS[SPFD_IPV4HINT],
                &FD_IPV4_HINT,
                value,
                off,
                4,
                |c| FieldValue::Ipv4Addr([c[0], c[1], c[2], c[3]]),
            );
            true
        }
        KEY_IPV6HINT if !value.is_empty() && value.len() % 16 == 0 => {
            push_list(
                buf,
                &SVC_PARAM_CHILD_FIELDS[SPFD_IPV6HINT],
                &FD_IPV6_HINT,
                value,
                off,
                16,
                |c| {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(c);
                    FieldValue::Ipv6Addr(a)
                },
            );
            true
        }
        // RFC 9848, Section 3 — <https://www.rfc-editor.org/rfc/rfc9848#section-3>:
        // "In wire format, the value of the parameter is an ECHConfigList
        // (Section 4 of [ECH]), including the redundant length prefix."
        // The ECHConfigList is kept opaque.
        KEY_ECH => {
            buf.push_field(
                &SVC_PARAM_CHILD_FIELDS[SPFD_ECH],
                FieldValue::Bytes(value),
                off..end,
            );
            true
        }
        // RFC 9461, Section 5 — <https://www.rfc-editor.org/rfc/rfc9461#section-5>:
        // the value "MUST be a URI Template in relative form ([RFC6570],
        // Section 1.1) encoded in UTF-8 [RFC3629]."
        KEY_DOHPATH if core::str::from_utf8(value).is_ok() => {
            buf.push_field(
                &SVC_PARAM_CHILD_FIELDS[SPFD_DOHPATH],
                FieldValue::Bytes(value),
                off..end,
            );
            true
        }
        _ => false,
    }
}
