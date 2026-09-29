//! EDNS(0) option decoding for the OPT pseudo-RR.
//!
//! ## References
//! - RFC 6891, Section 6.1.2 (option format): <https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2>
//! - RFC 5001, Section 2.3 (NSID): <https://www.rfc-editor.org/rfc/rfc5001#section-2.3>
//! - RFC 6975, Section 3 (DAU / DHU / N3U): <https://www.rfc-editor.org/rfc/rfc6975#section-3>
//! - RFC 7314, Sections 2-3 (EXPIRE): <https://www.rfc-editor.org/rfc/rfc7314#section-3>
//! - RFC 7828, Section 3 (TCP Keepalive): <https://www.rfc-editor.org/rfc/rfc7828#section-3>
//! - RFC 7830, Section 3 (Padding): <https://www.rfc-editor.org/rfc/rfc7830#section-3>
//! - RFC 7871, Section 6 (Client Subnet): <https://www.rfc-editor.org/rfc/rfc7871#section-6>
//! - RFC 7873, Section 4 (COOKIE): <https://www.rfc-editor.org/rfc/rfc7873#section-4>
//! - RFC 8145, Section 4.1 (edns-key-tag): <https://www.rfc-editor.org/rfc/rfc8145#section-4.1>
//! - RFC 8914, Section 2 (Extended DNS Error): <https://www.rfc-editor.org/rfc/rfc8914#section-2>
//! - RFC 9567, Section 5 (Report-Channel): <https://www.rfc-editor.org/rfc/rfc9567#section-5>
//! - RFC 9660, Section 2.1 (ZONEVERSION): <https://www.rfc-editor.org/rfc/rfc9660#section-2.1>
//! - IANA DNS EDNS0 Option Codes: <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11>
//! - IANA Extended DNS Error Codes: <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

use crate::{uncompressed_name_len, write_dns_name};

/// NSID — RFC 5001, Section 2.3 — <https://www.rfc-editor.org/rfc/rfc5001#section-2.3>
const EDNS_OPT_NSID: u16 = 3;
/// DNSSEC Algorithm Understood — RFC 6975, Section 3 — <https://www.rfc-editor.org/rfc/rfc6975#section-3>
const EDNS_OPT_DAU: u16 = 5;
/// DS Hash Understood — RFC 6975, Section 3 — <https://www.rfc-editor.org/rfc/rfc6975#section-3>
const EDNS_OPT_DHU: u16 = 6;
/// NSEC3 Hash Understood — RFC 6975, Section 3 — <https://www.rfc-editor.org/rfc/rfc6975#section-3>
const EDNS_OPT_N3U: u16 = 7;
/// Client Subnet — RFC 7871, Section 6 — <https://www.rfc-editor.org/rfc/rfc7871#section-6>
const EDNS_OPT_CLIENT_SUBNET: u16 = 8;
/// EXPIRE — RFC 7314, Sections 2-3 — <https://www.rfc-editor.org/rfc/rfc7314#section-3>
const EDNS_OPT_EXPIRE: u16 = 9;
/// COOKIE — RFC 7873, Section 4 — <https://www.rfc-editor.org/rfc/rfc7873#section-4>
const EDNS_OPT_COOKIE: u16 = 10;
/// EDNS0 option code for TCP Keepalive.
///
/// RFC 7828, Section 3 — <https://www.rfc-editor.org/rfc/rfc7828#section-3>
pub(crate) const EDNS_OPT_TCP_KEEPALIVE: u16 = 11;
/// Padding — RFC 7830, Section 3 — <https://www.rfc-editor.org/rfc/rfc7830#section-3>
const EDNS_OPT_PADDING: u16 = 12;
/// edns-key-tag — RFC 8145, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc8145#section-4.1>
const EDNS_OPT_KEY_TAG: u16 = 14;
/// Extended DNS Error — RFC 8914, Section 2 — <https://www.rfc-editor.org/rfc/rfc8914#section-2>
const EDNS_OPT_EDE: u16 = 15;
/// Report-Channel — RFC 9567, Section 5 — <https://www.rfc-editor.org/rfc/rfc9567#section-5>
const EDNS_OPT_REPORT_CHANNEL: u16 = 18;
/// ZONEVERSION — RFC 9660, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc9660#section-2.1>
const EDNS_OPT_ZONEVERSION: u16 = 19;

/// Returns a human-readable name for EDNS0 option codes.
///
/// Names follow the IANA "DNS EDNS0 Option Codes (OPT)" registry
/// (RFC 6891, Section 9 — <https://www.rfc-editor.org/rfc/rfc6891#section-9>).
pub(crate) fn edns_option_code_name(code: u16) -> Option<&'static str> {
    match code {
        1 => Some("LLQ"),
        2 => Some("UPDATE-LEASE"),
        EDNS_OPT_NSID => Some("NSID"),
        EDNS_OPT_DAU => Some("DAU"),
        EDNS_OPT_DHU => Some("DHU"),
        EDNS_OPT_N3U => Some("N3U"),
        EDNS_OPT_CLIENT_SUBNET => Some("CLIENT-SUBNET"),
        EDNS_OPT_EXPIRE => Some("EXPIRE"),
        EDNS_OPT_COOKIE => Some("COOKIE"),
        EDNS_OPT_TCP_KEEPALIVE => Some("TCP-KEEPALIVE"),
        EDNS_OPT_PADDING => Some("PADDING"),
        13 => Some("CHAIN"),
        EDNS_OPT_KEY_TAG => Some("KEY-TAG"),
        EDNS_OPT_EDE => Some("EXTENDED-DNS-ERROR"),
        16 => Some("CLIENT-TAG"),
        17 => Some("SERVER-TAG"),
        EDNS_OPT_REPORT_CHANNEL => Some("REPORT-CHANNEL"),
        EDNS_OPT_ZONEVERSION => Some("ZONEVERSION"),
        20 => Some("MQTYPE-QUERY"),
        21 => Some("MQTYPE-RESPONSE"),
        22 => Some("EDE-EXTRA-TEXT-LANGUAGE"),
        23 => Some("FILTERING-CONTACT"),
        24 => Some("FILTERING-ORGANIZATION"),
        25 => Some("FILTERING-DB"),
        26 => Some("STRUCTURED-DNS-ERROR"),
        _ => None,
    }
}

/// Returns the name of an Extended DNS Error INFO-CODE.
///
/// RFC 8914, Section 4 — <https://www.rfc-editor.org/rfc/rfc8914#section-4>,
/// extended by the IANA "Extended DNS Error Codes" registry.
pub(crate) fn ede_info_code_name(code: u16) -> Option<&'static str> {
    match code {
        0 => Some("Other Error"),
        1 => Some("Unsupported DNSKEY Algorithm"),
        2 => Some("Unsupported DS Digest Type"),
        3 => Some("Stale Answer"),
        4 => Some("Forged Answer"),
        5 => Some("DNSSEC Indeterminate"),
        6 => Some("DNSSEC Bogus"),
        7 => Some("Signature Expired"),
        8 => Some("Signature Not Yet Valid"),
        9 => Some("DNSKEY Missing"),
        10 => Some("RRSIGs Missing"),
        11 => Some("No Zone Key Bit Set"),
        12 => Some("NSEC Missing"),
        13 => Some("Cached Error"),
        14 => Some("Not Ready"),
        15 => Some("Blocked"),
        16 => Some("Censored"),
        17 => Some("Filtered"),
        18 => Some("Prohibited"),
        19 => Some("Stale NXDomain Answer"),
        20 => Some("Not Authoritative"),
        21 => Some("Not Supported"),
        22 => Some("No Reachable Authority"),
        23 => Some("Network Error"),
        24 => Some("Invalid Data"),
        25 => Some("Signature Expired before Valid"),
        26 => Some("Too Early"),
        27 => Some("Unsupported NSEC3 Iterations Value"),
        28 => Some("Unable to conform to policy"),
        29 => Some("Synthesized"),
        30 => Some("Invalid Query Type"),
        31 => Some("Rate Limited"),
        32 => Some("Over Quota"),
        33 => Some("Negative Trust Anchor"),
        34 => Some("New Delegation Only"),
        35 => Some("Blocked by Upstream DNS Server"),
        _ => None,
    }
}

/// Returns the name of a ZONEVERSION TYPE value.
///
/// RFC 9660, Section 4 — <https://www.rfc-editor.org/rfc/rfc9660#section-4>
fn zoneversion_type_name(t: u8) -> Option<&'static str> {
    match t {
        0 => Some("SOA-SERIAL"),
        _ => None,
    }
}

// Indices into EDNS_OPTION_CHILD_FIELDS.
const EOFD_CODE: usize = 0;
const EOFD_LENGTH: usize = 1;
const EOFD_DATA: usize = 2;
const EOFD_TIMEOUT: usize = 3;
const EOFD_NSID: usize = 4;
const EOFD_ALGORITHMS: usize = 5;
const EOFD_FAMILY: usize = 6;
const EOFD_SOURCE_PREFIX: usize = 7;
const EOFD_SCOPE_PREFIX: usize = 8;
const EOFD_ADDRESS: usize = 9;
const EOFD_EXPIRE: usize = 10;
const EOFD_CLIENT_COOKIE: usize = 11;
const EOFD_SERVER_COOKIE: usize = 12;
const EOFD_KEY_TAGS: usize = 13;
const EOFD_INFO_CODE: usize = 14;
const EOFD_EXTRA_TEXT: usize = 15;
const EOFD_AGENT_DOMAIN: usize = 16;
const EOFD_LABEL_COUNT: usize = 17;
const EOFD_VERSION_TYPE: usize = 18;
const EOFD_VERSION: usize = 19;

/// Element descriptor for the DAU / DHU / N3U algorithm list.
static FD_ALGORITHM: FieldDescriptor =
    FieldDescriptor::new("algorithm", "Algorithm", FieldType::U8);

/// Element descriptor for the edns-key-tag list.
static FD_KEY_TAG: FieldDescriptor = FieldDescriptor::new("key_tag", "Key Tag", FieldType::U16);

/// Descriptor for the EDNS0 option Object container itself.
///
/// `display_fn` is invoked by
/// [`DissectBuffer::resolve_container_display_name`] with the container's
/// children, so the outer label resolves to the option name (e.g.
/// "COOKIE") instead of colliding with the inner `Code` field.
pub(crate) static FD_EDNS_OPTION: FieldDescriptor = FieldDescriptor {
    name: "edns_option",
    display_name: "EDNS Option",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("code", FieldValue::U16(c)) => edns_option_code_name(*c),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Child field descriptors for EDNS0 option entries.
///
/// RFC 6891, Section 6.1.2 — <https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2>
pub(crate) static EDNS_OPTION_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "code",
        display_name: "Code",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(c) => edns_option_code_name(*c),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    // RFC 7828, Section 3 — <https://www.rfc-editor.org/rfc/rfc7828#section-3>: timeout in 100 ms units.
    FieldDescriptor::new("timeout", "Timeout", FieldType::U16).optional(),
    // RFC 5001, Section 2.3 — <https://www.rfc-editor.org/rfc/rfc5001#section-2.3>: NSID payload as text, when printable.
    FieldDescriptor::new("nsid", "Name Server Identifier", FieldType::Str).optional(),
    // RFC 6975, Section 3 — DAU / DHU / N3U: <https://www.rfc-editor.org/rfc/rfc6975#section-3>
    FieldDescriptor::new("algorithms", "Algorithms", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_ALGORITHM)),
    // RFC 7871, Section 6 — Client Subnet: <https://www.rfc-editor.org/rfc/rfc7871#section-6>
    FieldDescriptor::new("family", "Family", FieldType::U16).optional(),
    FieldDescriptor::new(
        "source_prefix_length",
        "Source Prefix-Length",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("scope_prefix_length", "Scope Prefix-Length", FieldType::U8).optional(),
    FieldDescriptor::new("address", "Address", FieldType::Bytes).optional(),
    // RFC 7314, Section 3 — EXPIRE: <https://www.rfc-editor.org/rfc/rfc7314#section-3>
    FieldDescriptor::new("expire", "Expire", FieldType::U32).optional(),
    // RFC 7873, Section 4 — COOKIE: <https://www.rfc-editor.org/rfc/rfc7873#section-4>
    FieldDescriptor::new("client_cookie", "Client Cookie", FieldType::Bytes).optional(),
    FieldDescriptor::new("server_cookie", "Server Cookie", FieldType::Bytes).optional(),
    // RFC 8145, Section 4.1 — edns-key-tag: <https://www.rfc-editor.org/rfc/rfc8145#section-4.1>
    FieldDescriptor::new("key_tags", "Key Tags", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_KEY_TAG)),
    // RFC 8914, Section 2 — Extended DNS Error: <https://www.rfc-editor.org/rfc/rfc8914#section-2>
    FieldDescriptor {
        name: "info_code",
        display_name: "INFO-CODE",
        field_type: FieldType::U16,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(c) => ede_info_code_name(*c),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("extra_text", "EXTRA-TEXT", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    // RFC 9567, Section 5 — Report-Channel: <https://www.rfc-editor.org/rfc/rfc9567#section-5>
    FieldDescriptor::new("agent_domain", "Agent Domain", FieldType::Bytes)
        .optional()
        .with_format_fn(write_dns_name),
    // RFC 9660, Section 2.1 — ZONEVERSION: <https://www.rfc-editor.org/rfc/rfc9660#section-2.1>
    FieldDescriptor::new("label_count", "Label Count", FieldType::U8).optional(),
    FieldDescriptor {
        name: "version_type",
        display_name: "Type",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => zoneversion_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("version", "Version", FieldType::Bytes).optional(),
];

/// Parse EDNS0 options from OPT RDATA.
///
/// Each option is: code(2) + length(2) + data(length)
/// (RFC 6891, Section 6.1.2 — <https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2>).
/// Options whose payload does not match the format defined for their code
/// keep the raw `data` field.
pub(crate) fn parse_edns_options<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    rdata: &'pkt [u8],
    abs_offset: usize,
) {
    let mut pos = 0;
    while pos + 4 <= rdata.len() {
        let code = read_be_u16(rdata, pos).unwrap_or_default();
        let length = read_be_u16(rdata, pos + 2).unwrap_or_default() as usize;
        if pos + 4 + length > rdata.len() {
            break;
        }
        let option_data = &rdata[pos + 4..pos + 4 + length];
        let option_start = abs_offset + pos;
        let option_end = option_start + 4 + length;

        let obj_idx = buf.begin_container(
            &FD_EDNS_OPTION,
            FieldValue::Object(0..0),
            option_start..option_end,
        );

        buf.push_field(
            &EDNS_OPTION_CHILD_FIELDS[EOFD_CODE],
            FieldValue::U16(code),
            option_start..option_start + 2,
        );
        buf.push_field(
            &EDNS_OPTION_CHILD_FIELDS[EOFD_LENGTH],
            FieldValue::U16(length as u16),
            option_start + 2..option_start + 4,
        );

        if !parse_option_value(buf, code, option_data, option_start + 4) {
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_DATA],
                FieldValue::Bytes(option_data),
                option_start + 4..option_end,
            );
        }

        buf.end_container(obj_idx);
        pos += 4 + length;
    }
}

/// Push the typed fields for one option value.
///
/// Returns `false` if the code is not decoded or the value is malformed, in
/// which case the caller emits the raw `data` field. Nothing is pushed when
/// `false` is returned.
fn parse_option_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    code: u16,
    data: &'pkt [u8],
    off: usize,
) -> bool {
    let end = off + data.len();
    match code {
        // RFC 5001, Section 2.3 — <https://www.rfc-editor.org/rfc/rfc5001#section-2.3>
        // The payload is opaque; it is also shown as text when printable.
        EDNS_OPT_NSID => {
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_DATA],
                FieldValue::Bytes(data),
                off..end,
            );
            if let Ok(text) = core::str::from_utf8(data) {
                if !text.is_empty() && !text.chars().any(char::is_control) {
                    buf.push_field(
                        &EDNS_OPTION_CHILD_FIELDS[EOFD_NSID],
                        FieldValue::Str(text),
                        off..end,
                    );
                }
            }
            true
        }
        // RFC 6975, Section 3 — <https://www.rfc-editor.org/rfc/rfc6975#section-3>
        // ALG-CODE: a list of one-octet algorithm numbers.
        EDNS_OPT_DAU | EDNS_OPT_DHU | EDNS_OPT_N3U => {
            let arr = buf.begin_container(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_ALGORITHMS],
                FieldValue::Array(0..0),
                off..end,
            );
            for (i, &alg) in data.iter().enumerate() {
                buf.push_field(&FD_ALGORITHM, FieldValue::U8(alg), off + i..off + i + 1);
            }
            buf.end_container(arr);
            true
        }
        // RFC 7871, Section 6 — <https://www.rfc-editor.org/rfc/rfc7871#section-6>
        EDNS_OPT_CLIENT_SUBNET if data.len() >= 4 => {
            let family = read_be_u16(data, 0).unwrap_or_default();
            let address = &data[4..];
            // "This document only defines the format for FAMILY 1 (IPv4) and
            // FAMILY 2 (IPv6)". The ADDRESS is truncated to SOURCE
            // PREFIX-LENGTH, so it is widened with zero octets here.
            let address_value = match family {
                1 if address.len() <= 4 => {
                    let mut a = [0u8; 4];
                    a[..address.len()].copy_from_slice(address);
                    FieldValue::Ipv4Addr(a)
                }
                2 if address.len() <= 16 => {
                    let mut a = [0u8; 16];
                    a[..address.len()].copy_from_slice(address);
                    FieldValue::Ipv6Addr(a)
                }
                _ => FieldValue::Bytes(address),
            };
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_FAMILY],
                FieldValue::U16(family),
                off..off + 2,
            );
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_SOURCE_PREFIX],
                FieldValue::U8(data[2]),
                off + 2..off + 3,
            );
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_SCOPE_PREFIX],
                FieldValue::U8(data[3]),
                off + 3..off + 4,
            );
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_ADDRESS],
                address_value,
                off + 4..end,
            );
            true
        }
        // RFC 7314, Sections 2 and 3 — <https://www.rfc-editor.org/rfc/rfc7314#section-3>
        // Zero-length in queries; "an EDNS EXPIRE option of length 4" in
        // responses.
        EDNS_OPT_EXPIRE if data.is_empty() => true,
        EDNS_OPT_EXPIRE if data.len() == 4 => {
            let expire = read_be_u32(data, 0).unwrap_or_default();
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_EXPIRE],
                FieldValue::U32(expire),
                off..end,
            );
            true
        }
        // RFC 7873, Section 4 — <https://www.rfc-editor.org/rfc/rfc7873#section-4>
        // 8-octet Client Cookie, optionally followed by an 8 to 32 octet
        // Server Cookie.
        EDNS_OPT_COOKIE if data.len() == 8 || (16..=40).contains(&data.len()) => {
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_CLIENT_COOKIE],
                FieldValue::Bytes(&data[..8]),
                off..off + 8,
            );
            if data.len() > 8 {
                buf.push_field(
                    &EDNS_OPTION_CHILD_FIELDS[EOFD_SERVER_COOKIE],
                    FieldValue::Bytes(&data[8..]),
                    off + 8..end,
                );
            }
            true
        }
        // RFC 7828, Section 3 — <https://www.rfc-editor.org/rfc/rfc7828#section-3>
        // Length is 0 (query, no timeout) or 2 (timeout in 100 ms units).
        EDNS_OPT_TCP_KEEPALIVE if data.is_empty() => true,
        EDNS_OPT_TCP_KEEPALIVE if data.len() == 2 => {
            let timeout = read_be_u16(data, 0).unwrap_or_default();
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_TIMEOUT],
                FieldValue::U16(timeout),
                off..end,
            );
            true
        }
        // RFC 7830, Section 3 — <https://www.rfc-editor.org/rfc/rfc7830#section-3>
        // The padding octets carry no information; only the length is shown.
        EDNS_OPT_PADDING => true,
        // RFC 8145, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc8145#section-4.1>
        // A list of 16-bit key tags.
        EDNS_OPT_KEY_TAG if !data.is_empty() && data.len() % 2 == 0 => {
            let arr = buf.begin_container(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_KEY_TAGS],
                FieldValue::Array(0..0),
                off..end,
            );
            for i in (0..data.len()).step_by(2) {
                let tag = read_be_u16(data, i).unwrap_or_default();
                buf.push_field(&FD_KEY_TAG, FieldValue::U16(tag), off + i..off + i + 2);
            }
            buf.end_container(arr);
            true
        }
        // RFC 8914, Section 2 — <https://www.rfc-editor.org/rfc/rfc8914#section-2>
        // INFO-CODE (16 bits) followed by an optional EXTRA-TEXT.
        EDNS_OPT_EDE if data.len() >= 2 => {
            let info_code = read_be_u16(data, 0).unwrap_or_default();
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_INFO_CODE],
                FieldValue::U16(info_code),
                off..off + 2,
            );
            if data.len() > 2 {
                buf.push_field(
                    &EDNS_OPTION_CHILD_FIELDS[EOFD_EXTRA_TEXT],
                    FieldValue::Bytes(&data[2..]),
                    off + 2..end,
                );
            }
            true
        }
        // RFC 9567, Section 5 — <https://www.rfc-editor.org/rfc/rfc9567#section-5>
        // "AGENT DOMAIN:  A fully qualified domain name [RFC9499] in
        //  uncompressed DNS wire format."
        EDNS_OPT_REPORT_CHANNEL if uncompressed_name_len(data) == Some(data.len()) => {
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_AGENT_DOMAIN],
                FieldValue::Bytes(data),
                off..end,
            );
            true
        }
        // RFC 9660, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc9660#section-2.1>
        // Empty in queries; LABELCOUNT(1) + TYPE(1) + VERSION in responses.
        EDNS_OPT_ZONEVERSION if data.is_empty() => true,
        EDNS_OPT_ZONEVERSION if data.len() >= 2 => {
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_LABEL_COUNT],
                FieldValue::U8(data[0]),
                off..off + 1,
            );
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_VERSION_TYPE],
                FieldValue::U8(data[1]),
                off + 1..off + 2,
            );
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_VERSION],
                FieldValue::Bytes(&data[2..]),
                off + 2..end,
            );
            true
        }
        _ => false,
    }
}
