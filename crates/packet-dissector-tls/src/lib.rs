//! TLS (Transport Layer Security) record layer dissector.
//!
//! Parses the TLS record layer header (5 bytes) and, for unencrypted
//! content types, peeks into the payload to extract handshake type or
//! alert information.
//!
//! ## References
//! - RFC 5246 (TLS 1.2): <https://www.rfc-editor.org/rfc/rfc5246>
//! - RFC 8446 (TLS 1.3): <https://www.rfc-editor.org/rfc/rfc8446>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24};

/// TLS record layer header size (always 5 bytes).
///
/// ```text
/// RFC 5246, Section 6.2.1 — https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1
///
/// struct {
///     ContentType type;
///     ProtocolVersion version;
///     uint16 length;
///     opaque fragment[TLSPlaintext.length];
/// } TLSPlaintext;
/// ```
const RECORD_HEADER_SIZE: usize = 5;

/// TLS handshake message header size (1-byte type + 3-byte length).
///
/// RFC 5246, Section 7.4 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4>
const HANDSHAKE_HEADER_SIZE: usize = 4;

/// TLS alert message size (1-byte level + 1-byte description).
///
/// RFC 5246, Section 7.2 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.2>
const ALERT_SIZE: usize = 2;

/// `change_cipher_spec(20)`
const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
/// `alert(21)`
const CONTENT_TYPE_ALERT: u8 = 21;
/// `handshake(22)`
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
/// `application_data(23)`
const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

/// Returns a human-readable name for a TLS `ContentType` value.
///
/// RFC 5246, Section 6.2.1 — <https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1>
fn content_type_name(ct: u8) -> &'static str {
    match ct {
        CONTENT_TYPE_CHANGE_CIPHER_SPEC => "Change Cipher Spec",
        CONTENT_TYPE_ALERT => "Alert",
        CONTENT_TYPE_HANDSHAKE => "Handshake",
        CONTENT_TYPE_APPLICATION_DATA => "Application Data",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for a TLS `ProtocolVersion` value.
///
/// RFC 5246, Section 6.2.1 — <https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1>
fn version_name(version: u16) -> &'static str {
    match version {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2 / TLS 1.3 legacy_record_version",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
    }
}

/// Returns a version-qualified short name for use as the layer display name.
///
/// For record-layer version `0x0303` we display `"TLSv1.2"` because the
/// record header carries the same value for both TLS 1.2 and TLS 1.3
/// (`legacy_record_version`); this matches Wireshark behaviour.
///
/// RFC 5246, Section 6.2.1 — <https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1>
/// RFC 8446, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc8446#section-5.1>
fn version_short_name(version: u16) -> Option<&'static str> {
    match version {
        0x0300 => Some("SSL 3.0"),
        0x0301 => Some("TLSv1.0"),
        0x0302 => Some("TLSv1.1"),
        0x0303 => Some("TLSv1.2"),
        0x0304 => Some("TLSv1.3"),
        _ => None,
    }
}

/// Returns a human-readable name for a TLS `HandshakeType` value.
///
/// RFC 5246, Section 7.4 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4>
/// RFC 8446, Section 4 — <https://www.rfc-editor.org/rfc/rfc8446#section-4>
fn handshake_type_name(ht: u8) -> &'static str {
    match ht {
        // RFC 5246, Section 7.4
        0 => "Hello Request",
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        5 => "End Of Early Data",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        // RFC 8446, Section 4
        24 => "Key Update",
        254 => "Message Hash",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for a TLS `AlertLevel` value.
///
/// RFC 5246, Section 7.2 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.2>
fn alert_level_name(level: u8) -> &'static str {
    match level {
        1 => "warning",
        2 => "fatal",
        _ => "unknown",
    }
}

/// Returns a human-readable name for a TLS `AlertDescription` value.
///
/// Based on the IANA TLS Alert Registry:
/// <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6>
fn alert_description_name(desc: u8) -> &'static str {
    match desc {
        // RFC 5246
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        21 => "decryption_failed",
        22 => "record_overflow",
        30 => "decompression_failure",
        40 => "handshake_failure",
        41 => "no_certificate",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        60 => "export_restriction",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        100 => "no_renegotiation",
        // RFC 7301
        120 => "no_application_protocol",
        // RFC 7507
        // 86 already covered above (inappropriate_fallback)
        // RFC 8446
        109 => "missing_extension",
        110 => "unsupported_extension",
        111 => "certificate_unobtainable",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        114 => "bad_certificate_hash_value",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        _ => "unknown",
    }
}

/// Returns a human-readable name for a TLS `ExtensionType` value.
///
/// Based on the IANA TLS ExtensionType Values registry:
/// <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml>
fn extension_type_name(ext_type: u16) -> &'static str {
    match ext_type {
        0 => "server_name",
        1 => "max_fragment_length",
        5 => "status_request",
        10 => "supported_groups",
        11 => "ec_point_formats",
        13 => "signature_algorithms",
        14 => "use_srtp",
        15 => "heartbeat",
        16 => "application_layer_protocol_negotiation",
        18 => "signed_certificate_timestamp",
        21 => "padding",
        23 => "extended_master_secret",
        35 => "session_ticket",
        41 => "pre_shared_key",
        42 => "early_data",
        43 => "supported_versions",
        44 => "cookie",
        45 => "psk_key_exchange_modes",
        47 => "certificate_authorities",
        49 => "post_handshake_auth",
        50 => "signature_algorithms_cert",
        51 => "key_share",
        0xff01 => "renegotiation_info",
        _ => "unknown",
    }
}

/// Returns a human-readable name for a TLS `CipherSuite` value.
///
/// Covers the most commonly used cipher suites in modern TLS deployments.
/// Based on the IANA TLS Cipher Suites registry:
/// <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4>
fn cipher_suite_name(cs: u16) -> Option<&'static str> {
    match cs {
        // TLS 1.3 cipher suites — RFC 8446, Appendix B.4
        0x1301 => Some("TLS_AES_128_GCM_SHA256"),
        0x1302 => Some("TLS_AES_256_GCM_SHA384"),
        0x1303 => Some("TLS_CHACHA20_POLY1305_SHA256"),
        0x1304 => Some("TLS_AES_128_CCM_SHA256"),
        0x1305 => Some("TLS_AES_128_CCM_8_SHA256"),
        // ECDHE+ECDSA — RFC 5289
        0xc02b => Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        0xc02c => Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
        0xc023 => Some("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
        0xc024 => Some("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
        // ECDHE+RSA — RFC 5289
        0xc02f => Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        0xc030 => Some("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        0xc027 => Some("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
        0xc028 => Some("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
        // DHE+RSA — RFC 5288
        0x009e => Some("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
        0x009f => Some("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
        // RSA — RFC 5288 / RFC 5246
        0x009c => Some("TLS_RSA_WITH_AES_128_GCM_SHA256"),
        0x009d => Some("TLS_RSA_WITH_AES_256_GCM_SHA384"),
        0x002f => Some("TLS_RSA_WITH_AES_128_CBC_SHA"),
        0x0035 => Some("TLS_RSA_WITH_AES_256_CBC_SHA"),
        0x003c => Some("TLS_RSA_WITH_AES_128_CBC_SHA256"),
        0x003d => Some("TLS_RSA_WITH_AES_256_CBC_SHA256"),
        // CHACHA20-POLY1305 — RFC 7905
        0xcca8 => Some("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        0xcca9 => Some("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
        0xccaa => Some("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        _ => None,
    }
}

/// Minimum ClientHello body size: version(2) + random(32) + session_id_len(1).
///
/// RFC 5246, Section 7.4.1.2 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2>
const CLIENT_HELLO_MIN_BODY: usize = 2 + 32 + 1;

/// Minimum ServerHello body size: version(2) + random(32) + session_id_len(1).
///
/// RFC 5246, Section 7.4.1.3 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.3>
const SERVER_HELLO_MIN_BODY: usize = 2 + 32 + 1;

/// Size of the TLS `Random` field (32 bytes).
///
/// RFC 5246, Section 7.4.1.2 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2>
const RANDOM_SIZE: usize = 32;

/// Handshake type for ClientHello.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

/// Handshake type for ServerHello.
const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_CONTENT_TYPE: usize = 0;
const FD_VERSION: usize = 1;
const FD_LENGTH: usize = 2;
const FD_HANDSHAKE_TYPE: usize = 3;
const FD_HANDSHAKE_LENGTH: usize = 4;
const FD_ALERT_LEVEL: usize = 5;
const FD_ALERT_DESCRIPTION: usize = 6;
const FD_HANDSHAKE_VERSION: usize = 7;
const FD_RANDOM: usize = 8;
const FD_SESSION_ID: usize = 9;
const FD_CIPHER_SUITES: usize = 10;
const FD_CIPHER_SUITE: usize = 11;
const FD_COMPRESSION_METHODS: usize = 12;
const FD_COMPRESSION_METHOD: usize = 13;
const FD_EXTENSIONS: usize = 14;

/// Field descriptor indices for [`EXTENSION_CHILD_FIELDS`].
const EFD_TYPE: usize = 0;
const EFD_LENGTH: usize = 1;
const EFD_DATA: usize = 2;
const EFD_SERVER_NAME: usize = 3;

/// Child field descriptors for extension objects within the `extensions` array.
///
/// RFC 5246, Section 7.4.1.4 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.4>
static EXTENSION_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Extension Type",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(t) => Some(extension_type_name(*t)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Extension Length", FieldType::U16),
    FieldDescriptor::new("data", "Extension Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("server_name", "Server Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
];

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "content_type",
        display_name: "Content Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(ct) => Some(content_type_name(*ct)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "version",
        display_name: "Version",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(ver) => Some(version_name(*ver)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U16),
    // --- Handshake fields (optional, only when content_type == 22) ---
    FieldDescriptor {
        name: "handshake_type",
        display_name: "Handshake Type",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(ht) => Some(handshake_type_name(*ht)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("handshake_length", "Handshake Length", FieldType::U32).optional(),
    // --- Alert fields (optional, only when content_type == 21) ---
    FieldDescriptor {
        name: "alert_level",
        display_name: "Alert Level",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(l) => Some(alert_level_name(*l)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "alert_description",
        display_name: "Alert Description",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(d) => Some(alert_description_name(*d)),
            _ => None,
        }),
        format_fn: None,
    },
    // --- ClientHello / ServerHello fields (optional) ---
    FieldDescriptor {
        name: "handshake_version",
        display_name: "Handshake Version",
        field_type: FieldType::U16,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(ver) => Some(version_name(*ver)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("random", "Random", FieldType::Bytes).optional(),
    FieldDescriptor::new("session_id", "Session ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("cipher_suites", "Cipher Suites", FieldType::Array).optional(),
    FieldDescriptor {
        name: "cipher_suite",
        display_name: "Cipher Suite",
        field_type: FieldType::U16,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(cs) => cipher_suite_name(*cs),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new(
        "compression_methods",
        "Compression Methods",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("compression_method", "Compression Method", FieldType::U8).optional(),
    FieldDescriptor::new("extensions", "Extensions", FieldType::Array)
        .optional()
        .with_children(EXTENSION_CHILD_FIELDS),
];

/// Parse the TLS extensions list into a [`DissectBuffer`].
///
/// Each extension is a 2-byte type, 2-byte length, and variable-length data.
///
/// RFC 5246, Section 7.4.1.4 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.4>
fn parse_extensions<'pkt>(data: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let ext_type = read_be_u16(data, pos).unwrap_or_default();
        let ext_len = read_be_u16(data, pos + 2).unwrap_or_default() as usize;
        if pos + 4 + ext_len > data.len() {
            break;
        }
        let ext_data = &data[pos + 4..pos + 4 + ext_len];

        let obj_idx = buf.begin_container(
            &EXTENSION_CHILD_FIELDS[EFD_TYPE],
            FieldValue::Object(0..0),
            offset + pos..offset + pos + 4 + ext_len,
        );

        buf.push_field(
            &EXTENSION_CHILD_FIELDS[EFD_TYPE],
            FieldValue::U16(ext_type),
            offset + pos..offset + pos + 2,
        );
        buf.push_field(
            &EXTENSION_CHILD_FIELDS[EFD_LENGTH],
            FieldValue::U16(ext_len as u16),
            offset + pos + 2..offset + pos + 4,
        );
        buf.push_field(
            &EXTENSION_CHILD_FIELDS[EFD_DATA],
            FieldValue::Bytes(ext_data),
            offset + pos + 4..offset + pos + 4 + ext_len,
        );

        // RFC 6066, Section 3 — https://www.rfc-editor.org/rfc/rfc6066#section-3
        if ext_type == 0 && ext_len >= 5 {
            let name_list_len = read_be_u16(ext_data, 0).unwrap_or_default() as usize;
            if name_list_len + 2 <= ext_len && name_list_len >= 3 {
                let name_type = ext_data[2];
                if name_type == 0 {
                    let name_len = read_be_u16(ext_data, 3).unwrap_or_default() as usize;
                    if 5 + name_len <= ext_len {
                        let name_bytes = &ext_data[5..5 + name_len];
                        buf.push_field(
                            &EXTENSION_CHILD_FIELDS[EFD_SERVER_NAME],
                            FieldValue::Bytes(name_bytes),
                            offset + pos + 4 + 5..offset + pos + 4 + 5 + name_len,
                        );
                    }
                }
            }
        }

        buf.end_container(obj_idx);
        pos += 4 + ext_len;
    }
}

/// Parse a ClientHello handshake body and append fields.
///
/// RFC 5246, Section 7.4.1.2 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2>
/// RFC 8446, Section 4.1.2 — <https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2>
fn parse_client_hello<'pkt>(body: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    if body.len() < CLIENT_HELLO_MIN_BODY {
        return;
    }
    let mut pos = 0;

    let client_version = read_be_u16(body, pos).unwrap_or_default();
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_HANDSHAKE_VERSION],
        FieldValue::U16(client_version),
        offset + pos..offset + pos + 2,
    );
    pos += 2;

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_RANDOM],
        FieldValue::Bytes(&body[pos..pos + RANDOM_SIZE]),
        offset + pos..offset + pos + RANDOM_SIZE,
    );
    pos += RANDOM_SIZE;

    let session_id_len = body[pos] as usize;
    pos += 1;
    if pos + session_id_len > body.len() {
        return;
    }
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_SESSION_ID],
        FieldValue::Bytes(&body[pos..pos + session_id_len]),
        offset + pos..offset + pos + session_id_len,
    );
    pos += session_id_len;

    // cipher_suites: 2-byte length prefix + list of u16
    if pos + 2 > body.len() {
        return;
    }
    let cs_len = read_be_u16(body, pos).unwrap_or_default() as usize;
    pos += 2;
    if pos + cs_len > body.len() || cs_len % 2 != 0 {
        return;
    }
    let cs_array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_CIPHER_SUITES],
        FieldValue::Array(0..0),
        offset + pos..offset + pos + cs_len,
    );
    for i in (0..cs_len).step_by(2) {
        let suite = read_be_u16(body, pos + i).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CIPHER_SUITE],
            FieldValue::U16(suite),
            offset + pos + i..offset + pos + i + 2,
        );
    }
    buf.end_container(cs_array_idx);
    pos += cs_len;

    if pos >= body.len() {
        return;
    }
    let comp_len = body[pos] as usize;
    pos += 1;
    if pos + comp_len > body.len() {
        return;
    }
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_COMPRESSION_METHODS],
        FieldValue::Bytes(&body[pos..pos + comp_len]),
        offset + pos..offset + pos + comp_len,
    );
    pos += comp_len;

    if pos + 2 > body.len() {
        return;
    }
    let ext_len = read_be_u16(body, pos).unwrap_or_default() as usize;
    pos += 2;
    if pos + ext_len > body.len() {
        return;
    }
    let ext_data = &body[pos..pos + ext_len];
    let ext_array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_EXTENSIONS],
        FieldValue::Array(0..0),
        offset + pos..offset + pos + ext_len,
    );
    parse_extensions(ext_data, offset + pos, buf);
    buf.end_container(ext_array_idx);
}

/// Parse a ServerHello handshake body and append fields.
///
/// RFC 5246, Section 7.4.1.3 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.3>
/// RFC 8446, Section 4.1.3 — <https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3>
fn parse_server_hello<'pkt>(body: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    if body.len() < SERVER_HELLO_MIN_BODY {
        return;
    }
    let mut pos = 0;

    let server_version = read_be_u16(body, pos).unwrap_or_default();
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_HANDSHAKE_VERSION],
        FieldValue::U16(server_version),
        offset + pos..offset + pos + 2,
    );
    pos += 2;

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_RANDOM],
        FieldValue::Bytes(&body[pos..pos + RANDOM_SIZE]),
        offset + pos..offset + pos + RANDOM_SIZE,
    );
    pos += RANDOM_SIZE;

    let session_id_len = body[pos] as usize;
    pos += 1;
    if pos + session_id_len > body.len() {
        return;
    }
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_SESSION_ID],
        FieldValue::Bytes(&body[pos..pos + session_id_len]),
        offset + pos..offset + pos + session_id_len,
    );
    pos += session_id_len;

    if pos + 2 > body.len() {
        return;
    }
    let cs = read_be_u16(body, pos).unwrap_or_default();
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_CIPHER_SUITE],
        FieldValue::U16(cs),
        offset + pos..offset + pos + 2,
    );
    pos += 2;

    if pos >= body.len() {
        return;
    }
    let comp = body[pos];
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_COMPRESSION_METHOD],
        FieldValue::U8(comp),
        offset + pos..offset + pos + 1,
    );
    pos += 1;

    if pos + 2 > body.len() {
        return;
    }
    let ext_len = read_be_u16(body, pos).unwrap_or_default() as usize;
    pos += 2;
    if pos + ext_len > body.len() {
        return;
    }
    let ext_data = &body[pos..pos + ext_len];
    let ext_array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_EXTENSIONS],
        FieldValue::Array(0..0),
        offset + pos..offset + pos + ext_len,
    );
    parse_extensions(ext_data, offset + pos, buf);
    buf.end_container(ext_array_idx);
}

/// TLS record layer dissector.
pub struct TlsDissector;

impl Dissector for TlsDissector {
    fn name(&self) -> &'static str {
        "Transport Layer Security"
    }

    fn short_name(&self) -> &'static str {
        "TLS"
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
        // RFC 5246, Section 6.2.1 — https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1
        //
        // struct {
        //     ContentType type;          /* 1 byte  */
        //     ProtocolVersion version;   /* 2 bytes */
        //     uint16 length;             /* 2 bytes */
        //     opaque fragment[TLSPlaintext.length];
        // } TLSPlaintext;
        if data.len() < RECORD_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: RECORD_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let ct = data[0];
        let version = read_be_u16(data, 1)?;
        let length = read_be_u16(data, 3)?;

        let record_len = RECORD_HEADER_SIZE + length as usize;
        if data.len() < record_len {
            return Err(PacketError::Truncated {
                expected: record_len,
                actual: data.len(),
            });
        }

        buf.begin_layer(
            self.short_name(),
            version_short_name(version),
            FIELD_DESCRIPTORS,
            offset..offset + record_len,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CONTENT_TYPE],
            FieldValue::U8(ct),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U16(version),
            offset + 1..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LENGTH],
            FieldValue::U16(length),
            offset + 3..offset + 5,
        );

        let payload = &data[RECORD_HEADER_SIZE..record_len];
        let payload_offset = offset + RECORD_HEADER_SIZE;

        // RFC 5246, Section 7.4 — https://www.rfc-editor.org/rfc/rfc5246#section-7.4
        //
        // struct {
        //     HandshakeType msg_type;   /* 1 byte  */
        //     uint24 length;            /* 3 bytes */
        //     select (HandshakeType) { ... } body;
        // } Handshake;
        if ct == CONTENT_TYPE_HANDSHAKE && payload.len() >= HANDSHAKE_HEADER_SIZE {
            let ht = payload[0];
            let hs_length = read_be_u24(payload, 1)?;

            buf.push_field(
                &FIELD_DESCRIPTORS[FD_HANDSHAKE_TYPE],
                FieldValue::U8(ht),
                payload_offset..payload_offset + 1,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_HANDSHAKE_LENGTH],
                FieldValue::U32(hs_length),
                payload_offset + 1..payload_offset + 4,
            );

            // Parse handshake body for ClientHello and ServerHello.
            let hs_body_len =
                core::cmp::min(hs_length as usize, payload.len() - HANDSHAKE_HEADER_SIZE);
            let hs_body = &payload[HANDSHAKE_HEADER_SIZE..HANDSHAKE_HEADER_SIZE + hs_body_len];
            let hs_body_offset = payload_offset + HANDSHAKE_HEADER_SIZE;
            match ht {
                HANDSHAKE_TYPE_CLIENT_HELLO => {
                    parse_client_hello(hs_body, hs_body_offset, buf);
                }
                HANDSHAKE_TYPE_SERVER_HELLO => {
                    parse_server_hello(hs_body, hs_body_offset, buf);
                }
                _ => {}
            }
        }

        // RFC 5246, Section 7.2 — https://www.rfc-editor.org/rfc/rfc5246#section-7.2
        //
        // struct {
        //     AlertLevel level;            /* 1 byte */
        //     AlertDescription description; /* 1 byte */
        // } Alert;
        if ct == CONTENT_TYPE_ALERT && payload.len() >= ALERT_SIZE {
            let level = payload[0];
            let description = payload[1];

            buf.push_field(
                &FIELD_DESCRIPTORS[FD_ALERT_LEVEL],
                FieldValue::U8(level),
                payload_offset..payload_offset + 1,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_ALERT_DESCRIPTION],
                FieldValue::U8(description),
                payload_offset + 1..payload_offset + 2,
            );
        }

        buf.end_layer();

        Ok(DissectResult::new(record_len, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 5246 / RFC 8446 (TLS) Coverage
    //!
    //! | RFC Section   | Description            | Test                                     |
    //! |---------------|------------------------|------------------------------------------|
    //! | 5246 §6.2.1   | Record header format   | parse_tls_handshake_record               |
    //! | 5246 §7.4     | Handshake header       | parse_tls_handshake_record               |
    //! | 5246 §7.2     | Alert protocol         | parse_tls_alert_record                   |
    //! | 5246 §7.1     | ChangeCipherSpec       | parse_tls_change_cipher_spec             |
    //! | 5246 §6.2.1   | Application data       | parse_tls_application_data               |
    //! | 5246 §6.2.1   | Truncated record       | parse_tls_truncated_header               |
    //! | 5246 §6.2.1   | Truncated payload      | parse_tls_truncated_payload              |
    //! | 5246 §6.2.1   | Unknown content type   | parse_tls_unknown_content_type           |
    //! | 5246 §6.2.1   | Version names          | parse_tls_version_names                  |
    //! | 5246 §7.4     | Handshake type names   | parse_tls_handshake_type_names           |
    //! | 5246 §7.2     | Alert description names| parse_tls_alert_description_names        |
    //! | 8446 §5.1     | TLS 1.3 record version | parse_tls13_record                       |
    //! | 5246 §7.4.1.2 | ClientHello            | parse_client_hello_basic                 |
    //! | 5246 §7.4.1.2 | ClientHello extensions | parse_client_hello_with_extensions       |
    //! | 8446 §4.1.2   | TLS 1.3 ClientHello    | parse_client_hello_with_supported_versions|
    //! | 5246 §7.4.1.3 | ServerHello            | parse_server_hello_basic                 |
    //! | 5246 §7.4.1.3 | ServerHello extensions | parse_server_hello_with_extensions       |
    //! | 5246 §7.4.1.4 | Extension format       | parse_client_hello_with_extensions       |
    //! | 6066 §3       | SNI extension          | parse_client_hello_with_extensions       |
    //! | 5246 §7.4.1.2 | ClientHello truncated  | parse_client_hello_truncated_body        |
    //! | 5246 §7.4.1.3 | ServerHello truncated  | parse_server_hello_truncated_body        |

    use super::*;

    /// Build a TLS record: [content_type(1), version(2), length(2), payload...]
    fn build_tls_record(ct: u8, version: u16, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u16;
        let mut buf = Vec::with_capacity(RECORD_HEADER_SIZE + payload.len());
        buf.push(ct);
        buf.extend_from_slice(&version.to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// Build a TLS handshake header: [type(1), length(3)]
    fn build_handshake_header(ht: u8, length: u32) -> Vec<u8> {
        let len_bytes = length.to_be_bytes();
        vec![ht, len_bytes[1], len_bytes[2], len_bytes[3]]
    }

    #[test]
    fn parse_tls_handshake_record() {
        // ClientHello handshake record over TLS 1.2
        let hs_payload = build_handshake_header(1, 512); // ClientHello, length=512
        let mut payload = hs_payload;
        payload.extend_from_slice(&vec![0u8; 512]); // dummy handshake body
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0301, &payload);

        let mut buf = DissectBuffer::new();
        let result = TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, RECORD_HEADER_SIZE + payload.len());

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "content_type").unwrap().value,
            FieldValue::U8(22)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "content_type_name"),
            Some("Handshake")
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U16(0x0301)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "version_name"),
            Some("TLS 1.0")
        );
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U16(payload.len() as u16)
        );
        assert_eq!(
            buf.field_by_name(layer, "handshake_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "handshake_type_name"),
            Some("Client Hello")
        );
        assert_eq!(
            buf.field_by_name(layer, "handshake_length").unwrap().value,
            FieldValue::U32(512)
        );
    }

    #[test]
    fn parse_tls_alert_record() {
        // Fatal handshake_failure alert
        let alert_payload = vec![2u8, 40]; // level=fatal(2), description=handshake_failure(40)
        let data = build_tls_record(CONTENT_TYPE_ALERT, 0x0303, &alert_payload);

        let mut buf = DissectBuffer::new();
        let result = TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, RECORD_HEADER_SIZE + 2);

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "content_type_name"),
            Some("Alert")
        );
        assert_eq!(
            buf.field_by_name(layer, "alert_level").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "alert_level_name"),
            Some("fatal")
        );
        assert_eq!(
            buf.field_by_name(layer, "alert_description").unwrap().value,
            FieldValue::U8(40)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "alert_description_name"),
            Some("handshake_failure")
        );
        // No handshake fields present
        assert!(buf.field_by_name(layer, "handshake_type").is_none());
    }

    #[test]
    fn parse_tls_change_cipher_spec() {
        // ChangeCipherSpec is a single byte with value 1
        // RFC 5246, Section 7.1 — https://www.rfc-editor.org/rfc/rfc5246#section-7.1
        let data = build_tls_record(CONTENT_TYPE_CHANGE_CIPHER_SPEC, 0x0303, &[0x01]);

        let mut buf = DissectBuffer::new();
        let result = TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, RECORD_HEADER_SIZE + 1);

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "content_type_name"),
            Some("Change Cipher Spec")
        );
        // No handshake or alert fields
        assert!(buf.field_by_name(layer, "handshake_type").is_none());
        assert!(buf.field_by_name(layer, "alert_level").is_none());
    }

    #[test]
    fn parse_tls_application_data() {
        let app_data = vec![0xab; 128]; // encrypted payload
        let data = build_tls_record(CONTENT_TYPE_APPLICATION_DATA, 0x0303, &app_data);

        let mut buf = DissectBuffer::new();
        let result = TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, RECORD_HEADER_SIZE + 128);

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "content_type_name"),
            Some("Application Data")
        );
        assert!(buf.field_by_name(layer, "handshake_type").is_none());
        assert!(buf.field_by_name(layer, "alert_level").is_none());
    }

    #[test]
    fn parse_tls_truncated_header() {
        let data = [0x16, 0x03, 0x03]; // Only 3 bytes, need 5
        let mut buf = DissectBuffer::new();
        let err = TlsDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, RECORD_HEADER_SIZE);
                assert_eq!(actual, 3);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn parse_tls_truncated_payload() {
        // Header says length=100 but only 10 bytes of payload present
        let mut data = vec![0x17, 0x03, 0x03, 0x00, 0x64]; // content_type=23, length=100
        data.extend_from_slice(&[0u8; 10]); // only 10 bytes

        let mut buf = DissectBuffer::new();
        let err = TlsDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, RECORD_HEADER_SIZE + 100);
                assert_eq!(actual, 15);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn parse_tls_unknown_content_type() {
        let data = build_tls_record(99, 0x0303, &[0x00]);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "content_type_name"),
            Some("Unknown")
        );
    }

    #[test]
    fn parse_tls_version_names() {
        for (ver, expected_name) in [
            (0x0300u16, "SSL 3.0"),
            (0x0301, "TLS 1.0"),
            (0x0302, "TLS 1.1"),
            (0x0303, "TLS 1.2 / TLS 1.3 legacy_record_version"),
            (0x0304, "TLS 1.3"),
            (0x0399, "Unknown"),
        ] {
            let data = build_tls_record(CONTENT_TYPE_APPLICATION_DATA, ver, &[0x00]);

            let mut buf = DissectBuffer::new();
            TlsDissector.dissect(&data, &mut buf, 0).unwrap();

            let layer = buf.layer_by_name("TLS").unwrap();
            assert_eq!(
                buf.resolve_display_name(layer, "version_name").unwrap(),
                expected_name,
                "version 0x{ver:04x} should map to {expected_name}"
            );
        }
    }

    #[test]
    fn parse_tls_handshake_type_names() {
        for (ht, expected_name) in [
            (0u8, "Hello Request"),
            (1, "Client Hello"),
            (2, "Server Hello"),
            (4, "New Session Ticket"),
            (5, "End Of Early Data"),
            (8, "Encrypted Extensions"),
            (11, "Certificate"),
            (12, "Server Key Exchange"),
            (13, "Certificate Request"),
            (14, "Server Hello Done"),
            (15, "Certificate Verify"),
            (16, "Client Key Exchange"),
            (20, "Finished"),
            (24, "Key Update"),
            (254, "Message Hash"),
            (99, "Unknown"),
        ] {
            let hs_payload = build_handshake_header(ht, 0);
            let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &hs_payload);

            let mut buf = DissectBuffer::new();
            TlsDissector.dissect(&data, &mut buf, 0).unwrap();

            let layer = buf.layer_by_name("TLS").unwrap();
            assert_eq!(
                buf.resolve_display_name(layer, "handshake_type_name")
                    .unwrap(),
                expected_name,
                "handshake type {ht} should map to {expected_name}"
            );
        }
    }

    #[test]
    fn parse_tls_alert_description_names() {
        for (desc, expected_name) in [
            (0u8, "close_notify"),
            (10, "unexpected_message"),
            (20, "bad_record_mac"),
            (40, "handshake_failure"),
            (48, "unknown_ca"),
            (80, "internal_error"),
            (255, "unknown"),
        ] {
            let alert_payload = vec![2, desc]; // fatal level
            let data = build_tls_record(CONTENT_TYPE_ALERT, 0x0303, &alert_payload);

            let mut buf = DissectBuffer::new();
            TlsDissector.dissect(&data, &mut buf, 0).unwrap();

            let layer = buf.layer_by_name("TLS").unwrap();
            assert_eq!(
                buf.resolve_display_name(layer, "alert_description_name")
                    .unwrap(),
                expected_name,
                "alert description {desc} should map to {expected_name}"
            );
        }
    }

    #[test]
    fn parse_tls13_record() {
        // TLS 1.3 records use version 0x0303 in the record header but the
        // supported_versions extension indicates the actual version.
        // RFC 8446, Section 5.1 — https://www.rfc-editor.org/rfc/rfc8446#section-5.1
        let app_data = vec![0xab; 64];
        let data = build_tls_record(CONTENT_TYPE_APPLICATION_DATA, 0x0303, &app_data);

        let mut buf = DissectBuffer::new();
        let result = TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, RECORD_HEADER_SIZE + 64);

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U16(0x0303)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "version_name"),
            Some("TLS 1.2 / TLS 1.3 legacy_record_version")
        );
    }

    #[test]
    fn parse_tls_with_nonzero_offset() {
        // Verify that field byte ranges use the provided offset correctly.
        let data = build_tls_record(CONTENT_TYPE_APPLICATION_DATA, 0x0303, &[0x00]);
        let base_offset = 100;

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, base_offset).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(layer.range, base_offset..base_offset + 6);
        assert_eq!(
            buf.field_by_name(layer, "content_type").unwrap().range,
            base_offset..base_offset + 1
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().range,
            base_offset + 1..base_offset + 3
        );
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().range,
            base_offset + 3..base_offset + 5
        );
    }

    #[test]
    fn parse_tls_handshake_short_payload() {
        // Handshake record with payload too short for handshake header (< 4 bytes).
        // Should still parse the record header but not add handshake fields.
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &[0x01, 0x00]);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "content_type_name"),
            Some("Handshake")
        );
        assert!(buf.field_by_name(layer, "handshake_type").is_none());
    }

    #[test]
    fn parse_tls_alert_short_payload() {
        // Alert record with only 1 byte of payload (need 2).
        let data = build_tls_record(CONTENT_TYPE_ALERT, 0x0303, &[0x02]);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "content_type_name"),
            Some("Alert")
        );
        assert!(buf.field_by_name(layer, "alert_level").is_none());
    }

    /// Build a minimal ClientHello body (no extensions).
    ///
    /// Layout: version(2) + random(32) + session_id_len(1) + session_id(var)
    ///       + cipher_suites_len(2) + cipher_suites(var)
    ///       + compression_methods_len(1) + compression_methods(var)
    fn build_client_hello_body(
        version: u16,
        session_id: &[u8],
        cipher_suites: &[u16],
        compression_methods: &[u8],
        extensions: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&version.to_be_bytes());
        buf.extend_from_slice(&[0xab; RANDOM_SIZE]); // random
        buf.push(session_id.len() as u8);
        buf.extend_from_slice(session_id);
        let cs_len = (cipher_suites.len() * 2) as u16;
        buf.extend_from_slice(&cs_len.to_be_bytes());
        for &cs in cipher_suites {
            buf.extend_from_slice(&cs.to_be_bytes());
        }
        buf.push(compression_methods.len() as u8);
        buf.extend_from_slice(compression_methods);
        if let Some(ext_bytes) = extensions {
            buf.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(ext_bytes);
        }
        buf
    }

    /// Build a minimal ServerHello body.
    fn build_server_hello_body(
        version: u16,
        session_id: &[u8],
        cipher_suite: u16,
        compression_method: u8,
        extensions: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&version.to_be_bytes());
        buf.extend_from_slice(&[0xcd; RANDOM_SIZE]); // random
        buf.push(session_id.len() as u8);
        buf.extend_from_slice(session_id);
        buf.extend_from_slice(&cipher_suite.to_be_bytes());
        buf.push(compression_method);
        if let Some(ext_bytes) = extensions {
            buf.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(ext_bytes);
        }
        buf
    }

    /// Build a TLS extension: type(2) + length(2) + data(var).
    fn build_extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&ext_type.to_be_bytes());
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
        buf
    }

    /// Build an SNI extension (type=0) with a single host_name entry.
    fn build_sni_extension(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len() as u16;
        // ServerNameList: list_length(2) + name_type(1) + name_length(2) + name
        let list_len = 1 + 2 + name_len;
        let mut data = Vec::new();
        data.extend_from_slice(&list_len.to_be_bytes());
        data.push(0); // name_type = host_name(0)
        data.extend_from_slice(&name_len.to_be_bytes());
        data.extend_from_slice(name_bytes);
        build_extension(0, &data)
    }

    /// Wrap a ClientHello body in a handshake header + TLS record.
    fn wrap_client_hello(body: &[u8]) -> Vec<u8> {
        let mut hs = build_handshake_header(HANDSHAKE_TYPE_CLIENT_HELLO, body.len() as u32);
        hs.extend_from_slice(body);
        build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0301, &hs)
    }

    /// Wrap a ServerHello body in a handshake header + TLS record.
    fn wrap_server_hello(body: &[u8]) -> Vec<u8> {
        let mut hs = build_handshake_header(HANDSHAKE_TYPE_SERVER_HELLO, body.len() as u32);
        hs.extend_from_slice(body);
        build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &hs)
    }

    #[test]
    fn parse_client_hello_basic() {
        // ClientHello with no extensions, 2 cipher suites, 1 compression method.
        let body = build_client_hello_body(
            0x0303,
            &[0x01; 32], // 32-byte session ID
            &[0xc02f, 0x009e],
            &[0x00], // null compression
            None,
        );
        let data = wrap_client_hello(&body);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "handshake_version").unwrap().value,
            FieldValue::U16(0x0303)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "handshake_version_name"),
            Some("TLS 1.2 / TLS 1.3 legacy_record_version")
        );
        assert_eq!(
            buf.field_by_name(layer, "random").unwrap().value,
            FieldValue::Bytes(&[0xab; RANDOM_SIZE])
        );
        assert_eq!(
            buf.field_by_name(layer, "session_id").unwrap().value,
            FieldValue::Bytes(&[0x01; 32])
        );

        // cipher_suites is an Array of U16
        let cs_field = buf.field_by_name(layer, "cipher_suites").unwrap();
        let cs_range = cs_field.value.as_container_range().unwrap();
        let suites = buf.nested_fields(cs_range);
        assert_eq!(suites.len(), 2);
        assert_eq!(suites[0].value, FieldValue::U16(0xc02f));
        assert_eq!(suites[1].value, FieldValue::U16(0x009e));

        assert_eq!(
            buf.field_by_name(layer, "compression_methods")
                .unwrap()
                .value,
            FieldValue::Bytes(&[0x00])
        );

        // No extensions field
        assert!(buf.field_by_name(layer, "extensions").is_none());
    }

    #[test]
    fn parse_client_hello_with_extensions() {
        // ClientHello with an SNI extension.
        let sni_ext = build_sni_extension("example.com");
        let body = build_client_hello_body(
            0x0303,
            &[],               // empty session ID
            &[0x1301, 0x1302], // TLS 1.3 cipher suites
            &[0x00],
            Some(&sni_ext),
        );
        let data = wrap_client_hello(&body);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        let ext_field = buf.field_by_name(layer, "extensions").unwrap();
        let ext_range = ext_field.value.as_container_range().unwrap();
        let extensions = buf.nested_fields(ext_range);
        // Each extension is an Object container + its children
        // First Object's children: type, length, data, server_name
        assert!(extensions[0].value.is_object());
        let obj_range = extensions[0].value.as_container_range().unwrap();
        let ext_children = buf.nested_fields(obj_range);
        assert_eq!(ext_children[0].value, FieldValue::U16(0)); // type
        assert_eq!(
            ext_children[0]
                .value
                .as_u16()
                .map(|t| extension_type_name(t)),
            Some("server_name")
        );

        // Check server_name field
        let sni_field = ext_children
            .iter()
            .find(|f| f.name() == "server_name")
            .unwrap();
        assert_eq!(sni_field.value, FieldValue::Bytes(b"example.com"));
    }

    #[test]
    fn parse_client_hello_with_supported_versions() {
        // Build a supported_versions extension (type=43).
        // RFC 8446, Section 4.2.1 — https://www.rfc-editor.org/rfc/rfc8446#section-4.2.1
        // In ClientHello: supported_versions contains a list_length(1) + versions(2*n).
        let mut sv_data = vec![4]; // 4 bytes of version data
        sv_data.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3
        sv_data.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2
        let sv_ext = build_extension(43, &sv_data);

        let body = build_client_hello_body(
            0x0303, // legacy version
            &[],
            &[0x1301],
            &[0x00],
            Some(&sv_ext),
        );
        let data = wrap_client_hello(&body);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        let ext_field = buf.field_by_name(layer, "extensions").unwrap();
        let ext_range = ext_field.value.as_container_range().unwrap();
        let extensions = buf.nested_fields(ext_range);
        assert!(extensions[0].value.is_object());
        let obj_range = extensions[0].value.as_container_range().unwrap();
        let ext_children = buf.nested_fields(obj_range);
        assert_eq!(ext_children[0].value, FieldValue::U16(43)); // type = supported_versions
        assert_eq!(
            buf.resolve_nested_display_name(obj_range, "type_name"),
            Some("supported_versions")
        );
    }

    #[test]
    fn parse_server_hello_basic() {
        // ServerHello with no extensions.
        let body = build_server_hello_body(
            0x0303,
            &[0x02; 32], // 32-byte session ID
            0xc02f,      // cipher suite
            0x00,        // compression
            None,
        );
        let data = wrap_server_hello(&body);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "handshake_type").unwrap().value,
            FieldValue::U8(HANDSHAKE_TYPE_SERVER_HELLO)
        );
        assert_eq!(
            buf.field_by_name(layer, "handshake_version").unwrap().value,
            FieldValue::U16(0x0303)
        );
        assert_eq!(
            buf.field_by_name(layer, "random").unwrap().value,
            FieldValue::Bytes(&[0xcd; RANDOM_SIZE])
        );
        assert_eq!(
            buf.field_by_name(layer, "session_id").unwrap().value,
            FieldValue::Bytes(&[0x02; 32])
        );
        assert_eq!(
            buf.field_by_name(layer, "cipher_suite").unwrap().value,
            FieldValue::U16(0xc02f)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "cipher_suite_name"),
            Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        );
        assert_eq!(
            buf.field_by_name(layer, "compression_method")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
        assert!(buf.field_by_name(layer, "extensions").is_none());
        // ClientHello-only fields should not be present
        assert!(buf.field_by_name(layer, "cipher_suites").is_none());
        assert!(buf.field_by_name(layer, "compression_methods").is_none());
    }

    #[test]
    fn parse_server_hello_with_extensions() {
        // ServerHello with supported_versions extension (type=43).
        // In ServerHello, supported_versions contains just a single version (2 bytes).
        let sv_ext = build_extension(43, &0x0304u16.to_be_bytes());

        let body = build_server_hello_body(
            0x0303, // legacy version
            &[],    // empty session ID
            0x1301, // TLS_AES_128_GCM_SHA256
            0x00,
            Some(&sv_ext),
        );
        let data = wrap_server_hello(&body);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "cipher_suite").unwrap().value,
            FieldValue::U16(0x1301)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "cipher_suite_name"),
            Some("TLS_AES_128_GCM_SHA256")
        );

        let ext_field = buf.field_by_name(layer, "extensions").unwrap();
        let ext_range = ext_field.value.as_container_range().unwrap();
        let extensions = buf.nested_fields(ext_range);
        assert!(extensions[0].value.is_object());
        let obj_range = extensions[0].value.as_container_range().unwrap();
        let ext_children = buf.nested_fields(obj_range);
        assert_eq!(ext_children[0].value, FieldValue::U16(43));
    }

    #[test]
    fn parse_client_hello_truncated_body() {
        // ClientHello with a body too short to contain even the minimum fields.
        // Should parse handshake type/length but not body fields.
        let short_body = vec![0x03, 0x03]; // only 2 bytes (version), no random
        let mut hs = build_handshake_header(HANDSHAKE_TYPE_CLIENT_HELLO, short_body.len() as u32);
        hs.extend_from_slice(&short_body);
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0301, &hs);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "handshake_type").unwrap().value,
            FieldValue::U8(HANDSHAKE_TYPE_CLIENT_HELLO)
        );
        // Body fields should not be present due to truncation
        assert!(buf.field_by_name(layer, "handshake_version").is_none());
        assert!(buf.field_by_name(layer, "random").is_none());
    }

    #[test]
    fn parse_server_hello_truncated_body() {
        // ServerHello with body truncated after session_id.
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // version
        body.extend_from_slice(&[0x00; RANDOM_SIZE]); // random
        body.push(0); // session_id_len=0
        // Missing cipher_suite and compression_method

        let mut hs = build_handshake_header(HANDSHAKE_TYPE_SERVER_HELLO, body.len() as u32);
        hs.extend_from_slice(&body);
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &hs);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        // Basic fields should be present
        assert_eq!(
            buf.field_by_name(layer, "handshake_version").unwrap().value,
            FieldValue::U16(0x0303)
        );
        assert_eq!(
            buf.field_by_name(layer, "session_id").unwrap().value,
            FieldValue::Bytes(&[])
        );
        // Truncated fields should not be present
        assert!(buf.field_by_name(layer, "cipher_suite").is_none());
        assert!(buf.field_by_name(layer, "compression_method").is_none());
    }

    #[test]
    fn parse_tls_extension_type_names() {
        for (ext_type, expected_name) in [
            (0u16, "server_name"),
            (10, "supported_groups"),
            (13, "signature_algorithms"),
            (16, "application_layer_protocol_negotiation"),
            (43, "supported_versions"),
            (51, "key_share"),
            (0xff01, "renegotiation_info"),
            (9999, "unknown"),
        ] {
            assert_eq!(
                extension_type_name(ext_type),
                expected_name,
                "extension type {ext_type} should map to {expected_name}"
            );
        }
    }

    #[test]
    fn parse_tls_cipher_suite_names() {
        for (cs, expected_name) in [
            (0x1301u16, Some("TLS_AES_128_GCM_SHA256")),
            (0x1302, Some("TLS_AES_256_GCM_SHA384")),
            (0x1303, Some("TLS_CHACHA20_POLY1305_SHA256")),
            (0xc02f, Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")),
            (0xc02b, Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")),
            (0xcca8, Some("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")),
            (0x0000, None),
            (0xffff, None),
        ] {
            assert_eq!(
                cipher_suite_name(cs),
                expected_name,
                "cipher suite 0x{cs:04x} should map to {expected_name:?}"
            );
        }
    }

    #[test]
    fn parse_client_hello_multiple_extensions() {
        // ClientHello with SNI + supported_versions extensions.
        let sni_ext = build_sni_extension("test.example.org");
        let sv_ext = build_extension(43, &[2, 0x03, 0x04]); // 1 version: TLS 1.3
        let mut all_ext = Vec::new();
        all_ext.extend_from_slice(&sni_ext);
        all_ext.extend_from_slice(&sv_ext);

        let body = build_client_hello_body(0x0303, &[], &[0x1301], &[0x00], Some(&all_ext));
        let data = wrap_client_hello(&body);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        let ext_field = buf.field_by_name(layer, "extensions").unwrap();
        let ext_range = ext_field.value.as_container_range().unwrap();
        let extensions = buf.nested_fields(ext_range);
        // Count Object containers (each extension is an Object)
        let obj_count = extensions.iter().filter(|f| f.value.is_object()).count();
        assert_eq!(obj_count, 2);

        // First: SNI
        let sni_range = extensions[0].value.as_container_range().unwrap();
        let sni_children = buf.nested_fields(sni_range);
        assert_eq!(sni_children[0].value, FieldValue::U16(0));
        let sni_name = sni_children
            .iter()
            .find(|f| f.name() == "server_name")
            .unwrap();
        assert_eq!(sni_name.value, FieldValue::Bytes(b"test.example.org"));

        // Second: supported_versions — find the second Object field
        let second_obj = extensions
            .iter()
            .filter(|f| f.value.is_object())
            .nth(1)
            .unwrap();
        let sv_range = second_obj.value.as_container_range().unwrap();
        let sv_children = buf.nested_fields(sv_range);
        assert_eq!(sv_children[0].value, FieldValue::U16(43));
    }
}
