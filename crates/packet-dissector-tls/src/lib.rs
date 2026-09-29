//! TLS (Transport Layer Security) record layer dissector.
//!
//! Parses the TLS record layer header (5 bytes) and the plaintext messages
//! it carries: every handshake message in a Handshake record (with
//! ClientHello / ServerHello bodies decoded) and the Alert message.
//!
//! The dissector is stateless, so it cannot know whether record protection
//! is already active. It classifies a record by its structure instead:
//!
//! - An Alert record whose length is not 2 is reported as `encrypted_alert`.
//! - A Handshake record is decoded only when it consists of whole handshake
//!   headers with known types. The last message may continue in the next
//!   record; it is then flagged with `fragment_length`, or, if the record
//!   ends inside its header, the header bytes are reported as
//!   `opaque_handshake`. Anything else is reported as `opaque_handshake`: an
//!   encrypted handshake message (TLS 1.2 Finished after ChangeCipherSpec) or
//!   the continuation of a message fragmented across records. Handshake
//!   messages are not reassembled across records.
//!
//! The layer label (`TLSv1.x`) is not taken from the record version, which
//! TLS 1.3 fixes at 0x0303 (RFC 9846, Section 5.1). It comes from the
//! ServerHello `supported_versions` extension or `legacy_version`, or from the
//! ClientHello `legacy_version` when the client does not offer
//! `supported_versions`.
//!
//! ## References
//! - RFC 9846 (TLS 1.3, obsoletes RFC 8446 and RFC 5246): <https://www.rfc-editor.org/rfc/rfc9846>
//! - RFC 5246 (TLS 1.2): <https://www.rfc-editor.org/rfc/rfc5246>
//! - RFC 4680 (TLS Handshake Message for Supplemental Data): <https://www.rfc-editor.org/rfc/rfc4680>
//! - RFC 6066 (TLS Extensions Definitions): <https://www.rfc-editor.org/rfc/rfc6066>
//! - RFC 6520 (Heartbeat Extension): <https://www.rfc-editor.org/rfc/rfc6520>
//! - RFC 7301 (ALPN): <https://www.rfc-editor.org/rfc/rfc7301>
//! - RFC 7366 (Encrypt-then-MAC): <https://www.rfc-editor.org/rfc/rfc7366>
//! - RFC 7905 (ChaCha20-Poly1305 Cipher Suites): <https://www.rfc-editor.org/rfc/rfc7905>
//! - RFC 8449 (Record Size Limit): <https://www.rfc-editor.org/rfc/rfc8449>
//! - RFC 8879 (TLS Certificate Compression): <https://www.rfc-editor.org/rfc/rfc8879>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24};

/// TLS record layer header size (always 5 bytes).
///
/// ```text
/// RFC 9846, Section 5.1 — https://www.rfc-editor.org/rfc/rfc9846#section-5.1
///
/// struct {
///     ContentType type;
///     ProtocolVersion legacy_record_version;
///     uint16 length;
///     opaque fragment[TLSPlaintext.length];
/// } TLSPlaintext;
/// ```
const RECORD_HEADER_SIZE: usize = 5;

/// Largest record `length` accepted: 2^14 + 2048.
///
/// RFC 5246, Section 6.2.3 — <https://www.rfc-editor.org/rfc/rfc5246#section-6.2.3>:
/// "The length MUST NOT exceed 2^14 + 2048." This is the largest limit of
/// any TLS version; TLS 1.3 allows at most 2^14 + 256
/// (RFC 9846, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc9846#section-5.2>).
const MAX_RECORD_LENGTH: usize = (1 << 14) + 2048;

/// Major version byte of every SSL 3.0 / TLS `ProtocolVersion` (0x03xx).
///
/// RFC 5246, Appendix E — <https://www.rfc-editor.org/rfc/rfc5246#appendix-E>
const TLS_MAJOR_VERSION: u8 = 3;

/// TLS handshake message header size (1-byte type + 3-byte length).
///
/// RFC 9846, Section 4 — <https://www.rfc-editor.org/rfc/rfc9846#section-4>
const HANDSHAKE_HEADER_SIZE: usize = 4;

/// Largest declared length accepted for a handshake message that runs past
/// the end of its record.
///
/// The protocol allows messages up to 2^24 - 1 bytes, but a stateless
/// dissector cannot tell a fragmented message from ciphertext whose first
/// bytes happen to form a known handshake header. Real messages that span
/// records are certificate chains, which stay far below this bound (OpenSSL's
/// default `max_cert_list` is 100 KiB), while a random 24-bit length exceeds
/// it with probability 63/64.
const MAX_FRAGMENTED_HANDSHAKE_LENGTH: usize = 1 << 18;

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
/// `heartbeat(24)` — RFC 6520, Section 3 — <https://www.rfc-editor.org/rfc/rfc6520#section-3>
const CONTENT_TYPE_HEARTBEAT: u8 = 24;

/// Returns a human-readable name for a TLS `ContentType` value.
///
/// RFC 9846, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc9846#section-5.1>
/// RFC 6520, Section 3 — <https://www.rfc-editor.org/rfc/rfc6520#section-3> (Heartbeat)
fn content_type_name(ct: u8) -> &'static str {
    match ct {
        CONTENT_TYPE_CHANGE_CIPHER_SPEC => "Change Cipher Spec",
        CONTENT_TYPE_ALERT => "Alert",
        CONTENT_TYPE_HANDSHAKE => "Handshake",
        CONTENT_TYPE_APPLICATION_DATA => "Application Data",
        CONTENT_TYPE_HEARTBEAT => "Heartbeat",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for a record or `legacy_version` value.
///
/// 0x0303 is ambiguous in these fields: TLS 1.3 sends it as
/// `legacy_record_version` / `legacy_version`.
///
/// RFC 5246, Section 6.2.1 — <https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1>
/// RFC 9846, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc9846#section-5.1>
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

/// Returns a human-readable name for a version in the `supported_versions`
/// extension, where every value means exactly that version.
///
/// RFC 9846, Section 4.3.1 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3.1>
fn supported_version_name(version: u16) -> &'static str {
    match version {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
    }
}

/// Returns a version-qualified short name for use as the layer display name.
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

/// Layer label for a record that carries no ClientHello / ServerHello.
///
/// RFC 9846, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc9846#section-5.1>:
/// `legacy_record_version` "MUST be set to 0x0303 for all records generated
/// by a TLS 1.3 implementation other than an initial ClientHello". So 0x0303
/// does not identify the version, while 0x0300..=0x0302 in a record that is
/// not part of a ClientHello can only come from SSL 3.0 / TLS 1.0 / TLS 1.1.
fn record_version_label(version: u16) -> Option<&'static str> {
    match version {
        0x0300..=0x0302 => version_short_name(version),
        _ => None,
    }
}

/// Returns a human-readable name for a TLS `HandshakeType` value.
///
/// Based on the IANA TLS HandshakeType registry:
/// <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7>
///
/// RFC 5246, Section 7.4 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4>
/// RFC 9846, Section 4 — <https://www.rfc-editor.org/rfc/rfc9846#section-4>
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
        // RFC 6066, Sections 5 and 8 — https://www.rfc-editor.org/rfc/rfc6066#section-8
        21 => "Certificate URL",
        22 => "Certificate Status",
        // RFC 4680, Section 2 — https://www.rfc-editor.org/rfc/rfc4680#section-2
        23 => "Supplemental Data",
        // RFC 9846, Section 4.7.3
        24 => "Key Update",
        // RFC 8879, Section 5
        25 => "Compressed Certificate",
        254 => "Message Hash",
        _ => "Unknown",
    }
}

/// Whether `ht` is a handshake type that can appear in a TLS record.
///
/// `message_hash(254)` is excluded: it only exists inside the transcript
/// hash (RFC 9846, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.1>).
/// DTLS-only types are excluded as well.
fn is_wire_handshake_type(ht: u8) -> bool {
    matches!(
        ht,
        0 | 1 | 2 | 4 | 5 | 8 | 11 | 12 | 13 | 14 | 15 | 16 | 20 | 21 | 22 | 23 | 24 | 25
    )
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
        // RFC 9846, Section 6
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
/// Based on the TLS 1.3 ExtensionType enum (RFC 9846, Section 4.3 —
/// <https://www.rfc-editor.org/rfc/rfc9846#section-4.3>) and the IANA TLS
/// ExtensionType Values registry:
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
        // RFC 9846, Section 4.3 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3
        // (originally RFC 7250 — https://www.rfc-editor.org/rfc/rfc7250)
        19 => "client_certificate_type",
        20 => "server_certificate_type",
        21 => "padding",
        // RFC 7366, Section 2 — https://www.rfc-editor.org/rfc/rfc7366#section-2
        22 => "encrypt_then_mac",
        23 => "extended_master_secret",
        // RFC 8879, Section 7.1 — https://www.rfc-editor.org/rfc/rfc8879#section-7.1
        27 => "compress_certificate",
        // RFC 8449, Section 5 — https://www.rfc-editor.org/rfc/rfc8449#section-5
        28 => "record_size_limit",
        35 => "session_ticket",
        41 => "pre_shared_key",
        42 => "early_data",
        43 => "supported_versions",
        44 => "cookie",
        45 => "psk_key_exchange_modes",
        47 => "certificate_authorities",
        // RFC 9846, Section 4.3.5 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.5
        48 => "oid_filters",
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
        // TLS 1.3 cipher suites — RFC 9846, Appendix B.4
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

/// Minimum ClientHello / ServerHello body size:
/// legacy_version(2) + random(32) + legacy_session_id length(1).
///
/// RFC 9846, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.2.2>
/// RFC 9846, Section 4.2.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.2.3>
const HELLO_MIN_BODY: usize = 2 + 32 + 1;

/// Size of the TLS `Random` field (32 bytes).
///
/// RFC 9846, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.2.2>
const RANDOM_SIZE: usize = 32;

/// ServerHello.random value that marks a HelloRetryRequest
/// (SHA-256 of "HelloRetryRequest").
///
/// RFC 9846, Section 4.2.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.2.3>
const HELLO_RETRY_REQUEST_RANDOM: [u8; RANDOM_SIZE] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Handshake type for ClientHello.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

/// Handshake type for ServerHello (and HelloRetryRequest).
const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;

/// ExtensionType `supported_versions(43)`.
///
/// RFC 9846, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3>
const EXT_SUPPORTED_VERSIONS: u16 = 43;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_CONTENT_TYPE: usize = 0;
const FD_VERSION: usize = 1;
const FD_LENGTH: usize = 2;
const FD_HANDSHAKE_MESSAGES: usize = 3;
const FD_OPAQUE_HANDSHAKE: usize = 4;
const FD_ALERT_LEVEL: usize = 5;
const FD_ALERT_DESCRIPTION: usize = 6;
const FD_ENCRYPTED_ALERT: usize = 7;

/// Field descriptor indices for [`HANDSHAKE_CHILD_FIELDS`].
const HFD_TYPE: usize = 0;
const HFD_LENGTH: usize = 1;
const HFD_FRAGMENT_LENGTH: usize = 2;
const HFD_VERSION: usize = 3;
const HFD_RANDOM: usize = 4;
const HFD_HELLO_RETRY_REQUEST: usize = 5;
const HFD_SESSION_ID: usize = 6;
const HFD_CIPHER_SUITES: usize = 7;
const HFD_CIPHER_SUITE: usize = 8;
const HFD_COMPRESSION_METHODS: usize = 9;
const HFD_COMPRESSION_METHOD: usize = 10;
const HFD_EXTENSIONS: usize = 11;

/// Field descriptor indices for [`EXTENSION_CHILD_FIELDS`].
const EFD_TYPE: usize = 0;
const EFD_LENGTH: usize = 1;
const EFD_DATA: usize = 2;
const EFD_SERVER_NAME: usize = 3;
const EFD_VERSIONS: usize = 4;
const EFD_VERSION: usize = 5;
const EFD_SELECTED_VERSION: usize = 6;

/// Container descriptor for an extension Object.
///
/// The outer label resolves to the extension name (e.g. `server_name`) by
/// looking up the inner `type` field, avoiding collision with the inner
/// "Extension Type" label.
static FD_EXTENSION: FieldDescriptor = FieldDescriptor {
    name: "extension",
    display_name: "Extension",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U16(t)) => Some(extension_type_name(*t)),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Descriptor for a version value inside `supported_versions`.
const fn supported_version_descriptor(
    name: &'static str,
    display_name: &'static str,
) -> FieldDescriptor {
    FieldDescriptor {
        name,
        display_name,
        field_type: FieldType::U16,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(ver) => Some(supported_version_name(*ver)),
            _ => None,
        }),
        format_fn: None,
    }
}

/// Child field descriptors for extension objects within the `extensions` array.
///
/// RFC 9846, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3>
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
    // RFC 9846, Section 4.3.1 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.1
    FieldDescriptor::new("versions", "Supported Versions", FieldType::Array).optional(),
    supported_version_descriptor("version", "Supported Version"),
    supported_version_descriptor("selected_version", "Selected Version"),
];

/// Container descriptor for a handshake message Object.
///
/// The label resolves to the handshake type name, or "Hello Retry Request"
/// for a ServerHello carrying the HelloRetryRequest random
/// (RFC 9846, Section 4.2.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.2.3>).
static FD_HANDSHAKE: FieldDescriptor = FieldDescriptor {
    name: "handshake",
    display_name: "Handshake Message",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| {
        if !matches!(v, FieldValue::Object(_)) {
            return None;
        }
        if children.iter().any(|f| f.name() == "hello_retry_request") {
            return Some("Hello Retry Request");
        }
        children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => Some(handshake_type_name(*t)),
            _ => None,
        })
    }),
    format_fn: None,
};

/// Child field descriptors for handshake message objects within the
/// `handshake_messages` array.
///
/// RFC 9846, Section 4 — <https://www.rfc-editor.org/rfc/rfc9846#section-4>
static HANDSHAKE_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Handshake Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(ht) => Some(handshake_type_name(*ht)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Handshake Length", FieldType::U32),
    // Present only when the message continues in a following record: the
    // number of body bytes carried by this record.
    FieldDescriptor::new("fragment_length", "Fragment Length", FieldType::U32).optional(),
    // --- ClientHello / ServerHello fields ---
    FieldDescriptor {
        name: "version",
        display_name: "Legacy Version",
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
    FieldDescriptor::new("hello_retry_request", "Hello Retry Request", FieldType::U8).optional(),
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
    // --- Handshake records (content_type == 22) ---
    FieldDescriptor::new("handshake_messages", "Handshake Messages", FieldType::Array)
        .optional()
        .with_children(HANDSHAKE_CHILD_FIELDS),
    FieldDescriptor::new(
        "opaque_handshake",
        "Encrypted or Continued Handshake Data",
        FieldType::Bytes,
    )
    .optional(),
    // --- Alert records (content_type == 21) ---
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
    FieldDescriptor::new("encrypted_alert", "Encrypted Alert", FieldType::Bytes).optional(),
];

/// What a ClientHello / ServerHello says about the protocol version.
#[derive(Clone, Copy)]
struct HelloVersion {
    /// `legacy_version` from the message body.
    legacy_version: u16,
    /// The `supported_versions` extension, if any.
    supported_versions: SupportedVersions,
}

/// State of the `supported_versions` extension in a Hello message.
///
/// RFC 9846, Section 4.3.1 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3.1>
#[derive(Clone, Copy, PartialEq, Eq)]
enum SupportedVersions {
    /// The extension is not present.
    Absent,
    /// The extension is present without selecting a single version (a
    /// ClientHello list, or a malformed ServerHello value), or the message is
    /// too malformed to tell whether it is present.
    Undetermined,
    /// A ServerHello / HelloRetryRequest `selected_version`.
    Selected(u16),
}

impl HelloVersion {
    /// Layer label implied by this Hello message.
    ///
    /// RFC 9846, Section 4.3.1 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3.1>:
    /// "If this extension is present, clients MUST ignore the
    /// ServerHello.legacy_version value and MUST use only the
    /// "supported_versions" extension to determine the selected version."
    /// A ClientHello that carries the extension offers a list, so no single
    /// version applies to it.
    fn label(self) -> Option<&'static str> {
        match self.supported_versions {
            SupportedVersions::Absent => version_short_name(self.legacy_version),
            SupportedVersions::Undetermined => None,
            SupportedVersions::Selected(v) => version_short_name(v),
        }
    }
}

/// Decode the `supported_versions` extension body.
///
/// ```text
/// RFC 9846, Section 4.3.1 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.1
///
/// struct {
///     select (Handshake.msg_type) {
///         case client_hello:
///              ProtocolVersion versions<2..254>;
///
///         case server_hello: /* and HelloRetryRequest */
///              ProtocolVersion selected_version;
///     };
/// } SupportedVersions;
/// ```
fn parse_supported_versions<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    handshake_type: u8,
    buf: &mut DissectBuffer<'pkt>,
) -> SupportedVersions {
    if handshake_type == HANDSHAKE_TYPE_SERVER_HELLO {
        if data.len() == 2 {
            let v = read_be_u16(data, 0).unwrap_or_default();
            buf.push_field(
                &EXTENSION_CHILD_FIELDS[EFD_SELECTED_VERSION],
                FieldValue::U16(v),
                offset..offset + 2,
            );
            return SupportedVersions::Selected(v);
        }
        return SupportedVersions::Undetermined;
    }

    let Some((&list_len, list)) = data.split_first() else {
        return SupportedVersions::Undetermined;
    };
    let list_len = list_len as usize;
    if list_len != list.len() || list_len < 2 || list_len % 2 != 0 {
        return SupportedVersions::Undetermined;
    }
    let arr = buf.begin_container(
        &EXTENSION_CHILD_FIELDS[EFD_VERSIONS],
        FieldValue::Array(0..0),
        offset + 1..offset + 1 + list_len,
    );
    for (i, v) in list.chunks_exact(2).enumerate() {
        let start = offset + 1 + i * 2;
        buf.push_field(
            &EXTENSION_CHILD_FIELDS[EFD_VERSION],
            FieldValue::U16(u16::from_be_bytes([v[0], v[1]])),
            start..start + 2,
        );
    }
    buf.end_container(arr);
    SupportedVersions::Undetermined
}

/// Parse the TLS extensions list into a [`DissectBuffer`].
///
/// Each extension is a 2-byte type, 2-byte length, and variable-length data.
/// Returns what the `supported_versions` extension says, if present.
///
/// RFC 9846, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3>
fn parse_extensions<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    handshake_type: u8,
    buf: &mut DissectBuffer<'pkt>,
) -> SupportedVersions {
    let mut supported_versions = SupportedVersions::Absent;
    let mut pos = 0;
    while pos < data.len() {
        let (Ok(ext_type), Ok(ext_len)) = (read_be_u16(data, pos), read_be_u16(data, pos + 2))
        else {
            break;
        };
        let ext_len = ext_len as usize;
        if pos + 4 + ext_len > data.len() {
            break;
        }
        let ext_data = &data[pos + 4..pos + 4 + ext_len];
        let ext_data_offset = offset + pos + 4;

        let obj_idx = buf.begin_container(
            &FD_EXTENSION,
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
            ext_data_offset..ext_data_offset + ext_len,
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
                            ext_data_offset + 5..ext_data_offset + 5 + name_len,
                        );
                    }
                }
            }
        }

        if ext_type == EXT_SUPPORTED_VERSIONS && supported_versions == SupportedVersions::Absent {
            supported_versions =
                parse_supported_versions(ext_data, ext_data_offset, handshake_type, buf);
        }

        buf.end_container(obj_idx);
        pos += 4 + ext_len;
    }
    if pos != data.len() && supported_versions == SupportedVersions::Absent {
        // A malformed extension may hide supported_versions.
        return SupportedVersions::Undetermined;
    }
    supported_versions
}

/// Parse the trailing `extensions` vector of a Hello message body starting
/// at `pos`, if it is present and fits.
///
/// A body that ends right before the vector has no extensions (TLS 1.2 and
/// earlier, RFC 5246, Section 7.4.1.2 —
/// <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2>).
fn parse_hello_extensions<'pkt>(
    body: &'pkt [u8],
    pos: usize,
    offset: usize,
    handshake_type: u8,
    buf: &mut DissectBuffer<'pkt>,
) -> SupportedVersions {
    if pos == body.len() {
        return SupportedVersions::Absent;
    }
    let Ok(ext_len) = read_be_u16(body, pos) else {
        return SupportedVersions::Undetermined;
    };
    let ext_len = ext_len as usize;
    let start = pos + 2;
    let Some(ext_data) = body.get(start..start + ext_len) else {
        return SupportedVersions::Undetermined;
    };
    let ext_array_idx = buf.begin_container(
        &HANDSHAKE_CHILD_FIELDS[HFD_EXTENSIONS],
        FieldValue::Array(0..0),
        offset + start..offset + start + ext_len,
    );
    let supported_versions = parse_extensions(ext_data, offset + start, handshake_type, buf);
    buf.end_container(ext_array_idx);
    supported_versions
}

/// Push `legacy_version`, `random` and `legacy_session_id` shared by
/// ClientHello and ServerHello.
///
/// Returns `None` (pushing nothing) when the body is shorter than
/// [`HELLO_MIN_BODY`]. Otherwise returns the version information, with
/// `supported_versions` still undetermined, and the position after the
/// session ID, or `None` if the session ID does not fit.
fn parse_hello_prefix<'pkt>(
    body: &'pkt [u8],
    offset: usize,
    handshake_type: u8,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<(HelloVersion, Option<usize>)> {
    if body.len() < HELLO_MIN_BODY {
        return None;
    }
    let mut pos = 0;
    let version = read_be_u16(body, pos).ok()?;
    let hello = HelloVersion {
        legacy_version: version,
        supported_versions: SupportedVersions::Undetermined,
    };
    buf.push_field(
        &HANDSHAKE_CHILD_FIELDS[HFD_VERSION],
        FieldValue::U16(version),
        offset + pos..offset + pos + 2,
    );
    pos += 2;

    let random = &body[pos..pos + RANDOM_SIZE];
    buf.push_field(
        &HANDSHAKE_CHILD_FIELDS[HFD_RANDOM],
        FieldValue::Bytes(random),
        offset + pos..offset + pos + RANDOM_SIZE,
    );
    // RFC 9846, Section 4.2.3 — https://www.rfc-editor.org/rfc/rfc9846#section-4.2.3
    // "Upon receiving a message with type server_hello, implementations MUST
    // first examine the Random value and, if it matches this value, process
    // it as described in Section 4.2.4."
    if handshake_type == HANDSHAKE_TYPE_SERVER_HELLO && random == HELLO_RETRY_REQUEST_RANDOM {
        buf.push_field(
            &HANDSHAKE_CHILD_FIELDS[HFD_HELLO_RETRY_REQUEST],
            FieldValue::U8(1),
            offset + pos..offset + pos + RANDOM_SIZE,
        );
    }
    pos += RANDOM_SIZE;

    let session_id_len = body[pos] as usize;
    pos += 1;
    let Some(session_id) = body.get(pos..pos + session_id_len) else {
        return Some((hello, None));
    };
    buf.push_field(
        &HANDSHAKE_CHILD_FIELDS[HFD_SESSION_ID],
        FieldValue::Bytes(session_id),
        offset + pos..offset + pos + session_id_len,
    );
    Some((hello, Some(pos + session_id_len)))
}

/// Parse a ClientHello handshake body and append fields.
///
/// RFC 5246, Section 7.4.1.2 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2>
/// RFC 9846, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.2.2>
fn parse_client_hello<'pkt>(
    body: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<HelloVersion> {
    let (mut hello, pos) = parse_hello_prefix(body, offset, HANDSHAKE_TYPE_CLIENT_HELLO, buf)?;
    let Some(mut pos) = pos else {
        return Some(hello);
    };

    // cipher_suites: 2-byte length prefix + list of u16
    let Ok(cs_len) = read_be_u16(body, pos) else {
        return Some(hello);
    };
    let cs_len = cs_len as usize;
    pos += 2;
    if pos + cs_len > body.len() || cs_len % 2 != 0 {
        return Some(hello);
    }
    let cs_array_idx = buf.begin_container(
        &HANDSHAKE_CHILD_FIELDS[HFD_CIPHER_SUITES],
        FieldValue::Array(0..0),
        offset + pos..offset + pos + cs_len,
    );
    for i in (0..cs_len).step_by(2) {
        let suite = read_be_u16(body, pos + i).unwrap_or_default();
        buf.push_field(
            &HANDSHAKE_CHILD_FIELDS[HFD_CIPHER_SUITE],
            FieldValue::U16(suite),
            offset + pos + i..offset + pos + i + 2,
        );
    }
    buf.end_container(cs_array_idx);
    pos += cs_len;

    let Some(&comp_len) = body.get(pos) else {
        return Some(hello);
    };
    let comp_len = comp_len as usize;
    pos += 1;
    let Some(comp) = body.get(pos..pos + comp_len) else {
        return Some(hello);
    };
    buf.push_field(
        &HANDSHAKE_CHILD_FIELDS[HFD_COMPRESSION_METHODS],
        FieldValue::Bytes(comp),
        offset + pos..offset + pos + comp_len,
    );
    pos += comp_len;

    hello.supported_versions =
        parse_hello_extensions(body, pos, offset, HANDSHAKE_TYPE_CLIENT_HELLO, buf);
    Some(hello)
}

/// Parse a ServerHello (or HelloRetryRequest) handshake body and append fields.
///
/// RFC 5246, Section 7.4.1.3 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.3>
/// RFC 9846, Section 4.2.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.2.3>
fn parse_server_hello<'pkt>(
    body: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<HelloVersion> {
    let (mut hello, pos) = parse_hello_prefix(body, offset, HANDSHAKE_TYPE_SERVER_HELLO, buf)?;
    let Some(mut pos) = pos else {
        return Some(hello);
    };

    let Ok(cs) = read_be_u16(body, pos) else {
        return Some(hello);
    };
    buf.push_field(
        &HANDSHAKE_CHILD_FIELDS[HFD_CIPHER_SUITE],
        FieldValue::U16(cs),
        offset + pos..offset + pos + 2,
    );
    pos += 2;

    let Some(&comp) = body.get(pos) else {
        return Some(hello);
    };
    buf.push_field(
        &HANDSHAKE_CHILD_FIELDS[HFD_COMPRESSION_METHOD],
        FieldValue::U8(comp),
        offset + pos..offset + pos + 1,
    );
    pos += 1;

    hello.supported_versions =
        parse_hello_extensions(body, pos, offset, HANDSHAKE_TYPE_SERVER_HELLO, buf);
    Some(hello)
}

/// Whether a Handshake record payload is a sequence of plaintext handshake
/// messages.
///
/// RFC 9846, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc9846#section-5.1>:
/// "Handshake messages MAY be coalesced into a single TLSPlaintext record
/// or fragmented across several records". The payload qualifies when it
/// starts with a complete header and every header has a known type. The
/// last message may extend past the end of the record (up to
/// [`MAX_FRAGMENTED_HANDSHAKE_LENGTH`]), or the record may end inside the
/// last header. Anything else is either ciphertext (TLS 1.2 after
/// ChangeCipherSpec, RFC 5246, Section 6.2.3 —
/// <https://www.rfc-editor.org/rfc/rfc5246#section-6.2.3>) or the
/// continuation of a message started in an earlier record.
fn is_plaintext_handshake(payload: &[u8]) -> bool {
    if payload.len() < HANDSHAKE_HEADER_SIZE {
        return false;
    }
    let mut pos = 0;
    while pos < payload.len() {
        if !is_wire_handshake_type(payload[pos]) {
            return false;
        }
        let Ok(msg_len) = read_be_u24(payload, pos + 1) else {
            // The record ends inside this header.
            return true;
        };
        let msg_len = msg_len as usize;
        pos += HANDSHAKE_HEADER_SIZE;
        if msg_len > payload.len() - pos && msg_len > MAX_FRAGMENTED_HANDSHAKE_LENGTH {
            return false;
        }
        pos += msg_len;
    }
    true
}

/// Dissect the payload of a Handshake record. Returns the layer label.
///
/// The label comes from the first ClientHello / ServerHello. A record of
/// other plaintext handshake messages uses the record version (see
/// [`record_version_label`]). Opaque data gets no version: it may continue a
/// TLS 1.3 initial ClientHello, whose record version may be 0x0301.
///
/// ```text
/// RFC 9846, Section 4 — https://www.rfc-editor.org/rfc/rfc9846#section-4
///
/// struct {
///     HandshakeType msg_type;    /* handshake type */
///     uint24 length;             /* remaining bytes in message */
///     select (Handshake.msg_type) { ... };
/// } Handshake;
/// ```
fn dissect_handshake_record<'pkt>(
    payload: &'pkt [u8],
    offset: usize,
    record_version: u16,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<&'static str> {
    if payload.is_empty() {
        // RFC 9846, Section 5.1: "Implementations MUST NOT send zero-length
        // fragments of Handshake types".
        return None;
    }
    if !is_plaintext_handshake(payload) {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_OPAQUE_HANDSHAKE],
            FieldValue::Bytes(payload),
            offset..offset + payload.len(),
        );
        return None;
    }

    let mut hello: Option<HelloVersion> = None;
    let mut saw_hello = false;
    let arr_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_HANDSHAKE_MESSAGES],
        FieldValue::Array(0..0),
        offset..offset + payload.len(),
    );
    let mut pos = 0;
    while pos + HANDSHAKE_HEADER_SIZE <= payload.len() {
        let ht = payload[pos];
        saw_hello |= matches!(
            ht,
            HANDSHAKE_TYPE_CLIENT_HELLO | HANDSHAKE_TYPE_SERVER_HELLO
        );
        let msg_len = read_be_u24(payload, pos + 1).unwrap_or_default();
        let body_start = pos + HANDSHAKE_HEADER_SIZE;
        let available = payload.len() - body_start;
        let fragmented = msg_len as usize > available;
        let body_len = if fragmented {
            available
        } else {
            msg_len as usize
        };
        let body_end = body_start + body_len;
        let body = &payload[body_start..body_end];
        let body_offset = offset + body_start;

        let obj_idx = buf.begin_container(
            &FD_HANDSHAKE,
            FieldValue::Object(0..0),
            offset + pos..offset + body_end,
        );
        buf.push_field(
            &HANDSHAKE_CHILD_FIELDS[HFD_TYPE],
            FieldValue::U8(ht),
            offset + pos..offset + pos + 1,
        );
        buf.push_field(
            &HANDSHAKE_CHILD_FIELDS[HFD_LENGTH],
            FieldValue::U32(msg_len),
            offset + pos + 1..offset + body_start,
        );
        if fragmented {
            // The rest of the message is in the following record(s); a
            // partial body is not decoded.
            buf.push_field(
                &HANDSHAKE_CHILD_FIELDS[HFD_FRAGMENT_LENGTH],
                FieldValue::U32(body_len as u32),
                body_offset..offset + body_end,
            );
        } else {
            let parsed = match ht {
                HANDSHAKE_TYPE_CLIENT_HELLO => parse_client_hello(body, body_offset, buf),
                HANDSHAKE_TYPE_SERVER_HELLO => parse_server_hello(body, body_offset, buf),
                _ => None,
            };
            if hello.is_none() {
                hello = parsed;
            }
        }
        buf.end_container(obj_idx);
        pos = body_end;
    }
    buf.end_container(arr_idx);

    if pos < payload.len() {
        // The record ends inside a handshake header; the message continues
        // in the next record.
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_OPAQUE_HANDSHAKE],
            FieldValue::Bytes(&payload[pos..]),
            offset + pos..offset + payload.len(),
        );
    }

    match hello {
        Some(hello) => hello.label(),
        // A fragmented or malformed Hello may come from TLS 1.3.
        None if saw_hello => None,
        None => record_version_label(record_version),
    }
}

/// Dissect the payload of an Alert record.
///
/// ```text
/// RFC 5246, Section 7.2 — https://www.rfc-editor.org/rfc/rfc5246#section-7.2
///
/// struct {
///     AlertLevel level;
///     AlertDescription description;
/// } Alert;
/// ```
///
/// RFC 9846, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc9846#section-5.1>:
/// "a record with an Alert type MUST contain exactly one message". A
/// plaintext Alert record is therefore 2 bytes long; a longer one carries a
/// protected alert (TLS 1.2 and earlier, RFC 5246, Section 6.2.3 —
/// <https://www.rfc-editor.org/rfc/rfc5246#section-6.2.3>).
fn dissect_alert_record<'pkt>(payload: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    match payload.len() {
        ALERT_SIZE => {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_ALERT_LEVEL],
                FieldValue::U8(payload[0]),
                offset..offset + 1,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_ALERT_DESCRIPTION],
                FieldValue::U8(payload[1]),
                offset + 1..offset + 2,
            );
        }
        len if len > ALERT_SIZE => {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_ENCRYPTED_ALERT],
                FieldValue::Bytes(payload),
                offset..offset + len,
            );
        }
        _ => {}
    }
}

/// TLS record layer dissector.
pub struct TlsDissector;

/// Specification references for the TLS dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 9846",
        "The Transport Layer Security (TLS) Protocol Version 1.3",
        "https://www.rfc-editor.org/rfc/rfc9846",
    ),
    SpecReference::new(
        "RFC 5246",
        "The Transport Layer Security (TLS) Protocol Version 1.2",
        "https://www.rfc-editor.org/rfc/rfc5246",
    ),
    SpecReference::new(
        "RFC 4680",
        "TLS Handshake Message for Supplemental Data",
        "https://www.rfc-editor.org/rfc/rfc4680",
    ),
    SpecReference::new(
        "RFC 6066",
        "Transport Layer Security (TLS) Extensions: Extension Definitions",
        "https://www.rfc-editor.org/rfc/rfc6066",
    ),
    SpecReference::new(
        "RFC 6520",
        "Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS) Heartbeat Extension",
        "https://www.rfc-editor.org/rfc/rfc6520",
    ),
    SpecReference::new(
        "RFC 7301",
        "Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension",
        "https://www.rfc-editor.org/rfc/rfc7301",
    ),
    SpecReference::new(
        "RFC 7366",
        "Encrypt-then-MAC for Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)",
        "https://www.rfc-editor.org/rfc/rfc7366",
    ),
    SpecReference::new(
        "RFC 7905",
        "ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)",
        "https://www.rfc-editor.org/rfc/rfc7905",
    ),
    SpecReference::new(
        "RFC 8449",
        "Record Size Limit Extension for TLS",
        "https://www.rfc-editor.org/rfc/rfc8449",
    ),
    SpecReference::new(
        "RFC 8879",
        "TLS Certificate Compression",
        "https://www.rfc-editor.org/rfc/rfc8879",
    ),
];

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
        // RFC 9846, Section 5.1 — https://www.rfc-editor.org/rfc/rfc9846#section-5.1
        //
        // struct {
        //     ContentType type;
        //     ProtocolVersion legacy_record_version;
        //     uint16 length;
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

        // Validate the header before emitting a layer so that non-TLS
        // payloads are not reported as TLS.
        if !matches!(ct, CONTENT_TYPE_CHANGE_CIPHER_SPEC..=CONTENT_TYPE_HEARTBEAT) {
            return Err(PacketError::InvalidFieldValue {
                field: "content_type",
                value: u32::from(ct),
            });
        }
        if data[1] != TLS_MAJOR_VERSION {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }
        if length as usize > MAX_RECORD_LENGTH {
            return Err(PacketError::InvalidFieldValue {
                field: "length",
                value: u32::from(length),
            });
        }

        let record_len = RECORD_HEADER_SIZE + length as usize;
        if data.len() < record_len {
            return Err(PacketError::Truncated {
                expected: record_len,
                actual: data.len(),
            });
        }

        buf.begin_layer(
            self.short_name(),
            None,
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

        let label = match ct {
            CONTENT_TYPE_HANDSHAKE => {
                dissect_handshake_record(payload, payload_offset, version, buf)
            }
            CONTENT_TYPE_ALERT => {
                dissect_alert_record(payload, payload_offset, buf);
                record_version_label(version)
            }
            _ => record_version_label(version),
        };
        if let Some(layer) = buf.last_layer_mut() {
            layer.display_name = label;
        }

        buf.end_layer();

        Ok(DissectResult::new(record_len, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 9846 / RFC 5246 (TLS) Coverage
    //!
    //! | RFC Section   | Description                         | Test                                          |
    //! |---------------|-------------------------------------|-----------------------------------------------|
    //! | 5246 §6.2.1   | Record header format                | parse_tls_handshake_record                    |
    //! | 9846 §5.1     | Unknown content type rejected       | parse_tls_unknown_content_type                |
    //! | 9846 §5.1     | Non-TLS payload rejected            | parse_tls_rejects_non_tls_payload             |
    //! | 5246 §6.2.1   | Major version must be 3             | parse_tls_rejects_bad_major_version           |
    //! | 5246 §6.2.3   | Record length limit (2^14 + 2048)   | parse_tls_record_length_limit                 |
    //! | 5246 §7.4     | Handshake header                    | parse_tls_handshake_record                    |
    //! | 9846 §5.1     | Coalesced handshake messages        | parse_tls_coalesced_handshake_messages        |
    //! | 9846 §5.1     | Handshake message fragmented        | parse_tls_handshake_message_fragment          |
    //! | 9846 §5.1     | Fragmented ClientHello not decoded  | parse_tls_client_hello_fragment               |
    //! | 5246 §6.2.3   | Encrypted handshake message         | parse_tls_encrypted_handshake_record          |
    //! | 9846 §5.1     | Partial trailing handshake header   | parse_tls_handshake_trailing_partial_header   |
    //! | 5288 §3       | Encrypted Finished, zero nonce      | parse_tls_encrypted_finished_with_zero_nonce  |
    //! | 9846 §5.1     | Fragment length plausibility limit  | parse_tls_fragment_length_limit               |
    //! | 9846 §5.1     | Zero-length handshake record        | parse_tls_empty_handshake_record              |
    //! | 5246 §7.2     | Alert protocol                      | parse_tls_alert_record                        |
    //! | 5246 §6.2.3   | Encrypted alert                     | parse_tls_encrypted_alert                     |
    //! | 5246 §7.1     | ChangeCipherSpec                    | parse_tls_change_cipher_spec                  |
    //! | 5246 §6.2.1   | Application data                    | parse_tls_application_data                    |
    //! | 5246 §6.2.1   | Truncated record                    | parse_tls_truncated_header                    |
    //! | 5246 §6.2.1   | Truncated payload                   | parse_tls_truncated_payload                   |
    //! | 5246 §6.2.1   | Version names                       | parse_tls_version_names                       |
    //! | 5246 §7.4     | Handshake type names                | parse_tls_handshake_type_names                |
    //! | 6066 §8       | CertificateStatus handshake type    | parse_tls_handshake_type_names                |
    //! | 5246 §7.2     | Alert description names             | parse_tls_alert_description_names             |
    //! | 9846 §5.1     | legacy_record_version ignored       | parse_tls13_record                            |
    //! | 5246 §6.2.1   | Pre-TLS 1.2 record version label    | parse_tls10_record_label                      |
    //! | 5246 §7.4.1.2 | ClientHello                         | parse_client_hello_basic                      |
    //! | 5246 §7.4.1.2 | ClientHello extensions              | parse_client_hello_with_extensions            |
    //! | 9846 §4.3.1   | supported_versions (ClientHello)    | parse_client_hello_with_supported_versions    |
    //! | 9846 §4.3.1   | ClientHello label w/o extension     | parse_client_hello_label_from_legacy_version  |
    //! | 5246 §7.4.1.3 | ServerHello                         | parse_server_hello_basic                      |
    //! | 9846 §4.3.1   | supported_versions (ServerHello)    | parse_server_hello_with_extensions            |
    //! | 9846 §4.3.1   | Malformed selected_version          | parse_server_hello_malformed_supported_versions |
    //! | 9846 §4.3.1   | Malformed extensions block          | parse_server_hello_malformed_extensions_block |
    //! | 9846 §4.2.3   | HelloRetryRequest random            | parse_hello_retry_request                     |
    //! | 5246 §7.4.1.4 | Extension format                    | parse_client_hello_with_extensions            |
    //! | 6066 §3       | SNI extension                       | parse_client_hello_with_extensions            |
    //! | 5246 §7.4.1.2 | ClientHello truncated               | parse_client_hello_truncated_body             |
    //! | 5246 §7.4.1.3 | ServerHello truncated               | parse_server_hello_truncated_body             |
    //! | 9846 §4.3     | TLS 1.3 ExtensionType               | parse_tls_extension_type_names                |
    //! | 6520 §3       | Heartbeat ContentType               | parse_tls_heartbeat_content_type              |
    //! | 7366 §2       | encrypt_then_mac (22)               | parse_tls_extension_type_names                |
    //! | 8449 §5       | record_size_limit (28)              | parse_tls_extension_type_names                |
    //! | 8879 §5       | Compressed Certificate              | parse_tls_handshake_type_names                |
    //! | 8879 §7.1     | compress_certificate                | parse_tls_extension_type_names                |

    use super::*;
    use core::ops::Range;
    use packet_dissector_core::field::Field;

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

    /// Build a complete handshake message: header + body.
    fn build_handshake(ht: u8, body: &[u8]) -> Vec<u8> {
        let mut hs = build_handshake_header(ht, body.len() as u32);
        hs.extend_from_slice(body);
        hs
    }

    /// Field ranges of the handshake message objects in the TLS layer, in order.
    fn handshake_objects(buf: &DissectBuffer<'_>) -> Vec<Range<u32>> {
        let layer = buf.layer_by_name("TLS").unwrap();
        let arr = buf.field_by_name(layer, "handshake_messages").unwrap();
        let range = arr.value.as_container_range().unwrap().clone();
        let mut out = Vec::new();
        let mut i = range.start;
        while i < range.end {
            let obj = buf.fields()[i as usize]
                .value
                .as_container_range()
                .unwrap()
                .clone();
            // The object's field index is the element immediately before its children.
            out.push(i..obj.end);
            i = obj.end;
        }
        out
    }

    /// Children of the handshake object whose element index range is `obj`.
    fn children<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, obj: &Range<u32>) -> &'a [Field<'pkt>] {
        let range = buf.fields()[obj.start as usize]
            .value
            .as_container_range()
            .unwrap()
            .clone();
        buf.nested_fields(&range)
    }

    /// First field named `name` among the children of the handshake object `obj`.
    fn child<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        obj: &Range<u32>,
        name: &str,
    ) -> Option<&'a Field<'pkt>> {
        children(buf, obj).iter().find(|f| f.name() == name)
    }

    /// First (and usually only) handshake object in the record.
    fn first_handshake(buf: &DissectBuffer<'_>) -> Range<u32> {
        handshake_objects(buf).into_iter().next().unwrap()
    }

    /// The layer's display name (version-qualified label).
    fn tls_label(buf: &DissectBuffer<'_>) -> Option<&'static str> {
        buf.layer_by_name("TLS").unwrap().display_name
    }

    /// Extension objects (field index ranges) inside the handshake object `obj`.
    fn extension_objects(buf: &DissectBuffer<'_>, obj: &Range<u32>) -> Vec<Range<u32>> {
        let exts_idx = (obj.start..obj.end)
            .find(|&i| buf.fields()[i as usize].name() == "extensions")
            .unwrap();
        let range = buf.fields()[exts_idx as usize]
            .value
            .as_container_range()
            .unwrap()
            .clone();
        let mut out = Vec::new();
        let mut i = range.start;
        while i < range.end {
            let r = buf.fields()[i as usize]
                .value
                .as_container_range()
                .unwrap()
                .clone();
            out.push(i..r.end);
            i = r.end;
        }
        out
    }

    #[test]
    fn parse_tls_handshake_record() {
        // ClientHello handshake record over TLS 1.0 record version
        let hs = build_handshake(1, &[0u8; 512]); // ClientHello, dummy body
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0301, &hs);

        let mut buf = DissectBuffer::new();
        let result = TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, RECORD_HEADER_SIZE + hs.len());

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
            FieldValue::U16(hs.len() as u16)
        );

        let objs = handshake_objects(&buf);
        assert_eq!(objs.len(), 1);
        let hs_obj = &objs[0];
        assert_eq!(
            child(&buf, hs_obj, "type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_container_display_name(hs_obj.start),
            Some("Client Hello")
        );
        assert_eq!(
            child(&buf, hs_obj, "length").unwrap().value,
            FieldValue::U32(512)
        );
        assert_eq!(buf.fields()[hs_obj.start as usize].range, 5..5 + 4 + 512);
        assert!(child(&buf, hs_obj, "fragment_length").is_none());
    }

    #[test]
    fn parse_tls_coalesced_handshake_messages() {
        // TLS 1.2 server flight: ServerHello, Certificate (empty list) and
        // ServerHelloDone in one record.
        // RFC 5246, Section 6.2.1 — https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x02, 0x00, 0x00, 0x26, 0x03, 0x03]);
        payload.extend_from_slice(&[0x11; 32]);
        payload.extend_from_slice(&[0x00, 0xc0, 0x2f, 0x00]);
        payload.extend_from_slice(&[0x0b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]);
        payload.extend_from_slice(&[0x0e, 0x00, 0x00, 0x00]);
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &payload);
        assert_eq!(&data[..5], &[0x16, 0x03, 0x03, 0x00, 0x35]);

        let mut buf = DissectBuffer::new();
        let result = TlsDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());

        let objs = handshake_objects(&buf);
        assert_eq!(objs.len(), 3);

        // ServerHello
        assert_eq!(
            child(&buf, &objs[0], "type").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            child(&buf, &objs[0], "length").unwrap().value,
            FieldValue::U32(0x26)
        );
        assert_eq!(
            child(&buf, &objs[0], "cipher_suite").unwrap().value,
            FieldValue::U16(0xc02f)
        );
        assert_eq!(
            child(&buf, &objs[0], "random").unwrap().value,
            FieldValue::Bytes(&[0x11; 32])
        );
        assert_eq!(buf.fields()[objs[0].start as usize].range, 5..5 + 42);

        // Certificate
        assert_eq!(
            child(&buf, &objs[1], "type").unwrap().value,
            FieldValue::U8(11)
        );
        assert_eq!(
            buf.resolve_container_display_name(objs[1].start),
            Some("Certificate")
        );
        assert_eq!(
            child(&buf, &objs[1], "length").unwrap().value,
            FieldValue::U32(3)
        );
        assert_eq!(buf.fields()[objs[1].start as usize].range, 47..54);

        // ServerHelloDone
        assert_eq!(
            child(&buf, &objs[2], "type").unwrap().value,
            FieldValue::U8(14)
        );
        assert_eq!(
            buf.resolve_container_display_name(objs[2].start),
            Some("Server Hello Done")
        );
        assert_eq!(buf.fields()[objs[2].start as usize].range, 54..58);

        // Not reported as opaque.
        let layer = buf.layer_by_name("TLS").unwrap();
        assert!(buf.field_by_name(layer, "opaque_handshake").is_none());
        // TLS 1.2 ServerHello without supported_versions → label from legacy_version.
        assert_eq!(tls_label(&buf), Some("TLSv1.2"));
    }

    #[test]
    fn parse_tls_handshake_message_fragment() {
        // ServerHelloDone followed by the first 10 bytes of a 5000-byte
        // Certificate message that continues in the next record.
        // RFC 9846, Section 5.1 — https://www.rfc-editor.org/rfc/rfc9846#section-5.1
        let mut payload = build_handshake(14, &[]);
        payload.extend_from_slice(&build_handshake_header(11, 5000));
        payload.extend_from_slice(&[0x00; 10]);
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &payload);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let objs = handshake_objects(&buf);
        assert_eq!(objs.len(), 2);
        assert!(child(&buf, &objs[0], "fragment_length").is_none());
        assert_eq!(
            child(&buf, &objs[1], "type").unwrap().value,
            FieldValue::U8(11)
        );
        assert_eq!(
            child(&buf, &objs[1], "length").unwrap().value,
            FieldValue::U32(5000)
        );
        assert_eq!(
            child(&buf, &objs[1], "fragment_length").unwrap().value,
            FieldValue::U32(10)
        );
        // The object covers only the bytes present in this record.
        assert_eq!(buf.fields()[objs[1].start as usize].range, 9..9 + 4 + 10);
    }

    #[test]
    fn parse_tls_client_hello_fragment() {
        // A ClientHello whose declared length exceeds the record: the body
        // is not decoded from a partial message.
        let body = build_client_hello_body(0x0303, &[], &[0x1301], &[0x00], None);
        let mut hs = build_handshake_header(HANDSHAKE_TYPE_CLIENT_HELLO, 20_000);
        hs.extend_from_slice(&body);
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0301, &hs);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_handshake(&buf);
        assert_eq!(
            child(&buf, &obj, "fragment_length").unwrap().value,
            FieldValue::U32(body.len() as u32)
        );
        assert!(child(&buf, &obj, "version").is_none());
        assert!(child(&buf, &obj, "random").is_none());
        assert_eq!(tls_label(&buf), None);
    }

    #[test]
    fn parse_tls_encrypted_handshake_record() {
        // An encrypted Finished (TLS 1.2, after ChangeCipherSpec) whose first
        // byte is not a known handshake type.
        // RFC 5246, Section 6.2.3 — https://www.rfc-editor.org/rfc/rfc5246#section-6.2.3
        let payload = [0xab; 40];
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &payload);

        let mut buf = DissectBuffer::new();
        let result = TlsDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());

        let layer = buf.layer_by_name("TLS").unwrap();
        assert!(buf.field_by_name(layer, "handshake_messages").is_none());
        let opaque = buf.field_by_name(layer, "opaque_handshake").unwrap();
        assert_eq!(opaque.value, FieldValue::Bytes(&[0xab; 40]));
        assert_eq!(opaque.range, 5..45);
        assert_eq!(tls_label(&buf), None);
    }

    #[test]
    fn parse_tls_handshake_trailing_partial_header() {
        // ServerHello followed by the first 2 bytes of a Certificate header:
        // a message may be split at any byte (RFC 9846, Section 5.1), so the
        // complete ServerHello is decoded and the rest is reported as
        // continued handshake data.
        let body = build_server_hello_body(0x0303, &[], 0xc02f, 0x00, None);
        let mut payload = build_handshake(HANDSHAKE_TYPE_SERVER_HELLO, &body);
        let sh_len = payload.len();
        payload.extend_from_slice(&[0x0b, 0x00]);
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &payload);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let objs = handshake_objects(&buf);
        assert_eq!(objs.len(), 1);
        assert_eq!(
            child(&buf, &objs[0], "cipher_suite").unwrap().value,
            FieldValue::U16(0xc02f)
        );
        let layer = buf.layer_by_name("TLS").unwrap();
        let rest = buf.field_by_name(layer, "opaque_handshake").unwrap();
        assert_eq!(rest.value, FieldValue::Bytes(&[0x0b, 0x00]));
        assert_eq!(rest.range, 5 + sh_len..5 + sh_len + 2);
        assert_eq!(tls_label(&buf), Some("TLSv1.2"));

        // The trailing bytes must still start with a known handshake type.
        let mut payload = build_handshake(14, &[]);
        payload.extend_from_slice(&[0xab, 0x00]);
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &payload);
        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("TLS").unwrap();
        assert!(buf.field_by_name(layer, "handshake_messages").is_none());
        assert_eq!(
            buf.field_by_name(layer, "opaque_handshake").unwrap().value,
            FieldValue::Bytes(&payload)
        );
    }

    #[test]
    fn parse_tls_encrypted_finished_with_zero_nonce() {
        // TLS 1.2 AES-GCM Finished whose explicit nonce is sequence number 0:
        // the zero bytes look like two HelloRequest headers, followed by
        // ciphertext whose first byte happens to be a known type (Finished)
        // and whose 24-bit length is implausibly large for a fragment.
        // RFC 5288, Section 3 — https://www.rfc-editor.org/rfc/rfc5288#section-3
        let mut payload = vec![0x00; 8];
        payload.extend_from_slice(&[0x14, 0x9a, 0x3c, 0x7f]);
        payload.extend_from_slice(&[0x5e; 28]);
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &payload);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        assert!(buf.field_by_name(layer, "handshake_messages").is_none());
        assert_eq!(
            buf.field_by_name(layer, "opaque_handshake").unwrap().value,
            FieldValue::Bytes(&payload)
        );
    }

    #[test]
    fn parse_tls_fragment_length_limit() {
        // A fragmented message up to MAX_FRAGMENTED_HANDSHAKE_LENGTH is
        // accepted; a longer declared length is treated as ciphertext.
        for (len, decoded) in [
            (MAX_FRAGMENTED_HANDSHAKE_LENGTH as u32, true),
            (MAX_FRAGMENTED_HANDSHAKE_LENGTH as u32 + 1, false),
        ] {
            let mut payload = build_handshake_header(11, len);
            payload.extend_from_slice(&[0x00; 16]);
            let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &payload);
            let mut buf = DissectBuffer::new();
            TlsDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = buf.layer_by_name("TLS").unwrap();
            assert_eq!(
                buf.field_by_name(layer, "handshake_messages").is_some(),
                decoded,
                "declared length {len}"
            );
        }
    }

    #[test]
    fn parse_tls_empty_handshake_record() {
        // Zero-length Handshake fragments are forbidden (RFC 9846, Section
        // 5.1); nothing beyond the record header is reported.
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &[]);

        let mut buf = DissectBuffer::new();
        let result = TlsDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, RECORD_HEADER_SIZE);

        let layer = buf.layer_by_name("TLS").unwrap();
        assert!(buf.field_by_name(layer, "handshake_messages").is_none());
        assert!(buf.field_by_name(layer, "opaque_handshake").is_none());
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
        assert!(buf.field_by_name(layer, "encrypted_alert").is_none());
        assert!(buf.field_by_name(layer, "handshake_messages").is_none());
    }

    #[test]
    fn parse_tls_encrypted_alert() {
        // TLS 1.2 alert after ChangeCipherSpec: 26 bytes of ciphertext.
        // RFC 5246, Section 6.2.3 — https://www.rfc-editor.org/rfc/rfc5246#section-6.2.3
        let data = build_tls_record(CONTENT_TYPE_ALERT, 0x0303, &[0xab; 26]);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        assert!(buf.field_by_name(layer, "alert_level").is_none());
        assert!(buf.field_by_name(layer, "alert_description").is_none());
        let enc = buf.field_by_name(layer, "encrypted_alert").unwrap();
        assert_eq!(enc.value, FieldValue::Bytes(&[0xab; 26]));
        assert_eq!(enc.range, 5..31);
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
        assert!(buf.field_by_name(layer, "handshake_messages").is_none());
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
        assert!(buf.field_by_name(layer, "handshake_messages").is_none());
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
        let err = TlsDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidFieldValue {
                field: "content_type",
                value: 99
            }
        );
        assert!(buf.layers().is_empty());
        assert_eq!(content_type_name(99), "Unknown");
    }

    #[test]
    fn parse_tls_rejects_non_tls_payload() {
        // Arbitrary bytes on TCP 443 are not a TLS record.
        let data = [0x00, 0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];

        let mut buf = DissectBuffer::new();
        let err = TlsDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidFieldValue {
                field: "content_type",
                value: 0
            }
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn parse_tls_rejects_bad_major_version() {
        let data = build_tls_record(CONTENT_TYPE_APPLICATION_DATA, 0x0203, &[0x00]);

        let mut buf = DissectBuffer::new();
        let err = TlsDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidFieldValue {
                field: "version",
                value: 0x0203
            }
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn parse_tls_record_length_limit() {
        // RFC 5246, Section 6.2.3 — https://www.rfc-editor.org/rfc/rfc5246#section-6.2.3
        // "The length MUST NOT exceed 2^14 + 2048."
        let max = (1usize << 14) + 2048;
        let data = build_tls_record(CONTENT_TYPE_APPLICATION_DATA, 0x0303, &vec![0u8; max]);
        let mut buf = DissectBuffer::new();
        let result = TlsDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, RECORD_HEADER_SIZE + max);

        let data = build_tls_record(CONTENT_TYPE_APPLICATION_DATA, 0x0303, &vec![0u8; max + 1]);
        let mut buf = DissectBuffer::new();
        let err = TlsDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidFieldValue {
                field: "length",
                value: (max + 1) as u32
            }
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn parse_tls_heartbeat_content_type() {
        // RFC 6520, Section 3 — https://www.rfc-editor.org/rfc/rfc6520#section-3
        // ContentType heartbeat(24); minimal HeartbeatMessage body is irrelevant
        // here — we only verify that ContentType 24 is recognised by name.
        let data = build_tls_record(CONTENT_TYPE_HEARTBEAT, 0x0303, &[0u8; 16]);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "content_type_name"),
            Some("Heartbeat")
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
            // RFC 6066 §5, §8 — https://www.rfc-editor.org/rfc/rfc6066#section-8
            (21, "Certificate URL"),
            (22, "Certificate Status"),
            // RFC 4680 §2 — https://www.rfc-editor.org/rfc/rfc4680#section-2
            (23, "Supplemental Data"),
            (24, "Key Update"),
            // RFC 8879 §5 — https://www.rfc-editor.org/rfc/rfc8879#section-5
            (25, "Compressed Certificate"),
        ] {
            let hs_payload = build_handshake_header(ht, 0);
            let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &hs_payload);

            let mut buf = DissectBuffer::new();
            TlsDissector.dissect(&data, &mut buf, 0).unwrap();

            let obj = first_handshake(&buf);
            assert_eq!(
                buf.resolve_container_display_name(obj.start),
                Some(expected_name),
                "handshake type {ht} should map to {expected_name}"
            );
            let range = buf.fields()[obj.start as usize]
                .value
                .as_container_range()
                .unwrap()
                .clone();
            assert_eq!(
                buf.resolve_nested_display_name(&range, "type_name"),
                Some(expected_name)
            );
        }
        // message_hash is only used in the transcript hash, never on the wire
        // (RFC 9846, Section 4.1 — https://www.rfc-editor.org/rfc/rfc9846#section-4.1).
        assert_eq!(handshake_type_name(254), "Message Hash");
        assert_eq!(handshake_type_name(99), "Unknown");
        for ht in [99u8, 254] {
            let data = build_tls_record(
                CONTENT_TYPE_HANDSHAKE,
                0x0303,
                &build_handshake_header(ht, 0),
            );
            let mut buf = DissectBuffer::new();
            TlsDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = buf.layer_by_name("TLS").unwrap();
            assert!(buf.field_by_name(layer, "handshake_messages").is_none());
            assert!(buf.field_by_name(layer, "opaque_handshake").is_some());
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
        // TLS 1.3 records use legacy_record_version 0x0303, which "MUST be
        // ignored for all purposes", so the layer label carries no version.
        // RFC 9846, Section 5.1 — https://www.rfc-editor.org/rfc/rfc9846#section-5.1
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
        assert_eq!(tls_label(&buf), None);
        assert_eq!(layer.protocol_name(), "TLS");
    }

    #[test]
    fn parse_tls10_record_label() {
        // Only an initial ClientHello from a TLS 1.3 client may use a record
        // version other than 0x0303 (RFC 9846, Section 5.1), so a non-handshake
        // record with 0x0300..=0x0302 identifies the negotiated version.
        for (ver, label) in [
            (0x0300u16, Some("SSL 3.0")),
            (0x0301, Some("TLSv1.0")),
            (0x0302, Some("TLSv1.1")),
            (0x0304, None),
        ] {
            let data = build_tls_record(CONTENT_TYPE_ALERT, ver, &[1, 0]);
            let mut buf = DissectBuffer::new();
            TlsDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(tls_label(&buf), label, "record version 0x{ver:04x}");
        }
        // Plaintext handshake messages other than Hellos are never sent by
        // TLS 1.3 in a non-0x0303 record, so the record version applies.
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0301, &build_handshake(14, &[]));
        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(tls_label(&buf), Some("TLSv1.0"));
        // Opaque handshake data may continue a TLS 1.3 initial ClientHello
        // (record version 0x0301), so it gets no version.
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0301, &[0xab; 8]);
        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(tls_label(&buf), None);
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
        // Handshake record with payload too short for a handshake header
        // (< 4 bytes): reported as opaque data, not as a handshake message.
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &[0x01, 0x00]);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "content_type_name"),
            Some("Handshake")
        );
        assert!(buf.field_by_name(layer, "handshake_messages").is_none());
        assert_eq!(
            buf.field_by_name(layer, "opaque_handshake").unwrap().value,
            FieldValue::Bytes(&[0x01, 0x00])
        );
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
        assert!(buf.field_by_name(layer, "encrypted_alert").is_none());
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
        build_server_hello_body_with_random(
            version,
            &[0xcd; RANDOM_SIZE],
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        )
    }

    /// Build a ServerHello body with an explicit Random.
    fn build_server_hello_body_with_random(
        version: u16,
        random: &[u8; RANDOM_SIZE],
        session_id: &[u8],
        cipher_suite: u16,
        compression_method: u8,
        extensions: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&version.to_be_bytes());
        buf.extend_from_slice(random);
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
        let hs = build_handshake(HANDSHAKE_TYPE_CLIENT_HELLO, body);
        build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0301, &hs)
    }

    /// Wrap a ServerHello body in a handshake header + TLS record.
    fn wrap_server_hello(body: &[u8]) -> Vec<u8> {
        let hs = build_handshake(HANDSHAKE_TYPE_SERVER_HELLO, body);
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

        let obj = first_handshake(&buf);
        let range = buf.fields()[obj.start as usize]
            .value
            .as_container_range()
            .unwrap()
            .clone();
        assert_eq!(
            child(&buf, &obj, "version").unwrap().value,
            FieldValue::U16(0x0303)
        );
        assert_eq!(
            buf.resolve_nested_display_name(&range, "version_name"),
            Some("TLS 1.2 / TLS 1.3 legacy_record_version")
        );
        assert_eq!(
            child(&buf, &obj, "random").unwrap().value,
            FieldValue::Bytes(&[0xab; RANDOM_SIZE])
        );
        assert_eq!(
            child(&buf, &obj, "session_id").unwrap().value,
            FieldValue::Bytes(&[0x01; 32])
        );

        // cipher_suites is an Array of U16
        let cs_field = child(&buf, &obj, "cipher_suites").unwrap();
        let cs_range = cs_field.value.as_container_range().unwrap();
        let suites = buf.nested_fields(cs_range);
        assert_eq!(suites.len(), 2);
        assert_eq!(suites[0].value, FieldValue::U16(0xc02f));
        assert_eq!(suites[1].value, FieldValue::U16(0x009e));

        assert_eq!(
            child(&buf, &obj, "compression_methods").unwrap().value,
            FieldValue::Bytes(&[0x00])
        );

        // No extensions field
        assert!(child(&buf, &obj, "extensions").is_none());
        // Without supported_versions the label follows legacy_version.
        assert_eq!(tls_label(&buf), Some("TLSv1.2"));
    }

    #[test]
    fn parse_client_hello_label_from_legacy_version() {
        // A TLS 1.2 ClientHello in a 0x0301 record is labelled by the body's
        // legacy_version (0x0303), not the record version.
        let sni = build_sni_extension("example.com");
        let body = build_client_hello_body(0x0303, &[], &[0xc02f], &[0x00], Some(&sni));
        let data = wrap_client_hello(&body);
        assert_eq!(&data[1..3], &[0x03, 0x01]);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(tls_label(&buf), Some("TLSv1.2"));
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

        let obj = first_handshake(&buf);
        let exts = extension_objects(&buf, &obj);
        assert_eq!(exts.len(), 1);
        let ext_children = children(&buf, &exts[0]);
        assert_eq!(ext_children[0].value, FieldValue::U16(0)); // type
        assert_eq!(
            buf.resolve_container_display_name(exts[0].start),
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
        // RFC 9846, Section 4.3.1 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.1
        // In ClientHello: ProtocolVersion versions<2..254>.
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
        assert_eq!(&data[1..3], &[0x03, 0x01]);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_handshake(&buf);
        let exts = extension_objects(&buf, &obj);
        assert_eq!(exts.len(), 1);
        assert_eq!(
            buf.resolve_container_display_name(exts[0].start),
            Some("supported_versions")
        );
        let versions = child(&buf, &exts[0], "versions").unwrap();
        let v_range = versions.value.as_container_range().unwrap();
        let v = buf.nested_fields(v_range);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].value, FieldValue::U16(0x0304));
        assert_eq!(v[1].value, FieldValue::U16(0x0303));
        assert_eq!(v[0].range, 5 + 4 + 43 + 4 + 1..5 + 4 + 43 + 4 + 3);
        assert_eq!(
            v[0].descriptor.display_fn.unwrap()(&v[0].value, v),
            Some("TLS 1.3")
        );
        assert_eq!(
            v[1].descriptor.display_fn.unwrap()(&v[1].value, v),
            Some("TLS 1.2")
        );
        assert!(child(&buf, &exts[0], "selected_version").is_none());

        // The client offers a list; nothing is negotiated yet, so the label
        // is neither TLSv1.0 (record) nor TLSv1.2 (legacy_version).
        assert_eq!(tls_label(&buf), None);
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

        let obj = first_handshake(&buf);
        let range = buf.fields()[obj.start as usize]
            .value
            .as_container_range()
            .unwrap()
            .clone();
        assert_eq!(
            child(&buf, &obj, "type").unwrap().value,
            FieldValue::U8(HANDSHAKE_TYPE_SERVER_HELLO)
        );
        assert_eq!(
            child(&buf, &obj, "version").unwrap().value,
            FieldValue::U16(0x0303)
        );
        assert_eq!(
            child(&buf, &obj, "random").unwrap().value,
            FieldValue::Bytes(&[0xcd; RANDOM_SIZE])
        );
        assert_eq!(
            child(&buf, &obj, "session_id").unwrap().value,
            FieldValue::Bytes(&[0x02; 32])
        );
        assert_eq!(
            child(&buf, &obj, "cipher_suite").unwrap().value,
            FieldValue::U16(0xc02f)
        );
        assert_eq!(
            buf.resolve_nested_display_name(&range, "cipher_suite_name"),
            Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        );
        assert_eq!(
            child(&buf, &obj, "compression_method").unwrap().value,
            FieldValue::U8(0)
        );
        assert!(child(&buf, &obj, "extensions").is_none());
        assert!(child(&buf, &obj, "hello_retry_request").is_none());
        // ClientHello-only fields should not be present
        assert!(child(&buf, &obj, "cipher_suites").is_none());
        assert!(child(&buf, &obj, "compression_methods").is_none());
        assert_eq!(
            buf.resolve_container_display_name(obj.start),
            Some("Server Hello")
        );
        assert_eq!(tls_label(&buf), Some("TLSv1.2"));
    }

    #[test]
    fn parse_server_hello_with_extensions() {
        // TLS 1.3 ServerHello: supported_versions carries selected_version.
        // RFC 9846, Section 4.3.1 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.1
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

        let obj = first_handshake(&buf);
        assert_eq!(
            child(&buf, &obj, "cipher_suite").unwrap().value,
            FieldValue::U16(0x1301)
        );

        let exts = extension_objects(&buf, &obj);
        assert_eq!(exts.len(), 1);
        let ext_children = children(&buf, &exts[0]);
        assert_eq!(ext_children[0].value, FieldValue::U16(43));
        let selected = child(&buf, &exts[0], "selected_version").unwrap();
        assert_eq!(selected.value, FieldValue::U16(0x0304));
        assert_eq!(
            selected.descriptor.display_fn.unwrap()(&selected.value, ext_children),
            Some("TLS 1.3")
        );
        assert!(child(&buf, &exts[0], "versions").is_none());

        // The layer is labelled from selected_version, not the 0x0303 record.
        assert_eq!(tls_label(&buf), Some("TLSv1.3"));
    }

    #[test]
    fn parse_server_hello_malformed_supported_versions() {
        // supported_versions in a ServerHello must hold exactly one version.
        let sv_ext = build_extension(43, &[0x03]);
        let body = build_server_hello_body(0x0303, &[], 0x1301, 0x00, Some(&sv_ext));
        let data = wrap_server_hello(&body);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_handshake(&buf);
        let exts = extension_objects(&buf, &obj);
        assert!(child(&buf, &exts[0], "selected_version").is_none());
        // The extension is present, so legacy_version must not be used.
        assert_eq!(tls_label(&buf), None);
    }

    #[test]
    fn parse_server_hello_malformed_extensions_block() {
        // An extensions block that overruns the body, or an extension that
        // overruns the block, may hide supported_versions, so legacy_version
        // is not used for the label.
        let mut body = build_server_hello_body(0x0303, &[], 0x1301, 0x00, None);
        body.extend_from_slice(&[0x00, 0x10, 0x00, 0x2b]);
        let data = wrap_server_hello(&body);
        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(child(&buf, &first_handshake(&buf), "extensions").is_none());
        assert_eq!(tls_label(&buf), None);

        let bad_ext = [0x00, 0x0a, 0x00, 0x20, 0x00];
        let body = build_server_hello_body(0x0303, &[], 0x1301, 0x00, Some(&bad_ext));
        let data = wrap_server_hello(&body);
        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(child(&buf, &first_handshake(&buf), "extensions").is_some());
        assert_eq!(tls_label(&buf), None);

        // An empty extensions block is well-formed.
        let body = build_server_hello_body(0x0303, &[], 0xc02f, 0x00, Some(&[]));
        let data = wrap_server_hello(&body);
        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(tls_label(&buf), Some("TLSv1.2"));
    }

    #[test]
    fn parse_hello_retry_request() {
        // RFC 9846, Section 4.2.3 — https://www.rfc-editor.org/rfc/rfc9846#section-4.2.3
        let hrr_random: [u8; RANDOM_SIZE] = [
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
            0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
            0xc8, 0xa8, 0x33, 0x9c,
        ];
        let sv_ext = build_extension(43, &0x0304u16.to_be_bytes());
        let body = build_server_hello_body_with_random(
            0x0303,
            &hrr_random,
            &[],
            0x1301,
            0x00,
            Some(&sv_ext),
        );
        let data = wrap_server_hello(&body);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_handshake(&buf);
        let hrr = child(&buf, &obj, "hello_retry_request").unwrap();
        assert_eq!(hrr.value, FieldValue::U8(1));
        assert_eq!(hrr.range, 5 + 4 + 2..5 + 4 + 2 + RANDOM_SIZE);
        assert_eq!(
            buf.resolve_container_display_name(obj.start),
            Some("Hello Retry Request")
        );
        assert_eq!(tls_label(&buf), Some("TLSv1.3"));
    }

    #[test]
    fn parse_client_hello_truncated_body() {
        // A complete ClientHello message whose body is too short to contain
        // even the minimum fields: type/length are reported, body is not.
        let short_body = vec![0x03, 0x03]; // only 2 bytes (version), no random
        let hs = build_handshake(HANDSHAKE_TYPE_CLIENT_HELLO, &short_body);
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0301, &hs);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_handshake(&buf);
        assert_eq!(
            child(&buf, &obj, "type").unwrap().value,
            FieldValue::U8(HANDSHAKE_TYPE_CLIENT_HELLO)
        );
        // Body fields should not be present due to truncation
        assert!(child(&buf, &obj, "version").is_none());
        assert!(child(&buf, &obj, "random").is_none());
        assert_eq!(tls_label(&buf), None);
    }

    #[test]
    fn parse_server_hello_truncated_body() {
        // ServerHello with body truncated after session_id.
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // version
        body.extend_from_slice(&[0x00; RANDOM_SIZE]); // random
        body.push(0); // session_id_len=0
        // Missing cipher_suite and compression_method

        let hs = build_handshake(HANDSHAKE_TYPE_SERVER_HELLO, &body);
        let data = build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &hs);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_handshake(&buf);
        // Basic fields should be present
        assert_eq!(
            child(&buf, &obj, "version").unwrap().value,
            FieldValue::U16(0x0303)
        );
        assert_eq!(
            child(&buf, &obj, "session_id").unwrap().value,
            FieldValue::Bytes(&[])
        );
        // Truncated fields should not be present
        assert!(child(&buf, &obj, "cipher_suite").is_none());
        assert!(child(&buf, &obj, "compression_method").is_none());
    }

    #[test]
    fn parse_tls_extension_type_names() {
        for (ext_type, expected_name) in [
            (0u16, "server_name"),
            (10, "supported_groups"),
            (13, "signature_algorithms"),
            (16, "application_layer_protocol_negotiation"),
            // RFC 9846 §4.3 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3
            (19, "client_certificate_type"),
            (20, "server_certificate_type"),
            // RFC 7366 §2 — https://www.rfc-editor.org/rfc/rfc7366#section-2
            (22, "encrypt_then_mac"),
            // RFC 8879 §7.1 — https://www.rfc-editor.org/rfc/rfc8879#section-7.1
            (27, "compress_certificate"),
            // RFC 8449 §5 — https://www.rfc-editor.org/rfc/rfc8449#section-5
            (28, "record_size_limit"),
            (43, "supported_versions"),
            // RFC 9846 §4.3.5 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.5
            (48, "oid_filters"),
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

        let obj = first_handshake(&buf);
        let exts = extension_objects(&buf, &obj);
        assert_eq!(exts.len(), 2);

        // First: SNI
        let sni_children = children(&buf, &exts[0]);
        assert_eq!(sni_children[0].value, FieldValue::U16(0));
        let sni_name = child(&buf, &exts[0], "server_name").unwrap();
        assert_eq!(sni_name.value, FieldValue::Bytes(b"test.example.org"));

        // Second: supported_versions
        let sv_children = children(&buf, &exts[1]);
        assert_eq!(sv_children[0].value, FieldValue::U16(43));
    }

    #[test]
    fn parse_client_hello_malformed_supported_versions() {
        // An odd-length version list is not decoded but the extension stays.
        let sv_ext = build_extension(43, &[3, 0x03, 0x04, 0x03]);
        let body = build_client_hello_body(0x0303, &[], &[0x1301], &[0x00], Some(&sv_ext));
        let data = wrap_client_hello(&body);

        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_handshake(&buf);
        let exts = extension_objects(&buf, &obj);
        assert!(child(&buf, &exts[0], "versions").is_none());
        assert!(child(&buf, &exts[0], "data").is_some());
        assert_eq!(tls_label(&buf), None);
    }

    #[test]
    fn extension_container_resolves_to_extension_name() {
        // ClientHello with a single SNI extension so the container label
        // resolves to "server_name" instead of duplicating "Extension Type".
        let sni = build_sni_extension("test.example.org");
        let body = build_client_hello_body(0x0303, &[], &[0x1301], &[0x00], Some(&sni));
        let data = wrap_client_hello(&body);
        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(&data, &mut buf, 0).unwrap();

        let (idx, field) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "extension")
            .expect("extension container not found");
        assert!(matches!(field.value, FieldValue::Object(_)));
        assert_eq!(field.display_name(), "Extension");
        assert_eq!(
            buf.resolve_container_display_name(idx as u32),
            Some("server_name")
        );
    }

    #[test]
    fn references_and_layer() {
        let references = TlsDissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert!(references.iter().any(|r| r.id == "RFC 9846"));
        assert!(!references.iter().any(|r| r.id == "RFC 8446"));
        assert_eq!(TlsDissector.layer(), Some(ProtocolLayer::Application));
    }
}
