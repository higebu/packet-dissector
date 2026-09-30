//! TLS (Transport Layer Security) record layer dissector.
//!
//! Parses the TLS record layer header (5 bytes) and the plaintext messages
//! it carries: every handshake message in a Handshake record (see
//! `handshake.rs` for the decoded bodies and `extensions.rs` for the decoded
//! extensions), the Alert message, and the Heartbeat message.
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
//! TLS 1.3 fixes at 0x0303 (RFC 9846, Section 5.1 (<https://www.rfc-editor.org/rfc/rfc9846#section-5.1>)). It comes from the
//! ServerHello `supported_versions` extension or `legacy_version`, or from the
//! ClientHello `legacy_version` when the client does not offer
//! `supported_versions`.
//!
//! The crate also provides [`DtlsDissector`] for DTLS 1.0, 1.2 and 1.3
//! records over datagram transports. It shares the handshake body, alert and
//! heartbeat decoders with [`TlsDissector`].
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
//! - RFC 4346 (TLS 1.1, CertificateRequest without signature algorithms): <https://www.rfc-editor.org/rfc/rfc4346>
//! - RFC 5077 (TLS 1.2 NewSessionTicket; obsoleted by RFC 9846): <https://www.rfc-editor.org/rfc/rfc5077>
//! - RFC 8422 (ECC for TLS 1.2 and earlier; obsoleted by RFC 9846): <https://www.rfc-editor.org/rfc/rfc8422>
//! - RFC 8701 (GREASE): <https://www.rfc-editor.org/rfc/rfc8701>
//! - RFC 9000 (QUIC transport parameter encoding): <https://www.rfc-editor.org/rfc/rfc9000>
//! - RFC 9001 (quic_transport_parameters extension): <https://www.rfc-editor.org/rfc/rfc9001>
//! - RFC 9180 (HPKE identifiers): <https://www.rfc-editor.org/rfc/rfc9180>
//! - RFC 9345 (Delegated Credentials): <https://www.rfc-editor.org/rfc/rfc9345>
//! - RFC 9849 (TLS Encrypted Client Hello): <https://www.rfc-editor.org/rfc/rfc9849>
//! - RFC 9147 (DTLS 1.3, obsoletes RFC 6347): <https://www.rfc-editor.org/rfc/rfc9147>
//! - RFC 6347 (DTLS 1.2): <https://www.rfc-editor.org/rfc/rfc6347>
//! - RFC 4347 (DTLS 1.0): <https://www.rfc-editor.org/rfc/rfc4347>
//! - RFC 9146 (Connection Identifiers for DTLS 1.2): <https://www.rfc-editor.org/rfc/rfc9146>
//! - IANA TLS Parameters: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml>

#![deny(missing_docs)]

/// An optional field descriptor whose value is shown through a name lookup
/// function, e.g. `named_field!("group", "Group", U16, named_group_name)`.
macro_rules! named_field {
    ($name:expr, $display:expr, $ty:ident, $lookup:path) => {
        FieldDescriptor {
            name: $name,
            display_name: $display,
            field_type: FieldType::$ty,
            optional: true,
            children: None,
            display_fn: Some(|v, _siblings| match v {
                FieldValue::$ty(x) => Some($lookup(*x)),
                _ => None,
            }),
            format_fn: None,
        }
    };
}

mod dtls;
mod extensions;
mod handshake;
mod names;
mod reader;

pub use dtls::DtlsDissector;
use handshake::{HANDSHAKE_CHILD_FIELDS, dissect_handshake_record};
#[cfg(test)]
use handshake::{
    HANDSHAKE_TYPE_CLIENT_HELLO, HANDSHAKE_TYPE_SERVER_HELLO, HELLO_RETRY_REQUEST_RANDOM,
    RANDOM_SIZE,
};
use names::heartbeat_message_type_name;
#[cfg(test)]
use names::{cipher_suite_name, extension_type_name};

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

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
/// RFC 9146, Section 4 — <https://www.rfc-editor.org/rfc/rfc9146#section-4> (tls12_cid, DTLS only)
/// RFC 9147, Section 7 — <https://www.rfc-editor.org/rfc/rfc9147#section-7> (ACK, DTLS only)
fn content_type_name(ct: u8) -> &'static str {
    match ct {
        CONTENT_TYPE_CHANGE_CIPHER_SPEC => "Change Cipher Spec",
        CONTENT_TYPE_ALERT => "Alert",
        CONTENT_TYPE_HANDSHAKE => "Handshake",
        CONTENT_TYPE_APPLICATION_DATA => "Application Data",
        CONTENT_TYPE_HEARTBEAT => "Heartbeat",
        dtls::CONTENT_TYPE_TLS12_CID => "TLS12 CID",
        dtls::CONTENT_TYPE_ACK => "ACK",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for a record or `legacy_version` value.
///
/// 0x0303 is ambiguous in these fields: TLS 1.3 sends it as
/// `legacy_record_version` / `legacy_version`. Likewise, DTLS 1.3 sends the
/// DTLS 1.2 value 0xFEFD (RFC 9147, Section 5.3 —
/// <https://www.rfc-editor.org/rfc/rfc9147#section-5.3>).
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
        // RFC 6347, Section 4.1 — https://www.rfc-editor.org/rfc/rfc6347#section-4.1
        // RFC 9147, Section 4 — https://www.rfc-editor.org/rfc/rfc9147#section-4
        dtls::DTLS_1_0_VERSION => "DTLS 1.0",
        dtls::DTLS_1_2_VERSION => "DTLS 1.2 / DTLS 1.3 legacy_record_version",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for a version in the `supported_versions`
/// extension, where every value means exactly that version.
///
/// RFC 9846, Section 4.3.1 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3.1>
fn supported_version_name(version: u16) -> &'static str {
    if names::is_grease_u16(version) {
        return "GREASE";
    }
    match version {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        // RFC 9147, Section 5.3 — https://www.rfc-editor.org/rfc/rfc9147#section-5.3
        dtls::DTLS_1_0_VERSION => "DTLS 1.0",
        dtls::DTLS_1_2_VERSION => "DTLS 1.2",
        dtls::DTLS_1_3_VERSION => "DTLS 1.3",
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
        // RFC 5246, Section 7.4 (https://www.rfc-editor.org/rfc/rfc5246#section-7.4)
        0 => "Hello Request",
        1 => "Client Hello",
        2 => "Server Hello",
        // RFC 6347, Section 4.2.1 (https://www.rfc-editor.org/rfc/rfc6347#section-4.2.1)
        3 => "Hello Verify Request",
        4 => "New Session Ticket",
        5 => "End Of Early Data",
        8 => "Encrypted Extensions",
        // RFC 9147, Section 5.2 (https://www.rfc-editor.org/rfc/rfc9147#section-5.2)
        9 => "Request Connection Id",
        10 => "New Connection Id",
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
        // RFC 9846, Section 4.7.3 (https://www.rfc-editor.org/rfc/rfc9846#section-4.7.3)
        24 => "Key Update",
        // RFC 8879, Section 5 (https://www.rfc-editor.org/rfc/rfc8879#section-5)
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
        // RFC 5246 (https://www.rfc-editor.org/rfc/rfc5246)
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
        // RFC 7301 (https://www.rfc-editor.org/rfc/rfc7301)
        120 => "no_application_protocol",
        // RFC 7507 (https://www.rfc-editor.org/rfc/rfc7507)
        // 86 already covered above (inappropriate_fallback)
        // RFC 9846, Section 6 (https://www.rfc-editor.org/rfc/rfc9846#section-6)
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

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_CONTENT_TYPE: usize = 0;
const FD_VERSION: usize = 1;
const FD_LENGTH: usize = 2;
const FD_HANDSHAKE_MESSAGES: usize = 3;
const FD_OPAQUE_HANDSHAKE: usize = 4;
const FD_ALERT_LEVEL: usize = 5;
const FD_ALERT_DESCRIPTION: usize = 6;
const FD_ENCRYPTED_ALERT: usize = 7;
const FD_HEARTBEAT_TYPE: usize = 8;
const FD_PAYLOAD_LENGTH: usize = 9;
const FD_PAYLOAD: usize = 10;
const FD_PADDING: usize = 11;
const FD_PAYLOAD_LENGTH_EXCEEDS_RECORD: usize = 12;
const FD_ENCRYPTED_HEARTBEAT: usize = 13;

/// HeartbeatMessage header size: type(1) + payload_length(2).
///
/// RFC 6520, Section 4 — <https://www.rfc-editor.org/rfc/rfc6520#section-4>
const HEARTBEAT_HEADER_SIZE: usize = 3;

/// Minimum HeartbeatMessage padding: "The padding_length MUST be at least 16."
///
/// RFC 6520, Section 4 — <https://www.rfc-editor.org/rfc/rfc6520#section-4>
const HEARTBEAT_MIN_PADDING: usize = 16;

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
    // --- Heartbeat records (content_type == 24) ---
    // RFC 6520, Section 4 — https://www.rfc-editor.org/rfc/rfc6520#section-4
    named_field!(
        "heartbeat_type",
        "Heartbeat Message Type",
        U8,
        heartbeat_message_type_name
    ),
    FieldDescriptor::new("payload_length", "Payload Length", FieldType::U16).optional(),
    FieldDescriptor::new("payload", "Payload", FieldType::Bytes).optional(),
    FieldDescriptor::new("padding", "Padding", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "payload_length_exceeds_record",
        "Payload Length Exceeds Record",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "encrypted_heartbeat",
        "Encrypted Heartbeat",
        FieldType::Bytes,
    )
    .optional(),
];

/// Dissect the payload of a Heartbeat record.
///
/// ```text
/// RFC 6520, Section 4 — https://www.rfc-editor.org/rfc/rfc6520#section-4
///
/// struct {
///    HeartbeatMessageType type;
///    uint16 payload_length;
///    opaque payload[HeartbeatMessage.payload_length];
///    opaque padding[padding_length];
/// } HeartbeatMessage;
/// ```
///
/// "The padding_length MUST be at least 16." and "If the payload_length of
/// a received HeartbeatMessage is too large, the received HeartbeatMessage
/// MUST be discarded silently."
///
/// Heartbeats sent after ChangeCipherSpec are protected, so a record is
/// decoded only when it has a known message type and either is well formed
/// (payload plus at least 16 bytes of padding) or is shorter than the
/// smallest well-formed message (3 + 16 bytes), which ciphertext never is.
/// The latter is the Heartbleed pattern; if its `payload_length` does not
/// fit, it is flagged with `payload_length_exceeds_record` and the bytes
/// that are present are reported as `payload`. Anything else is reported as
/// `encrypted_heartbeat`.
fn dissect_heartbeat_record<'pkt>(
    payload: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    let plaintext = match payload {
        [1 | 2, hi, lo, rest @ ..] => {
            let payload_length = usize::from(u16::from_be_bytes([*hi, *lo]));
            rest.len() >= payload_length + HEARTBEAT_MIN_PADDING
                || payload.len() < HEARTBEAT_HEADER_SIZE + HEARTBEAT_MIN_PADDING
        }
        _ => false,
    };
    if !plaintext {
        if !payload.is_empty() {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_ENCRYPTED_HEARTBEAT],
                FieldValue::Bytes(payload),
                offset..offset + payload.len(),
            );
        }
        return;
    }
    let payload_length = u16::from_be_bytes([payload[1], payload[2]]);
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_HEARTBEAT_TYPE],
        FieldValue::U8(payload[0]),
        offset..offset + 1,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PAYLOAD_LENGTH],
        FieldValue::U16(payload_length),
        offset + 1..offset + HEARTBEAT_HEADER_SIZE,
    );
    let payload_end = HEARTBEAT_HEADER_SIZE + payload_length as usize;
    if payload_end > payload.len() {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PAYLOAD_LENGTH_EXCEEDS_RECORD],
            FieldValue::U8(1),
            offset + 1..offset + HEARTBEAT_HEADER_SIZE,
        );
        if payload.len() > HEARTBEAT_HEADER_SIZE {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_PAYLOAD],
                FieldValue::Bytes(&payload[HEARTBEAT_HEADER_SIZE..]),
                offset + HEARTBEAT_HEADER_SIZE..offset + payload.len(),
            );
        }
        return;
    }
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PAYLOAD],
        FieldValue::Bytes(&payload[HEARTBEAT_HEADER_SIZE..payload_end]),
        offset + HEARTBEAT_HEADER_SIZE..offset + payload_end,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PADDING],
        FieldValue::Bytes(&payload[payload_end..]),
        offset + payload_end..offset + payload.len(),
    );
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
    SpecReference::new(
        "RFC 4346",
        "The Transport Layer Security (TLS) Protocol Version 1.1",
        "https://www.rfc-editor.org/rfc/rfc4346",
    ),
    SpecReference::new(
        "RFC 5077",
        "Transport Layer Security (TLS) Session Resumption without Server-Side State",
        "https://www.rfc-editor.org/rfc/rfc5077",
    ),
    SpecReference::new(
        "RFC 8422",
        "Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier",
        "https://www.rfc-editor.org/rfc/rfc8422",
    ),
    SpecReference::new(
        "RFC 8701",
        "Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility",
        "https://www.rfc-editor.org/rfc/rfc8701",
    ),
    SpecReference::new(
        "RFC 9000",
        "QUIC: A UDP-Based Multiplexed and Secure Transport",
        "https://www.rfc-editor.org/rfc/rfc9000",
    ),
    SpecReference::new(
        "RFC 9001",
        "Using TLS to Secure QUIC",
        "https://www.rfc-editor.org/rfc/rfc9001",
    ),
    SpecReference::new(
        "RFC 9180",
        "Hybrid Public Key Encryption",
        "https://www.rfc-editor.org/rfc/rfc9180",
    ),
    SpecReference::new(
        "RFC 9345",
        "Delegated Credentials for TLS and DTLS",
        "https://www.rfc-editor.org/rfc/rfc9345",
    ),
    SpecReference::new(
        "RFC 9849",
        "TLS Encrypted Client Hello",
        "https://www.rfc-editor.org/rfc/rfc9849",
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
            CONTENT_TYPE_HEARTBEAT => {
                dissect_heartbeat_record(payload, payload_offset, buf);
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
    //! | 7301 §3.1     | ALPN protocol_name_list             | parse_alpn_extension                          |
    //! | 9846 §4.3.7   | supported_groups                    | parse_supported_groups_extension              |
    //! | 9846 §4.3.3   | signature_algorithms(_cert)         | parse_signature_algorithms_extensions         |
    //! | 9846 §4.3.8   | key_share (CH / SH / HRR)           | parse_key_share_extension_forms               |
    //! | 9846 §4.3.9   | psk_key_exchange_modes              | parse_psk_extensions                          |
    //! | 9846 §4.3.11  | pre_shared_key (CH / SH)            | parse_psk_extensions                          |
    //! | 8422 §5.1.2   | ec_point_formats                    | parse_ec_point_formats_extension              |
    //! | 6066 §8       | status_request                      | parse_status_request_extension                |
    //! | 8449 §4       | record_size_limit                   | parse_record_size_limit_extension             |
    //! | 8879 §3       | compress_certificate algorithms     | parse_compress_certificate_extension          |
    //! | 9001 §8.2     | quic_transport_parameters           | parse_quic_transport_parameters_extension     |
    //! | 9849 §5       | encrypted_client_hello              | parse_encrypted_client_hello_extension        |
    //! | 8701 §2       | GREASE values                       | parse_extension_names_and_grease              |
    //! | 9345 §4.1     | delegated_credential name           | parse_extension_names_and_grease              |
    //! | 5246 §7.4.2   | Certificate (TLS 1.2)               | parse_certificate_tls12                       |
    //! | 9846 §4.5.1   | Certificate (TLS 1.3)               | parse_certificate_tls13                       |
    //! | 9846 §4.5.1   | Certificate malformed               | parse_certificate_malformed                   |
    //! | 8422 §5.4     | ServerKeyExchange (ECDHE)           | parse_server_key_exchange_ecdhe               |
    //! | 5246 §7.4.3   | ServerKeyExchange (DHE)             | parse_server_key_exchange_dhe                 |
    //! | 5246 §7.4.4   | CertificateRequest (TLS 1.2)        | parse_certificate_request_forms               |
    //! | 9846 §4.4.2   | CertificateRequest (TLS 1.3)        | parse_certificate_request_forms               |
    //! | 5077 §3.3     | NewSessionTicket (TLS 1.2)          | parse_new_session_ticket_forms                |
    //! | 9846 §4.7.1   | NewSessionTicket (TLS 1.3)          | parse_new_session_ticket_forms                |
    //! | 9846 §4.4.1   | EncryptedExtensions                 | parse_encrypted_extensions                    |
    //! | 9846 §4.7.3   | KeyUpdate                           | parse_key_update                              |
    //! | 8879 §4       | CompressedCertificate               | parse_compressed_certificate                  |
    //! | 6066 §8       | CertificateStatus                   | parse_certificate_status                      |
    //! | 6520 §4       | HeartbeatMessage                    | parse_heartbeat_messages                      |
    //! | 6520 §4       | Protected heartbeat not Heartbleed  | parse_heartbeat_encrypted_with_known_first_byte |
    //! | 5246 §7.4.3   | SKE form needs a filling signature  | parse_server_key_exchange_ambiguous_forms     |
    //! | 9846 §4.3     | Malformed extension bodies stay raw | parse_malformed_extension_bodies_stay_raw     |
    //! | 9846 §3.4     | Vector minimum lengths              | parse_handshake_bodies_minimum_lengths        |
    //! | IANA          | Cipher suite names                  | parse_tls_cipher_suite_names                  |

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
        // a message may be split at any byte (RFC 9846, Section 5.1 (https://www.rfc-editor.org/rfc/rfc9846#section-5.1)), so the
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
        // Zero-length Handshake fragments are forbidden; nothing beyond the
        // record header is reported.
        // RFC 9846, Section 5.1 — https://www.rfc-editor.org/rfc/rfc9846#section-5.1
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
        // version other than 0x0303 (RFC 9846, Section 5.1 (https://www.rfc-editor.org/rfc/rfc9846#section-5.1)), so a non-handshake
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
            // Full IANA registry
            (0x0000, Some("TLS_NULL_WITH_NULL_NULL")),
            (0xc013, Some("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")),
            (0xc014, Some("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA")),
            (0xc009, Some("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")),
            (0xc00a, Some("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA")),
            (0x00ff, Some("TLS_EMPTY_RENEGOTIATION_INFO_SCSV")),
            (0x5600, Some("TLS_FALLBACK_SCSV")),
            // RFC 8701 (https://www.rfc-editor.org/rfc/rfc8701) GREASE
            (0xcaca, Some("GREASE")),
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

    // ---------------------------------------------------------------------
    // Extension and handshake body decoders
    // ---------------------------------------------------------------------

    /// Direct children of a container whose children range is `range`.
    fn direct<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, range: &Range<u32>) -> Vec<&'a Field<'pkt>> {
        let mut out = Vec::new();
        let mut i = range.start;
        while i < range.end {
            let f = &buf.fields()[i as usize];
            out.push(f);
            i = match f.value.as_container_range() {
                Some(r) => r.end,
                None => i + 1,
            };
        }
        out
    }

    /// Values of the direct children of the array field `name` in object `obj`.
    fn array_values<'pkt>(
        buf: &DissectBuffer<'pkt>,
        obj: &Range<u32>,
        name: &str,
    ) -> Vec<FieldValue<'pkt>> {
        let arr = child(buf, obj, name).unwrap_or_else(|| panic!("{name} missing"));
        direct(buf, arr.value.as_container_range().unwrap())
            .into_iter()
            .map(|f| f.value.clone())
            .collect()
    }

    /// Display name of a field through its descriptor's `display_fn`.
    fn shown(f: &Field<'_>) -> Option<&'static str> {
        f.descriptor.display_fn.and_then(|d| d(&f.value, &[]))
    }

    /// Element range (`index..end`) of an Object field.
    fn object_of(buf: &DissectBuffer<'_>, f: &Field<'_>) -> Range<u32> {
        let idx = buf
            .fields()
            .iter()
            .position(|x| core::ptr::eq(x, f))
            .unwrap() as u32;
        idx..f.value.as_container_range().unwrap().end
    }

    /// Dissect a record and return the buffer.
    fn dissect(data: &[u8]) -> DissectBuffer<'_> {
        let mut buf = DissectBuffer::new();
        TlsDissector.dissect(data, &mut buf, 0).unwrap();
        buf
    }

    /// A ClientHello record carrying exactly `exts`.
    fn client_hello_with(exts: &[u8]) -> Vec<u8> {
        wrap_client_hello(&build_client_hello_body(
            0x0303,
            &[],
            &[0x1301],
            &[0x00],
            Some(exts),
        ))
    }

    /// A ServerHello record carrying exactly `exts`.
    fn server_hello_with(exts: &[u8]) -> Vec<u8> {
        wrap_server_hello(&build_server_hello_body(
            0x0303,
            &[],
            0x1301,
            0x00,
            Some(exts),
        ))
    }

    /// First extension object of the first handshake message.
    fn first_extension(buf: &DissectBuffer<'_>) -> Range<u32> {
        extension_objects(buf, &first_handshake(buf))
            .into_iter()
            .next()
            .unwrap()
    }

    /// Length-prefixed vector with a `n`-byte big-endian length.
    fn vec_n(n: usize, body: &[u8]) -> Vec<u8> {
        let len = (body.len() as u32).to_be_bytes();
        let mut v = len[4 - n..].to_vec();
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn parse_alpn_extension() {
        // RFC 7301, Section 3.1 — https://www.rfc-editor.org/rfc/rfc7301#section-3.1
        let alpn = build_extension(
            16,
            &[
                0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
            ],
        );
        let data = client_hello_with(&alpn);
        let buf = dissect(&data);
        let ext = first_extension(&buf);
        assert_eq!(
            array_values(&buf, &ext, "protocol_names"),
            vec![FieldValue::Bytes(b"h2"), FieldValue::Bytes(b"http/1.1")]
        );
        // The reproduction in the issue: a single "h2".
        let alpn = build_extension(16, &[0x00, 0x03, 0x02, b'h', b'2']);
        let data = client_hello_with(&alpn);
        let buf = dissect(&data);
        let ext = first_extension(&buf);
        let names = child(&buf, &ext, "protocol_names").unwrap();
        let first = direct(&buf, names.value.as_container_range().unwrap())[0];
        assert_eq!(first.value, FieldValue::Bytes(b"h2"));
        assert_eq!(first.range, 5 + 4 + 43 + 4 + 3..5 + 4 + 43 + 4 + 5);
        // A malformed list is left as raw data only.
        let bad = build_extension(16, &[0x00, 0x04, 0x05, b'h', b'2', b'x']);
        let data = client_hello_with(&bad);
        let buf = dissect(&data);
        let ext = first_extension(&buf);
        assert!(child(&buf, &ext, "protocol_names").is_none());
        assert!(child(&buf, &ext, "data").is_some());
    }

    #[test]
    fn parse_supported_groups_extension() {
        // RFC 9846, Section 4.3.7 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.7
        let ext = build_extension(
            10,
            &[0x00, 0x08, 0x3a, 0x3a, 0x11, 0xec, 0x00, 0x1d, 0x00, 0x17],
        );
        let data = client_hello_with(&ext);
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        let groups = child(&buf, &obj, "named_groups").unwrap();
        let items = direct(&buf, groups.value.as_container_range().unwrap());
        let names: Vec<_> = items.iter().map(|f| shown(f)).collect();
        assert_eq!(
            names,
            vec![
                Some("GREASE"),
                Some("X25519MLKEM768"),
                Some("x25519"),
                Some("secp256r1")
            ]
        );
    }

    #[test]
    fn parse_signature_algorithms_extensions() {
        // RFC 9846, Section 4.3.3 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.3
        for ext_type in [13u16, 50] {
            let ext = build_extension(ext_type, &[0x00, 0x04, 0x08, 0x04, 0x04, 0x03]);
            let data = client_hello_with(&ext);
            let buf = dissect(&data);
            let obj = first_extension(&buf);
            let arr = child(&buf, &obj, "signature_schemes").unwrap();
            let items = direct(&buf, arr.value.as_container_range().unwrap());
            assert_eq!(items[0].value, FieldValue::U16(0x0804));
            assert_eq!(shown(items[0]), Some("rsa_pss_rsae_sha256"));
            assert_eq!(shown(items[1]), Some("ecdsa_secp256r1_sha256"));
        }
    }

    #[test]
    fn parse_key_share_extension_forms() {
        // RFC 9846, Section 4.3.8 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.8
        let mut shares = Vec::new();
        shares.extend_from_slice(&[0x00, 0x1d, 0x00, 0x04, 1, 2, 3, 4]);
        shares.extend_from_slice(&[0x00, 0x17, 0x00, 0x02, 5, 6]);
        let ext = build_extension(51, &vec_n(2, &shares));
        let data = client_hello_with(&ext);
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        let arr = child(&buf, &obj, "client_shares").unwrap();
        let entries = direct(&buf, arr.value.as_container_range().unwrap());
        assert_eq!(entries.len(), 2);
        let e0 = object_of(&buf, entries[0]);
        assert_eq!(
            child(&buf, &e0, "group").unwrap().value,
            FieldValue::U16(0x1d)
        );
        assert_eq!(shown(child(&buf, &e0, "group").unwrap()), Some("x25519"));
        assert_eq!(
            child(&buf, &e0, "key_exchange").unwrap().value,
            FieldValue::Bytes(&[1, 2, 3, 4])
        );
        assert_eq!(buf.resolve_container_display_name(e0.start), Some("x25519"));
        let e1 = object_of(&buf, entries[1]);
        assert_eq!(
            child(&buf, &e1, "key_exchange").unwrap().value,
            FieldValue::Bytes(&[5, 6])
        );

        // ServerHello: a single KeyShareEntry.
        let ext = build_extension(51, &[0x00, 0x1d, 0x00, 0x02, 9, 9]);
        let data = server_hello_with(&ext);
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        let share = child(&buf, &obj, "server_share").unwrap();
        let share = object_of(&buf, share);
        assert_eq!(
            child(&buf, &share, "group").unwrap().value,
            FieldValue::U16(0x1d)
        );
        assert_eq!(
            child(&buf, &share, "key_exchange").unwrap().value,
            FieldValue::Bytes(&[9, 9])
        );

        // HelloRetryRequest: selected_group only.
        let ext = build_extension(51, &[0x11, 0xec]);
        let body = build_server_hello_body_with_random(
            0x0303,
            &HELLO_RETRY_REQUEST_RANDOM,
            &[],
            0x1301,
            0,
            Some(&ext),
        );
        let data = wrap_server_hello(&body);
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        let sel = child(&buf, &obj, "selected_group").unwrap();
        assert_eq!(sel.value, FieldValue::U16(0x11ec));
        assert_eq!(shown(sel), Some("X25519MLKEM768"));
        assert!(child(&buf, &obj, "server_share").is_none());
    }

    #[test]
    fn parse_psk_extensions() {
        // RFC 9846, Section 4.3.9 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.9
        let modes = build_extension(45, &[0x02, 0x01, 0x0b]);
        // RFC 9846, Section 4.3.11 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.11
        let mut identities = vec_n(2, b"ticket");
        identities.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        let mut psk = vec_n(2, &identities);
        psk.extend_from_slice(&vec_n(2, &vec_n(1, &[0xbb; 32])));
        let psk = build_extension(41, &psk);
        let mut exts = modes;
        exts.extend_from_slice(&psk);
        let data = client_hello_with(&exts);
        let buf = dissect(&data);
        let objs = extension_objects(&buf, &first_handshake(&buf));

        let modes = child(&buf, &objs[0], "ke_modes").unwrap();
        let items = direct(&buf, modes.value.as_container_range().unwrap());
        assert_eq!(shown(items[0]), Some("psk_dhe_ke"));
        assert_eq!(shown(items[1]), Some("GREASE"));

        let ids = child(&buf, &objs[1], "identities").unwrap();
        let ids = direct(&buf, ids.value.as_container_range().unwrap());
        assert_eq!(ids.len(), 1);
        let id0 = object_of(&buf, ids[0]);
        assert_eq!(
            child(&buf, &id0, "identity").unwrap().value,
            FieldValue::Bytes(b"ticket")
        );
        assert_eq!(
            child(&buf, &id0, "obfuscated_ticket_age").unwrap().value,
            FieldValue::U32(0x0102_0304)
        );
        assert_eq!(
            array_values(&buf, &objs[1], "binders"),
            vec![FieldValue::Bytes(&[0xbb; 32])]
        );

        // ServerHello: selected_identity.
        let ext = build_extension(41, &[0x00, 0x00]);
        let data = server_hello_with(&ext);
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        assert_eq!(
            child(&buf, &obj, "selected_identity").unwrap().value,
            FieldValue::U16(0)
        );
    }

    #[test]
    fn parse_ec_point_formats_extension() {
        // RFC 8422, Section 5.1.2 — https://www.rfc-editor.org/rfc/rfc8422#section-5.1.2
        let ext = build_extension(11, &[0x02, 0x00, 0x01]);
        let data = client_hello_with(&ext);
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        let arr = child(&buf, &obj, "ec_point_formats").unwrap();
        let items = direct(&buf, arr.value.as_container_range().unwrap());
        assert_eq!(shown(items[0]), Some("uncompressed"));
        assert_eq!(shown(items[1]), Some("ansiX962_compressed_prime"));
    }

    #[test]
    fn parse_status_request_extension() {
        // RFC 6066, Section 8 — https://www.rfc-editor.org/rfc/rfc6066#section-8
        let mut req = vec![0x01];
        req.extend_from_slice(&vec_n(2, &vec_n(2, &[0xaa, 0xbb])));
        req.extend_from_slice(&vec_n(2, &[0xcc]));
        let ext = build_extension(5, &req);
        let data = client_hello_with(&ext);
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        let st = child(&buf, &obj, "status_type").unwrap();
        assert_eq!(st.value, FieldValue::U8(1));
        assert_eq!(shown(st), Some("ocsp"));
        assert_eq!(
            array_values(&buf, &obj, "responder_id_list"),
            vec![FieldValue::Bytes(&[0xaa, 0xbb])]
        );
        assert_eq!(
            child(&buf, &obj, "request_extensions").unwrap().value,
            FieldValue::Bytes(&[0xcc])
        );

        // An empty status_request in a TLS 1.2 ServerHello stays empty.
        let data = server_hello_with(&build_extension(5, &[]));
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        assert!(child(&buf, &obj, "status_type").is_none());
    }

    #[test]
    fn parse_record_size_limit_extension() {
        // RFC 8449, Section 4 — https://www.rfc-editor.org/rfc/rfc8449#section-4
        let data = client_hello_with(&build_extension(28, &[0x40, 0x01]));
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        assert_eq!(
            child(&buf, &obj, "record_size_limit").unwrap().value,
            FieldValue::U16(0x4001)
        );
    }

    #[test]
    fn parse_compress_certificate_extension() {
        // RFC 8879, Section 3 — https://www.rfc-editor.org/rfc/rfc8879#section-3
        let data = client_hello_with(&build_extension(27, &[0x04, 0x00, 0x02, 0x00, 0x03]));
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        let arr = child(&buf, &obj, "algorithms").unwrap();
        let items = direct(&buf, arr.value.as_container_range().unwrap());
        assert_eq!(shown(items[0]), Some("brotli"));
        assert_eq!(shown(items[1]), Some("zstd"));
    }

    #[test]
    fn parse_quic_transport_parameters_extension() {
        // RFC 9001, Section 8.2 — https://www.rfc-editor.org/rfc/rfc9001#section-8.2
        // RFC 9000, Section 18 — https://www.rfc-editor.org/rfc/rfc9000#section-18
        let params = [
            0x01, 0x02, 0x67, 0x10, // max_idle_timeout = 10000 (2-byte varint)
            0x0f, 0x00, // initial_source_connection_id, empty
            0x40, 0x3a, 0x01, 0xff, // reserved id 58 (2-byte varint), 1-byte value
        ];
        let data = client_hello_with(&build_extension(57, &params));
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        let arr = child(&buf, &obj, "transport_parameters").unwrap();
        let items = direct(&buf, arr.value.as_container_range().unwrap());
        assert_eq!(items.len(), 3);
        let p0 = object_of(&buf, items[0]);
        let id = child(&buf, &p0, "id").unwrap();
        assert_eq!(id.value, FieldValue::U64(1));
        assert_eq!(shown(id), Some("max_idle_timeout"));
        assert_eq!(
            child(&buf, &p0, "value").unwrap().value,
            FieldValue::Bytes(&[0x67, 0x10])
        );
        assert_eq!(
            buf.resolve_container_display_name(p0.start),
            Some("max_idle_timeout")
        );
        let p2 = object_of(&buf, items[2]);
        assert_eq!(child(&buf, &p2, "id").unwrap().value, FieldValue::U64(58));
        assert_eq!(shown(child(&buf, &p2, "id").unwrap()), Some("reserved"));

        // A parameter whose length overruns the extension is not decoded.
        let data = client_hello_with(&build_extension(57, &[0x01, 0x05, 0x00]));
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        assert!(child(&buf, &obj, "transport_parameters").is_none());
    }

    #[test]
    fn parse_encrypted_client_hello_extension() {
        // RFC 9849, Section 5 — https://www.rfc-editor.org/rfc/rfc9849#section-5
        let mut outer = vec![0x00, 0x00, 0x01, 0x00, 0x01, 0x42];
        outer.extend_from_slice(&vec_n(2, &[0x11; 32]));
        outer.extend_from_slice(&vec_n(2, &[0x22; 8]));
        let data = client_hello_with(&build_extension(0xfe0d, &outer));
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        assert_eq!(
            buf.resolve_container_display_name(obj.start),
            Some("encrypted_client_hello")
        );
        let t = child(&buf, &obj, "ech_type").unwrap();
        assert_eq!(shown(t), Some("outer"));
        let kdf = child(&buf, &obj, "kdf_id").unwrap();
        assert_eq!(shown(kdf), Some("HKDF-SHA256"));
        let aead = child(&buf, &obj, "aead_id").unwrap();
        assert_eq!(shown(aead), Some("AES-128-GCM"));
        assert_eq!(
            child(&buf, &obj, "config_id").unwrap().value,
            FieldValue::U8(0x42)
        );
        assert_eq!(
            child(&buf, &obj, "enc").unwrap().value,
            FieldValue::Bytes(&[0x11; 32])
        );
        assert_eq!(
            child(&buf, &obj, "payload").unwrap().value,
            FieldValue::Bytes(&[0x22; 8])
        );

        // Inner variant: type only.
        let data = client_hello_with(&build_extension(0xfe0d, &[0x01]));
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        assert_eq!(shown(child(&buf, &obj, "ech_type").unwrap()), Some("inner"));
        assert!(child(&buf, &obj, "config_id").is_none());

        // HelloRetryRequest: 8-byte confirmation.
        let body = build_server_hello_body_with_random(
            0x0303,
            &HELLO_RETRY_REQUEST_RANDOM,
            &[],
            0x1301,
            0,
            Some(&build_extension(0xfe0d, &[0x33; 8])),
        );
        let data = wrap_server_hello(&body);
        let buf = dissect(&data);
        let obj = first_extension(&buf);
        assert_eq!(
            child(&buf, &obj, "confirmation").unwrap().value,
            FieldValue::Bytes(&[0x33; 8])
        );
    }

    #[test]
    fn parse_extension_names_and_grease() {
        // RFC 8701, Section 2 — https://www.rfc-editor.org/rfc/rfc8701#section-2
        for (ext_type, expected) in [
            (17u16, "status_request_v2"),
            (23, "extended_main_secret"),
            (34, "delegated_credential"),
            (57, "quic_transport_parameters"),
            (0xfe0d, "encrypted_client_hello"),
            (0x0a0a, "GREASE"),
            (0xfafa, "GREASE"),
            (0x0a1a, "unknown"),
        ] {
            assert_eq!(extension_type_name(ext_type), expected, "{ext_type:#06x}");
        }
        assert_eq!(cipher_suite_name(0x2a2a), Some("GREASE"));
        assert_eq!(names::named_group_name(0xdada), "GREASE");
        assert_eq!(names::signature_scheme_name(0x1a1a), "GREASE");
        assert_eq!(supported_version_name(0x7a7a), "GREASE");
        // A GREASE extension in a ClientHello is labelled as such.
        let data = client_hello_with(&build_extension(0x3a3a, &[]));
        let buf = dissect(&data);
        assert_eq!(
            buf.resolve_container_display_name(first_extension(&buf).start),
            Some("GREASE")
        );
    }

    /// A handshake record carrying one message of type `ht` with `body`.
    fn handshake_record(ht: u8, body: &[u8]) -> Vec<u8> {
        build_tls_record(CONTENT_TYPE_HANDSHAKE, 0x0303, &build_handshake(ht, body))
    }

    #[test]
    fn parse_certificate_tls12() {
        // RFC 5246, Section 7.4.2 — https://www.rfc-editor.org/rfc/rfc5246#section-7.4.2
        let mut list = vec_n(3, &[0x30, 0x01, 0xaa]);
        list.extend_from_slice(&vec_n(3, &[0x30, 0x02, 0xbb, 0xcc]));
        let data = handshake_record(11, &vec_n(3, &list));
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        assert_eq!(
            array_values(&buf, &obj, "certificates"),
            vec![
                FieldValue::Bytes(&[0x30, 0x01, 0xaa]),
                FieldValue::Bytes(&[0x30, 0x02, 0xbb, 0xcc])
            ]
        );
        let certs = child(&buf, &obj, "certificates").unwrap();
        let first = direct(&buf, certs.value.as_container_range().unwrap())[0];
        assert_eq!(first.range, 5 + 4 + 3 + 3..5 + 4 + 3 + 3 + 3);
        assert!(child(&buf, &obj, "certificate_request_context").is_none());
    }

    #[test]
    fn parse_certificate_tls13() {
        // RFC 9846, Section 4.5.1 — https://www.rfc-editor.org/rfc/rfc9846#section-4.5.1
        let mut status = vec![0x01];
        status.extend_from_slice(&vec_n(3, &[0x0d; 3]));
        let mut entry = vec_n(3, &[0x30, 0x01, 0xaa]);
        entry.extend_from_slice(&vec_n(2, &build_extension(5, &status)));
        let mut body = vec_n(1, &[]);
        body.extend_from_slice(&vec_n(3, &entry));
        let data = handshake_record(11, &body);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        assert_eq!(
            child(&buf, &obj, "certificate_request_context")
                .unwrap()
                .value,
            FieldValue::Bytes(&[])
        );
        let entries = child(&buf, &obj, "certificate_entries").unwrap();
        let entries = direct(&buf, entries.value.as_container_range().unwrap());
        assert_eq!(entries.len(), 1);
        let e0 = object_of(&buf, entries[0]);
        assert_eq!(
            child(&buf, &e0, "cert_data").unwrap().value,
            FieldValue::Bytes(&[0x30, 0x01, 0xaa])
        );
        let exts = extension_objects(&buf, &e0);
        assert_eq!(
            child(&buf, &exts[0], "ocsp_response").unwrap().value,
            FieldValue::Bytes(&[0x0d; 3])
        );
    }

    #[test]
    fn parse_certificate_malformed() {
        // A list length that matches neither form leaves only type/length.
        let data = handshake_record(11, &[0x00, 0x00, 0x09, 0x01]);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        assert!(child(&buf, &obj, "certificates").is_none());
        assert!(child(&buf, &obj, "certificate_entries").is_none());
    }

    #[test]
    fn parse_server_key_exchange_ecdhe() {
        // RFC 8422, Section 5.4 — https://www.rfc-editor.org/rfc/rfc8422#section-5.4
        let mut body = vec![0x03, 0x00, 0x1d];
        body.extend_from_slice(&vec_n(1, &[0x44; 32]));
        body.extend_from_slice(&[0x08, 0x04]);
        body.extend_from_slice(&vec_n(2, &[0x55; 16]));
        let data = handshake_record(12, &body);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        let ct = child(&buf, &obj, "curve_type").unwrap();
        assert_eq!(shown(ct), Some("named_curve"));
        let nc = child(&buf, &obj, "named_curve").unwrap();
        assert_eq!(shown(nc), Some("x25519"));
        assert_eq!(
            child(&buf, &obj, "public_key").unwrap().value,
            FieldValue::Bytes(&[0x44; 32])
        );
        let alg = child(&buf, &obj, "signature_algorithm").unwrap();
        assert_eq!(shown(alg), Some("rsa_pss_rsae_sha256"));
        assert_eq!(
            child(&buf, &obj, "signature").unwrap().value,
            FieldValue::Bytes(&[0x55; 16])
        );

        // TLS 1.0 / 1.1: no SignatureAndHashAlgorithm before the signature.
        let mut body = vec![0x03, 0x00, 0x17];
        body.extend_from_slice(&vec_n(1, &[0x04; 5]));
        body.extend_from_slice(&vec_n(2, &[0x55; 6]));
        let data = handshake_record(12, &body);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        assert!(child(&buf, &obj, "signature_algorithm").is_none());
        assert_eq!(
            child(&buf, &obj, "signature").unwrap().value,
            FieldValue::Bytes(&[0x55; 6])
        );
    }

    #[test]
    fn parse_server_key_exchange_dhe() {
        // RFC 5246, Section 7.4.3 — https://www.rfc-editor.org/rfc/rfc5246#section-7.4.3
        let mut body = vec_n(2, &[0xff; 4]);
        body.extend_from_slice(&vec_n(2, &[0x02]));
        body.extend_from_slice(&vec_n(2, &[0x77; 4]));
        body.extend_from_slice(&[0x04, 0x01]);
        body.extend_from_slice(&vec_n(2, &[0x55; 8]));
        let data = handshake_record(12, &body);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        assert_eq!(
            child(&buf, &obj, "dh_p").unwrap().value,
            FieldValue::Bytes(&[0xff; 4])
        );
        assert_eq!(
            child(&buf, &obj, "dh_g").unwrap().value,
            FieldValue::Bytes(&[0x02])
        );
        assert_eq!(
            child(&buf, &obj, "dh_ys").unwrap().value,
            FieldValue::Bytes(&[0x77; 4])
        );
        assert_eq!(
            shown(child(&buf, &obj, "signature_algorithm").unwrap()),
            Some("rsa_pkcs1_sha256")
        );
        assert!(child(&buf, &obj, "curve_type").is_none());

        // Parameters that do not fit are left undecoded.
        let data = handshake_record(12, &[0x00, 0x09, 0x01]);
        let buf = dissect(&data);
        assert!(child(&buf, &first_handshake(&buf), "dh_p").is_none());
    }

    #[test]
    fn parse_certificate_request_forms() {
        // RFC 5246, Section 7.4.4 — https://www.rfc-editor.org/rfc/rfc5246#section-7.4.4
        let mut body = vec_n(1, &[0x01, 0x40]);
        body.extend_from_slice(&vec_n(2, &[0x04, 0x03]));
        body.extend_from_slice(&vec_n(2, &vec_n(2, &[0x30, 0x00])));
        let data = handshake_record(13, &body);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        let types = child(&buf, &obj, "certificate_types").unwrap();
        let types = direct(&buf, types.value.as_container_range().unwrap());
        assert_eq!(shown(types[0]), Some("rsa_sign"));
        assert_eq!(shown(types[1]), Some("ecdsa_sign"));
        assert_eq!(
            array_values(&buf, &obj, "supported_signature_algorithms"),
            vec![FieldValue::U16(0x0403)]
        );
        assert_eq!(
            array_values(&buf, &obj, "certificate_authorities"),
            vec![FieldValue::Bytes(&[0x30, 0x00])]
        );

        // RFC 9846, Section 4.4.2 — https://www.rfc-editor.org/rfc/rfc9846#section-4.4.2
        let mut body = vec_n(1, &[0x07]);
        body.extend_from_slice(&vec_n(2, &build_extension(13, &[0x00, 0x02, 0x08, 0x07])));
        let data = handshake_record(13, &body);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        assert_eq!(
            child(&buf, &obj, "certificate_request_context")
                .unwrap()
                .value,
            FieldValue::Bytes(&[0x07])
        );
        let exts = extension_objects(&buf, &obj);
        let schemes = child(&buf, &exts[0], "signature_schemes").unwrap();
        let schemes = direct(&buf, schemes.value.as_container_range().unwrap());
        assert_eq!(shown(schemes[0]), Some("ed25519"));
    }

    #[test]
    fn parse_new_session_ticket_forms() {
        // RFC 5077, Section 3.3 — https://www.rfc-editor.org/rfc/rfc5077#section-3.3
        let mut body = 7200u32.to_be_bytes().to_vec();
        body.extend_from_slice(&vec_n(2, &[0x99; 10]));
        let data = handshake_record(4, &body);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        assert_eq!(
            child(&buf, &obj, "ticket_lifetime").unwrap().value,
            FieldValue::U32(7200)
        );
        assert_eq!(
            child(&buf, &obj, "ticket").unwrap().value,
            FieldValue::Bytes(&[0x99; 10])
        );
        assert!(child(&buf, &obj, "ticket_age_add").is_none());

        // RFC 9846, Section 4.7.1 — https://www.rfc-editor.org/rfc/rfc9846#section-4.7.1
        let mut body = 7200u32.to_be_bytes().to_vec();
        body.extend_from_slice(&0xdead_beefu32.to_be_bytes());
        body.extend_from_slice(&vec_n(1, &[0x00]));
        body.extend_from_slice(&vec_n(2, &[0x99; 10]));
        body.extend_from_slice(&vec_n(2, &build_extension(42, &[0x00, 0x00, 0x40, 0x00])));
        let data = handshake_record(4, &body);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        assert_eq!(
            child(&buf, &obj, "ticket_age_add").unwrap().value,
            FieldValue::U32(0xdead_beef)
        );
        assert_eq!(
            child(&buf, &obj, "ticket_nonce").unwrap().value,
            FieldValue::Bytes(&[0x00])
        );
        let exts = extension_objects(&buf, &obj);
        assert_eq!(
            child(&buf, &exts[0], "max_early_data_size").unwrap().value,
            FieldValue::U32(0x4000)
        );
    }

    #[test]
    fn parse_encrypted_extensions() {
        // RFC 9846, Section 4.4.1 — https://www.rfc-editor.org/rfc/rfc9846#section-4.4.1
        let alpn = build_extension(16, &[0x00, 0x03, 0x02, b'h', b'3']);
        let data = handshake_record(8, &vec_n(2, &alpn));
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        let exts = extension_objects(&buf, &obj);
        assert_eq!(
            array_values(&buf, &exts[0], "protocol_names"),
            vec![FieldValue::Bytes(b"h3")]
        );
    }

    #[test]
    fn parse_key_update() {
        // RFC 9846, Section 4.7.3 — https://www.rfc-editor.org/rfc/rfc9846#section-4.7.3
        let data = handshake_record(24, &[0x01]);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        let ru = child(&buf, &obj, "request_update").unwrap();
        assert_eq!(ru.value, FieldValue::U8(1));
        assert_eq!(shown(ru), Some("update_requested"));
    }

    #[test]
    fn parse_compressed_certificate() {
        // RFC 8879, Section 4 — https://www.rfc-editor.org/rfc/rfc8879#section-4
        let mut body = vec![0x00, 0x01, 0x00, 0x10, 0x00];
        body.extend_from_slice(&vec_n(3, &[0x78; 6]));
        let data = handshake_record(25, &body);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        assert_eq!(shown(child(&buf, &obj, "algorithm").unwrap()), Some("zlib"));
        assert_eq!(
            child(&buf, &obj, "uncompressed_length").unwrap().value,
            FieldValue::U32(0x1000)
        );
        assert_eq!(
            child(&buf, &obj, "compressed_certificate_message")
                .unwrap()
                .value,
            FieldValue::Bytes(&[0x78; 6])
        );
    }

    #[test]
    fn parse_certificate_status() {
        // RFC 6066, Section 8 — https://www.rfc-editor.org/rfc/rfc6066#section-8
        let mut body = vec![0x01];
        body.extend_from_slice(&vec_n(3, &[0x30, 0x03]));
        let data = handshake_record(22, &body);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        assert_eq!(
            shown(child(&buf, &obj, "status_type").unwrap()),
            Some("ocsp")
        );
        assert_eq!(
            child(&buf, &obj, "ocsp_response").unwrap().value,
            FieldValue::Bytes(&[0x30, 0x03])
        );
    }

    #[test]
    fn parse_heartbeat_messages() {
        // RFC 6520, Section 4 — https://www.rfc-editor.org/rfc/rfc6520#section-4
        let mut msg = vec![0x01, 0x00, 0x03, b'a', b'b', b'c'];
        msg.extend_from_slice(&[0x00; 16]);
        let data = build_tls_record(CONTENT_TYPE_HEARTBEAT, 0x0303, &msg);
        let buf = dissect(&data);
        let layer = buf.layer_by_name("TLS").unwrap();
        let t = buf.field_by_name(layer, "heartbeat_type").unwrap();
        assert_eq!(t.value, FieldValue::U8(1));
        assert_eq!(
            buf.resolve_display_name(layer, "heartbeat_type_name"),
            Some("heartbeat_request")
        );
        assert_eq!(
            buf.field_by_name(layer, "payload_length").unwrap().value,
            FieldValue::U16(3)
        );
        assert_eq!(
            buf.field_by_name(layer, "payload").unwrap().value,
            FieldValue::Bytes(b"abc")
        );
        assert_eq!(
            buf.field_by_name(layer, "padding").unwrap().value,
            FieldValue::Bytes(&[0x00; 16])
        );
        assert!(
            buf.field_by_name(layer, "payload_length_exceeds_record")
                .is_none()
        );

        // Heartbleed-style request: payload_length larger than the record.
        let data = build_tls_record(CONTENT_TYPE_HEARTBEAT, 0x0302, &[0x01, 0x40, 0x00]);
        let buf = dissect(&data);
        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "payload_length").unwrap().value,
            FieldValue::U16(0x4000)
        );
        assert!(buf.field_by_name(layer, "payload").is_none());
        assert_eq!(
            buf.field_by_name(layer, "payload_length_exceeds_record")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );

        // A protected heartbeat (unknown type byte) is reported raw.
        let data = build_tls_record(CONTENT_TYPE_HEARTBEAT, 0x0303, &[0xab; 24]);
        let buf = dissect(&data);
        let layer = buf.layer_by_name("TLS").unwrap();
        assert!(buf.field_by_name(layer, "heartbeat_type").is_none());
        assert_eq!(
            buf.field_by_name(layer, "encrypted_heartbeat")
                .unwrap()
                .value,
            FieldValue::Bytes(&[0xab; 24])
        );
    }

    #[test]
    fn parse_server_key_exchange_ambiguous_forms() {
        // ffdhe6144 DHE parameters start with dh_p length 0x0300, which also
        // reads as curve_type named_curve(3); the ECDHE form only applies when
        // the signature fills the rest of the body.
        let mut body = vec_n(2, &[0xff; 0x300]);
        body.extend_from_slice(&vec_n(2, &[0x02]));
        body.extend_from_slice(&vec_n(2, &[0x77; 8]));
        body.extend_from_slice(&[0x08, 0x04]);
        body.extend_from_slice(&vec_n(2, &[0x55; 8]));
        let data = handshake_record(12, &body);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        assert!(child(&buf, &obj, "curve_type").is_none());
        assert_eq!(
            child(&buf, &obj, "dh_p").unwrap().value,
            FieldValue::Bytes(&[0xff; 0x300])
        );

        // TLS 1.0 RSA_EXPORT parameters (modulus, exponent) followed by a
        // signature are not DHE: three vectors with nothing after them.
        let mut body = vec_n(2, &[0xc1; 8]);
        body.extend_from_slice(&vec_n(2, &[0x01, 0x00, 0x01]));
        body.extend_from_slice(&vec_n(2, &[0x55; 8]));
        let data = handshake_record(12, &body);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        assert!(child(&buf, &obj, "dh_p").is_none());
        assert!(child(&buf, &obj, "signature").is_none());
    }

    #[test]
    fn parse_heartbeat_encrypted_with_known_first_byte() {
        // A protected heartbeat whose first ciphertext byte is 0x01 is not a
        // Heartbleed request: it is too long to be a malformed plaintext
        // message and its payload_length does not fit.
        let mut msg = vec![0x01, 0x9a, 0x3c];
        msg.extend_from_slice(&[0x5e; 37]);
        let data = build_tls_record(CONTENT_TYPE_HEARTBEAT, 0x0303, &msg);
        let buf = dissect(&data);
        let layer = buf.layer_by_name("TLS").unwrap();
        assert!(buf.field_by_name(layer, "heartbeat_type").is_none());
        assert!(
            buf.field_by_name(layer, "payload_length_exceeds_record")
                .is_none()
        );
        assert_eq!(
            buf.field_by_name(layer, "encrypted_heartbeat")
                .unwrap()
                .value,
            FieldValue::Bytes(&msg)
        );

        // A short Heartbleed request with trailing bytes keeps them visible.
        let mut msg = vec![0x01, 0x40, 0x00];
        msg.extend_from_slice(&[0x61; 10]);
        let data = build_tls_record(CONTENT_TYPE_HEARTBEAT, 0x0302, &msg);
        let buf = dissect(&data);
        let layer = buf.layer_by_name("TLS").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "payload").unwrap().value,
            FieldValue::Bytes(&[0x61; 10])
        );
        assert!(
            buf.field_by_name(layer, "payload_length_exceeds_record")
                .is_some()
        );
    }

    #[test]
    fn parse_malformed_extension_bodies_stay_raw() {
        for (ext_type, data) in [
            // quic_transport_parameters: truncated varint.
            (57u16, vec![0x40]),
            // quic_transport_parameters: second parameter overruns.
            (57, vec![0x01, 0x00, 0x02, 0x05, 0x00]),
            // status_request: OCSP request missing request_extensions.
            (5, vec![0x01, 0x00, 0x00]),
            // status_request: unknown status type.
            (5, vec![0x07, 0x00]),
            // encrypted_client_hello: truncated outer.
            (0xfe0d, vec![0x00, 0x00, 0x01]),
            // encrypted_client_hello: inner with trailing bytes.
            (0xfe0d, vec![0x01, 0x00]),
            // key_share: empty key_exchange.
            (51, vec_n(2, &[0x00, 0x1d, 0x00, 0x00])),
            // pre_shared_key: binder shorter than 32 bytes.
            (41, {
                let mut id = vec_n(2, b"t");
                id.extend_from_slice(&[0, 0, 0, 0]);
                let mut v = vec_n(2, &id);
                v.extend_from_slice(&vec_n(2, &vec_n(1, &[0xbb; 8])));
                v
            }),
            // pre_shared_key: no identities.
            (41, {
                let mut v = vec_n(2, &[]);
                v.extend_from_slice(&vec_n(2, &vec_n(1, &[0xbb; 32])));
                v
            }),
        ] {
            let data = client_hello_with(&build_extension(ext_type, &data));
            let buf = dissect(&data);
            let obj = first_extension(&buf);
            let names: Vec<&str> = children(&buf, &obj).iter().map(|f| f.name()).collect();
            assert_eq!(
                names,
                vec!["type", "length", "data"],
                "extension {ext_type:#06x} with malformed body"
            );
        }
    }

    #[test]
    fn parse_handshake_bodies_minimum_lengths() {
        // TLS 1.3 NewSessionTicket with an empty ticket (ticket<1..2^16-1>).
        let mut body = 7200u32.to_be_bytes().to_vec();
        body.extend_from_slice(&[0, 0, 0, 1]);
        body.extend_from_slice(&vec_n(1, &[]));
        body.extend_from_slice(&vec_n(2, &[]));
        body.extend_from_slice(&vec_n(2, &[]));
        let data = handshake_record(4, &body);
        let buf = dissect(&data);
        assert!(child(&buf, &first_handshake(&buf), "ticket").is_none());

        // TLS 1.2 CertificateRequest with an empty signature algorithm list
        // (supported_signature_algorithms<2..2^16-2>) and no CAs.
        let mut body = vec_n(1, &[0x01]);
        body.extend_from_slice(&vec_n(2, &[]));
        body.extend_from_slice(&vec_n(2, &[]));
        let data = handshake_record(13, &body);
        let buf = dissect(&data);
        let obj = first_handshake(&buf);
        assert!(child(&buf, &obj, "supported_signature_algorithms").is_none());

        // TLS 1.3 Certificate entry with empty cert_data (cert_data<1..2^24-1>).
        let mut entry = vec_n(3, &[]);
        entry.extend_from_slice(&vec_n(2, &[]));
        let mut body = vec_n(1, &[]);
        body.extend_from_slice(&vec_n(3, &entry));
        let data = handshake_record(11, &body);
        let buf = dissect(&data);
        assert!(child(&buf, &first_handshake(&buf), "certificate_entries").is_none());

        // CertificateStatus with trailing bytes is not decoded.
        let mut body = vec![0x01];
        body.extend_from_slice(&vec_n(3, &[0x30]));
        body.push(0xff);
        let data = handshake_record(22, &body);
        let buf = dissect(&data);
        assert!(child(&buf, &first_handshake(&buf), "status_type").is_none());
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
