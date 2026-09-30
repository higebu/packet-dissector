//! TLS handshake message decoders.
//!
//! Walks the handshake messages in a Handshake record and decodes the
//! message bodies. Messages whose layout differs between TLS 1.2 and
//! TLS 1.3 (Certificate, CertificateRequest, NewSessionTicket) are
//! recognised by structure: the form whose length fields exactly fill the
//! message is used, and nothing is decoded if neither does.
//!
//! ## References
//! - RFC 9846, Section 4 (Handshake Protocol): <https://www.rfc-editor.org/rfc/rfc9846#section-4>
//! - RFC 5246, Section 7.4 (TLS 1.2 Handshake Protocol): <https://www.rfc-editor.org/rfc/rfc5246#section-7.4>
//! - RFC 5077, Section 3.3 (TLS 1.2 NewSessionTicket): <https://www.rfc-editor.org/rfc/rfc5077#section-3.3>
//! - RFC 6066, Section 8 (CertificateStatus): <https://www.rfc-editor.org/rfc/rfc6066#section-8>
//! - RFC 8422, Section 5.4 (ECDHE ServerKeyExchange): <https://www.rfc-editor.org/rfc/rfc8422#section-5.4>
//! - RFC 8879, Section 4 (CompressedCertificate): <https://www.rfc-editor.org/rfc/rfc8879#section-4>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u24;

use crate::extensions::{
    EXTENSION_CHILD_FIELDS, ExtContext, SupportedVersions, push_certificate_status,
    push_extensions_vector, push_u8_list, push_u16_list, push_vector_list,
};
use crate::names::{
    certificate_compression_algorithm_name, certificate_status_type_name, cipher_suite_name,
    client_certificate_type_name, ec_curve_type_name, key_update_request_name, named_group_name,
    signature_scheme_name,
};
use crate::reader::{Reader, Span, vectors_tile};
use crate::{
    FD_HANDSHAKE_MESSAGES, FD_OPAQUE_HANDSHAKE, FIELD_DESCRIPTORS, HANDSHAKE_HEADER_SIZE,
    MAX_FRAGMENTED_HANDSHAKE_LENGTH, handshake_type_name, is_wire_handshake_type,
    record_version_label, version_name, version_short_name,
};

/// Minimum ClientHello / ServerHello body size:
/// legacy_version(2) + random(32) + legacy_session_id length(1).
///
/// RFC 9846, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.2.2>
/// RFC 9846, Section 4.2.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.2.3>
const HELLO_MIN_BODY: usize = 2 + 32 + 1;

/// Size of the TLS `Random` field (32 bytes).
///
/// RFC 9846, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.2.2>
pub(crate) const RANDOM_SIZE: usize = 32;

/// ServerHello.random value that marks a HelloRetryRequest
/// (SHA-256 of "HelloRetryRequest").
///
/// RFC 9846, Section 4.2.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.2.3>
pub(crate) const HELLO_RETRY_REQUEST_RANDOM: [u8; RANDOM_SIZE] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

// HandshakeType values with a decoded body.
// RFC 9846, Section 4 — https://www.rfc-editor.org/rfc/rfc9846#section-4
pub(crate) const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
pub(crate) const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
/// `hello_verify_request(3)`, DTLS only.
/// RFC 6347, Section 4.2.1 — <https://www.rfc-editor.org/rfc/rfc6347#section-4.2.1>
pub(crate) const HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST: u8 = 3;
const HANDSHAKE_TYPE_NEW_SESSION_TICKET: u8 = 4;
const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
const HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE: u8 = 12;
const HANDSHAKE_TYPE_CERTIFICATE_REQUEST: u8 = 13;
const HANDSHAKE_TYPE_CERTIFICATE_STATUS: u8 = 22;
const HANDSHAKE_TYPE_KEY_UPDATE: u8 = 24;
const HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE: u8 = 25;

/// `ECCurveType` `named_curve(3)` — RFC 8422, Section 5.4 (<https://www.rfc-editor.org/rfc/rfc8422#section-5.4>).
const EC_CURVE_TYPE_NAMED_CURVE: u8 = 3;

/// Container descriptor for a handshake message Object.
///
/// The label resolves to the handshake type name, or "Hello Retry Request"
/// for a ServerHello carrying the HelloRetryRequest random
/// (RFC 9846, Section 4.2.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.2.3>).
pub(crate) static FD_HANDSHAKE: FieldDescriptor = FieldDescriptor {
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

/// Child fields of a TLS 1.3 `CertificateEntry` Object.
///
/// RFC 9846, Section 4.5.1 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.5.1>
static CERTIFICATE_ENTRY_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("cert_data", "Certificate Data", FieldType::Bytes),
    FieldDescriptor::new("extensions", "Extensions", FieldType::Array)
        .optional()
        .with_children(EXTENSION_CHILD_FIELDS),
];

/// A `CertificateEntry` in `certificate_entries`.
static FD_CERTIFICATE_ENTRY: FieldDescriptor =
    FieldDescriptor::new("certificate_entry", "Certificate Entry", FieldType::Object)
        .with_children(CERTIFICATE_ENTRY_FIELDS);

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
const HFD_CERTIFICATE_REQUEST_CONTEXT: usize = 12;
const HFD_CERTIFICATES: usize = 13;
const HFD_CERTIFICATE: usize = 14;
const HFD_CERTIFICATE_ENTRIES: usize = 15;
const HFD_CURVE_TYPE: usize = 16;
const HFD_NAMED_CURVE: usize = 17;
const HFD_PUBLIC_KEY: usize = 18;
const HFD_DH_P: usize = 19;
const HFD_DH_G: usize = 20;
const HFD_DH_YS: usize = 21;
const HFD_SIGNATURE_ALGORITHM: usize = 22;
const HFD_SIGNATURE: usize = 23;
const HFD_CERTIFICATE_TYPES: usize = 24;
const HFD_CERTIFICATE_TYPE: usize = 25;
const HFD_SUPPORTED_SIGNATURE_ALGORITHMS: usize = 26;
const HFD_CERTIFICATE_AUTHORITIES: usize = 27;
const HFD_DISTINGUISHED_NAME: usize = 28;
const HFD_TICKET_LIFETIME: usize = 29;
const HFD_TICKET_AGE_ADD: usize = 30;
const HFD_TICKET_NONCE: usize = 31;
const HFD_TICKET: usize = 32;
const HFD_REQUEST_UPDATE: usize = 33;
const HFD_ALGORITHM: usize = 34;
const HFD_UNCOMPRESSED_LENGTH: usize = 35;
const HFD_COMPRESSED_CERTIFICATE_MESSAGE: usize = 36;
const HFD_STATUS_TYPE: usize = 37;
const HFD_OCSP_RESPONSE: usize = 38;

/// Handshake `msg_type` field, shared by the TLS and DTLS handshake headers.
///
/// RFC 9846, Section 4 — <https://www.rfc-editor.org/rfc/rfc9846#section-4>
/// RFC 9147, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc9147#section-5.2>
pub(crate) const HANDSHAKE_TYPE_FIELD: FieldDescriptor = FieldDescriptor {
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
};

/// Handshake `length` field (bytes in the whole message), shared by the TLS
/// and DTLS handshake headers.
pub(crate) const HANDSHAKE_LENGTH_FIELD: FieldDescriptor =
    FieldDescriptor::new("length", "Handshake Length", FieldType::U32);

/// Number of entries in [`HANDSHAKE_BODY_FIELDS`].
pub(crate) const HANDSHAKE_BODY_FIELD_COUNT: usize = 36;

/// Number of TLS handshake header fields that precede the body fields in
/// [`HANDSHAKE_CHILD_FIELDS`].
const TLS_HANDSHAKE_HEADER_FIELD_COUNT: usize = 3;

/// Field descriptors for decoded handshake message bodies, shared by TLS
/// and DTLS: both use the same message bodies (RFC 9147, Section 5 —
/// <https://www.rfc-editor.org/rfc/rfc9147#section-5>).
pub(crate) const HANDSHAKE_BODY_FIELDS: [FieldDescriptor; HANDSHAKE_BODY_FIELD_COUNT] = [
    // --- ClientHello / ServerHello (RFC 9846, Section 4.2.2 and Section 4.2.3) ---
    // https://www.rfc-editor.org/rfc/rfc9846#section-4.2.2
    // https://www.rfc-editor.org/rfc/rfc9846#section-4.2.3
    named_field!("version", "Legacy Version", U16, version_name),
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
    // --- Certificate (RFC 5246, Section 7.4.2; RFC 9846, Section 4.5.1) ---
    // https://www.rfc-editor.org/rfc/rfc5246#section-7.4.2
    // https://www.rfc-editor.org/rfc/rfc9846#section-4.5.1
    FieldDescriptor::new(
        "certificate_request_context",
        "Certificate Request Context",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("certificates", "Certificates", FieldType::Array).optional(),
    FieldDescriptor::new("certificate", "Certificate", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "certificate_entries",
        "Certificate Entries",
        FieldType::Array,
    )
    .optional()
    .with_children(CERTIFICATE_ENTRY_FIELDS),
    // --- ServerKeyExchange (RFC 8422, Section 5.4; RFC 5246, Section 7.4.3) ---
    // https://www.rfc-editor.org/rfc/rfc8422#section-5.4
    // https://www.rfc-editor.org/rfc/rfc5246#section-7.4.3
    named_field!("curve_type", "Curve Type", U8, ec_curve_type_name),
    named_field!("named_curve", "Named Curve", U16, named_group_name),
    FieldDescriptor::new("public_key", "Public Key", FieldType::Bytes).optional(),
    FieldDescriptor::new("dh_p", "DH Prime", FieldType::Bytes).optional(),
    FieldDescriptor::new("dh_g", "DH Generator", FieldType::Bytes).optional(),
    FieldDescriptor::new("dh_ys", "DH Public Value", FieldType::Bytes).optional(),
    named_field!(
        "signature_algorithm",
        "Signature Algorithm",
        U16,
        signature_scheme_name
    ),
    FieldDescriptor::new("signature", "Signature", FieldType::Bytes).optional(),
    // --- CertificateRequest (RFC 5246, Section 7.4.4) ---
    // https://www.rfc-editor.org/rfc/rfc5246#section-7.4.4
    FieldDescriptor::new("certificate_types", "Certificate Types", FieldType::Array).optional(),
    named_field!(
        "certificate_type",
        "Certificate Type",
        U8,
        client_certificate_type_name
    ),
    FieldDescriptor::new(
        "supported_signature_algorithms",
        "Supported Signature Algorithms",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new(
        "certificate_authorities",
        "Certificate Authorities",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new("distinguished_name", "Distinguished Name", FieldType::Bytes).optional(),
    // --- NewSessionTicket (RFC 5077, Section 3.3; RFC 9846, Section 4.7.1) ---
    // https://www.rfc-editor.org/rfc/rfc5077#section-3.3
    // https://www.rfc-editor.org/rfc/rfc9846#section-4.7.1
    FieldDescriptor::new("ticket_lifetime", "Ticket Lifetime", FieldType::U32).optional(),
    FieldDescriptor::new("ticket_age_add", "Ticket Age Add", FieldType::U32).optional(),
    FieldDescriptor::new("ticket_nonce", "Ticket Nonce", FieldType::Bytes).optional(),
    FieldDescriptor::new("ticket", "Ticket", FieldType::Bytes).optional(),
    // --- KeyUpdate (RFC 9846, Section 4.7.3) ---
    // https://www.rfc-editor.org/rfc/rfc9846#section-4.7.3
    named_field!(
        "request_update",
        "Request Update",
        U8,
        key_update_request_name
    ),
    // --- CompressedCertificate (RFC 8879, Section 4) ---
    // https://www.rfc-editor.org/rfc/rfc8879#section-4
    named_field!(
        "algorithm",
        "Compression Algorithm",
        U16,
        certificate_compression_algorithm_name
    ),
    FieldDescriptor::new("uncompressed_length", "Uncompressed Length", FieldType::U32).optional(),
    FieldDescriptor::new(
        "compressed_certificate_message",
        "Compressed Certificate Message",
        FieldType::Bytes,
    )
    .optional(),
    // --- CertificateStatus (RFC 6066, Section 8) ---
    // https://www.rfc-editor.org/rfc/rfc6066#section-8
    named_field!(
        "status_type",
        "Status Type",
        U8,
        certificate_status_type_name
    ),
    FieldDescriptor::new("ocsp_response", "OCSP Response", FieldType::Bytes).optional(),
];

/// Concatenate two descriptor arrays at compile time; `N` must equal `A + B`.
pub(crate) const fn concat_fields<const A: usize, const B: usize, const N: usize>(
    head: [FieldDescriptor; A],
    tail: [FieldDescriptor; B],
) -> [FieldDescriptor; N] {
    assert!(A + B == N, "concat_fields: N must equal A + B");
    assert!(B > 0, "concat_fields: tail must not be empty");
    let mut out = [tail[0]; N];
    let mut i = 0;
    while i < A {
        out[i] = head[i];
        i += 1;
    }
    let mut j = 0;
    while j < B {
        out[A + j] = tail[j];
        j += 1;
    }
    out
}

/// Child field descriptors for handshake message objects within the
/// `handshake_messages` array.
///
/// RFC 9846, Section 4 — <https://www.rfc-editor.org/rfc/rfc9846#section-4>
pub(crate) static HANDSHAKE_CHILD_FIELDS: &[FieldDescriptor] = &concat_fields::<
    TLS_HANDSHAKE_HEADER_FIELD_COUNT,
    HANDSHAKE_BODY_FIELD_COUNT,
    { TLS_HANDSHAKE_HEADER_FIELD_COUNT + HANDSHAKE_BODY_FIELD_COUNT },
>(
    [
        HANDSHAKE_TYPE_FIELD,
        HANDSHAKE_LENGTH_FIELD,
        // Present only when the message continues in a following record: the
        // number of body bytes carried by this record.
        FieldDescriptor::new("fragment_length", "Fragment Length", FieldType::U32).optional(),
    ],
    HANDSHAKE_BODY_FIELDS,
);

/// Shorthand for a handshake child descriptor.
fn hfd(idx: usize) -> &'static FieldDescriptor {
    &HANDSHAKE_CHILD_FIELDS[idx]
}

/// Push a field read as `(bytes, range)` from a [`Reader`].
fn push_bytes<'pkt>(buf: &mut DissectBuffer<'pkt>, idx: usize, (bytes, range): Span<'pkt>) {
    buf.push_field(hfd(idx), FieldValue::Bytes(bytes), range);
}

/// What a ClientHello / ServerHello says about the protocol version.
#[derive(Clone, Copy)]
pub(crate) struct HelloVersion {
    /// `legacy_version` from the message body.
    legacy_version: u16,
    /// The `supported_versions` extension, if any.
    supported_versions: SupportedVersions,
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
        self.label_with(version_short_name)
    }

    /// Like [`label`](Self::label), with the version names given by
    /// `short_name` (TLS or DTLS).
    pub(crate) fn label_with(
        self,
        short_name: fn(u16) -> Option<&'static str>,
    ) -> Option<&'static str> {
        match self.supported_versions {
            SupportedVersions::Absent => short_name(self.legacy_version),
            SupportedVersions::Undetermined => None,
            SupportedVersions::Selected(v) => short_name(v),
        }
    }
}

/// Parse the trailing `extensions` vector of a Hello message body.
///
/// A body that ends right before the vector has no extensions (TLS 1.2 and
/// earlier, RFC 5246, Section 7.4.1.2 —
/// <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2>).
fn parse_hello_extensions<'pkt>(
    r: &mut Reader<'pkt>,
    ctx: ExtContext,
    buf: &mut DissectBuffer<'pkt>,
) -> SupportedVersions {
    if r.is_empty() {
        return SupportedVersions::Absent;
    }
    push_extensions_vector(r, hfd(HFD_EXTENSIONS), ctx, buf)
        .unwrap_or(SupportedVersions::Undetermined)
}

/// Push `legacy_version`, `random` and `legacy_session_id` shared by
/// ClientHello and ServerHello.
///
/// Returns `None` (pushing nothing) when the body is shorter than
/// [`HELLO_MIN_BODY`]. Otherwise returns the version information (with
/// `supported_versions` still undetermined), whether the Random marks a
/// HelloRetryRequest, and whether the session ID fits.
fn parse_hello_prefix<'pkt>(
    r: &mut Reader<'pkt>,
    handshake_type: u8,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<(HelloVersion, bool, bool)> {
    if r.remaining() < HELLO_MIN_BODY {
        return None;
    }
    let start = r.offset();
    let version = r.u16()?;
    buf.push_field(hfd(HFD_VERSION), FieldValue::U16(version), start..start + 2);
    let hello = HelloVersion {
        legacy_version: version,
        supported_versions: SupportedVersions::Undetermined,
    };

    let (random, random_range) = r.bytes(RANDOM_SIZE)?;
    buf.push_field(
        hfd(HFD_RANDOM),
        FieldValue::Bytes(random),
        random_range.clone(),
    );
    // RFC 9846, Section 4.2.3 — https://www.rfc-editor.org/rfc/rfc9846#section-4.2.3
    // "Upon receiving a message with type server_hello, implementations MUST
    // first examine the Random value and, if it matches this value, process
    // it as described in Section 4.2.4."
    let hrr = handshake_type == HANDSHAKE_TYPE_SERVER_HELLO && random == HELLO_RETRY_REQUEST_RANDOM;
    if hrr {
        buf.push_field(
            hfd(HFD_HELLO_RETRY_REQUEST),
            FieldValue::U8(1),
            random_range,
        );
    }

    let Some(session_id) = r.vector(1) else {
        return Some((hello, hrr, false));
    };
    push_bytes(buf, HFD_SESSION_ID, session_id);
    Some((hello, hrr, true))
}

/// Parse a ClientHello handshake body and append fields.
///
/// With `dtls_cookie`, the body is a DTLS ClientHello, which carries a
/// cookie after the session ID; the cookie is pushed with that descriptor.
///
/// RFC 5246, Section 7.4.1.2 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2>
/// RFC 9846, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.2.2>
/// RFC 6347, Section 4.2.1 — <https://www.rfc-editor.org/rfc/rfc6347#section-4.2.1>
/// RFC 9147, Section 5.3 — <https://www.rfc-editor.org/rfc/rfc9147#section-5.3>
fn parse_client_hello<'pkt>(
    body: &'pkt [u8],
    offset: usize,
    dtls_cookie: Option<&'static FieldDescriptor>,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<HelloVersion> {
    let mut r = Reader::new(body, offset);
    let (mut hello, _, complete) = parse_hello_prefix(&mut r, HANDSHAKE_TYPE_CLIENT_HELLO, buf)?;
    if !complete {
        return Some(hello);
    }

    // RFC 6347, Section 4.2.1 — https://www.rfc-editor.org/rfc/rfc6347#section-4.2.1
    // opaque cookie<0..2^8-1>;                             // New field
    if let Some(cookie_fd) = dtls_cookie {
        let Some((cookie, range)) = r.vector(1) else {
            return Some(hello);
        };
        buf.push_field(cookie_fd, FieldValue::Bytes(cookie), range);
    }

    // RFC 9846, Section 4.2.2 — https://www.rfc-editor.org/rfc/rfc9846#section-4.2.2
    // CipherSuite cipher_suites<2..2^16-2>;
    let Some((suites, range)) = r.vector(2).filter(|(s, _)| s.len() % 2 == 0) else {
        return Some(hello);
    };
    push_u16_list(
        suites,
        range.start,
        hfd(HFD_CIPHER_SUITES),
        hfd(HFD_CIPHER_SUITE),
        buf,
    );

    // RFC 9846, Section 4.2.2 — https://www.rfc-editor.org/rfc/rfc9846#section-4.2.2
    // opaque legacy_compression_methods<1..2^8-1>;
    let Some(comp) = r.vector(1) else {
        return Some(hello);
    };
    push_bytes(buf, HFD_COMPRESSION_METHODS, comp);

    hello.supported_versions = parse_hello_extensions(&mut r, ExtContext::ClientHello, buf);
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
    let mut r = Reader::new(body, offset);
    let (mut hello, hrr, complete) = parse_hello_prefix(&mut r, HANDSHAKE_TYPE_SERVER_HELLO, buf)?;
    if !complete {
        return Some(hello);
    }

    let start = r.offset();
    let Some(cs) = r.u16() else {
        return Some(hello);
    };
    buf.push_field(hfd(HFD_CIPHER_SUITE), FieldValue::U16(cs), start..start + 2);

    let start = r.offset();
    let Some(comp) = r.u8() else {
        return Some(hello);
    };
    buf.push_field(
        hfd(HFD_COMPRESSION_METHOD),
        FieldValue::U8(comp),
        start..start + 1,
    );

    let ctx = if hrr {
        ExtContext::HelloRetryRequest
    } else {
        ExtContext::ServerHello
    };
    hello.supported_versions = parse_hello_extensions(&mut r, ctx, buf);
    Some(hello)
}

/// Read a TLS 1.3 `CertificateEntry` with non-empty `cert_data`; returns
/// the certificate and the packet offset of the end of the entry.
///
/// RFC 9846, Section 4.5.1 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.5.1>
fn read_certificate_entry<'pkt>(r: &mut Reader<'pkt>) -> Option<(Span<'pkt>, usize)> {
    let mut probe = *r;
    let cert = probe.vector(3).filter(|(c, _)| !c.is_empty())?;
    probe.vector(2)?;
    *r = probe;
    Some((cert, probe.offset()))
}

/// Parse a Certificate body.
///
/// ```text
/// RFC 5246, Section 7.4.2 — https://www.rfc-editor.org/rfc/rfc5246#section-7.4.2
///
/// opaque ASN.1Cert<1..2^24-1>;
///
/// struct {
///     ASN.1Cert certificate_list<0..2^24-1>;
/// } Certificate;
///
/// RFC 9846, Section 4.5.1 — https://www.rfc-editor.org/rfc/rfc9846#section-4.5.1
///
/// struct {
///     select (certificate_type) {
///         case RawPublicKey:
///           opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
///         case X509:
///           opaque cert_data<1..2^24-1>;
///     };
///     Extension extensions<0..2^16-1>;
/// } CertificateEntry;
///
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
/// ```
///
/// The X.509 data is not parsed.
fn parse_certificate<'pkt>(body: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    // TLS 1.2 form: a list of ASN.1Cert that exactly fills the body.
    let mut r = Reader::new(body, offset);
    if let Some(list) = r.vector(3) {
        if r.is_empty() && vectors_tile(list.0, 3, 1) {
            push_vector_list(list, 3, hfd(HFD_CERTIFICATES), hfd(HFD_CERTIFICATE), buf);
            return;
        }
    }

    // TLS 1.3 form.
    let mut r = Reader::new(body, offset);
    let (Some(context), Some((list, list_range))) = (r.vector(1), r.vector(3)) else {
        return;
    };
    if !r.is_empty() {
        return;
    }
    let mut check = Reader::new(list, 0);
    while !check.is_empty() {
        if read_certificate_entry(&mut check).is_none() {
            return;
        }
    }
    push_bytes(buf, HFD_CERTIFICATE_REQUEST_CONTEXT, context);
    let idx = buf.begin_container(
        hfd(HFD_CERTIFICATE_ENTRIES),
        FieldValue::Array(0..0),
        list_range.clone(),
    );
    let mut r = Reader::new(list, list_range.start);
    loop {
        let start = r.offset();
        let mut probe = r;
        let Some((cert, end)) = read_certificate_entry(&mut probe) else {
            break;
        };
        let obj = buf.begin_container(&FD_CERTIFICATE_ENTRY, FieldValue::Object(0..0), start..end);
        buf.push_field(
            &CERTIFICATE_ENTRY_FIELDS[0],
            FieldValue::Bytes(cert.0),
            cert.1,
        );
        let _ = r.vector(3);
        let _ = push_extensions_vector(
            &mut r,
            &CERTIFICATE_ENTRY_FIELDS[1],
            ExtContext::Certificate,
            buf,
        );
        buf.end_container(obj);
    }
    buf.end_container(idx);
}

/// The signature that ends a ServerKeyExchange.
struct SignedParams<'pkt> {
    /// TLS 1.2 `SignatureAndHashAlgorithm` and its offset, if present.
    algorithm: Option<(u16, usize)>,
    /// The signature bytes and their range.
    signature: Span<'pkt>,
}

/// Read the signature at the end of a ServerKeyExchange; it must fill the
/// rest of the body.
///
/// TLS 1.2 prefixes the signature with a `SignatureAndHashAlgorithm`
/// (RFC 5246, Section 4.7 — <https://www.rfc-editor.org/rfc/rfc5246#section-4.7>);
/// TLS 1.0 / 1.1 do not
/// (RFC 4346, Section 7.4.3 — <https://www.rfc-editor.org/rfc/rfc4346#section-7.4.3>).
fn read_signed_params<'pkt>(r: Reader<'pkt>) -> Option<SignedParams<'pkt>> {
    let mut tls12 = r;
    let start = tls12.offset();
    if let (Some(alg), Some(signature)) = (tls12.u16(), tls12.vector(2)) {
        if tls12.is_empty() {
            return Some(SignedParams {
                algorithm: Some((alg, start)),
                signature,
            });
        }
    }
    let mut legacy = r;
    let signature = legacy.vector(2)?;
    legacy.is_empty().then_some(SignedParams {
        algorithm: None,
        signature,
    })
}

/// Push the fields of a [`SignedParams`].
fn push_signed_params<'pkt>(signed: SignedParams<'pkt>, buf: &mut DissectBuffer<'pkt>) {
    if let Some((alg, start)) = signed.algorithm {
        buf.push_field(
            hfd(HFD_SIGNATURE_ALGORITHM),
            FieldValue::U16(alg),
            start..start + 2,
        );
    }
    push_bytes(buf, HFD_SIGNATURE, signed.signature);
}

/// Parse a ServerKeyExchange body for ECDHE or DHE key exchange.
///
/// ```text
/// RFC 8422, Section 5.4 — https://www.rfc-editor.org/rfc/rfc8422#section-5.4
///
/// struct {
///     ECCurveType    curve_type;
///     select (curve_type) {
///         case named_curve:
///             NamedCurve namedcurve;
///     };
/// } ECParameters;
///
/// struct {
///     opaque point <1..2^8-1>;
/// } ECPoint;
///
/// struct {
///     ECParameters    curve_params;
///     ECPoint         public;
/// } ServerECDHParams;
///
/// RFC 5246, Section 7.4.3 — https://www.rfc-editor.org/rfc/rfc5246#section-7.4.3
///
/// struct {
///     opaque dh_p<1..2^16-1>;
///     opaque dh_g<1..2^16-1>;
///     opaque dh_Ys<1..2^16-1>;
/// } ServerDHParams;
/// ```
///
/// Both are followed by a signature, which must fill the rest of the body
/// (see [`read_signed_params`]); this keeps DHE parameters whose `dh_p`
/// length starts with 0x03 from being read as ECDHE. Other key exchange
/// methods (anonymous, PSK, SRP, RSA_EXPORT) are not decoded; a DHE_PSK body
/// (psk_identity_hint followed by ServerDHParams) can still match the TLS
/// 1.0 DHE layout, since no signature algorithm distinguishes them.
fn parse_server_key_exchange<'pkt>(body: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let mut ecdhe = Reader::new(body, offset);
    if let (Some(EC_CURVE_TYPE_NAMED_CURVE), Some(curve), Some(point)) =
        (ecdhe.u8(), ecdhe.u16(), ecdhe.vector(1))
    {
        if let Some(signed) = read_signed_params(ecdhe).filter(|_| !point.0.is_empty()) {
            buf.push_field(
                hfd(HFD_CURVE_TYPE),
                FieldValue::U8(EC_CURVE_TYPE_NAMED_CURVE),
                offset..offset + 1,
            );
            buf.push_field(
                hfd(HFD_NAMED_CURVE),
                FieldValue::U16(curve),
                offset + 1..offset + 3,
            );
            push_bytes(buf, HFD_PUBLIC_KEY, point);
            push_signed_params(signed, buf);
            return;
        }
    }

    let mut dhe = Reader::new(body, offset);
    let (Some(p), Some(g), Some(ys)) = (dhe.vector(2), dhe.vector(2), dhe.vector(2)) else {
        return;
    };
    if p.0.is_empty() || g.0.is_empty() || ys.0.is_empty() {
        return;
    }
    let Some(signed) = read_signed_params(dhe) else {
        return;
    };
    push_bytes(buf, HFD_DH_P, p);
    push_bytes(buf, HFD_DH_G, g);
    push_bytes(buf, HFD_DH_YS, ys);
    push_signed_params(signed, buf);
}

/// Parse a CertificateRequest body.
///
/// ```text
/// RFC 5246, Section 7.4.4 — https://www.rfc-editor.org/rfc/rfc5246#section-7.4.4
///
/// struct {
///     ClientCertificateType certificate_types<1..2^8-1>;
///     SignatureAndHashAlgorithm
///       supported_signature_algorithms<2^16-1>;
///     DistinguishedName certificate_authorities<0..2^16-1>;
/// } CertificateRequest;
///
/// RFC 9846, Section 4.4.2 — https://www.rfc-editor.org/rfc/rfc9846#section-4.4.2
///
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     Extension extensions<0..2^16-1>;
/// } CertificateRequest;
/// ```
///
/// TLS 1.0 / 1.1 omit `supported_signature_algorithms`
/// (RFC 4346, Section 7.4.4 — <https://www.rfc-editor.org/rfc/rfc4346#section-7.4.4>).
fn parse_certificate_request<'pkt>(body: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    // TLS 1.2 form.
    let mut r = Reader::new(body, offset);
    if let (Some(types), Some(algs), Some(cas)) = (r.vector(1), r.vector(2), r.vector(2)) {
        if r.is_empty()
            && !types.0.is_empty()
            && !algs.0.is_empty()
            && algs.0.len() % 2 == 0
            && vectors_tile(cas.0, 2, 1)
        {
            push_u8_list(
                types.0,
                types.1.start,
                hfd(HFD_CERTIFICATE_TYPES),
                hfd(HFD_CERTIFICATE_TYPE),
                buf,
            );
            push_u16_list(
                algs.0,
                algs.1.start,
                hfd(HFD_SUPPORTED_SIGNATURE_ALGORITHMS),
                hfd(HFD_SIGNATURE_ALGORITHM),
                buf,
            );
            push_vector_list(
                cas,
                2,
                hfd(HFD_CERTIFICATE_AUTHORITIES),
                hfd(HFD_DISTINGUISHED_NAME),
                buf,
            );
            return;
        }
    }

    // TLS 1.0 / 1.1 form.
    let mut r = Reader::new(body, offset);
    if let (Some(types), Some(cas)) = (r.vector(1), r.vector(2)) {
        if r.is_empty() && !types.0.is_empty() && vectors_tile(cas.0, 2, 1) {
            push_u8_list(
                types.0,
                types.1.start,
                hfd(HFD_CERTIFICATE_TYPES),
                hfd(HFD_CERTIFICATE_TYPE),
                buf,
            );
            push_vector_list(
                cas,
                2,
                hfd(HFD_CERTIFICATE_AUTHORITIES),
                hfd(HFD_DISTINGUISHED_NAME),
                buf,
            );
            return;
        }
    }

    // TLS 1.3 form.
    let mut r = Reader::new(body, offset);
    let Some(context) = r.vector(1) else {
        return;
    };
    let mut probe = r;
    if probe.vector(2).is_none() || !probe.is_empty() {
        return;
    }
    push_bytes(buf, HFD_CERTIFICATE_REQUEST_CONTEXT, context);
    let _ = push_extensions_vector(
        &mut r,
        hfd(HFD_EXTENSIONS),
        ExtContext::CertificateRequest,
        buf,
    );
}

/// Parse a NewSessionTicket body.
///
/// ```text
/// RFC 5077, Section 3.3 — https://www.rfc-editor.org/rfc/rfc5077#section-3.3
///
/// struct {
///     uint32 ticket_lifetime_hint;
///     opaque ticket<0..2^16-1>;
/// } NewSessionTicket;
///
/// RFC 9846, Section 4.7.1 — https://www.rfc-editor.org/rfc/rfc9846#section-4.7.1
///
/// struct {
///     uint32 ticket_lifetime;
///     uint32 ticket_age_add;
///     opaque ticket_nonce<0..255>;
///     opaque ticket<1..2^16-1>;
///     Extension extensions<0..2^16-2>;
/// } NewSessionTicket;
/// ```
fn parse_new_session_ticket<'pkt>(body: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    // TLS 1.2 form.
    let mut r = Reader::new(body, offset);
    if let (Some(lifetime), Some(ticket)) = (r.u32(), r.vector(2)) {
        if r.is_empty() {
            buf.push_field(
                hfd(HFD_TICKET_LIFETIME),
                FieldValue::U32(lifetime),
                offset..offset + 4,
            );
            push_bytes(buf, HFD_TICKET, ticket);
            return;
        }
    }

    // TLS 1.3 form.
    let mut r = Reader::new(body, offset);
    let (Some(lifetime), Some(age_add), Some(nonce), Some(ticket)) =
        (r.u32(), r.u32(), r.vector(1), r.vector(2))
    else {
        return;
    };
    let mut probe = r;
    if ticket.0.is_empty() || probe.vector(2).is_none() || !probe.is_empty() {
        return;
    }
    buf.push_field(
        hfd(HFD_TICKET_LIFETIME),
        FieldValue::U32(lifetime),
        offset..offset + 4,
    );
    buf.push_field(
        hfd(HFD_TICKET_AGE_ADD),
        FieldValue::U32(age_add),
        offset + 4..offset + 8,
    );
    push_bytes(buf, HFD_TICKET_NONCE, nonce);
    push_bytes(buf, HFD_TICKET, ticket);
    let _ = push_extensions_vector(
        &mut r,
        hfd(HFD_EXTENSIONS),
        ExtContext::NewSessionTicket,
        buf,
    );
}

/// Parse an EncryptedExtensions body.
///
/// ```text
/// RFC 9846, Section 4.4.1 — https://www.rfc-editor.org/rfc/rfc9846#section-4.4.1
///
/// struct {
///     Extension extensions<0..2^16-1>;
/// } EncryptedExtensions;
/// ```
fn parse_encrypted_extensions<'pkt>(
    body: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    let mut r = Reader::new(body, offset);
    let mut probe = r;
    if probe.vector(2).is_some() && probe.is_empty() {
        let _ = push_extensions_vector(
            &mut r,
            hfd(HFD_EXTENSIONS),
            ExtContext::EncryptedExtensions,
            buf,
        );
    }
}

/// Parse a KeyUpdate body.
///
/// ```text
/// RFC 9846, Section 4.7.3 — https://www.rfc-editor.org/rfc/rfc9846#section-4.7.3
///
/// struct {
///     KeyUpdateRequest request_update;
/// } KeyUpdate;
/// ```
fn parse_key_update<'pkt>(body: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    if let [request] = body {
        buf.push_field(
            hfd(HFD_REQUEST_UPDATE),
            FieldValue::U8(*request),
            offset..offset + 1,
        );
    }
}

/// Parse a CompressedCertificate body.
///
/// ```text
/// RFC 8879, Section 4 — https://www.rfc-editor.org/rfc/rfc8879#section-4
///
/// struct {
///      CertificateCompressionAlgorithm algorithm;
///      uint24 uncompressed_length;
///      opaque compressed_certificate_message<1..2^24-1>;
/// } CompressedCertificate;
/// ```
fn parse_compressed_certificate<'pkt>(
    body: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    let mut r = Reader::new(body, offset);
    let (Some(algorithm), Some(uncompressed_length), Some(message)) =
        (r.u16(), r.uint(3), r.vector(3))
    else {
        return;
    };
    if !r.is_empty() {
        return;
    }
    buf.push_field(
        hfd(HFD_ALGORITHM),
        FieldValue::U16(algorithm),
        offset..offset + 2,
    );
    buf.push_field(
        hfd(HFD_UNCOMPRESSED_LENGTH),
        FieldValue::U32(uncompressed_length),
        offset + 2..offset + 5,
    );
    push_bytes(buf, HFD_COMPRESSED_CERTIFICATE_MESSAGE, message);
}

/// Parse a HelloVerifyRequest body (DTLS only).
///
/// ```text
/// RFC 6347, Section 4.2.1 — https://www.rfc-editor.org/rfc/rfc6347#section-4.2.1
///
/// struct {
///   ProtocolVersion server_version;
///   opaque cookie<0..2^8-1>;
/// } HelloVerifyRequest;
/// ```
///
/// Nothing is pushed unless the two fields exactly fill the body.
fn parse_hello_verify_request<'pkt>(
    body: &'pkt [u8],
    offset: usize,
    cookie_fd: &'static FieldDescriptor,
    buf: &mut DissectBuffer<'pkt>,
) {
    let mut r = Reader::new(body, offset);
    let (Some(version), Some((cookie, range))) = (r.u16(), r.vector(1)) else {
        return;
    };
    if !r.is_empty() {
        return;
    }
    buf.push_field(
        hfd(HFD_VERSION),
        FieldValue::U16(version),
        offset..offset + 2,
    );
    buf.push_field(cookie_fd, FieldValue::Bytes(cookie), range);
}

/// Decode the body of one complete handshake message. Returns version
/// information for ClientHello / ServerHello.
///
/// `dtls_cookie` is `Some` for DTLS: it is the descriptor of the `cookie`
/// field of ClientHello and HelloVerifyRequest, which only exist in DTLS
/// (RFC 6347, Section 4.2.1 — <https://www.rfc-editor.org/rfc/rfc6347#section-4.2.1>).
pub(crate) fn parse_body<'pkt>(
    ht: u8,
    body: &'pkt [u8],
    offset: usize,
    dtls_cookie: Option<&'static FieldDescriptor>,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<HelloVersion> {
    match ht {
        HANDSHAKE_TYPE_CLIENT_HELLO => return parse_client_hello(body, offset, dtls_cookie, buf),
        HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST => {
            if let Some(cookie_fd) = dtls_cookie {
                parse_hello_verify_request(body, offset, cookie_fd, buf);
            }
        }
        HANDSHAKE_TYPE_SERVER_HELLO => return parse_server_hello(body, offset, buf),
        HANDSHAKE_TYPE_NEW_SESSION_TICKET => parse_new_session_ticket(body, offset, buf),
        HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS => parse_encrypted_extensions(body, offset, buf),
        HANDSHAKE_TYPE_CERTIFICATE => parse_certificate(body, offset, buf),
        HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE => parse_server_key_exchange(body, offset, buf),
        HANDSHAKE_TYPE_CERTIFICATE_REQUEST => parse_certificate_request(body, offset, buf),
        // RFC 6066, Section 8 — https://www.rfc-editor.org/rfc/rfc6066#section-8
        HANDSHAKE_TYPE_CERTIFICATE_STATUS => push_certificate_status(
            body,
            offset,
            hfd(HFD_STATUS_TYPE),
            hfd(HFD_OCSP_RESPONSE),
            buf,
        ),
        HANDSHAKE_TYPE_KEY_UPDATE => parse_key_update(body, offset, buf),
        HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE => parse_compressed_certificate(body, offset, buf),
        _ => {}
    }
    None
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
pub(crate) fn dissect_handshake_record<'pkt>(
    payload: &'pkt [u8],
    offset: usize,
    record_version: u16,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<&'static str> {
    if payload.is_empty() {
        // RFC 9846, Section 5.1 (https://www.rfc-editor.org/rfc/rfc9846#section-5.1): "Implementations MUST NOT send zero-length
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
            hfd(HFD_TYPE),
            FieldValue::U8(ht),
            offset + pos..offset + pos + 1,
        );
        buf.push_field(
            hfd(HFD_LENGTH),
            FieldValue::U32(msg_len),
            offset + pos + 1..offset + body_start,
        );
        if fragmented {
            // The rest of the message is in the following record(s); a
            // partial body is not decoded.
            buf.push_field(
                hfd(HFD_FRAGMENT_LENGTH),
                FieldValue::U32(body_len as u32),
                body_offset..offset + body_end,
            );
        } else {
            let parsed = parse_body(ht, body, body_offset, None, buf);
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
