//! TLS extension decoders.
//!
//! Every extension keeps its raw `data`; the decoders below add structured
//! fields when the extension body is well formed. A malformed body is left
//! as raw data only.
//!
//! ## References
//! - RFC 9846, Section 4.3 (Extensions): <https://www.rfc-editor.org/rfc/rfc9846#section-4.3>
//! - RFC 6066 (server_name, status_request): <https://www.rfc-editor.org/rfc/rfc6066>
//! - RFC 7301 (ALPN): <https://www.rfc-editor.org/rfc/rfc7301>
//! - RFC 8422 (ec_point_formats): <https://www.rfc-editor.org/rfc/rfc8422>
//! - RFC 8449 (record_size_limit): <https://www.rfc-editor.org/rfc/rfc8449>
//! - RFC 8701 (GREASE): <https://www.rfc-editor.org/rfc/rfc8701>
//! - RFC 8879 (compress_certificate): <https://www.rfc-editor.org/rfc/rfc8879>
//! - RFC 9001, Section 8.2 (quic_transport_parameters): <https://www.rfc-editor.org/rfc/rfc9001#section-8.2>
//! - RFC 9000, Section 18 (Transport Parameter Encoding): <https://www.rfc-editor.org/rfc/rfc9000#section-18>
//! - RFC 9849, Section 5 (encrypted_client_hello): <https://www.rfc-editor.org/rfc/rfc9849#section-5>

use core::ops::Range;

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;

use crate::names::{
    certificate_compression_algorithm_name, certificate_status_type_name, ec_point_format_name,
    ech_client_hello_type_name, extension_type_name, hpke_aead_name, hpke_kdf_name,
    named_group_name, psk_ke_mode_name, quic_transport_parameter_name, signature_scheme_name,
};
use crate::reader::{Reader, Span, vectors_tile, whole_vector};
use crate::supported_version_name;

/// The message an extension block belongs to. Several extensions have a
/// different body depending on the enclosing message
/// (RFC 9846, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3>).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtContext {
    /// ClientHello.
    ClientHello,
    /// ServerHello.
    ServerHello,
    /// HelloRetryRequest (a ServerHello with the special Random).
    HelloRetryRequest,
    /// EncryptedExtensions.
    EncryptedExtensions,
    /// A CertificateEntry in a TLS 1.3 Certificate message.
    Certificate,
    /// A TLS 1.3 CertificateRequest.
    CertificateRequest,
    /// A TLS 1.3 NewSessionTicket.
    NewSessionTicket,
}

/// State of the `supported_versions` extension in an extension block.
///
/// RFC 9846, Section 4.3.1 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3.1>
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SupportedVersions {
    /// The extension is not present.
    Absent,
    /// The extension is present without selecting a single version (a
    /// ClientHello list, or a malformed ServerHello value), or the message is
    /// too malformed to tell whether it is present.
    Undetermined,
    /// A ServerHello / HelloRetryRequest `selected_version`.
    Selected(u16),
}

// ExtensionType values decoded below.
// RFC 9846, Section 4.3 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3
const EXT_SERVER_NAME: u16 = 0;
const EXT_STATUS_REQUEST: u16 = 5;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_COMPRESS_CERTIFICATE: u16 = 27;
const EXT_RECORD_SIZE_LIMIT: u16 = 28;
const EXT_PRE_SHARED_KEY: u16 = 41;
const EXT_EARLY_DATA: u16 = 42;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
const EXT_SIGNATURE_ALGORITHMS_CERT: u16 = 50;
const EXT_KEY_SHARE: u16 = 51;
const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 57;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// `CertificateStatusType` `ocsp(1)` — RFC 6066, Section 8 (<https://www.rfc-editor.org/rfc/rfc6066#section-8>).
const STATUS_TYPE_OCSP: u8 = 1;

/// `ECHClientHelloType` `outer(0)` — RFC 9849, Section 5 (<https://www.rfc-editor.org/rfc/rfc9849#section-5>).
const ECH_TYPE_OUTER: u8 = 0;

/// Container descriptor for an extension Object.
///
/// The outer label resolves to the extension name (e.g. `server_name`) by
/// looking up the inner `type` field, avoiding collision with the inner
/// "Extension Type" label.
pub(crate) static FD_EXTENSION: FieldDescriptor = FieldDescriptor {
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

/// Child fields of a `KeyShareEntry` Object.
///
/// RFC 9846, Section 4.3.8 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3.8>
static KEY_SHARE_ENTRY_FIELDS: &[FieldDescriptor] = &[
    named_field!("group", "Group", U16, named_group_name),
    FieldDescriptor::new("key_exchange", "Key Exchange", FieldType::Bytes),
];

/// Display function for a `KeyShareEntry` Object: the group name.
fn key_share_entry_display(
    v: &FieldValue<'_>,
    children: &[packet_dissector_core::field::Field<'_>],
) -> Option<&'static str> {
    match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("group", FieldValue::U16(g)) => Some(named_group_name(*g)),
            _ => None,
        }),
        _ => None,
    }
}

/// A `KeyShareEntry` in `client_shares`.
static FD_KEY_SHARE_ENTRY: FieldDescriptor = FieldDescriptor {
    name: "key_share_entry",
    display_name: "Key Share Entry",
    field_type: FieldType::Object,
    optional: false,
    children: Some(KEY_SHARE_ENTRY_FIELDS),
    display_fn: Some(key_share_entry_display),
    format_fn: None,
};

/// Child fields of a `PskIdentity` Object.
///
/// RFC 9846, Section 4.3.11 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3.11>
static PSK_IDENTITY_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("identity", "Identity", FieldType::Bytes),
    FieldDescriptor::new(
        "obfuscated_ticket_age",
        "Obfuscated Ticket Age",
        FieldType::U32,
    ),
];

/// A `PskIdentity` in `identities`.
static FD_PSK_IDENTITY: FieldDescriptor =
    FieldDescriptor::new("psk_identity", "PSK Identity", FieldType::Object)
        .with_children(PSK_IDENTITY_FIELDS);

/// Child fields of a QUIC transport parameter Object.
///
/// RFC 9000, Section 18 — <https://www.rfc-editor.org/rfc/rfc9000#section-18>
static TRANSPORT_PARAMETER_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "id",
        display_name: "Transport Parameter ID",
        field_type: FieldType::U64,
        optional: false,
        children: None,
        display_fn: Some(|v, _| match v {
            FieldValue::U64(id) => Some(quic_transport_parameter_name(*id)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Transport Parameter Length", FieldType::U64),
    FieldDescriptor::new("value", "Transport Parameter Value", FieldType::Bytes),
];

/// A transport parameter in `transport_parameters`; labelled by its ID.
static FD_TRANSPORT_PARAMETER: FieldDescriptor = FieldDescriptor {
    name: "transport_parameter",
    display_name: "Transport Parameter",
    field_type: FieldType::Object,
    optional: false,
    children: Some(TRANSPORT_PARAMETER_FIELDS),
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("id", FieldValue::U64(id)) => Some(quic_transport_parameter_name(*id)),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Field descriptor indices for [`EXTENSION_CHILD_FIELDS`].
const EFD_TYPE: usize = 0;
const EFD_LENGTH: usize = 1;
const EFD_DATA: usize = 2;
const EFD_SERVER_NAME: usize = 3;
const EFD_VERSIONS: usize = 4;
const EFD_VERSION: usize = 5;
const EFD_SELECTED_VERSION: usize = 6;
const EFD_PROTOCOL_NAMES: usize = 7;
const EFD_PROTOCOL_NAME: usize = 8;
const EFD_NAMED_GROUPS: usize = 9;
const EFD_NAMED_GROUP: usize = 10;
const EFD_SIGNATURE_SCHEMES: usize = 11;
const EFD_SIGNATURE_SCHEME: usize = 12;
const EFD_CLIENT_SHARES: usize = 13;
const EFD_SERVER_SHARE: usize = 14;
const EFD_SELECTED_GROUP: usize = 15;
const EFD_KE_MODES: usize = 16;
const EFD_KE_MODE: usize = 17;
const EFD_IDENTITIES: usize = 18;
const EFD_BINDERS: usize = 19;
const EFD_BINDER: usize = 20;
const EFD_SELECTED_IDENTITY: usize = 21;
const EFD_EC_POINT_FORMATS: usize = 22;
const EFD_EC_POINT_FORMAT: usize = 23;
const EFD_STATUS_TYPE: usize = 24;
const EFD_RESPONDER_ID_LIST: usize = 25;
const EFD_RESPONDER_ID: usize = 26;
const EFD_REQUEST_EXTENSIONS: usize = 27;
const EFD_OCSP_RESPONSE: usize = 28;
const EFD_RECORD_SIZE_LIMIT: usize = 29;
const EFD_ALGORITHMS: usize = 30;
const EFD_ALGORITHM: usize = 31;
const EFD_TRANSPORT_PARAMETERS: usize = 32;
const EFD_ECH_TYPE: usize = 33;
const EFD_KDF_ID: usize = 34;
const EFD_AEAD_ID: usize = 35;
const EFD_CONFIG_ID: usize = 36;
const EFD_ENC: usize = 37;
const EFD_PAYLOAD: usize = 38;
const EFD_CONFIRMATION: usize = 39;
const EFD_RETRY_CONFIGS: usize = 40;
const EFD_MAX_EARLY_DATA_SIZE: usize = 41;

/// Child field descriptors for extension objects within an `extensions` array.
///
/// RFC 9846, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3>
pub(crate) static EXTENSION_CHILD_FIELDS: &[FieldDescriptor] = &[
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
    // RFC 6066, Section 3 (https://www.rfc-editor.org/rfc/rfc6066#section-3)
    FieldDescriptor::new("server_name", "Server Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    // RFC 9846, Section 4.3.1 (https://www.rfc-editor.org/rfc/rfc9846#section-4.3.1)
    FieldDescriptor::new("versions", "Supported Versions", FieldType::Array).optional(),
    named_field!("version", "Supported Version", U16, supported_version_name),
    named_field!(
        "selected_version",
        "Selected Version",
        U16,
        supported_version_name
    ),
    // RFC 7301, Section 3.1 (https://www.rfc-editor.org/rfc/rfc7301#section-3.1)
    FieldDescriptor::new("protocol_names", "Protocol Names", FieldType::Array).optional(),
    FieldDescriptor::new("protocol_name", "Protocol Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    // RFC 9846, Section 4.3.7 (https://www.rfc-editor.org/rfc/rfc9846#section-4.3.7)
    FieldDescriptor::new("named_groups", "Named Groups", FieldType::Array).optional(),
    named_field!("named_group", "Named Group", U16, named_group_name),
    // RFC 9846, Section 4.3.3 (https://www.rfc-editor.org/rfc/rfc9846#section-4.3.3)
    FieldDescriptor::new("signature_schemes", "Signature Schemes", FieldType::Array).optional(),
    named_field!(
        "signature_scheme",
        "Signature Scheme",
        U16,
        signature_scheme_name
    ),
    // RFC 9846, Section 4.3.8 (https://www.rfc-editor.org/rfc/rfc9846#section-4.3.8)
    FieldDescriptor::new("client_shares", "Client Shares", FieldType::Array)
        .optional()
        .with_children(KEY_SHARE_ENTRY_FIELDS),
    FieldDescriptor {
        name: "server_share",
        display_name: "Server Share",
        field_type: FieldType::Object,
        optional: true,
        children: Some(KEY_SHARE_ENTRY_FIELDS),
        display_fn: Some(key_share_entry_display),
        format_fn: None,
    },
    named_field!("selected_group", "Selected Group", U16, named_group_name),
    // RFC 9846, Section 4.3.9 (https://www.rfc-editor.org/rfc/rfc9846#section-4.3.9)
    FieldDescriptor::new("ke_modes", "PSK Key Exchange Modes", FieldType::Array).optional(),
    named_field!("ke_mode", "PSK Key Exchange Mode", U8, psk_ke_mode_name),
    // RFC 9846, Section 4.3.11 (https://www.rfc-editor.org/rfc/rfc9846#section-4.3.11)
    FieldDescriptor::new("identities", "Identities", FieldType::Array)
        .optional()
        .with_children(PSK_IDENTITY_FIELDS),
    FieldDescriptor::new("binders", "Binders", FieldType::Array).optional(),
    FieldDescriptor::new("binder", "Binder", FieldType::Bytes).optional(),
    FieldDescriptor::new("selected_identity", "Selected Identity", FieldType::U16).optional(),
    // RFC 8422, Section 5.1.2 (https://www.rfc-editor.org/rfc/rfc8422#section-5.1.2)
    FieldDescriptor::new("ec_point_formats", "EC Point Formats", FieldType::Array).optional(),
    named_field!(
        "ec_point_format",
        "EC Point Format",
        U8,
        ec_point_format_name
    ),
    // RFC 6066, Section 8 (https://www.rfc-editor.org/rfc/rfc6066#section-8)
    named_field!(
        "status_type",
        "Status Type",
        U8,
        certificate_status_type_name
    ),
    FieldDescriptor::new("responder_id_list", "Responder ID List", FieldType::Array).optional(),
    FieldDescriptor::new("responder_id", "Responder ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("request_extensions", "Request Extensions", FieldType::Bytes).optional(),
    FieldDescriptor::new("ocsp_response", "OCSP Response", FieldType::Bytes).optional(),
    // RFC 8449, Section 4 (https://www.rfc-editor.org/rfc/rfc8449#section-4)
    FieldDescriptor::new("record_size_limit", "Record Size Limit", FieldType::U16).optional(),
    // RFC 8879, Section 3 (https://www.rfc-editor.org/rfc/rfc8879#section-3)
    FieldDescriptor::new("algorithms", "Compression Algorithms", FieldType::Array).optional(),
    named_field!(
        "algorithm",
        "Compression Algorithm",
        U16,
        certificate_compression_algorithm_name
    ),
    // RFC 9001, Section 8.2 (https://www.rfc-editor.org/rfc/rfc9001#section-8.2)
    FieldDescriptor::new(
        "transport_parameters",
        "Transport Parameters",
        FieldType::Array,
    )
    .optional()
    .with_children(TRANSPORT_PARAMETER_FIELDS),
    // RFC 9849, Section 5 (https://www.rfc-editor.org/rfc/rfc9849#section-5)
    named_field!(
        "ech_type",
        "ECH ClientHello Type",
        U8,
        ech_client_hello_type_name
    ),
    named_field!("kdf_id", "HPKE KDF", U16, hpke_kdf_name),
    named_field!("aead_id", "HPKE AEAD", U16, hpke_aead_name),
    FieldDescriptor::new("config_id", "Config ID", FieldType::U8).optional(),
    FieldDescriptor::new("enc", "Encapsulated Key", FieldType::Bytes).optional(),
    FieldDescriptor::new("payload", "Encrypted Payload", FieldType::Bytes).optional(),
    FieldDescriptor::new("confirmation", "Confirmation", FieldType::Bytes).optional(),
    FieldDescriptor::new("retry_configs", "Retry Configs", FieldType::Bytes).optional(),
    // RFC 9846, Section 4.3.10 (https://www.rfc-editor.org/rfc/rfc9846#section-4.3.10)
    FieldDescriptor::new("max_early_data_size", "Max Early Data Size", FieldType::U32).optional(),
];

/// Shorthand for an extension child descriptor.
fn efd(idx: usize) -> &'static FieldDescriptor {
    &EXTENSION_CHILD_FIELDS[idx]
}

/// Push a list of `uint16` values as an Array `array` of `item` fields.
pub(crate) fn push_u16_list<'pkt>(
    list: &'pkt [u8],
    offset: usize,
    array: &'static FieldDescriptor,
    item: &'static FieldDescriptor,
    buf: &mut DissectBuffer<'pkt>,
) {
    let idx = buf.begin_container(array, FieldValue::Array(0..0), offset..offset + list.len());
    for (i, v) in list.chunks_exact(2).enumerate() {
        let start = offset + i * 2;
        buf.push_field(
            item,
            FieldValue::U16(u16::from_be_bytes([v[0], v[1]])),
            start..start + 2,
        );
    }
    buf.end_container(idx);
}

/// Push a list of `uint8` values as an Array `array` of `item` fields.
pub(crate) fn push_u8_list<'pkt>(
    list: &'pkt [u8],
    offset: usize,
    array: &'static FieldDescriptor,
    item: &'static FieldDescriptor,
    buf: &mut DissectBuffer<'pkt>,
) {
    let idx = buf.begin_container(array, FieldValue::Array(0..0), offset..offset + list.len());
    for (i, &v) in list.iter().enumerate() {
        buf.push_field(item, FieldValue::U8(v), offset + i..offset + i + 1);
    }
    buf.end_container(idx);
}

/// Push a sequence of length-prefixed vectors (already validated with
/// [`vectors_tile`]) as an Array `array` of `item` Bytes fields.
pub(crate) fn push_vector_list<'pkt>(
    (list, range): Span<'pkt>,
    len_size: usize,
    array: &'static FieldDescriptor,
    item: &'static FieldDescriptor,
    buf: &mut DissectBuffer<'pkt>,
) {
    let idx = buf.begin_container(array, FieldValue::Array(0..0), range.clone());
    let mut r = Reader::new(list, range.start);
    while let Some((v, range)) = r.vector(len_size) {
        buf.push_field(item, FieldValue::Bytes(v), range);
    }
    buf.end_container(idx);
}

/// Decode a non-empty list of `uint16` values carried in a single vector
/// with a `len_size`-byte length (supported_groups, signature_algorithms,
/// compress_certificate).
fn decode_u16_vector<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    len_size: usize,
    array: usize,
    item: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    if let Some((list, range)) = whole_vector(data, offset, len_size) {
        if !list.is_empty() && list.len() % 2 == 0 {
            push_u16_list(list, range.start, efd(array), efd(item), buf);
        }
    }
}

/// Decode a non-empty list of `uint8` values carried in a single vector
/// with a 1-byte length (ec_point_formats, psk_key_exchange_modes).
fn decode_u8_vector<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    array: usize,
    item: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    if let Some((list, range)) = whole_vector(data, offset, 1) {
        if !list.is_empty() {
            push_u8_list(list, range.start, efd(array), efd(item), buf);
        }
    }
}

/// Decode `server_name`: the first `host_name` entry.
///
/// RFC 6066, Section 3 — <https://www.rfc-editor.org/rfc/rfc6066#section-3>:
/// "The ServerNameList MUST NOT contain more than one name of the same
/// name_type", and `host_name(0)` is the only defined type.
fn decode_server_name<'pkt>(data: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let Some((list, range)) = whole_vector(data, offset, 2) else {
        return;
    };
    let mut r = Reader::new(list, range.start);
    if r.u8() != Some(0) {
        return;
    }
    if let Some((name, range)) = r.vector(2) {
        buf.push_field(efd(EFD_SERVER_NAME), FieldValue::Bytes(name), range);
    }
}

/// Decode `supported_versions`.
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
fn decode_supported_versions<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    ctx: ExtContext,
    buf: &mut DissectBuffer<'pkt>,
) -> SupportedVersions {
    match ctx {
        ExtContext::ServerHello | ExtContext::HelloRetryRequest => {
            if data.len() == 2 {
                let v = u16::from_be_bytes([data[0], data[1]]);
                buf.push_field(
                    efd(EFD_SELECTED_VERSION),
                    FieldValue::U16(v),
                    offset..offset + 2,
                );
                return SupportedVersions::Selected(v);
            }
        }
        _ => {
            if let Some((list, range)) = whole_vector(data, offset, 1) {
                if list.len() >= 2 && list.len() % 2 == 0 {
                    push_u16_list(list, range.start, efd(EFD_VERSIONS), efd(EFD_VERSION), buf);
                }
            }
        }
    }
    SupportedVersions::Undetermined
}

/// Decode `application_layer_protocol_negotiation`.
///
/// ```text
/// RFC 7301, Section 3.1 — https://www.rfc-editor.org/rfc/rfc7301#section-3.1
///
/// opaque ProtocolName<1..2^8-1>;
///
/// struct {
///     ProtocolName protocol_name_list<2..2^16-1>
/// } ProtocolNameList;
/// ```
fn decode_alpn<'pkt>(data: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    if let Some(list) = whole_vector(data, offset, 2) {
        if !list.0.is_empty() && vectors_tile(list.0, 1, 1) {
            push_vector_list(
                list,
                1,
                efd(EFD_PROTOCOL_NAMES),
                efd(EFD_PROTOCOL_NAME),
                buf,
            );
        }
    }
}

/// Read a `KeyShareEntry` (group + non-empty key_exchange).
///
/// RFC 9846, Section 4.3.8 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3.8>
fn read_key_share_entry<'pkt>(r: &mut Reader<'pkt>) -> Option<(u16, Span<'pkt>)> {
    let mut probe = *r;
    let group = probe.u16()?;
    let key = probe.vector(2).filter(|(k, _)| !k.is_empty())?;
    *r = probe;
    Some((group, key))
}

/// Push a `KeyShareEntry` Object read from `r`.
fn push_key_share_entry<'pkt>(
    r: &mut Reader<'pkt>,
    fd: &'static FieldDescriptor,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<()> {
    let start = r.offset();
    let (group, key) = read_key_share_entry(r)?;
    let idx = buf.begin_container(fd, FieldValue::Object(0..0), start..r.offset());
    buf.push_field(
        &KEY_SHARE_ENTRY_FIELDS[0],
        FieldValue::U16(group),
        start..start + 2,
    );
    buf.push_field(&KEY_SHARE_ENTRY_FIELDS[1], FieldValue::Bytes(key.0), key.1);
    buf.end_container(idx);
    Some(())
}

/// Decode `key_share`.
///
/// ```text
/// RFC 9846, Section 4.3.8 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.8
///
/// struct {
///     NamedGroup group;
///     opaque key_exchange<1..2^16-1>;
/// } KeyShareEntry;
///
/// struct { KeyShareEntry client_shares<0..2^16-1>; } KeyShareClientHello;
/// struct { NamedGroup selected_group; } KeyShareHelloRetryRequest;
/// struct { KeyShareEntry server_share; } KeyShareServerHello;
/// ```
fn decode_key_share<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    ctx: ExtContext,
    buf: &mut DissectBuffer<'pkt>,
) {
    match ctx {
        ExtContext::ClientHello => {
            let Some((list, range)) = whole_vector(data, offset, 2) else {
                return;
            };
            let mut check = Reader::new(list, range.start);
            while !check.is_empty() {
                if read_key_share_entry(&mut check).is_none() {
                    return;
                }
            }
            let idx = buf.begin_container(
                efd(EFD_CLIENT_SHARES),
                FieldValue::Array(0..0),
                range.clone(),
            );
            let mut r = Reader::new(list, range.start);
            while push_key_share_entry(&mut r, &FD_KEY_SHARE_ENTRY, buf).is_some() {}
            buf.end_container(idx);
        }
        ExtContext::ServerHello => {
            let mut r = Reader::new(data, offset);
            let mut check = r;
            if read_key_share_entry(&mut check).is_some() && check.is_empty() {
                let _ = push_key_share_entry(&mut r, efd(EFD_SERVER_SHARE), buf);
            }
        }
        ExtContext::HelloRetryRequest if data.len() == 2 => {
            buf.push_field(
                efd(EFD_SELECTED_GROUP),
                FieldValue::U16(u16::from_be_bytes([data[0], data[1]])),
                offset..offset + 2,
            );
        }
        _ => {}
    }
}

/// Minimum `PskBinderEntry` length (`opaque PskBinderEntry<32..255>`).
///
/// RFC 9846, Section 4.3.11 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3.11>
const PSK_BINDER_MIN_LEN: usize = 32;

/// Read a `PskIdentity` (non-empty identity + obfuscated_ticket_age).
///
/// RFC 9846, Section 4.3.11 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3.11>
fn read_psk_identity<'pkt>(r: &mut Reader<'pkt>) -> Option<(Span<'pkt>, u32)> {
    let mut probe = *r;
    let id = probe.vector(2).filter(|(id, _)| !id.is_empty())?;
    let age = probe.u32()?;
    *r = probe;
    Some((id, age))
}

/// Decode `pre_shared_key`.
///
/// ```text
/// RFC 9846, Section 4.3.11 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.11
///
/// struct {
///     opaque identity<1..2^16-1>;
///     uint32 obfuscated_ticket_age;
/// } PskIdentity;
///
/// opaque PskBinderEntry<32..255>;
///
/// struct {
///     PskIdentity identities<7..2^16-1>;
///     PskBinderEntry binders<33..2^16-1>;
/// } OfferedPsks;
///
/// struct {
///     select (Handshake.msg_type) {
///         case client_hello: OfferedPsks;
///         case server_hello: uint16 selected_identity;
///     };
/// } PreSharedKeyExtension;
/// ```
fn decode_pre_shared_key<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    ctx: ExtContext,
    buf: &mut DissectBuffer<'pkt>,
) {
    match ctx {
        ExtContext::ClientHello => {
            let mut r = Reader::new(data, offset);
            let (Some((ids, ids_range)), Some(binders)) = (r.vector(2), r.vector(2)) else {
                return;
            };
            if !r.is_empty()
                || ids.is_empty()
                || binders.0.is_empty()
                || !vectors_tile(binders.0, 1, PSK_BINDER_MIN_LEN)
            {
                return;
            }
            let mut check = Reader::new(ids, 0);
            while !check.is_empty() {
                if read_psk_identity(&mut check).is_none() {
                    return;
                }
            }

            let idx = buf.begin_container(
                efd(EFD_IDENTITIES),
                FieldValue::Array(0..0),
                ids_range.clone(),
            );
            let mut r = Reader::new(ids, ids_range.start);
            loop {
                let start = r.offset();
                let Some((id, age)) = read_psk_identity(&mut r) else {
                    break;
                };
                let obj = buf.begin_container(
                    &FD_PSK_IDENTITY,
                    FieldValue::Object(0..0),
                    start..r.offset(),
                );
                buf.push_field(&PSK_IDENTITY_FIELDS[0], FieldValue::Bytes(id.0), id.1);
                buf.push_field(
                    &PSK_IDENTITY_FIELDS[1],
                    FieldValue::U32(age),
                    r.offset() - 4..r.offset(),
                );
                buf.end_container(obj);
            }
            buf.end_container(idx);
            push_vector_list(binders, 1, efd(EFD_BINDERS), efd(EFD_BINDER), buf);
        }
        ExtContext::ServerHello if data.len() == 2 => {
            buf.push_field(
                efd(EFD_SELECTED_IDENTITY),
                FieldValue::U16(u16::from_be_bytes([data[0], data[1]])),
                offset..offset + 2,
            );
        }
        _ => {}
    }
}

/// Decode `status_request` when it carries a well-formed OCSP request.
///
/// ```text
/// RFC 6066, Section 8 — https://www.rfc-editor.org/rfc/rfc6066#section-8
///
/// struct {
///     CertificateStatusType status_type;
///     select (status_type) {
///         case ocsp: OCSPStatusRequest;
///     } request;
/// } CertificateStatusRequest;
///
/// opaque ResponderID<1..2^16-1>;
/// opaque Extensions<0..2^16-1>;
///
/// struct {
///     ResponderID responder_id_list<0..2^16-1>;
///     Extensions  request_extensions;
/// } OCSPStatusRequest;
/// ```
///
/// In a TLS 1.3 CertificateEntry the extension carries a
/// `CertificateStatus` instead (RFC 9846, Section 4.5.1.1 —
/// <https://www.rfc-editor.org/rfc/rfc9846#section-4.5.1.1>). In a TLS 1.3
/// CertificateRequest it is empty (same section: "sending an empty
/// "status_request" extension in its CertificateRequest message"), so it is
/// not decoded there.
fn decode_status_request<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    ctx: ExtContext,
    buf: &mut DissectBuffer<'pkt>,
) {
    match ctx {
        ExtContext::ClientHello => {
            let mut r = Reader::new(data, offset);
            let (Some(STATUS_TYPE_OCSP), Some(ids), Some(exts)) =
                (r.u8(), r.vector(2), r.vector(2))
            else {
                return;
            };
            if !r.is_empty() || !vectors_tile(ids.0, 2, 1) {
                return;
            }
            buf.push_field(
                efd(EFD_STATUS_TYPE),
                FieldValue::U8(STATUS_TYPE_OCSP),
                offset..offset + 1,
            );
            push_vector_list(
                ids,
                2,
                efd(EFD_RESPONDER_ID_LIST),
                efd(EFD_RESPONDER_ID),
                buf,
            );
            buf.push_field(
                efd(EFD_REQUEST_EXTENSIONS),
                FieldValue::Bytes(exts.0),
                exts.1,
            );
        }
        ExtContext::Certificate => push_certificate_status(
            data,
            offset,
            efd(EFD_STATUS_TYPE),
            efd(EFD_OCSP_RESPONSE),
            buf,
        ),
        _ => {}
    }
}

/// Push a `CertificateStatus` body (`status_type` + `OCSPResponse`) if it is
/// a well-formed OCSP response.
///
/// ```text
/// RFC 6066, Section 8 — https://www.rfc-editor.org/rfc/rfc6066#section-8
///
/// struct {
///     CertificateStatusType status_type;
///     select (status_type) {
///         case ocsp: OCSPResponse;
///     } response;
/// } CertificateStatus;
///
/// opaque OCSPResponse<1..2^24-1>;
/// ```
pub(crate) fn push_certificate_status<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    status_type_fd: &'static FieldDescriptor,
    response_fd: &'static FieldDescriptor,
    buf: &mut DissectBuffer<'pkt>,
) {
    let mut r = Reader::new(data, offset);
    let (Some(STATUS_TYPE_OCSP), Some((resp, range))) = (r.u8(), r.vector(3)) else {
        return;
    };
    if !r.is_empty() || resp.is_empty() {
        return;
    }
    buf.push_field(
        status_type_fd,
        FieldValue::U8(STATUS_TYPE_OCSP),
        offset..offset + 1,
    );
    buf.push_field(response_fd, FieldValue::Bytes(resp), range);
}

/// One QUIC transport parameter with the packet ranges of its parts.
struct TransportParameter<'pkt> {
    id: u64,
    id_range: Range<usize>,
    length: u64,
    length_range: Range<usize>,
    value: Span<'pkt>,
}

/// Read one QUIC transport parameter:
/// `(ID (i), Length (i), Value (..))`.
///
/// RFC 9000, Section 18 — <https://www.rfc-editor.org/rfc/rfc9000#section-18>
fn read_transport_parameter<'pkt>(r: &mut Reader<'pkt>) -> Option<TransportParameter<'pkt>> {
    let mut probe = *r;
    let id_start = probe.offset();
    let id = probe.varint()?;
    let length_start = probe.offset();
    let length = probe.varint()?;
    let length_end = probe.offset();
    let value = probe.bytes(usize::try_from(length).ok()?)?;
    *r = probe;
    Some(TransportParameter {
        id,
        id_range: id_start..length_start,
        length,
        length_range: length_start..length_end,
        value,
    })
}

/// Decode `quic_transport_parameters` when every entry is well formed.
///
/// RFC 9001, Section 8.2 — <https://www.rfc-editor.org/rfc/rfc9001#section-8.2>
/// RFC 9000, Section 18 — <https://www.rfc-editor.org/rfc/rfc9000#section-18>
fn decode_quic_transport_parameters<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    let mut check = Reader::new(data, offset);
    while !check.is_empty() {
        if read_transport_parameter(&mut check).is_none() {
            return;
        }
    }
    let idx = buf.begin_container(
        efd(EFD_TRANSPORT_PARAMETERS),
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    let mut r = Reader::new(data, offset);
    loop {
        let start = r.offset();
        let Some(param) = read_transport_parameter(&mut r) else {
            break;
        };
        let obj = buf.begin_container(
            &FD_TRANSPORT_PARAMETER,
            FieldValue::Object(0..0),
            start..r.offset(),
        );
        buf.push_field(
            &TRANSPORT_PARAMETER_FIELDS[0],
            FieldValue::U64(param.id),
            param.id_range,
        );
        buf.push_field(
            &TRANSPORT_PARAMETER_FIELDS[1],
            FieldValue::U64(param.length),
            param.length_range,
        );
        buf.push_field(
            &TRANSPORT_PARAMETER_FIELDS[2],
            FieldValue::Bytes(param.value.0),
            param.value.1,
        );
        buf.end_container(obj);
    }
    buf.end_container(idx);
}

/// Decode `encrypted_client_hello` when its body is well formed.
///
/// ```text
/// RFC 9849, Section 5 — https://www.rfc-editor.org/rfc/rfc9849#section-5
///
/// struct {
///    ECHClientHelloType type;
///    select (ECHClientHello.type) {
///        case outer:
///            HpkeSymmetricCipherSuite cipher_suite;
///            uint8 config_id;
///            opaque enc<0..2^16-1>;
///            opaque payload<1..2^16-1>;
///        case inner:
///            Empty;
///    };
/// } ECHClientHello;
///
/// struct { ECHConfigList retry_configs; } ECHEncryptedExtensions;
/// struct { opaque confirmation[8]; } ECHHelloRetryRequest;
///
/// RFC 9849, Section 4 — https://www.rfc-editor.org/rfc/rfc9849#section-4
///
/// ECHConfig ECHConfigList<4..2^16-1>;
/// ```
fn decode_encrypted_client_hello<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    ctx: ExtContext,
    buf: &mut DissectBuffer<'pkt>,
) {
    match ctx {
        ExtContext::ClientHello => {
            let mut r = Reader::new(data, offset);
            match r.u8() {
                Some(ECH_TYPE_OUTER) => {
                    let (Some(kdf), Some(aead), Some(config_id), Some(enc), Some(payload)) =
                        (r.u16(), r.u16(), r.u8(), r.vector(2), r.vector(2))
                    else {
                        return;
                    };
                    if !r.is_empty() || payload.0.is_empty() {
                        return;
                    }
                    let o = offset + 1;
                    buf.push_field(efd(EFD_ECH_TYPE), FieldValue::U8(ECH_TYPE_OUTER), offset..o);
                    buf.push_field(efd(EFD_KDF_ID), FieldValue::U16(kdf), o..o + 2);
                    buf.push_field(efd(EFD_AEAD_ID), FieldValue::U16(aead), o + 2..o + 4);
                    buf.push_field(efd(EFD_CONFIG_ID), FieldValue::U8(config_id), o + 4..o + 5);
                    buf.push_field(efd(EFD_ENC), FieldValue::Bytes(enc.0), enc.1);
                    buf.push_field(efd(EFD_PAYLOAD), FieldValue::Bytes(payload.0), payload.1);
                }
                Some(ech_type) if r.is_empty() => {
                    buf.push_field(
                        efd(EFD_ECH_TYPE),
                        FieldValue::U8(ech_type),
                        offset..offset + 1,
                    );
                }
                _ => {}
            }
        }
        ExtContext::HelloRetryRequest if data.len() == 8 => {
            buf.push_field(
                efd(EFD_CONFIRMATION),
                FieldValue::Bytes(data),
                offset..offset + 8,
            );
        }
        ExtContext::EncryptedExtensions if is_ech_config_list(data) => {
            buf.push_field(
                efd(EFD_RETRY_CONFIGS),
                FieldValue::Bytes(data),
                offset..offset + data.len(),
            );
        }
        _ => {}
    }
}

/// Whether `data` is exactly one `ECHConfigList` whose `ECHConfig` entries
/// fill it.
///
/// ```text
/// RFC 9849, Section 4 — https://www.rfc-editor.org/rfc/rfc9849#section-4
///
/// struct {
///     uint16 version;
///     uint16 length;
///     select (ECHConfig.version) {
///       case 0xfe0d: ECHConfigContents contents;
///     }
/// } ECHConfig;
///
/// ECHConfig ECHConfigList<4..2^16-1>;
/// ```
fn is_ech_config_list(data: &[u8]) -> bool {
    let Some((list, _)) = whole_vector(data, 0, 2) else {
        return false;
    };
    if list.len() < 4 {
        return false;
    }
    let mut r = Reader::new(list, 0);
    while !r.is_empty() {
        if r.u16().is_none() || r.vector(2).is_none() {
            return false;
        }
    }
    true
}

/// Decode the body of one extension. Returns the `supported_versions`
/// state when `ext_type` is `supported_versions`.
fn decode_extension<'pkt>(
    ext_type: u16,
    data: &'pkt [u8],
    offset: usize,
    ctx: ExtContext,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<SupportedVersions> {
    match ext_type {
        EXT_SERVER_NAME => decode_server_name(data, offset, buf),
        EXT_STATUS_REQUEST => decode_status_request(data, offset, ctx, buf),
        // RFC 9846, Section 4.3.7 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.7
        // NamedGroup named_group_list<2..2^16-1>;
        EXT_SUPPORTED_GROUPS => {
            decode_u16_vector(data, offset, 2, EFD_NAMED_GROUPS, EFD_NAMED_GROUP, buf);
        }
        // RFC 8422, Section 5.1.2 — https://www.rfc-editor.org/rfc/rfc8422#section-5.1.2
        // ECPointFormat ec_point_format_list<1..2^8-1>
        EXT_EC_POINT_FORMATS => {
            decode_u8_vector(data, offset, EFD_EC_POINT_FORMATS, EFD_EC_POINT_FORMAT, buf);
        }
        // RFC 9846, Section 4.3.3 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.3
        // SignatureScheme supported_signature_algorithms<2..2^16-2>;
        EXT_SIGNATURE_ALGORITHMS | EXT_SIGNATURE_ALGORITHMS_CERT => decode_u16_vector(
            data,
            offset,
            2,
            EFD_SIGNATURE_SCHEMES,
            EFD_SIGNATURE_SCHEME,
            buf,
        ),
        EXT_ALPN => decode_alpn(data, offset, buf),
        // RFC 8879, Section 3 — https://www.rfc-editor.org/rfc/rfc8879#section-3
        // CertificateCompressionAlgorithm algorithms<2..2^8-2>;
        EXT_COMPRESS_CERTIFICATE => {
            decode_u16_vector(data, offset, 1, EFD_ALGORITHMS, EFD_ALGORITHM, buf);
        }
        // RFC 8449, Section 4 — https://www.rfc-editor.org/rfc/rfc8449#section-4
        // uint16 RecordSizeLimit;
        EXT_RECORD_SIZE_LIMIT if data.len() == 2 => {
            buf.push_field(
                efd(EFD_RECORD_SIZE_LIMIT),
                FieldValue::U16(u16::from_be_bytes([data[0], data[1]])),
                offset..offset + 2,
            );
        }
        EXT_PRE_SHARED_KEY => decode_pre_shared_key(data, offset, ctx, buf),
        // RFC 9846, Section 4.3.10 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.10
        // In NewSessionTicket: uint32 max_early_data_size;
        EXT_EARLY_DATA if ctx == ExtContext::NewSessionTicket && data.len() == 4 => {
            buf.push_field(
                efd(EFD_MAX_EARLY_DATA_SIZE),
                FieldValue::U32(u32::from_be_bytes([data[0], data[1], data[2], data[3]])),
                offset..offset + 4,
            );
        }
        EXT_SUPPORTED_VERSIONS => {
            return Some(decode_supported_versions(data, offset, ctx, buf));
        }
        // RFC 9846, Section 4.3.9 — https://www.rfc-editor.org/rfc/rfc9846#section-4.3.9
        // PskKeyExchangeMode ke_modes<1..255>;
        EXT_PSK_KEY_EXCHANGE_MODES => {
            decode_u8_vector(data, offset, EFD_KE_MODES, EFD_KE_MODE, buf);
        }
        EXT_KEY_SHARE => decode_key_share(data, offset, ctx, buf),
        EXT_QUIC_TRANSPORT_PARAMETERS => decode_quic_transport_parameters(data, offset, buf),
        EXT_ENCRYPTED_CLIENT_HELLO => decode_encrypted_client_hello(data, offset, ctx, buf),
        _ => {}
    }
    None
}

/// Parse an extensions list (the contents of an `extensions` vector) into
/// the current container.
///
/// Each extension is a 2-byte type, 2-byte length, and variable-length data.
/// Returns what the `supported_versions` extension says, if present.
///
/// RFC 9846, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3>
pub(crate) fn parse_extensions<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    ctx: ExtContext,
    buf: &mut DissectBuffer<'pkt>,
) -> SupportedVersions {
    let mut supported_versions = SupportedVersions::Absent;
    let mut r = Reader::new(data, offset);
    while !r.is_empty() {
        let start = r.offset();
        let mut probe = r;
        let (Some(ext_type), Some((ext_data, data_range))) = (probe.u16(), probe.vector(2)) else {
            break;
        };
        r = probe;

        let obj_idx = buf.begin_container(
            &FD_EXTENSION,
            FieldValue::Object(0..0),
            start..data_range.end,
        );
        buf.push_field(
            &EXTENSION_CHILD_FIELDS[EFD_TYPE],
            FieldValue::U16(ext_type),
            start..start + 2,
        );
        buf.push_field(
            &EXTENSION_CHILD_FIELDS[EFD_LENGTH],
            FieldValue::U16(ext_data.len() as u16),
            start + 2..start + 4,
        );
        buf.push_field(
            &EXTENSION_CHILD_FIELDS[EFD_DATA],
            FieldValue::Bytes(ext_data),
            data_range.clone(),
        );
        let sv = decode_extension(ext_type, ext_data, data_range.start, ctx, buf);
        if let (Some(sv), SupportedVersions::Absent) = (sv, supported_versions) {
            supported_versions = sv;
        }
        buf.end_container(obj_idx);
    }
    if !r.is_empty() && supported_versions == SupportedVersions::Absent {
        // A malformed extension may hide supported_versions.
        return SupportedVersions::Undetermined;
    }
    supported_versions
}

/// Push an `extensions` vector read from `r` as an Array described by `fd`.
/// Returns `None` (pushing nothing) if the vector does not fit.
pub(crate) fn push_extensions_vector<'pkt>(
    r: &mut Reader<'pkt>,
    fd: &'static FieldDescriptor,
    ctx: ExtContext,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<SupportedVersions> {
    let (exts, range) = r.vector(2)?;
    let idx = buf.begin_container(fd, FieldValue::Array(0..0), range.clone());
    let sv = parse_extensions(exts, range.start, ctx, buf);
    buf.end_container(idx);
    Some(sv)
}
