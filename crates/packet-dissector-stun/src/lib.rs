//! STUN (Session Traversal Utilities for NAT) and TURN ChannelData dissector.
//!
//! The STUN port (3478) is shared with TURN, which relays application data in
//! ChannelData messages once a channel is bound. [`StunDissector`] tells them
//! apart by the first byte (RFC 8656, Section 12, Table 3) and emits
//! ChannelData as a [`TurnChannelDataDissector`] layer. [`StunTcpDissector`]
//! applies the stream framing rules on TCP. Classic STUN (RFC 3489)
//! Binding messages without the magic cookie are recognised as described in
//! RFC 5389, Section 12.
//!
//! ## References
//! - RFC 8489 (Obsoletes RFC 5389): <https://www.rfc-editor.org/rfc/rfc8489>
//! - RFC 5389, Section 12 (Backwards Compatibility with RFC 3489):
//!   <https://www.rfc-editor.org/rfc/rfc5389#section-12>
//! - RFC 8656 (TURN, Obsoletes RFC 5766), Section 12 (Channels), Sections
//!   17-19 (methods, attributes, error codes):
//!   <https://www.rfc-editor.org/rfc/rfc8656#section-12>,
//!   <https://www.rfc-editor.org/rfc/rfc8656#section-17>
//! - RFC 6062 (TURN TCP), Section 6: <https://www.rfc-editor.org/rfc/rfc6062#section-6>
//! - RFC 8445 (ICE), Section 16: <https://www.rfc-editor.org/rfc/rfc8445#section-16>
//! - RFC 5780 (NAT Behavior Discovery), Section 7:
//!   <https://www.rfc-editor.org/rfc/rfc5780#section-7>
//! - RFC 5769 (STUN test vectors): <https://www.rfc-editor.org/rfc/rfc5769>
//! - RFC 7983 (Multiplexing Scheme Updates for SRTP with DTLS), Section 7,
//!   updated by RFC 9443: <https://www.rfc-editor.org/rfc/rfc7983#section-7>,
//!   <https://www.rfc-editor.org/rfc/rfc9443>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32, read_be_u64};

/// STUN header size in bytes.
///
/// RFC 8489, Section 5 — <https://www.rfc-editor.org/rfc/rfc8489#section-5>.
const HEADER_SIZE: usize = 20;

/// STUN magic cookie value.
///
/// RFC 8489, Section 5 — "The Magic Cookie field MUST contain the fixed value
/// 0x2112A442 in network byte order."
/// <https://www.rfc-editor.org/rfc/rfc8489#section-5>.
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Layer display name for classic STUN (RFC 3489) messages.
///
/// RFC 5389, Section 12 — "The field that is now the magic cookie field was a
/// part of the transaction ID field, and transaction IDs were 128 bits long."
/// <https://www.rfc-editor.org/rfc/rfc5389#section-12>.
const CLASSIC_DISPLAY_NAME: &str = "Classic STUN (RFC 3489)";

/// STUN Indication message class.
///
/// RFC 8489, Section 5 — "0b01 is an indication".
/// <https://www.rfc-editor.org/rfc/rfc8489#section-5>.
const CLASS_INDICATION: u8 = 0b01;

/// STUN Binding method.
///
/// RFC 8489, Section 18.2 — <https://www.rfc-editor.org/rfc/rfc8489#section-18.2>.
const METHOD_BINDING: u16 = 0x001;

/// First-byte range of a TURN ChannelData message.
///
/// RFC 8656, Section 12, Table 3 — "[64..79] | TURN Channel".
/// <https://www.rfc-editor.org/rfc/rfc8656#section-12>.
const TURN_CHANNEL_FIRST_BYTE: core::ops::RangeInclusive<u8> = 64..=79;

/// Transport the message was received on; framing rules differ.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Transport {
    /// UDP (or an unknown transport, e.g. decode-as).
    Datagram,
    /// TCP or TLS-over-TCP.
    Stream,
}

/// Minimum attribute size: Type(2) + Length(2).
///
/// RFC 8489, Section 14 — "After the STUN header are zero or more attributes.
/// Each attribute MUST be TLV encoded, with a 16-bit type, 16-bit length, and
/// value." <https://www.rfc-editor.org/rfc/rfc8489#section-14>.
const MIN_ATTR_SIZE: usize = 4;

/// Returns a human-readable name for the STUN message class.
///
/// RFC 8489, Section 5 — Message class values —
/// <https://www.rfc-editor.org/rfc/rfc8489#section-5>.
fn class_name(class: u8) -> &'static str {
    match class {
        0b00 => "Request",
        0b01 => "Indication",
        0b10 => "Success Response",
        0b11 => "Error Response",
        _ => unreachable!(),
    }
}

/// Returns a human-readable name for the STUN method.
///
/// RFC 8489, Section 18.2 — STUN Methods Registry —
/// <https://www.rfc-editor.org/rfc/rfc8489#section-18.2>.
/// TURN methods: RFC 8656, Section 17 —
/// <https://www.rfc-editor.org/rfc/rfc8656#section-17>.
/// TURN-TCP methods: RFC 6062, Section 6.1 —
/// <https://www.rfc-editor.org/rfc/rfc6062#section-6.1>.
fn method_name(method: u16) -> Option<&'static str> {
    match method {
        0x001 => Some("Binding"),
        0x003 => Some("Allocate"),
        0x004 => Some("Refresh"),
        0x006 => Some("Send"),
        0x007 => Some("Data"),
        0x008 => Some("CreatePermission"),
        0x009 => Some("ChannelBind"),
        0x00A => Some("Connect"),
        0x00B => Some("ConnectionBind"),
        0x00C => Some("ConnectionAttempt"),
        _ => None,
    }
}

/// Returns a human-readable name for a STUN attribute type.
///
/// RFC 8489, Section 18.3 — STUN Attributes Registry —
/// <https://www.rfc-editor.org/rfc/rfc8489#section-18.3>.
///
/// Also names the attributes of TURN (RFC 8656, Section 18 —
/// <https://www.rfc-editor.org/rfc/rfc8656#section-18>), TURN-TCP
/// (RFC 6062, Section 6.2 — <https://www.rfc-editor.org/rfc/rfc6062#section-6.2>),
/// ICE (RFC 8445, Section 16.1 —
/// <https://www.rfc-editor.org/rfc/rfc8445#section-16.1>) and NAT behavior
/// discovery (RFC 5780, Section 7 —
/// <https://www.rfc-editor.org/rfc/rfc5780#section-7>).
pub fn attribute_type_name(attr_type: u16) -> Option<&'static str> {
    match attr_type {
        // Comprehension-required range (0x0000-0x7FFF).
        ATTR_MAPPED_ADDRESS => Some("MAPPED-ADDRESS"),
        ATTR_CHANGE_REQUEST => Some("CHANGE-REQUEST"),
        ATTR_USERNAME => Some("USERNAME"),
        ATTR_MESSAGE_INTEGRITY => Some("MESSAGE-INTEGRITY"),
        ATTR_ERROR_CODE => Some("ERROR-CODE"),
        ATTR_UNKNOWN_ATTRIBUTES => Some("UNKNOWN-ATTRIBUTES"),
        ATTR_CHANNEL_NUMBER => Some("CHANNEL-NUMBER"),
        ATTR_LIFETIME => Some("LIFETIME"),
        ATTR_XOR_PEER_ADDRESS => Some("XOR-PEER-ADDRESS"),
        ATTR_DATA => Some("DATA"),
        ATTR_REALM => Some("REALM"),
        ATTR_NONCE => Some("NONCE"),
        ATTR_XOR_RELAYED_ADDRESS => Some("XOR-RELAYED-ADDRESS"),
        ATTR_REQUESTED_ADDRESS_FAMILY => Some("REQUESTED-ADDRESS-FAMILY"),
        ATTR_EVEN_PORT => Some("EVEN-PORT"),
        ATTR_REQUESTED_TRANSPORT => Some("REQUESTED-TRANSPORT"),
        ATTR_DONT_FRAGMENT => Some("DONT-FRAGMENT"),
        ATTR_MESSAGE_INTEGRITY_SHA256 => Some("MESSAGE-INTEGRITY-SHA256"),
        ATTR_PASSWORD_ALGORITHM => Some("PASSWORD-ALGORITHM"),
        ATTR_USERHASH => Some("USERHASH"),
        ATTR_XOR_MAPPED_ADDRESS => Some("XOR-MAPPED-ADDRESS"),
        ATTR_RESERVATION_TOKEN => Some("RESERVATION-TOKEN"),
        ATTR_PRIORITY => Some("PRIORITY"),
        ATTR_USE_CANDIDATE => Some("USE-CANDIDATE"),
        ATTR_PADDING => Some("PADDING"),
        ATTR_RESPONSE_PORT => Some("RESPONSE-PORT"),
        ATTR_CONNECTION_ID => Some("CONNECTION-ID"),
        // Comprehension-optional range (0x8000-0xFFFF).
        ATTR_ADDITIONAL_ADDRESS_FAMILY => Some("ADDITIONAL-ADDRESS-FAMILY"),
        ATTR_ADDRESS_ERROR_CODE => Some("ADDRESS-ERROR-CODE"),
        ATTR_PASSWORD_ALGORITHMS => Some("PASSWORD-ALGORITHMS"),
        ATTR_ALTERNATE_DOMAIN => Some("ALTERNATE-DOMAIN"),
        ATTR_ICMP => Some("ICMP"),
        ATTR_SOFTWARE => Some("SOFTWARE"),
        ATTR_ALTERNATE_SERVER => Some("ALTERNATE-SERVER"),
        ATTR_FINGERPRINT => Some("FINGERPRINT"),
        ATTR_ICE_CONTROLLED => Some("ICE-CONTROLLED"),
        ATTR_ICE_CONTROLLING => Some("ICE-CONTROLLING"),
        ATTR_RESPONSE_ORIGIN => Some("RESPONSE-ORIGIN"),
        ATTR_OTHER_ADDRESS => Some("OTHER-ADDRESS"),
        _ => None,
    }
}

// STUN attribute types.
// RFC 8489, Section 18.3 — https://www.rfc-editor.org/rfc/rfc8489#section-18.3
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;
const ATTR_PASSWORD_ALGORITHM: u16 = 0x001D;
const ATTR_USERHASH: u16 = 0x001E;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_PASSWORD_ALGORITHMS: u16 = 0x8002;
const ATTR_ALTERNATE_DOMAIN: u16 = 0x8003;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_ALTERNATE_SERVER: u16 = 0x8023;
const ATTR_FINGERPRINT: u16 = 0x8028;
// RFC 8656, Section 18 — https://www.rfc-editor.org/rfc/rfc8656#section-18
const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
const ATTR_EVEN_PORT: u16 = 0x0018;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_DONT_FRAGMENT: u16 = 0x001A;
const ATTR_RESERVATION_TOKEN: u16 = 0x0022;
const ATTR_ADDITIONAL_ADDRESS_FAMILY: u16 = 0x8000;
const ATTR_ADDRESS_ERROR_CODE: u16 = 0x8001;
const ATTR_ICMP: u16 = 0x8004;
// RFC 6062, Section 6.2 — https://www.rfc-editor.org/rfc/rfc6062#section-6.2
const ATTR_CONNECTION_ID: u16 = 0x002A;
// RFC 8445, Section 16.1 — https://www.rfc-editor.org/rfc/rfc8445#section-16.1
const ATTR_PRIORITY: u16 = 0x0024;
const ATTR_USE_CANDIDATE: u16 = 0x0025;
const ATTR_ICE_CONTROLLED: u16 = 0x8029;
const ATTR_ICE_CONTROLLING: u16 = 0x802A;
// RFC 5780, Section 7 — https://www.rfc-editor.org/rfc/rfc5780#section-7
const ATTR_CHANGE_REQUEST: u16 = 0x0003;
const ATTR_PADDING: u16 = 0x0026;
const ATTR_RESPONSE_PORT: u16 = 0x0027;
const ATTR_RESPONSE_ORIGIN: u16 = 0x802B;
const ATTR_OTHER_ADDRESS: u16 = 0x802C;

/// Address family values.
///
/// RFC 8489, Section 14.1 — "0x01:IPv4", "0x02:IPv6" —
/// <https://www.rfc-editor.org/rfc/rfc8489#section-14.1>.
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

fn family_name(family: u8) -> Option<&'static str> {
    match family {
        FAMILY_IPV4 => Some("IPv4"),
        FAMILY_IPV6 => Some("IPv6"),
        _ => None,
    }
}

/// Returns the registered reason phrase for a STUN error code.
///
/// RFC 8489, Section 14.8 — <https://www.rfc-editor.org/rfc/rfc8489#section-14.8>;
/// RFC 8656, Section 19 — <https://www.rfc-editor.org/rfc/rfc8656#section-19>;
/// RFC 6062, Section 6.3 — <https://www.rfc-editor.org/rfc/rfc6062#section-6.3>;
/// RFC 8445, Section 16.2 — <https://www.rfc-editor.org/rfc/rfc8445#section-16.2>.
fn error_code_name(code: u16) -> Option<&'static str> {
    match code {
        300 => Some("Try Alternate"),
        400 => Some("Bad Request"),
        401 => Some("Unauthenticated"),
        403 => Some("Forbidden"),
        420 => Some("Unknown Attribute"),
        437 => Some("Allocation Mismatch"),
        438 => Some("Stale Nonce"),
        440 => Some("Address Family not Supported"),
        441 => Some("Wrong Credentials"),
        442 => Some("Unsupported Transport Protocol"),
        443 => Some("Peer Address Family Mismatch"),
        446 => Some("Connection Already Exists"),
        447 => Some("Connection Timeout or Failure"),
        486 => Some("Allocation Quota Reached"),
        487 => Some("Role Conflict"),
        500 => Some("Server Error"),
        508 => Some("Insufficient Capacity"),
        _ => None,
    }
}

/// Returns the name of a password algorithm.
///
/// RFC 8489, Section 18.5 — <https://www.rfc-editor.org/rfc/rfc8489#section-18.5>.
fn password_algorithm_name(algorithm: u16) -> Option<&'static str> {
    match algorithm {
        0x0001 => Some("MD5"),
        0x0002 => Some("SHA-256"),
        _ => None,
    }
}

/// Returns the name of a REQUESTED-TRANSPORT protocol number.
///
/// RFC 8656, Section 18.8 — "This specification only allows the use of code
/// point 17 (User Datagram Protocol)." RFC 6062, Section 4.1 adds TCP (6).
/// <https://www.rfc-editor.org/rfc/rfc8656#section-18.8>,
/// <https://www.rfc-editor.org/rfc/rfc6062#section-4.1>.
fn transport_protocol_name(protocol: u8) -> Option<&'static str> {
    match protocol {
        6 => Some("TCP"),
        17 => Some("UDP"),
        _ => None,
    }
}

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_MESSAGE_TYPE: usize = 0;
const FD_MESSAGE_CLASS: usize = 1;
const FD_MESSAGE_METHOD: usize = 2;
const FD_MESSAGE_LENGTH: usize = 3;
const FD_MAGIC_COOKIE: usize = 4;
const FD_TRANSACTION_ID: usize = 5;
const FD_ATTRIBUTES: usize = 6;

/// Field descriptor indices for [`ATTR_CHILD_FIELDS`].
const AFD_TYPE: usize = 0;
const AFD_LENGTH: usize = 1;
const AFD_VALUE: usize = 2;
const AFD_FAMILY: usize = 3;
const AFD_PORT: usize = 4;
const AFD_ADDRESS: usize = 5;
const AFD_TEXT: usize = 6;
const AFD_HMAC: usize = 7;
const AFD_USERHASH: usize = 8;
const AFD_CRC32: usize = 9;
const AFD_ERROR_CODE: usize = 10;
const AFD_REASON: usize = 11;
const AFD_ATTRIBUTE_TYPES: usize = 12;
const AFD_ALGORITHMS: usize = 15;
const AFD_CHANNEL_NUMBER: usize = 16;
const AFD_LIFETIME: usize = 17;
const AFD_DATA: usize = 18;
const AFD_RESERVE_NEXT: usize = 19;
const AFD_PROTOCOL: usize = 20;
const AFD_TOKEN: usize = 21;
const AFD_ICMP_TYPE: usize = 22;
const AFD_ICMP_CODE: usize = 23;
const AFD_ERROR_DATA: usize = 24;
const AFD_CONNECTION_ID: usize = 25;
const AFD_PRIORITY: usize = 26;
const AFD_TIE_BREAKER: usize = 27;
const AFD_CHANGE_IP: usize = 28;
const AFD_CHANGE_PORT: usize = 29;
const AFD_PADDING: usize = 30;

/// Container descriptor for an attribute Object.
///
/// The outer label resolves to the attribute name (e.g. `USERNAME`) by looking
/// up the inner `type` field. This avoids duplicating the inner "Attribute
/// Type" label on the surrounding container.
static FD_ATTRIBUTE: FieldDescriptor = FieldDescriptor {
    name: "attribute",
    display_name: "Attribute",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U16(t)) => attribute_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Child field descriptors for attribute Array elements.
///
/// RFC 8489, Section 14 — Each attribute is TLV-encoded —
/// <https://www.rfc-editor.org/rfc/rfc8489#section-14>.
static ATTR_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Attribute Type",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(t) => attribute_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Attribute Length", FieldType::U16),
    // Raw value of an unknown or malformed attribute.
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
    // RFC 8489, Section 14.1 — https://www.rfc-editor.org/rfc/rfc8489#section-14.1
    FieldDescriptor::new("family", "Family", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(f) => family_name(*f),
            _ => None,
        }),
    FieldDescriptor::new("port", "Port", FieldType::U16).optional(),
    // Ipv4Addr or Ipv6Addr depending on `family`.
    FieldDescriptor::new("address", "Address", FieldType::Any).optional(),
    // RFC 8489, Sections 14.3, 14.9, 14.10, 14.14, 14.16 —
    // https://www.rfc-editor.org/rfc/rfc8489#section-14.3
    FieldDescriptor::new("text", "Text", FieldType::Str).optional(),
    // RFC 8489, Sections 14.5, 14.6 — https://www.rfc-editor.org/rfc/rfc8489#section-14.5
    FieldDescriptor::new("hmac", "HMAC", FieldType::Bytes).optional(),
    // RFC 8489, Section 14.4 — https://www.rfc-editor.org/rfc/rfc8489#section-14.4
    FieldDescriptor::new("userhash", "Userhash", FieldType::Bytes).optional(),
    // RFC 8489, Section 14.7 — https://www.rfc-editor.org/rfc/rfc8489#section-14.7
    FieldDescriptor::new("crc32", "CRC-32", FieldType::U32).optional(),
    // RFC 8489, Section 14.8 — https://www.rfc-editor.org/rfc/rfc8489#section-14.8
    FieldDescriptor::new("error_code", "Error Code", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(c) => error_code_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("reason", "Reason Phrase", FieldType::Str).optional(),
    // RFC 8489, Section 14.13 — https://www.rfc-editor.org/rfc/rfc8489#section-14.13
    FieldDescriptor::new(
        "attribute_types",
        "Unknown Attribute Types",
        FieldType::Array,
    )
    .optional()
    .with_children(core::slice::from_ref(&FD_UNKNOWN_ATTRIBUTE_TYPE)),
    // RFC 8489, Section 14.12 — https://www.rfc-editor.org/rfc/rfc8489#section-14.12
    FD_PASSWORD_ALGORITHM,
    FD_PASSWORD_ALGORITHM_PARAMETERS,
    // RFC 8489, Section 14.11 — https://www.rfc-editor.org/rfc/rfc8489#section-14.11
    FieldDescriptor::new("algorithms", "Password Algorithms", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_PASSWORD_ALGORITHM_ENTRY)),
    // RFC 8656, Section 18.1 — https://www.rfc-editor.org/rfc/rfc8656#section-18.1
    FieldDescriptor::new("channel_number", "Channel Number", FieldType::U16).optional(),
    // RFC 8656, Section 18.2 — https://www.rfc-editor.org/rfc/rfc8656#section-18.2
    FieldDescriptor::new("lifetime", "Lifetime", FieldType::U32).optional(),
    // RFC 8656, Section 18.4 — https://www.rfc-editor.org/rfc/rfc8656#section-18.4
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    // RFC 8656, Section 18.7 — https://www.rfc-editor.org/rfc/rfc8656#section-18.7
    FieldDescriptor::new("reserve_next", "Reserve Next Port (R)", FieldType::U8).optional(),
    // RFC 8656, Section 18.8 — https://www.rfc-editor.org/rfc/rfc8656#section-18.8
    FieldDescriptor::new("protocol", "Protocol", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(p) => transport_protocol_name(*p),
            _ => None,
        }),
    // RFC 8656, Section 18.10 — https://www.rfc-editor.org/rfc/rfc8656#section-18.10
    FieldDescriptor::new("token", "Reservation Token", FieldType::Bytes).optional(),
    // RFC 8656, Section 18.13 — https://www.rfc-editor.org/rfc/rfc8656#section-18.13
    FieldDescriptor::new("icmp_type", "ICMP Type", FieldType::U8).optional(),
    FieldDescriptor::new("icmp_code", "ICMP Code", FieldType::U8).optional(),
    FieldDescriptor::new("error_data", "Error Data", FieldType::U32).optional(),
    // RFC 6062, Section 6.2.1 — https://www.rfc-editor.org/rfc/rfc6062#section-6.2.1
    FieldDescriptor::new("connection_id", "Connection ID", FieldType::U32).optional(),
    // RFC 8445, Section 16.1 — https://www.rfc-editor.org/rfc/rfc8445#section-16.1
    FieldDescriptor::new("priority", "Priority", FieldType::U32).optional(),
    FieldDescriptor::new("tie_breaker", "Tie Breaker", FieldType::U64).optional(),
    // RFC 5780, Section 7.2 — https://www.rfc-editor.org/rfc/rfc5780#section-7.2
    FieldDescriptor::new("change_ip", "Change IP (A)", FieldType::U8).optional(),
    FieldDescriptor::new("change_port", "Change Port (B)", FieldType::U8).optional(),
    // RFC 5780, Section 7.6 — https://www.rfc-editor.org/rfc/rfc5780#section-7.6
    FieldDescriptor::new("padding", "Padding", FieldType::Bytes).optional(),
];

/// Element descriptor for UNKNOWN-ATTRIBUTES entries.
static FD_UNKNOWN_ATTRIBUTE_TYPE: FieldDescriptor =
    FieldDescriptor::new("attribute_type", "Attribute Type", FieldType::U16).with_display_fn(
        |v, _| match v {
            FieldValue::U16(t) => attribute_type_name(*t),
            _ => None,
        },
    );

/// Password algorithm number (RFC 8489, Section 18.5 —
/// <https://www.rfc-editor.org/rfc/rfc8489#section-18.5>).
const FD_PASSWORD_ALGORITHM: FieldDescriptor =
    FieldDescriptor::new("algorithm", "Algorithm", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(a) => password_algorithm_name(*a),
            _ => None,
        });

/// Password algorithm parameters.
const FD_PASSWORD_ALGORITHM_PARAMETERS: FieldDescriptor = FieldDescriptor::new(
    "algorithm_parameters",
    "Algorithm Parameters",
    FieldType::Bytes,
)
.optional();

/// Children of a PASSWORD-ALGORITHMS entry.
static PASSWORD_ALGORITHM_ENTRY_FIELDS: &[FieldDescriptor] =
    &[FD_PASSWORD_ALGORITHM, FD_PASSWORD_ALGORITHM_PARAMETERS];

/// Element descriptor for PASSWORD-ALGORITHMS entries.
static FD_PASSWORD_ALGORITHM_ENTRY: FieldDescriptor = FieldDescriptor::new(
    "password_algorithm",
    "Password Algorithm",
    FieldType::Object,
)
.with_children(PASSWORD_ALGORITHM_ENTRY_FIELDS);

/// Field descriptors for the STUN dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("message_type", "Message Type", FieldType::U16),
    FieldDescriptor {
        name: "message_class",
        display_name: "Message Class",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(c) => Some(class_name(*c)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "message_method",
        display_name: "Message Method",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(m) => method_name(*m),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("message_length", "Message Length", FieldType::U16),
    // Absent in classic STUN (RFC 5389, Section 12).
    // https://www.rfc-editor.org/rfc/rfc5389#section-12
    FieldDescriptor::new("magic_cookie", "Magic Cookie", FieldType::U32).optional(),
    FieldDescriptor::new("transaction_id", "Transaction ID", FieldType::Bytes),
    FieldDescriptor::new("attributes", "Attributes", FieldType::Array)
        .optional()
        .with_children(ATTR_CHILD_FIELDS),
];

/// Decode the STUN message type into class and method.
///
/// RFC 8489, Section 5, Figure 3 — The message type field uses a non-contiguous
/// bit layout:
///
/// ```text
///         0                 1
///         2  3  4 5 6 7 8 9 0 1 2 3 4 5
///        +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
///        |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
///        |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
///        +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// <https://www.rfc-editor.org/rfc/rfc8489#section-5>.
fn decode_message_type(raw_type: u16) -> (u8, u16) {
    // RFC 8489, Section 5 — https://www.rfc-editor.org/rfc/rfc8489#section-5
    // C0 is at bit 4, C1 at bit 8 of the 14-bit message type value.
    let c0 = (raw_type >> 4) & 0x1;
    let c1 = (raw_type >> 8) & 0x1;
    let class = ((c1 << 1) | c0) as u8;

    // Method bits:
    //   M0-M3  → bits 0-3  (mask 0x000F)
    //   M4-M6  → bits 5-7  (mask 0x00E0, shift right by 1 to skip C0 at bit 4)
    //   M7-M11 → bits 9-13 (mask 0x3E00, shift right by 2 to skip C0 and C1)
    let method = (raw_type & 0x000F) | ((raw_type & 0x00E0) >> 1) | ((raw_type & 0x3E00) >> 2);

    (class, method)
}

/// Push STUN attributes into a [`DissectBuffer`].
///
/// `xor_key` is the key for the XOR- address attributes ([`xor_key`]), or
/// `None` for classic STUN, which has no magic cookie.
///
/// RFC 8489, Section 14 — Each attribute is TLV-encoded with 4-byte alignment —
/// <https://www.rfc-editor.org/rfc/rfc8489#section-14>.
fn push_attrs<'pkt>(
    attr_data: &'pkt [u8],
    buf_offset: usize,
    xor_key: Option<&[u8; 16]>,
    buf: &mut DissectBuffer<'pkt>,
) {
    let mut pos = 0;

    while pos + MIN_ATTR_SIZE <= attr_data.len() {
        let attr_type = read_be_u16(attr_data, pos).unwrap_or_default();
        let attr_len = read_be_u16(attr_data, pos + 2).unwrap_or_default() as usize;

        // RFC 8489, Section 14 — "The value in the Length field MUST contain
        // the length of the Value part of the attribute, prior to padding,
        // measured in bytes." Length excludes the 4-byte TLV header and any
        // trailing padding bytes.
        // https://www.rfc-editor.org/rfc/rfc8489#section-14
        if pos + MIN_ATTR_SIZE + attr_len > attr_data.len() {
            break;
        }

        let abs = buf_offset + pos;
        let value_data = &attr_data[pos + MIN_ATTR_SIZE..pos + MIN_ATTR_SIZE + attr_len];

        let obj_idx = buf.begin_container(
            &FD_ATTRIBUTE,
            FieldValue::Object(0..0),
            abs..abs + MIN_ATTR_SIZE + attr_len,
        );
        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_TYPE],
            FieldValue::U16(attr_type),
            abs..abs + 2,
        );
        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_LENGTH],
            FieldValue::U16(attr_len as u16),
            abs + 2..abs + 4,
        );
        let value_abs = abs + MIN_ATTR_SIZE;
        if !push_attr_value(attr_type, value_data, value_abs, xor_key, buf) {
            buf.push_field(
                &ATTR_CHILD_FIELDS[AFD_VALUE],
                FieldValue::Bytes(value_data),
                value_abs..value_abs + attr_len,
            );
        }
        buf.end_container(obj_idx);

        // RFC 8489, Section 14 — "STUN aligns attributes on 32-bit boundaries,
        // attributes whose content is not a multiple of 4 bytes are padded
        // with 1, 2, or 3 bytes of padding so that its value contains a
        // multiple of 4 bytes."
        // https://www.rfc-editor.org/rfc/rfc8489#section-14
        let padded_len = MIN_ATTR_SIZE + attr_len.next_multiple_of(4);
        pos += padded_len;
    }
}

/// Push the decoded fields of a known attribute value.
///
/// Returns `false` without pushing anything when the attribute type is
/// unknown or the value does not match its specified format; the caller then
/// pushes the raw `value` bytes instead.
fn push_attr_value<'pkt>(
    attr_type: u16,
    v: &'pkt [u8],
    off: usize,
    xor_key: Option<&[u8; 16]>,
    buf: &mut DissectBuffer<'pkt>,
) -> bool {
    let f = |i: usize| &ATTR_CHILD_FIELDS[i];
    match attr_type {
        // RFC 8489, Section 14.1 (MAPPED-ADDRESS), 14.15 (ALTERNATE-SERVER);
        // RFC 5780, Sections 7.3, 7.4 (RESPONSE-ORIGIN, OTHER-ADDRESS) use the
        // MAPPED-ADDRESS format.
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.1
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.15
        // https://www.rfc-editor.org/rfc/rfc5780#section-7.3
        // https://www.rfc-editor.org/rfc/rfc5780#section-7.4
        ATTR_MAPPED_ADDRESS | ATTR_ALTERNATE_SERVER | ATTR_RESPONSE_ORIGIN | ATTR_OTHER_ADDRESS => {
            push_address(v, off, &[0; 16], buf)
        }
        // RFC 8489, Section 14.2 (XOR-MAPPED-ADDRESS); RFC 8656, Sections
        // 18.3, 18.5 (XOR-PEER-ADDRESS, XOR-RELAYED-ADDRESS) — "encoded in the
        // same way as the XOR-MAPPED-ADDRESS attribute".
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.2
        // https://www.rfc-editor.org/rfc/rfc8656#section-18.3
        // https://www.rfc-editor.org/rfc/rfc8656#section-18.5
        //
        // Classic STUN (RFC 3489) has no magic cookie and no XOR- attributes
        // (RFC 5389, Section 12 —
        // https://www.rfc-editor.org/rfc/rfc5389#section-12), so they stay raw.
        ATTR_XOR_MAPPED_ADDRESS | ATTR_XOR_PEER_ADDRESS | ATTR_XOR_RELAYED_ADDRESS => {
            xor_key.is_some_and(|key| push_address(v, off, key, buf))
        }
        // RFC 8489, Sections 14.3, 14.9, 14.10, 14.14, 14.16 — UTF-8 text.
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.3
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.9
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.10
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.14
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.16
        ATTR_USERNAME | ATTR_REALM | ATTR_NONCE | ATTR_SOFTWARE | ATTR_ALTERNATE_DOMAIN => {
            match core::str::from_utf8(v) {
                Ok(text) => {
                    buf.push_field(f(AFD_TEXT), FieldValue::Str(text), off..off + v.len());
                    true
                }
                Err(_) => false,
            }
        }
        // RFC 8489, Section 14.4 — "The value of USERHASH has a fixed length
        // of 32 bytes."
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.4
        ATTR_USERHASH if v.len() == 32 => {
            buf.push_field(f(AFD_USERHASH), FieldValue::Bytes(v), off..off + v.len());
            true
        }
        // RFC 8489, Section 14.5 — "the HMAC will be 20 bytes."; Section 14.6 —
        // "at most 32 bytes, but it MUST be at least 16 bytes and MUST be a
        // multiple of 4 bytes."
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.5
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.6
        ATTR_MESSAGE_INTEGRITY if v.len() == 20 => {
            buf.push_field(f(AFD_HMAC), FieldValue::Bytes(v), off..off + v.len());
            true
        }
        ATTR_MESSAGE_INTEGRITY_SHA256 if (16..=32).contains(&v.len()) && v.len() % 4 == 0 => {
            buf.push_field(f(AFD_HMAC), FieldValue::Bytes(v), off..off + v.len());
            true
        }
        // RFC 8489, Section 14.7 — CRC-32 XOR 0x5354554e (not verified).
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.7
        ATTR_FINGERPRINT => push_u32(v, off, f(AFD_CRC32), buf),
        // RFC 8489, Section 14.8 — https://www.rfc-editor.org/rfc/rfc8489#section-14.8
        ATTR_ERROR_CODE => push_error_code(v, off, false, buf),
        // RFC 8489, Section 14.13 — "The attribute contains a list of 16-bit
        // values, each of which represents an attribute type".
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.13
        ATTR_UNKNOWN_ATTRIBUTES if v.len() % 2 == 0 => {
            let idx = buf.begin_container(
                f(AFD_ATTRIBUTE_TYPES),
                FieldValue::Array(0..0),
                off..off + v.len(),
            );
            for (i, pair) in v.chunks_exact(2).enumerate() {
                let t = u16::from_be_bytes([pair[0], pair[1]]);
                let at = off + i * 2;
                buf.push_field(&FD_UNKNOWN_ATTRIBUTE_TYPE, FieldValue::U16(t), at..at + 2);
            }
            buf.end_container(idx);
            true
        }
        // RFC 8489, Section 14.12 — https://www.rfc-editor.org/rfc/rfc8489#section-14.12
        ATTR_PASSWORD_ALGORITHM => match parse_password_algorithm(v) {
            // The attribute holds exactly one entry. Its parameter padding is
            // normally the attribute padding, but accept it inside the
            // attribute length too.
            Some((algorithm, params, consumed))
                if consumed == v.len() || consumed.next_multiple_of(4) == v.len() =>
            {
                push_password_algorithm(algorithm, params, off, buf);
                true
            }
            _ => false,
        },
        // RFC 8489, Section 14.11 — https://www.rfc-editor.org/rfc/rfc8489#section-14.11
        ATTR_PASSWORD_ALGORITHMS => {
            // Validate the whole list before pushing anything.
            if !PasswordAlgorithmEntries::new(v).all(|entry| entry.is_some()) {
                return false;
            }
            let idx = buf.begin_container(
                f(AFD_ALGORITHMS),
                FieldValue::Array(0..0),
                off..off + v.len(),
            );
            for (pos, algorithm, params) in PasswordAlgorithmEntries::new(v).flatten() {
                let at = off + pos;
                let entry = buf.begin_container(
                    &FD_PASSWORD_ALGORITHM_ENTRY,
                    FieldValue::Object(0..0),
                    at..at + 4 + params.len(),
                );
                push_password_algorithm(algorithm, params, at, buf);
                buf.end_container(entry);
            }
            buf.end_container(idx);
            true
        }
        // RFC 8656, Section 18.1 — "a 16-bit unsigned integer followed by a
        // two-octet RFFU".
        // https://www.rfc-editor.org/rfc/rfc8656#section-18.1
        ATTR_CHANNEL_NUMBER if v.len() == 4 => {
            let n = read_be_u16(v, 0).unwrap_or_default();
            buf.push_field(f(AFD_CHANNEL_NUMBER), FieldValue::U16(n), off..off + 2);
            true
        }
        // RFC 8656, Section 18.2 — https://www.rfc-editor.org/rfc/rfc8656#section-18.2
        ATTR_LIFETIME => push_u32(v, off, f(AFD_LIFETIME), buf),
        // RFC 8656, Section 18.4 — https://www.rfc-editor.org/rfc/rfc8656#section-18.4
        ATTR_DATA => {
            buf.push_field(f(AFD_DATA), FieldValue::Bytes(v), off..off + v.len());
            true
        }
        // RFC 8656, Sections 18.6, 18.11 — Family(8) + Reserved(24).
        // https://www.rfc-editor.org/rfc/rfc8656#section-18.6
        // https://www.rfc-editor.org/rfc/rfc8656#section-18.11
        ATTR_REQUESTED_ADDRESS_FAMILY | ATTR_ADDITIONAL_ADDRESS_FAMILY if v.len() == 4 => {
            buf.push_field(f(AFD_FAMILY), FieldValue::U8(v[0]), off..off + 1);
            true
        }
        // RFC 8656, Section 18.7 — "The value portion of this attribute is 1
        // byte long." R is the most significant bit.
        // https://www.rfc-editor.org/rfc/rfc8656#section-18.7
        ATTR_EVEN_PORT if v.len() == 1 => {
            buf.push_field(f(AFD_RESERVE_NEXT), FieldValue::U8(v[0] >> 7), off..off + 1);
            true
        }
        // RFC 8656, Section 18.8 — Protocol(8) + RFFU(24).
        // https://www.rfc-editor.org/rfc/rfc8656#section-18.8
        ATTR_REQUESTED_TRANSPORT if v.len() == 4 => {
            buf.push_field(f(AFD_PROTOCOL), FieldValue::U8(v[0]), off..off + 1);
            true
        }
        // RFC 8656, Section 18.9 — "This attribute has no value part";
        // RFC 8445, Section 16.1 — USE-CANDIDATE "has no content".
        // https://www.rfc-editor.org/rfc/rfc8656#section-18.9
        // https://www.rfc-editor.org/rfc/rfc8445#section-16.1
        ATTR_DONT_FRAGMENT | ATTR_USE_CANDIDATE => v.is_empty(),
        // RFC 8656, Section 18.10 — "The attribute value is 8 bytes".
        // https://www.rfc-editor.org/rfc/rfc8656#section-18.10
        ATTR_RESERVATION_TOKEN if v.len() == 8 => {
            buf.push_field(f(AFD_TOKEN), FieldValue::Bytes(v), off..off + 8);
            true
        }
        // RFC 8656, Section 18.12 — https://www.rfc-editor.org/rfc/rfc8656#section-18.12
        ATTR_ADDRESS_ERROR_CODE => push_error_code(v, off, true, buf),
        // RFC 8656, Section 18.13 — Reserved(16), ICMP Type, ICMP Code,
        // Error Data(32).
        // https://www.rfc-editor.org/rfc/rfc8656#section-18.13
        ATTR_ICMP if v.len() == 8 => {
            let error_data = read_be_u32(v, 4).unwrap_or_default();
            buf.push_field(f(AFD_ICMP_TYPE), FieldValue::U8(v[2]), off + 2..off + 3);
            buf.push_field(f(AFD_ICMP_CODE), FieldValue::U8(v[3]), off + 3..off + 4);
            buf.push_field(
                f(AFD_ERROR_DATA),
                FieldValue::U32(error_data),
                off + 4..off + 8,
            );
            true
        }
        // RFC 6062, Section 6.2.1 — "a 32-bit unsigned integral value".
        // https://www.rfc-editor.org/rfc/rfc6062#section-6.2.1
        ATTR_CONNECTION_ID => push_u32(v, off, f(AFD_CONNECTION_ID), buf),
        // RFC 8445, Section 16.1 — PRIORITY "is a 32-bit unsigned integer";
        // ICE-CONTROLLED / ICE-CONTROLLING carry "a 64-bit unsigned integer".
        // https://www.rfc-editor.org/rfc/rfc8445#section-16.1
        ATTR_PRIORITY => push_u32(v, off, f(AFD_PRIORITY), buf),
        ATTR_ICE_CONTROLLED | ATTR_ICE_CONTROLLING if v.len() == 8 => {
            let tie_breaker = read_be_u64(v, 0).unwrap_or_default();
            buf.push_field(
                f(AFD_TIE_BREAKER),
                FieldValue::U64(tie_breaker),
                off..off + 8,
            );
            true
        }
        // RFC 5780, Section 7.2 — 32 bits, A ("change IP") and B ("change
        // port") are bits 29 and 30 of the value.
        // https://www.rfc-editor.org/rfc/rfc5780#section-7.2
        ATTR_CHANGE_REQUEST if v.len() == 4 => {
            buf.push_field(
                f(AFD_CHANGE_IP),
                FieldValue::U8((v[3] >> 2) & 1),
                off + 3..off + 4,
            );
            buf.push_field(
                f(AFD_CHANGE_PORT),
                FieldValue::U8((v[3] >> 1) & 1),
                off + 3..off + 4,
            );
            true
        }
        // RFC 5780, Section 7.5 — "a 16-bit unsigned integer in network byte
        // order followed by 2 bytes of padding."
        // https://www.rfc-editor.org/rfc/rfc5780#section-7.5
        ATTR_RESPONSE_PORT if v.len() == 4 => {
            let port = read_be_u16(v, 0).unwrap_or_default();
            buf.push_field(f(AFD_PORT), FieldValue::U16(port), off..off + 2);
            true
        }
        // RFC 5780, Section 7.6 — "PADDING consists entirely of a free-form
        // string, the value of which does not matter."
        // https://www.rfc-editor.org/rfc/rfc5780#section-7.6
        ATTR_PADDING => {
            buf.push_field(f(AFD_PADDING), FieldValue::Bytes(v), off..off + v.len());
            true
        }
        _ => false,
    }
}

/// Push a 4-byte unsigned value.
fn push_u32<'pkt>(
    v: &'pkt [u8],
    off: usize,
    descriptor: &'static FieldDescriptor,
    buf: &mut DissectBuffer<'pkt>,
) -> bool {
    match read_be_u32(v, 0) {
        Ok(value) if v.len() == 4 => {
            buf.push_field(descriptor, FieldValue::U32(value), off..off + 4);
            true
        }
        _ => false,
    }
}

/// Push a (XOR-)MAPPED-ADDRESS style transport address.
///
/// RFC 8489, Section 14.1 — "If the address family is IPv4, the address MUST
/// be 32 bits.  If the address family is IPv6, the address MUST be 128 bits."
/// <https://www.rfc-editor.org/rfc/rfc8489#section-14.1>.
///
/// `key` is XORed onto the port and address: all zeros for a plain address,
/// or the magic cookie followed by the transaction ID for the XOR- attributes
/// (see [`xor_key`]).
fn push_address<'pkt>(
    v: &'pkt [u8],
    off: usize,
    key: &[u8; 16],
    buf: &mut DissectBuffer<'pkt>,
) -> bool {
    let family = match v.get(1) {
        Some(&FAMILY_IPV4) if v.len() == 8 => FAMILY_IPV4,
        Some(&FAMILY_IPV6) if v.len() == 20 => FAMILY_IPV6,
        _ => return false,
    };
    let port = u16::from_be_bytes([v[2] ^ key[0], v[3] ^ key[1]]);
    let mut raw = [0u8; 16];
    for ((b, x), k) in raw.iter_mut().zip(&v[4..]).zip(key) {
        *b = x ^ k;
    }
    let address = if family == FAMILY_IPV4 {
        FieldValue::Ipv4Addr([raw[0], raw[1], raw[2], raw[3]])
    } else {
        FieldValue::Ipv6Addr(raw)
    };
    buf.push_field(
        &ATTR_CHILD_FIELDS[AFD_FAMILY],
        FieldValue::U8(family),
        off + 1..off + 2,
    );
    buf.push_field(
        &ATTR_CHILD_FIELDS[AFD_PORT],
        FieldValue::U16(port),
        off + 2..off + 4,
    );
    buf.push_field(
        &ATTR_CHILD_FIELDS[AFD_ADDRESS],
        address,
        off + 4..off + v.len(),
    );
    true
}

/// XOR key for the XOR- address attributes.
///
/// RFC 8489, Section 14.2 — "X-Port is computed by XOR'ing the mapped port
/// with the most significant 16 bits of the magic cookie.  If the IP address
/// family is IPv4, X-Address is computed by XOR'ing the mapped IP address with
/// the magic cookie.  If the IP address family is IPv6, X-Address is computed
/// by XOR'ing the mapped IP address with the concatenation of the magic cookie
/// and the 96-bit transaction ID."
/// <https://www.rfc-editor.org/rfc/rfc8489#section-14.2>.
fn xor_key(transaction_id: &[u8; 12]) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    key[4..].copy_from_slice(transaction_id);
    key
}

/// Push ERROR-CODE (or, with `family`, ADDRESS-ERROR-CODE) fields.
///
/// RFC 8489, Section 14.8 — "The Class represents the hundreds digit of the
/// error code.  The value MUST be between 3 and 6.  The Number represents the
/// binary encoding of the error code modulo 100, and its value MUST be between
/// 0 and 99."
/// <https://www.rfc-editor.org/rfc/rfc8489#section-14.8>.
/// RFC 8656, Section 18.12 — ADDRESS-ERROR-CODE carries a Family in the first
/// byte. <https://www.rfc-editor.org/rfc/rfc8656#section-18.12>.
fn push_error_code<'pkt>(
    v: &'pkt [u8],
    off: usize,
    family: bool,
    buf: &mut DissectBuffer<'pkt>,
) -> bool {
    if v.len() < 4 {
        return false;
    }
    let class = v[2] & 0x07;
    let number = v[3];
    if !(3..=6).contains(&class) || number > 99 {
        return false;
    }
    let Ok(reason) = core::str::from_utf8(&v[4..]) else {
        return false;
    };
    if family {
        buf.push_field(
            &ATTR_CHILD_FIELDS[AFD_FAMILY],
            FieldValue::U8(v[0]),
            off..off + 1,
        );
    }
    let code = u16::from(class) * 100 + u16::from(number);
    buf.push_field(
        &ATTR_CHILD_FIELDS[AFD_ERROR_CODE],
        FieldValue::U16(code),
        off + 2..off + 4,
    );
    buf.push_field(
        &ATTR_CHILD_FIELDS[AFD_REASON],
        FieldValue::Str(reason),
        off + 4..off + v.len(),
    );
    true
}

/// Parse one algorithm entry: Algorithm(16) + Parameters Length(16) +
/// Parameters. Returns the algorithm, the parameters and the unpadded size.
///
/// RFC 8489, Section 14.11 — "The parameters start with the length (prior to
/// padding) of the parameters as a 16-bit value, followed by the parameters
/// that are specific to each algorithm.  The parameters are padded to a
/// 32-bit boundary, in the same manner as an attribute."
/// <https://www.rfc-editor.org/rfc/rfc8489#section-14.11>.
fn parse_password_algorithm(v: &[u8]) -> Option<(u16, &[u8], usize)> {
    let algorithm = read_be_u16(v, 0).ok()?;
    let len = usize::from(read_be_u16(v, 2).ok()?);
    let params = v.get(4..4 + len)?;
    Some((algorithm, params, 4 + len))
}

/// Iterator over PASSWORD-ALGORITHMS entries as `(offset, algorithm,
/// parameters)`, each padded to a 32-bit boundary. Yields `None` once for a
/// malformed entry and then stops. The padding of the last entry may be the
/// attribute padding.
///
/// RFC 8489, Section 14.11 — <https://www.rfc-editor.org/rfc/rfc8489#section-14.11>.
struct PasswordAlgorithmEntries<'a> {
    v: &'a [u8],
    pos: usize,
    failed: bool,
}

impl<'a> PasswordAlgorithmEntries<'a> {
    fn new(v: &'a [u8]) -> Self {
        Self {
            v,
            pos: 0,
            failed: false,
        }
    }
}

impl<'a> Iterator for PasswordAlgorithmEntries<'a> {
    type Item = Option<(usize, u16, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.pos >= self.v.len() {
            return None;
        }
        let at = self.pos;
        match self.v.get(at..).and_then(parse_password_algorithm) {
            Some((algorithm, params, consumed)) => {
                self.pos = (at + consumed).next_multiple_of(4);
                Some(Some((at, algorithm, params)))
            }
            None => {
                self.failed = true;
                Some(None)
            }
        }
    }
}

/// Push `algorithm` and `algorithm_parameters` for one entry at `at`.
fn push_password_algorithm<'pkt>(
    algorithm: u16,
    params: &'pkt [u8],
    at: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    let fields = PASSWORD_ALGORITHM_ENTRY_FIELDS;
    buf.push_field(&fields[0], FieldValue::U16(algorithm), at..at + 2);
    buf.push_field(
        &fields[1],
        FieldValue::Bytes(params),
        at + 4..at + 4 + params.len(),
    );
}

/// STUN dissector.
pub struct StunDissector;

/// Specification references for the STUN dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 8489",
        "Session Traversal Utilities for NAT (STUN)",
        "https://www.rfc-editor.org/rfc/rfc8489",
    ),
    SpecReference::new(
        "RFC 5389",
        "Session Traversal Utilities for NAT (STUN), Section 12: Backwards Compatibility with RFC 3489",
        "https://www.rfc-editor.org/rfc/rfc5389#section-12",
    ),
    SpecReference::new(
        "RFC 8656",
        "Traversal Using Relays around NAT (TURN), Sections 12 and 17-19: Channels, Methods, Attributes, Error Codes",
        "https://www.rfc-editor.org/rfc/rfc8656",
    ),
    SpecReference::new(
        "RFC 6062",
        "TURN Extensions for TCP Allocations, Section 6",
        "https://www.rfc-editor.org/rfc/rfc6062#section-6",
    ),
    SpecReference::new(
        "RFC 8445",
        "Interactive Connectivity Establishment (ICE), Section 16",
        "https://www.rfc-editor.org/rfc/rfc8445#section-16",
    ),
    SpecReference::new(
        "RFC 5780",
        "NAT Behavior Discovery Using STUN, Section 7",
        "https://www.rfc-editor.org/rfc/rfc5780#section-7",
    ),
];

impl Dissector for StunDissector {
    fn name(&self) -> &'static str {
        "Session Traversal Utilities for NAT"
    }

    fn short_name(&self) -> &'static str {
        "STUN"
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
        dissect_stun(data, buf, offset, Transport::Datagram)
    }
}

/// STUN dissector for stream transports (TCP, TLS-over-TCP).
///
/// Same output as [`StunDissector`], with the stream framing rules: TURN
/// ChannelData messages are always padded to a multiple of four bytes
/// (RFC 8656, Section 12.5 —
/// <https://www.rfc-editor.org/rfc/rfc8656#section-12.5>), and classic STUN
/// is not recognised because RFC 3489 only ran over UDP (RFC 5389,
/// Section 12 — <https://www.rfc-editor.org/rfc/rfc5389#section-12>).
pub struct StunTcpDissector;

impl Dissector for StunTcpDissector {
    fn name(&self) -> &'static str {
        StunDissector.name()
    }

    fn short_name(&self) -> &'static str {
        StunDissector.short_name()
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
        dissect_stun(data, buf, offset, Transport::Stream)
    }
}

/// Parse one STUN message, or hand a TURN ChannelData message to
/// [`dissect_channeldata`].
fn dissect_stun<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    transport: Transport,
) -> Result<DissectResult, PacketError> {
    // RFC 8656, Section 12, Table 3 — "[64..79] | TURN Channel".
    // https://www.rfc-editor.org/rfc/rfc8656#section-12
    if data
        .first()
        .is_some_and(|b| TURN_CHANNEL_FIRST_BYTE.contains(b))
    {
        return dissect_channeldata(data, buf, offset, transport);
    }

    // RFC 8489, Section 5 — STUN header is 20 bytes.
    // https://www.rfc-editor.org/rfc/rfc8489#section-5
    if data.len() < HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: HEADER_SIZE,
            actual: data.len(),
        });
    }

    // RFC 8489, Section 5 — "The most significant 2 bits of every STUN
    // message MUST be zeroes."
    // https://www.rfc-editor.org/rfc/rfc8489#section-5
    if data[0] & 0xC0 != 0 {
        return Err(PacketError::InvalidHeader(
            "top 2 bits of STUN message must be zero",
        ));
    }

    // RFC 8489, Section 5 — STUN Message Type (14 bits, bytes 0-1).
    // https://www.rfc-editor.org/rfc/rfc8489#section-5
    let raw_type = read_be_u16(data, 0)? & 0x3FFF;
    let (class, method) = decode_message_type(raw_type);

    // RFC 8489, Section 5 — Message Length (bytes 2-3).
    // https://www.rfc-editor.org/rfc/rfc8489#section-5
    let msg_len_raw = read_be_u16(data, 2)?;
    let msg_len = msg_len_raw as usize;

    // RFC 8489, Section 5 — "The message length MUST contain the size, in
    // bytes, of the message not including the 20-byte STUN header. Since all
    // STUN attributes are padded to a multiple of 4 bytes, the last 2 bits
    // of this field are always zero."
    // https://www.rfc-editor.org/rfc/rfc8489#section-5
    if msg_len % 4 != 0 {
        return Err(PacketError::InvalidHeader(
            "STUN message length must be a multiple of 4",
        ));
    }

    // RFC 8489, Section 5 — Magic Cookie (bytes 4-7).
    // https://www.rfc-editor.org/rfc/rfc8489#section-5
    let cookie = read_be_u32(data, 4)?;
    let total_len = HEADER_SIZE + msg_len;
    let classic = cookie != MAGIC_COOKIE;
    if classic {
        // RFC 5389, Section 12.2 — "A STUN server can detect when a given
        // Binding request message was sent from an RFC 3489 [RFC3489]
        // client by the absence of the correct value in the magic cookie
        // field."
        // https://www.rfc-editor.org/rfc/rfc5389#section-12.2
        //
        // RFC 5389, Section 12 — "UDP was the only supported transport."
        // https://www.rfc-editor.org/rfc/rfc5389#section-12
        // Only the Binding method is used for compatibility (RFC 5389,
        // Section 12.1 — https://www.rfc-editor.org/rfc/rfc5389#section-12.1),
        // and a datagram holds exactly one message, so a
        // cookie-less message is accepted only when it is a Binding request
        // or response (RFC 3489 has no indications) over UDP that does not
        // leave trailing bytes. A shorter datagram is reported as truncated
        // below.
        if transport == Transport::Stream
            || method != METHOD_BINDING
            || class == CLASS_INDICATION
            || data.len() > total_len
        {
            return Err(PacketError::InvalidFieldValue {
                field: "magic_cookie",
                value: cookie,
            });
        }
    }

    if data.len() < total_len {
        return Err(PacketError::Truncated {
            expected: total_len,
            actual: data.len(),
        });
    }

    buf.begin_layer(
        "STUN",
        classic.then_some(CLASSIC_DISPLAY_NAME),
        FIELD_DESCRIPTORS,
        offset..offset + total_len,
    );

    // Build header fields.
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MESSAGE_TYPE],
        FieldValue::U16(raw_type),
        offset..offset + 2,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MESSAGE_CLASS],
        FieldValue::U8(class),
        offset..offset + 2,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MESSAGE_METHOD],
        FieldValue::U16(method),
        offset..offset + 2,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MESSAGE_LENGTH],
        FieldValue::U16(msg_len_raw),
        offset + 2..offset + 4,
    );
    // RFC 8489, Section 5 — Transaction ID (bytes 8-19, 96 bits).
    // https://www.rfc-editor.org/rfc/rfc8489#section-5
    // Classic STUN (RFC 5389, Section 12) has a 128-bit transaction ID in
    // bytes 4-19 and no magic cookie.
    // https://www.rfc-editor.org/rfc/rfc5389#section-12
    let tid_start = if classic { 4 } else { 8 };
    if !classic {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MAGIC_COOKIE],
            FieldValue::U32(cookie),
            offset + 4..offset + 8,
        );
    }
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_TRANSACTION_ID],
        FieldValue::Bytes(&data[tid_start..HEADER_SIZE]),
        offset + tid_start..offset + HEADER_SIZE,
    );

    // RFC 8489, Section 14 — Parse STUN attributes (TLV).
    // https://www.rfc-editor.org/rfc/rfc8489#section-14
    if msg_len > 0 {
        let attr_data = &data[HEADER_SIZE..total_len];
        let array_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_ATTRIBUTES],
            FieldValue::Array(0..0),
            offset + HEADER_SIZE..offset + total_len,
        );
        let key = (!classic).then(|| {
            let mut transaction_id = [0u8; 12];
            transaction_id.copy_from_slice(&data[8..HEADER_SIZE]);
            xor_key(&transaction_id)
        });
        push_attrs(attr_data, offset + HEADER_SIZE, key.as_ref(), buf);
        buf.end_container(array_idx);
    }

    buf.end_layer();

    Ok(DissectResult::new(total_len, DispatchHint::End))
}

/// Layer short name for TURN ChannelData messages.
const CHANNELDATA_SHORT_NAME: &str = "TURN-ChannelData";

/// ChannelData header size: Channel Number(2) + Length(2).
///
/// RFC 8656, Section 12.4 — <https://www.rfc-editor.org/rfc/rfc8656#section-12.4>.
const CHANNELDATA_HEADER_SIZE: usize = 4;

/// Allowed TURN channel numbers.
///
/// RFC 8656, Section 12, Table 2 — "0x4000 through 0x4FFF: These values are
/// the allowed channel numbers (4096 possible values)."
/// <https://www.rfc-editor.org/rfc/rfc8656#section-12>.
const CHANNEL_NUMBER_RANGE: core::ops::RangeInclusive<u16> = 0x4000..=0x4FFF;

/// Field descriptor indices for [`CHANNELDATA_FIELD_DESCRIPTORS`].
const CFD_CHANNEL_NUMBER: usize = 0;
const CFD_LENGTH: usize = 1;
const CFD_DATA: usize = 2;
const CFD_PADDING: usize = 3;

/// Field descriptors for the TURN ChannelData dissector.
///
/// RFC 8656, Section 12.4 — <https://www.rfc-editor.org/rfc/rfc8656#section-12.4>.
static CHANNELDATA_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("channel_number", "Channel Number", FieldType::U16),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("data", "Application Data", FieldType::Bytes),
    // RFC 8656, Section 12.5 — padding is required over TCP, optional over UDP.
    // https://www.rfc-editor.org/rfc/rfc8656#section-12.5
    FieldDescriptor::new("padding", "Padding", FieldType::Bytes).optional(),
];

/// Specification references for the TURN ChannelData dissector.
static CHANNELDATA_REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 8656",
        "Traversal Using Relays around NAT (TURN), Section 12: Channels",
        "https://www.rfc-editor.org/rfc/rfc8656#section-12",
    ),
    SpecReference::new(
        "RFC 7983",
        "Multiplexing Scheme Updates for SRTP Extension for DTLS, Section 7",
        "https://www.rfc-editor.org/rfc/rfc7983#section-7",
    ),
    SpecReference::new(
        "RFC 9443",
        "Multiplexing Scheme Updates for QUIC",
        "https://www.rfc-editor.org/rfc/rfc9443",
    ),
];

/// TURN ChannelData dissector.
///
/// Parses one ChannelData message (RFC 8656, Section 12.4 —
/// <https://www.rfc-editor.org/rfc/rfc8656#section-12.4>) received over UDP
/// and consumes its padding when present. [`StunDissector`] and
/// [`StunTcpDissector`] parse ChannelData themselves when the first byte is
/// 64-79, so this dissector does not need to be registered on the STUN port.
///
/// The application data is not dispatched further: the peer protocol is only
/// known from the ChannelBind state.
pub struct TurnChannelDataDissector;

impl Dissector for TurnChannelDataDissector {
    fn name(&self) -> &'static str {
        "TURN ChannelData"
    }

    fn short_name(&self) -> &'static str {
        CHANNELDATA_SHORT_NAME
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        CHANNELDATA_FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        CHANNELDATA_REFERENCES
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
        dissect_channeldata(data, buf, offset, Transport::Datagram)
    }
}

/// Parse one TURN ChannelData message.
///
/// RFC 8656, Section 12.4 — <https://www.rfc-editor.org/rfc/rfc8656#section-12.4>.
fn dissect_channeldata<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    transport: Transport,
) -> Result<DissectResult, PacketError> {
    // RFC 8656, Section 12.4 — Channel Number(2) + Length(2).
    // https://www.rfc-editor.org/rfc/rfc8656#section-12.4
    if data.len() < CHANNELDATA_HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: CHANNELDATA_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let channel_number = read_be_u16(data, 0)?;
    // RFC 8656, Section 12.6 — "If the message uses a value in the
    // reserved range (0x5000 through 0xFFFF), then the message is
    // silently discarded."
    // https://www.rfc-editor.org/rfc/rfc8656#section-12.6
    if !CHANNEL_NUMBER_RANGE.contains(&channel_number) {
        return Err(PacketError::InvalidFieldValue {
            field: "channel_number",
            value: u32::from(channel_number),
        });
    }

    // RFC 8656, Section 12.4 — "The Length field specifies the length in
    // bytes of the application data field (i.e., it does not include the
    // size of the ChannelData header).  Note that 0 is a valid length."
    // https://www.rfc-editor.org/rfc/rfc8656#section-12.4
    let length = read_be_u16(data, 2)?;
    let data_end = CHANNELDATA_HEADER_SIZE + usize::from(length);
    if data.len() < data_end {
        return Err(PacketError::Truncated {
            expected: data_end,
            actual: data.len(),
        });
    }

    // RFC 8656, Section 12.5 — "Over TCP and TLS-over-TCP, the ChannelData
    // message MUST be padded to a multiple of four bytes in order to
    // ensure the alignment of subsequent messages. ... Over UDP, the
    // padding is not required but MAY be included."
    // https://www.rfc-editor.org/rfc/rfc8656#section-12.5
    // Over a stream the padding is part of the message, so wait for it.
    // Over UDP consume it when the datagram carries it.
    let padded_end = data_end.next_multiple_of(4);
    let total_len = if data.len() >= padded_end {
        padded_end
    } else if transport == Transport::Stream {
        return Err(PacketError::Truncated {
            expected: padded_end,
            actual: data.len(),
        });
    } else {
        data_end
    };

    buf.begin_layer(
        CHANNELDATA_SHORT_NAME,
        None,
        CHANNELDATA_FIELD_DESCRIPTORS,
        offset..offset + total_len,
    );
    buf.push_field(
        &CHANNELDATA_FIELD_DESCRIPTORS[CFD_CHANNEL_NUMBER],
        FieldValue::U16(channel_number),
        offset..offset + 2,
    );
    buf.push_field(
        &CHANNELDATA_FIELD_DESCRIPTORS[CFD_LENGTH],
        FieldValue::U16(length),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &CHANNELDATA_FIELD_DESCRIPTORS[CFD_DATA],
        FieldValue::Bytes(&data[CHANNELDATA_HEADER_SIZE..data_end]),
        offset + CHANNELDATA_HEADER_SIZE..offset + data_end,
    );
    if total_len > data_end {
        buf.push_field(
            &CHANNELDATA_FIELD_DESCRIPTORS[CFD_PADDING],
            FieldValue::Bytes(&data[data_end..total_len]),
            offset + data_end..offset + total_len,
        );
    }
    buf.end_layer();

    Ok(DissectResult::new(total_len, DispatchHint::End))
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::Field;

    // # RFC 8489 Coverage
    //
    // | RFC Section | Description                           | Test                                    |
    // |-------------|---------------------------------------|-----------------------------------------|
    // | 5           | Header: top 2 bits must be zero       | test_invalid_top_bits                   |
    // | 5           | Header: Message Type (class+method)   | test_parse_binding_request              |
    // | 5           | Header: Message Length                | test_parse_binding_request              |
    // | 5           | Header: Message Length multiple of 4  | test_message_length_not_multiple_of_4   |
    // | 5           | Header: Magic Cookie                  | test_parse_binding_request              |
    // | 5           | Header: Magic Cookie validation       | test_invalid_magic_cookie               |
    // | 5           | Header: Transaction ID                | test_parse_binding_request              |
    // | 5           | Message class: Request                | test_parse_binding_request              |
    // | 5           | Message class: Success Response       | test_parse_binding_response             |
    // | 5           | Message class: Indication             | test_parse_binding_indication           |
    // | 5           | Message class: Error Response         | test_parse_binding_error_response       |
    // | 5           | Truncated header                      | test_truncated_header                   |
    // | 5           | Truncated attributes                  | test_truncated_attributes               |
    // | 14          | TLV attribute parsing                 | test_parse_binding_response             |
    // | 14          | Multiple attributes                   | test_multiple_attributes                |
    // | 14          | 4-byte attribute padding              | test_attribute_with_non_aligned_length  |
    // | 18.2        | Method: Binding (0x001)               | test_parse_binding_request              |
    // | 18.2        | Method: Binding (0x001)               | test_method_names                       |
    // | 18.3        | Attribute Registry (codes & names)    | test_attribute_type_name_lookup         |
    //
    // # STUN attribute value coverage (RFC 8489, RFC 8656, RFC 6062, RFC 8445, RFC 5780)
    //
    // | RFC Section      | Description                              | Test                                        |
    // |------------------|------------------------------------------|---------------------------------------------|
    // | 5769 2.1         | Sample request (SOFTWARE, PRIORITY,      | test_rfc5769_sample_request                 |
    // |                  | ICE-CONTROLLED, USERNAME, M-I, FP)       |                                             |
    // | 5769 2.2         | Sample IPv4 response (XOR-MAPPED-ADDRESS)| test_rfc5769_sample_ipv4_response           |
    // | 5769 2.3         | Sample IPv6 response (XOR-MAPPED-ADDRESS)| test_rfc5769_sample_ipv6_response           |
    // | 5769 2.4         | Long-term auth (USERNAME, NONCE, REALM)  | test_rfc5769_long_term_auth_request         |
    // | 8489 14.1        | MAPPED-ADDRESS (IPv4 / IPv6)             | test_mapped_address_ipv4, _ipv6             |
    // | 8489 14.1        | Unknown family / bad length → raw value  | test_address_malformed_falls_back_to_raw    |
    // | 8489 14.4        | USERHASH                                 | test_userhash                               |
    // | 8489 14.6        | MESSAGE-INTEGRITY-SHA256                 | test_message_integrity_sha256               |
    // | 8489 14.8        | ERROR-CODE                               | test_error_code                             |
    // | 8489 14.8        | ERROR-CODE with invalid class → raw      | test_error_code_malformed                   |
    // | 8489 14.11       | PASSWORD-ALGORITHMS                      | test_password_algorithms                    |
    // | 8489 14.12       | PASSWORD-ALGORITHM                       | test_password_algorithm                     |
    // | 8489 14.13       | UNKNOWN-ATTRIBUTES                       | test_unknown_attributes                     |
    // | 8489 14.15       | ALTERNATE-SERVER                         | test_alternate_server                       |
    // | 8489 14.16       | ALTERNATE-DOMAIN                         | test_alternate_domain                       |
    // | 8489 14.3        | Invalid UTF-8 text → raw value           | test_text_invalid_utf8_falls_back_to_raw    |
    // | 8489 18.3        | Unknown attribute keeps raw value        | test_unknown_attribute_raw_value            |
    // | 8489 14, 8656 18 | Fixed-length value with wrong length     | test_fixed_length_attributes_wrong_length_fall_back_to_raw |
    // | 8656 17          | TURN method names                        | test_method_names                           |
    // | 8656 18.1        | CHANNEL-NUMBER                           | test_turn_channel_number                    |
    // | 8656 18.2        | LIFETIME                                 | test_turn_lifetime                          |
    // | 8656 18.3        | XOR-PEER-ADDRESS                         | test_turn_xor_peer_and_relayed_address      |
    // | 8656 18.4        | DATA                                     | test_turn_data                              |
    // | 8656 18.5        | XOR-RELAYED-ADDRESS                      | test_turn_xor_peer_and_relayed_address      |
    // | 8656 18.6        | REQUESTED-ADDRESS-FAMILY                 | test_turn_address_family_attributes         |
    // | 8656 18.7        | EVEN-PORT                                | test_turn_even_port                         |
    // | 8656 18.8        | REQUESTED-TRANSPORT                      | test_turn_requested_transport               |
    // | 8656 18.9        | DONT-FRAGMENT                            | test_empty_flag_attributes                  |
    // | 8656 18.10       | RESERVATION-TOKEN                        | test_turn_reservation_token                 |
    // | 8656 18.11       | ADDITIONAL-ADDRESS-FAMILY                | test_turn_address_family_attributes         |
    // | 8656 18.12       | ADDRESS-ERROR-CODE                       | test_turn_address_error_code                |
    // | 8656 18.13       | ICMP                                     | test_turn_icmp                              |
    // | 6062 6.1         | TURN-TCP method names                    | test_method_names                           |
    // | 6062 6.2.1       | CONNECTION-ID                            | test_connection_id                          |
    // | 8445 16.1        | PRIORITY / ICE-CONTROLLED                | test_rfc5769_sample_request                 |
    // | 8445 16.1        | USE-CANDIDATE                            | test_empty_flag_attributes                  |
    // | 8445 16.1        | ICE-CONTROLLING                          | test_ice_controlling                        |
    // | 5780 7.2         | CHANGE-REQUEST                           | test_change_request                         |
    // | 5780 7.3, 7.4    | RESPONSE-ORIGIN / OTHER-ADDRESS          | test_response_origin_and_other_address      |
    // | 5780 7.5         | RESPONSE-PORT                            | test_response_port                          |
    // | 5780 7.6         | PADDING                                  | test_padding_attribute                      |
    //
    // # RFC 5389 / RFC 8489 Classic STUN (RFC 3489) Coverage
    //
    // | RFC Section      | Description                            | Test                                      |
    // |------------------|----------------------------------------|-------------------------------------------|
    // | 5389 12, 12.2    | Binding request without magic cookie   | test_classic_binding_request              |
    // | 5389 12.1        | Classic response with attributes       | test_classic_binding_response_with_attrs  |
    // | 5389 12          | Non-Binding without cookie rejected    | test_invalid_magic_cookie                 |
    // | 5389 12          | Classic length must match datagram     | test_classic_length_mismatch_rejected     |
    // | 5389 12          | No classic Binding Indication          | test_classic_indication_rejected          |
    // | 5389 12          | Truncated classic message              | test_classic_truncated                    |
    // | 5389 12          | Classic STUN is UDP only               | test_classic_rejected_over_stream         |
    // | 5389 12          | No XOR- decoding without magic cookie  | test_classic_xor_attribute_stays_raw      |
    //
    // # RFC 8656 (TURN) ChannelData Coverage
    //
    // | RFC Section | Description                                 | Test                                        |
    // |-------------|---------------------------------------------|---------------------------------------------|
    // | 12          | First byte 64-79 demultiplexed as channel   | test_channeldata_via_stun_dissector         |
    // | 12          | ChannelData >= 20 bytes not treated as STUN | test_channeldata_long_via_stun_dissector    |
    // | 12          | First byte 80-127 is not a TURN channel     | test_first_byte_outside_turn_channel_range  |
    // | 12, 12.6    | Reserved channel number                     | test_channeldata_reserved_channel_number    |
    // | 12.4        | Channel Number / Length / Application Data  | test_channeldata_basic                      |
    // | 12.4        | Length 0 is valid                           | test_channeldata_zero_length                |
    // | 12.5        | Padding to 4 bytes (TCP)                    | test_channeldata_with_padding               |
    // | 12.5        | Padding optional (UDP)                      | test_channeldata_without_padding            |
    // | 12.5        | Padding required (TCP)                      | test_channeldata_stream_requires_padding    |
    // | 12.5        | One message consumed per call (pipelining)  | test_channeldata_consumes_one_message       |
    // | 12.6        | Datagram shorter than Length                | test_channeldata_truncated_data             |
    // | 12.4        | Header shorter than 4 bytes                 | test_channeldata_truncated_header           |
    // | 12          | Non-channel first byte rejected             | test_channeldata_dissector_rejects_stun     |

    /// Build a STUN message from parts.
    fn build_stun(class: u8, method: u16, attrs: &[u8]) -> Vec<u8> {
        // Encode message type from class and method.
        // RFC 8489, Section 14.1
        let c0 = (class & 0x1) as u16;
        let c1 = ((class >> 1) & 0x1) as u16;
        let m0_3 = method & 0x000F;
        let m4_6 = (method & 0x0070) << 1;
        let m7_11 = (method & 0x0F80) << 2;
        let raw_type = m7_11 | c1 << 8 | m4_6 | c0 << 4 | m0_3;

        let msg_len = attrs.len() as u16;
        let mut pkt = Vec::with_capacity(HEADER_SIZE + attrs.len());
        pkt.extend_from_slice(&raw_type.to_be_bytes());
        pkt.extend_from_slice(&msg_len.to_be_bytes());
        pkt.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        // Transaction ID: 12 bytes
        pkt.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ]);
        pkt.extend_from_slice(attrs);
        pkt
    }

    /// Build a TLV attribute with padding.
    fn build_attr(attr_type: u16, value: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&attr_type.to_be_bytes());
        buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        buf.extend_from_slice(value);
        // Pad to 4-byte boundary.
        let pad = (4 - (value.len() % 4)) % 4;
        buf.extend(core::iter::repeat_n(0u8, pad));
        buf
    }

    #[test]
    fn test_parse_binding_request() {
        // STUN Binding Request: class=0b00, method=0x001, no attributes.
        let data = build_stun(0b00, 0x001, &[]);
        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(buf.layers().len(), 1);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "STUN");
        assert_eq!(layer.range, 0..20);

        // Message type: Binding Request → raw_type = 0x0001
        assert_eq!(
            buf.field_by_name(layer, "message_type").unwrap().value,
            FieldValue::U16(0x0001)
        );
        assert_eq!(
            buf.field_by_name(layer, "message_class").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_class_name"),
            Some("Request")
        );
        assert_eq!(
            buf.field_by_name(layer, "message_method").unwrap().value,
            FieldValue::U16(0x001)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_method_name"),
            Some("Binding")
        );
        assert_eq!(
            buf.field_by_name(layer, "message_length").unwrap().value,
            FieldValue::U16(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "magic_cookie").unwrap().value,
            FieldValue::U32(MAGIC_COOKIE)
        );
        assert_eq!(
            buf.field_by_name(layer, "transaction_id").unwrap().value,
            FieldValue::Bytes(&[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C
            ])
        );
        // No attributes field when message_length is 0.
        assert!(buf.field_by_name(layer, "attributes").is_none());
    }

    /// Helper: find the nth Object entry within an Array's nested fields.
    fn nth_object_range(
        buf: &DissectBuffer,
        array_range: &core::ops::Range<u32>,
        index: usize,
    ) -> core::ops::Range<u32> {
        let children = buf.nested_fields(array_range);
        let mut obj_count = 0;
        for field in children {
            if let FieldValue::Object(r) = &field.value {
                if obj_count == index {
                    return r.clone();
                }
                obj_count += 1;
            }
        }
        panic!("Object at index {index} not found");
    }

    /// Helper: count Object entries within an Array's nested fields.
    fn count_objects(buf: &DissectBuffer, array_range: &core::ops::Range<u32>) -> usize {
        buf.nested_fields(array_range)
            .iter()
            .filter(|f| matches!(f.value, FieldValue::Object(_)))
            .count()
    }

    #[test]
    fn test_parse_binding_response() {
        // STUN Binding Success Response with XOR-MAPPED-ADDRESS attribute.
        // XOR-MAPPED-ADDRESS (0x0020): 8 bytes value.
        let xor_mapped = build_attr(0x0020, &[0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43]);
        let data = build_stun(0b10, 0x001, &xor_mapped);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        // class = 0b10 → Success Response
        assert_eq!(
            buf.field_by_name(layer, "message_class").unwrap().value,
            FieldValue::U8(0b10)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_class_name"),
            Some("Success Response")
        );

        // Check attribute
        let attrs_field = buf.field_by_name(layer, "attributes").unwrap();
        if let FieldValue::Array(ref array_range) = attrs_field.value {
            assert_eq!(count_objects(&buf, array_range), 1);
            let obj_range = nth_object_range(&buf, array_range, 0);
            let fields = buf.nested_fields(&obj_range);
            let type_field = fields.iter().find(|f| f.name() == "type").unwrap();
            assert_eq!(type_field.value, FieldValue::U16(0x0020));
            // Decoded with the header's cookie and transaction ID.
            let port = fields.iter().find(|f| f.name() == "port").unwrap();
            // X-Port 0xA147 XOR 0x2112 (RFC 5769, Section 2.2 —
            // https://www.rfc-editor.org/rfc/rfc5769#section-2.2).
            assert_eq!(port.value, FieldValue::U16(0x8055));
            assert!(fields.iter().all(|f| f.name() != "value"));
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn test_parse_binding_indication() {
        // STUN Binding Indication: class=0b01, method=0x001.
        let data = build_stun(0b01, 0x001, &[]);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "message_class").unwrap().value,
            FieldValue::U8(0b01)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_class_name"),
            Some("Indication")
        );
    }

    #[test]
    fn test_parse_binding_error_response() {
        // STUN Binding Error Response with ERROR-CODE attribute (0x0009).
        // ERROR-CODE: 4 bytes header (reserved + class + number) + reason phrase.
        let error_value = [
            0x00, 0x00, // reserved
            0x04, // class = 4
            0x01, // number = 01 → error 401
            b'U', b'n', b'a', b'u', b't', b'h', b'o', b'r',
        ];
        let error_attr = build_attr(0x0009, &error_value);
        let data = build_stun(0b11, 0x001, &error_attr);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "message_class").unwrap().value,
            FieldValue::U8(0b11)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_class_name"),
            Some("Error Response")
        );

        let attrs_field = buf.field_by_name(layer, "attributes").unwrap();
        if let FieldValue::Array(ref array_range) = attrs_field.value {
            assert_eq!(count_objects(&buf, array_range), 1);
            let obj_range = nth_object_range(&buf, array_range, 0);
            let fields = buf.nested_fields(&obj_range);
            let type_field = fields.iter().find(|f| f.name() == "type").unwrap();
            assert_eq!(type_field.value, FieldValue::U16(0x0009));
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn test_invalid_magic_cookie() {
        // Only Binding can be classic STUN (RFC 5389, Section 12 —
        // https://www.rfc-editor.org/rfc/rfc5389#section-12), so a missing
        // cookie on any other method is still an error.
        let mut data = build_stun(0b00, 0x003, &[]);
        // Corrupt magic cookie (bytes 4-7).
        data[4] = 0x00;
        data[5] = 0x00;
        data[6] = 0x00;
        data[7] = 0x00;

        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "magic_cookie");
            }
            other => panic!("Expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn test_truncated_header() {
        let data = [0u8; 19];
        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, 20);
                assert_eq!(actual, 19);
            }
            other => panic!("Expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn test_truncated_attributes() {
        // Build a valid header claiming 8 bytes of attributes, but only provide 4.
        let mut data = build_stun(0b00, 0x001, &[]);
        // Set message length to 8 in header.
        data[2] = 0x00;
        data[3] = 0x08;
        // Only 20 bytes total (header only), but claims 20 + 8 = 28.

        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, 28);
                assert_eq!(actual, 20);
            }
            other => panic!("Expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn test_message_length_not_multiple_of_4() {
        let mut data = build_stun(0b00, 0x001, &[]);
        // Set message length to 3 (not multiple of 4).
        data[2] = 0x00;
        data[3] = 0x03;

        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("multiple of 4"));
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn test_invalid_top_bits() {
        let mut data = build_stun(0b00, 0x001, &[]);
        // Set top 2 bits to non-zero.
        data[0] |= 0x80;

        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("top 2 bits"));
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn test_multiple_attributes() {
        // Two attributes: SOFTWARE (0x8022) and FINGERPRINT (0x8028).
        let software = build_attr(0x8022, b"test");
        let fingerprint = build_attr(0x8028, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&software);
        attrs.extend_from_slice(&fingerprint);

        let data = build_stun(0b00, 0x001, &attrs);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let attrs_field = buf.field_by_name(layer, "attributes").unwrap();
        if let FieldValue::Array(ref array_range) = attrs_field.value {
            assert_eq!(count_objects(&buf, array_range), 2);
            // First attribute: SOFTWARE
            let obj0 = nth_object_range(&buf, array_range, 0);
            let fields0 = buf.nested_fields(&obj0);
            let type_field = fields0.iter().find(|f| f.name() == "type").unwrap();
            assert_eq!(type_field.value, FieldValue::U16(0x8022));
            // Second attribute: FINGERPRINT
            let obj1 = nth_object_range(&buf, array_range, 1);
            let fields1 = buf.nested_fields(&obj1);
            let type_field = fields1.iter().find(|f| f.name() == "type").unwrap();
            assert_eq!(type_field.value, FieldValue::U16(0x8028));
            let crc = fields1.iter().find(|f| f.name() == "crc32").unwrap();
            assert_eq!(crc.value, FieldValue::U32(0xDEAD_BEEF));
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn test_dissect_with_offset() {
        let data = build_stun(0b00, 0x001, &[]);
        let offset = 42;
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, offset).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(layer.range, offset..offset + HEADER_SIZE);
        assert_eq!(
            buf.field_by_name(layer, "transaction_id").unwrap().range,
            offset + 8..offset + 20
        );
    }

    #[test]
    fn test_field_descriptors() {
        let descriptors = StunDissector.field_descriptors();
        assert_eq!(descriptors.len(), 7);
        assert_eq!(descriptors[0].name, "message_type");
        assert_eq!(descriptors[6].name, "attributes");
        assert!(descriptors[6].children.is_some());
    }

    #[test]
    fn test_attribute_type_name_lookup() {
        // RFC 8489, Section 18.3 — https://www.rfc-editor.org/rfc/rfc8489#section-18.3
        // Comprehension-required range (0x0000-0x7FFF).
        assert_eq!(attribute_type_name(0x0001), Some("MAPPED-ADDRESS"));
        assert_eq!(attribute_type_name(0x0006), Some("USERNAME"));
        assert_eq!(attribute_type_name(0x0008), Some("MESSAGE-INTEGRITY"));
        assert_eq!(attribute_type_name(0x0009), Some("ERROR-CODE"));
        assert_eq!(attribute_type_name(0x000A), Some("UNKNOWN-ATTRIBUTES"));
        assert_eq!(attribute_type_name(0x0014), Some("REALM"));
        assert_eq!(attribute_type_name(0x0015), Some("NONCE"));
        assert_eq!(
            attribute_type_name(0x001C),
            Some("MESSAGE-INTEGRITY-SHA256")
        );
        assert_eq!(attribute_type_name(0x001D), Some("PASSWORD-ALGORITHM"));
        assert_eq!(attribute_type_name(0x001E), Some("USERHASH"));
        assert_eq!(attribute_type_name(0x0020), Some("XOR-MAPPED-ADDRESS"));
        // Comprehension-optional range (0x8000-0xFFFF).
        assert_eq!(attribute_type_name(0x8002), Some("PASSWORD-ALGORITHMS"));
        assert_eq!(attribute_type_name(0x8003), Some("ALTERNATE-DOMAIN"));
        assert_eq!(attribute_type_name(0x8022), Some("SOFTWARE"));
        assert_eq!(attribute_type_name(0x8023), Some("ALTERNATE-SERVER"));
        assert_eq!(attribute_type_name(0x8028), Some("FINGERPRINT"));
        // Reserved or unassigned codepoints return None.
        assert_eq!(attribute_type_name(0x0000), None);
        assert_eq!(attribute_type_name(0x0002), None);
        assert_eq!(attribute_type_name(0x0010), None);
        // TURN (https://www.rfc-editor.org/rfc/rfc8656#section-18) and
        // RFC 6062 (https://www.rfc-editor.org/rfc/rfc6062#section-6.2).
        assert_eq!(attribute_type_name(0x000C), Some("CHANNEL-NUMBER"));
        assert_eq!(attribute_type_name(0x000D), Some("LIFETIME"));
        assert_eq!(attribute_type_name(0x0012), Some("XOR-PEER-ADDRESS"));
        assert_eq!(attribute_type_name(0x0013), Some("DATA"));
        assert_eq!(attribute_type_name(0x0016), Some("XOR-RELAYED-ADDRESS"));
        assert_eq!(
            attribute_type_name(0x0017),
            Some("REQUESTED-ADDRESS-FAMILY")
        );
        assert_eq!(attribute_type_name(0x0018), Some("EVEN-PORT"));
        assert_eq!(attribute_type_name(0x0019), Some("REQUESTED-TRANSPORT"));
        assert_eq!(attribute_type_name(0x001A), Some("DONT-FRAGMENT"));
        assert_eq!(attribute_type_name(0x0022), Some("RESERVATION-TOKEN"));
        assert_eq!(attribute_type_name(0x002A), Some("CONNECTION-ID"));
        assert_eq!(
            attribute_type_name(0x8000),
            Some("ADDITIONAL-ADDRESS-FAMILY")
        );
        assert_eq!(attribute_type_name(0x8001), Some("ADDRESS-ERROR-CODE"));
        assert_eq!(attribute_type_name(0x8004), Some("ICMP"));
        // ICE (https://www.rfc-editor.org/rfc/rfc8445#section-16.1).
        assert_eq!(attribute_type_name(0x0024), Some("PRIORITY"));
        assert_eq!(attribute_type_name(0x0025), Some("USE-CANDIDATE"));
        assert_eq!(attribute_type_name(0x8029), Some("ICE-CONTROLLED"));
        assert_eq!(attribute_type_name(0x802A), Some("ICE-CONTROLLING"));
        // NAT behavior discovery (https://www.rfc-editor.org/rfc/rfc5780#section-7).
        assert_eq!(attribute_type_name(0x0003), Some("CHANGE-REQUEST"));
        assert_eq!(attribute_type_name(0x0026), Some("PADDING"));
        assert_eq!(attribute_type_name(0x0027), Some("RESPONSE-PORT"));
        assert_eq!(attribute_type_name(0x802B), Some("RESPONSE-ORIGIN"));
        assert_eq!(attribute_type_name(0x802C), Some("OTHER-ADDRESS"));
        assert_eq!(attribute_type_name(0xFFFF), None);
    }

    #[test]
    fn test_attribute_with_non_aligned_length() {
        // Attribute with 3-byte value (needs 1 byte of padding).
        let attr = build_attr(0x8022, b"abc");
        let data = build_stun(0b10, 0x001, &attr);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let attrs_field = buf.field_by_name(layer, "attributes").unwrap();
        if let FieldValue::Array(ref array_range) = attrs_field.value {
            assert_eq!(count_objects(&buf, array_range), 1);
            let obj_range = nth_object_range(&buf, array_range, 0);
            let fields = buf.nested_fields(&obj_range);
            let len_field = fields.iter().find(|f| f.name() == "length").unwrap();
            assert_eq!(len_field.value, FieldValue::U16(3));
            let text = fields.iter().find(|f| f.name() == "text").unwrap();
            assert_eq!(text.value, FieldValue::Str("abc"));
            assert_eq!(text.range, 24..27);
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn test_attribute_display_name() {
        let attr = build_attr(0x0020, &[0x00; 8]);
        let data = build_stun(0b10, 0x001, &attr);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let attrs_field = buf.field_by_name(layer, "attributes").unwrap();
        if let FieldValue::Array(ref array_range) = attrs_field.value {
            let obj_range = nth_object_range(&buf, array_range, 0);
            assert_eq!(
                buf.resolve_nested_display_name(&obj_range, "type_name"),
                Some("XOR-MAPPED-ADDRESS")
            );
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn attribute_container_resolves_to_attribute_name() {
        // USERNAME attribute so the container label resolves to "USERNAME"
        // rather than duplicating the inner "Attribute Type" label.
        let attr = build_attr(0x0006, b"user");
        let data = build_stun(0b00, 0x001, &attr);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let (idx, field) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "attribute")
            .expect("attribute container not found");
        assert!(matches!(field.value, FieldValue::Object(_)));
        assert_eq!(field.display_name(), "Attribute");
        assert_eq!(
            buf.resolve_container_display_name(idx as u32),
            Some("USERNAME")
        );
    }

    #[test]
    fn test_no_attributes_when_length_zero() {
        let data = build_stun(0b00, 0x001, &[]);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(buf.field_by_name(&buf.layers()[0], "attributes").is_none());
    }

    // --- Attribute values ----------------------------------------------------

    /// Transaction ID of the RFC 5769 Section 2.1-2.3 test vectors
    /// (<https://www.rfc-editor.org/rfc/rfc5769#section-2>).
    const RFC5769_TID: [u8; 12] = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];

    /// Parse a hex dump (whitespace separated) into bytes.
    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    /// Fields of the `index`th attribute object.
    fn attr<'a>(buf: &'a DissectBuffer<'a>, index: usize) -> &'a [Field<'a>] {
        let layer = &buf.layers()[0];
        let FieldValue::Array(ref array_range) =
            buf.field_by_name(layer, "attributes").unwrap().value
        else {
            panic!("expected Array");
        };
        let obj = nth_object_range(buf, array_range, index);
        buf.nested_fields(&obj)
    }

    fn get<'a>(fields: &'a [Field<'a>], name: &str) -> Option<&'a FieldValue<'a>> {
        fields.iter().find(|f| f.name() == name).map(|f| &f.value)
    }

    /// Resolve a child's display name via its descriptor's `display_fn`.
    fn display<'a>(fields: &'a [Field<'a>], name: &str) -> Option<&'static str> {
        let field = fields.iter().find(|f| f.name() == name)?;
        (field.descriptor.display_fn?)(&field.value, fields)
    }

    /// Dissect a single-attribute message and return the buffer.
    fn dissect_one(class: u8, method: u16, attr_type: u16, value: &[u8]) -> DissectBuffer<'static> {
        let data: &'static [u8] =
            Box::leak(build_stun(class, method, &build_attr(attr_type, value)).into_boxed_slice());
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(data, &mut buf, 0).unwrap();
        buf
    }

    #[test]
    fn test_rfc5769_sample_request() {
        let data = hex("00 01 00 58 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
             80 22 00 10 53 54 55 4e 20 74 65 73 74 20 63 6c 69 65 6e 74
             00 24 00 04 6e 00 01 ff
             80 29 00 08 93 2f f9 b1 51 26 3b 36
             00 06 00 09 65 76 74 6a 3a 68 36 76 59 20 20 20
             00 08 00 14 9a ea a7 0c bf d8 cb 56 78 1e f2 b5 b2 d3 f2 49 c1 b5 71 a2
             80 28 00 04 e5 7a 3b cf");
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        let software = attr(&buf, 0);
        assert_eq!(
            get(software, "text"),
            Some(&FieldValue::Str("STUN test client"))
        );
        assert!(get(software, "value").is_none());
        let priority = attr(&buf, 1);
        assert_eq!(
            get(priority, "priority"),
            Some(&FieldValue::U32(0x6e00_01ff))
        );
        let controlled = attr(&buf, 2);
        assert_eq!(
            get(controlled, "tie_breaker"),
            Some(&FieldValue::U64(0x932f_f9b1_5126_3b36))
        );
        let username = attr(&buf, 3);
        assert_eq!(get(username, "text"), Some(&FieldValue::Str("evtj:h6vY")));
        let integrity = attr(&buf, 4);
        assert_eq!(
            get(integrity, "hmac"),
            Some(&FieldValue::Bytes(&data[80..100]))
        );
        let fingerprint = attr(&buf, 5);
        assert_eq!(
            get(fingerprint, "crc32"),
            Some(&FieldValue::U32(0xe57a_3bcf))
        );
    }

    #[test]
    fn test_rfc5769_sample_ipv4_response() {
        let data = hex("01 01 00 3c 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
             80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
             00 20 00 08 00 01 a1 47 e1 12 a6 43
             00 08 00 14 2b 91 f5 99 fd 9e 90 c3 8c 74 89 f9 2a f9 ba 53 f0 6b e7 d7
             80 28 00 04 c0 7d 4c 96");
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(
            get(attr(&buf, 0), "text"),
            Some(&FieldValue::Str("test vector"))
        );
        let xma = attr(&buf, 1);
        assert_eq!(get(xma, "family"), Some(&FieldValue::U8(1)));
        assert_eq!(display(xma, "family"), Some("IPv4"));
        assert_eq!(get(xma, "port"), Some(&FieldValue::U16(32853)));
        assert_eq!(
            get(xma, "address"),
            Some(&FieldValue::Ipv4Addr([192, 0, 2, 1]))
        );
        assert!(get(xma, "value").is_none());
        let address = xma.iter().find(|f| f.name() == "address").unwrap();
        assert_eq!(address.range, 44..48);
    }

    #[test]
    fn test_rfc5769_sample_ipv6_response() {
        let data = hex("01 01 00 48 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
             80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
             00 20 00 14 00 02 a1 47 01 13 a9 fa a5 d3 f1 79 bc 25 f4 b5 be d2 b9 d9
             00 08 00 14 a3 82 95 4e 4b e6 7b f1 17 84 c9 7c 82 92 c2 75 bf e3 ed 41
             80 28 00 04 c8 fb 0b 4c");
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "transaction_id")
                .unwrap()
                .value,
            FieldValue::Bytes(&RFC5769_TID)
        );
        let xma = attr(&buf, 1);
        assert_eq!(get(xma, "family"), Some(&FieldValue::U8(2)));
        assert_eq!(display(xma, "family"), Some("IPv6"));
        assert_eq!(get(xma, "port"), Some(&FieldValue::U16(32853)));
        assert_eq!(
            get(xma, "address"),
            Some(&FieldValue::Ipv6Addr([
                0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0x66, 0x77
            ]))
        );
        assert_eq!(
            get(attr(&buf, 3), "crc32"),
            Some(&FieldValue::U32(0xc8fb_0b4c))
        );
    }

    #[test]
    fn test_rfc5769_long_term_auth_request() {
        let data = hex("00 01 00 60 21 12 a4 42 78 ad 34 33 c6 ad 72 c0 29 da 41 2e
             00 06 00 12 e3 83 9e e3 83 88 e3 83 aa e3 83 83 e3 82 af e3 82 b9 00 00
             00 15 00 1c 66 2f 2f 34 39 39 6b 39 35 34 64 36 4f 4c 33 34 6f 4c 39 46
                         53 54 76 79 36 34 73 41
             00 14 00 0b 65 78 61 6d 70 6c 65 2e 6f 72 67 00
             00 08 00 14 f6 70 24 65 6d d6 4a 3e 02 b8 e0 71 2e 85 c9 a2 8c a8 96 66");
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(
            get(attr(&buf, 0), "text"),
            Some(&FieldValue::Str(
                "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}"
            ))
        );
        assert_eq!(
            get(attr(&buf, 1), "text"),
            Some(&FieldValue::Str("f//499k954d6OL34oL9FSTvy64sA"))
        );
        assert_eq!(
            get(attr(&buf, 2), "text"),
            Some(&FieldValue::Str("example.org"))
        );
    }

    #[test]
    fn test_mapped_address_ipv4() {
        let buf = dissect_one(0b10, 0x001, 0x0001, &[0x00, 0x01, 0x80, 0x55, 192, 0, 2, 1]);
        let a = attr(&buf, 0);
        assert_eq!(get(a, "port"), Some(&FieldValue::U16(0x8055)));
        assert_eq!(
            get(a, "address"),
            Some(&FieldValue::Ipv4Addr([192, 0, 2, 1]))
        );
    }

    #[test]
    fn test_mapped_address_ipv6() {
        let mut v = vec![0x00, 0x02, 0x12, 0x34];
        v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let buf = dissect_one(0b10, 0x001, 0x0001, &v);
        let a = attr(&buf, 0);
        assert_eq!(get(a, "port"), Some(&FieldValue::U16(0x1234)));
        assert_eq!(
            get(a, "address"),
            Some(&FieldValue::Ipv6Addr([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ]))
        );
    }

    #[test]
    fn test_address_malformed_falls_back_to_raw() {
        // Unknown family.
        let buf = dissect_one(0b10, 0x001, 0x0020, &[0x00, 0x03, 0xa1, 0x47, 0, 0, 0, 0]);
        let a = attr(&buf, 0);
        assert!(get(a, "address").is_none());
        assert_eq!(
            get(a, "value"),
            Some(&FieldValue::Bytes(&[0x00, 0x03, 0xa1, 0x47, 0, 0, 0, 0]))
        );
        // IPv6 family with an IPv4-sized value.
        let buf = dissect_one(0b10, 0x001, 0x0001, &[0x00, 0x02, 0xa1, 0x47, 0, 0, 0, 0]);
        assert!(get(attr(&buf, 0), "value").is_some());
    }

    #[test]
    fn test_text_invalid_utf8_falls_back_to_raw() {
        let buf = dissect_one(0b00, 0x001, 0x0006, &[0xff, 0xfe]);
        let a = attr(&buf, 0);
        assert!(get(a, "text").is_none());
        assert_eq!(get(a, "value"), Some(&FieldValue::Bytes(&[0xff, 0xfe])));
    }

    #[test]
    fn test_fixed_length_attributes_wrong_length_fall_back_to_raw() {
        // Each fixed-length attribute with a value one byte too long keeps
        // the raw `value` instead of decoding partial data.
        for (attr_type, good_len) in [
            (0x000C, 4),  // CHANNEL-NUMBER
            (0x000D, 4),  // LIFETIME
            (0x0017, 4),  // REQUESTED-ADDRESS-FAMILY
            (0x0018, 1),  // EVEN-PORT
            (0x0019, 4),  // REQUESTED-TRANSPORT
            (0x0022, 8),  // RESERVATION-TOKEN
            (0x8004, 8),  // ICMP
            (0x8029, 8),  // ICE-CONTROLLED
            (0x802A, 8),  // ICE-CONTROLLING
            (0x0003, 4),  // CHANGE-REQUEST
            (0x0027, 4),  // RESPONSE-PORT
            (0x001E, 32), // USERHASH
            (0x0008, 20), // MESSAGE-INTEGRITY
            (0x002A, 4),  // CONNECTION-ID
            (0x0024, 4),  // PRIORITY
            (0x8028, 4),  // FINGERPRINT
        ] {
            let v = vec![0x01; good_len + 1];
            let buf = dissect_one(0b00, 0x001, attr_type, &v);
            let a = attr(&buf, 0);
            assert_eq!(
                get(a, "value"),
                Some(&FieldValue::Bytes(&v[..])),
                "attribute {attr_type:#06x}"
            );
            assert_eq!(a.len(), 3, "attribute {attr_type:#06x}");
        }
        // MESSAGE-INTEGRITY-SHA256: shorter than 16 or not a multiple of 4.
        for len in [12, 18, 36] {
            let buf = dissect_one(0b00, 0x001, 0x001C, &vec![0; len]);
            assert!(get(attr(&buf, 0), "value").is_some(), "len {len}");
        }
        // DONT-FRAGMENT / USE-CANDIDATE with a value.
        for attr_type in [0x001A, 0x0025] {
            let buf = dissect_one(0b00, 0x001, attr_type, &[0]);
            assert!(get(attr(&buf, 0), "value").is_some());
        }
    }

    #[test]
    fn test_unknown_attribute_raw_value() {
        let buf = dissect_one(0b00, 0x001, 0x7fff, &[1, 2, 3]);
        let a = attr(&buf, 0);
        assert_eq!(get(a, "value"), Some(&FieldValue::Bytes(&[1, 2, 3])));
    }

    #[test]
    fn test_userhash() {
        let buf = dissect_one(0b00, 0x001, 0x001E, &[0xAB; 32]);
        assert_eq!(
            get(attr(&buf, 0), "userhash"),
            Some(&FieldValue::Bytes(&[0xAB; 32]))
        );
    }

    #[test]
    fn test_message_integrity_sha256() {
        let buf = dissect_one(0b00, 0x001, 0x001C, &[0xCD; 32]);
        assert_eq!(
            get(attr(&buf, 0), "hmac"),
            Some(&FieldValue::Bytes(&[0xCD; 32]))
        );
    }

    #[test]
    fn test_error_code() {
        let mut v = vec![0x00, 0x00, 0x04, 0x01];
        v.extend_from_slice(b"Unauthorized");
        let buf = dissect_one(0b11, 0x001, 0x0009, &v);
        let a = attr(&buf, 0);
        assert_eq!(get(a, "error_code"), Some(&FieldValue::U16(401)));
        assert_eq!(display(a, "error_code"), Some("Unauthenticated"));
        assert_eq!(get(a, "reason"), Some(&FieldValue::Str("Unauthorized")));
        // Empty reason phrase is valid.
        let buf = dissect_one(0b11, 0x001, 0x0009, &[0x00, 0x00, 0x04, 0x26]);
        let a = attr(&buf, 0);
        assert_eq!(get(a, "error_code"), Some(&FieldValue::U16(438)));
        assert_eq!(display(a, "error_code"), Some("Stale Nonce"));
        assert_eq!(get(a, "reason"), Some(&FieldValue::Str("")));
    }

    #[test]
    fn test_error_code_malformed() {
        // Number 100 is out of range (MUST be 0-99).
        let buf = dissect_one(0b11, 0x001, 0x0009, &[0x00, 0x00, 0x04, 100]);
        let a = attr(&buf, 0);
        assert!(get(a, "error_code").is_none());
        assert!(get(a, "value").is_some());
        // Too short.
        let buf = dissect_one(0b11, 0x001, 0x0009, &[0x00, 0x00, 0x04]);
        assert!(get(attr(&buf, 0), "value").is_some());
    }

    #[test]
    fn test_error_code_names() {
        for (code, name) in [
            (300, "Try Alternate"),
            (400, "Bad Request"),
            (401, "Unauthenticated"),
            (403, "Forbidden"),
            (420, "Unknown Attribute"),
            (437, "Allocation Mismatch"),
            (438, "Stale Nonce"),
            (440, "Address Family not Supported"),
            (441, "Wrong Credentials"),
            (442, "Unsupported Transport Protocol"),
            (443, "Peer Address Family Mismatch"),
            (446, "Connection Already Exists"),
            (447, "Connection Timeout or Failure"),
            (486, "Allocation Quota Reached"),
            (487, "Role Conflict"),
            (500, "Server Error"),
            (508, "Insufficient Capacity"),
        ] {
            assert_eq!(error_code_name(code), Some(name), "{code}");
        }
        assert_eq!(error_code_name(499), None);
    }

    #[test]
    fn test_unknown_attributes() {
        let buf = dissect_one(0b11, 0x001, 0x000A, &[0x00, 0x1A, 0x7F, 0x00, 0x00, 0x25]);
        let a = attr(&buf, 0);
        let Some(FieldValue::Array(r)) = get(a, "attribute_types") else {
            panic!("expected attribute_types array");
        };
        let types: Vec<_> = buf
            .nested_fields(r)
            .iter()
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(
            types,
            [
                FieldValue::U16(0x001A),
                FieldValue::U16(0x7F00),
                FieldValue::U16(0x0025)
            ]
        );
        let first = &buf.nested_fields(r)[0];
        assert_eq!(
            (first.descriptor.display_fn.unwrap())(&first.value, &[]),
            Some("DONT-FRAGMENT")
        );
        // Odd length is malformed.
        let buf = dissect_one(0b11, 0x001, 0x000A, &[0x00, 0x1A, 0x7F]);
        assert!(get(attr(&buf, 0), "value").is_some());
    }

    #[test]
    fn test_password_algorithm() {
        let buf = dissect_one(0b00, 0x001, 0x001D, &[0x00, 0x02, 0x00, 0x00]);
        let a = attr(&buf, 0);
        assert_eq!(get(a, "algorithm"), Some(&FieldValue::U16(2)));
        assert_eq!(display(a, "algorithm"), Some("SHA-256"));
        assert_eq!(
            get(a, "algorithm_parameters"),
            Some(&FieldValue::Bytes(&[]))
        );
        // Parameter padding counted in the attribute length is accepted.
        let buf = dissect_one(
            0b00,
            0x001,
            0x001D,
            &[0x00, 0x01, 0x00, 0x01, 0xAA, 0, 0, 0],
        );
        let a = attr(&buf, 0);
        assert_eq!(
            get(a, "algorithm_parameters"),
            Some(&FieldValue::Bytes(&[0xAA]))
        );
        // Parameters longer than the attribute are malformed.
        let buf = dissect_one(0b00, 0x001, 0x001D, &[0x00, 0x01, 0x00, 0x08]);
        assert!(get(attr(&buf, 0), "value").is_some());
    }

    #[test]
    fn test_password_algorithms() {
        // MD5 with 3 parameter bytes (padded to 4), then SHA-256 without.
        let v = [
            0x00, 0x01, 0x00, 0x03, 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02, 0x00, 0x00,
        ];
        let buf = dissect_one(0b10, 0x001, 0x8002, &v);
        let a = attr(&buf, 0);
        let Some(FieldValue::Array(r)) = get(a, "algorithms") else {
            panic!("expected algorithms array");
        };
        let entries: Vec<_> = buf
            .nested_fields(r)
            .iter()
            .filter_map(|f| match &f.value {
                FieldValue::Object(o) => Some(o.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(entries.len(), 2);
        let first = buf.nested_fields(&entries[0]);
        assert_eq!(get(first, "algorithm"), Some(&FieldValue::U16(1)));
        assert_eq!(display(first, "algorithm"), Some("MD5"));
        assert_eq!(
            get(first, "algorithm_parameters"),
            Some(&FieldValue::Bytes(&[0xAA, 0xBB, 0xCC]))
        );
        let second = buf.nested_fields(&entries[1]);
        assert_eq!(get(second, "algorithm"), Some(&FieldValue::U16(2)));
        // Truncated entry is malformed.
        let buf = dissect_one(0b10, 0x001, 0x8002, &[0x00, 0x01, 0x00, 0x04, 0xAA]);
        assert!(get(attr(&buf, 0), "value").is_some());
    }

    #[test]
    fn test_alternate_server() {
        let buf = dissect_one(0b11, 0x001, 0x8023, &[0x00, 0x01, 0x0D, 0x96, 10, 0, 0, 1]);
        let a = attr(&buf, 0);
        assert_eq!(get(a, "port"), Some(&FieldValue::U16(3478)));
        assert_eq!(
            get(a, "address"),
            Some(&FieldValue::Ipv4Addr([10, 0, 0, 1]))
        );
    }

    #[test]
    fn test_alternate_domain() {
        let buf = dissect_one(0b11, 0x001, 0x8003, b"turn.example.org");
        assert_eq!(
            get(attr(&buf, 0), "text"),
            Some(&FieldValue::Str("turn.example.org"))
        );
    }

    #[test]
    fn test_method_names() {
        for (m, name) in [
            (0x001, "Binding"),
            (0x003, "Allocate"),
            (0x004, "Refresh"),
            (0x006, "Send"),
            (0x007, "Data"),
            (0x008, "CreatePermission"),
            (0x009, "ChannelBind"),
            (0x00A, "Connect"),
            (0x00B, "ConnectionBind"),
            (0x00C, "ConnectionAttempt"),
        ] {
            assert_eq!(method_name(m), Some(name), "{m:#x}");
        }
        assert_eq!(method_name(0x000), None);
        assert_eq!(method_name(0x002), None);
        assert_eq!(method_name(0x005), None);

        // Allocate request resolves its method name through the layer.
        let data = build_stun(0b00, 0x003, &[]);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "message_method_name"),
            Some("Allocate")
        );
    }

    #[test]
    fn test_turn_channel_number() {
        let buf = dissect_one(0b00, 0x009, 0x000C, &[0x40, 0x01, 0x00, 0x00]);
        assert_eq!(
            get(attr(&buf, 0), "channel_number"),
            Some(&FieldValue::U16(0x4001))
        );
    }

    #[test]
    fn test_turn_lifetime() {
        let buf = dissect_one(0b10, 0x003, 0x000D, &[0x00, 0x00, 0x02, 0x58]);
        assert_eq!(get(attr(&buf, 0), "lifetime"), Some(&FieldValue::U32(600)));
    }

    #[test]
    fn test_turn_xor_peer_and_relayed_address() {
        // 192.0.2.1:32853 XOR-encoded (RFC 8489, Section 14.2 —
        // https://www.rfc-editor.org/rfc/rfc8489#section-14.2).
        let v = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        for attr_type in [0x0012, 0x0016] {
            let buf = dissect_one(0b10, 0x003, attr_type, &v);
            let a = attr(&buf, 0);
            assert_eq!(get(a, "port"), Some(&FieldValue::U16(32853)));
            assert_eq!(
                get(a, "address"),
                Some(&FieldValue::Ipv4Addr([192, 0, 2, 1]))
            );
        }
    }

    #[test]
    fn test_turn_data() {
        let buf = dissect_one(0b01, 0x006, 0x0013, &[0x80, 0x60, 0x00]);
        assert_eq!(
            get(attr(&buf, 0), "data"),
            Some(&FieldValue::Bytes(&[0x80, 0x60, 0x00]))
        );
    }

    #[test]
    fn test_turn_address_family_attributes() {
        for attr_type in [0x0017, 0x8000] {
            let buf = dissect_one(0b00, 0x003, attr_type, &[0x02, 0x00, 0x00, 0x00]);
            let a = attr(&buf, 0);
            assert_eq!(get(a, "family"), Some(&FieldValue::U8(2)));
            assert_eq!(display(a, "family"), Some("IPv6"));
        }
    }

    #[test]
    fn test_turn_even_port() {
        let buf = dissect_one(0b00, 0x003, 0x0018, &[0x80]);
        assert_eq!(get(attr(&buf, 0), "reserve_next"), Some(&FieldValue::U8(1)));
        let buf = dissect_one(0b00, 0x003, 0x0018, &[0x7F]);
        assert_eq!(get(attr(&buf, 0), "reserve_next"), Some(&FieldValue::U8(0)));
    }

    #[test]
    fn test_turn_requested_transport() {
        let buf = dissect_one(0b00, 0x003, 0x0019, &[17, 0, 0, 0]);
        let a = attr(&buf, 0);
        assert_eq!(get(a, "protocol"), Some(&FieldValue::U8(17)));
        assert_eq!(display(a, "protocol"), Some("UDP"));
    }

    #[test]
    fn test_empty_flag_attributes() {
        // DONT-FRAGMENT and USE-CANDIDATE carry no value.
        for attr_type in [0x001A, 0x0025] {
            let buf = dissect_one(0b00, 0x001, attr_type, &[]);
            let a = attr(&buf, 0);
            assert_eq!(get(a, "length"), Some(&FieldValue::U16(0)));
            assert!(get(a, "value").is_none());
        }
    }

    #[test]
    fn test_turn_reservation_token() {
        let buf = dissect_one(0b10, 0x003, 0x0022, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            get(attr(&buf, 0), "token"),
            Some(&FieldValue::Bytes(&[1, 2, 3, 4, 5, 6, 7, 8]))
        );
    }

    #[test]
    fn test_turn_address_error_code() {
        let mut v = vec![0x02, 0x00, 0x04, 40];
        v.extend_from_slice(b"Address Family not Supported");
        let buf = dissect_one(0b10, 0x003, 0x8001, &v);
        let a = attr(&buf, 0);
        assert_eq!(get(a, "family"), Some(&FieldValue::U8(2)));
        assert_eq!(get(a, "error_code"), Some(&FieldValue::U16(440)));
        assert_eq!(
            get(a, "reason"),
            Some(&FieldValue::Str("Address Family not Supported"))
        );
    }

    #[test]
    fn test_turn_icmp() {
        let buf = dissect_one(0b01, 0x007, 0x8004, &[0, 0, 3, 4, 0, 0, 0x05, 0xDC]);
        let a = attr(&buf, 0);
        assert_eq!(get(a, "icmp_type"), Some(&FieldValue::U8(3)));
        assert_eq!(get(a, "icmp_code"), Some(&FieldValue::U8(4)));
        assert_eq!(get(a, "error_data"), Some(&FieldValue::U32(1500)));
    }

    #[test]
    fn test_connection_id() {
        let buf = dissect_one(0b01, 0x00C, 0x002A, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            get(attr(&buf, 0), "connection_id"),
            Some(&FieldValue::U32(0xDEAD_BEEF))
        );
    }

    #[test]
    fn test_ice_controlling() {
        let buf = dissect_one(0b00, 0x001, 0x802A, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            get(attr(&buf, 0), "tie_breaker"),
            Some(&FieldValue::U64(0x0102_0304_0506_0708))
        );
    }

    #[test]
    fn test_change_request() {
        let buf = dissect_one(0b00, 0x001, 0x0003, &[0, 0, 0, 0x06]);
        let a = attr(&buf, 0);
        assert_eq!(get(a, "change_ip"), Some(&FieldValue::U8(1)));
        assert_eq!(get(a, "change_port"), Some(&FieldValue::U8(1)));
        let buf = dissect_one(0b00, 0x001, 0x0003, &[0, 0, 0, 0x02]);
        let a = attr(&buf, 0);
        assert_eq!(get(a, "change_ip"), Some(&FieldValue::U8(0)));
        assert_eq!(get(a, "change_port"), Some(&FieldValue::U8(1)));
    }

    #[test]
    fn test_response_origin_and_other_address() {
        for attr_type in [0x802B, 0x802C] {
            let buf = dissect_one(
                0b10,
                0x001,
                attr_type,
                &[0x00, 0x01, 0x0D, 0x97, 10, 0, 0, 2],
            );
            let a = attr(&buf, 0);
            assert_eq!(get(a, "port"), Some(&FieldValue::U16(3479)));
            assert_eq!(
                get(a, "address"),
                Some(&FieldValue::Ipv4Addr([10, 0, 0, 2]))
            );
        }
    }

    #[test]
    fn test_response_port() {
        let buf = dissect_one(0b00, 0x001, 0x0027, &[0x13, 0x88, 0x00, 0x00]);
        assert_eq!(get(attr(&buf, 0), "port"), Some(&FieldValue::U16(5000)));
    }

    #[test]
    fn test_padding_attribute() {
        let buf = dissect_one(0b00, 0x001, 0x0026, &[0x20; 8]);
        assert_eq!(
            get(attr(&buf, 0), "padding"),
            Some(&FieldValue::Bytes(&[0x20; 8]))
        );
    }

    // --- Classic STUN (RFC 3489) --------------------------------------------

    /// Build a classic (RFC 3489) STUN message: no magic cookie, 128-bit
    /// transaction ID.
    fn build_classic(raw_type: u16, attrs: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&raw_type.to_be_bytes());
        pkt.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&[0x5A; 16]);
        pkt.extend_from_slice(attrs);
        pkt
    }

    #[test]
    fn test_classic_binding_request() {
        let data = build_classic(0x0001, &[]);
        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(result.next, DispatchHint::End);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "STUN");
        assert_eq!(layer.display_name, Some(CLASSIC_DISPLAY_NAME));
        assert_eq!(layer.range, 0..20);
        assert_eq!(
            buf.resolve_display_name(layer, "message_method_name"),
            Some("Binding")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_class_name"),
            Some("Request")
        );
        // No magic cookie in classic STUN; the transaction ID is 128 bits.
        assert!(buf.field_by_name(layer, "magic_cookie").is_none());
        let tid = buf.field_by_name(layer, "transaction_id").unwrap();
        assert_eq!(tid.value, FieldValue::Bytes(&[0x5A; 16]));
        assert_eq!(tid.range, 4..20);
    }

    #[test]
    fn test_classic_binding_response_with_attrs() {
        // MAPPED-ADDRESS 192.0.2.1:32853.
        let attr = build_attr(0x0001, &[0x00, 0x01, 0x80, 0x55, 192, 0, 2, 1]);
        let data = build_classic(0x0101, &attr);
        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 10).unwrap();

        assert_eq!(result.bytes_consumed, 32);
        let layer = &buf.layers()[0];
        assert_eq!(layer.display_name, Some(CLASSIC_DISPLAY_NAME));
        assert_eq!(layer.range, 10..42);
        assert_eq!(
            buf.resolve_display_name(layer, "message_class_name"),
            Some("Success Response")
        );
        let attrs_field = buf.field_by_name(layer, "attributes").unwrap();
        let FieldValue::Array(ref array_range) = attrs_field.value else {
            panic!("expected Array");
        };
        assert_eq!(count_objects(&buf, array_range), 1);
    }

    #[test]
    fn test_classic_truncated() {
        // A snaplen-truncated classic message is truncated, not invalid.
        let attr = build_attr(0x0001, &[0x00, 0x01, 0x80, 0x55, 192, 0, 2, 1]);
        let data = build_classic(0x0101, &attr);
        let mut buf = DissectBuffer::new();
        let err = StunDissector.dissect(&data[..28], &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 32,
                actual: 28
            }
        ));
    }

    #[test]
    fn test_classic_rejected_over_stream() {
        // RFC 5389, Section 12 — "UDP was the only supported transport."
        // https://www.rfc-editor.org/rfc/rfc5389#section-12
        let data = build_classic(0x0001, &[]);
        let mut buf = DissectBuffer::new();
        let err = StunTcpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "magic_cookie",
                ..
            }
        ));
    }

    #[test]
    fn test_classic_xor_attribute_stays_raw() {
        // RFC 3489 has no magic cookie, so XOR-MAPPED-ADDRESS cannot be
        // decoded (RFC 5389, Section 12 —
        // https://www.rfc-editor.org/rfc/rfc5389#section-12).
        let v = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let data = build_classic(0x0101, &build_attr(0x0020, &v));
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();
        let a = attr(&buf, 0);
        assert!(get(a, "address").is_none());
        assert_eq!(get(a, "value"), Some(&FieldValue::Bytes(&v)));
    }

    #[test]
    fn test_classic_indication_rejected() {
        // RFC 3489 has no indications (RFC 5389, Section 12 —
        // https://www.rfc-editor.org/rfc/rfc5389#section-12), so a
        // cookie-less Binding Indication is not classic STUN.
        let data = build_classic(0x0011, &[]);
        let mut buf = DissectBuffer::new();
        let err = StunDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "magic_cookie",
                ..
            }
        ));
        // Binding Error Response is classic.
        let data = build_classic(0x0111, &[]);
        let mut buf = DissectBuffer::new();
        StunDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(buf.layers()[0].display_name, Some(CLASSIC_DISPLAY_NAME));
    }

    #[test]
    fn test_classic_length_mismatch_rejected() {
        // A Binding message without the cookie whose length does not cover
        // the whole datagram is not accepted as classic STUN.
        let mut data = build_classic(0x0001, &[]);
        data.extend_from_slice(&[0x00; 4]);
        let mut buf = DissectBuffer::new();
        let err = StunDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "magic_cookie",
                value: 0x5A5A_5A5A
            }
        ));
        assert!(buf.layers().is_empty());
    }

    // --- TURN ChannelData (RFC 8656) ---------------------------------------

    fn channeldata_field<'a>(buf: &'a DissectBuffer, name: &str) -> &'a FieldValue<'a> {
        let layer = &buf.layers()[0];
        &buf.field_by_name(layer, name).unwrap().value
    }

    #[test]
    fn test_channeldata_basic() {
        let data = [0x40, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut buf = DissectBuffer::new();
        let result = TurnChannelDataDissector
            .dissect(&data, &mut buf, 0)
            .unwrap();

        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, CHANNELDATA_SHORT_NAME);
        assert_eq!(layer.range, 0..8);
        assert_eq!(
            *channeldata_field(&buf, "channel_number"),
            FieldValue::U16(0x4000)
        );
        assert_eq!(*channeldata_field(&buf, "length"), FieldValue::U16(4));
        assert_eq!(
            *channeldata_field(&buf, "data"),
            FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
        );
        assert_eq!(buf.field_by_name(layer, "data").unwrap().range, 4..8);
        assert!(buf.field_by_name(layer, "padding").is_none());
    }

    #[test]
    fn test_channeldata_via_stun_dissector() {
        let data = [0x40, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(buf.layers()[0].name, CHANNELDATA_SHORT_NAME);
    }

    #[test]
    fn test_channeldata_long_via_stun_dissector() {
        // 24-byte ChannelData: previously rejected by the STUN top-bits check.
        let mut data = vec![0x4F, 0xFF, 0x00, 0x14];
        data.extend_from_slice(&[0xAB; 20]);
        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 24);
        assert_eq!(
            *channeldata_field(&buf, "channel_number"),
            FieldValue::U16(0x4FFF)
        );
    }

    #[test]
    fn test_channeldata_zero_length() {
        let data = [0x40, 0x10, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(*channeldata_field(&buf, "length"), FieldValue::U16(0));
        assert_eq!(*channeldata_field(&buf, "data"), FieldValue::Bytes(&[]));
    }

    #[test]
    fn test_channeldata_with_padding() {
        let data = [0x40, 0x01, 0x00, 0x02, 0x11, 0x22, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 100).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 100..108);
        assert_eq!(
            *channeldata_field(&buf, "data"),
            FieldValue::Bytes(&[0x11, 0x22])
        );
        let padding = buf.field_by_name(layer, "padding").unwrap();
        assert_eq!(padding.value, FieldValue::Bytes(&[0x00, 0x00]));
        assert_eq!(padding.range, 106..108);
    }

    #[test]
    fn test_channeldata_without_padding() {
        // UDP: padding is optional (RFC 8656, Section 12.5 —
        // https://www.rfc-editor.org/rfc/rfc8656#section-12.5).
        let data = [0x40, 0x01, 0x00, 0x02, 0x11, 0x22];
        let mut buf = DissectBuffer::new();
        let result = StunDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 6);
        assert!(buf.field_by_name(&buf.layers()[0], "padding").is_none());
    }

    #[test]
    fn test_channeldata_consumes_one_message() {
        // Two padded ChannelData messages back to back (TCP framing).
        let data = [
            0x40, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, // channel 0x4000
            0x40, 0x01, 0x00, 0x02, 0x11, 0x22, 0x00, 0x00, // channel 0x4001
        ];
        let mut buf = DissectBuffer::new();
        let first = StunDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(first.bytes_consumed, 8);
        let second = StunDissector.dissect(&data[8..], &mut buf, 8).unwrap();
        assert_eq!(second.bytes_consumed, 8);
        assert_eq!(buf.layers().len(), 2);
        assert_eq!(buf.layers()[1].range, 8..16);
        assert_eq!(
            buf.field_by_name(&buf.layers()[1], "channel_number")
                .unwrap()
                .value,
            FieldValue::U16(0x4001)
        );
    }

    #[test]
    fn test_channeldata_stream_requires_padding() {
        // RFC 8656, Section 12.5 — over TCP the message MUST be padded.
        // https://www.rfc-editor.org/rfc/rfc8656#section-12.5
        let data = [0x40, 0x01, 0x00, 0x02, 0x11, 0x22, 0x00];
        let mut buf = DissectBuffer::new();
        let err = StunTcpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 7
            }
        ));
        assert!(buf.layers().is_empty());

        let data = [0x40, 0x01, 0x00, 0x02, 0x11, 0x22, 0x00, 0x00];
        let result = StunTcpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(buf.layers()[0].name, CHANNELDATA_SHORT_NAME);
    }

    #[test]
    fn test_stun_tcp_parses_stun() {
        let data = build_stun(0b00, 0x001, &[]);
        let mut buf = DissectBuffer::new();
        let result = StunTcpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(buf.layers()[0].name, "STUN");
        assert_eq!(buf.layers()[0].display_name, None);
    }

    #[test]
    fn test_stun_tcp_metadata() {
        assert_eq!(StunTcpDissector.short_name(), StunDissector.short_name());
        assert_eq!(StunTcpDissector.name(), StunDissector.name());
        assert_eq!(
            StunTcpDissector.field_descriptors().len(),
            StunDissector.field_descriptors().len()
        );
        assert_eq!(
            StunTcpDissector.references().len(),
            StunDissector.references().len()
        );
        assert_eq!(StunTcpDissector.layer(), Some(ProtocolLayer::Application));
    }

    #[test]
    fn test_channeldata_truncated_data() {
        let data = [0x40, 0x00, 0x00, 0x08, 0xDE, 0xAD];
        let mut buf = DissectBuffer::new();
        let err = StunDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 12,
                actual: 6
            }
        ));
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn test_channeldata_truncated_header() {
        let data = [0x40, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        let err = StunDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 3
            }
        ));
    }

    #[test]
    fn test_first_byte_outside_turn_channel_range() {
        // RFC 8656, Section 12, Table 3 — 80-127 is neither STUN nor a TURN
        // channel. https://www.rfc-editor.org/rfc/rfc8656#section-12
        let mut data = vec![0x50];
        data.extend_from_slice(&[0x00; 23]);
        let mut buf = DissectBuffer::new();
        let err = StunDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(msg) if msg.contains("top 2 bits")));
    }

    #[test]
    fn test_channeldata_reserved_channel_number() {
        // 0x5000-0xFFFF is reserved (RFC 8656, Section 12, Table 2 —
        // https://www.rfc-editor.org/rfc/rfc8656#section-12).
        let data = [0x50, 0x00, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        let err = TurnChannelDataDissector
            .dissect(&data, &mut buf, 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "channel_number",
                value: 0x5000
            }
        ));
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn test_channeldata_dissector_rejects_stun() {
        let data = build_stun(0b00, 0x001, &[]);
        let mut buf = DissectBuffer::new();
        let err = TurnChannelDataDissector
            .dissect(&data, &mut buf, 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "channel_number",
                value: 0x0001
            }
        ));
    }

    #[test]
    fn channeldata_metadata() {
        let d = TurnChannelDataDissector;
        assert_eq!(d.short_name(), CHANNELDATA_SHORT_NAME);
        assert_eq!(d.name(), "TURN ChannelData");
        assert_eq!(d.layer(), Some(ProtocolLayer::Application));
        let names: Vec<_> = d.field_descriptors().iter().map(|f| f.name).collect();
        assert_eq!(names, ["channel_number", "length", "data", "padding"]);
        assert!(d.field_descriptors()[3].optional);
        assert!(d.references().iter().any(|r| r.id == "RFC 8656"));
    }

    #[test]
    fn references_and_layer() {
        let references = StunDissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(StunDissector.layer(), Some(ProtocolLayer::Application));
        // STUN on the shared port also emits TURN ChannelData layers.
        assert!(references.iter().any(|r| r.id == "RFC 8656"));
    }
}
