//! NTP (Network Time Protocol) dissector.
//!
//! ## References
//! - RFC 5905 (NTPv4): <https://www.rfc-editor.org/rfc/rfc5905>
//! - RFC 7822 (Extension Fields update): <https://www.rfc-editor.org/rfc/rfc7822>
//! - RFC 8573 (AES-CMAC for NTP): <https://www.rfc-editor.org/rfc/rfc8573>
//! - RFC 8915 (Network Time Security): <https://www.rfc-editor.org/rfc/rfc8915>
//! - RFC 9109 (Port Randomization): <https://www.rfc-editor.org/rfc/rfc9109>
//! - RFC 9748 (IANA Registry updates): <https://www.rfc-editor.org/rfc/rfc9748>
//! - RFC 9769 (Interleaved Modes): <https://www.rfc-editor.org/rfc/rfc9769>
//! - RFC 9327 (Control Messages, mode 6; Historic):
//!   <https://www.rfc-editor.org/rfc/rfc9327>
//! - IANA "NTP Extension Field Types" registry:
//!   <https://www.iana.org/assignments/ntp-parameters>
//!
//! The layout is selected by the Mode field:
//!
//! - Modes 0-5: the 48-octet fixed NTPv4 header (RFC 5905, Section 7.3),
//!   followed by optional extension fields and an optional MAC (see below).
//! - Mode 6: the NTP Control Message header and data (RFC 9327, Section 2).
//! - Mode 7: "reserved for private use" (RFC 5905, Section 7.3); only the
//!   Version and Mode are decoded and the rest is kept as raw data.
//!
//! ## Extension fields and MAC (modes 0-5)
//!
//! RFC 5905, Section 7.3 (<https://www.rfc-editor.org/rfc/rfc5905#section-7.3>):
//! "The NTP packet header shown in Figure 8 has 12 words followed by
//! optional extension fields and finally an optional message authentication
//! code (MAC) consisting of the Key Identifier field and Message Digest
//! field."
//!
//! The octets after the header are split as follows:
//!
//! 1. NTPv4 only (VN = 4): while more than 24 octets remain, each block is
//!    read as an extension field (`extension_fields`, RFC 7822, Section 3).
//!    RFC 7822 updates RFC 5905 Section 7.5 so that a MAC "MUST NOT be
//!    longer than 24 octets if there is no extension field present"
//!    (7.5.1.3) and, without a MAC, "the length of the last extension field
//!    MUST be at least 28 octets" (7.5.1.4). A remainder of more than 24
//!    octets therefore cannot be a MAC alone, and a remainder of 24 octets
//!    or fewer cannot be a trailing extension field.
//!    (<https://www.rfc-editor.org/rfc/rfc7822#section-3>)
//! 2. A remainder of 4 to 24 octets that is a whole number of 32-bit words
//!    is the MAC: `key_id` (32 bits) and `digest` (MD5 or SHA-1 digest, or
//!    an AES-CMAC tag per RFC 8573; absent for the 4-octet crypto-NAK of
//!    RFC 5905, Section 9.2). The MAC is not verified.
//! 3. Anything that does not decode is kept as `trailing_data`.
//!
//! This follows the RFC 7822 rules. A longer MAC "agreed upon by both client
//! and server" (7.5.1.3), or one whose length is set by an extension field
//! specification (7.5.1.1), cannot be recognised without that knowledge: it
//! is shown as `trailing_data`, or, if its first octets happen to look like
//! an extension field header, as an extension field followed by a MAC. Extension fields are "In NTPv4"
//! only, so for other versions (e.g. NTPv3) only a MAC is recognised.
//!
//! The NTS extension fields of RFC 8915, Sections 5.3-5.6
//! (<https://www.rfc-editor.org/rfc/rfc8915#section-5.3>) are decoded into
//! typed children (`unique_id`, `cookie`, `nonce_length`,
//! `ciphertext_length`, `nonce`, `ciphertext` and paddings). Field Type
//! 0x0204 is shared with the Autokey Message Request (RFC 5906 —
//! <https://www.rfc-editor.org/rfc/rfc5906>), so it is
//! read as an NTS Cookie only in a client or server packet (modes 3 and 4)
//! without a MAC. The ciphertext is kept opaque; nothing is decrypted.

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, FormatContext};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32, read_be_u64};

/// Format NTP reference_id: stratum 0-1 as ASCII code, stratum 2+ as IPv4 address.
///
/// RFC 5905, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>:
/// for stratum 0 the field is a 4-character ASCII "kiss code" (KoD); for
/// stratum 1 it is a left-justified, zero-padded ASCII identifier of the
/// reference clock (e.g., "GPS", "PPS"); for stratum 2+ it is an IPv4
/// address (or the first four octets of the MD5 hash of an IPv6 address).
fn format_ntp_ref_id(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let bytes = match value {
        FieldValue::Bytes(b) if b.len() == 4 => *b,
        _ => return w.write_all(b"\"\""),
    };
    // If all bytes are printable ASCII (0x20..=0x7E) or null padding, treat as ASCII code.
    if bytes.iter().all(|&b| b == 0 || (0x20..=0x7E).contains(&b)) {
        let s: String = bytes
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();
        write!(w, "\"{s}\"")
    } else {
        write!(w, "\"{}.{}.{}.{}\"", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

/// NTP fixed header size in bytes.
///
/// RFC 5905, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>:
/// "The NTP packet is a UDP datagram [RFC0768]. ... The packet consists of an
/// integral number of 32-bit (4 octet) words in network byte order."  The
/// fixed header is 12 words (48 octets).
const HEADER_SIZE: usize = 48;

/// NTP Control Message header size in bytes.
///
/// RFC 9327, Section 2 — <https://www.rfc-editor.org/rfc/rfc9327#section-2>,
/// Figure 1: three 32-bit words precede the Data field.
const CONTROL_HEADER_SIZE: usize = 12;

/// Mode value for a client packet.
///
/// RFC 5905, Section 7.3, Figure 10 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
const MODE_CLIENT: u8 = 3;

/// Mode value for a server packet.
///
/// RFC 5905, Section 7.3, Figure 10 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
const MODE_SERVER: u8 = 4;

/// Mode value for NTP control messages.
///
/// RFC 5905, Section 7.3, Figure 10 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
const MODE_CONTROL: u8 = 6;

/// Mode value reserved for private use.
///
/// RFC 5905, Section 7.3, Figure 10 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
const MODE_PRIVATE: u8 = 7;

/// Returns the meaning of an NTP control message operation code.
///
/// RFC 9327, Section 2, Table 1 —
/// <https://www.rfc-editor.org/rfc/rfc9327#section-2>.
fn control_opcode_name(opcode: u8) -> &'static str {
    // Verbatim from RFC 9327, Table 1.
    //   <https://www.rfc-editor.org/rfc/rfc9327>
    match opcode {
        1 => "read status command/response",
        2 => "read variables command/response",
        3 => "write variables command/response",
        4 => "read clock variables command/response",
        5 => "write clock variables command/response",
        6 => "set trap address/port command/response",
        7 => "trap response",
        8 => "runtime configuration command/response",
        9 => "export configuration to file command/response",
        10 => "retrieve remote address stats command/response",
        11 => "retrieve ordered list command/response",
        12 => "request client-specific nonce command/response",
        31 => "unset trap address/port command/response",
        _ => "reserved",
    }
}

/// Returns a human-readable name for the Leap Indicator value.
///
/// RFC 5905, Section 7.3, Figure 9 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
fn leap_indicator_name(li: u8) -> &'static str {
    // Verbatim from RFC 5905, Figure 9.
    match li {
        0 => "no warning",
        1 => "last minute of the day has 61 seconds",
        2 => "last minute of the day has 59 seconds",
        3 => "unknown (clock unsynchronized)",
        _ => unreachable!(),
    }
}

/// Returns a human-readable name for the Mode value.
///
/// RFC 5905, Section 7.3, Figure 10 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
fn mode_name(mode: u8) -> &'static str {
    // Verbatim from RFC 5905, Figure 10.
    match mode {
        0 => "reserved",
        1 => "symmetric active",
        2 => "symmetric passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "NTP control message",
        7 => "reserved for private use",
        _ => unreachable!(),
    }
}

/// Returns a human-readable name for the Stratum value.
///
/// RFC 5905, Section 7.3, Figure 11 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
fn stratum_name(stratum: u8) -> &'static str {
    // Verbatim from RFC 5905, Figure 11. Stratum 0 is also referred to as
    // "Kiss-o'-Death" in Section 7.4 when carried in a received packet.
    match stratum {
        0 => "unspecified or invalid",
        1 => "primary server",
        2..=15 => "secondary server",
        16 => "unsynchronized",
        _ => "reserved",
    }
}

/// Returns a human-readable name for a Kiss-o'-Death code.
///
/// RFC 5905, Section 7.4, Figure 13 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.4>.
///
/// Per RFC 9748, codes beginning with "X" are reserved for experimental use;
/// the registry is maintained by IANA with a Specification Required policy
/// (<https://www.rfc-editor.org/rfc/rfc9748>).
pub fn kod_name(code: &str) -> Option<&'static str> {
    // Verbatim meanings from RFC 5905, Figure 13.
    match code {
        "ACST" => Some("The association belongs to a unicast server"),
        "AUTH" => Some("Server authentication failed"),
        "AUTO" => Some("Autokey sequence failed"),
        "BCST" => Some("The association belongs to a broadcast server"),
        "CRYP" => Some("Cryptographic authentication or identification failed"),
        "DENY" => Some("Access denied by remote server"),
        "DROP" => Some("Lost peer in symmetric mode"),
        "RSTR" => Some("Access denied due to local policy"),
        "INIT" => Some("The association has not yet synchronized for the first time"),
        "MCST" => Some("The association belongs to a dynamically discovered server"),
        "NKEY" => Some("No key found. Either the key was never installed or is not trusted"),
        "RATE" => Some(
            "Rate exceeded. The server has temporarily denied access because the client exceeded the rate threshold",
        ),
        "RMOT" => Some("Alteration of association from a remote host running ntpdc"),
        "STEP" => Some(
            "A step change in system time has occurred, but the association has not yet resynchronized",
        ),
        _ => None,
    }
}

/// Index constants for `FIELD_DESCRIPTORS`.
const FD_LEAP_INDICATOR: usize = 0;
const FD_VERSION: usize = 1;
const FD_MODE: usize = 2;
const FD_STRATUM: usize = 3;
const FD_POLL: usize = 4;
const FD_PRECISION: usize = 5;
const FD_ROOT_DELAY: usize = 6;
const FD_ROOT_DISPERSION: usize = 7;
const FD_REFERENCE_ID: usize = 8;
const FD_REFERENCE_TIMESTAMP: usize = 9;
const FD_ORIGIN_TIMESTAMP: usize = 10;
const FD_RECEIVE_TIMESTAMP: usize = 11;
const FD_TRANSMIT_TIMESTAMP: usize = 12;
// RFC 9327, Section 2 — NTP Control Message (mode 6) fields.
//   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
const FD_RESPONSE: usize = 13;
const FD_ERROR: usize = 14;
const FD_MORE: usize = 15;
const FD_OPCODE: usize = 16;
const FD_SEQUENCE: usize = 17;
const FD_STATUS: usize = 18;
const FD_ASSOCIATION_ID: usize = 19;
const FD_OFFSET: usize = 20;
const FD_COUNT: usize = 21;
const FD_DATA: usize = 22;
const FD_PADDING: usize = 23;
const FD_AUTHENTICATOR: usize = 24;
// RFC 7822, Section 3 / RFC 5905, Section 7.3 — extension fields and MAC.
//   <https://www.rfc-editor.org/rfc/rfc7822#section-3>
//   <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>
const FD_EXTENSION_FIELDS: usize = 25;
const FD_KEY_ID: usize = 26;
const FD_DIGEST: usize = 27;
const FD_TRAILING_DATA: usize = 28;

/// Index constants for `EXTENSION_FIELD_CHILD_FIELDS`.
const EFFD_FIELD_TYPE: usize = 0;
const EFFD_LENGTH: usize = 1;
const EFFD_VALUE: usize = 2;
const EFFD_UNIQUE_ID: usize = 3;
const EFFD_COOKIE: usize = 4;
const EFFD_NONCE_LENGTH: usize = 5;
const EFFD_CIPHERTEXT_LENGTH: usize = 6;
const EFFD_NONCE: usize = 7;
const EFFD_NONCE_PADDING: usize = 8;
const EFFD_CIPHERTEXT: usize = 9;
const EFFD_CIPHERTEXT_PADDING: usize = 10;
const EFFD_ADDITIONAL_PADDING: usize = 11;
const EFFD_PLACEHOLDER: usize = 12;

/// Version Number of NTPv4.
///
/// RFC 7822, Section 3 — <https://www.rfc-editor.org/rfc/rfc7822#section-3>:
/// "In NTPv4, one or more extension fields can be inserted after the header
/// and before the MAC, if a MAC is present."
const VERSION_4: u8 = 4;

/// Size of the Field Type and Length words of an extension field.
///
/// RFC 7822, Section 3, Figure 14 —
/// <https://www.rfc-editor.org/rfc/rfc7822#section-3>.
const EF_HEADER_SIZE: usize = 4;

/// Minimum extension field length.
///
/// RFC 7822, Section 3 — <https://www.rfc-editor.org/rfc/rfc7822#section-3>:
/// "While the minimum field length containing required fields is four words
/// (16 octets), the maximum field length cannot be longer than 65532 octets,
/// due to the maximum size of the Length field."
const EF_MIN_LEN: usize = 16;

/// Maximum MAC length when no extension field is present.
///
/// RFC 7822, Section 3 (7.5.1.3) —
/// <https://www.rfc-editor.org/rfc/rfc7822#section-3>: "A MAC MUST NOT be
/// longer than 24 octets if there is no extension field present, unless a
/// longer MAC is agreed upon by both client and server."
const MAX_MAC_LEN: usize = 24;

/// Size of the MAC Key Identifier.
///
/// RFC 5905, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>:
/// "Key Identifier (keyid): 32-bit unsigned integer used by the client and
/// server to designate a secret 128-bit MD5 key."
const KEY_ID_SIZE: usize = 4;

/// Unique Identifier extension field.
///
/// RFC 8915, Section 5.3 — <https://www.rfc-editor.org/rfc/rfc8915#section-5.3>:
/// "It has a Field Type of 0x0104."
const EF_TYPE_UNIQUE_ID: u16 = 0x0104;

/// NTS Cookie extension field.
///
/// RFC 8915, Section 5.4 — <https://www.rfc-editor.org/rfc/rfc8915#section-5.4>:
/// "The NTS Cookie extension field has a Field Type of 0x0204."
const EF_TYPE_NTS_COOKIE: u16 = 0x0204;

/// NTS Cookie Placeholder extension field.
///
/// RFC 8915, Section 5.5 — <https://www.rfc-editor.org/rfc/rfc8915#section-5.5>:
/// "The NTS Cookie Placeholder extension field has a Field Type of 0x0304."
const EF_TYPE_NTS_COOKIE_PLACEHOLDER: u16 = 0x0304;

/// NTS Authenticator and Encrypted Extension Fields extension field.
///
/// RFC 8915, Section 5.6 — <https://www.rfc-editor.org/rfc/rfc8915#section-5.6>:
/// "Its Field Type is 0x0404."
const EF_TYPE_NTS_AUTHENTICATOR: u16 = 0x0404;

/// Returns the meaning of an NTP extension Field Type.
///
/// Verbatim from the IANA "NTP Extension Field Types" registry
/// (<https://www.iana.org/assignments/ntp-parameters>).
///
/// Field Type 0x0204 is registered twice, as "Autokey Message Request"
/// (RFC 5906, <https://www.rfc-editor.org/rfc/rfc5906>) and "NTS Cookie"
/// (RFC 8915, Section 5.4,
/// <https://www.rfc-editor.org/rfc/rfc8915#section-5.4>); the registry notes
/// that "in practice this is not a problem as the field semantics will be
/// determined by other parts of the message". Both names are shown. The
/// body is decoded as an NTS `cookie` only when no MAC follows the extension
/// fields: NTS packets are authenticated by the NTS Authenticator extension
/// field instead, while Autokey (RFC 5906) packets always carry a MAC.
fn extension_field_type_name(field_type: u16) -> Option<&'static str> {
    match field_type {
        0x0000 => Some("Crypto-NAK; authentication failure"),
        0x0104 => Some("Unique Identifier"),
        0x010A => Some("Network Correction"),
        0x0200 => Some("No-Operation Request"),
        0x0201 => Some("Association Message Request"),
        0x0202 => Some("Certificate Message Request"),
        0x0203 => Some("Cookie Message Request"),
        0x0204 => Some("NTS Cookie / Autokey Message Request"),
        0x0205 => Some("Leapseconds Message Request"),
        0x0206 => Some("Sign Message Request"),
        0x0207 => Some("IFF Identity Message Request"),
        0x0208 => Some("GQ Identity Message Request"),
        0x0209 => Some("MV Identity Message Request"),
        0x0304 => Some("NTS Cookie Placeholder"),
        0x0404 => Some("NTS Authenticator and Encrypted Extension Fields"),
        0x2005 => Some("UDP Checksum Complement"),
        0x8200 => Some("No-Operation Response"),
        0x8201 => Some("Association Message Response"),
        0x8202 => Some("Certificate Message Response"),
        0x8203 => Some("Cookie Message Response"),
        0x8204 => Some("Autokey Message Response"),
        0x8205 => Some("Leapseconds Message Response"),
        0x8206 => Some("Sign Message Response"),
        0x8207 => Some("IFF Identity Message Response"),
        0x8208 => Some("GQ Identity Message Response"),
        0x8209 => Some("MV Identity Message Response"),
        0xC200 => Some("No-Operation Error Response"),
        0xC201 => Some("Association Message Error Response"),
        0xC202 => Some("Certificate Message Error Response"),
        0xC203 => Some("Cookie Message Error Response"),
        0xC204 => Some("Autokey Message Error Response"),
        0xC205 => Some("Leapseconds Message Error Response"),
        0xC206 => Some("Sign Message Error Response"),
        0xC207 => Some("IFF Identity Message Error Response"),
        0xC208 => Some("GQ Identity Message Error Response"),
        0xC209 => Some("MV Identity Message Error Response"),
        0x0002 | 0x0102 | 0x0302 | 0x0402 | 0x0502 | 0x0602 | 0x0702 | 0x0802 | 0x0902 | 0x8002
        | 0x8102 | 0x8302 | 0x8402 | 0x8502 | 0x8602 | 0x8702 | 0x8802 | 0x8902 | 0xC002
        | 0xC102 | 0xC302 | 0xC402 | 0xC502 | 0xC602 | 0xC702 | 0xC802 | 0xC902 => {
            Some("Reserved for historic reasons")
        }
        0xF000..=0xFFFF => Some("Reserved for Private or Experimental Use"),
        _ => None,
    }
}

/// Layer name used for every NTP mode.
const SHORT_NAME: &str = "NTP";

/// NTP dissector.
pub struct NtpDissector;

/// Specification references for the NTP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 5905",
        "Network Time Protocol Version 4: Protocol and Algorithms Specification",
        "https://www.rfc-editor.org/rfc/rfc5905",
    ),
    SpecReference::new(
        "RFC 7822",
        "Network Time Protocol Version 4 (NTPv4) Extension Fields",
        "https://www.rfc-editor.org/rfc/rfc7822",
    ),
    SpecReference::new(
        "RFC 8573",
        "Message Authentication Code for the Network Time Protocol",
        "https://www.rfc-editor.org/rfc/rfc8573",
    ),
    SpecReference::new(
        "RFC 8915",
        "Network Time Security for the Network Time Protocol",
        "https://www.rfc-editor.org/rfc/rfc8915",
    ),
    SpecReference::new(
        "RFC 9109",
        "Network Time Protocol Version 4: Port Randomization",
        "https://www.rfc-editor.org/rfc/rfc9109",
    ),
    SpecReference::new(
        "RFC 9748",
        "Updating the NTP Registries",
        "https://www.rfc-editor.org/rfc/rfc9748",
    ),
    SpecReference::new(
        "RFC 9769",
        "NTP Interleaved Modes",
        "https://www.rfc-editor.org/rfc/rfc9769",
    ),
    SpecReference::new(
        "RFC 9327",
        "Control Messages Protocol for Use with Network Time Protocol Version 4",
        "https://www.rfc-editor.org/rfc/rfc9327",
    ),
];

/// Field descriptors for the NTP dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "leap_indicator",
        display_name: "Leap Indicator",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(li) => Some(leap_indicator_name(*li)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("version", "Version Number", FieldType::U8),
    FieldDescriptor {
        name: "mode",
        display_name: "Mode",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(m) => Some(mode_name(*m)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "stratum",
        display_name: "Stratum",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(s) => Some(stratum_name(*s)),
            _ => None,
        }),
        format_fn: None,
    },
    // Fields below are present for modes 0-5 only (RFC 5905, Section 7.3).
    //   <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>
    FieldDescriptor::new("poll", "Poll Interval", FieldType::I32).optional(),
    FieldDescriptor::new("precision", "Precision", FieldType::I32).optional(),
    FieldDescriptor::new("root_delay", "Root Delay", FieldType::U32).optional(),
    FieldDescriptor::new("root_dispersion", "Root Dispersion", FieldType::U32).optional(),
    FieldDescriptor::new("reference_id", "Reference ID", FieldType::Bytes)
        .optional()
        .with_format_fn(format_ntp_ref_id),
    FieldDescriptor::new("reference_timestamp", "Reference Timestamp", FieldType::U64).optional(),
    FieldDescriptor::new("origin_timestamp", "Origin Timestamp", FieldType::U64).optional(),
    FieldDescriptor::new("receive_timestamp", "Receive Timestamp", FieldType::U64).optional(),
    FieldDescriptor::new("transmit_timestamp", "Transmit Timestamp", FieldType::U64).optional(),
    // Fields below are present for mode 6 only (RFC 9327, Section 2).
    //   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
    FieldDescriptor::new("response", "Response Bit", FieldType::U8).optional(),
    FieldDescriptor::new("error", "Error Bit", FieldType::U8).optional(),
    FieldDescriptor::new("more", "More Bit", FieldType::U8).optional(),
    FieldDescriptor {
        name: "opcode",
        display_name: "Operation Code",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(op) => Some(control_opcode_name(*op)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("sequence", "Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("status", "Status", FieldType::U16).optional(),
    FieldDescriptor::new("association_id", "Association ID", FieldType::U16).optional(),
    FieldDescriptor::new("offset", "Offset", FieldType::U16).optional(),
    FieldDescriptor::new("count", "Count", FieldType::U16).optional(),
    // Mode 6 Data, or the raw body of a mode 7 message.
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("padding", "Padding", FieldType::Bytes).optional(),
    FieldDescriptor::new("authenticator", "Authenticator", FieldType::Bytes).optional(),
    // Fields below follow the header in modes 0-5 (RFC 5905, Section 7.3;
    // RFC 7822, Section 3).
    //   <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>
    //   <https://www.rfc-editor.org/rfc/rfc7822#section-3>
    FieldDescriptor::new("extension_fields", "Extension Fields", FieldType::Array)
        .optional()
        .with_children(EXTENSION_FIELD_CHILD_FIELDS),
    FieldDescriptor::new("key_id", "Key Identifier", FieldType::U32).optional(),
    FieldDescriptor::new("digest", "Message Digest", FieldType::Bytes).optional(),
    FieldDescriptor::new("trailing_data", "Trailing Data", FieldType::Bytes).optional(),
];

/// Descriptor for one extension field Object in `extension_fields`.
///
/// `display_fn` lets [`DissectBuffer::resolve_container_display_name`]
/// label the Object with the IANA name of its Field Type.
static FD_EXTENSION_FIELD: FieldDescriptor = FieldDescriptor {
    name: "extension_field",
    display_name: "Extension Field",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("field_type", FieldValue::U16(t)) => extension_field_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Child field descriptors of an extension field.
///
/// RFC 7822, Section 3, Figure 14 —
/// <https://www.rfc-editor.org/rfc/rfc7822#section-3>; NTS fields from
/// RFC 8915, Sections 5.3-5.6 —
/// <https://www.rfc-editor.org/rfc/rfc8915#section-5.3>.
static EXTENSION_FIELD_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "field_type",
        display_name: "Field Type",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(t) => extension_field_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U16),
    // Value and Padding of a field without a typed decoder.
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
    // RFC 8915, Section 5.3 — Unique Identifier.
    FieldDescriptor::new("unique_id", "Unique Identifier", FieldType::Bytes).optional(),
    // RFC 8915, Sections 5.4-5.5 — NTS Cookie / NTS Cookie Placeholder.
    FieldDescriptor::new("cookie", "Cookie", FieldType::Bytes).optional(),
    // RFC 8915, Section 5.6, Figure 4 — NTS Authenticator and Encrypted
    // Extension Fields.
    FieldDescriptor::new("nonce_length", "Nonce Length", FieldType::U16).optional(),
    FieldDescriptor::new("ciphertext_length", "Ciphertext Length", FieldType::U16).optional(),
    FieldDescriptor::new("nonce", "Nonce", FieldType::Bytes).optional(),
    FieldDescriptor::new("nonce_padding", "Nonce Padding", FieldType::Bytes).optional(),
    FieldDescriptor::new("ciphertext", "Ciphertext", FieldType::Bytes).optional(),
    FieldDescriptor::new("ciphertext_padding", "Ciphertext Padding", FieldType::Bytes).optional(),
    FieldDescriptor::new("additional_padding", "Additional Padding", FieldType::Bytes).optional(),
    // RFC 8915, Section 5.5 — NTS Cookie Placeholder body.
    //   <https://www.rfc-editor.org/rfc/rfc8915#section-5.5>
    FieldDescriptor::new("placeholder", "Placeholder", FieldType::Bytes).optional(),
];

impl Dissector for NtpDissector {
    fn name(&self) -> &'static str {
        "Network Time Protocol"
    }

    fn short_name(&self) -> &'static str {
        SHORT_NAME
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
        let Some(&first_byte) = data.first() else {
            return Err(PacketError::Truncated {
                expected: 1,
                actual: 0,
            });
        };

        // RFC 5905, Section 7.3 — first octet: LI (2 bits) | VN (3 bits) | Mode (3 bits).
        // https://www.rfc-editor.org/rfc/rfc5905#section-7.3
        let li = (first_byte >> 6) & 0x03;
        let vn = (first_byte >> 3) & 0x07;
        let mode = first_byte & 0x07;

        match mode {
            MODE_CONTROL => return dissect_control(data, buf, offset, li, vn, mode),
            MODE_PRIVATE => return dissect_private(data, buf, offset, vn, mode),
            _ => {}
        }

        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        let stratum = data[1];
        // RFC 5905, Section 7.3 — Poll and Precision are signed 8-bit integers
        // (log2 seconds).
        // https://www.rfc-editor.org/rfc/rfc5905#section-7.3
        let poll = data[2] as i8 as i32;
        let precision = data[3] as i8 as i32;

        // RFC 5905, Section 6 (Figure 3, "NTP Short Format"): Root Delay and
        // Root Dispersion are each a 16-bit unsigned seconds field followed by
        // a 16-bit fraction field, i.e. unsigned 16.16 fixed-point.
        // https://www.rfc-editor.org/rfc/rfc5905#section-6
        let root_delay = read_be_u32(data, 4)?;
        let root_dispersion = read_be_u32(data, 8)?;

        // RFC 5905, Section 6 (Figure 4, "NTP Timestamp Format"): 32-bit
        // unsigned seconds plus 32-bit fraction. A value of zero is a special
        // case representing unknown or unsynchronized time (Section 7.3).
        // https://www.rfc-editor.org/rfc/rfc5905#section-6
        let reference_ts = read_be_u64(data, 16)?;
        let origin_ts = read_be_u64(data, 24)?;
        let receive_ts = read_be_u64(data, 32)?;
        let transmit_ts = read_be_u64(data, 40)?;
        let total = data.len();

        buf.begin_layer(SHORT_NAME, None, FIELD_DESCRIPTORS, offset..offset + total);
        push_first_octet(buf, offset, Some(li), vn, mode);
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_STRATUM],
            FieldValue::U8(stratum),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_POLL],
            FieldValue::I32(poll),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PRECISION],
            FieldValue::I32(precision),
            offset + 3..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ROOT_DELAY],
            FieldValue::U32(root_delay),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ROOT_DISPERSION],
            FieldValue::U32(root_dispersion),
            offset + 8..offset + 12,
        );
        // For stratum 0 (KoD) and stratum 1 (primary), Reference ID is a
        // four-character ASCII string. For stratum 2+, it is implementation-
        // dependent (commonly an IPv4 address — RFC 5905, Section 7.3).
        // Store raw bytes; formatted by format_ntp_ref_id via format_fn.
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_REFERENCE_ID],
            FieldValue::Bytes(&data[12..16]),
            offset + 12..offset + 16,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_REFERENCE_TIMESTAMP],
            FieldValue::U64(reference_ts),
            offset + 16..offset + 24,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ORIGIN_TIMESTAMP],
            FieldValue::U64(origin_ts),
            offset + 24..offset + 32,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_RECEIVE_TIMESTAMP],
            FieldValue::U64(receive_ts),
            offset + 32..offset + 40,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TRANSMIT_TIMESTAMP],
            FieldValue::U64(transmit_ts),
            offset + 40..offset + 48,
        );
        dissect_trailer(data, buf, offset, vn, mode);
        buf.end_layer();

        Ok(DissectResult::new(total, DispatchHint::End))
    }
}

/// Dissects the extension fields, MAC and any trailing octets that follow
/// the 48-octet header of a mode 0-5 packet.
///
/// See the module documentation for how extension fields and the MAC are
/// told apart (RFC 7822, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc7822#section-3>).
fn dissect_trailer<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    vn: u8,
    mode: u8,
) {
    let total = data.len();
    let mut pos = HEADER_SIZE;

    // RFC 7822, Section 3 — "In NTPv4, one or more extension fields can be
    // inserted after the header and before the MAC, if a MAC is present."
    //   <https://www.rfc-editor.org/rfc/rfc7822#section-3>
    if vn == VERSION_4 {
        let ef_end = extension_fields_end(data, pos);
        if ef_end > pos {
            let with_mac = is_mac_shaped(total - ef_end);
            let arr_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_EXTENSION_FIELDS],
                FieldValue::Array(0..0),
                offset + pos..offset + ef_end,
            );
            while let Some(len) = extension_field_len(data, pos).filter(|_| pos < ef_end) {
                push_extension_field(buf, &data[pos..pos + len], offset + pos, mode, with_mac);
                pos += len;
            }
            buf.end_container(arr_idx);
        }
    }

    let rest = total - pos;
    if rest == 0 {
        return;
    }

    if is_mac_shaped(rest) {
        let key_id = read_be_u32(data, pos).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_KEY_ID],
            FieldValue::U32(key_id),
            offset + pos..offset + pos + KEY_ID_SIZE,
        );
        let digest_start = pos + KEY_ID_SIZE;
        // RFC 5905, Section 9.2 — a crypto-NAK carries "a MAC consisting
        // of four octets of zeros", i.e. no digest.
        //   <https://www.rfc-editor.org/rfc/rfc5905#section-9.2>
        if digest_start < total {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_DIGEST],
                FieldValue::Bytes(&data[digest_start..]),
                offset + digest_start..offset + total,
            );
        }
        return;
    }

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_TRAILING_DATA],
        FieldValue::Bytes(&data[pos..]),
        offset + pos..offset + total,
    );
}

/// Whether a trailer of `len` octets after the header and extension fields
/// has the shape of a MAC.
///
/// RFC 5905, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>:
/// "The MAC consists of the Key Identifier followed by the Message Digest."
/// The Key Identifier is a 32-bit word and the digests in use (MD5 and
/// SHA-1, and the AES-CMAC tag of RFC 8573 —
/// <https://www.rfc-editor.org/rfc/rfc8573#section-3>) are whole words.
/// RFC 7822, Section 3 (7.5.1.3) —
/// <https://www.rfc-editor.org/rfc/rfc7822#section-3>: "A MAC MUST NOT be
/// longer than 24 octets if there is no extension field present, unless a
/// longer MAC is agreed upon by both client and server."
fn is_mac_shaped(len: usize) -> bool {
    (KEY_ID_SIZE..=MAX_MAC_LEN).contains(&len) && len % 4 == 0
}

/// Returns the Length of a well-formed extension field starting at `pos`,
/// or `None` if the octets at `pos` are not one.
///
/// RFC 7822, Section 3 — <https://www.rfc-editor.org/rfc/rfc7822#section-3>:
/// "All extension fields are zero-padded to a word (four octets) boundary."
/// "While the minimum field length containing required fields is four words
/// (16 octets) [...]" "The Length field is a 16-bit unsigned integer that
/// indicates the length of the entire extension field in octets, including
/// the Padding field."
fn extension_field_len(data: &[u8], pos: usize) -> Option<usize> {
    let len = read_be_u16(data, pos.checked_add(2)?).ok()? as usize;
    let end = pos.checked_add(len)?;
    (len >= EF_MIN_LEN && len % 4 == 0 && end <= data.len()).then_some(len)
}

/// Returns the end of the run of extension fields starting at `start`.
///
/// A block is read as an extension field only while more than
/// [`MAX_MAC_LEN`] octets remain: RFC 7822, Section 3 (7.5.1.4) —
/// <https://www.rfc-editor.org/rfc/rfc7822#section-3> — "If the packet
/// includes a single extension field, the length of the extension field MUST
/// be at least 7 words, i.e., at least 28 octets." and "If the packet
/// includes more than one extension field, the length of the last extension
/// field MUST be at least 28 octets." A remainder of 24 octets or fewer is
/// therefore a MAC (7.5.1.3), even when its Key Identifier happens to look
/// like an extension field header.
fn extension_fields_end(data: &[u8], start: usize) -> usize {
    let mut pos = start;
    while data.len() - pos > MAX_MAC_LEN {
        match extension_field_len(data, pos) {
            Some(len) => pos += len,
            None => break,
        }
    }
    pos
}

/// Pushes one extension field as an Object inside `extension_fields`.
///
/// `ef` is the whole field (header, Value and Padding) and `abs` is its
/// absolute offset. `mode` (the packet's Mode) and `with_mac` (whether a MAC
/// follows the extension fields) select the meaning of Field Type 0x0204.
///
/// RFC 7822, Section 3, Figure 14 —
/// <https://www.rfc-editor.org/rfc/rfc7822#section-3>.
fn push_extension_field<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    ef: &'pkt [u8],
    abs: usize,
    mode: u8,
    with_mac: bool,
) {
    let field_type = read_be_u16(ef, 0).unwrap_or_default();
    let length = read_be_u16(ef, 2).unwrap_or_default();
    let body = &ef[EF_HEADER_SIZE.min(ef.len())..];
    let body_abs = abs + EF_HEADER_SIZE;
    let body_range = body_abs..abs + ef.len();

    let obj_idx = buf.begin_container(
        &FD_EXTENSION_FIELD,
        FieldValue::Object(0..0),
        abs..abs + ef.len(),
    );
    buf.push_field(
        &EXTENSION_FIELD_CHILD_FIELDS[EFFD_FIELD_TYPE],
        FieldValue::U16(field_type),
        abs..abs + 2,
    );
    buf.push_field(
        &EXTENSION_FIELD_CHILD_FIELDS[EFFD_LENGTH],
        FieldValue::U16(length),
        abs + 2..abs + 4,
    );

    match field_type {
        // RFC 8915, Section 5.3 — "its body SHALL consist of a string of
        // octets generated by a cryptographically secure random number
        // generator".
        //   <https://www.rfc-editor.org/rfc/rfc8915#section-5.3>
        EF_TYPE_UNIQUE_ID => buf.push_field(
            &EXTENSION_FIELD_CHILD_FIELDS[EFFD_UNIQUE_ID],
            FieldValue::Bytes(body),
            body_range,
        ),
        // RFC 8915, Section 5.4 — "The contents of its body SHALL be
        // implementation-defined, and clients MUST NOT attempt to interpret
        // them." Field Type 0x0204 is also the Autokey Message Request
        // (RFC 5906 — <https://www.rfc-editor.org/rfc/rfc5906>), whose body
        // is kept as `value`. It is an NTS Cookie only without a MAC and in
        // a client or server packet: "The NTS Cookie extension field MUST
        // NOT be included in NTP packets whose mode is other than 3
        // (client) or 4 (server)."
        //   <https://www.rfc-editor.org/rfc/rfc8915#section-5.4>
        EF_TYPE_NTS_COOKIE if !with_mac && matches!(mode, MODE_CLIENT | MODE_SERVER) => buf
            .push_field(
                &EXTENSION_FIELD_CHILD_FIELDS[EFFD_COOKIE],
                FieldValue::Bytes(body),
                body_range,
            ),
        // RFC 8915, Section 5.5 — "The contents of the NTS Cookie
        // Placeholder extension field's body SHOULD be all zeros".
        //   <https://www.rfc-editor.org/rfc/rfc8915#section-5.5>
        EF_TYPE_NTS_COOKIE_PLACEHOLDER => buf.push_field(
            &EXTENSION_FIELD_CHILD_FIELDS[EFFD_PLACEHOLDER],
            FieldValue::Bytes(body),
            body_range,
        ),
        EF_TYPE_NTS_AUTHENTICATOR if push_nts_authenticator(buf, body, body_abs) => {}
        _ => buf.push_field(
            &EXTENSION_FIELD_CHILD_FIELDS[EFFD_VALUE],
            FieldValue::Bytes(body),
            body_range,
        ),
    }

    buf.end_container(obj_idx);
}

/// Pushes the fields of an NTS Authenticator and Encrypted Extension Fields
/// body. Returns `false` (pushing nothing) if the Nonce Length and
/// Ciphertext Length do not fit in `body`.
///
/// RFC 8915, Section 5.6, Figure 4 —
/// <https://www.rfc-editor.org/rfc/rfc8915#section-5.6>:
///
/// "Nonce Length:  Two octets in network byte order, giving the length of
/// the Nonce field, excluding any padding, interpreted as an unsigned
/// integer."
///
/// "Ciphertext Length:  Two octets in network byte order, giving the length
/// of the Ciphertext field, excluding any padding, interpreted as an
/// unsigned integer."
///
/// "Nonce:  A nonce as required by the negotiated AEAD algorithm.  The end
/// of the field is zero-padded to a word (four octets) boundary."
///
/// "Ciphertext:  The output of the negotiated AEAD algorithm. [...] The end
/// of the field is zero-padded to a word (four octets) boundary."
///
/// The Ciphertext is kept opaque; it is not decrypted.
fn push_nts_authenticator<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    body_abs: usize,
) -> bool {
    let (Ok(nonce_len), Ok(ciphertext_len)) = (read_be_u16(body, 0), read_be_u16(body, 2)) else {
        return false;
    };
    let nonce_start = 4;
    let nonce_end = nonce_start + nonce_len as usize;
    let nonce_pad_end = nonce_start + (nonce_len as usize).next_multiple_of(4);
    let ciphertext_end = nonce_pad_end + ciphertext_len as usize;
    let ciphertext_pad_end = nonce_pad_end + (ciphertext_len as usize).next_multiple_of(4);
    if ciphertext_pad_end > body.len() {
        return false;
    }

    buf.push_field(
        &EXTENSION_FIELD_CHILD_FIELDS[EFFD_NONCE_LENGTH],
        FieldValue::U16(nonce_len),
        body_abs..body_abs + 2,
    );
    buf.push_field(
        &EXTENSION_FIELD_CHILD_FIELDS[EFFD_CIPHERTEXT_LENGTH],
        FieldValue::U16(ciphertext_len),
        body_abs + 2..body_abs + 4,
    );
    // "Additional Padding:  Clients that use a nonce length shorter than the
    // maximum allowed by the negotiated AEAD algorithm may be required to
    // include additional zero-padding."
    //   <https://www.rfc-editor.org/rfc/rfc8915#section-5.6>
    for (fd, range) in [
        (EFFD_NONCE, nonce_start..nonce_end),
        (EFFD_NONCE_PADDING, nonce_end..nonce_pad_end),
        (EFFD_CIPHERTEXT, nonce_pad_end..ciphertext_end),
        (EFFD_CIPHERTEXT_PADDING, ciphertext_end..ciphertext_pad_end),
        (EFFD_ADDITIONAL_PADDING, ciphertext_pad_end..body.len()),
    ] {
        if !range.is_empty() {
            buf.push_field(
                &EXTENSION_FIELD_CHILD_FIELDS[fd],
                FieldValue::Bytes(&body[range.clone()]),
                body_abs + range.start..body_abs + range.end,
            );
        }
    }
    true
}

/// Pushes the LI / VN / Mode fields of the first octet.
///
/// RFC 5905, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
fn push_first_octet<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    li: Option<u8>,
    vn: u8,
    mode: u8,
) {
    if let Some(li) = li {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LEAP_INDICATOR],
            FieldValue::U8(li),
            offset..offset + 1,
        );
    }
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_VERSION],
        FieldValue::U8(vn),
        offset..offset + 1,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MODE],
        FieldValue::U8(mode),
        offset..offset + 1,
    );
}

/// Dissects an NTP Control Message (mode 6).
///
/// RFC 9327, Section 2 — <https://www.rfc-editor.org/rfc/rfc9327#section-2>.
fn dissect_control<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    li: u8,
    vn: u8,
    mode: u8,
) -> Result<DissectResult, PacketError> {
    if data.len() < CONTROL_HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: CONTROL_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // RFC 9327, Section 2, Figure 1 — second octet: R | E | M | opcode (5 bits).
    //   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
    let byte1 = data[1];
    let response = (byte1 >> 7) & 0x01;
    let error = (byte1 >> 6) & 0x01;
    let more = (byte1 >> 5) & 0x01;
    let opcode = byte1 & 0x1F;
    let sequence = read_be_u16(data, 2)?;
    let status = read_be_u16(data, 4)?;
    let association_id = read_be_u16(data, 6)?;
    let data_offset = read_be_u16(data, 8)?;
    // RFC 9327, Section 2 — "Count: This is a 16-bit unsigned integer
    // indicating the length of the data field, in octets."
    //   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
    let count = read_be_u16(data, 10)?;

    let data_end = CONTROL_HEADER_SIZE + count as usize;
    if data.len() < data_end {
        return Err(PacketError::Truncated {
            expected: data_end,
            actual: data.len(),
        });
    }

    // RFC 9327, Section 2 — "Padding (optional): Contains zero to 3 octets
    // with a value of zero, as needed to ensure the overall control message
    // size is a multiple of 4 octets." Anything after the padding is the
    // optional Authenticator.
    //   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
    let padding_end = (data_end + (4 - data_end % 4) % 4).min(data.len());
    let total = data.len();

    buf.begin_layer(SHORT_NAME, None, FIELD_DESCRIPTORS, offset..offset + total);
    push_first_octet(buf, offset, Some(li), vn, mode);
    for (fd, value) in [
        (FD_RESPONSE, response),
        (FD_ERROR, error),
        (FD_MORE, more),
        (FD_OPCODE, opcode),
    ] {
        buf.push_field(
            &FIELD_DESCRIPTORS[fd],
            FieldValue::U8(value),
            offset + 1..offset + 2,
        );
    }
    for (fd, value, pos) in [
        (FD_SEQUENCE, sequence, 2),
        (FD_STATUS, status, 4),
        (FD_ASSOCIATION_ID, association_id, 6),
        (FD_OFFSET, data_offset, 8),
        (FD_COUNT, count, 10),
    ] {
        buf.push_field(
            &FIELD_DESCRIPTORS[fd],
            FieldValue::U16(value),
            offset + pos..offset + pos + 2,
        );
    }
    for (fd, range) in [
        (FD_DATA, CONTROL_HEADER_SIZE..data_end),
        (FD_PADDING, data_end..padding_end),
        (FD_AUTHENTICATOR, padding_end..total),
    ] {
        if !range.is_empty() {
            buf.push_field(
                &FIELD_DESCRIPTORS[fd],
                FieldValue::Bytes(&data[range.clone()]),
                offset + range.start..offset + range.end,
            );
        }
    }
    buf.end_layer();

    Ok(DissectResult::new(total, DispatchHint::End))
}

/// Dissects a mode 7 message.
///
/// RFC 5905, Section 7.3, Figure 10 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3> — mode 7 is
/// "reserved for private use". The format used by implementations (e.g.
/// ntpd's `ntpdc`) is not specified in an RFC and reuses the LI bits, so
/// only VN and Mode are decoded; the remaining octets are raw data.
fn dissect_private<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    vn: u8,
    mode: u8,
) -> Result<DissectResult, PacketError> {
    let total = data.len();
    buf.begin_layer(SHORT_NAME, None, FIELD_DESCRIPTORS, offset..offset + total);
    push_first_octet(buf, offset, None, vn, mode);
    if total > 1 {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DATA],
            FieldValue::Bytes(&data[1..]),
            offset + 1..offset + total,
        );
    }
    buf.end_layer();

    Ok(DissectResult::new(total, DispatchHint::End))
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 5905 Coverage
    //
    // | RFC Section | Description                                  | Test                                |
    // |-------------|----------------------------------------------|-------------------------------------|
    // | 6           | NTP Short Format (unsigned 16.16)            | test_root_delay_is_unsigned         |
    // | 7.3         | Header: LI, VN, Mode bit layout              | test_parse_client_request           |
    // | 7.3         | VN field width (3 bits)                      | test_version_number_field_width     |
    // | 7.3, Fig. 9 | Leap Indicator values                        | test_leap_indicator_values          |
    // | 7.3, Fig. 10| Mode values                                  | test_mode_values                    |
    // | 7.3, Fig. 11| Stratum values                               | test_stratum_ranges                 |
    // | 7.3         | Poll (signed log2 s), Precision              | test_parse_server_response          |
    // | 7.3         | Root Delay, Root Dispersion                  | test_parse_server_response          |
    // | 7.3         | Reference ID (ASCII, stratum 1)              | test_parse_stratum_1_primary        |
    // | 7.3         | Reference ID (IPv4, stratum >= 2)            | test_reference_id_ipv4_formatting   |
    // | 7.3         | Reference ID ASCII formatting                | test_reference_id_ascii_formatting  |
    // | 7.3         | Reference, Origin, Receive, Transmit TSes    | test_parse_server_response          |
    // | 7.4, Fig. 13| Kiss-o'-Death reference ID (all codes)       | test_all_kod_codes_from_rfc_figure_13 |
    // | 7.4         | Kiss-o'-Death packet (stratum 0)             | test_parse_stratum_0_kod            |
    // | 7.4         | KoD code lookup                              | test_kod_name_lookup                |
    // | 7.3         | Dissection at non-zero offset                | test_dissect_with_offset            |
    // | ---         | Truncated header                             | test_truncated_packet               |
    // | ---         | Field descriptor count / naming              | test_field_descriptors              |
    // | 7.3, Fig. 10| Mode 7 (reserved for private use)            | test_parse_mode7_private            |
    // | ---         | Empty payload                                | test_empty_packet                   |
    //
    // # RFC 9327 (NTP Control Messages) Coverage
    //
    // | RFC Section | Description                                  | Test                                |
    // |-------------|----------------------------------------------|-------------------------------------|
    // | 2           | Header: R/E/M bits, opcode, sequence         | test_parse_mode6_request            |
    // | 2           | Status, Association ID, Offset, Count        | test_parse_mode6_response           |
    // | 2, Table 1  | Operation code names                         | test_mode6_opcode_names             |
    // | 2           | Data (count octets)                          | test_parse_mode6_response           |
    // | 2           | Padding and Authenticator                    | test_parse_mode6_padding_and_authenticator |
    // | 2           | Truncated header (< 12 octets)               | test_mode6_truncated_header         |
    // | 2           | Truncated data (< 12 + count octets)         | test_mode6_truncated_data           |
    //
    // # RFC 7822 / RFC 5905 Section 7.3 (Extension Fields and MAC) Coverage
    //
    // | RFC Section        | Description                                  | Test                                |
    // |--------------------|----------------------------------------------|-------------------------------------|
    // | 7822 §3 (7.5)      | Field Type / Length / Value, single EF       | test_parse_single_unknown_extension_field |
    // | 7822 §3 (7.5)      | Length >= 16, multiple of 4, fits datagram   | test_malformed_extension_field_length |
    // | 7822 §3 (7.5)      | EFs are NTPv4 only (NTPv3: MAC only)         | test_ntpv3_mac_without_extension_fields |
    // | 7822 §3 (7.5.1.3)  | MAC without EF, 24 octets                    | test_parse_mac_24_octets            |
    // | 7822 §3 (7.5.1.4)  | <= 24-octet trailer is a MAC, not an EF      | test_parse_mac_20_octets            |
    // | 7822 §3 (7.5)      | EF (16 octets) followed by a MAC             | test_parse_extension_field_followed_by_mac |
    // | IANA NTP EF Types | 0x0204 with a MAC is Autokey, not NTS Cookie | test_autokey_message_request_with_mac_is_not_nts_cookie |
    // | 5905 §7.3          | MAC: Key Identifier + Message Digest         | test_parse_mac_20_octets            |
    // | 5905 §7.3          | Trailer not a whole number of words          | test_trailer_not_mac_shaped         |
    // | 5905 §9.2          | Crypto-NAK (4-octet MAC of zeros)            | test_parse_crypto_nak               |
    // | IANA registry      | Extension Field Type names                   | test_extension_field_type_names     |
    //
    // # RFC 8915 (NTS) Coverage
    //
    // | RFC Section | Description                                  | Test                                |
    // |-------------|----------------------------------------------|-------------------------------------|
    // | 5.3         | Unique Identifier extension field            | test_parse_nts_client_request       |
    // | 5.4         | NTS Cookie extension field                   | test_parse_nts_client_request       |
    // | 5.5         | NTS Cookie Placeholder extension field       | test_parse_nts_client_request       |
    // | 5.6         | NTS Authenticator: lengths, nonce, ciphertext| test_parse_nts_client_request       |
    // | 5.6         | Nonce/Ciphertext padding, Additional Padding | test_parse_nts_authenticator_padding |
    // | 5.6         | Inconsistent Nonce/Ciphertext Length         | test_nts_authenticator_inconsistent_lengths |
    // | 5.7         | NTS client request layout                    | test_parse_nts_client_request       |
    // | 5.4         | 0x0204 outside modes 3/4 is not NTS Cookie   | test_0x0204_outside_client_server_is_not_nts_cookie |

    /// Build a minimal NTP packet with the given parameters.
    #[allow(clippy::too_many_arguments)]
    fn build_ntp(
        li: u8,
        vn: u8,
        mode: u8,
        stratum: u8,
        poll: i8,
        precision: i8,
        root_delay: u32,
        root_dispersion: u32,
        ref_id: [u8; 4],
        ref_ts: u64,
        origin_ts: u64,
        recv_ts: u64,
        xmit_ts: u64,
    ) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(HEADER_SIZE);
        pkt.push((li << 6) | (vn << 3) | mode);
        pkt.push(stratum);
        pkt.push(poll as u8);
        pkt.push(precision as u8);
        pkt.extend_from_slice(&root_delay.to_be_bytes());
        pkt.extend_from_slice(&root_dispersion.to_be_bytes());
        pkt.extend_from_slice(&ref_id);
        pkt.extend_from_slice(&ref_ts.to_be_bytes());
        pkt.extend_from_slice(&origin_ts.to_be_bytes());
        pkt.extend_from_slice(&recv_ts.to_be_bytes());
        pkt.extend_from_slice(&xmit_ts.to_be_bytes());
        pkt
    }

    #[test]
    fn test_parse_client_request() {
        // NTPv4 client request: LI=0, VN=4, Mode=3
        let data = build_ntp(
            0,
            4,
            3,
            0,
            6,
            -20,
            0,
            0,
            [0; 4],
            0,
            0,
            0,
            0xDEAD_BEEF_CAFE_BABE,
        );
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "NTP");

        assert_eq!(
            buf.field_by_name(layer, "leap_indicator").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "leap_indicator_name"),
            Some("no warning")
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            buf.field_by_name(layer, "mode").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(buf.resolve_display_name(layer, "mode_name"), Some("client"));
        assert_eq!(
            buf.field_by_name(layer, "stratum").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "poll").unwrap().value,
            FieldValue::I32(6)
        );
        assert_eq!(
            buf.field_by_name(layer, "precision").unwrap().value,
            FieldValue::I32(-20)
        );
        assert_eq!(
            buf.field_by_name(layer, "transmit_timestamp")
                .unwrap()
                .value,
            FieldValue::U64(0xDEAD_BEEF_CAFE_BABE)
        );
    }

    #[test]
    fn test_parse_server_response() {
        // NTPv4 server response: LI=0, VN=4, Mode=4, Stratum=2
        let data = build_ntp(
            0,
            4,
            4,
            2,
            6,
            -24,
            0x0000_0100, // root delay
            0x0000_0200, // root dispersion
            [192, 168, 1, 1],
            0x1122_3344_5566_7788,
            0xAABB_CCDD_EEFF_0011,
            0x2233_4455_6677_8899,
            0x3344_5566_7788_99AA,
        );
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "mode").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(buf.resolve_display_name(layer, "mode_name"), Some("server"));
        assert_eq!(
            buf.field_by_name(layer, "stratum").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "stratum_name"),
            Some("secondary server")
        );
        assert_eq!(
            buf.field_by_name(layer, "precision").unwrap().value,
            FieldValue::I32(-24)
        );
        assert_eq!(
            buf.field_by_name(layer, "root_delay").unwrap().value,
            FieldValue::U32(0x0000_0100)
        );
        assert_eq!(
            buf.field_by_name(layer, "root_dispersion").unwrap().value,
            FieldValue::U32(0x0000_0200)
        );
        // Stratum 2: reference ID stored as raw bytes
        assert_eq!(
            buf.field_by_name(layer, "reference_id").unwrap().value,
            FieldValue::Bytes(&[192, 168, 1, 1])
        );
        assert_eq!(
            buf.field_by_name(layer, "reference_timestamp")
                .unwrap()
                .value,
            FieldValue::U64(0x1122_3344_5566_7788)
        );
        assert_eq!(
            buf.field_by_name(layer, "origin_timestamp").unwrap().value,
            FieldValue::U64(0xAABB_CCDD_EEFF_0011)
        );
        assert_eq!(
            buf.field_by_name(layer, "receive_timestamp").unwrap().value,
            FieldValue::U64(0x2233_4455_6677_8899)
        );
        assert_eq!(
            buf.field_by_name(layer, "transmit_timestamp")
                .unwrap()
                .value,
            FieldValue::U64(0x3344_5566_7788_99AA)
        );
    }

    #[test]
    fn test_parse_stratum_0_kod() {
        // KoD packet: Stratum=0, Reference ID="RATE"
        let data = build_ntp(3, 4, 4, 0, 6, -20, 0, 0, *b"RATE", 0, 0, 0, 0);
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "leap_indicator").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "leap_indicator_name"),
            Some("unknown (clock unsynchronized)")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "stratum_name"),
            Some("unspecified or invalid")
        );
        assert_eq!(
            buf.field_by_name(layer, "reference_id").unwrap().value,
            FieldValue::Bytes(b"RATE")
        );
    }

    #[test]
    fn test_parse_stratum_1_primary() {
        // Primary server: Stratum=1, Reference ID="GPS\0"
        let data = build_ntp(0, 4, 4, 1, 4, -18, 0, 0, *b"GPS\0", 0, 0, 0, 0);
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "stratum_name"),
            Some("primary server")
        );
        // Raw bytes including trailing NUL
        assert_eq!(
            buf.field_by_name(layer, "reference_id").unwrap().value,
            FieldValue::Bytes(b"GPS\0")
        );
    }

    #[test]
    fn test_truncated_packet() {
        let data = [0u8; 47]; // 47 < 48
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, 48);
                assert_eq!(actual, 47);
            }
            other => panic!("Expected Truncated, got {other:?}"),
        }
    }

    /// Build an NTP control message (RFC 9327, Section 2).
    ///   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
    #[allow(clippy::too_many_arguments)]
    fn build_mode6(
        vn: u8,
        rem_op: u8,
        seq: u16,
        status: u16,
        assoc: u16,
        off: u16,
        data: &[u8],
    ) -> Vec<u8> {
        let mut pkt = vec![(vn << 3) | 6, rem_op];
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&status.to_be_bytes());
        pkt.extend_from_slice(&assoc.to_be_bytes());
        pkt.extend_from_slice(&off.to_be_bytes());
        pkt.extend_from_slice(&(data.len() as u16).to_be_bytes());
        pkt.extend_from_slice(data);
        pkt
    }

    #[test]
    fn test_parse_mode6_request() {
        // `ntpq -c rv` request: LI=0, VN=2, Mode=6, opcode 2 (READVAR), seq 1.
        let data = [0x16, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 42).unwrap();
        assert_eq!(result.bytes_consumed, 12);
        assert!(matches!(result.next, DispatchHint::End));

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "NTP");
        assert_eq!(layer.range, 42..54);
        assert_eq!(
            buf.field_by_name(layer, "leap_indicator").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "mode").unwrap().value,
            FieldValue::U8(6)
        );
        for (name, v) in [("response", 0), ("error", 0), ("more", 0)] {
            let f = buf.field_by_name(layer, name).unwrap();
            assert_eq!(f.value, FieldValue::U8(v), "{name}");
            assert_eq!(f.range, 43..44, "{name}");
        }
        assert_eq!(
            buf.field_by_name(layer, "opcode").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "opcode_name"),
            Some("read variables command/response")
        );
        let seq = buf.field_by_name(layer, "sequence").unwrap();
        assert_eq!(seq.value, FieldValue::U16(1));
        assert_eq!(seq.range, 44..46);
        assert_eq!(
            buf.field_by_name(layer, "count").unwrap().value,
            FieldValue::U16(0)
        );
        assert!(buf.field_by_name(layer, "data").is_none());
        assert!(buf.field_by_name(layer, "stratum").is_none());
        assert!(buf.field_by_name(layer, "transmit_timestamp").is_none());
    }

    #[test]
    fn test_parse_mode6_response() {
        let text = b"version=\"ntpd 4.2.8p15\", processor=\"x86_64\", system=\"Linux\", leap=00";
        assert_eq!(text.len(), 68);
        // R=1, E=0, M=0, opcode 2; status 0x0618.
        let data = build_mode6(2, 0x82, 1, 0x0618, 0, 0, text);
        assert_eq!(data.len(), 80);
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 80);

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "response").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "status").unwrap().value,
            FieldValue::U16(0x0618)
        );
        assert_eq!(
            buf.field_by_name(layer, "association_id").unwrap().value,
            FieldValue::U16(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "offset").unwrap().value,
            FieldValue::U16(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "count").unwrap().value,
            FieldValue::U16(68)
        );
        let d = buf.field_by_name(layer, "data").unwrap();
        assert_eq!(d.value, FieldValue::Bytes(text));
        assert_eq!(d.range, 12..80);
        assert!(buf.field_by_name(layer, "padding").is_none());
        assert!(buf.field_by_name(layer, "authenticator").is_none());
        assert!(buf.field_by_name(layer, "stratum").is_none());
    }

    #[test]
    fn test_parse_mode6_padding_and_authenticator() {
        // E=1, M=1, opcode 1; 5 data octets, 3 octets of padding and a
        // 20-octet authenticator (key ID + MD5 digest).
        let mut data = build_mode6(2, 0xE1, 9, 0, 3, 16, b"abcde");
        data.extend_from_slice(&[0, 0, 0]);
        data.extend_from_slice(&[0x5A; 20]);
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 40);

        let layer = &buf.layers()[0];
        for name in ["response", "error", "more"] {
            assert_eq!(
                buf.field_by_name(layer, name).unwrap().value,
                FieldValue::U8(1),
                "{name}"
            );
        }
        assert_eq!(
            buf.resolve_display_name(layer, "opcode_name"),
            Some("read status command/response")
        );
        assert_eq!(
            buf.field_by_name(layer, "offset").unwrap().value,
            FieldValue::U16(16)
        );
        let pad = buf.field_by_name(layer, "padding").unwrap();
        assert_eq!(pad.value, FieldValue::Bytes(&[0, 0, 0]));
        assert_eq!(pad.range, 17..20);
        let auth = buf.field_by_name(layer, "authenticator").unwrap();
        assert_eq!(auth.value, FieldValue::Bytes(&[0x5A; 20]));
        assert_eq!(auth.range, 20..40);
    }

    #[test]
    fn test_mode6_opcode_names() {
        let expected = [
            (0, "reserved"),
            (3, "write variables command/response"),
            (4, "read clock variables command/response"),
            (5, "write clock variables command/response"),
            (6, "set trap address/port command/response"),
            (7, "trap response"),
            (8, "runtime configuration command/response"),
            (9, "export configuration to file command/response"),
            (10, "retrieve remote address stats command/response"),
            (11, "retrieve ordered list command/response"),
            (12, "request client-specific nonce command/response"),
            (13, "reserved"),
            (30, "reserved"),
            (31, "unset trap address/port command/response"),
        ];
        for (op, name) in expected {
            assert_eq!(control_opcode_name(op), name, "opcode {op}");
        }
    }

    #[test]
    fn test_mode6_truncated_header() {
        let data = [0x16, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        let err = NtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 12,
                actual: 11
            }
        ));
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn test_mode6_truncated_data() {
        let mut data = build_mode6(2, 0x82, 1, 0, 0, 0, &[b'x'; 10]);
        data.truncate(15);
        let mut buf = DissectBuffer::new();
        let err = NtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 22,
                actual: 15
            }
        ));
    }

    #[test]
    fn test_parse_mode7_private() {
        // RFC 5905, Section 7.3, Figure 10 — mode 7 is "reserved for private
        // use"; only VN and Mode are interpreted.
        //   <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>
        let data = [0x17, 0x00, 0x03, 0x2a, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "mode").unwrap().value,
            FieldValue::U8(7)
        );
        let d = buf.field_by_name(layer, "data").unwrap();
        assert_eq!(d.value, FieldValue::Bytes(&data[1..]));
        assert_eq!(d.range, 1..8);
        assert!(buf.field_by_name(layer, "leap_indicator").is_none());
        assert!(buf.field_by_name(layer, "stratum").is_none());

        // A lone first octet is still a valid (empty) private message.
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data[..1], &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 1);
        assert!(buf.field_by_name(&buf.layers()[0], "data").is_none());
    }

    #[test]
    fn test_empty_packet() {
        let mut buf = DissectBuffer::new();
        let err = NtpDissector.dissect(&[], &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 1,
                actual: 0
            }
        ));
    }

    #[test]
    fn test_field_descriptors() {
        let descriptors = NtpDissector.field_descriptors();
        assert_eq!(descriptors.len(), 29);
        assert_eq!(descriptors[0].name, "leap_indicator");
        assert_eq!(
            descriptors[FD_TRANSMIT_TIMESTAMP].name,
            "transmit_timestamp"
        );
        assert_eq!(descriptors[FD_AUTHENTICATOR].name, "authenticator");
        assert_eq!(descriptors[FD_EXTENSION_FIELDS].name, "extension_fields");
        assert_eq!(descriptors[FD_KEY_ID].name, "key_id");
        assert_eq!(descriptors[FD_DIGEST].name, "digest");
        assert_eq!(descriptors[descriptors.len() - 1].name, "trailing_data");
        // Only VN and Mode are present in every mode.
        for (i, d) in descriptors.iter().enumerate() {
            assert_eq!(d.optional, i != FD_VERSION && i != FD_MODE, "{}", d.name);
        }
    }

    #[test]
    fn test_dissect_with_offset() {
        // Verify byte ranges use absolute offsets
        let data = build_ntp(0, 4, 3, 0, 6, -20, 0, 0, [0; 4], 0, 0, 0, 0);
        let offset = 42; // simulate preceding headers
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, offset).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(layer.range, offset..offset + HEADER_SIZE);
        assert_eq!(
            buf.field_by_name(layer, "transmit_timestamp")
                .unwrap()
                .range,
            offset + 40..offset + 48
        );
    }

    #[test]
    fn test_mode_values() {
        // Test all mode values
        for mode in 0..=7 {
            let data = build_ntp(0, 4, mode, 0, 0, 0, 0, 0, [0; 4], 0, 0, 0, 0);
            let mut buf = DissectBuffer::new();
            NtpDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert_eq!(
                buf.field_by_name(layer, "mode").unwrap().value,
                FieldValue::U8(mode)
            );
            // Ensure mode_name is present and non-empty
            let mode_display = buf.resolve_display_name(layer, "mode_name");
            assert!(mode_display.is_some());
            assert!(!mode_display.unwrap().is_empty());
        }
    }

    #[test]
    fn test_leap_indicator_values() {
        for li in 0..=3 {
            let data = build_ntp(li, 4, 3, 0, 0, 0, 0, 0, [0; 4], 0, 0, 0, 0);
            let mut buf = DissectBuffer::new();
            NtpDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert_eq!(
                buf.field_by_name(layer, "leap_indicator").unwrap().value,
                FieldValue::U8(li)
            );
        }
    }

    #[test]
    fn test_stratum_ranges() {
        // Stratum 16 = Unsynchronized
        let data = build_ntp(0, 4, 4, 16, 0, 0, 0, 0, [0; 4], 0, 0, 0, 0);
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "stratum_name"),
            Some("unsynchronized")
        );

        // Stratum 17 = Reserved
        let data = build_ntp(0, 4, 4, 17, 0, 0, 0, 0, [0; 4], 0, 0, 0, 0);
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "stratum_name"),
            Some("reserved")
        );
    }

    #[test]
    fn test_kod_name_lookup() {
        // Descriptions are verbatim from RFC 5905, Figure 13.
        assert_eq!(kod_name("DENY"), Some("Access denied by remote server"));
        assert_eq!(
            kod_name("RATE"),
            Some(
                "Rate exceeded. The server has temporarily denied access because the client exceeded the rate threshold"
            )
        );
        assert_eq!(kod_name("XXXX"), None);
    }

    #[test]
    fn test_root_delay_is_unsigned() {
        // RFC 5905, Section 6 (Figure 3 — NTP Short Format) defines Root Delay
        // as a 16-bit unsigned seconds field and a 16-bit fraction field, so
        // high-bit values must decode as large positive numbers, not as
        // negative values.
        // https://www.rfc-editor.org/rfc/rfc5905#section-6
        let data = build_ntp(
            0,
            4,
            4,
            2,
            6,
            -24,
            0xFFFF_FFFF, // root delay: max unsigned 16.16
            0xFFFF_FFFF, // root dispersion: max unsigned 16.16
            [0; 4],
            0,
            0,
            0,
            0,
        );
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "root_delay").unwrap().value,
            FieldValue::U32(0xFFFF_FFFF)
        );
        assert_eq!(
            buf.field_by_name(layer, "root_dispersion").unwrap().value,
            FieldValue::U32(0xFFFF_FFFF)
        );
    }

    #[test]
    fn test_version_number_field_width() {
        // RFC 5905, Section 7.3: VN is a 3-bit integer, so values 0..=7 must
        // round-trip through the dissector. This guards against accidental
        // masking changes.
        // https://www.rfc-editor.org/rfc/rfc5905#section-7.3
        for vn in 0u8..=7 {
            let data = build_ntp(0, vn, 3, 0, 0, 0, 0, 0, [0; 4], 0, 0, 0, 0);
            let mut buf = DissectBuffer::new();
            NtpDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert_eq!(
                buf.field_by_name(layer, "version").unwrap().value,
                FieldValue::U8(vn)
            );
        }
    }

    /// Helper: call `format_ntp_ref_id` with an empty `FormatContext`.
    fn call_ref_id_format(value: &FieldValue<'_>) -> Vec<u8> {
        let ctx = FormatContext {
            packet_data: &[],
            scratch: &[],
            layer_range: 0..0,
            field_range: 0..0,
        };
        let mut out: Vec<u8> = Vec::new();
        format_ntp_ref_id(value, &ctx, &mut out).unwrap();
        out
    }

    #[test]
    fn test_reference_id_ipv4_formatting() {
        // Stratum >= 2 encodes Reference ID as an IPv4 address
        // (RFC 5905, Section 7.3).
        // https://www.rfc-editor.org/rfc/rfc5905#section-7.3
        let bytes = [10u8, 0, 0, 42];
        let out = call_ref_id_format(&FieldValue::Bytes(&bytes));
        assert_eq!(out, b"\"10.0.0.42\"");
    }

    #[test]
    fn test_reference_id_ascii_formatting() {
        // Stratum 0/1 encode Reference ID as a 4-character ASCII code
        // (RFC 5905, Section 7.3 / Section 7.4 — KoD codes).
        // https://www.rfc-editor.org/rfc/rfc5905#section-7.4
        let bytes = *b"GPS\0";
        let out = call_ref_id_format(&FieldValue::Bytes(&bytes));
        assert_eq!(out, b"\"GPS\"");
    }

    #[test]
    fn test_all_kod_codes_from_rfc_figure_13() {
        // Every KoD code from RFC 5905, Figure 13 must resolve to a
        // non-empty description. This guards against entries being removed.
        // https://www.rfc-editor.org/rfc/rfc5905#section-7.4
        const CODES: &[&str] = &[
            "ACST", "AUTH", "AUTO", "BCST", "CRYP", "DENY", "DROP", "RSTR", "INIT", "MCST", "NKEY",
            "RATE", "RMOT", "STEP",
        ];
        for code in CODES {
            assert!(
                kod_name(code).is_some_and(|s| !s.is_empty()),
                "KoD code {code} missing description"
            );
        }
    }

    #[test]
    fn references_and_layer_are_populated() {
        let dissector = NtpDissector;
        let references = dissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Application));
    }

    // ---------------------------------------------------------------
    // Extension fields, NTS and MACs (RFC 7822, RFC 8915, RFC 5905 §7.3)
    // ---------------------------------------------------------------

    /// A 48-octet client request header: LI 0, mode 3, rest zero.
    fn client_header(vn: u8) -> Vec<u8> {
        build_ntp(0, vn, 3, 0, 0, 0, 0, 0, [0; 4], 0, 0, 0, 0)
    }

    /// Build an extension field (RFC 7822, Section 3) whose Length covers
    /// the 4-octet type/length header plus `body`.
    ///   <https://www.rfc-editor.org/rfc/rfc7822#section-3>
    fn build_ef(field_type: u16, body: &[u8]) -> Vec<u8> {
        let mut ef = field_type.to_be_bytes().to_vec();
        ef.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        ef.extend_from_slice(body);
        ef
    }

    /// Build the body of an NTS Authenticator and Encrypted Extension Fields
    /// extension field (RFC 8915, Section 5.6, Figure 4).
    ///   <https://www.rfc-editor.org/rfc/rfc8915#section-5.6>
    fn build_nts_auth_body(nonce: &[u8], ciphertext: &[u8], additional_padding: usize) -> Vec<u8> {
        let pad4 = |n: usize| (4 - n % 4) % 4;
        let mut body = (nonce.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        body.extend_from_slice(nonce);
        body.extend(std::iter::repeat_n(0u8, pad4(nonce.len())));
        body.extend_from_slice(ciphertext);
        body.extend(std::iter::repeat_n(0u8, pad4(ciphertext.len())));
        body.extend(std::iter::repeat_n(0u8, additional_padding));
        body
    }

    /// Returns `(object field index, children range)` for every Object in
    /// the `extension_fields` Array, in wire order.
    fn extension_fields(
        buf: &DissectBuffer<'_>,
        layer: &packet_dissector_core::packet::Layer,
    ) -> Vec<(u32, core::ops::Range<u32>)> {
        let Some(arr) = buf.field_by_name(layer, "extension_fields") else {
            return Vec::new();
        };
        let range = arr.value.as_container_range().unwrap().clone();
        let mut out = Vec::new();
        let mut idx = range.start;
        while idx < range.end {
            let children = buf.fields()[idx as usize]
                .value
                .as_container_range()
                .unwrap()
                .clone();
            out.push((idx, children.clone()));
            idx = children.end;
        }
        out
    }

    /// Finds a child field by name within an Object's children.
    fn child<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        range: &core::ops::Range<u32>,
        name: &str,
    ) -> Option<&'a packet_dissector_core::field::Field<'pkt>> {
        buf.nested_fields(range).iter().find(|f| f.name() == name)
    }

    #[test]
    fn test_parse_single_unknown_extension_field() {
        // Client request with a single 28-octet extension field of an
        // experimental type and a zero Value (RFC 7822, Section 3,
        // 7.5.1.4: a lone extension field without a MAC is at least 28
        // octets).
        //   <https://www.rfc-editor.org/rfc/rfc7822#section-3>
        let mut data = client_header(4);
        data.extend_from_slice(&build_ef(0xFF00, &[0; 24]));
        assert_eq!(data.len(), 76);
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 76);
        assert!(matches!(result.next, DispatchHint::End));

        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 0..76);
        let arr = buf.field_by_name(layer, "extension_fields").unwrap();
        assert_eq!(arr.range, 48..76);
        let efs = extension_fields(&buf, layer);
        assert_eq!(efs.len(), 1);
        let (obj_idx, ef) = &efs[0];
        assert_eq!(buf.fields()[*obj_idx as usize].range, 48..76);
        assert_eq!(
            buf.resolve_container_display_name(*obj_idx),
            Some("Reserved for Private or Experimental Use")
        );
        let ft = child(&buf, ef, "field_type").unwrap();
        assert_eq!(ft.value, FieldValue::U16(0xFF00));
        assert_eq!(ft.range, 48..50);
        assert_eq!(
            buf.resolve_nested_display_name(ef, "field_type_name"),
            Some("Reserved for Private or Experimental Use")
        );
        let len = child(&buf, ef, "length").unwrap();
        assert_eq!(len.value, FieldValue::U16(28));
        assert_eq!(len.range, 50..52);
        let value = child(&buf, ef, "value").unwrap();
        assert_eq!(value.value, FieldValue::Bytes(&[0; 24]));
        assert_eq!(value.range, 52..76);
        assert!(buf.field_by_name(layer, "key_id").is_none());
        assert!(buf.field_by_name(layer, "digest").is_none());
        assert!(buf.field_by_name(layer, "trailing_data").is_none());
    }

    /// RFC 8915, Section 5.4 — "The NTS Cookie extension field MUST NOT be
    /// included in NTP packets whose mode is other than 3 (client) or 4
    /// (server)." In symmetric and broadcast packets, Field Type 0x0204 is
    /// the Autokey Message Request (RFC 5906) even without a MAC, so its body
    /// is kept as `value`.
    ///   <https://www.rfc-editor.org/rfc/rfc8915#section-5.4>
    #[test]
    fn test_0x0204_outside_client_server_is_not_nts_cookie() {
        for mode in [1u8, 2, 5] {
            let mut data = build_ntp(0, 4, mode, 2, 0, 0, 0, 0, [0; 4], 0, 0, 0, 0);
            data.extend_from_slice(&build_ef(0x0204, &[0x5A; 36]));
            let mut buf = DissectBuffer::new();
            NtpDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            let efs = extension_fields(&buf, layer);
            assert_eq!(efs.len(), 1, "mode {mode}");
            let names: Vec<_> = buf
                .nested_fields(&efs[0].1)
                .iter()
                .map(|f| f.name())
                .collect();
            assert_eq!(names, ["field_type", "length", "value"], "mode {mode}");
        }
    }

    #[test]
    fn test_parse_nts_client_request() {
        // RFC 8915, Section 5.7 — a client request carries a Unique
        // Identifier, an NTS Cookie, optional Cookie Placeholders and an NTS
        // Authenticator and Encrypted Extension Fields extension field.
        //   <https://www.rfc-editor.org/rfc/rfc8915#section-5.7>
        let uid: Vec<u8> = (0u8..32).collect();
        let cookie: Vec<u8> = (0u8..100).map(|b| b ^ 0xA5).collect();
        let nonce = [0x11u8; 16];
        let ciphertext = [0x22u8; 16];
        let mut data = client_header(4);
        data.extend_from_slice(&build_ef(0x0104, &uid)); // 36 octets
        data.extend_from_slice(&build_ef(0x0204, &cookie)); // 104 octets
        data.extend_from_slice(&build_ef(0x0304, &[0; 100])); // 104 octets
        data.extend_from_slice(&build_ef(
            0x0404,
            &build_nts_auth_body(&nonce, &ciphertext, 0),
        )); // 40 octets
        assert_eq!(data.len(), 48 + 36 + 104 + 104 + 40);

        let off = 42;
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, off).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, off..off + data.len());

        let efs = extension_fields(&buf, layer);
        assert_eq!(efs.len(), 4);

        // Unique Identifier (RFC 8915, Section 5.3).
        let (idx, ef) = &efs[0];
        assert_eq!(
            buf.resolve_container_display_name(*idx),
            Some("Unique Identifier")
        );
        assert_eq!(
            child(&buf, ef, "field_type").unwrap().value,
            FieldValue::U16(0x0104)
        );
        let u = child(&buf, ef, "unique_id").unwrap();
        assert_eq!(u.value, FieldValue::Bytes(&uid));
        assert_eq!(u.range, off + 52..off + 84);
        assert!(child(&buf, ef, "value").is_none());

        // NTS Cookie (RFC 8915, Section 5.4).
        let (idx, ef) = &efs[1];
        assert_eq!(
            buf.resolve_container_display_name(*idx),
            Some("NTS Cookie / Autokey Message Request")
        );
        let c = child(&buf, ef, "cookie").unwrap();
        assert_eq!(c.value, FieldValue::Bytes(&cookie));
        assert_eq!(c.range, off + 88..off + 188);

        // NTS Cookie Placeholder (RFC 8915, Section 5.5).
        let (idx, ef) = &efs[2];
        assert_eq!(
            buf.resolve_container_display_name(*idx),
            Some("NTS Cookie Placeholder")
        );
        assert_eq!(
            child(&buf, ef, "placeholder").unwrap().value,
            FieldValue::Bytes(&[0; 100])
        );
        assert!(child(&buf, ef, "cookie").is_none());

        // NTS Authenticator and Encrypted Extension Fields (Section 5.6).
        let (idx, ef) = &efs[3];
        assert_eq!(
            buf.resolve_container_display_name(*idx),
            Some("NTS Authenticator and Encrypted Extension Fields")
        );
        let base = off + 48 + 36 + 104 + 104;
        let nl = child(&buf, ef, "nonce_length").unwrap();
        assert_eq!(nl.value, FieldValue::U16(16));
        assert_eq!(nl.range, base + 4..base + 6);
        let cl = child(&buf, ef, "ciphertext_length").unwrap();
        assert_eq!(cl.value, FieldValue::U16(16));
        assert_eq!(cl.range, base + 6..base + 8);
        let n = child(&buf, ef, "nonce").unwrap();
        assert_eq!(n.value, FieldValue::Bytes(&nonce));
        assert_eq!(n.range, base + 8..base + 24);
        let ct = child(&buf, ef, "ciphertext").unwrap();
        assert_eq!(ct.value, FieldValue::Bytes(&ciphertext));
        assert_eq!(ct.range, base + 24..base + 40);
        for name in [
            "nonce_padding",
            "ciphertext_padding",
            "additional_padding",
            "value",
        ] {
            assert!(child(&buf, ef, name).is_none(), "{name}");
        }
        assert!(buf.field_by_name(layer, "key_id").is_none());
        assert!(buf.field_by_name(layer, "trailing_data").is_none());
    }

    #[test]
    fn test_parse_nts_authenticator_padding() {
        // RFC 8915, Section 5.6 — Nonce and Ciphertext are each zero-padded
        // to a word boundary and may be followed by Additional Padding.
        //   <https://www.rfc-editor.org/rfc/rfc8915#section-5.6>
        let nonce = [0x33u8; 13];
        let ciphertext = [0x44u8; 17];
        let mut data = client_header(4);
        data.extend_from_slice(&build_ef(
            0x0404,
            &build_nts_auth_body(&nonce, &ciphertext, 4),
        ));
        // 4 (EF header) + 4 (lengths) + 16 (nonce) + 20 (ciphertext) + 4.
        assert_eq!(data.len(), 96);
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 96);
        let layer = &buf.layers()[0];
        let efs = extension_fields(&buf, layer);
        assert_eq!(efs.len(), 1);
        let ef = &efs[0].1;
        let n = child(&buf, ef, "nonce").unwrap();
        assert_eq!(n.value, FieldValue::Bytes(&nonce));
        assert_eq!(n.range, 56..69);
        let np = child(&buf, ef, "nonce_padding").unwrap();
        assert_eq!(np.value, FieldValue::Bytes(&[0, 0, 0]));
        assert_eq!(np.range, 69..72);
        let ct = child(&buf, ef, "ciphertext").unwrap();
        assert_eq!(ct.value, FieldValue::Bytes(&ciphertext));
        assert_eq!(ct.range, 72..89);
        let cp = child(&buf, ef, "ciphertext_padding").unwrap();
        assert_eq!(cp.range, 89..92);
        let ap = child(&buf, ef, "additional_padding").unwrap();
        assert_eq!(ap.value, FieldValue::Bytes(&[0; 4]));
        assert_eq!(ap.range, 92..96);

        // Zero-length Nonce and Ciphertext: only the lengths and padding.
        let mut data = client_header(4);
        data.extend_from_slice(&build_ef(0x0404, &build_nts_auth_body(&[], &[], 24)));
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let efs = extension_fields(&buf, layer);
        let ef = &efs[0].1;
        assert_eq!(
            child(&buf, ef, "nonce_length").unwrap().value,
            FieldValue::U16(0)
        );
        assert!(child(&buf, ef, "nonce").is_none());
        assert!(child(&buf, ef, "ciphertext").is_none());
        assert_eq!(child(&buf, ef, "additional_padding").unwrap().range, 56..80);
    }

    #[test]
    fn test_nts_authenticator_inconsistent_lengths() {
        // Nonce Length + Ciphertext Length exceed the extension field: the
        // body cannot be decoded as Figure 4 and is kept as opaque `value`.
        //   <https://www.rfc-editor.org/rfc/rfc8915#section-5.6>
        for (nonce_len, ct_len) in [(200u16, 16u16), (16, 200), (0xFFFF, 0xFFFF)] {
            let mut body = build_nts_auth_body(&[0x55; 16], &[0x66; 16], 0);
            body[0..2].copy_from_slice(&nonce_len.to_be_bytes());
            body[2..4].copy_from_slice(&ct_len.to_be_bytes());
            let mut data = client_header(4);
            data.extend_from_slice(&build_ef(0x0404, &body));
            let mut buf = DissectBuffer::new();
            let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(result.bytes_consumed, data.len());
            let layer = &buf.layers()[0];
            let efs = extension_fields(&buf, layer);
            assert_eq!(efs.len(), 1);
            let ef = &efs[0].1;
            assert_eq!(
                child(&buf, ef, "value").unwrap().value,
                FieldValue::Bytes(&body)
            );
            assert!(child(&buf, ef, "nonce_length").is_none());
            assert!(child(&buf, ef, "nonce").is_none());
        }
    }

    #[test]
    fn test_parse_mac_20_octets() {
        // RFC 5905, Section 7.3 — MAC = 32-bit Key Identifier + 128-bit
        // digest (MD5, or AES-CMAC per RFC 8573). Key ID 16 makes the first
        // word look like an extension field header (type 0x0000, length 16),
        // but RFC 7822, Section 3 (7.5.1.4) requires a trailing extension
        // field without a MAC to be at least 28 octets, so the block is a MAC.
        //   <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>
        //   <https://www.rfc-editor.org/rfc/rfc7822#section-3>
        let digest: Vec<u8> = (0xE0u8..0xF0).collect();
        let mut data = build_ntp(0, 4, 1, 2, 6, -20, 0, 0, [10, 0, 0, 1], 0, 0, 0, 0);
        data.extend_from_slice(&16u32.to_be_bytes());
        data.extend_from_slice(&digest);
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 68);
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 0..68);
        assert!(buf.field_by_name(layer, "extension_fields").is_none());
        let key_id = buf.field_by_name(layer, "key_id").unwrap();
        assert_eq!(key_id.value, FieldValue::U32(16));
        assert_eq!(key_id.range, 48..52);
        let d = buf.field_by_name(layer, "digest").unwrap();
        assert_eq!(d.value, FieldValue::Bytes(&digest));
        assert_eq!(d.range, 52..68);
        assert!(buf.field_by_name(layer, "trailing_data").is_none());
    }

    #[test]
    fn test_parse_mac_24_octets() {
        // RFC 7822, Section 3 (7.5.1.3) — "A MAC MUST NOT be longer than 24
        // octets if there is no extension field present": 32-bit key ID +
        // 160-bit digest.
        //   <https://www.rfc-editor.org/rfc/rfc7822#section-3>
        let mut data = build_ntp(0, 4, 2, 2, 6, -20, 0, 0, [10, 0, 0, 1], 0, 0, 0, 0);
        data.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        data.extend_from_slice(&[0x77; 20]);
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 72);
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "extension_fields").is_none());
        assert_eq!(
            buf.field_by_name(layer, "key_id").unwrap().value,
            FieldValue::U32(0xDEAD_BEEF)
        );
        let d = buf.field_by_name(layer, "digest").unwrap();
        assert_eq!(d.value, FieldValue::Bytes(&[0x77; 20]));
        assert_eq!(d.range, 52..72);
    }

    #[test]
    fn test_parse_crypto_nak() {
        // RFC 5905, Section 9.2 — a crypto-NAK "includes the normal NTP
        // header data shown in Figure 8, but with a MAC consisting of four
        // octets of zeros".
        //   <https://www.rfc-editor.org/rfc/rfc5905#section-9.2>
        let mut data = build_ntp(0, 4, 4, 2, 6, -20, 0, 0, [10, 0, 0, 1], 0, 0, 0, 0);
        data.extend_from_slice(&[0; 4]);
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 52);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "key_id").unwrap().value,
            FieldValue::U32(0)
        );
        assert!(buf.field_by_name(layer, "digest").is_none());
    }

    #[test]
    fn test_parse_extension_field_followed_by_mac() {
        // RFC 7822, Section 3 (7.5) — extension fields are "inserted after
        // the header and before the MAC, if a MAC is present"; with a MAC
        // an extension field may be as short as 16 octets.
        //   <https://www.rfc-editor.org/rfc/rfc7822#section-3>
        let mut data = client_header(4);
        data.extend_from_slice(&build_ef(0x0200, &[0xAB; 12])); // 16 octets
        data.extend_from_slice(&7u32.to_be_bytes());
        data.extend_from_slice(&[0xCD; 16]);
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 84);
        let layer = &buf.layers()[0];
        let efs = extension_fields(&buf, layer);
        assert_eq!(efs.len(), 1);
        assert_eq!(
            buf.resolve_container_display_name(efs[0].0),
            Some("No-Operation Request")
        );
        assert_eq!(child(&buf, &efs[0].1, "value").unwrap().range, 52..64);
        let key_id = buf.field_by_name(layer, "key_id").unwrap();
        assert_eq!(key_id.value, FieldValue::U32(7));
        assert_eq!(key_id.range, 64..68);
        assert_eq!(buf.field_by_name(layer, "digest").unwrap().range, 68..84);
        assert!(buf.field_by_name(layer, "trailing_data").is_none());
    }

    #[test]
    fn test_autokey_message_request_with_mac_is_not_nts_cookie() {
        // IANA "NTP Extension Field Types": 0x0204 is both "Autokey Message
        // Request" (RFC 5906) and "NTS Cookie" (RFC 8915, Section 5.4). An
        // Autokey packet carries a MAC, so the body is kept as `value`.
        let mut data = client_header(4);
        data.extend_from_slice(&build_ef(0x0204, &[0x11; 12])); // 16 octets
        data.extend_from_slice(&9u32.to_be_bytes());
        data.extend_from_slice(&[0x22; 16]);
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let efs = extension_fields(&buf, layer);
        assert_eq!(efs.len(), 1);
        assert!(child(&buf, &efs[0].1, "cookie").is_none());
        assert_eq!(
            child(&buf, &efs[0].1, "value").unwrap().value,
            FieldValue::Bytes(&[0x11; 12])
        );
        assert!(buf.field_by_name(layer, "key_id").is_some());
    }

    #[test]
    fn test_malformed_extension_field_length() {
        // RFC 7822, Section 3 (7.5) — Length covers the whole field, is at
        // least 16 octets and every field is padded to a word boundary.
        // Violations leave the remaining octets as `trailing_data`.
        //   <https://www.rfc-editor.org/rfc/rfc7822#section-3>
        for bad_len in [30u16, 12, 200, 0] {
            let mut data = client_header(4);
            let mut ef = build_ef(0xFF00, &[0; 28]);
            ef[2..4].copy_from_slice(&bad_len.to_be_bytes());
            data.extend_from_slice(&ef);
            let mut buf = DissectBuffer::new();
            let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(result.bytes_consumed, 80, "len {bad_len}");
            let layer = &buf.layers()[0];
            assert_eq!(layer.range, 0..80);
            assert!(
                buf.field_by_name(layer, "extension_fields").is_none(),
                "len {bad_len}"
            );
            let t = buf.field_by_name(layer, "trailing_data").unwrap();
            assert_eq!(t.value, FieldValue::Bytes(&ef));
            assert_eq!(t.range, 48..80);
        }

        // A valid extension field followed by an undecodable block keeps the
        // decoded field and the rest as `trailing_data`.
        let mut data = client_header(4);
        data.extend_from_slice(&build_ef(0xFF00, &[0; 24]));
        let junk = [0xFFu8; 27];
        data.extend_from_slice(&junk);
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        let layer = &buf.layers()[0];
        assert_eq!(extension_fields(&buf, layer).len(), 1);
        let t = buf.field_by_name(layer, "trailing_data").unwrap();
        assert_eq!(t.value, FieldValue::Bytes(&junk));
        assert_eq!(t.range, 76..103);
    }

    #[test]
    fn test_trailer_not_mac_shaped() {
        // Blocks of 24 octets or fewer that are not a whole number of 32-bit
        // words (RFC 5905, Section 7.3) cannot be a MAC and are kept raw.
        //   <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>
        for n in [1usize, 3, 7, 23] {
            let mut data = client_header(4);
            data.extend(std::iter::repeat_n(0x42u8, n));
            let mut buf = DissectBuffer::new();
            let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(result.bytes_consumed, 48 + n);
            let layer = &buf.layers()[0];
            assert!(buf.field_by_name(layer, "key_id").is_none(), "{n}");
            let t = buf.field_by_name(layer, "trailing_data").unwrap();
            assert_eq!(t.range, 48..48 + n);
        }
    }

    #[test]
    fn test_ntpv3_mac_without_extension_fields() {
        // RFC 7822, Section 3 (7.5) — extension fields are an NTPv4
        // feature ("In NTPv4, one or more extension fields can be
        // inserted after the header and before the MAC, if a MAC is
        // present."). An NTPv3 packet may only carry a MAC.
        //   <https://www.rfc-editor.org/rfc/rfc7822#section-3>
        let mut data = client_header(3);
        data.extend_from_slice(&5u32.to_be_bytes());
        data.extend_from_slice(&[0x99; 16]);
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 68);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "key_id").unwrap().value,
            FieldValue::U32(5)
        );

        // An extension-field-shaped block in an NTPv3 packet is not decoded.
        let mut data = client_header(3);
        let ef = build_ef(0xFF00, &[0; 24]);
        data.extend_from_slice(&ef);
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 76);
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "extension_fields").is_none());
        assert_eq!(
            buf.field_by_name(layer, "trailing_data").unwrap().value,
            FieldValue::Bytes(&ef)
        );
    }

    #[test]
    fn test_extension_field_type_names() {
        // IANA "NTP Extension Field Types" registry.
        //   <https://www.iana.org/assignments/ntp-parameters>
        let expected = [
            (0x0000, Some("Crypto-NAK; authentication failure")),
            (0x0002, Some("Reserved for historic reasons")),
            (0x0102, Some("Reserved for historic reasons")),
            (0x0104, Some("Unique Identifier")),
            (0x010A, Some("Network Correction")),
            (0x0200, Some("No-Operation Request")),
            (0x0201, Some("Association Message Request")),
            (0x0202, Some("Certificate Message Request")),
            (0x0203, Some("Cookie Message Request")),
            (0x0204, Some("NTS Cookie / Autokey Message Request")),
            (0x0205, Some("Leapseconds Message Request")),
            (0x0206, Some("Sign Message Request")),
            (0x0207, Some("IFF Identity Message Request")),
            (0x0208, Some("GQ Identity Message Request")),
            (0x0209, Some("MV Identity Message Request")),
            (0x0302, Some("Reserved for historic reasons")),
            (0x0304, Some("NTS Cookie Placeholder")),
            (
                0x0404,
                Some("NTS Authenticator and Encrypted Extension Fields"),
            ),
            (0x0902, Some("Reserved for historic reasons")),
            (0x2005, Some("UDP Checksum Complement")),
            (0x8002, Some("Reserved for historic reasons")),
            (0x8200, Some("No-Operation Response")),
            (0x8204, Some("Autokey Message Response")),
            (0x8209, Some("MV Identity Message Response")),
            (0x8902, Some("Reserved for historic reasons")),
            (0xC002, Some("Reserved for historic reasons")),
            (0xC200, Some("No-Operation Error Response")),
            (0xC209, Some("MV Identity Message Error Response")),
            (0xC902, Some("Reserved for historic reasons")),
            (0xF000, Some("Reserved for Private or Experimental Use")),
            (0xFFFF, Some("Reserved for Private or Experimental Use")),
            (0x0001, None),
            (0x0A02, None),
            (0x1234, None),
        ];
        for (t, name) in expected {
            assert_eq!(extension_field_type_name(t), name, "{t:#06x}");
        }
    }
}
