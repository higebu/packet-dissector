//! SCTP (Stream Control Transmission Protocol) dissector.
//!
//! Parses the SCTP common header (12 bytes) and individual chunks. Every
//! chunk is an object with its type, flags and length. The bodies of DATA,
//! INIT, INIT ACK, SACK, HEARTBEAT, HEARTBEAT ACK, ABORT, SHUTDOWN, ERROR,
//! SHUTDOWN COMPLETE and I-DATA chunks are decoded into named fields; other
//! chunks keep their body as a raw `value`.
//!
//! The user data of every unfragmented DATA / I-DATA chunk in the packet is
//! recorded with [`DissectBuffer::push_embedded_payload`], so bundled user
//! messages (RFC 9260, Section 6.10 —
//! <https://www.rfc-editor.org/rfc/rfc9260#section-6.10>) are each dispatched to the upper layer,
//! selected by their Payload Protocol Identifier first and the SCTP ports
//! second ([`DispatchHint::BySctpPpid`]). Fragments of a user message (B and
//! E bits not both set, Section 6.9) are shown but not dispatched.
//!
//! ## References
//! - RFC 9260: <https://www.rfc-editor.org/rfc/rfc9260>
//!   - Section 3.2 (Chunk Field Descriptions): <https://www.rfc-editor.org/rfc/rfc9260#section-3.2>
//!   - Section 3.2.1 (Parameter Format): <https://www.rfc-editor.org/rfc/rfc9260#section-3.2.1>
//!   - Section 3.3 (Chunk Definitions): <https://www.rfc-editor.org/rfc/rfc9260#section-3.3>
//!   - Section 6.9 (Fragmentation and Reassembly): <https://www.rfc-editor.org/rfc/rfc9260#section-6.9>
//!   - Section 6.10 (Bundling): <https://www.rfc-editor.org/rfc/rfc9260#section-6.10>
//! - RFC 8260 (I-DATA, I-FORWARD-TSN): <https://www.rfc-editor.org/rfc/rfc8260>
//! - RFC 4895 (AUTH): <https://www.rfc-editor.org/rfc/rfc4895>
//! - RFC 5061 (ASCONF, ASCONF-ACK): <https://www.rfc-editor.org/rfc/rfc5061>
//! - RFC 6525 (RE-CONFIG): <https://www.rfc-editor.org/rfc/rfc6525>
//! - RFC 4820 (PAD): <https://www.rfc-editor.org/rfc/rfc4820>
//! - RFC 3758 (FORWARD TSN): <https://www.rfc-editor.org/rfc/rfc3758>
//! - IANA SCTP Parameters (chunk types, parameter types, cause codes,
//!   Payload Protocol Identifiers): <https://www.iana.org/assignments/sctp-parameters/>

#![deny(missing_docs)]

use packet_dissector_core::checksum::{
    ChecksumStatus, checksum_status_descriptor, crc32c, ip_payload,
};
use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Minimum SCTP common header size (always 12 bytes).
/// RFC 9260, Section 3 — SCTP Packet Format.
const COMMON_HEADER_SIZE: usize = 12;

/// Minimum chunk header size (type + flags + length = 4 bytes).
/// RFC 9260, Section 3.2 — Chunk Field Descriptions.
const MIN_CHUNK_SIZE: usize = 4;

/// Chunk type identifiers.
/// RFC 9260, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.2>
const CHUNK_TYPE_DATA: u8 = 0;
const CHUNK_TYPE_INIT: u8 = 1;
const CHUNK_TYPE_INIT_ACK: u8 = 2;
const CHUNK_TYPE_SACK: u8 = 3;
const CHUNK_TYPE_HEARTBEAT: u8 = 4;
const CHUNK_TYPE_HEARTBEAT_ACK: u8 = 5;
const CHUNK_TYPE_ABORT: u8 = 6;
const CHUNK_TYPE_SHUTDOWN: u8 = 7;
const CHUNK_TYPE_ERROR: u8 = 9;
const CHUNK_TYPE_SHUTDOWN_COMPLETE: u8 = 14;
/// RFC 8260, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc8260#section-2.1>
const CHUNK_TYPE_I_DATA: u8 = 64;

/// DATA chunk header size: Type(1) + Flags(1) + Length(2) + TSN(4) +
/// Stream Identifier(2) + Stream Sequence Number(2) + Payload Protocol Identifier(4) = 16 bytes.
/// RFC 9260, Section 3.3.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1>
const DATA_CHUNK_HEADER_SIZE: usize = 16;

/// I-DATA chunk header size.
/// RFC 8260, Section 2.1 — "The length of the I-DATA chunk header is 20
/// bytes" — <https://www.rfc-editor.org/rfc/rfc8260#section-2.1>
const I_DATA_CHUNK_HEADER_SIZE: usize = 20;

/// INIT / INIT ACK chunk size up to the parameters: chunk header(4) +
/// Initiate Tag(4) + a_rwnd(4) + Outbound Streams(2) + Inbound Streams(2) +
/// Initial TSN(4) = 20 bytes.
/// RFC 9260, Sections 3.3.2 and 3.3.3 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.2>
const INIT_CHUNK_FIXED_SIZE: usize = 20;

/// SACK chunk size up to the Gap Ack Blocks: chunk header(4) + Cumulative
/// TSN Ack(4) + a_rwnd(4) + Number of Gap Ack Blocks(2) + Number of
/// Duplicate TSNs(2) = 16 bytes.
/// RFC 9260, Section 3.3.4 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.4>
const SACK_CHUNK_FIXED_SIZE: usize = 16;

/// SHUTDOWN chunk size: chunk header(4) + Cumulative TSN Ack(4).
/// RFC 9260, Section 3.3.8 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.8>
const SHUTDOWN_CHUNK_SIZE: usize = 8;

/// Parameter / error cause TLV header size (type or code + length).
/// RFC 9260, Sections 3.2.1 and 3.3.10 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.2.1>
const TLV_HEADER_SIZE: usize = 4;

/// DATA / I-DATA chunk flag bits `|  Res  |I|U|B|E|`.
/// RFC 9260, Section 3.3.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1>
/// RFC 8260, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc8260#section-2.1>
const DATA_FLAG_I: u8 = 0x08;
const DATA_FLAG_U: u8 = 0x04;
const DATA_FLAG_B: u8 = 0x02;
const DATA_FLAG_E: u8 = 0x01;

/// ABORT / SHUTDOWN COMPLETE T bit.
/// RFC 9260, Sections 3.3.7 and 3.3.13 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.7>
const FLAG_T: u8 = 0x01;

/// Parameter types decoded into typed fields.
/// RFC 9260, Sections 3.3.2.1, 3.3.3.1, 3.3.5 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.2.1>
const PARAM_HEARTBEAT_INFO: u16 = 1;
const PARAM_IPV4_ADDRESS: u16 = 5;
const PARAM_IPV6_ADDRESS: u16 = 6;
const PARAM_STATE_COOKIE: u16 = 7;
const PARAM_COOKIE_PRESERVATIVE: u16 = 9;
const PARAM_HOST_NAME_ADDRESS: u16 = 11;
const PARAM_SUPPORTED_ADDRESS_TYPES: u16 = 12;

/// Returns a human-readable name for SCTP chunk type values.
///
/// RFC 9260, Section 3.2 — Chunk Types table, extended by the IANA "Chunk
/// Types" registry (<https://www.iana.org/assignments/sctp-parameters/>).
/// Types 12 (ECNE) and 13 (CWR) are listed as "Reserved for Explicit
/// Congestion Notification Echo" and "Reserved for Congestion Window
/// Reduced" in the same table.
fn sctp_chunk_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("DATA"),
        1 => Some("INIT"),
        2 => Some("INIT_ACK"),
        3 => Some("SACK"),
        4 => Some("HEARTBEAT"),
        5 => Some("HEARTBEAT_ACK"),
        6 => Some("ABORT"),
        7 => Some("SHUTDOWN"),
        8 => Some("SHUTDOWN_ACK"),
        9 => Some("ERROR"),
        10 => Some("COOKIE_ECHO"),
        11 => Some("COOKIE_ACK"),
        12 => Some("ECNE"),
        13 => Some("CWR"),
        14 => Some("SHUTDOWN_COMPLETE"),
        // RFC 4895, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc4895#section-4.1>
        15 => Some("AUTH"),
        // RFC 8260, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc8260#section-2.1>
        64 => Some("I_DATA"),
        // RFC 5061, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc5061#section-4.1>
        128 => Some("ASCONF_ACK"),
        // RFC 6525, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc6525#section-3.1>
        130 => Some("RE_CONFIG"),
        // RFC 4820, Section 3 — <https://www.rfc-editor.org/rfc/rfc4820#section-3>
        132 => Some("PAD"),
        // RFC 3758, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc3758#section-3.2>
        192 => Some("FORWARD_TSN"),
        // RFC 5061, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc5061#section-4.1>
        193 => Some("ASCONF"),
        // RFC 8260, Section 2.3.1 — <https://www.rfc-editor.org/rfc/rfc8260#section-2.3.1>
        194 => Some("I_FORWARD_TSN"),
        _ => None,
    }
}

/// Returns a name for a chunk parameter type.
///
/// IANA "Chunk Parameter Types" registry —
/// <https://www.iana.org/assignments/sctp-parameters/>.
fn sctp_parameter_type_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("Heartbeat Info"),
        5 => Some("IPv4 Address"),
        6 => Some("IPv6 Address"),
        7 => Some("State Cookie"),
        8 => Some("Unrecognized Parameter"),
        9 => Some("Cookie Preservative"),
        11 => Some("Host Name Address"),
        12 => Some("Supported Address Types"),
        13 => Some("Outgoing SSN Reset Request"),
        14 => Some("Incoming SSN Reset Request"),
        15 => Some("SSN/TSN Reset Request"),
        16 => Some("Re-configuration Response"),
        17 => Some("Add Outgoing Streams Request"),
        18 => Some("Add Incoming Streams Request"),
        0x8000 => Some("Reserved for ECN Capable"),
        0x8001 => Some("Zero Checksum Acceptable"),
        0x8002 => Some("Random"),
        0x8003 => Some("Chunk List"),
        0x8004 => Some("Requested HMAC Algorithm"),
        0x8005 => Some("Padding"),
        0x8008 => Some("Supported Extensions"),
        0xC000 => Some("Forward TSN Supported"),
        0xC001 => Some("Add IP Address"),
        0xC002 => Some("Delete IP Address"),
        0xC003 => Some("Error Cause Indication"),
        0xC004 => Some("Set Primary Address"),
        0xC005 => Some("Success Indication"),
        0xC006 => Some("Adaptation Layer Indication"),
        _ => None,
    }
}

/// Returns a name for an error cause code.
///
/// RFC 9260, Sections 3.3.10.1–3.3.10.13
/// (<https://www.rfc-editor.org/rfc/rfc9260#section-3.3.10>) and the IANA
/// "Error Cause Codes" registry
/// (<https://www.iana.org/assignments/sctp-parameters/>).
fn sctp_cause_code_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("Invalid Stream Identifier"),
        2 => Some("Missing Mandatory Parameter"),
        3 => Some("Stale Cookie"),
        4 => Some("Out of Resource"),
        5 => Some("Unresolvable Address"),
        6 => Some("Unrecognized Chunk Type"),
        7 => Some("Invalid Mandatory Parameter"),
        8 => Some("Unrecognized Parameters"),
        9 => Some("No User Data"),
        10 => Some("Cookie Received While Shutting Down"),
        11 => Some("Restart of an Association with New Addresses"),
        12 => Some("User-Initiated Abort"),
        13 => Some("Protocol Violation"),
        160 => Some("Request to Delete Last Remaining IP Address"),
        161 => Some("Operation Refused Due to Resource Shortage"),
        162 => Some("Request to Delete Source IP Address"),
        163 => Some("Association Aborted due to illegal ASCONF-ACK"),
        164 => Some("Request refused - no authorization"),
        261 => Some("Unsupported HMAC Identifier"),
        _ => None,
    }
}

/// Returns a name for a Payload Protocol Identifier.
///
/// IANA "SCTP Payload Protocol Identifiers" registry
/// (<https://www.iana.org/assignments/sctp-parameters/>, last updated
/// 2026-08-13). PPID 0 is "Reserved by SCTP" (unspecified) and has no name.
fn sctp_ppid_name(v: u32) -> Option<&'static str> {
    match v {
        1 => Some("IUA"),
        2 => Some("M2UA"),
        3 => Some("M3UA"),
        4 => Some("SUA"),
        5 => Some("M2PA"),
        6 => Some("V5UA"),
        7 => Some("H.248"),
        8 => Some("BICC/Q.2150.3"),
        9 => Some("TALI"),
        10 => Some("DUA"),
        11 => Some("ASAP"),
        12 => Some("ENRP"),
        13 => Some("H.323"),
        14 => Some("Q.IPC/Q.2150.3"),
        15 => Some("SIMCO"),
        16 => Some("DDP Segment Chunk"),
        17 => Some("DDP Stream Session Control"),
        18 => Some("S1AP"),
        19 => Some("RUA"),
        20 => Some("HNBAP"),
        21 => Some("ForCES-HP"),
        22 => Some("ForCES-MP"),
        23 => Some("ForCES-LP"),
        24 => Some("SBc-AP"),
        25 => Some("NBAP"),
        27 => Some("X2AP"),
        28 => Some("IRCP"),
        29 => Some("LCS-AP"),
        30 => Some("MPICH2"),
        31 => Some("SABP"),
        32 => Some("FGP"),
        33 => Some("PPP"),
        34 => Some("CALCAPP"),
        35 => Some("SSP"),
        36 => Some("NPMP-CONTROL"),
        37 => Some("NPMP-DATA"),
        38 => Some("ECHO"),
        39 => Some("DISCARD"),
        40 => Some("DAYTIME"),
        41 => Some("CHARGEN"),
        42 => Some("3GPP RNA"),
        43 => Some("3GPP M2AP"),
        44 => Some("3GPP M3AP"),
        45 => Some("SSH over SCTP"),
        46 => Some("Diameter"),
        47 => Some("Diameter over DTLS"),
        48 => Some("R14P"),
        49 => Some("GDT"),
        50 => Some("WebRTC DCEP"),
        51 => Some("WebRTC String"),
        52 => Some("WebRTC Binary Partial"),
        53 => Some("WebRTC Binary"),
        54 => Some("WebRTC String Partial"),
        55 => Some("3GPP PUA"),
        56 => Some("WebRTC String Empty"),
        57 => Some("WebRTC Binary Empty"),
        58 => Some("3GPP XwAP"),
        59 => Some("3GPP Xw-Control Plane"),
        60 => Some("NGAP"),
        61 => Some("XnAP"),
        62 => Some("F1AP"),
        63 => Some("HTTP/SCTP"),
        64 => Some("E1AP"),
        65 => Some("ELE2 Lawful Interception"),
        66 => Some("NGAP over DTLS"),
        67 => Some("XnAP over DTLS"),
        68 => Some("F1AP over DTLS"),
        69 => Some("E1AP over DTLS"),
        70 => Some("E2-CP"),
        71 => Some("O-RAN D2"),
        72 => Some("E2-DU"),
        73 => Some("W1AP"),
        4242 => Some("DTLS Chunk Key-Management"),
        _ => None,
    }
}

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_SRC_PORT: usize = 0;
const FD_DST_PORT: usize = 1;
const FD_VERIFICATION_TAG: usize = 2;
const FD_CHECKSUM: usize = 3;
const FD_CHUNKS: usize = 4;
const FD_CHECKSUM_STATUS: usize = 5;

/// Child field descriptor indices for [`CHUNK_CHILD_FIELDS`].
const CFD_TYPE: usize = 0;
const CFD_FLAGS: usize = 1;
const CFD_LENGTH: usize = 2;
const CFD_VALUE: usize = 3;
const CFD_UNDECODED: usize = 4;
const CFD_I: usize = 5;
const CFD_U: usize = 6;
const CFD_B: usize = 7;
const CFD_E: usize = 8;
const CFD_TSN: usize = 9;
const CFD_STREAM_ID: usize = 10;
const CFD_SSN: usize = 11;
const CFD_PPID: usize = 12;
const CFD_USER_DATA: usize = 13;
const CFD_T: usize = 14;
const CFD_MID: usize = 15;
const CFD_FSN: usize = 16;
const CFD_INITIATE_TAG: usize = 17;
const CFD_A_RWND: usize = 18;
const CFD_OUTBOUND_STREAMS: usize = 19;
const CFD_INBOUND_STREAMS: usize = 20;
const CFD_INITIAL_TSN: usize = 21;
const CFD_PARAMETERS: usize = 22;
const CFD_CUMULATIVE_TSN_ACK: usize = 23;
const CFD_NUM_GAP_ACK_BLOCKS: usize = 24;
const CFD_NUM_DUP_TSNS: usize = 25;
const CFD_GAP_ACK_BLOCKS: usize = 26;
const CFD_DUPLICATE_TSNS: usize = 27;
const CFD_ERROR_CAUSES: usize = 28;

/// Child field descriptor indices for [`PARAMETER_CHILD_FIELDS`].
const PFD_TYPE: usize = 0;
const PFD_LENGTH: usize = 1;
const PFD_VALUE: usize = 2;
const PFD_IPV4_ADDRESS: usize = 3;
const PFD_IPV6_ADDRESS: usize = 4;
const PFD_COOKIE_LIFE_SPAN_INCREMENT: usize = 5;
const PFD_HOST_NAME: usize = 6;
const PFD_ADDRESS_TYPES: usize = 7;
const PFD_STATE_COOKIE: usize = 8;
const PFD_HEARTBEAT_INFO: usize = 9;

/// Child field descriptor indices for [`ERROR_CAUSE_CHILD_FIELDS`].
const EFD_CODE: usize = 0;
const EFD_LENGTH: usize = 1;
const EFD_VALUE: usize = 2;

/// Child field descriptor indices for [`GAP_ACK_BLOCK_CHILD_FIELDS`].
const GFD_START: usize = 0;
const GFD_END: usize = 1;

/// Container descriptor for a chunk Object.
///
/// The outer label resolves to the chunk name (e.g. `INIT`) by looking up
/// the inner `type` field, avoiding collision with the inner "Chunk Type"
/// label.
static FD_CHUNK: FieldDescriptor = FieldDescriptor {
    name: "chunk",
    display_name: "Chunk",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => sctp_chunk_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Container descriptor for a parameter Object.
///
/// RFC 9260, Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.2.1>
static FD_PARAMETER: FieldDescriptor = FieldDescriptor {
    name: "parameter",
    display_name: "Parameter",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U16(t)) => sctp_parameter_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Container descriptor for an error cause Object.
///
/// RFC 9260, Section 3.3.10 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.10>
static FD_ERROR_CAUSE: FieldDescriptor = FieldDescriptor {
    name: "error_cause",
    display_name: "Error Cause",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("code", FieldValue::U16(c)) => sctp_cause_code_name(*c),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Container descriptor for a Gap Ack Block Object.
///
/// RFC 9260, Section 3.3.4 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.4>
static FD_GAP_ACK_BLOCK: FieldDescriptor =
    FieldDescriptor::new("gap_ack_block", "Gap Ack Block", FieldType::Object);

/// Element descriptor for the `address_types` array.
static FD_ADDRESS_TYPE: FieldDescriptor =
    FieldDescriptor::new("address_type", "Address Type", FieldType::U16);

/// Element descriptor for the `duplicate_tsns` array.
static FD_DUPLICATE_TSN: FieldDescriptor =
    FieldDescriptor::new("duplicate_tsn", "Duplicate TSN", FieldType::U32);

/// Child field descriptors for parameter entries within `parameters`.
/// RFC 9260, Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.2.1>
static PARAMETER_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Parameter Type",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(t) => sctp_parameter_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Parameter Length", FieldType::U16),
    FieldDescriptor::new("value", "Parameter Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("ipv4_address", "IPv4 Address", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("ipv6_address", "IPv6 Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new(
        "cookie_life_span_increment",
        "Suggested Cookie Life-Span Increment",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("host_name", "Host Name", FieldType::Str).optional(),
    FieldDescriptor::new("address_types", "Supported Address Types", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_ADDRESS_TYPE)),
    FieldDescriptor::new("state_cookie", "State Cookie", FieldType::Bytes).optional(),
    FieldDescriptor::new("heartbeat_info", "Heartbeat Information", FieldType::Bytes).optional(),
];

/// Child field descriptors for error cause entries within `error_causes`.
/// RFC 9260, Section 3.3.10 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.10>
static ERROR_CAUSE_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "code",
        display_name: "Cause Code",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(c) => sctp_cause_code_name(*c),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Cause Length", FieldType::U16),
    FieldDescriptor::new("value", "Cause-Specific Information", FieldType::Bytes).optional(),
];

/// Child field descriptors for Gap Ack Block entries.
/// RFC 9260, Section 3.3.4 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.4>
static GAP_ACK_BLOCK_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("start", "Gap Ack Block Start", FieldType::U16),
    FieldDescriptor::new("end", "Gap Ack Block End", FieldType::U16),
];

/// Child field descriptors for SCTP chunk entries within the `chunks` array.
///
/// `type`, `flags` and `length` are present for every chunk; the others
/// depend on the chunk type.
static CHUNK_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Chunk Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => sctp_chunk_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("flags", "Chunk Flags", FieldType::U8),
    FieldDescriptor::new("length", "Chunk Length", FieldType::U16),
    FieldDescriptor::new("value", "Chunk Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("undecoded", "Undecoded Data", FieldType::Bytes).optional(),
    // RFC 9260, Section 3.3.1 — DATA chunk fields — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1
    FieldDescriptor::new("i", "I (Immediate)", FieldType::U8).optional(),
    FieldDescriptor::new("u", "U (Unordered)", FieldType::U8).optional(),
    FieldDescriptor::new("b", "B (Beginning Fragment)", FieldType::U8).optional(),
    FieldDescriptor::new("e", "E (Ending Fragment)", FieldType::U8).optional(),
    FieldDescriptor::new("tsn", "TSN", FieldType::U32).optional(),
    FieldDescriptor::new("stream_id", "Stream Identifier", FieldType::U16).optional(),
    FieldDescriptor::new("ssn", "Stream Sequence Number", FieldType::U16).optional(),
    FieldDescriptor {
        name: "ppid",
        display_name: "Payload Protocol Identifier",
        field_type: FieldType::U32,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U32(p) => sctp_ppid_name(*p),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("user_data", "User Data", FieldType::Bytes).optional(),
    // RFC 9260, Sections 3.3.7 and 3.3.13 — T bit — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.7
    FieldDescriptor::new("t", "T (TCB Destroyed)", FieldType::U8).optional(),
    // RFC 8260, Section 2.1 — I-DATA fields — https://www.rfc-editor.org/rfc/rfc8260#section-2.1
    FieldDescriptor::new("mid", "Message Identifier", FieldType::U32).optional(),
    FieldDescriptor::new("fsn", "Fragment Sequence Number", FieldType::U32).optional(),
    // RFC 9260, Sections 3.3.2 and 3.3.3 — INIT / INIT ACK fixed fields — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.2
    FieldDescriptor::new("initiate_tag", "Initiate Tag", FieldType::U32).optional(),
    FieldDescriptor::new(
        "a_rwnd",
        "Advertised Receiver Window Credit",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new(
        "outbound_streams",
        "Number of Outbound Streams",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "inbound_streams",
        "Number of Inbound Streams",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("initial_tsn", "Initial TSN", FieldType::U32).optional(),
    FieldDescriptor::new("parameters", "Parameters", FieldType::Array)
        .optional()
        .with_children(PARAMETER_CHILD_FIELDS),
    // RFC 9260, Sections 3.3.4 and 3.3.8 — SACK / SHUTDOWN — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.4
    FieldDescriptor::new("cumulative_tsn_ack", "Cumulative TSN Ack", FieldType::U32).optional(),
    FieldDescriptor::new(
        "num_gap_ack_blocks",
        "Number of Gap Ack Blocks",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("num_dup_tsns", "Number of Duplicate TSNs", FieldType::U16).optional(),
    FieldDescriptor::new("gap_ack_blocks", "Gap Ack Blocks", FieldType::Array)
        .optional()
        .with_children(GAP_ACK_BLOCK_CHILD_FIELDS),
    FieldDescriptor::new("duplicate_tsns", "Duplicate TSNs", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_DUPLICATE_TSN)),
    // RFC 9260, Sections 3.3.7 and 3.3.10 — ABORT / ERROR — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.10
    FieldDescriptor::new("error_causes", "Error Causes", FieldType::Array)
        .optional()
        .with_children(ERROR_CAUSE_CHILD_FIELDS),
];

/// Common header fields plus a `chunks` Array field whose child descriptors
/// describe each chunk's sub-fields.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("src_port", "Source Port", FieldType::U16),
    FieldDescriptor::new("dst_port", "Destination Port", FieldType::U16),
    FieldDescriptor::new("verification_tag", "Verification Tag", FieldType::U32),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U32),
    FieldDescriptor::new("chunks", "Chunks", FieldType::Array)
        .optional()
        .with_children(CHUNK_CHILD_FIELDS),
    checksum_status_descriptor("checksum_status", "Checksum Status"),
];

/// Verify the CRC32c checksum of the SCTP packet `data` at `offset`.
///
/// RFC 9260, Section 6.8 — the receiver MUST "Replace the 32 bits of the
/// checksum field in the received SCTP packet with 0 and calculate a CRC32c
/// checksum value of the whole received packet"; the value is transmitted
/// least significant byte first (Appendix A). The packet is the whole IP
/// payload, so a snaplen-cut capture or a fragment is `unverified`.
/// <https://www.rfc-editor.org/rfc/rfc9260#section-6.8>
///
/// RFC 9653, Section 5.3 — with an alternate error detection method a
/// packet may carry "an incorrect checksum value of zero", reported as
/// `not_present`.
/// <https://www.rfc-editor.org/rfc/rfc9653#section-5.3>
fn checksum_status(buf: &DissectBuffer<'_>, offset: usize, data: &[u8]) -> ChecksumStatus {
    let Some(packet) = ip_payload(buf, offset, data) else {
        return ChecksumStatus::Unverified;
    };
    let Some(received) = packet.get(8..COMMON_HEADER_SIZE) else {
        return ChecksumStatus::Unverified;
    };
    let crc = crc32c(&[&packet[..8], &[0; 4], &packet[COMMON_HEADER_SIZE..]]);
    if crc.to_le_bytes() == received {
        ChecksumStatus::Good
    } else if received == [0; 4] {
        ChecksumStatus::NotPresent
    } else {
        ChecksumStatus::Bad
    }
}

/// Specification references for the SCTP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 9260",
        "Stream Control Transmission Protocol",
        "https://www.rfc-editor.org/rfc/rfc9260",
    ),
    SpecReference::new(
        "RFC 8260",
        "Stream Schedulers and User Message Interleaving for the Stream Control Transmission Protocol",
        "https://www.rfc-editor.org/rfc/rfc8260",
    ),
];

/// SCTP dissector.
pub struct SctpDissector;

impl Dissector for SctpDissector {
    fn name(&self) -> &'static str {
        "Stream Control Transmission Protocol"
    }

    fn short_name(&self) -> &'static str {
        "SCTP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Transport)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < COMMON_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: COMMON_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 9260, Section 3.1 — SCTP Common Header Field Descriptions
        let src_port = read_be_u16(data, 0)?;
        let dst_port = read_be_u16(data, 2)?;
        let verification_tag = read_be_u32(data, 4)?;
        let checksum = read_be_u32(data, 8)?;

        // RFC 9260, Section 3.1 — Port number 0 MUST NOT be used.
        if src_port == 0 {
            return Err(PacketError::InvalidFieldValue {
                field: "src_port",
                value: 0,
            });
        }
        if dst_port == 0 {
            return Err(PacketError::InvalidFieldValue {
                field: "dst_port",
                value: 0,
            });
        }

        let total_consumed = data.len();
        let payloads_base = buf.embedded_payloads().len();
        let ports = (src_port, dst_port);

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_consumed,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SRC_PORT],
            FieldValue::U16(src_port),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DST_PORT],
            FieldValue::U16(dst_port),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERIFICATION_TAG],
            FieldValue::U32(verification_tag),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM],
            FieldValue::U32(checksum),
            offset + 8..offset + 12,
        );
        if buf.verify_checksums() {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_CHECKSUM_STATUS],
                checksum_status(buf, offset, data).to_field_value(),
                offset + 8..offset + 12,
            );
        }

        // RFC 9260, Section 3.2 — Parse chunks
        let mut pos = COMMON_HEADER_SIZE;
        let mut has_chunks = false;
        let mut array_idx = 0u32;

        while pos + MIN_CHUNK_SIZE <= data.len() {
            let chunk_type = data[pos];
            let chunk_flags = data[pos + 1];
            // RFC 9260, Section 3.2 — Chunk Length includes the 4-byte chunk header
            let chunk_length = read_be_u16(data, pos + 2)? as usize;

            if chunk_length < MIN_CHUNK_SIZE {
                return Err(PacketError::InvalidFieldValue {
                    field: "chunk_length",
                    value: chunk_length as u32,
                });
            }

            if pos + chunk_length > data.len() {
                return Err(PacketError::Truncated {
                    expected: pos + chunk_length,
                    actual: data.len(),
                });
            }

            if !has_chunks {
                has_chunks = true;
                array_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_CHUNKS],
                    FieldValue::Array(0..0),
                    offset + COMMON_HEADER_SIZE..offset + total_consumed,
                );
            }

            let obj_idx = buf.begin_container(
                &FD_CHUNK,
                FieldValue::Object(0..0),
                offset + pos..offset + pos + chunk_length,
            );

            buf.push_field(
                &CHUNK_CHILD_FIELDS[CFD_TYPE],
                FieldValue::U8(chunk_type),
                offset + pos..offset + pos + 1,
            );
            buf.push_field(
                &CHUNK_CHILD_FIELDS[CFD_FLAGS],
                FieldValue::U8(chunk_flags),
                offset + pos + 1..offset + pos + 2,
            );
            buf.push_field(
                &CHUNK_CHILD_FIELDS[CFD_LENGTH],
                FieldValue::U16(chunk_length as u16),
                offset + pos + 2..offset + pos + 4,
            );

            // A chunk whose body is not decoded at all keeps it as `value`;
            // bytes left over after decoded fields become `undecoded`.
            let chunk = &data[pos..pos + chunk_length];
            let decoded_end =
                push_chunk_body(buf, chunk, offset + pos, ports)?.unwrap_or(MIN_CHUNK_SIZE);
            if decoded_end < chunk_length {
                let fd = if decoded_end == MIN_CHUNK_SIZE {
                    CFD_VALUE
                } else {
                    CFD_UNDECODED
                };
                buf.push_field(
                    &CHUNK_CHILD_FIELDS[fd],
                    FieldValue::Bytes(&chunk[decoded_end..]),
                    offset + pos + decoded_end..offset + pos + chunk_length,
                );
            }

            buf.end_container(obj_idx);

            // RFC 9260, Section 3.2 — Chunks are padded to 4-byte boundaries.
            // The padding is NOT included in the Chunk Length field.
            let padded_length = (chunk_length + 3) & !3;
            pos += padded_length;
        }

        if has_chunks {
            buf.end_container(array_idx);
        }

        buf.end_layer();

        // The layer's own hint names the upper protocol of its first user
        // message (used by summaries); without one, fall back to the ports.
        let next = buf
            .embedded_payloads()
            .get(payloads_base)
            .map(|p| p.next.clone())
            .unwrap_or(DispatchHint::BySctpPort(src_port, dst_port));
        Ok(DissectResult::new(total_consumed, next))
    }
}

/// Push the type-specific fields of one chunk.
///
/// `chunk` spans the chunk from its Type byte to the end of its value
/// (excluding padding) and `abs` is its absolute offset in the packet. Type,
/// Flags and Length have already been pushed. Returns the offset within
/// `chunk` up to which the body was decoded, or `None` when the chunk type
/// has no decoder or the chunk is too short for its fixed fields.
fn push_chunk_body<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    chunk: &'pkt [u8],
    abs: usize,
    ports: (u16, u16),
) -> Result<Option<usize>, PacketError> {
    let flags = chunk[1];
    let end = match chunk[0] {
        CHUNK_TYPE_DATA if chunk.len() >= DATA_CHUNK_HEADER_SIZE => {
            push_data_chunk_fields(buf, chunk, abs, ports)?;
            chunk.len()
        }
        CHUNK_TYPE_I_DATA if chunk.len() >= I_DATA_CHUNK_HEADER_SIZE => {
            push_i_data_chunk_fields(buf, chunk, abs, ports)?;
            chunk.len()
        }
        CHUNK_TYPE_INIT | CHUNK_TYPE_INIT_ACK if chunk.len() >= INIT_CHUNK_FIXED_SIZE => {
            // RFC 9260, Sections 3.3.2 and 3.3.3 —
            // https://www.rfc-editor.org/rfc/rfc9260#section-3.3.2
            push_u32(buf, CFD_INITIATE_TAG, chunk, 4, abs)?;
            push_u32(buf, CFD_A_RWND, chunk, 8, abs)?;
            push_u16(buf, CFD_OUTBOUND_STREAMS, chunk, 12, abs)?;
            push_u16(buf, CFD_INBOUND_STREAMS, chunk, 14, abs)?;
            push_u32(buf, CFD_INITIAL_TSN, chunk, 16, abs)?;
            push_parameters(buf, chunk, INIT_CHUNK_FIXED_SIZE, abs)?
        }
        CHUNK_TYPE_SACK if chunk.len() >= SACK_CHUNK_FIXED_SIZE => {
            push_sack_fields(buf, chunk, abs)?
        }
        CHUNK_TYPE_HEARTBEAT | CHUNK_TYPE_HEARTBEAT_ACK => {
            // RFC 9260, Sections 3.3.5 and 3.3.6 — Heartbeat Info TLV —
            // https://www.rfc-editor.org/rfc/rfc9260#section-3.3.5
            push_parameters(buf, chunk, MIN_CHUNK_SIZE, abs)?
        }
        CHUNK_TYPE_ABORT => {
            // RFC 9260, Section 3.3.7 — T bit and zero or more error causes —
            // https://www.rfc-editor.org/rfc/rfc9260#section-3.3.7
            push_t_bit(buf, flags, abs);
            push_error_causes(buf, chunk, abs)?
        }
        CHUNK_TYPE_SHUTDOWN if chunk.len() >= SHUTDOWN_CHUNK_SIZE => {
            // RFC 9260, Section 3.3.8 —
            // https://www.rfc-editor.org/rfc/rfc9260#section-3.3.8
            push_u32(buf, CFD_CUMULATIVE_TSN_ACK, chunk, 4, abs)?;
            SHUTDOWN_CHUNK_SIZE
        }
        CHUNK_TYPE_ERROR => {
            // RFC 9260, Section 3.3.10 — one or more error causes —
            // https://www.rfc-editor.org/rfc/rfc9260#section-3.3.10
            push_error_causes(buf, chunk, abs)?
        }
        CHUNK_TYPE_SHUTDOWN_COMPLETE => {
            // RFC 9260, Section 3.3.13 —
            // https://www.rfc-editor.org/rfc/rfc9260#section-3.3.13
            push_t_bit(buf, flags, abs);
            MIN_CHUNK_SIZE
        }
        _ => return Ok(None),
    };
    Ok(Some(end))
}

/// Push a big-endian `u16` chunk field read at `at` within `chunk`.
fn push_u16(
    buf: &mut DissectBuffer<'_>,
    fd: usize,
    chunk: &[u8],
    at: usize,
    abs: usize,
) -> Result<u16, PacketError> {
    let v = read_be_u16(chunk, at)?;
    buf.push_field(
        &CHUNK_CHILD_FIELDS[fd],
        FieldValue::U16(v),
        abs + at..abs + at + 2,
    );
    Ok(v)
}

/// Push a big-endian `u32` chunk field read at `at` within `chunk`.
fn push_u32(
    buf: &mut DissectBuffer<'_>,
    fd: usize,
    chunk: &[u8],
    at: usize,
    abs: usize,
) -> Result<u32, PacketError> {
    let v = read_be_u32(chunk, at)?;
    buf.push_field(
        &CHUNK_CHILD_FIELDS[fd],
        FieldValue::U32(v),
        abs + at..abs + at + 4,
    );
    Ok(v)
}

/// Push the T bit of an ABORT or SHUTDOWN COMPLETE chunk.
fn push_t_bit(buf: &mut DissectBuffer<'_>, flags: u8, abs: usize) {
    buf.push_field(
        &CHUNK_CHILD_FIELDS[CFD_T],
        FieldValue::U8(u8::from(flags & FLAG_T != 0)),
        abs + 1..abs + 2,
    );
}

/// Push the I, U, B and E bits shared by DATA and I-DATA chunks.
fn push_data_flag_bits(buf: &mut DissectBuffer<'_>, flags: u8, abs: usize) {
    for (fd, mask) in [
        (CFD_I, DATA_FLAG_I),
        (CFD_U, DATA_FLAG_U),
        (CFD_B, DATA_FLAG_B),
        (CFD_E, DATA_FLAG_E),
    ] {
        buf.push_field(
            &CHUNK_CHILD_FIELDS[fd],
            FieldValue::U8(u8::from(flags & mask != 0)),
            abs + 1..abs + 2,
        );
    }
}

/// Push the user data of a DATA / I-DATA chunk starting at `header_len` and
/// record it for dispatch when it is a whole user message.
///
/// RFC 9260, Section 3.3.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1>
fn push_user_data<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    chunk: &'pkt [u8],
    header_len: usize,
    abs: usize,
    ppid: Option<u32>,
    ports: (u16, u16),
) {
    let user_data = &chunk[header_len..];
    // RFC 9260, Section 3.3.1 — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1
    // "L MUST be greater than 0". An empty User Data field is shown by its
    // absence and is not dispatched.
    if user_data.is_empty() {
        return;
    }
    let user_data_range = abs + header_len..abs + chunk.len();
    buf.push_field(
        &CHUNK_CHILD_FIELDS[CFD_USER_DATA],
        FieldValue::Bytes(user_data),
        user_data_range.clone(),
    );

    // RFC 9260, Section 3.3.1 — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1
    // "An unfragmented user message MUST have both the B and E bits set to
    // 1." Any other combination is one fragment of a user message that is
    // only complete after reassembly (Section 6.9 —
    // https://www.rfc-editor.org/rfc/rfc9260#section-6.9), so it is not
    // handed to the upper layer on its own.
    let unfragmented = DATA_FLAG_B | DATA_FLAG_E;
    if let (true, Some(ppid)) = (chunk[1] & unfragmented == unfragmented, ppid) {
        buf.push_embedded_payload(
            user_data_range,
            DispatchHint::BySctpPpid {
                ppid,
                src_port: ports.0,
                dst_port: ports.1,
            },
        );
    }
}

/// Push the fields of a DATA chunk and record its user data for dispatch.
///
/// `chunk` is at least [`DATA_CHUNK_HEADER_SIZE`] bytes long.
///
/// RFC 9260, Section 3.3.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1>
fn push_data_chunk_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    chunk: &'pkt [u8],
    abs: usize,
    ports: (u16, u16),
) -> Result<(), PacketError> {
    push_data_flag_bits(buf, chunk[1], abs);
    push_u32(buf, CFD_TSN, chunk, 4, abs)?;
    push_u16(buf, CFD_STREAM_ID, chunk, 8, abs)?;
    push_u16(buf, CFD_SSN, chunk, 10, abs)?;
    let ppid = push_u32(buf, CFD_PPID, chunk, 12, abs)?;
    push_user_data(buf, chunk, DATA_CHUNK_HEADER_SIZE, abs, Some(ppid), ports);
    Ok(())
}

/// Push the fields of an I-DATA chunk and record its user data for dispatch.
///
/// `chunk` is at least [`I_DATA_CHUNK_HEADER_SIZE`] bytes long.
///
/// RFC 8260, Section 2.1 — "If the B bit is set, this field contains the
/// PPID of the user message. [...] If the B bit is not set, this field
/// contains the FSN." — <https://www.rfc-editor.org/rfc/rfc8260#section-2.1>
fn push_i_data_chunk_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    chunk: &'pkt [u8],
    abs: usize,
    ports: (u16, u16),
) -> Result<(), PacketError> {
    let flags = chunk[1];
    push_data_flag_bits(buf, flags, abs);
    push_u32(buf, CFD_TSN, chunk, 4, abs)?;
    push_u16(buf, CFD_STREAM_ID, chunk, 8, abs)?;
    push_u32(buf, CFD_MID, chunk, 12, abs)?;
    let ppid = if flags & DATA_FLAG_B != 0 {
        Some(push_u32(buf, CFD_PPID, chunk, 16, abs)?)
    } else {
        push_u32(buf, CFD_FSN, chunk, 16, abs)?;
        None
    };
    push_user_data(buf, chunk, I_DATA_CHUNK_HEADER_SIZE, abs, ppid, ports);
    Ok(())
}

/// Push the fields of a SACK chunk.
///
/// `chunk` is at least [`SACK_CHUNK_FIXED_SIZE`] bytes long. Gap Ack Blocks
/// and Duplicate TSNs are decoded up to the counts in the header or the end
/// of the chunk, whichever comes first. Returns the offset within `chunk`
/// after the last decoded entry.
///
/// RFC 9260, Section 3.3.4 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.4>
fn push_sack_fields(
    buf: &mut DissectBuffer<'_>,
    chunk: &[u8],
    abs: usize,
) -> Result<usize, PacketError> {
    push_u32(buf, CFD_CUMULATIVE_TSN_ACK, chunk, 4, abs)?;
    push_u32(buf, CFD_A_RWND, chunk, 8, abs)?;
    let num_gaps = push_u16(buf, CFD_NUM_GAP_ACK_BLOCKS, chunk, 12, abs)? as usize;
    let num_dups = push_u16(buf, CFD_NUM_DUP_TSNS, chunk, 14, abs)? as usize;

    let mut pos = SACK_CHUNK_FIXED_SIZE;
    let gaps = num_gaps.min((chunk.len() - pos) / 4);
    if gaps > 0 {
        let arr = buf.begin_container(
            &CHUNK_CHILD_FIELDS[CFD_GAP_ACK_BLOCKS],
            FieldValue::Array(0..0),
            abs + pos..abs + pos + gaps * 4,
        );
        for _ in 0..gaps {
            let obj = buf.begin_container(
                &FD_GAP_ACK_BLOCK,
                FieldValue::Object(0..0),
                abs + pos..abs + pos + 4,
            );
            buf.push_field(
                &GAP_ACK_BLOCK_CHILD_FIELDS[GFD_START],
                FieldValue::U16(read_be_u16(chunk, pos)?),
                abs + pos..abs + pos + 2,
            );
            buf.push_field(
                &GAP_ACK_BLOCK_CHILD_FIELDS[GFD_END],
                FieldValue::U16(read_be_u16(chunk, pos + 2)?),
                abs + pos + 2..abs + pos + 4,
            );
            buf.end_container(obj);
            pos += 4;
        }
        buf.end_container(arr);
    }

    let dups = num_dups.min((chunk.len() - pos) / 4);
    if dups > 0 {
        let arr = buf.begin_container(
            &CHUNK_CHILD_FIELDS[CFD_DUPLICATE_TSNS],
            FieldValue::Array(0..0),
            abs + pos..abs + pos + dups * 4,
        );
        for _ in 0..dups {
            buf.push_field(
                &FD_DUPLICATE_TSN,
                FieldValue::U32(read_be_u32(chunk, pos)?),
                abs + pos..abs + pos + 4,
            );
            pos += 4;
        }
        buf.end_container(arr);
    }
    Ok(pos)
}

/// Walk the TLVs (parameters or error causes) in `chunk[start..]`.
///
/// Calls `visit(type_or_code, tlv_start, tlv_len)` for each well-formed TLV,
/// where `tlv_len` includes the 4-byte header but not the padding. Stops at
/// the first TLV whose Length is below 4 or runs past the chunk (Postel's
/// Law: the entries before it are kept). The last TLV's padding may be
/// absent. Returns the offset within `chunk` after the last visited TLV and
/// its padding.
///
/// RFC 9260, Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.2.1>
fn for_each_tlv(
    chunk: &[u8],
    start: usize,
    mut visit: impl FnMut(u16, usize, usize) -> Result<(), PacketError>,
) -> Result<usize, PacketError> {
    let mut pos = start;
    while pos + TLV_HEADER_SIZE <= chunk.len() {
        let kind = read_be_u16(chunk, pos)?;
        let len = read_be_u16(chunk, pos + 2)? as usize;
        if len < TLV_HEADER_SIZE || pos + len > chunk.len() {
            break;
        }
        visit(kind, pos, len)?;
        pos = (pos + ((len + 3) & !3)).min(chunk.len());
    }
    Ok(pos)
}

/// Push the TLVs in `chunk[start..]` into an Array container `array_fd`,
/// one Object `item_fd` each, with `push_item` pushing an entry's fields.
///
/// The Array is only created when there is at least one well-formed TLV and
/// covers exactly the TLVs pushed. Returns the offset within `chunk` after
/// the last TLV (`start` when there is none).
fn push_tlv_array<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    chunk: &'pkt [u8],
    start: usize,
    abs: usize,
    array_fd: &'static FieldDescriptor,
    item_fd: &'static FieldDescriptor,
    mut push_item: impl FnMut(&mut DissectBuffer<'pkt>, u16, usize, usize) -> Result<(), PacketError>,
) -> Result<usize, PacketError> {
    let mut array_idx = None;
    let end = for_each_tlv(chunk, start, |kind, at, len| {
        if array_idx.is_none() {
            array_idx = Some(buf.begin_container(
                array_fd,
                FieldValue::Array(0..0),
                abs + start..abs + chunk.len(),
            ));
        }
        let obj = buf.begin_container(item_fd, FieldValue::Object(0..0), abs + at..abs + at + len);
        push_item(buf, kind, at, len)?;
        buf.end_container(obj);
        Ok(())
    })?;
    if let Some(idx) = array_idx {
        buf.end_container(idx);
        if let Some(array) = buf.field_mut(idx as usize) {
            array.range = abs + start..abs + end;
        }
    }
    Ok(end)
}

/// Push the parameter TLVs in `chunk[start..]` as the `parameters` array.
/// Returns the offset within `chunk` after the last parameter.
///
/// RFC 9260, Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.2.1>
fn push_parameters<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    chunk: &'pkt [u8],
    start: usize,
    abs: usize,
) -> Result<usize, PacketError> {
    push_tlv_array(
        buf,
        chunk,
        start,
        abs,
        &CHUNK_CHILD_FIELDS[CFD_PARAMETERS],
        &FD_PARAMETER,
        |buf, ptype, at, len| {
            buf.push_field(
                &PARAMETER_CHILD_FIELDS[PFD_TYPE],
                FieldValue::U16(ptype),
                abs + at..abs + at + 2,
            );
            buf.push_field(
                &PARAMETER_CHILD_FIELDS[PFD_LENGTH],
                FieldValue::U16(len as u16),
                abs + at + 2..abs + at + 4,
            );
            let value = &chunk[at + TLV_HEADER_SIZE..at + len];
            push_parameter_value(buf, ptype, value, abs + at + TLV_HEADER_SIZE)
        },
    )
}

/// Push a parameter's value as a typed field, falling back to raw bytes
/// when the type is not decoded or the value does not have the specified
/// form.
///
/// RFC 9260, Sections 3.3.2.1, 3.3.3.1 and 3.3.5 —
/// <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.2.1>
fn push_parameter_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    ptype: u16,
    value: &'pkt [u8],
    abs: usize,
) -> Result<(), PacketError> {
    let range = abs..abs + value.len();
    let typed = match (ptype, value.len()) {
        (PARAM_IPV4_ADDRESS, 4) => Some((
            PFD_IPV4_ADDRESS,
            FieldValue::Ipv4Addr([value[0], value[1], value[2], value[3]]),
        )),
        (PARAM_IPV6_ADDRESS, 16) => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(value);
            Some((PFD_IPV6_ADDRESS, FieldValue::Ipv6Addr(addr)))
        }
        (PARAM_COOKIE_PRESERVATIVE, 4) => Some((
            PFD_COOKIE_LIFE_SPAN_INCREMENT,
            FieldValue::U32(read_be_u32(value, 0)?),
        )),
        // RFC 9260, Section 3.3.2.1.4 — "At least one null terminator is
        // included in the Host Name string and MUST be included in the
        // length." — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.2.1.4
        (PARAM_HOST_NAME_ADDRESS, _) => {
            let name = value.split(|&b| b == 0).next().unwrap_or(&[]);
            core::str::from_utf8(name)
                .ok()
                .map(|s| (PFD_HOST_NAME, FieldValue::Str(s)))
        }
        (PARAM_STATE_COOKIE, _) => Some((PFD_STATE_COOKIE, FieldValue::Bytes(value))),
        (PARAM_HEARTBEAT_INFO, _) => Some((PFD_HEARTBEAT_INFO, FieldValue::Bytes(value))),
        // RFC 9260, Section 3.3.2.1.5 — a list of 16-bit address types —
        // https://www.rfc-editor.org/rfc/rfc9260#section-3.3.2.1.5
        (PARAM_SUPPORTED_ADDRESS_TYPES, len) if len > 0 && len % 2 == 0 => {
            let arr = buf.begin_container(
                &PARAMETER_CHILD_FIELDS[PFD_ADDRESS_TYPES],
                FieldValue::Array(0..0),
                range,
            );
            for i in (0..len).step_by(2) {
                buf.push_field(
                    &FD_ADDRESS_TYPE,
                    FieldValue::U16(read_be_u16(value, i)?),
                    abs + i..abs + i + 2,
                );
            }
            buf.end_container(arr);
            return Ok(());
        }
        _ => None,
    };
    match typed {
        Some((fd, v)) => buf.push_field(&PARAMETER_CHILD_FIELDS[fd], v, range),
        None if !value.is_empty() => buf.push_field(
            &PARAMETER_CHILD_FIELDS[PFD_VALUE],
            FieldValue::Bytes(value),
            range,
        ),
        None => {}
    }
    Ok(())
}

/// Push the error causes in the body of an ABORT or ERROR chunk as the
/// `error_causes` array. Returns the offset within `chunk` after the last
/// cause.
///
/// RFC 9260, Section 3.3.10 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.10>
fn push_error_causes<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    chunk: &'pkt [u8],
    abs: usize,
) -> Result<usize, PacketError> {
    push_tlv_array(
        buf,
        chunk,
        MIN_CHUNK_SIZE,
        abs,
        &CHUNK_CHILD_FIELDS[CFD_ERROR_CAUSES],
        &FD_ERROR_CAUSE,
        |buf, code, at, len| {
            buf.push_field(
                &ERROR_CAUSE_CHILD_FIELDS[EFD_CODE],
                FieldValue::U16(code),
                abs + at..abs + at + 2,
            );
            buf.push_field(
                &ERROR_CAUSE_CHILD_FIELDS[EFD_LENGTH],
                FieldValue::U16(len as u16),
                abs + at + 2..abs + at + 4,
            );
            if len > TLV_HEADER_SIZE {
                buf.push_field(
                    &ERROR_CAUSE_CHILD_FIELDS[EFD_VALUE],
                    FieldValue::Bytes(&chunk[at + TLV_HEADER_SIZE..at + len]),
                    abs + at + TLV_HEADER_SIZE..abs + at + len,
                );
            }
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::packet::Layer;

    // # RFC 9260 Coverage
    //
    // | RFC Section | Description                                    | Test                                  |
    // |-------------|------------------------------------------------|---------------------------------------|
    // | 3.1         | Common header fields parsed                    | parse_common_header                   |
    // | 3.1         | Source port 0 rejected                         | reject_source_port_zero               |
    // | 3.1         | Destination port 0 rejected                    | reject_destination_port_zero          |
    // | 3.1         | Truncated common header (< 12 bytes)           | truncated_common_header               |
    // | 3.2 / IANA  | Chunk type name resolution                     | chunk_type_names                      |
    // | 3.2         | Unassigned / reserved chunk types return None  | chunk_type_names                      |
    // | 3.2         | Generic chunk (type/flags/length/value)        | parse_init_chunk                      |
    // | 3.2         | Chunk padded to 4-byte boundary                | chunk_padding_not_counted_in_length   |
    // | 3.2         | chunk_length < 4 rejected                      | invalid_chunk_length_below_minimum    |
    // | 3.2         | Truncated chunk (pos + length > data)          | truncated_chunk_value                 |
    // | 3.2         | Multiple chunks in one packet                  | multiple_chunks                       |
    // | 3.3.1       | DATA chunk user data recorded as payload       | parse_data_chunk_embedded_payload     |
    // | 3.3.1       | DATA chunk header fields and I/U/B/E bits      | parse_data_chunk_fields               |
    // | 3.3.1       | DATA chunk with L == 0 does not dispatch       | empty_data_chunk_no_dispatch          |
    // | 3.3.1       | DATA chunk shorter than its header             | short_data_chunk_generic_value        |
    // | 3.3.1, 6.9  | Fragments (B/E not both set) not dispatched    | fragmented_data_chunks_not_dispatched |
    // | 6.10        | Every bundled DATA chunk recorded as payload   | bundled_data_chunks_each_dispatched   |
    // | 3.3.1       | Payload hint carries PPID and ports            | data_payload_hint_carries_ppid        |
    // | IANA PPID   | Payload Protocol Identifier names              | ppid_names                            |
    // | 3.2.1       | Parameter TLVs, padding, malformed length      | parse_init_parameters                 |
    // | 3.3.2       | INIT fixed fields                              | parse_init_chunk_fields               |
    // | 3.3.2       | INIT shorter than fixed part                   | short_init_chunk_generic_value        |
    // | 3.3.3       | INIT ACK fixed fields + State Cookie           | parse_init_ack_chunk_fields           |
    // | 3.3.4       | SACK gap ack blocks and duplicate TSNs         | parse_sack_chunk_fields               |
    // | 3.3.4       | SACK counts beyond chunk length                | sack_counts_clamped_to_chunk          |
    // | 3.3.5, 3.3.6| HEARTBEAT / HEARTBEAT ACK Heartbeat Info       | parse_heartbeat_chunks                |
    // | 3.3.7       | ABORT T bit and error causes                   | parse_abort_chunk_fields              |
    // | 3.3.8       | SHUTDOWN Cumulative TSN Ack                    | parse_shutdown_chunk_fields           |
    // | 3.3.10      | ERROR causes (code/length/value)               | parse_error_chunk_causes              |
    // | 3.3.13      | SHUTDOWN COMPLETE T bit                        | parse_shutdown_complete_t_bit         |
    // | RFC 8260 2.1| I-DATA fields, PPID/FSN by B bit, dispatch     | parse_i_data_chunk                    |
    // | RFC 8260 2.1| I-DATA fragments not dispatched                | i_data_fragments_not_dispatched       |
    // | 3.2, 3.2.1  | Bytes after decoded fields shown as undecoded  | undecoded_trailing_bytes_shown        |
    // | IANA        | Number of named values per registry            | registry_name_counts                  |
    // | 3.2.1, 3.3.10 | Parameter / cause names in display labels    | parameter_and_cause_display_names     |
    // | ---         | No chunks => no `chunks` array field           | common_header_only_no_chunks_field    |
    // | ---         | Offset handling in byte ranges                 | dissect_with_offset                   |
    // | ---         | Field descriptors                              | field_descriptors_list                |

    fn build_common_header(src_port: u16, dst_port: u16, vt: u32, checksum: u32) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(COMMON_HEADER_SIZE);
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&vt.to_be_bytes());
        pkt.extend_from_slice(&checksum.to_be_bytes());
        pkt
    }

    /// Append a generic chunk (type/flags/length/value), 4-byte padded.
    fn push_chunk(pkt: &mut Vec<u8>, ctype: u8, flags: u8, value: &[u8]) {
        let chunk_len = MIN_CHUNK_SIZE + value.len();
        pkt.push(ctype);
        pkt.push(flags);
        pkt.extend_from_slice(&(chunk_len as u16).to_be_bytes());
        pkt.extend_from_slice(value);
        while pkt.len() % 4 != 0 {
            pkt.push(0);
        }
    }

    /// Append a DATA chunk per RFC 9260, Section 3.3.1 —
    /// <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1>
    fn push_data_chunk(
        pkt: &mut Vec<u8>,
        flags: u8,
        tsn: u32,
        sid: u16,
        ssn: u16,
        ppi: u32,
        user_data: &[u8],
    ) {
        let chunk_len = DATA_CHUNK_HEADER_SIZE + user_data.len();
        pkt.push(CHUNK_TYPE_DATA);
        pkt.push(flags);
        pkt.extend_from_slice(&(chunk_len as u16).to_be_bytes());
        pkt.extend_from_slice(&tsn.to_be_bytes());
        pkt.extend_from_slice(&sid.to_be_bytes());
        pkt.extend_from_slice(&ssn.to_be_bytes());
        pkt.extend_from_slice(&ppi.to_be_bytes());
        pkt.extend_from_slice(user_data);
        while pkt.len() % 4 != 0 {
            pkt.push(0);
        }
    }

    #[test]
    fn parse_common_header() {
        // RFC 9260, Section 3.1 — Common Header Field Descriptions.
        let data = build_common_header(36412, 3868, 0xAABB_CCDD, 0x1234_5678);
        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, COMMON_HEADER_SIZE);
        assert_eq!(result.next, DispatchHint::BySctpPort(36412, 3868));
        assert!(result.embedded_payload.is_none());

        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "SCTP");
        assert_eq!(layer.range, 0..COMMON_HEADER_SIZE);

        assert_eq!(
            buf.field_by_name(layer, "src_port").unwrap().value,
            FieldValue::U16(36412)
        );
        assert_eq!(
            buf.field_by_name(layer, "dst_port").unwrap().value,
            FieldValue::U16(3868)
        );
        assert_eq!(
            buf.field_by_name(layer, "verification_tag").unwrap().value,
            FieldValue::U32(0xAABB_CCDD)
        );
        assert_eq!(
            buf.field_by_name(layer, "checksum").unwrap().value,
            FieldValue::U32(0x1234_5678)
        );
    }

    #[test]
    fn reject_source_port_zero() {
        // RFC 9260, Section 3.1 — "The Source Port Number 0 MUST NOT be used."
        let data = build_common_header(0, 3868, 0, 0);
        let mut buf = DissectBuffer::new();
        let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::InvalidFieldValue { field, value } => {
                assert_eq!(field, "src_port");
                assert_eq!(value, 0);
            }
            other => panic!("expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn reject_destination_port_zero() {
        // RFC 9260, Section 3.1 — "The Destination Port Number 0 MUST NOT be used."
        let data = build_common_header(3868, 0, 0, 0);
        let mut buf = DissectBuffer::new();
        let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::InvalidFieldValue { field, value } => {
                assert_eq!(field, "dst_port");
                assert_eq!(value, 0);
            }
            other => panic!("expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn truncated_common_header() {
        let data = [0u8; COMMON_HEADER_SIZE - 1];
        let mut buf = DissectBuffer::new();
        let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, COMMON_HEADER_SIZE);
                assert_eq!(actual, data.len());
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn chunk_type_names() {
        // RFC 9260, Section 3.2 — Chunk Types table (values 0..=14).
        let table = [
            (0u8, "DATA"),
            (1, "INIT"),
            (2, "INIT_ACK"),
            (3, "SACK"),
            (4, "HEARTBEAT"),
            (5, "HEARTBEAT_ACK"),
            (6, "ABORT"),
            (7, "SHUTDOWN"),
            (8, "SHUTDOWN_ACK"),
            (9, "ERROR"),
            (10, "COOKIE_ECHO"),
            (11, "COOKIE_ACK"),
            (12, "ECNE"),
            (13, "CWR"),
            (14, "SHUTDOWN_COMPLETE"),
        ];
        for (v, expected) in table {
            assert_eq!(sctp_chunk_type_name(v), Some(expected), "chunk type {v}");
        }
        // IANA "Chunk Types" registry extensions.
        let extensions = [
            (15u8, "AUTH"),         // RFC 4895
            (64, "I_DATA"),         // RFC 8260
            (128, "ASCONF_ACK"),    // RFC 5061
            (130, "RE_CONFIG"),     // RFC 6525
            (132, "PAD"),           // RFC 4820
            (192, "FORWARD_TSN"),   // RFC 3758
            (193, "ASCONF"),        // RFC 5061
            (194, "I_FORWARD_TSN"), // RFC 8260
        ];
        for (v, expected) in extensions {
            assert_eq!(sctp_chunk_type_name(v), Some(expected), "chunk type {v}");
        }
        // Unassigned / reserved values return None.
        assert_eq!(sctp_chunk_type_name(16), None);
        assert_eq!(sctp_chunk_type_name(63), None); // Reserved for IETF extensions
        assert_eq!(sctp_chunk_type_name(129), None);
        assert_eq!(sctp_chunk_type_name(255), None);
    }

    /// Count top-level chunk Objects inside the `chunks` Array container.
    fn count_chunk_objects(buf: &DissectBuffer<'_>, layer: &Layer) -> usize {
        let chunks = buf.field_by_name(layer, "chunks").expect("chunks present");
        let range = match &chunks.value {
            FieldValue::Array(r) => r.clone(),
            other => panic!("expected Array, got {other:?}"),
        };
        let mut idx = range.start;
        let mut count = 0usize;
        while idx < range.end {
            let field = &buf.fields()[idx as usize];
            match &field.value {
                FieldValue::Object(inner) => {
                    count += 1;
                    // Skip over this object's children; they are laid out
                    // contiguously after the placeholder.
                    idx = inner.end;
                }
                _ => idx += 1,
            }
        }
        count
    }

    #[test]
    fn parse_init_chunk() {
        // INIT chunk (type=1) with minimal 16-byte fixed parameter body.
        let mut data = build_common_header(12345, 3868, 0, 0);
        let body = [0u8; 16];
        push_chunk(&mut data, 1, 0, &body);
        let total_len = data.len();

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, total_len);
        assert!(result.embedded_payload.is_none());

        let layer = &buf.layers()[0];
        assert_eq!(count_chunk_objects(&buf, layer), 1);
    }

    #[test]
    fn parse_data_chunk_embedded_payload() {
        // RFC 9260, Section 3.3.1 — DATA chunk User Data follows 16-byte header.
        let payload = b"ngap-payload";
        let mut data = build_common_header(36412, 36412, 0, 0);
        push_data_chunk(&mut data, 0x03, 1, 0, 0, 60, payload);

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(
            result.next,
            DispatchHint::BySctpPpid {
                ppid: 60,
                src_port: 36412,
                dst_port: 36412
            }
        );
        assert!(result.embedded_payload.is_none());

        let payloads = buf.embedded_payloads();
        assert_eq!(payloads.len(), 1);
        let range = payloads[0].range.clone();
        assert_eq!(range.start, COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE);
        assert_eq!(range.end - range.start, payload.len());
        assert_eq!(&data[range], payload);
        assert_eq!(payloads[0].next, result.next);
    }

    /// Return the direct children of the `index`-th chunk Object.
    fn chunk_children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        layer: &Layer,
        index: usize,
    ) -> &'a [packet_dissector_core::field::Field<'pkt>] {
        let chunks = buf.field_by_name(layer, "chunks").expect("chunks present");
        let FieldValue::Array(ref range) = chunks.value else {
            panic!("expected Array, got {:?}", chunks.value);
        };
        let mut idx = range.start;
        let mut seen = 0usize;
        while idx < range.end {
            let field = &buf.fields()[idx as usize];
            if let FieldValue::Object(ref inner) = field.value {
                if seen == index {
                    return buf.nested_fields(inner);
                }
                seen += 1;
                idx = inner.end;
            } else {
                idx += 1;
            }
        }
        panic!("chunk {index} not found");
    }

    fn child<'a, 'pkt>(
        fields: &'a [packet_dissector_core::field::Field<'pkt>],
        name: &str,
    ) -> Option<&'a FieldValue<'pkt>> {
        fields.iter().find(|f| f.name() == name).map(|f| &f.value)
    }

    #[test]
    fn parse_data_chunk_fields() {
        // RFC 9260, Section 3.3.1 — Type = 0 | Res | I | U | B | E | Length,
        // TSN, Stream Identifier S, Stream Sequence Number n, Payload
        // Protocol Identifier, User Data.
        let mut data = build_common_header(40000, 40001, 1, 0);
        // I=1, U=1, B=1, E=1 plus reserved bits set (ignored on receipt).
        push_data_chunk(&mut data, 0xFF, 0xDEAD_BEEF, 7, 9, 46, b"abcde");

        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let c = chunk_children(&buf, layer, 0);

        assert_eq!(child(c, "type"), Some(&FieldValue::U8(0)));
        assert_eq!(child(c, "flags"), Some(&FieldValue::U8(0xFF)));
        assert_eq!(child(c, "i"), Some(&FieldValue::U8(1)));
        assert_eq!(child(c, "u"), Some(&FieldValue::U8(1)));
        assert_eq!(child(c, "b"), Some(&FieldValue::U8(1)));
        assert_eq!(child(c, "e"), Some(&FieldValue::U8(1)));
        assert_eq!(child(c, "length"), Some(&FieldValue::U16(21)));
        assert_eq!(child(c, "tsn"), Some(&FieldValue::U32(0xDEAD_BEEF)));
        assert_eq!(child(c, "stream_id"), Some(&FieldValue::U16(7)));
        assert_eq!(child(c, "ssn"), Some(&FieldValue::U16(9)));
        assert_eq!(child(c, "ppid"), Some(&FieldValue::U32(46)));
        assert_eq!(
            child(c, "user_data"),
            Some(&FieldValue::Bytes(b"abcde".as_slice()))
        );
        // The decoded DATA chunk has no generic `value` field.
        assert_eq!(child(c, "value"), None);

        let tsn = c.iter().find(|f| f.name() == "tsn").unwrap();
        assert_eq!(tsn.range, 16..20);
        let user_data = c.iter().find(|f| f.name() == "user_data").unwrap();
        assert_eq!(user_data.range, 28..33);

        // B = 0, E = 0, U = 0, I = 0 (middle fragment of an ordered message).
        let mut data = build_common_header(40000, 40001, 1, 0);
        push_data_chunk(&mut data, 0x00, 1, 0, 0, 0, b"x");
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let c = chunk_children(&buf, layer, 0);
        for bit in ["i", "u", "b", "e"] {
            assert_eq!(child(c, bit), Some(&FieldValue::U8(0)), "bit {bit}");
        }
    }

    #[test]
    fn bundled_data_chunks_each_dispatched() {
        // RFC 9260, Section 6.10 — multiple DATA chunks bundled into one
        // SCTP packet each carry a complete user message.
        let mut data = build_common_header(49152, 3868, 1, 0);
        push_data_chunk(&mut data, 0x03, 1, 0, 0, 46, b"first");
        let second_chunk = data.len();
        push_data_chunk(&mut data, 0x03, 2, 0, 1, 46, b"second!!");

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        assert!(result.embedded_payload.is_none());

        let payloads = buf.embedded_payloads();
        assert_eq!(payloads.len(), 2);
        assert_eq!(&data[payloads[0].range.clone()], b"first");
        assert_eq!(&data[payloads[1].range.clone()], b"second!!");
        assert_eq!(
            payloads[1].range.start,
            second_chunk + DATA_CHUNK_HEADER_SIZE
        );
        for p in payloads {
            assert_eq!(
                p.next,
                DispatchHint::BySctpPpid {
                    ppid: 46,
                    src_port: 49152,
                    dst_port: 3868
                }
            );
        }
    }

    #[test]
    fn fragmented_data_chunks_not_dispatched() {
        // RFC 9260, Section 3.3.1 — "An unfragmented user message MUST have
        // both the B and E bits set to 1." First (B=1, E=0), middle (B=0,
        // E=0) and last (B=0, E=1) fragments carry only part of a user
        // message (Section 6.9) and must not reach the upper layer.
        let mut data = build_common_header(49152, 3868, 1, 0);
        push_data_chunk(&mut data, 0x02, 1, 0, 0, 46, b"first-fragment");
        push_data_chunk(&mut data, 0x00, 2, 0, 0, 46, b"middle");
        push_data_chunk(&mut data, 0x01, 3, 0, 0, 46, b"last");
        push_data_chunk(&mut data, 0x03, 4, 1, 0, 46, b"whole");

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());

        let payloads = buf.embedded_payloads();
        assert_eq!(payloads.len(), 1, "only the unfragmented chunk");
        assert_eq!(&data[payloads[0].range.clone()], b"whole");

        let layer = &buf.layers()[0];
        assert_eq!(count_chunk_objects(&buf, layer), 4);
        let first = chunk_children(&buf, layer, 0);
        assert_eq!(child(first, "b"), Some(&FieldValue::U8(1)));
        assert_eq!(child(first, "e"), Some(&FieldValue::U8(0)));
        assert_eq!(
            child(first, "user_data"),
            Some(&FieldValue::Bytes(b"first-fragment".as_slice()))
        );
    }

    #[test]
    fn short_data_chunk_generic_value() {
        // A DATA chunk whose Length is below the 16-byte DATA header cannot
        // hold TSN/SID/SSN/PPID; show its body as raw bytes and do not
        // dispatch it (Postel's Law).
        let mut data = build_common_header(49152, 3868, 1, 0);
        push_chunk(&mut data, CHUNK_TYPE_DATA, 0x03, &[0xAA; 8]);

        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(buf.embedded_payloads().is_empty());

        let layer = &buf.layers()[0];
        let c = chunk_children(&buf, layer, 0);
        assert_eq!(
            child(c, "value"),
            Some(&FieldValue::Bytes([0xAA; 8].as_slice()))
        );
        assert_eq!(child(c, "tsn"), None);
    }

    #[test]
    fn chunk_padding_not_counted_in_length() {
        // RFC 9260, Section 3.2 — Chunks are padded to a 4-byte boundary and
        // the padding is NOT included in the Chunk Length field. A chunk with
        // a 1-byte value has Length = 5 and consumes 8 bytes including pad.
        let mut data = build_common_header(12345, 3868, 0, 0);
        push_chunk(&mut data, 9, 0, &[0xAB]); // ERROR chunk, Length=5, 3 bytes padding
        assert_eq!(data.len(), COMMON_HEADER_SIZE + 8);

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());

        // The chunk_length field stores the RFC "Length" (not the padded size).
        let layer = &buf.layers()[0];
        let chunks_field = buf.field_by_name(layer, "chunks").unwrap();
        let children = match &chunks_field.value {
            FieldValue::Array(r) => r.clone(),
            other => panic!("expected Array, got {other:?}"),
        };
        // First child is the chunk object; find its "length" within.
        let chunk_obj = &buf.fields()[children.start as usize];
        let chunk_children = match &chunk_obj.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let length_field = buf
            .fields()
            .get(chunk_children.start as usize..chunk_children.end as usize)
            .unwrap()
            .iter()
            .find(|f| f.name() == "length")
            .unwrap();
        assert_eq!(length_field.value, FieldValue::U16(5));
    }

    #[test]
    fn invalid_chunk_length_below_minimum() {
        let mut data = build_common_header(12345, 3868, 0, 0);
        // Chunk header with Length=3 (< MIN_CHUNK_SIZE).
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]);
        let mut buf = DissectBuffer::new();
        let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::InvalidFieldValue { field, value } => {
                assert_eq!(field, "chunk_length");
                assert_eq!(value, 3);
            }
            other => panic!("expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn truncated_chunk_value() {
        let mut data = build_common_header(12345, 3868, 0, 0);
        // Chunk claims Length=100 but only 4 header bytes follow.
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]);
        let expected = COMMON_HEADER_SIZE + 100;
        let actual_len = data.len();
        let mut buf = DissectBuffer::new();
        let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::Truncated {
                expected: e,
                actual: a,
            } => {
                assert_eq!(e, expected);
                assert_eq!(a, actual_len);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn multiple_chunks() {
        let mut data = build_common_header(12345, 3868, 0, 0);
        push_chunk(&mut data, 3, 0, &[0u8; 12]); // SACK
        push_data_chunk(&mut data, 0x03, 7, 0, 0, 60, b"X"); // DATA
        push_chunk(&mut data, 6, 0, &[]); // ABORT (Length=4, no value)

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());

        let payloads = buf.embedded_payloads();
        assert_eq!(payloads.len(), 1);
        assert_eq!(&data[payloads[0].range.clone()], b"X");

        let layer = &buf.layers()[0];
        assert_eq!(count_chunk_objects(&buf, layer), 3);
    }

    #[test]
    fn empty_data_chunk_no_dispatch() {
        // RFC 9260, Section 3.3.1 — "L MUST be greater than 0". A DATA chunk
        // with Length == 16 violates this, but we parse it and decline to
        // expose an embedded payload (Postel's Law).
        let mut data = build_common_header(12345, 3868, 0, 0);
        data.push(CHUNK_TYPE_DATA);
        data.push(0x03); // B|E: unfragmented, so only L == 0 blocks dispatch
        data.extend_from_slice(&(DATA_CHUNK_HEADER_SIZE as u16).to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes()); // TSN
        data.extend_from_slice(&0u16.to_be_bytes()); // SID
        data.extend_from_slice(&0u16.to_be_bytes()); // SSN
        data.extend_from_slice(&0u32.to_be_bytes()); // PPI

        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(result.embedded_payload.is_none());
        assert!(buf.embedded_payloads().is_empty());
    }

    #[test]
    fn data_payload_hint_carries_ppid() {
        // RFC 9260, Section 3.3.1 — each DATA chunk carries its own PPID, so
        // each recorded payload gets its own hint. The layer's own hint is
        // the first payload's, and falls back to ports without DATA.
        let mut data = build_common_header(40000, 40001, 1, 0);
        push_data_chunk(&mut data, 0x03, 1, 0, 0, 46, b"diameter");
        push_data_chunk(&mut data, 0x03, 2, 1, 0, 60, b"ngap");
        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let hints: Vec<_> = buf
            .embedded_payloads()
            .iter()
            .map(|p| p.next.clone())
            .collect();
        assert_eq!(
            hints,
            [
                DispatchHint::BySctpPpid {
                    ppid: 46,
                    src_port: 40000,
                    dst_port: 40001
                },
                DispatchHint::BySctpPpid {
                    ppid: 60,
                    src_port: 40000,
                    dst_port: 40001
                },
            ]
        );
        assert_eq!(result.next, hints[0]);

        let data = build_common_header(40000, 40001, 1, 0);
        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.next, DispatchHint::BySctpPort(40000, 40001));
    }

    #[test]
    fn ppid_names() {
        // IANA "SCTP Payload Protocol Identifiers" registry.
        assert_eq!(sctp_ppid_name(0), None); // Reserved by SCTP (unspecified)
        assert_eq!(sctp_ppid_name(3), Some("M3UA"));
        assert_eq!(sctp_ppid_name(18), Some("S1AP"));
        assert_eq!(sctp_ppid_name(26), None); // Unassigned
        assert_eq!(sctp_ppid_name(46), Some("Diameter"));
        assert_eq!(sctp_ppid_name(47), Some("Diameter over DTLS"));
        assert_eq!(sctp_ppid_name(60), Some("NGAP"));
        assert_eq!(sctp_ppid_name(73), Some("W1AP"));
        assert_eq!(sctp_ppid_name(74), None);
        assert_eq!(sctp_ppid_name(4242), Some("DTLS Chunk Key-Management"));

        // The `ppid` field resolves to the name.
        let mut data = build_common_header(40000, 40001, 1, 0);
        push_data_chunk(&mut data, 0x03, 1, 0, 0, 46, b"x");
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let (idx, _) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "ppid")
            .unwrap();
        let ppid = &buf.fields()[idx];
        let name = ppid.descriptor.display_fn.unwrap()(&ppid.value, &[]);
        assert_eq!(name, Some("Diameter"));
    }

    /// Direct children of each Object inside the Array `value`.
    fn array_objects<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        value: &FieldValue<'pkt>,
    ) -> Vec<&'a [packet_dissector_core::field::Field<'pkt>]> {
        let FieldValue::Array(range) = value else {
            panic!("expected Array, got {value:?}");
        };
        let mut out = Vec::new();
        let mut idx = range.start;
        while idx < range.end {
            let f = &buf.fields()[idx as usize];
            if let FieldValue::Object(ref inner) = f.value {
                out.push(buf.nested_fields(inner));
                idx = inner.end;
            } else {
                idx += 1;
            }
        }
        out
    }

    /// Scalar elements of the Array `value`.
    fn array_values<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        value: &FieldValue<'pkt>,
    ) -> Vec<&'a FieldValue<'pkt>> {
        let FieldValue::Array(range) = value else {
            panic!("expected Array, got {value:?}");
        };
        buf.nested_fields(range).iter().map(|f| &f.value).collect()
    }

    /// Append a parameter TLV, padded to 4 bytes.
    ///
    /// RFC 9260, Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.2.1>
    fn param(out: &mut Vec<u8>, ptype: u16, value: &[u8]) {
        out.extend_from_slice(&ptype.to_be_bytes());
        out.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }

    fn init_fixed(tag: u32, a_rwnd: u32, os: u16, mis: u16, tsn: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&tag.to_be_bytes());
        v.extend_from_slice(&a_rwnd.to_be_bytes());
        v.extend_from_slice(&os.to_be_bytes());
        v.extend_from_slice(&mis.to_be_bytes());
        v.extend_from_slice(&tsn.to_be_bytes());
        v
    }

    #[test]
    fn parse_init_chunk_fields() {
        // RFC 9260, Section 3.3.2 — INIT fixed part.
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 1, 0, &init_fixed(0x1122_3344, 65535, 10, 20, 7));
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(
            child(c, "initiate_tag"),
            Some(&FieldValue::U32(0x1122_3344))
        );
        assert_eq!(child(c, "a_rwnd"), Some(&FieldValue::U32(65535)));
        assert_eq!(child(c, "outbound_streams"), Some(&FieldValue::U16(10)));
        assert_eq!(child(c, "inbound_streams"), Some(&FieldValue::U16(20)));
        assert_eq!(child(c, "initial_tsn"), Some(&FieldValue::U32(7)));
        assert_eq!(child(c, "parameters"), None);
        assert_eq!(child(c, "value"), None);
        let tag = c.iter().find(|f| f.name() == "initiate_tag").unwrap();
        assert_eq!(tag.range, 16..20);
    }

    #[test]
    fn short_init_chunk_generic_value() {
        // An INIT whose Length cannot hold the 16-byte fixed part is shown
        // as raw bytes.
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 1, 0, &[0xAB; 8]);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(
            child(c, "value"),
            Some(&FieldValue::Bytes([0xAB; 8].as_slice()))
        );
        assert_eq!(child(c, "initiate_tag"), None);
    }

    #[test]
    fn parse_init_parameters() {
        // RFC 9260, Sections 3.2.1 and 3.3.2.1 —
        // https://www.rfc-editor.org/rfc/rfc9260#section-3.3.2.1
        let mut body = init_fixed(1, 2, 3, 4, 5);
        param(&mut body, 5, &[192, 0, 2, 1]); // IPv4 Address
        let mut v6 = [0u8; 16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        v6[2] = 0x0d;
        v6[3] = 0xb8;
        v6[15] = 1;
        param(&mut body, 6, &v6); // IPv6 Address
        param(&mut body, 9, &1000u32.to_be_bytes()); // Cookie Preservative
        param(&mut body, 11, b"host.example\0"); // Host Name Address, padded
        param(&mut body, 12, &[0, 5, 0, 6]); // Supported Address Types
        param(&mut body, 0xC000, &[]); // Forward TSN supported (RFC 3758)
        param(&mut body, 0x8008, &[0xC0, 0x82]); // Supported Extensions
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 1, 0, &body);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        let params = array_objects(&buf, child(c, "parameters").unwrap());
        assert_eq!(params.len(), 7);

        assert_eq!(child(params[0], "type"), Some(&FieldValue::U16(5)));
        assert_eq!(child(params[0], "length"), Some(&FieldValue::U16(8)));
        assert_eq!(
            child(params[0], "ipv4_address"),
            Some(&FieldValue::Ipv4Addr([192, 0, 2, 1]))
        );
        assert_eq!(
            child(params[1], "ipv6_address"),
            Some(&FieldValue::Ipv6Addr(v6))
        );
        assert_eq!(
            child(params[2], "cookie_life_span_increment"),
            Some(&FieldValue::U32(1000))
        );
        assert_eq!(
            child(params[3], "host_name"),
            Some(&FieldValue::Str("host.example"))
        );
        let types = array_values(&buf, child(params[4], "address_types").unwrap());
        assert_eq!(types, [&FieldValue::U16(5), &FieldValue::U16(6)]);
        assert_eq!(child(params[5], "type"), Some(&FieldValue::U16(0xC000)));
        assert_eq!(child(params[5], "value"), None);
        assert_eq!(
            child(params[6], "value"),
            Some(&FieldValue::Bytes([0xC0, 0x82].as_slice()))
        );

        // Parameter names come from the IANA "Chunk Parameter Types" registry.
        assert_eq!(sctp_parameter_type_name(5), Some("IPv4 Address"));
        assert_eq!(
            sctp_parameter_type_name(0xC000),
            Some("Forward TSN Supported")
        );
        assert_eq!(
            sctp_parameter_type_name(0x8001),
            Some("Zero Checksum Acceptable")
        );
        assert_eq!(sctp_parameter_type_name(2), None);

        // A parameter whose Length is below 4 or past the chunk stops the
        // list; the parameters before it are kept (Postel's Law).
        let mut body = init_fixed(1, 2, 3, 4, 5);
        param(&mut body, 5, &[192, 0, 2, 1]);
        body.extend_from_slice(&[0x00, 0x05, 0x00, 0x40]); // Length 64 > remaining
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 1, 0, &body);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(
            array_objects(&buf, child(c, "parameters").unwrap()).len(),
            1
        );

        let mut body = init_fixed(1, 2, 3, 4, 5);
        body.extend_from_slice(&[0x00, 0x05, 0x00, 0x02]); // Length 2 < 4
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 1, 0, &body);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(child(c, "parameters"), None);

        // IPv4 Address with a wrong length and a non-UTF-8 host name fall
        // back to raw bytes.
        let mut body = init_fixed(1, 2, 3, 4, 5);
        param(&mut body, 5, &[1, 2, 3]);
        param(&mut body, 11, &[0xFF, 0xFE, 0x00]);
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 1, 0, &body);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        let params = array_objects(&buf, child(c, "parameters").unwrap());
        assert_eq!(
            child(params[0], "value"),
            Some(&FieldValue::Bytes([1, 2, 3].as_slice()))
        );
        assert_eq!(
            child(params[1], "value"),
            Some(&FieldValue::Bytes([0xFF, 0xFE, 0x00].as_slice()))
        );
    }

    #[test]
    fn parse_init_ack_chunk_fields() {
        // RFC 9260, Section 3.3.3 — INIT ACK carries a State Cookie (7) and
        // may carry Unrecognized Parameter (8).
        let mut body = init_fixed(9, 8, 7, 6, 5);
        param(&mut body, 7, &[0xC0; 12]);
        param(&mut body, 8, &[0x80, 0x0A, 0x00, 0x04]);
        let mut data = build_common_header(3868, 5000, 0, 0);
        push_chunk(&mut data, 2, 0, &body);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(child(c, "initiate_tag"), Some(&FieldValue::U32(9)));
        let params = array_objects(&buf, child(c, "parameters").unwrap());
        assert_eq!(
            child(params[0], "state_cookie"),
            Some(&FieldValue::Bytes([0xC0; 12].as_slice()))
        );
        assert_eq!(
            child(params[1], "value"),
            Some(&FieldValue::Bytes([0x80, 0x0A, 0x00, 0x04].as_slice()))
        );
    }

    fn sack_body(cum: u32, a_rwnd: u32, gaps: &[(u16, u16)], dups: &[u32]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&cum.to_be_bytes());
        v.extend_from_slice(&a_rwnd.to_be_bytes());
        v.extend_from_slice(&(gaps.len() as u16).to_be_bytes());
        v.extend_from_slice(&(dups.len() as u16).to_be_bytes());
        for (s, e) in gaps {
            v.extend_from_slice(&s.to_be_bytes());
            v.extend_from_slice(&e.to_be_bytes());
        }
        for d in dups {
            v.extend_from_slice(&d.to_be_bytes());
        }
        v
    }

    #[test]
    fn parse_sack_chunk_fields() {
        // RFC 9260, Section 3.3.4 — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.4
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(
            &mut data,
            3,
            0,
            &sack_body(100, 4096, &[(2, 3), (5, 5)], &[99]),
        );
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(child(c, "cumulative_tsn_ack"), Some(&FieldValue::U32(100)));
        assert_eq!(child(c, "a_rwnd"), Some(&FieldValue::U32(4096)));
        assert_eq!(child(c, "num_gap_ack_blocks"), Some(&FieldValue::U16(2)));
        assert_eq!(child(c, "num_dup_tsns"), Some(&FieldValue::U16(1)));
        let gaps = array_objects(&buf, child(c, "gap_ack_blocks").unwrap());
        assert_eq!(gaps.len(), 2);
        assert_eq!(child(gaps[0], "start"), Some(&FieldValue::U16(2)));
        assert_eq!(child(gaps[0], "end"), Some(&FieldValue::U16(3)));
        assert_eq!(child(gaps[1], "start"), Some(&FieldValue::U16(5)));
        let dups = array_values(&buf, child(c, "duplicate_tsns").unwrap());
        assert_eq!(dups, [&FieldValue::U32(99)]);

        // No gap blocks and no duplicates: no arrays.
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 3, 0, &sack_body(1, 2, &[], &[]));
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(child(c, "gap_ack_blocks"), None);
        assert_eq!(child(c, "duplicate_tsns"), None);
    }

    #[test]
    fn sack_counts_clamped_to_chunk() {
        // Counts claim more entries than the chunk holds: decode what is
        // present (Postel's Law).
        let mut body = sack_body(1, 2, &[(2, 3)], &[]);
        body[8..10].copy_from_slice(&5u16.to_be_bytes()); // N = 5
        body[10..12].copy_from_slice(&3u16.to_be_bytes()); // M = 3
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 3, 0, &body);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(child(c, "num_gap_ack_blocks"), Some(&FieldValue::U16(5)));
        assert_eq!(
            array_objects(&buf, child(c, "gap_ack_blocks").unwrap()).len(),
            1
        );
        assert_eq!(child(c, "duplicate_tsns"), None);

        // Shorter than the 12-byte fixed part: raw bytes.
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 3, 0, &[0u8; 8]);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(
            child(c, "value"),
            Some(&FieldValue::Bytes([0u8; 8].as_slice()))
        );
    }

    #[test]
    fn parse_heartbeat_chunks() {
        // RFC 9260, Sections 3.3.5 and 3.3.6 — Heartbeat Info TLV (type 1).
        for chunk_type in [4u8, 5] {
            let mut body = Vec::new();
            param(&mut body, 1, b"sender-info!");
            let mut data = build_common_header(5000, 3868, 0, 0);
            push_chunk(&mut data, chunk_type, 0, &body);
            let mut buf = DissectBuffer::new();
            SctpDissector.dissect(&data, &mut buf, 0).unwrap();
            let c = chunk_children(&buf, &buf.layers()[0], 0);
            let params = array_objects(&buf, child(c, "parameters").unwrap());
            assert_eq!(params.len(), 1);
            assert_eq!(
                child(params[0], "heartbeat_info"),
                Some(&FieldValue::Bytes(b"sender-info!".as_slice()))
            );
            assert_eq!(child(c, "value"), None);
        }

        // A HEARTBEAT whose body is not a TLV is shown as raw bytes.
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 4, 0, &[0xAA, 0xBB]);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(child(c, "parameters"), None);
        assert_eq!(
            child(c, "value"),
            Some(&FieldValue::Bytes([0xAA, 0xBB].as_slice()))
        );
    }

    /// Append an error cause, padded to 4 bytes.
    ///
    /// RFC 9260, Section 3.3.10 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.10>
    fn cause(out: &mut Vec<u8>, code: u16, info: &[u8]) {
        param(out, code, info);
    }

    #[test]
    fn parse_abort_chunk_fields() {
        // RFC 9260, Section 3.3.7 — T bit and zero or more error causes.
        let mut body = Vec::new();
        cause(&mut body, 12, b"bye"); // User-Initiated Abort
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 6, 0x01, &body);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(child(c, "t"), Some(&FieldValue::U8(1)));
        let causes = array_objects(&buf, child(c, "error_causes").unwrap());
        assert_eq!(causes.len(), 1);
        assert_eq!(child(causes[0], "code"), Some(&FieldValue::U16(12)));
        assert_eq!(child(causes[0], "length"), Some(&FieldValue::U16(7)));
        assert_eq!(
            child(causes[0], "value"),
            Some(&FieldValue::Bytes(b"bye".as_slice()))
        );

        // ABORT with no causes and T = 0.
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 6, 0x00, &[]);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(child(c, "t"), Some(&FieldValue::U8(0)));
        assert_eq!(child(c, "error_causes"), None);
    }

    #[test]
    fn parse_error_chunk_causes() {
        // RFC 9260, Section 3.3.10 — one or more error causes. ERROR has no
        // T bit (IANA "ERROR Chunk Flags" are all unassigned).
        let mut body = Vec::new();
        cause(&mut body, 1, &[0x00, 0x07, 0x00, 0x00]); // Invalid Stream Identifier
        cause(&mut body, 3, &500_000u32.to_be_bytes()); // Stale Cookie
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 9, 0x01, &body);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(child(c, "t"), None);
        let causes = array_objects(&buf, child(c, "error_causes").unwrap());
        assert_eq!(causes.len(), 2);
        assert_eq!(child(causes[1], "code"), Some(&FieldValue::U16(3)));

        // A body without a well-formed cause is shown as raw bytes.
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 9, 0, &[0x00, 0x01, 0x00, 0x02]); // Length 2 < 4
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(child(c, "error_causes"), None);
        assert_eq!(
            child(c, "value"),
            Some(&FieldValue::Bytes([0x00, 0x01, 0x00, 0x02].as_slice()))
        );

        assert_eq!(sctp_cause_code_name(1), Some("Invalid Stream Identifier"));
        assert_eq!(sctp_cause_code_name(13), Some("Protocol Violation"));
        assert_eq!(
            sctp_cause_code_name(160),
            Some("Request to Delete Last Remaining IP Address")
        );
        assert_eq!(
            sctp_cause_code_name(261),
            Some("Unsupported HMAC Identifier")
        );
        assert_eq!(sctp_cause_code_name(14), None);
    }

    #[test]
    fn parse_shutdown_chunk_fields() {
        // RFC 9260, Section 3.3.8 — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.8
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 7, 0, &0xFFFF_FFFEu32.to_be_bytes());
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(
            child(c, "cumulative_tsn_ack"),
            Some(&FieldValue::U32(0xFFFF_FFFE))
        );
        assert_eq!(child(c, "value"), None);
    }

    #[test]
    fn parse_shutdown_complete_t_bit() {
        // RFC 9260, Section 3.3.13 — https://www.rfc-editor.org/rfc/rfc9260#section-3.3.13
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 14, 0x01, &[]);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(child(c, "t"), Some(&FieldValue::U8(1)));
    }

    /// Append an I-DATA chunk per RFC 8260, Section 2.1 —
    /// <https://www.rfc-editor.org/rfc/rfc8260#section-2.1>
    fn push_i_data_chunk(
        pkt: &mut Vec<u8>,
        flags: u8,
        tsn: u32,
        sid: u16,
        mid: u32,
        ppid_or_fsn: u32,
        user_data: &[u8],
    ) {
        let mut body = Vec::new();
        body.extend_from_slice(&tsn.to_be_bytes());
        body.extend_from_slice(&sid.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // Reserved
        body.extend_from_slice(&mid.to_be_bytes());
        body.extend_from_slice(&ppid_or_fsn.to_be_bytes());
        body.extend_from_slice(user_data);
        push_chunk(pkt, CHUNK_TYPE_I_DATA, flags, &body);
    }

    #[test]
    fn parse_i_data_chunk() {
        // RFC 8260, Section 2.1 — with B set, the last header word is the
        // PPID; the chunk is dispatched by PPID like DATA.
        let mut data = build_common_header(40000, 40001, 1, 0);
        push_i_data_chunk(&mut data, 0x03, 10, 2, 77, 60, b"ngap");
        let mut buf = DissectBuffer::new();
        let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(child(c, "b"), Some(&FieldValue::U8(1)));
        assert_eq!(child(c, "tsn"), Some(&FieldValue::U32(10)));
        assert_eq!(child(c, "stream_id"), Some(&FieldValue::U16(2)));
        assert_eq!(child(c, "mid"), Some(&FieldValue::U32(77)));
        assert_eq!(child(c, "ppid"), Some(&FieldValue::U32(60)));
        assert_eq!(child(c, "fsn"), None);
        assert_eq!(child(c, "ssn"), None);
        assert_eq!(
            child(c, "user_data"),
            Some(&FieldValue::Bytes(b"ngap".as_slice()))
        );
        let payloads = buf.embedded_payloads();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].range, 32..36);
        assert_eq!(
            payloads[0].next,
            DispatchHint::BySctpPpid {
                ppid: 60,
                src_port: 40000,
                dst_port: 40001
            }
        );
        assert_eq!(result.next, payloads[0].next);
    }

    #[test]
    fn i_data_fragments_not_dispatched() {
        // RFC 8260, Section 2.1 — without B the last header word is the FSN.
        let mut data = build_common_header(40000, 40001, 1, 0);
        push_i_data_chunk(&mut data, 0x02, 10, 2, 77, 60, b"first");
        push_i_data_chunk(&mut data, 0x01, 11, 2, 77, 1, b"last");
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(buf.embedded_payloads().is_empty());
        let layer = &buf.layers()[0];
        let last = chunk_children(&buf, layer, 1);
        assert_eq!(child(last, "fsn"), Some(&FieldValue::U32(1)));
        assert_eq!(child(last, "ppid"), None);

        // Shorter than the 20-byte I-DATA header: raw bytes.
        let mut data = build_common_header(40000, 40001, 1, 0);
        push_chunk(&mut data, CHUNK_TYPE_I_DATA, 0x03, &[0u8; 12]);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let c = chunk_children(&buf, &buf.layers()[0], 0);
        assert_eq!(
            child(c, "value"),
            Some(&FieldValue::Bytes([0u8; 12].as_slice()))
        );
    }

    #[test]
    fn undecoded_trailing_bytes_shown() {
        // Bytes a decoder cannot place (a malformed parameter or cause,
        // or bytes past the fixed / counted fields) stay visible.
        let cases: Vec<(u8, Vec<u8>, usize, &str)> = vec![
            // INIT: fixed part + 3 stray bytes.
            (
                1,
                [init_fixed(1, 2, 3, 4, 5), vec![0xAA, 0xBB, 0xCC]].concat(),
                20,
                "initiate_tag",
            ),
            // INIT: one good parameter, then one with Length 2.
            (
                1,
                {
                    let mut b = init_fixed(1, 2, 3, 4, 5);
                    param(&mut b, 5, &[192, 0, 2, 1]);
                    b.extend_from_slice(&[0x00, 0x05, 0x00, 0x02]);
                    b
                },
                28,
                "parameters",
            ),
            // ERROR: one good cause, then one running past the chunk.
            (
                9,
                {
                    let mut b = Vec::new();
                    cause(&mut b, 12, b"x");
                    b.extend_from_slice(&[0x00, 0x0d, 0xFF, 0xFF]);
                    b
                },
                12,
                "error_causes",
            ),
            // SHUTDOWN with 4 bytes past Cumulative TSN Ack.
            (
                7,
                vec![0, 0, 0, 1, 0xDE, 0xAD, 0xBE, 0xEF],
                8,
                "cumulative_tsn_ack",
            ),
            // SACK with both counts 0 and 8 extra bytes.
            (
                3,
                [sack_body(1, 2, &[], &[]), vec![0x11; 8]].concat(),
                16,
                "a_rwnd",
            ),
        ];
        for (ctype, body, decoded_len, decoded_field) in cases {
            let mut data = build_common_header(5000, 3868, 0, 0);
            push_chunk(&mut data, ctype, 0, &body);
            let mut buf = DissectBuffer::new();
            SctpDissector.dissect(&data, &mut buf, 0).unwrap();
            let c = chunk_children(&buf, &buf.layers()[0], 0);
            assert!(
                child(c, decoded_field).is_some(),
                "type {ctype}: {decoded_field}"
            );
            assert!(
                !c.iter()
                    .any(|f| core::ptr::eq(f.descriptor, &CHUNK_CHILD_FIELDS[CFD_VALUE])),
                "type {ctype}: no chunk-level value"
            );
            let undecoded = c.iter().find(|f| f.name() == "undecoded").unwrap();
            assert_eq!(
                undecoded.value,
                FieldValue::Bytes(&body[decoded_len - MIN_CHUNK_SIZE..]),
                "type {ctype}"
            );
            let start = COMMON_HEADER_SIZE + decoded_len;
            assert_eq!(
                undecoded.range,
                start..start + body.len() + MIN_CHUNK_SIZE - decoded_len
            );
            if let Some(FieldValue::Array(_)) = child(c, decoded_field) {
                let arr = c.iter().find(|f| f.name() == decoded_field).unwrap();
                assert_eq!(arr.range.end, start, "type {ctype}: array ends at last TLV");
            }
        }
    }

    #[test]
    fn registry_name_counts() {
        // Every permanent assignment in the IANA "SCTP Parameters" registries
        // (last updated 2026-08-13) has a name; temporary registrations and
        // reserved values do not.
        let chunk_types = (0..=u8::MAX).filter_map(sctp_chunk_type_name).count();
        assert_eq!(chunk_types, 23);
        let parameter_types = (0..=u16::MAX).filter_map(sctp_parameter_type_name).count();
        assert_eq!(parameter_types, 28);
        let cause_codes = (0..=u16::MAX).filter_map(sctp_cause_code_name).count();
        assert_eq!(cause_codes, 19);
        let ppids = (0..=5000u32).filter_map(sctp_ppid_name).count();
        assert_eq!(ppids, 73);
    }

    #[test]
    fn parameter_and_cause_display_names() {
        let mut body = init_fixed(1, 2, 3, 4, 5);
        param(&mut body, 5, &[192, 0, 2, 1]);
        let mut data = build_common_header(5000, 3868, 0, 0);
        push_chunk(&mut data, 1, 0, &body);
        let mut cause_body = Vec::new();
        cause(&mut cause_body, 12, b"bye");
        push_chunk(&mut data, 6, 0, &cause_body);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();

        let label = |name: &str| {
            let (idx, _) = buf
                .fields()
                .iter()
                .enumerate()
                .find(|(_, f)| f.name() == name)
                .unwrap();
            buf.resolve_container_display_name(idx as u32)
        };
        assert_eq!(label("parameter"), Some("IPv4 Address"));
        assert_eq!(label("error_cause"), Some("User-Initiated Abort"));

        let scalar = |name: &str, value: FieldValue<'static>| {
            let f = buf.fields().iter().find(|f| f.name() == name).unwrap();
            f.descriptor.display_fn.unwrap()(&value, &[])
        };
        assert_eq!(
            scalar("code", FieldValue::U16(12)),
            Some("User-Initiated Abort")
        );
        assert_eq!(scalar("code", FieldValue::U8(12)), None);
        let ppid_display = CHUNK_CHILD_FIELDS[CFD_PPID].display_fn.unwrap();
        assert_eq!(ppid_display(&FieldValue::U8(46), &[]), None);
        let param_type = buf
            .fields()
            .iter()
            .find(|f| f.name() == "type" && f.value == FieldValue::U16(5))
            .unwrap();
        let display = param_type.descriptor.display_fn.unwrap();
        assert_eq!(display(&FieldValue::U16(5), &[]), Some("IPv4 Address"));
        assert_eq!(display(&FieldValue::U8(5), &[]), None);

        // Containers without a type/code child have no label.
        for fd in [&FD_PARAMETER, &FD_ERROR_CAUSE] {
            let display = fd.display_fn.unwrap();
            assert_eq!(display(&FieldValue::Object(0..0), &[]), None);
            assert_eq!(display(&FieldValue::U8(0), &[]), None);
        }
    }

    #[test]
    fn common_header_only_no_chunks_field() {
        let data = build_common_header(12345, 3868, 0, 0);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "chunks").is_none());
    }

    #[test]
    fn dissect_with_offset() {
        let data = build_common_header(12345, 3868, 0, 0);
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&data, &mut buf, 100).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 100..100 + COMMON_HEADER_SIZE);
    }

    #[test]
    fn field_descriptors_list() {
        let descs = SctpDissector.field_descriptors();
        assert_eq!(descs.len(), 5);
        assert_eq!(descs[FD_SRC_PORT].name, "src_port");
        assert_eq!(descs[FD_DST_PORT].name, "dst_port");
        assert_eq!(descs[FD_VERIFICATION_TAG].name, "verification_tag");
        assert_eq!(descs[FD_CHECKSUM].name, "checksum");
        assert_eq!(descs[FD_CHUNKS].name, "chunks");
    }

    #[test]
    fn chunk_container_resolves_to_chunk_name() {
        // Single INIT chunk so the container label resolves to "INIT"
        // instead of duplicating the inner "Chunk Type" label.
        let mut pkt = build_common_header(36412, 3868, 0xAABB_CCDD, 0x1234_5678);
        push_chunk(&mut pkt, 1, 0, &[0u8; 16]); // INIT
        let mut buf = DissectBuffer::new();
        SctpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let (idx, field) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "chunk")
            .expect("chunk container not found");
        assert!(matches!(field.value, FieldValue::Object(_)));
        assert_eq!(field.display_name(), "Chunk");
        assert_eq!(buf.resolve_container_display_name(idx as u32), Some("INIT"));
    }

    #[test]
    fn references_and_layer() {
        let references = SctpDissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(SctpDissector.layer(), Some(ProtocolLayer::Transport));
    }
}
