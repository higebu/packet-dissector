//! DTLS (Datagram Transport Layer Security) record layer dissector.
//!
//! Parses every record in a datagram and emits one `DTLS` layer per record.
//! DTLS runs over UDP, so a datagram may carry several records
//! (RFC 9147, Section 4 — <https://www.rfc-editor.org/rfc/rfc9147#section-4>:
//! "As with previous versions of DTLS, multiple DTLSPlaintext and
//! DTLSCiphertext records can be included in the same underlying transport
//! datagram.").
//!
//! The first octet of each record selects its format
//! (RFC 9147, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc9147#section-4.1>):
//!
//! - 20 to 26: a `DTLSPlaintext` record with a 13-octet header (type,
//!   version, epoch, 48-bit sequence number, length). Handshake, Alert,
//!   Heartbeat and ACK payloads are decoded; the handshake message bodies
//!   are decoded by the TLS handshake decoders, with the DTLS `cookie` of
//!   ClientHello and HelloVerifyRequest.
//! - 25 (`tls12_cid`, RFC 9146): the header is decoded up to the sequence
//!   number. The Connection ID length is negotiated and not carried on the
//!   wire, so the CID, length and encrypted content are reported as one
//!   opaque `cid_and_record` field that runs to the end of the datagram.
//! - 32 to 63 (leading bits `001`): a DTLS 1.3 `DTLSCiphertext` record with
//!   the unified header. Its flags, epoch bits, sequence number and length
//!   are decoded. With the C bit set, the Connection ID length is unknown,
//!   so everything after the first octet is reported as `cid_and_record`.
//! - Anything else is rejected.
//!
//! A handshake message body is decoded only when the record carries the
//! whole message (`fragment_offset` 0 and `fragment_length` equal to
//! `length`). Handshake records in an epoch other than 0, and records whose
//! fragment headers do not exactly fill the record, are reported as
//! `opaque_handshake`: a DTLS 1.2 handshake record in epoch 1 or later is
//! encrypted (RFC 6347, Section 4.1 —
//! <https://www.rfc-editor.org/rfc/rfc6347#section-4.1>: "The epoch number
//! is initially zero and is incremented each time a ChangeCipherSpec
//! message is sent."). Messages are not reassembled across records or
//! datagrams, and nothing is decrypted.
//!
//! ## References
//! - RFC 9147 (DTLS 1.3, obsoletes RFC 6347): <https://www.rfc-editor.org/rfc/rfc9147>
//! - RFC 6347 (DTLS 1.2): <https://www.rfc-editor.org/rfc/rfc6347>
//! - RFC 4347 (DTLS 1.0): <https://www.rfc-editor.org/rfc/rfc4347>
//! - RFC 9146 (Connection Identifiers for DTLS 1.2): <https://www.rfc-editor.org/rfc/rfc9146>
//! - RFC 6520 (TLS and DTLS Heartbeat Extension): <https://www.rfc-editor.org/rfc/rfc6520>
//! - IANA TLS Parameters: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml>

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u64};

use crate::handshake::{
    FD_HANDSHAKE, HANDSHAKE_BODY_FIELD_COUNT, HANDSHAKE_BODY_FIELDS, HANDSHAKE_LENGTH_FIELD,
    HANDSHAKE_TYPE_CLIENT_HELLO, HANDSHAKE_TYPE_FIELD, HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST,
    HANDSHAKE_TYPE_SERVER_HELLO, HelloVersion, concat_fields, parse_body,
};
use crate::{
    CONTENT_TYPE_ALERT, CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
    CONTENT_TYPE_HEARTBEAT, FD_ALERT_DESCRIPTION, FD_ALERT_LEVEL, FD_ENCRYPTED_ALERT,
    FD_ENCRYPTED_HEARTBEAT, FD_HEARTBEAT_TYPE, FD_PADDING, FD_PAYLOAD, FD_PAYLOAD_LENGTH,
    FD_PAYLOAD_LENGTH_EXCEEDS_RECORD, FIELD_DESCRIPTORS as TLS_FIELD_DESCRIPTORS,
    MAX_RECORD_LENGTH, content_type_name, dissect_alert_record, dissect_heartbeat_record,
    is_wire_handshake_type, version_name,
};

/// DTLS 1.0 wire version {254, 255}.
///
/// RFC 9147, Section 5.3 — <https://www.rfc-editor.org/rfc/rfc9147#section-5.3>:
/// "The supported_versions entries for DTLS 1.0 and DTLS 1.2 are 0xfeff and
/// 0xfefd (to match the wire versions).  The value 0xfefc is used to
/// indicate DTLS 1.3."
pub(crate) const DTLS_1_0_VERSION: u16 = 0xFEFF;
/// DTLS 1.2 wire version {254, 253}, also DTLS 1.3's `legacy_record_version`.
pub(crate) const DTLS_1_2_VERSION: u16 = 0xFEFD;
/// DTLS 1.3 `supported_versions` value.
pub(crate) const DTLS_1_3_VERSION: u16 = 0xFEFC;

/// Major version octet of every DTLS wire version (1's complement of 1).
///
/// RFC 6347, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc6347#section-4.1>:
/// "The version value of 254.253 is the 1's complement of DTLS version
/// 1.2."
const DTLS_MAJOR_VERSION: u8 = 254;

/// `tls12_cid(25)` — RFC 9146, Section 4 — <https://www.rfc-editor.org/rfc/rfc9146#section-4>
pub(crate) const CONTENT_TYPE_TLS12_CID: u8 = 25;
/// `ack(26)` — RFC 9147, Section 7 — <https://www.rfc-editor.org/rfc/rfc9147#section-7>
pub(crate) const CONTENT_TYPE_ACK: u8 = 26;

/// `DTLSPlaintext` header size: type(1) + version(2) + epoch(2) +
/// sequence_number(6) + length(2).
///
/// ```text
/// RFC 9147, Section 4 — https://www.rfc-editor.org/rfc/rfc9147#section-4
///
/// struct {
///     ContentType type;
///     ProtocolVersion legacy_record_version;
///     uint16 epoch = 0
///     uint48 sequence_number;
///     uint16 length;
///     opaque fragment[DTLSPlaintext.length];
/// } DTLSPlaintext;
/// ```
const PLAINTEXT_HEADER_SIZE: usize = 13;

/// Bytes of a `tls12_cid` record before the CID: type, version, epoch and
/// sequence number.
///
/// ```text
/// RFC 9146, Section 4 — https://www.rfc-editor.org/rfc/rfc9146#section-4
///
/// struct {
///     ContentType outer_type = tls12_cid;
///     ProtocolVersion version;
///     uint16 epoch;
///     uint48 sequence_number;
///     opaque cid[cid_length];               // New field
///     uint16 length;
///     opaque enc_content[DTLSCiphertext.length];
/// } DTLSCiphertext;
/// ```
const TLS12_CID_PREFIX_SIZE: usize = 11;

/// DTLS handshake header size: msg_type(1) + length(3) + message_seq(2) +
/// fragment_offset(3) + fragment_length(3).
///
/// ```text
/// RFC 9147, Section 5.2 — https://www.rfc-editor.org/rfc/rfc9147#section-5.2
///
/// struct {
///     HandshakeType msg_type;    /* handshake type */
///     uint24 length;             /* bytes in message */
///     uint16 message_seq;        /* DTLS-required field */
///     uint24 fragment_offset;    /* DTLS-required field */
///     uint24 fragment_length;    /* DTLS-required field */
///     ...
/// } DTLSHandshake;
/// ```
const HANDSHAKE_HEADER_SIZE: usize = 12;

/// Size of one `RecordNumber` in an ACK: uint64 epoch + uint64
/// sequence_number.
///
/// RFC 9147, Section 4 — <https://www.rfc-editor.org/rfc/rfc9147#section-4>
const RECORD_NUMBER_SIZE: usize = 16;

// DTLS 1.3 unified header, first octet `0 0 1 C S L E E`.
// RFC 9147, Section 4 — https://www.rfc-editor.org/rfc/rfc9147#section-4
/// Mask of the three fixed high bits of the unified header.
const UNIFIED_HEADER_FIXED_MASK: u8 = 0b1110_0000;
/// "The three high bits of the first byte of the unified header are set to
/// 001."
const UNIFIED_HEADER_FIXED_BITS: u8 = 0b0010_0000;
/// "The C bit (0x10) is set if the Connection ID is present."
const UNIFIED_HEADER_C: u8 = 0x10;
/// "The S bit (0x08) indicates the size of the sequence number. 0 means an
/// 8-bit sequence number, 1 means 16-bit."
const UNIFIED_HEADER_S: u8 = 0x08;
/// "The L bit (0x04) is set if the length is present."
const UNIFIED_HEADER_L: u8 = 0x04;
/// "The two low bits (0x03) include the low-order two bits of the epoch."
const UNIFIED_HEADER_EPOCH: u8 = 0x03;

/// Largest `length` accepted in a unified header: 2^14 + 256.
///
/// RFC 9147, Section 4 — <https://www.rfc-editor.org/rfc/rfc9147#section-4>:
/// "Length:  Identical to the length field in a TLS 1.3 record." —
/// RFC 9846, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc9846#section-5.2>:
/// "The length MUST NOT exceed 2^14 + 256 bytes."
const MAX_CIPHERTEXT_LENGTH: usize = (1 << 14) + 256;

/// Layer label for DTLS 1.3 records.
const LABEL_DTLS13: &str = "DTLSv1.3";

/// Returns the layer label for a DTLS version.
fn dtls_version_short_name(version: u16) -> Option<&'static str> {
    match version {
        DTLS_1_0_VERSION => Some("DTLSv1.0"),
        DTLS_1_2_VERSION => Some("DTLSv1.2"),
        DTLS_1_3_VERSION => Some(LABEL_DTLS13),
        _ => None,
    }
}

/// Layer label for a record without a ClientHello / ServerHello.
///
/// RFC 9147, Section 4 — <https://www.rfc-editor.org/rfc/rfc9147#section-4>:
/// `legacy_record_version` "MUST be set to {254, 253} for all records other
/// than the initial ClientHello". So {254, 253} does not tell DTLS 1.2 from
/// DTLS 1.3, while {254, 255} can only be DTLS 1.0 (or an initial DTLS 1.3
/// ClientHello, which is labelled from its body instead).
fn record_version_label(version: u16) -> Option<&'static str> {
    match version {
        DTLS_1_0_VERSION => dtls_version_short_name(version),
        _ => None,
    }
}

/// Whether `ht` is a handshake type that can appear in a DTLS record: the
/// TLS types plus `hello_verify_request(3)`
/// (RFC 6347, Section 4.2.1 — <https://www.rfc-editor.org/rfc/rfc6347#section-4.2.1>),
/// `request_connection_id(9)` and `new_connection_id(10)`
/// (RFC 9147, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc9147#section-5.2>).
fn is_dtls_handshake_type(ht: u8) -> bool {
    is_wire_handshake_type(ht) || matches!(ht, HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST | 9 | 10)
}

/// Field descriptor indices for [`DTLS_HANDSHAKE_CHILD_FIELDS`].
const DHFD_TYPE: usize = 0;
const DHFD_LENGTH: usize = 1;
const DHFD_MESSAGE_SEQ: usize = 2;
const DHFD_FRAGMENT_OFFSET: usize = 3;
const DHFD_FRAGMENT_LENGTH: usize = 4;
const DHFD_COOKIE: usize = 5;
/// Number of DTLS handshake header fields before the body fields.
const DTLS_HANDSHAKE_HEADER_FIELD_COUNT: usize = 6;

/// Child fields of a DTLS handshake message object: the DTLS handshake
/// header, the DTLS `cookie`, then the body fields shared with TLS.
///
/// RFC 9147, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc9147#section-5.2>
/// RFC 6347, Section 4.2.1 — <https://www.rfc-editor.org/rfc/rfc6347#section-4.2.1>
static DTLS_HANDSHAKE_CHILD_FIELDS: &[FieldDescriptor] = &concat_fields::<
    DTLS_HANDSHAKE_HEADER_FIELD_COUNT,
    HANDSHAKE_BODY_FIELD_COUNT,
    { DTLS_HANDSHAKE_HEADER_FIELD_COUNT + HANDSHAKE_BODY_FIELD_COUNT },
>(
    [
        HANDSHAKE_TYPE_FIELD,
        HANDSHAKE_LENGTH_FIELD,
        FieldDescriptor::new("message_seq", "Message Sequence", FieldType::U16),
        FieldDescriptor::new("fragment_offset", "Fragment Offset", FieldType::U32),
        FieldDescriptor::new("fragment_length", "Fragment Length", FieldType::U32),
        // ClientHello and HelloVerifyRequest only.
        FieldDescriptor::new("cookie", "Cookie", FieldType::Bytes).optional(),
    ],
    HANDSHAKE_BODY_FIELDS,
);

/// Child fields of an ACK `RecordNumber` object.
///
/// ```text
/// RFC 9147, Section 4 — https://www.rfc-editor.org/rfc/rfc9147#section-4
///
/// struct {
///     uint64 epoch;
///     uint64 sequence_number;
/// } RecordNumber;
/// ```
static RECORD_NUMBER_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("epoch", "Epoch", FieldType::U64),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U64),
];

/// Container descriptor for one ACK `RecordNumber`.
static FD_RECORD_NUMBER: FieldDescriptor =
    FieldDescriptor::new("record_number", "Record Number", FieldType::Object);

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_CONTENT_TYPE: usize = 0;
const FD_VERSION: usize = 1;
const FD_EPOCH: usize = 2;
const FD_SEQUENCE_NUMBER: usize = 3;
const FD_LENGTH: usize = 4;
const FD_CONNECTION_ID_PRESENT: usize = 5;
const FD_SEQUENCE_NUMBER_16BIT: usize = 6;
const FD_LENGTH_PRESENT: usize = 7;
const FD_EPOCH_LOW_BITS: usize = 8;
const FD_ENCRYPTED_SEQUENCE_NUMBER: usize = 9;
const FD_ENCRYPTED_RECORD: usize = 10;
const FD_CID_AND_RECORD: usize = 11;
const FD_HANDSHAKE_MESSAGES: usize = 12;
const FD_OPAQUE_HANDSHAKE: usize = 13;
const FD_RECORD_NUMBERS: usize = 14;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // --- DTLSPlaintext and tls12_cid headers ---
    // RFC 6347, Section 4.1 — https://www.rfc-editor.org/rfc/rfc6347#section-4.1
    FieldDescriptor {
        name: "content_type",
        display_name: "Content Type",
        field_type: FieldType::U8,
        optional: true,
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
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(ver) => Some(version_name(*ver)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("epoch", "Epoch", FieldType::U16).optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U64).optional(),
    FieldDescriptor::new("length", "Length", FieldType::U16).optional(),
    // --- DTLS 1.3 unified header ---
    // RFC 9147, Section 4 — https://www.rfc-editor.org/rfc/rfc9147#section-4
    FieldDescriptor::new(
        "connection_id_present",
        "Connection ID Present",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "sequence_number_16bit",
        "16-bit Sequence Number",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("length_present", "Length Present", FieldType::U8).optional(),
    FieldDescriptor::new("epoch_low_bits", "Epoch (Low Bits)", FieldType::U8).optional(),
    // Record sequence numbers are encrypted in DTLS 1.3
    // (RFC 9147, Section 4.2.3 — https://www.rfc-editor.org/rfc/rfc9147#section-4.2.3).
    FieldDescriptor::new(
        "encrypted_sequence_number",
        "Encrypted Sequence Number",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("encrypted_record", "Encrypted Record", FieldType::Bytes).optional(),
    // The CID length is negotiated, not carried on the wire, so the CID and
    // everything after it are opaque (RFC 9146, Section 4 —
    // https://www.rfc-editor.org/rfc/rfc9146#section-4).
    FieldDescriptor::new(
        "cid_and_record",
        "Connection ID and Record",
        FieldType::Bytes,
    )
    .optional(),
    // --- Handshake records (content_type == 22) ---
    FieldDescriptor::new("handshake_messages", "Handshake Messages", FieldType::Array)
        .optional()
        .with_children(DTLS_HANDSHAKE_CHILD_FIELDS),
    FieldDescriptor::new(
        "opaque_handshake",
        "Encrypted or Malformed Handshake Data",
        FieldType::Bytes,
    )
    .optional(),
    // --- ACK records (content_type == 26) ---
    // RFC 9147, Section 7 — https://www.rfc-editor.org/rfc/rfc9147#section-7
    FieldDescriptor::new("record_numbers", "Record Numbers", FieldType::Array)
        .optional()
        .with_children(RECORD_NUMBER_FIELDS),
    // --- Alert and Heartbeat records, decoded as in TLS ---
    TLS_FIELD_DESCRIPTORS[FD_ALERT_LEVEL],
    TLS_FIELD_DESCRIPTORS[FD_ALERT_DESCRIPTION],
    TLS_FIELD_DESCRIPTORS[FD_ENCRYPTED_ALERT],
    TLS_FIELD_DESCRIPTORS[FD_HEARTBEAT_TYPE],
    TLS_FIELD_DESCRIPTORS[FD_PAYLOAD_LENGTH],
    TLS_FIELD_DESCRIPTORS[FD_PAYLOAD],
    TLS_FIELD_DESCRIPTORS[FD_PADDING],
    TLS_FIELD_DESCRIPTORS[FD_PAYLOAD_LENGTH_EXCEEDS_RECORD],
    TLS_FIELD_DESCRIPTORS[FD_ENCRYPTED_HEARTBEAT],
];

/// Shorthand for a record field descriptor.
fn fd(idx: usize) -> &'static FieldDescriptor {
    &FIELD_DESCRIPTORS[idx]
}

/// Shorthand for a handshake child field descriptor.
fn dhfd(idx: usize) -> &'static FieldDescriptor {
    &DTLS_HANDSHAKE_CHILD_FIELDS[idx]
}

/// Specification references for the DTLS dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 9147",
        "The Datagram Transport Layer Security (DTLS) Protocol Version 1.3",
        "https://www.rfc-editor.org/rfc/rfc9147",
    ),
    SpecReference::new(
        "RFC 6347",
        "Datagram Transport Layer Security Version 1.2",
        "https://www.rfc-editor.org/rfc/rfc6347",
    ),
    SpecReference::new(
        "RFC 4347",
        "Datagram Transport Layer Security",
        "https://www.rfc-editor.org/rfc/rfc4347",
    ),
    SpecReference::new(
        "RFC 9146",
        "Connection Identifier for DTLS 1.2",
        "https://www.rfc-editor.org/rfc/rfc9146",
    ),
    SpecReference::new(
        "RFC 6520",
        "Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS) Heartbeat Extension",
        "https://www.rfc-editor.org/rfc/rfc6520",
    ),
];

/// DTLS record layer dissector (DTLS 1.0, 1.2 and 1.3).
///
/// Emits one `DTLS` layer per record in the datagram and consumes every
/// record. A datagram that ends inside a record yields
/// [`PacketError::Truncated`]; the layers of the preceding records remain
/// in the buffer.
///
/// - `DTLSPlaintext` records (first octet 20 to 26) have their 13-octet
///   header decoded, plus Handshake, Alert, Heartbeat and ACK payloads. A
///   handshake body is decoded only for an unfragmented message in epoch 0;
///   the ClientHello and HelloVerifyRequest `cookie` is reported.
/// - `tls12_cid` records (RFC 9146) and DTLS 1.3 unified headers with the C
///   bit set are decoded up to the Connection ID, whose length is not carried
///   on the wire; the rest of the datagram is reported as `cid_and_record`.
/// - DTLS 1.3 unified headers (first octet `001CSLEE`) have their flags,
///   epoch bits, encrypted sequence number and length decoded.
///
/// Nothing is decrypted and handshake messages are not reassembled.
///
/// ## References
/// - RFC 9147 (DTLS 1.3): <https://www.rfc-editor.org/rfc/rfc9147>
/// - RFC 6347 (DTLS 1.2): <https://www.rfc-editor.org/rfc/rfc6347>
/// - RFC 9146 (Connection Identifiers for DTLS 1.2): <https://www.rfc-editor.org/rfc/rfc9146>
pub struct DtlsDissector;

impl Dissector for DtlsDissector {
    fn name(&self) -> &'static str {
        "Datagram Transport Layer Security"
    }

    fn short_name(&self) -> &'static str {
        "DTLS"
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
        if data.is_empty() {
            return Err(PacketError::Truncated {
                expected: 1,
                actual: 0,
            });
        }
        let mut pos = 0;
        while pos < data.len() {
            pos += dissect_record(data, pos, offset, buf)?;
        }
        Ok(DissectResult::new(pos, DispatchHint::End))
    }
}

/// Return a [`PacketError::Truncated`] unless `data` holds `needed` bytes
/// from `pos`.
fn require(data: &[u8], pos: usize, needed: usize) -> Result<(), PacketError> {
    let expected = pos + needed;
    if data.len() < expected {
        return Err(PacketError::Truncated {
            expected,
            actual: data.len(),
        });
    }
    Ok(())
}

/// Dissect the record that starts at `data[pos]` (a non-empty remainder).
/// Returns the number of bytes it occupies.
///
/// RFC 9147, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc9147#section-4.1>
fn dissect_record<'pkt>(
    data: &'pkt [u8],
    pos: usize,
    base: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<usize, PacketError> {
    let first = data[pos];
    // "If the first byte is any other value, then receivers MUST check to
    // see if the leading bits of the first byte are 001.  If so, the
    // implementation MUST process the record as DTLSCiphertext"
    if first & UNIFIED_HEADER_FIXED_MASK == UNIFIED_HEADER_FIXED_BITS {
        return dissect_unified_record(data, pos, base, buf);
    }
    // Figure 5: OCT 20 to 26 are the content types used outside the
    // unified header; "Otherwise, the record MUST be rejected".
    if !(CONTENT_TYPE_CHANGE_CIPHER_SPEC..=CONTENT_TYPE_ACK).contains(&first) {
        return Err(PacketError::InvalidFieldValue {
            field: "content_type",
            value: u32::from(first),
        });
    }
    dissect_plaintext_record(data, pos, base, buf)
}

/// Push the type, version, epoch and sequence number shared by
/// `DTLSPlaintext` and the `tls12_cid` record, whose first 11 bytes are
/// `rec[..11]`, located at packet offset `at`.
fn push_record_prefix<'pkt>(rec: &'pkt [u8], at: usize, buf: &mut DissectBuffer<'pkt>) {
    // Bounds are checked by the caller.
    let version = u16::from_be_bytes([rec[1], rec[2]]);
    let epoch = u16::from_be_bytes([rec[3], rec[4]]);
    let seq = rec[5..TLS12_CID_PREFIX_SIZE]
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    buf.push_field(fd(FD_CONTENT_TYPE), FieldValue::U8(rec[0]), at..at + 1);
    buf.push_field(fd(FD_VERSION), FieldValue::U16(version), at + 1..at + 3);
    buf.push_field(fd(FD_EPOCH), FieldValue::U16(epoch), at + 3..at + 5);
    buf.push_field(
        fd(FD_SEQUENCE_NUMBER),
        FieldValue::U64(seq),
        at + 5..at + TLS12_CID_PREFIX_SIZE,
    );
}

/// Dissect a `DTLSPlaintext` record, or a DTLS 1.2 `tls12_cid` record.
///
/// RFC 6347, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc6347#section-4.1>
/// RFC 9146, Section 4 — <https://www.rfc-editor.org/rfc/rfc9146#section-4>
fn dissect_plaintext_record<'pkt>(
    data: &'pkt [u8],
    pos: usize,
    base: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<usize, PacketError> {
    let rec = &data[pos..];
    let ct = rec[0];
    // A tls12_cid record needs at least one CID byte: "The CID field is
    // present and contains one or more bytes." (RFC 9146, Section 4).
    let header_size = if ct == CONTENT_TYPE_TLS12_CID {
        TLS12_CID_PREFIX_SIZE + 1
    } else {
        PLAINTEXT_HEADER_SIZE
    };
    require(data, pos, header_size)?;

    let version = read_be_u16(rec, 1)?;
    if rec[1] != DTLS_MAJOR_VERSION {
        return Err(PacketError::InvalidFieldValue {
            field: "version",
            value: u32::from(version),
        });
    }
    let at = base + pos;

    if ct == CONTENT_TYPE_TLS12_CID {
        buf.begin_layer("DTLS", None, FIELD_DESCRIPTORS, at..at + rec.len());
        push_record_prefix(rec, at, buf);
        buf.push_field(
            fd(FD_CID_AND_RECORD),
            FieldValue::Bytes(&rec[TLS12_CID_PREFIX_SIZE..]),
            at + TLS12_CID_PREFIX_SIZE..at + rec.len(),
        );
        // tls12_cid exists only in DTLS 1.2; DTLS 1.3 carries the CID in
        // the unified header (RFC 9147, Section 4 —
        // https://www.rfc-editor.org/rfc/rfc9147#section-4).
        if let Some(layer) = buf.last_layer_mut() {
            layer.display_name = dtls_version_short_name(DTLS_1_2_VERSION);
        }
        buf.end_layer();
        return Ok(rec.len());
    }

    let length = read_be_u16(rec, 11)?;
    // RFC 6347, Section 4.1: length is "Identical to the length field in a
    // TLS 1.2 record."
    if usize::from(length) > MAX_RECORD_LENGTH {
        return Err(PacketError::InvalidFieldValue {
            field: "length",
            value: u32::from(length),
        });
    }
    let record_len = PLAINTEXT_HEADER_SIZE + usize::from(length);
    require(data, pos, record_len)?;
    let epoch = u16::from_be_bytes([rec[3], rec[4]]);

    buf.begin_layer("DTLS", None, FIELD_DESCRIPTORS, at..at + record_len);
    push_record_prefix(rec, at, buf);
    buf.push_field(
        fd(FD_LENGTH),
        FieldValue::U16(length),
        at + 11..at + PLAINTEXT_HEADER_SIZE,
    );

    let payload = &rec[PLAINTEXT_HEADER_SIZE..record_len];
    let payload_offset = at + PLAINTEXT_HEADER_SIZE;
    let label = match ct {
        CONTENT_TYPE_HANDSHAKE => {
            dissect_handshake_record(payload, payload_offset, epoch, version, buf)
        }
        CONTENT_TYPE_ALERT => {
            dissect_alert_record(payload, payload_offset, buf);
            record_version_label(version)
        }
        CONTENT_TYPE_HEARTBEAT => {
            dissect_heartbeat_record(payload, payload_offset, buf);
            record_version_label(version)
        }
        CONTENT_TYPE_ACK => {
            dissect_ack(payload, payload_offset, buf);
            // ACK is defined by DTLS 1.3 (RFC 9147, Section 7 —
            // https://www.rfc-editor.org/rfc/rfc9147#section-7).
            Some(LABEL_DTLS13)
        }
        _ => record_version_label(version),
    };
    if let Some(layer) = buf.last_layer_mut() {
        layer.display_name = label;
    }
    buf.end_layer();
    Ok(record_len)
}

/// Dissect a DTLS 1.3 `DTLSCiphertext` record with the unified header.
///
/// ```text
/// RFC 9147, Section 4 — https://www.rfc-editor.org/rfc/rfc9147#section-4
///
///     0 1 2 3 4 5 6 7
///     +-+-+-+-+-+-+-+-+
///     |0|0|1|C|S|L|E E|
///     +-+-+-+-+-+-+-+-+
///     | Connection ID |
///     | (if any,      |
///     /  length as    /
///     |  negotiated)  |
///     +-+-+-+-+-+-+-+-+
///     |  8 or 16 bit  |
///     |Sequence Number|
///     +-+-+-+-+-+-+-+-+
///     | 16 bit Length |
///     | (if present)  |
///     +-+-+-+-+-+-+-+-+
/// ```
fn dissect_unified_record<'pkt>(
    data: &'pkt [u8],
    pos: usize,
    base: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<usize, PacketError> {
    let rec = &data[pos..];
    let flags = rec[0];
    let has_cid = flags & UNIFIED_HEADER_C != 0;
    let seq_16bit = flags & UNIFIED_HEADER_S != 0;
    let has_length = flags & UNIFIED_HEADER_L != 0;
    let seq_size = if seq_16bit { 2 } else { 1 };
    let length_size = if has_length { 2 } else { 0 };
    // A present CID has at least one byte (RFC 9146, Section 4 —
    // https://www.rfc-editor.org/rfc/rfc9146#section-4).
    let cid_min = usize::from(has_cid);
    require(data, pos, 1 + cid_min + seq_size + length_size)?;

    let record_len = if has_cid {
        // "Connection ID:  Variable-length CID." Its length was negotiated,
        // so the sequence number and length cannot be located: the rest of
        // the datagram is reported as one opaque field.
        rec.len()
    } else if has_length {
        let length = read_be_u16(rec, 1 + seq_size)?;
        if usize::from(length) > MAX_CIPHERTEXT_LENGTH {
            return Err(PacketError::InvalidFieldValue {
                field: "length",
                value: u32::from(length),
            });
        }
        let record_len = 1 + seq_size + length_size + usize::from(length);
        require(data, pos, record_len)?;
        record_len
    } else {
        // "The length field MAY be omitted by clearing the L bit, which
        // means that the record consumes the entire rest of the datagram in
        // the lower level transport."
        rec.len()
    };

    let at = base + pos;
    buf.begin_layer(
        "DTLS",
        Some(LABEL_DTLS13),
        FIELD_DESCRIPTORS,
        at..at + record_len,
    );
    let flag_range = at..at + 1;
    buf.push_field(
        fd(FD_CONNECTION_ID_PRESENT),
        FieldValue::U8(u8::from(has_cid)),
        flag_range.clone(),
    );
    buf.push_field(
        fd(FD_SEQUENCE_NUMBER_16BIT),
        FieldValue::U8(u8::from(seq_16bit)),
        flag_range.clone(),
    );
    buf.push_field(
        fd(FD_LENGTH_PRESENT),
        FieldValue::U8(u8::from(has_length)),
        flag_range.clone(),
    );
    buf.push_field(
        fd(FD_EPOCH_LOW_BITS),
        FieldValue::U8(flags & UNIFIED_HEADER_EPOCH),
        flag_range,
    );

    if has_cid {
        buf.push_field(
            fd(FD_CID_AND_RECORD),
            FieldValue::Bytes(&rec[1..]),
            at + 1..at + record_len,
        );
    } else {
        let seq = if seq_16bit {
            read_be_u16(rec, 1)?
        } else {
            u16::from(rec[1])
        };
        buf.push_field(
            fd(FD_ENCRYPTED_SEQUENCE_NUMBER),
            FieldValue::U16(seq),
            at + 1..at + 1 + seq_size,
        );
        let header_len = 1 + seq_size + length_size;
        if has_length {
            buf.push_field(
                fd(FD_LENGTH),
                FieldValue::U16(read_be_u16(rec, 1 + seq_size)?),
                at + 1 + seq_size..at + header_len,
            );
        }
        if record_len > header_len {
            buf.push_field(
                fd(FD_ENCRYPTED_RECORD),
                FieldValue::Bytes(&rec[header_len..record_len]),
                at + header_len..at + record_len,
            );
        }
    }
    buf.end_layer();
    Ok(record_len)
}

/// A DTLS handshake message header.
struct HandshakeHeader {
    msg_type: u8,
    length: u32,
    message_seq: u16,
    fragment_offset: u32,
    fragment_length: u32,
}

/// Read the DTLS handshake header at `payload[pos..]`, if it fits.
///
/// RFC 9147, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc9147#section-5.2>
fn read_handshake_header(payload: &[u8], pos: usize) -> Option<HandshakeHeader> {
    let h = payload.get(pos..pos.checked_add(HANDSHAKE_HEADER_SIZE)?)?;
    let u24 = |i: usize| u32::from_be_bytes([0, h[i], h[i + 1], h[i + 2]]);
    Some(HandshakeHeader {
        msg_type: h[0],
        length: u24(1),
        message_seq: u16::from_be_bytes([h[4], h[5]]),
        fragment_offset: u24(6),
        fragment_length: u24(9),
    })
}

/// Whether `payload` is a sequence of plaintext DTLS handshake fragments
/// with known types, each lying within its message
/// (`fragment_offset + fragment_length <= length`), that exactly fills it.
///
/// Each DTLS record carries whole fragments: RFC 6347, Section 4.2.3 —
/// <https://www.rfc-editor.org/rfc/rfc6347#section-4.2.3>: "each DTLS
/// message MUST fit within a single transport layer datagram" and
/// "When transmitting the handshake message, the sender divides the
/// message into a series of N contiguous data ranges."
fn is_plaintext_handshake(payload: &[u8]) -> bool {
    let mut pos = 0;
    while pos < payload.len() {
        let Some(h) = read_handshake_header(payload, pos) else {
            return false;
        };
        if !is_dtls_handshake_type(h.msg_type)
            || u64::from(h.fragment_offset) + u64::from(h.fragment_length) > u64::from(h.length)
        {
            return false;
        }
        pos += HANDSHAKE_HEADER_SIZE;
        let frag_len = h.fragment_length as usize;
        if frag_len > payload.len() - pos {
            return false;
        }
        pos += frag_len;
    }
    true
}

/// Dissect the payload of a Handshake record and return the layer label.
///
/// RFC 6347, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc6347#section-4.2.2>
/// RFC 9147, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc9147#section-5.2>
fn dissect_handshake_record<'pkt>(
    payload: &'pkt [u8],
    offset: usize,
    epoch: u16,
    record_version: u16,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<&'static str> {
    if payload.is_empty() {
        return record_version_label(record_version);
    }
    // A handshake record in a non-zero epoch is protected (RFC 6347,
    // Section 4.1 — https://www.rfc-editor.org/rfc/rfc6347#section-4.1);
    // DTLS 1.3 never sends DTLSPlaintext records with a non-zero epoch
    // (RFC 9147, Section 4 — "uint16 epoch = 0").
    if epoch != 0 || !is_plaintext_handshake(payload) {
        buf.push_field(
            fd(FD_OPAQUE_HANDSHAKE),
            FieldValue::Bytes(payload),
            offset..offset + payload.len(),
        );
        return record_version_label(record_version);
    }

    let mut hello: Option<HelloVersion> = None;
    let mut saw_hello = false;
    let arr = buf.begin_container(
        fd(FD_HANDSHAKE_MESSAGES),
        FieldValue::Array(0..0),
        offset..offset + payload.len(),
    );
    let mut pos = 0;
    while let Some(h) = read_handshake_header(payload, pos) {
        let body_start = pos + HANDSHAKE_HEADER_SIZE;
        let body_end = body_start + h.fragment_length as usize;
        let Some(body) = payload.get(body_start..body_end) else {
            break;
        };
        let at = offset + pos;
        let obj = buf.begin_container(
            &FD_HANDSHAKE,
            FieldValue::Object(0..0),
            at..offset + body_end,
        );
        buf.push_field(dhfd(DHFD_TYPE), FieldValue::U8(h.msg_type), at..at + 1);
        buf.push_field(dhfd(DHFD_LENGTH), FieldValue::U32(h.length), at + 1..at + 4);
        buf.push_field(
            dhfd(DHFD_MESSAGE_SEQ),
            FieldValue::U16(h.message_seq),
            at + 4..at + 6,
        );
        buf.push_field(
            dhfd(DHFD_FRAGMENT_OFFSET),
            FieldValue::U32(h.fragment_offset),
            at + 6..at + 9,
        );
        buf.push_field(
            dhfd(DHFD_FRAGMENT_LENGTH),
            FieldValue::U32(h.fragment_length),
            at + 9..at + HANDSHAKE_HEADER_SIZE,
        );
        saw_hello |= matches!(
            h.msg_type,
            HANDSHAKE_TYPE_CLIENT_HELLO | HANDSHAKE_TYPE_SERVER_HELLO
        );
        // RFC 6347, Section 4.2.3 — https://www.rfc-editor.org/rfc/rfc6347#section-4.2.3
        // "An unfragmented message is a degenerate case with
        // fragment_offset=0 and fragment_length=length."
        // Only an unfragmented message has a decodable body.
        if h.fragment_offset == 0 && h.fragment_length == h.length {
            let parsed = parse_body(
                h.msg_type,
                body,
                offset + body_start,
                Some(dhfd(DHFD_COOKIE)),
                buf,
            );
            if hello.is_none() {
                hello = parsed;
            }
        }
        buf.end_container(obj);
        pos = body_end;
    }
    buf.end_container(arr);

    match hello {
        Some(hello) => hello.label_with(dtls_version_short_name),
        None if saw_hello => None,
        None => record_version_label(record_version),
    }
}

/// Dissect the payload of an ACK record. Nothing is pushed unless the
/// `record_numbers` vector exactly fills the record with whole
/// `RecordNumber`s.
///
/// ```text
/// RFC 9147, Section 7 — https://www.rfc-editor.org/rfc/rfc9147#section-7
///
/// struct {
///     RecordNumber record_numbers<0..2^16-1>;
/// } ACK;
/// ```
fn dissect_ack<'pkt>(payload: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let Ok(len) = read_be_u16(payload, 0) else {
        return;
    };
    let len = usize::from(len);
    if payload.len() != 2 + len || len % RECORD_NUMBER_SIZE != 0 {
        return;
    }
    let arr = buf.begin_container(
        fd(FD_RECORD_NUMBERS),
        FieldValue::Array(0..0),
        offset + 2..offset + payload.len(),
    );
    let mut pos = 2;
    while pos < payload.len() {
        let (Ok(epoch), Ok(seq)) = (read_be_u64(payload, pos), read_be_u64(payload, pos + 8))
        else {
            break;
        };
        let at = offset + pos;
        let obj = buf.begin_container(
            &FD_RECORD_NUMBER,
            FieldValue::Object(0..0),
            at..at + RECORD_NUMBER_SIZE,
        );
        buf.push_field(&RECORD_NUMBER_FIELDS[0], FieldValue::U64(epoch), at..at + 8);
        buf.push_field(
            &RECORD_NUMBER_FIELDS[1],
            FieldValue::U64(seq),
            at + 8..at + RECORD_NUMBER_SIZE,
        );
        buf.end_container(obj);
        pos += RECORD_NUMBER_SIZE;
    }
    buf.end_container(arr);
}

#[cfg(test)]
mod tests {
    //! # RFC 9147 / RFC 6347 (DTLS) Coverage
    //!
    //! | RFC Section    | Description                                | Test                                        |
    //! |----------------|--------------------------------------------|---------------------------------------------|
    //! | 6347 §4.1      | DTLSPlaintext header (epoch, uint48 seq)   | parse_dtls12_client_hello_without_cookie    |
    //! | 6347 §4.2.1    | ClientHello with empty cookie              | parse_dtls12_client_hello_without_cookie    |
    //! | 6347 §4.2.1    | ClientHello with cookie                    | parse_dtls12_client_hello_with_cookie       |
    //! | 6347 §4.2.1    | HelloVerifyRequest                         | parse_hello_verify_request                  |
    //! | 6347 §4.2.1    | Malformed HelloVerifyRequest body          | parse_hello_verify_request_malformed        |
    //! | 6347 §4.2.2    | Handshake header (message_seq, fragments)  | parse_dtls12_client_hello_with_cookie       |
    //! | 6347 §4.2.2    | Fragmented handshake: header only          | parse_fragmented_handshake_header_only      |
    //! | 6347 §4.2.2    | Several handshake messages in one record   | parse_server_hello_and_server_hello_done    |
    //! | 6347 §4.2.2    | Inconsistent fragment → opaque             | parse_inconsistent_fragment_is_opaque       |
    //! | 6347 §4.1      | Handshake in epoch > 0 is encrypted        | parse_encrypted_handshake_epoch_nonzero     |
    //! | 9147 §4        | Two records in one datagram                | parse_two_records_in_one_datagram           |
    //! | 9147 §4        | Truncated 13-octet header                  | parse_truncated_plaintext_header            |
    //! | 9147 §4        | Truncated fragment                         | parse_truncated_plaintext_fragment          |
    //! | 9147 §4        | Truncated second record                    | parse_truncated_second_record               |
    //! | 9147 §4        | Empty input                                | parse_empty_input                           |
    //! | 9147 §4.1      | Unknown first octet rejected               | parse_rejects_unknown_first_octet           |
    //! | 6347 §4.1      | Version major must be 254                  | parse_rejects_non_dtls_version              |
    //! | 6347 §4.1      | Record length limit                        | parse_rejects_oversized_length              |
    //! | 6347 §4.1      | DTLS 1.0 record version label              | parse_dtls10_record_label                   |
    //! | 5246 §7.2      | Alert                                      | parse_alert_and_encrypted_alert             |
    //! | 5246 §7.1      | ChangeCipherSpec                           | parse_two_records_in_one_datagram           |
    //! | 6347 §4.1      | Application data                           | parse_application_data                      |
    //! | 6520 §4        | Heartbeat                                  | parse_heartbeat_record                      |
    //! | 9147 §7        | ACK record_numbers                         | parse_ack                                   |
    //! | 9147 §7        | Malformed ACK                              | parse_ack_malformed                         |
    //! | 9146 §4        | tls12_cid record: CID opaque               | parse_tls12_cid_record                      |
    //! | 9147 §4        | Unified header C=0 S=1 L=1                  | parse_unified_header_c0_s1_l1               |
    //! | 9147 §4        | Unified header minimal (8-bit seq, no len) | parse_unified_header_minimal                |
    //! | 9147 §4        | Unified header epoch low bits              | parse_unified_header_epoch_bits             |
    //! | 9147 §4        | Unified header C=1 (CID opaque)            | parse_unified_header_with_cid_opaque        |
    //! | 9147 §4        | Unified header truncated                   | parse_unified_header_truncated              |
    //! | 9147 §4        | Unified header then plaintext record       | parse_plaintext_then_unified_header         |
    //! | 9147 §5.3      | DTLS 1.3 ServerHello supported_versions    | parse_dtls13_server_hello_label             |
    //! | 9147 §5.2      | DTLS handshake type names                  | parse_dtls_handshake_type_names             |
    //! | 9147 §5.3      | DTLS version names                         | parse_dtls_version_names                    |
    //! | 9147 §5.2      | Schema covers the handshake body fields    | dtls_field_descriptors_cover_handshake_body |

    use super::*;
    use crate::handshake::HANDSHAKE_BODY_FIELDS;
    use core::ops::Range;
    use packet_dissector_core::field::{Field, FieldValue};
    use packet_dissector_core::packet::Layer;

    /// Build a DTLSPlaintext record (RFC 6347, Section 4.1 —
    /// <https://www.rfc-editor.org/rfc/rfc6347#section-4.1>).
    fn record(ct: u8, version: u16, epoch: u16, seq: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![ct];
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&epoch.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes()[2..]);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn u24(v: u32) -> [u8; 3] {
        let b = v.to_be_bytes();
        [b[1], b[2], b[3]]
    }

    /// Build a DTLS handshake fragment (RFC 6347, Section 4.2.2 —
    /// <https://www.rfc-editor.org/rfc/rfc6347#section-4.2.2>).
    fn hs_fragment(
        msg_type: u8,
        length: u32,
        message_seq: u16,
        frag_off: u32,
        frag: &[u8],
    ) -> Vec<u8> {
        let mut out = vec![msg_type];
        out.extend_from_slice(&u24(length));
        out.extend_from_slice(&message_seq.to_be_bytes());
        out.extend_from_slice(&u24(frag_off));
        out.extend_from_slice(&u24(frag.len() as u32));
        out.extend_from_slice(frag);
        out
    }

    /// An unfragmented DTLS handshake message.
    fn hs(msg_type: u8, message_seq: u16, body: &[u8]) -> Vec<u8> {
        hs_fragment(msg_type, body.len() as u32, message_seq, 0, body)
    }

    /// A DTLS 1.2 ClientHello body with the given cookie and extensions block.
    fn client_hello_body(cookie: &[u8], extensions: Option<&[u8]>) -> Vec<u8> {
        let mut b = vec![0xFE, 0xFD];
        b.extend_from_slice(&[0x11; 32]);
        b.push(0); // session_id
        b.push(cookie.len() as u8);
        b.extend_from_slice(cookie);
        b.extend_from_slice(&[0x00, 0x02, 0xC0, 0x2B]); // cipher_suites
        b.extend_from_slice(&[0x01, 0x00]); // compression_methods
        if let Some(ext) = extensions {
            b.extend_from_slice(&(ext.len() as u16).to_be_bytes());
            b.extend_from_slice(ext);
        }
        b
    }

    /// A ServerHello body with the given version and extensions block.
    fn server_hello_body(version: u16, extensions: Option<&[u8]>) -> Vec<u8> {
        let mut b = version.to_be_bytes().to_vec();
        b.extend_from_slice(&[0x22; 32]);
        b.push(0); // session_id
        b.extend_from_slice(&[0xC0, 0x2B]); // cipher_suite
        b.push(0); // compression_method
        if let Some(ext) = extensions {
            b.extend_from_slice(&(ext.len() as u16).to_be_bytes());
            b.extend_from_slice(ext);
        }
        b
    }

    fn dtls_layers<'a>(buf: &'a DissectBuffer<'_>) -> Vec<&'a Layer> {
        buf.layers().iter().filter(|l| l.name == "DTLS").collect()
    }

    fn only_layer<'a>(buf: &'a DissectBuffer<'_>) -> &'a Layer {
        let layers = dtls_layers(buf);
        assert_eq!(layers.len(), 1);
        layers[0]
    }

    /// Field index ranges of the handshake message objects in `layer`.
    fn handshake_objects(buf: &DissectBuffer<'_>, layer: &Layer) -> Vec<Range<u32>> {
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
            out.push(i..obj.end);
            i = obj.end;
        }
        out
    }

    fn child<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        obj: &Range<u32>,
        name: &str,
    ) -> Option<&'a Field<'pkt>> {
        let range = buf.fields()[obj.start as usize]
            .value
            .as_container_range()
            .unwrap()
            .clone();
        buf.nested_fields(&range).iter().find(|f| f.name() == name)
    }

    fn child_value<'pkt>(
        buf: &DissectBuffer<'pkt>,
        obj: &Range<u32>,
        name: &str,
    ) -> FieldValue<'pkt> {
        child(buf, obj, name)
            .unwrap_or_else(|| panic!("missing {name}"))
            .value
            .clone()
    }

    fn dissect(data: &[u8]) -> (Result<DissectResult, PacketError>, DissectBuffer<'_>) {
        let mut buf = DissectBuffer::new();
        let r = DtlsDissector.dissect(data, &mut buf, 0);
        (r, buf)
    }

    #[test]
    fn parse_dtls12_client_hello_without_cookie() {
        let body = client_hello_body(&[], None);
        let data = record(22, 0xFEFF, 0, 0, &hs(1, 0, &body));
        let (r, buf) = dissect(&data);
        let r = r.unwrap();
        assert_eq!(r.bytes_consumed, data.len());
        let layer = only_layer(&buf);
        assert_eq!(layer.range, 0..data.len());
        assert_eq!(buf.field_u8(layer, "content_type"), Some(22));
        assert_eq!(
            buf.resolve_display_name(layer, "content_type_name"),
            Some("Handshake")
        );
        assert_eq!(buf.field_u16(layer, "version"), Some(0xFEFF));
        assert_eq!(
            buf.resolve_display_name(layer, "version_name"),
            Some("DTLS 1.0")
        );
        assert_eq!(buf.field_u16(layer, "epoch"), Some(0));
        assert_eq!(buf.field_u64(layer, "sequence_number"), Some(0));
        assert_eq!(
            buf.field_u16(layer, "length"),
            Some((data.len() - 13) as u16)
        );
        let hs = handshake_objects(&buf, layer);
        assert_eq!(hs.len(), 1);
        let obj = &hs[0];
        assert_eq!(child_value(&buf, obj, "type"), FieldValue::U8(1));
        assert_eq!(
            child_value(&buf, obj, "length"),
            FieldValue::U32(body.len() as u32)
        );
        assert_eq!(child_value(&buf, obj, "message_seq"), FieldValue::U16(0));
        assert_eq!(
            child_value(&buf, obj, "fragment_offset"),
            FieldValue::U32(0)
        );
        assert_eq!(
            child_value(&buf, obj, "fragment_length"),
            FieldValue::U32(body.len() as u32)
        );
        assert_eq!(child_value(&buf, obj, "version"), FieldValue::U16(0xFEFD));
        assert_eq!(
            child_value(&buf, obj, "random"),
            FieldValue::Bytes(&[0x11; 32])
        );
        let cookie = child(&buf, obj, "cookie").unwrap();
        assert_eq!(cookie.value, FieldValue::Bytes(&[]));
        // 13 (record) + 12 (handshake) + 2 + 32 + 1 (session_id length) + 1
        // (cookie length): the empty cookie contents start right after.
        assert_eq!(cookie.range, 13 + 12 + 36..13 + 12 + 36);
        assert!(child(&buf, obj, "cipher_suites").is_some());
        assert!(child(&buf, obj, "compression_methods").is_some());
        assert_eq!(layer.display_name, Some("DTLSv1.2"));
    }

    #[test]
    fn parse_dtls12_client_hello_with_cookie() {
        let cookie = [0xAB; 20];
        let body = client_hello_body(&cookie, Some(&[]));
        let data = record(22, 0xFEFD, 0, 1, &hs(1, 1, &body));
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        assert_eq!(buf.field_u64(layer, "sequence_number"), Some(1));
        let obj = &handshake_objects(&buf, layer)[0];
        assert_eq!(child_value(&buf, obj, "message_seq"), FieldValue::U16(1));
        assert_eq!(child_value(&buf, obj, "cookie"), FieldValue::Bytes(&cookie));
        // The fields after the cookie are found at the right offsets
        // (cipher_suites contents follow their 2-byte length).
        let suites = child(&buf, obj, "cipher_suites").unwrap();
        assert_eq!(suites.range.start, 13 + 12 + 36 + cookie.len() + 2);
        assert!(child(&buf, obj, "extensions").is_some());
        assert_eq!(layer.display_name, Some("DTLSv1.2"));
    }

    #[test]
    fn parse_hello_verify_request() {
        let cookie = [0x5A; 16];
        let mut body = vec![0xFE, 0xFF, cookie.len() as u8];
        body.extend_from_slice(&cookie);
        let data = record(22, 0xFEFF, 0, 0, &hs(3, 0, &body));
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        let obj = &handshake_objects(&buf, layer)[0];
        assert_eq!(child_value(&buf, obj, "type"), FieldValue::U8(3));
        assert_eq!(
            buf.resolve_container_display_name(obj.start),
            Some("Hello Verify Request")
        );
        let version = child(&buf, obj, "version").unwrap();
        assert_eq!(version.value, FieldValue::U16(0xFEFF));
        assert_eq!(version.range, 25..27);
        let c = child(&buf, obj, "cookie").unwrap();
        assert_eq!(c.value, FieldValue::Bytes(&cookie));
        assert_eq!(c.range, 28..28 + cookie.len());
        assert_eq!(layer.display_name, Some("DTLSv1.0"));
    }

    #[test]
    fn parse_hello_verify_request_malformed() {
        // Cookie length runs past the body: nothing but the header decoded.
        let data = record(22, 0xFEFF, 0, 0, &hs(3, 0, &[0xFE, 0xFF, 5, 1, 2]));
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        let obj = &handshake_objects(&buf, layer)[0];
        assert!(child(&buf, obj, "cookie").is_none());
        assert!(child(&buf, obj, "version").is_none());
    }

    #[test]
    fn parse_fragmented_handshake_header_only() {
        // First fragment of a 1000-byte Certificate.
        let frag = [0x30; 100];
        let data = record(22, 0xFEFD, 0, 3, &hs_fragment(11, 1000, 2, 0, &frag));
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        let obj = &handshake_objects(&buf, layer)[0];
        assert_eq!(child_value(&buf, obj, "type"), FieldValue::U8(11));
        assert_eq!(child_value(&buf, obj, "length"), FieldValue::U32(1000));
        assert_eq!(child_value(&buf, obj, "message_seq"), FieldValue::U16(2));
        assert_eq!(
            child_value(&buf, obj, "fragment_offset"),
            FieldValue::U32(0)
        );
        assert_eq!(
            child_value(&buf, obj, "fragment_length"),
            FieldValue::U32(100)
        );
        assert!(child(&buf, obj, "certificates").is_none());

        // A later fragment of a ClientHello: the body is not decoded.
        let body = client_hello_body(&[], None);
        let data = record(
            22,
            0xFEFD,
            0,
            4,
            &hs_fragment(1, body.len() as u32 + 10, 0, 10, &body),
        );
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        let obj = &handshake_objects(&buf, layer)[0];
        assert_eq!(
            child_value(&buf, obj, "fragment_offset"),
            FieldValue::U32(10)
        );
        assert!(child(&buf, obj, "random").is_none());
        // A fragmented Hello yields no version label.
        assert_eq!(layer.display_name, None);
    }

    #[test]
    fn parse_server_hello_and_server_hello_done() {
        let mut payload = hs(2, 1, &server_hello_body(0xFEFD, None));
        payload.extend_from_slice(&hs(14, 2, &[]));
        let data = record(22, 0xFEFD, 0, 1, &payload);
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        let objs = handshake_objects(&buf, layer);
        assert_eq!(objs.len(), 2);
        assert_eq!(
            child_value(&buf, &objs[0], "cipher_suite"),
            FieldValue::U16(0xC02B)
        );
        assert_eq!(child_value(&buf, &objs[1], "type"), FieldValue::U8(14));
        assert_eq!(
            child_value(&buf, &objs[1], "message_seq"),
            FieldValue::U16(2)
        );
        assert_eq!(layer.display_name, Some("DTLSv1.2"));
    }

    #[test]
    fn parse_inconsistent_fragment_is_opaque() {
        // fragment_offset + fragment_length exceeds length.
        let payload = hs_fragment(11, 10, 0, 5, &[0; 8]);
        let data = record(22, 0xFEFD, 0, 0, &payload);
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        assert!(buf.field_by_name(layer, "handshake_messages").is_none());
        assert_eq!(
            buf.field_bytes(layer, "opaque_handshake"),
            Some(&payload[..])
        );

        // fragment_length runs past the record.
        let mut payload = hs_fragment(11, 100, 0, 0, &[0; 8]);
        payload[11] = 50;
        let data = record(22, 0xFEFD, 0, 0, &payload);
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        assert!(buf.field_by_name(layer, "opaque_handshake").is_some());

        // Trailing bytes too short for a handshake header.
        let mut payload = hs(14, 0, &[]);
        payload.extend_from_slice(&[0; 5]);
        let data = record(22, 0xFEFD, 0, 0, &payload);
        let (r, buf) = dissect(&data);
        r.unwrap();
        assert!(
            buf.field_by_name(only_layer(&buf), "opaque_handshake")
                .is_some()
        );

        // Unknown handshake type.
        let data = record(22, 0xFEFD, 0, 0, &hs(99, 0, &[]));
        let (r, buf) = dissect(&data);
        r.unwrap();
        assert!(
            buf.field_by_name(only_layer(&buf), "opaque_handshake")
                .is_some()
        );

        // Empty handshake record: nothing to decode.
        let data = record(22, 0xFEFD, 0, 0, &[]);
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        assert!(buf.field_by_name(layer, "opaque_handshake").is_none());
        assert!(buf.field_by_name(layer, "handshake_messages").is_none());
    }

    #[test]
    fn parse_encrypted_handshake_epoch_nonzero() {
        // Encrypted Finished in epoch 1 happens to look like a header.
        let payload = hs(20, 5, &[0x77; 12]);
        let data = record(22, 0xFEFD, 1, 0, &payload);
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        assert_eq!(buf.field_u16(layer, "epoch"), Some(1));
        assert!(buf.field_by_name(layer, "handshake_messages").is_none());
        assert_eq!(
            buf.field_bytes(layer, "opaque_handshake"),
            Some(&payload[..])
        );
    }

    #[test]
    fn parse_two_records_in_one_datagram() {
        let mut data = record(20, 0xFEFD, 0, 7, &[1]);
        let first_len = data.len();
        data.extend_from_slice(&record(22, 0xFEFD, 1, 0, &[0x99; 40]));
        let (r, buf) = dissect(&data);
        let r = r.unwrap();
        assert_eq!(r.bytes_consumed, data.len());
        let layers = dtls_layers(&buf);
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].range, 0..first_len);
        assert_eq!(layers[1].range, first_len..data.len());
        assert_eq!(
            buf.resolve_display_name(layers[0], "content_type_name"),
            Some("Change Cipher Spec")
        );
        assert_eq!(buf.field_u64(layers[0], "sequence_number"), Some(7));
        assert_eq!(buf.field_u16(layers[1], "epoch"), Some(1));
        let opaque = buf.field_by_name(layers[1], "opaque_handshake").unwrap();
        assert_eq!(opaque.range, first_len + 13..data.len());
    }

    #[test]
    fn parse_truncated_plaintext_header() {
        let data = record(22, 0xFEFD, 0, 0, &[]);
        let (r, _) = dissect(&data[..12]);
        assert_eq!(
            r.unwrap_err(),
            PacketError::Truncated {
                expected: 13,
                actual: 12
            }
        );
    }

    #[test]
    fn parse_truncated_plaintext_fragment() {
        let data = record(21, 0xFEFD, 0, 0, &[2, 40]);
        let (r, buf) = dissect(&data[..14]);
        assert_eq!(
            r.unwrap_err(),
            PacketError::Truncated {
                expected: 15,
                actual: 14
            }
        );
        assert!(dtls_layers(&buf).is_empty());
    }

    #[test]
    fn parse_truncated_second_record() {
        let mut data = record(21, 0xFEFD, 0, 0, &[1, 0]);
        data.extend_from_slice(&record(21, 0xFEFD, 0, 1, &[1, 0]));
        let cut = &data[..data.len() - 1];
        let (r, _) = dissect(cut);
        assert_eq!(
            r.unwrap_err(),
            PacketError::Truncated {
                expected: data.len(),
                actual: cut.len()
            }
        );
        // Second header cut short.
        let cut = &data[..15 + 5];
        let (r, _) = dissect(cut);
        assert_eq!(
            r.unwrap_err(),
            PacketError::Truncated {
                expected: 15 + 13,
                actual: 20
            }
        );
    }

    #[test]
    fn parse_empty_input() {
        let (r, _) = dissect(&[]);
        assert_eq!(
            r.unwrap_err(),
            PacketError::Truncated {
                expected: 1,
                actual: 0
            }
        );
    }

    #[test]
    fn parse_rejects_unknown_first_octet() {
        for first in [0u8, 19, 27, 31, 64, 0x80, 0xFF] {
            let data = record(first, 0xFEFD, 0, 0, &[0]);
            let (r, buf) = dissect(&data);
            assert_eq!(
                r.unwrap_err(),
                PacketError::InvalidFieldValue {
                    field: "content_type",
                    value: u32::from(first)
                },
                "first octet {first}"
            );
            assert!(dtls_layers(&buf).is_empty());
        }
    }

    #[test]
    fn parse_rejects_non_dtls_version() {
        let data = record(22, 0x0303, 0, 0, &[]);
        let (r, _) = dissect(&data);
        assert_eq!(
            r.unwrap_err(),
            PacketError::InvalidFieldValue {
                field: "version",
                value: 0x0303
            }
        );
    }

    #[test]
    fn parse_rejects_oversized_length() {
        let mut data = record(23, 0xFEFD, 1, 0, &[]);
        data[11..13].copy_from_slice(&0xFFFFu16.to_be_bytes());
        let (r, _) = dissect(&data);
        assert_eq!(
            r.unwrap_err(),
            PacketError::InvalidFieldValue {
                field: "length",
                value: 0xFFFF
            }
        );
    }

    #[test]
    fn parse_dtls10_record_label() {
        let data = record(23, 0xFEFF, 1, 0, &[1, 2, 3]);
        let (r, buf) = dissect(&data);
        r.unwrap();
        assert_eq!(only_layer(&buf).display_name, Some("DTLSv1.0"));
        // 0xFEFD is also DTLS 1.3's legacy_record_version: no label.
        let data = record(23, 0xFEFD, 1, 0, &[1, 2, 3]);
        let (r, buf) = dissect(&data);
        r.unwrap();
        assert_eq!(only_layer(&buf).display_name, None);
    }

    #[test]
    fn parse_alert_and_encrypted_alert() {
        let data = record(21, 0xFEFD, 0, 2, &[2, 40]);
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        assert_eq!(buf.field_u8(layer, "alert_level"), Some(2));
        assert_eq!(
            buf.resolve_display_name(layer, "alert_description_name"),
            Some("handshake_failure")
        );

        let data = record(21, 0xFEFD, 1, 2, &[0x42; 26]);
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        assert_eq!(
            buf.field_bytes(layer, "encrypted_alert"),
            Some(&[0x42; 26][..])
        );
    }

    #[test]
    fn parse_application_data() {
        let data = record(23, 0xFEFD, 1, 9, &[0xAA; 30]);
        let (r, buf) = dissect(&data);
        assert_eq!(r.unwrap().bytes_consumed, data.len());
        let layer = only_layer(&buf);
        assert_eq!(
            buf.resolve_display_name(layer, "content_type_name"),
            Some("Application Data")
        );
        assert_eq!(buf.field_u64(layer, "sequence_number"), Some(9));
    }

    #[test]
    fn parse_heartbeat_record() {
        let mut payload = vec![1, 0, 2, 0xDE, 0xAD];
        payload.extend_from_slice(&[0; 16]);
        let data = record(24, 0xFEFD, 0, 0, &payload);
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        assert_eq!(buf.field_u8(layer, "heartbeat_type"), Some(1));
        assert_eq!(buf.field_bytes(layer, "payload"), Some(&[0xDE, 0xAD][..]));
    }

    #[test]
    fn parse_ack() {
        let mut payload = 32u16.to_be_bytes().to_vec();
        payload.extend_from_slice(&2u64.to_be_bytes());
        payload.extend_from_slice(&5u64.to_be_bytes());
        payload.extend_from_slice(&2u64.to_be_bytes());
        payload.extend_from_slice(&6u64.to_be_bytes());
        let data = record(26, 0xFEFD, 0, 3, &payload);
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        assert_eq!(
            buf.resolve_display_name(layer, "content_type_name"),
            Some("ACK")
        );
        let arr = buf.field_by_name(layer, "record_numbers").unwrap();
        assert_eq!(arr.range, 15..data.len());
        let range = arr.value.as_container_range().unwrap().clone();
        let fields = buf.nested_fields(&range);
        // Two objects, each followed by its epoch and sequence_number.
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0].name(), "record_number");
        assert_eq!(fields[0].range, 15..31);
        assert_eq!(fields[1].value, FieldValue::U64(2));
        assert_eq!(fields[1].range, 15..23);
        assert_eq!(fields[2].name(), "sequence_number");
        assert_eq!(fields[2].value, FieldValue::U64(5));
        assert_eq!(fields[5].value, FieldValue::U64(6));
        assert_eq!(layer.display_name, Some("DTLSv1.3"));
    }

    #[test]
    fn parse_ack_malformed() {
        // Length not a multiple of 16, and a length that does not fill the record.
        for payload in [vec![0, 3, 1, 2, 3], vec![0, 16, 0], vec![0]] {
            let data = record(26, 0xFEFD, 0, 3, &payload);
            let (r, buf) = dissect(&data);
            r.unwrap();
            let layer = only_layer(&buf);
            assert!(buf.field_by_name(layer, "record_numbers").is_none());
        }
    }

    #[test]
    fn parse_tls12_cid_record() {
        // RFC 9146, Section 4: type, version, epoch, seq, cid, length, enc_content
        let mut data = vec![25, 0xFE, 0xFD, 0, 1, 0, 0, 0, 0, 0, 4];
        let rest = [0xC1, 0xC2, 0xC3, 0xC4, 0x00, 0x03, 0xEE, 0xEE, 0xEE];
        data.extend_from_slice(&rest);
        let (r, buf) = dissect(&data);
        assert_eq!(r.unwrap().bytes_consumed, data.len());
        let layer = only_layer(&buf);
        assert_eq!(
            buf.resolve_display_name(layer, "content_type_name"),
            Some("TLS12 CID")
        );
        assert_eq!(buf.field_u16(layer, "epoch"), Some(1));
        assert_eq!(buf.field_u64(layer, "sequence_number"), Some(4));
        assert!(buf.field_by_name(layer, "length").is_none());
        let opaque = buf.field_by_name(layer, "cid_and_record").unwrap();
        assert_eq!(opaque.value, FieldValue::Bytes(&rest));
        assert_eq!(opaque.range, 11..data.len());
        assert_eq!(layer.display_name, Some("DTLSv1.2"));

        // Header without any CID byte.
        let (r, _) = dissect(&data[..11]);
        assert_eq!(
            r.unwrap_err(),
            PacketError::Truncated {
                expected: 12,
                actual: 11
            }
        );
    }

    #[test]
    fn parse_unified_header_c0_s1_l1() {
        // 001 C=0 S=1 L=1 EE=01
        let mut data = vec![0b0010_1101, 0x12, 0x34, 0x00, 0x05];
        data.extend_from_slice(&[0xE0; 5]);
        let (r, buf) = dissect(&data);
        assert_eq!(r.unwrap().bytes_consumed, data.len());
        let layer = only_layer(&buf);
        assert!(buf.field_by_name(layer, "content_type").is_none());
        assert_eq!(buf.field_u8(layer, "connection_id_present"), Some(0));
        assert_eq!(buf.field_u8(layer, "sequence_number_16bit"), Some(1));
        assert_eq!(buf.field_u8(layer, "length_present"), Some(1));
        assert_eq!(buf.field_u8(layer, "epoch_low_bits"), Some(1));
        let seq = buf
            .field_by_name(layer, "encrypted_sequence_number")
            .unwrap();
        assert_eq!(seq.value, FieldValue::U16(0x1234));
        assert_eq!(seq.range, 1..3);
        let len = buf.field_by_name(layer, "length").unwrap();
        assert_eq!(len.value, FieldValue::U16(5));
        assert_eq!(len.range, 3..5);
        let rec = buf.field_by_name(layer, "encrypted_record").unwrap();
        assert_eq!(rec.range, 5..10);
        assert_eq!(layer.display_name, Some("DTLSv1.3"));
    }

    #[test]
    fn parse_unified_header_minimal() {
        // 001 C=0 S=0 L=0 EE=10: 8-bit sequence number, record fills the datagram.
        let data = [0b0010_0010, 0x7F, 1, 2, 3, 4];
        let (r, buf) = dissect(&data);
        assert_eq!(r.unwrap().bytes_consumed, data.len());
        let layer = only_layer(&buf);
        assert_eq!(buf.field_u8(layer, "sequence_number_16bit"), Some(0));
        assert_eq!(buf.field_u8(layer, "length_present"), Some(0));
        assert_eq!(
            buf.field_u16(layer, "encrypted_sequence_number"),
            Some(0x7F)
        );
        assert!(buf.field_by_name(layer, "length").is_none());
        assert_eq!(
            buf.field_bytes(layer, "encrypted_record"),
            Some(&[1, 2, 3, 4][..])
        );

        // Header only: no encrypted_record field.
        let (r, buf) = dissect(&data[..2]);
        r.unwrap();
        assert!(
            buf.field_by_name(only_layer(&buf), "encrypted_record")
                .is_none()
        );
    }

    #[test]
    fn parse_unified_header_epoch_bits() {
        for e in 0u8..4 {
            let data = [0x20 | e, 0x00, 0xAA];
            let (r, buf) = dissect(&data);
            r.unwrap();
            let layer = only_layer(&buf);
            let f = buf.field_by_name(layer, "epoch_low_bits").unwrap();
            assert_eq!(f.value, FieldValue::U8(e));
            assert_eq!(f.range, 0..1);
        }
    }

    #[test]
    fn parse_unified_header_with_cid_opaque() {
        // 001 C=1 S=1 L=1 EE=11 — CID length is not self-describing.
        let data = [0b0011_1111, 0xC1, 0xC2, 0x00, 0x01, 0x00, 0x02, 0xEE, 0xEE];
        let (r, buf) = dissect(&data);
        assert_eq!(r.unwrap().bytes_consumed, data.len());
        let layer = only_layer(&buf);
        assert_eq!(buf.field_u8(layer, "connection_id_present"), Some(1));
        assert_eq!(buf.field_u8(layer, "epoch_low_bits"), Some(3));
        assert!(
            buf.field_by_name(layer, "encrypted_sequence_number")
                .is_none()
        );
        assert!(buf.field_by_name(layer, "length").is_none());
        let opaque = buf.field_by_name(layer, "cid_and_record").unwrap();
        assert_eq!(opaque.value, FieldValue::Bytes(&data[1..]));
        assert_eq!(opaque.range, 1..data.len());
        assert_eq!(layer.display_name, Some("DTLSv1.3"));
    }

    #[test]
    fn parse_unified_header_truncated() {
        // S=1 L=1 needs 5 header bytes.
        let (r, _) = dissect(&[0b0010_1100, 0x00, 0x01]);
        assert_eq!(
            r.unwrap_err(),
            PacketError::Truncated {
                expected: 5,
                actual: 3
            }
        );
        // Length runs past the datagram.
        let (r, _) = dissect(&[0b0010_0100, 0x00, 0x00, 0x04, 0xAA]);
        assert_eq!(
            r.unwrap_err(),
            PacketError::Truncated {
                expected: 8,
                actual: 5
            }
        );
        // C=1 needs at least one CID byte and the sequence number.
        let (r, _) = dissect(&[0b0011_0000, 0xC1]);
        assert_eq!(
            r.unwrap_err(),
            PacketError::Truncated {
                expected: 3,
                actual: 2
            }
        );
        // Length above the limit.
        let (r, _) = dissect(&[0b0010_0100, 0x00, 0xFF, 0xFF]);
        assert_eq!(
            r.unwrap_err(),
            PacketError::InvalidFieldValue {
                field: "length",
                value: 0xFFFF
            }
        );
    }

    #[test]
    fn parse_plaintext_then_unified_header() {
        // An ACK in the clear followed by a DTLS 1.3 ciphertext record.
        let mut data = record(26, 0xFEFD, 0, 0, &[0, 0]);
        let first = data.len();
        data.extend_from_slice(&[0b0010_1111, 0x00, 0x01, 0x00, 0x02, 0xAB, 0xCD]);
        let (r, buf) = dissect(&data);
        assert_eq!(r.unwrap().bytes_consumed, data.len());
        let layers = dtls_layers(&buf);
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[1].range, first..data.len());
        assert_eq!(
            buf.field_by_name(layers[1], "encrypted_record")
                .unwrap()
                .range,
            first + 5..data.len()
        );
    }

    #[test]
    fn parse_dtls13_server_hello_label() {
        // supported_versions (43) selecting DTLS 1.3 (0xFEFC).
        let ext = [0x00, 0x2B, 0x00, 0x02, 0xFE, 0xFC];
        let data = record(
            22,
            0xFEFD,
            0,
            0,
            &hs(2, 0, &server_hello_body(0xFEFD, Some(&ext))),
        );
        let (r, buf) = dissect(&data);
        r.unwrap();
        let layer = only_layer(&buf);
        assert_eq!(layer.display_name, Some("DTLSv1.3"));

        // A ClientHello offering a supported_versions list has no single version.
        let ext = [0x00, 0x2B, 0x00, 0x05, 0x04, 0xFE, 0xFC, 0xFE, 0xFD];
        let data = record(
            22,
            0xFEFD,
            0,
            0,
            &hs(1, 0, &client_hello_body(&[], Some(&ext))),
        );
        let (r, buf) = dissect(&data);
        r.unwrap();
        assert_eq!(only_layer(&buf).display_name, None);
    }

    #[test]
    fn parse_dtls_handshake_type_names() {
        for (ht, name) in [
            (3u8, "Hello Verify Request"),
            (9, "Request Connection Id"),
            (10, "New Connection Id"),
        ] {
            let data = record(22, 0xFEFD, 0, 0, &hs(ht, 0, &[]));
            let (r, buf) = dissect(&data);
            r.unwrap();
            let layer = only_layer(&buf);
            let obj = &handshake_objects(&buf, layer)[0];
            assert_eq!(buf.resolve_container_display_name(obj.start), Some(name));
        }
    }

    #[test]
    fn parse_dtls_version_names() {
        for (ver, name) in [
            (0xFEFFu16, "DTLS 1.0"),
            (0xFEFD, "DTLS 1.2 / DTLS 1.3 legacy_record_version"),
            (0xFE00, "Unknown"),
        ] {
            let data = record(23, ver, 1, 0, &[0]);
            let (r, buf) = dissect(&data);
            r.unwrap();
            let layer = only_layer(&buf);
            assert_eq!(buf.resolve_display_name(layer, "version_name"), Some(name));
        }
        assert_eq!(crate::supported_version_name(0xFEFC), "DTLS 1.3");
        assert_eq!(crate::supported_version_name(0xFEFD), "DTLS 1.2");
        assert_eq!(crate::supported_version_name(0xFEFF), "DTLS 1.0");
    }

    #[test]
    fn dtls_field_descriptors_cover_handshake_body() {
        let fds = DtlsDissector.field_descriptors();
        let mut names: Vec<_> = fds.iter().map(|f| f.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), fds.len(), "field names must be unique");

        let hs = fds
            .iter()
            .find(|f| f.name == "handshake_messages")
            .and_then(|f| f.children)
            .unwrap();
        for name in [
            "type",
            "length",
            "message_seq",
            "fragment_offset",
            "fragment_length",
            "cookie",
        ] {
            assert!(hs.iter().any(|f| f.name == name), "missing {name}");
        }
        for body in HANDSHAKE_BODY_FIELDS {
            assert!(hs.contains(&body), "missing body field {}", body.name);
        }
        let mut hs_names: Vec<_> = hs.iter().map(|f| f.name).collect();
        hs_names.sort_unstable();
        hs_names.dedup();
        assert_eq!(hs_names.len(), hs.len(), "handshake names must be unique");

        assert!(!DtlsDissector.references().is_empty());
        assert_eq!(DtlsDissector.short_name(), "DTLS");
        assert_eq!(DtlsDissector.layer(), Some(ProtocolLayer::Application));
    }
}
