//! SNMP (Simple Network Management Protocol) dissector for SNMPv1, SNMPv2c
//! and SNMPv3 messages.
//!
//! Messages are BER-encoded (ITU-T X.690) and walked with
//! [`packet_dissector_core::ber`]. Object identifiers are kept as their
//! contents octets and rendered in dotted notation at serialization time.
//!
//! ## References
//! - RFC 1157 (SNMPv1): <https://www.rfc-editor.org/rfc/rfc1157>
//! - RFC 1901 (Community-based SNMPv2): <https://www.rfc-editor.org/rfc/rfc1901>
//! - RFC 3416 (Protocol Operations for SNMP): <https://www.rfc-editor.org/rfc/rfc3416>
//! - RFC 3412 (Message Processing and Dispatching, SNMPv3 message):
//!   <https://www.rfc-editor.org/rfc/rfc3412>
//! - RFC 3414 (User-based Security Model): <https://www.rfc-editor.org/rfc/rfc3414>
//! - RFC 3417 (Transport Mappings): <https://www.rfc-editor.org/rfc/rfc3417>
//! - RFC 2578 (SMIv2, application types): <https://www.rfc-editor.org/rfc/rfc2578>
//! - IANA SNMP Number Spaces (security models):
//!   <https://www.iana.org/assignments/snmp-number-spaces/>
//! - ITU-T X.690 (BER): <https://www.itu.int/rec/T-REC-X.690>

#![deny(missing_docs)]

use packet_dissector_core::ber::{self, Tag, TagClass};
use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{
    Field, FieldDescriptor, FieldType, FieldValue, FormatContext, format_utf8_lossy,
};
use packet_dissector_core::packet::DissectBuffer;

/// UDP port of SNMP agents (command responders).
///
/// RFC 3417, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc3417#section-3.2>:
/// "It is suggested that administrators configure their SNMP entities
/// supporting command responder applications to listen on UDP port 161."
pub const SNMP_PORT: u16 = 161;

/// UDP port of SNMP notification receivers.
///
/// RFC 3417, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc3417#section-3.2>:
/// "Further, it is suggested that SNMP entities supporting notification
/// receiver applications be configured to listen on UDP port 162."
pub const SNMP_TRAP_PORT: u16 = 162;

/// `msgVersion` of SNMPv1 (RFC 1157, Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc1157#section-4>: `version-1(0)`).
const VERSION_1: i32 = 0;
/// `msgVersion` of SNMPv2c (RFC 1901, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc1901#section-3>: `version(1)`).
const VERSION_2C: i32 = 1;
/// `msgVersion` of SNMPv3 (RFC 3412, Section 6 —
/// <https://www.rfc-editor.org/rfc/rfc3412#section-6>: "the value 3 is used
/// for snmpv3").
const VERSION_3: i32 = 3;

/// User-based Security Model number (IANA SNMP Number Spaces,
/// SnmpSecurityModel — <https://www.iana.org/assignments/snmp-number-spaces/>).
const SECURITY_MODEL_USM: i32 = 3;

/// SNMPv1 Trap-PDU tag (RFC 1157, Section 4.1.6 —
/// <https://www.rfc-editor.org/rfc/rfc1157#section-4.1.6>).
const PDU_TRAP_V1: u32 = 4;
/// GetBulkRequest-PDU tag (RFC 3416, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc3416#section-3>).
const PDU_GET_BULK: u32 = 5;

// ---------------------------------------------------------------------------
// Display and format functions
// ---------------------------------------------------------------------------

/// Message version name (see the `VERSION_*` constants: RFC 1157 —
/// <https://www.rfc-editor.org/rfc/rfc1157>, RFC 1901 — <https://www.rfc-editor.org/rfc/rfc1901>, RFC 3412 —
/// <https://www.rfc-editor.org/rfc/rfc3412>).
fn version_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::I32(VERSION_1) => Some("SNMPv1"),
        FieldValue::I32(VERSION_2C) => Some("SNMPv2c"),
        FieldValue::I32(VERSION_3) => Some("SNMPv3"),
        _ => None,
    }
}

/// Security level encoded in the low two `msgFlags` bits.
///
/// RFC 3412, Section 6 — <https://www.rfc-editor.org/rfc/rfc3412#section-6>:
///
/// ```text
/// --  .... ..00   is OK, means noAuthNoPriv
/// --  .... ..01   is OK, means authNoPriv
/// --  .... ..10   reserved, MUST NOT be used.
/// --  .... ..11   is OK, means authPriv
/// ```
fn security_level_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::U8(flags) => Some(match flags & 0x03 {
            0 => "noAuthNoPriv",
            1 => "authNoPriv",
            2 => "reserved",
            _ => "authPriv",
        }),
        _ => None,
    }
}

/// Security model name (IANA SNMP Number Spaces, SnmpSecurityModel —
/// <https://www.iana.org/assignments/snmp-number-spaces/>; RFC 3411 —
/// <https://www.rfc-editor.org/rfc/rfc3411>, RFC 5591 —
/// <https://www.rfc-editor.org/rfc/rfc5591>).
fn security_model_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::I32(0) => Some("any"),
        FieldValue::I32(1) => Some("SNMPv1"),
        FieldValue::I32(2) => Some("SNMPv2c"),
        FieldValue::I32(SECURITY_MODEL_USM) => Some("USM"),
        FieldValue::I32(4) => Some("TSM"),
        _ => None,
    }
}

/// PDU type name from the context-specific tag.
///
/// RFC 3416, Section 3 — <https://www.rfc-editor.org/rfc/rfc3416#section-3>
/// (`GetRequest-PDU ::= [0]` ... `Report-PDU ::= [8]`; "[4] is obsolete")
/// and RFC 1157, Section 4.1.6 —
/// <https://www.rfc-editor.org/rfc/rfc1157#section-4.1.6> (`Trap-PDU ::= [4]`).
fn pdu_type_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::U8(0) => Some("get-request"),
        FieldValue::U8(1) => Some("get-next-request"),
        FieldValue::U8(2) => Some("response"),
        FieldValue::U8(3) => Some("set-request"),
        FieldValue::U8(4) => Some("trap"),
        FieldValue::U8(5) => Some("get-bulk-request"),
        FieldValue::U8(6) => Some("inform-request"),
        FieldValue::U8(7) => Some("snmpV2-trap"),
        FieldValue::U8(8) => Some("report"),
        _ => None,
    }
}

/// `error-status` name. RFC 3416, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc3416#section-3>.
fn error_status_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::I32(0) => Some("noError"),
        FieldValue::I32(1) => Some("tooBig"),
        FieldValue::I32(2) => Some("noSuchName"),
        FieldValue::I32(3) => Some("badValue"),
        FieldValue::I32(4) => Some("readOnly"),
        FieldValue::I32(5) => Some("genErr"),
        FieldValue::I32(6) => Some("noAccess"),
        FieldValue::I32(7) => Some("wrongType"),
        FieldValue::I32(8) => Some("wrongLength"),
        FieldValue::I32(9) => Some("wrongEncoding"),
        FieldValue::I32(10) => Some("wrongValue"),
        FieldValue::I32(11) => Some("noCreation"),
        FieldValue::I32(12) => Some("inconsistentValue"),
        FieldValue::I32(13) => Some("resourceUnavailable"),
        FieldValue::I32(14) => Some("commitFailed"),
        FieldValue::I32(15) => Some("undoFailed"),
        FieldValue::I32(16) => Some("authorizationError"),
        FieldValue::I32(17) => Some("notWritable"),
        FieldValue::I32(18) => Some("inconsistentName"),
        _ => None,
    }
}

/// `generic-trap` name. RFC 1157, Section 4.1.6 —
/// <https://www.rfc-editor.org/rfc/rfc1157#section-4.1.6>.
fn generic_trap_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::I32(0) => Some("coldStart"),
        FieldValue::I32(1) => Some("warmStart"),
        FieldValue::I32(2) => Some("linkDown"),
        FieldValue::I32(3) => Some("linkUp"),
        FieldValue::I32(4) => Some("authenticationFailure"),
        FieldValue::I32(5) => Some("egpNeighborLoss"),
        FieldValue::I32(6) => Some("enterpriseSpecific"),
        _ => None,
    }
}

/// Name of a variable-binding value type from its identifier octet.
///
/// RFC 3416, Section 3 — <https://www.rfc-editor.org/rfc/rfc3416#section-3>
/// (`ObjectSyntax`, `ApplicationSyntax` and the `noSuchObject [0]`,
/// `noSuchInstance [1]`, `endOfMibView [2]` exceptions).
fn value_type_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::U8(0x02) => Some("INTEGER"),
        FieldValue::U8(0x04) => Some("OCTET STRING"),
        FieldValue::U8(0x05) => Some("NULL"),
        FieldValue::U8(0x06) => Some("OBJECT IDENTIFIER"),
        FieldValue::U8(0x40) => Some("IpAddress"),
        FieldValue::U8(0x41) => Some("Counter32"),
        FieldValue::U8(0x42) => Some("Gauge32"),
        FieldValue::U8(0x43) => Some("TimeTicks"),
        FieldValue::U8(0x44) => Some("Opaque"),
        FieldValue::U8(0x46) => Some("Counter64"),
        FieldValue::U8(0x80) => Some("noSuchObject"),
        FieldValue::U8(0x81) => Some("noSuchInstance"),
        FieldValue::U8(0x82) => Some("endOfMibView"),
        _ => None,
    }
}

/// Write OBJECT IDENTIFIER contents octets in dotted notation.
///
/// X.690, 8.19.2: each subidentifier is a series of base-128 octets, bit 8
/// set on all but the last. X.690, 8.19.4: the first subidentifier encodes
/// the first two arcs as `(X*40) + Y`. Malformed contents are written as
/// hexadecimal.
pub fn format_oid(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let FieldValue::Bytes(contents) = value else {
        return w.write_all(b"\"\"");
    };
    if !oid_is_well_formed(contents) {
        w.write_all(b"\"")?;
        for b in *contents {
            write!(w, "{b:02x}")?;
        }
        return w.write_all(b"\"");
    }
    w.write_all(b"\"")?;
    let mut first = true;
    let mut sub: u64 = 0;
    for &b in *contents {
        sub = (sub << 7) | u64::from(b & 0x7f);
        if b & 0x80 != 0 {
            continue;
        }
        if first {
            let (x, y) = match sub {
                0..40 => (0, sub),
                40..80 => (1, sub - 40),
                _ => (2, sub - 80),
            };
            write!(w, "{x}.{y}")?;
            first = false;
        } else {
            write!(w, ".{sub}")?;
        }
        sub = 0;
    }
    w.write_all(b"\"")
}

/// Whether OBJECT IDENTIFIER contents end on a complete subidentifier and
/// every subidentifier fits in 64 bits.
fn oid_is_well_formed(contents: &[u8]) -> bool {
    if contents.last().is_some_and(|b| b & 0x80 != 0) {
        return false;
    }
    let mut sub: u128 = 0;
    for &b in contents {
        sub = (sub << 7) | u128::from(b & 0x7f);
        if sub > u128::from(u64::MAX) {
            return false;
        }
        if b & 0x80 == 0 {
            sub = 0;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Field descriptors
// ---------------------------------------------------------------------------

/// User-based Security Model parameters. RFC 3414, Section 2.4 —
/// <https://www.rfc-editor.org/rfc/rfc3414#section-2.4>.
static USM_CHILDREN: [FieldDescriptor; 6] = [
    FieldDescriptor::new(
        "authoritative_engine_id",
        "msgAuthoritativeEngineID",
        FieldType::Bytes,
    ),
    FieldDescriptor::new(
        "authoritative_engine_boots",
        "msgAuthoritativeEngineBoots",
        FieldType::I32,
    ),
    FieldDescriptor::new(
        "authoritative_engine_time",
        "msgAuthoritativeEngineTime",
        FieldType::I32,
    ),
    FieldDescriptor::new("user_name", "msgUserName", FieldType::Bytes)
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new(
        "authentication_parameters",
        "msgAuthenticationParameters",
        FieldType::Bytes,
    ),
    FieldDescriptor::new(
        "privacy_parameters",
        "msgPrivacyParameters",
        FieldType::Bytes,
    ),
];

/// Variable binding. RFC 3416, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc3416#section-3>.
static VARBIND_CHILDREN: [FieldDescriptor; 3] = [
    FieldDescriptor::new("name", "Object Name", FieldType::Bytes).with_format_fn(format_oid),
    FieldDescriptor::new("value_type", "Value Type", FieldType::U8)
        .with_display_fn(value_type_name),
    FieldDescriptor::new("value", "Value", FieldType::Any).optional(),
];
const VB_NAME: usize = 0;
const VB_VALUE_TYPE: usize = 1;
const VB_VALUE: usize = 2;

/// `value` of an OBJECT IDENTIFIER variable binding, rendered dotted.
static FD_VALUE_OID: FieldDescriptor =
    FieldDescriptor::new("value", "Value", FieldType::Any).with_format_fn(format_oid);

static FD_VARBIND: FieldDescriptor =
    FieldDescriptor::new("varbind", "Variable Binding", FieldType::Object)
        .with_children(&VARBIND_CHILDREN);

/// PDU fields. RFC 3416, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc3416#section-3> (PDU, BulkPDU) and
/// RFC 1157, Section 4.1.6 — <https://www.rfc-editor.org/rfc/rfc1157#section-4.1.6>
/// (Trap-PDU).
static PDU_CHILDREN: [FieldDescriptor; 13] = [
    FieldDescriptor::new("type", "PDU Type", FieldType::U8).with_display_fn(pdu_type_name),
    FieldDescriptor::new("request_id", "request-id", FieldType::I32).optional(),
    FieldDescriptor::new("error_status", "error-status", FieldType::I32)
        .optional()
        .with_display_fn(error_status_name),
    FieldDescriptor::new("error_index", "error-index", FieldType::I32).optional(),
    FieldDescriptor::new("non_repeaters", "non-repeaters", FieldType::I32).optional(),
    FieldDescriptor::new("max_repetitions", "max-repetitions", FieldType::I32).optional(),
    FieldDescriptor::new("enterprise", "enterprise", FieldType::Bytes)
        .optional()
        .with_format_fn(format_oid),
    FieldDescriptor::new("agent_addr", "agent-addr", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("generic_trap", "generic-trap", FieldType::I32)
        .optional()
        .with_display_fn(generic_trap_name),
    FieldDescriptor::new("specific_trap", "specific-trap", FieldType::I32).optional(),
    FieldDescriptor::new("time_stamp", "time-stamp", FieldType::U32).optional(),
    FieldDescriptor::new("varbinds", "variable-bindings", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_VARBIND)),
    FieldDescriptor::new("data", "Undecoded PDU", FieldType::Bytes).optional(),
];
const PDU_TYPE: usize = 0;
const PDU_REQUEST_ID: usize = 1;
const PDU_ERROR_STATUS: usize = 2;
const PDU_ERROR_INDEX: usize = 3;
const PDU_NON_REPEATERS: usize = 4;
const PDU_MAX_REPETITIONS: usize = 5;
const PDU_ENTERPRISE: usize = 6;
const PDU_AGENT_ADDR: usize = 7;
const PDU_GENERIC_TRAP: usize = 8;
const PDU_SPECIFIC_TRAP: usize = 9;
const PDU_TIME_STAMP: usize = 10;
const PDU_VARBINDS: usize = 11;
const PDU_DATA: usize = 12;

/// Message fields. RFC 1157, Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc1157#section-4>; RFC 1901, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc1901#section-3>; RFC 3412, Section 6 —
/// <https://www.rfc-editor.org/rfc/rfc3412#section-6>.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::I32).with_display_fn(version_name),
    FieldDescriptor::new("community", "Community", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("msg_id", "msgID", FieldType::I32).optional(),
    FieldDescriptor::new("msg_max_size", "msgMaxSize", FieldType::I32).optional(),
    FieldDescriptor::new("msg_flags", "msgFlags", FieldType::U8)
        .optional()
        .with_display_fn(security_level_name),
    FieldDescriptor::new("auth_flag", "authFlag", FieldType::U8).optional(),
    FieldDescriptor::new("priv_flag", "privFlag", FieldType::U8).optional(),
    FieldDescriptor::new("reportable_flag", "reportableFlag", FieldType::U8).optional(),
    FieldDescriptor::new("msg_security_model", "msgSecurityModel", FieldType::I32)
        .optional()
        .with_display_fn(security_model_name),
    FieldDescriptor::new(
        "security_parameters",
        "msgSecurityParameters",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("usm", "USM Security Parameters", FieldType::Object)
        .optional()
        .with_children(&USM_CHILDREN),
    FieldDescriptor::new("context_engine_id", "contextEngineID", FieldType::Bytes).optional(),
    FieldDescriptor::new("context_name", "contextName", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("encrypted_pdu", "encryptedPDU", FieldType::Bytes).optional(),
    FieldDescriptor::new("pdu", "PDU", FieldType::Object)
        .optional()
        .with_children(&PDU_CHILDREN),
    FieldDescriptor::new("data", "Undecoded Data", FieldType::Bytes).optional(),
];
const FD_VERSION: usize = 0;
const FD_COMMUNITY: usize = 1;
const FD_MSG_ID: usize = 2;
const FD_MSG_MAX_SIZE: usize = 3;
const FD_MSG_FLAGS: usize = 4;
const FD_AUTH_FLAG: usize = 5;
const FD_PRIV_FLAG: usize = 6;
const FD_REPORTABLE_FLAG: usize = 7;
const FD_SECURITY_MODEL: usize = 8;
const FD_SECURITY_PARAMETERS: usize = 9;
const FD_USM: usize = 10;
const FD_CONTEXT_ENGINE_ID: usize = 11;
const FD_CONTEXT_NAME: usize = 12;
const FD_ENCRYPTED_PDU: usize = 13;
const FD_PDU: usize = 14;
const FD_DATA: usize = 15;

static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 1157",
        "A Simple Network Management Protocol (SNMP)",
        "https://www.rfc-editor.org/rfc/rfc1157",
    ),
    SpecReference::new(
        "RFC 1901",
        "Introduction to Community-based SNMPv2",
        "https://www.rfc-editor.org/rfc/rfc1901",
    ),
    SpecReference::new(
        "RFC 3416",
        "Version 2 of the Protocol Operations for the Simple Network Management Protocol (SNMP)",
        "https://www.rfc-editor.org/rfc/rfc3416",
    ),
    SpecReference::new(
        "RFC 3412",
        "Message Processing and Dispatching for the Simple Network Management Protocol (SNMP)",
        "https://www.rfc-editor.org/rfc/rfc3412",
    ),
    SpecReference::new(
        "RFC 3414",
        "User-based Security Model (USM) for version 3 of the Simple Network Management Protocol (SNMPv3)",
        "https://www.rfc-editor.org/rfc/rfc3414",
    ),
    SpecReference::new(
        "RFC 3417",
        "Transport Mappings for the Simple Network Management Protocol (SNMP)",
        "https://www.rfc-editor.org/rfc/rfc3417",
    ),
];

/// SNMP dissector (UDP 161 and 162).
#[derive(Debug, Clone, Copy, Default)]
pub struct SnmpDissector;

impl Dissector for SnmpDissector {
    fn name(&self) -> &'static str {
        "Simple Network Management Protocol"
    }

    fn short_name(&self) -> &'static str {
        "SNMP"
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
        // RFC 3417, Section 8 — <https://www.rfc-editor.org/rfc/rfc3417#section-8>:
        // "When encoding the length field, only the definite form is used;
        // use of the indefinite form encoding is prohibited."
        let message = ber::read_tlv(data)?;
        if !(message.tag.is_universal(Tag::SEQUENCE) && message.tag.constructed) {
            return Err(PacketError::InvalidHeader("SNMP message is not a SEQUENCE"));
        }
        let total = message.encoded_len();

        let fields_before = buf.field_count() as usize;
        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total,
        );
        let mut parser = Parser { data, offset };
        match parser.message(buf, message.header_len, total) {
            Ok(()) => {
                buf.end_layer();
                Ok(DissectResult::new(total, DispatchHint::End))
            }
            Err(e) => {
                // Leave the buffer as it was: no partial SNMP layer.
                buf.truncate_fields(fields_before);
                buf.pop_layer();
                Err(e)
            }
        }
    }
}

/// One BER element located in the dissected input.
struct Element<'pkt> {
    tag: Tag,
    /// Start of the identifier octets (index into the input).
    start: usize,
    /// Start of the contents octets.
    value_start: usize,
    /// End of the element.
    end: usize,
    /// Contents octets.
    value: &'pkt [u8],
}

impl Element<'_> {
    fn is_universal(&self, number: u32) -> bool {
        self.tag.is_universal(number)
    }

    fn is_application(&self, number: u32) -> bool {
        self.tag.class == TagClass::Application && self.tag.number == number
    }
}

/// Map a BER error inside the message: running out of octets there means
/// the element overruns its enclosing element, not that the capture is
/// short.
fn nested(e: PacketError) -> PacketError {
    match e {
        PacketError::Truncated { .. } => {
            PacketError::InvalidHeader("SNMP: BER element overruns its container")
        }
        e => e,
    }
}

/// Consecutive elements of one constructed element (or of the message),
/// with positions relative to the dissected input.
struct Cursor<'pkt> {
    /// Index of the iterated slice in the dissected input.
    base: usize,
    end: usize,
    iter: ber::TlvIter<'pkt>,
}

impl<'pkt> Cursor<'pkt> {
    fn new(data: &'pkt [u8], start: usize, end: usize) -> Self {
        Self {
            base: start,
            end,
            iter: ber::TlvIter::new(&data[start..end]),
        }
    }

    fn over(data: &'pkt [u8], element: &Element<'pkt>) -> Self {
        Self::new(data, element.value_start, element.end)
    }

    /// Position of the next element in the dissected input.
    fn pos(&self) -> usize {
        self.base + self.iter.offset()
    }

    fn is_empty(&self) -> bool {
        self.pos() >= self.end
    }

    fn next(&mut self) -> Result<Element<'pkt>, PacketError> {
        let (offset, tlv) = self
            .iter
            .next()
            .ok_or(PacketError::InvalidHeader("SNMP: missing element"))?
            .map_err(nested)?;
        let start = self.base + offset;
        Ok(Element {
            tag: tlv.tag,
            start,
            value_start: start + tlv.header_len,
            end: start + tlv.encoded_len(),
            value: tlv.value,
        })
    }

    /// Fail when elements remain after the last one the SEQUENCE defines.
    fn finish(&self) -> Result<(), PacketError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(PacketError::InvalidHeader(
                "SNMP: unexpected trailing element",
            ))
        }
    }

    fn next_integer(&mut self) -> Result<(i32, Element<'pkt>), PacketError> {
        let e = self.next_expect(Tag::INTEGER, "SNMP: expected INTEGER")?;
        let v = integer(e.value).ok_or(PacketError::InvalidHeader("SNMP: INTEGER out of range"))?;
        Ok((v, e))
    }

    /// Next element, which must be the universal type `number` in the form
    /// RFC 3417, Section 8 — <https://www.rfc-editor.org/rfc/rfc3417#section-8>
    /// requires: "the primitive form shall be used for all simple types"
    /// and "The constructed form of encoding shall be used only for
    /// structured types, i.e., a SEQUENCE or an IMPLICIT SEQUENCE."
    fn next_expect(
        &mut self,
        number: u32,
        message: &'static str,
    ) -> Result<Element<'pkt>, PacketError> {
        let e = self.next()?;
        if !e.is_universal(number) || e.tag.constructed != (number == Tag::SEQUENCE) {
            return Err(PacketError::InvalidHeader(message));
        }
        Ok(e)
    }
}

/// Two's-complement INTEGER of one to four contents octets (X.690, 8.3).
fn integer(value: &[u8]) -> Option<i32> {
    if value.is_empty() || value.len() > 4 {
        return None;
    }
    let mut v: i32 = if value[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in value {
        v = (v << 8) | i32::from(b);
    }
    Some(v)
}

/// Non-negative integer of up to `max_octets` value octets, allowing one
/// leading zero octet (X.690, 8.3: a positive value with bit 8 set needs a
/// leading zero octet). Negative encodings are out of the unsigned range.
fn unsigned(value: &[u8], max_octets: usize) -> Option<u64> {
    let value = match value {
        [0, rest @ ..] if !rest.is_empty() => rest,
        // Bit 8 of the first octet set: a negative value.
        [first, ..] if first & 0x80 != 0 => return None,
        v => v,
    };
    if value.is_empty() || value.len() > max_octets {
        return None;
    }
    Some(value.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

/// Walks one SNMP message.
struct Parser<'pkt> {
    data: &'pkt [u8],
    offset: usize,
}

impl<'pkt> Parser<'pkt> {
    fn range(&self, e: &Element<'_>) -> core::ops::Range<usize> {
        self.offset + e.start..self.offset + e.end
    }

    fn push(
        &self,
        buf: &mut DissectBuffer<'pkt>,
        descriptor: &'static FieldDescriptor,
        value: FieldValue<'pkt>,
        e: &Element<'_>,
    ) {
        buf.push_field(descriptor, value, self.range(e));
    }

    fn message(
        &mut self,
        buf: &mut DissectBuffer<'pkt>,
        value_start: usize,
        end: usize,
    ) -> Result<(), PacketError> {
        let fd = FIELD_DESCRIPTORS;
        let mut c = Cursor::new(self.data, value_start, end);
        let (version, e) = c.next_integer()?;
        self.push(buf, &fd[FD_VERSION], FieldValue::I32(version), &e);
        match version {
            // RFC 1157, Section 4 — <https://www.rfc-editor.org/rfc/rfc1157#section-4>
            // and RFC 1901, Section 3 — <https://www.rfc-editor.org/rfc/rfc1901#section-3>:
            // version, community OCTET STRING, data (the PDU).
            VERSION_1 | VERSION_2C => {
                let e = c.next_expect(Tag::OCTET_STRING, "SNMP: expected OCTET STRING")?;
                self.push(buf, &fd[FD_COMMUNITY], FieldValue::Bytes(e.value), &e);
                let e = c.next()?;
                self.pdu_or_data(buf, e)?;
                c.finish()
            }
            VERSION_3 => {
                self.v3(buf, &mut c)?;
                c.finish()
            }
            _ => {
                if !c.is_empty() {
                    let pos = c.pos();
                    let rest = Element {
                        tag: e.tag,
                        start: pos,
                        value_start: pos,
                        end: c.end,
                        value: &self.data[pos..c.end],
                    };
                    self.push(buf, &fd[FD_DATA], FieldValue::Bytes(rest.value), &rest);
                }
                Ok(())
            }
        }
    }

    /// SNMPv3 message after msgVersion. RFC 3412, Section 6 —
    /// <https://www.rfc-editor.org/rfc/rfc3412#section-6>.
    fn v3(
        &mut self,
        buf: &mut DissectBuffer<'pkt>,
        c: &mut Cursor<'pkt>,
    ) -> Result<(), PacketError> {
        let fd = FIELD_DESCRIPTORS;
        let header = c.next_expect(Tag::SEQUENCE, "SNMP: expected SEQUENCE")?;
        let mut h = Cursor::over(self.data, &header);
        let (msg_id, e) = h.next_integer()?;
        self.push(buf, &fd[FD_MSG_ID], FieldValue::I32(msg_id), &e);
        let (max_size, e) = h.next_integer()?;
        self.push(buf, &fd[FD_MSG_MAX_SIZE], FieldValue::I32(max_size), &e);
        let e = h.next_expect(Tag::OCTET_STRING, "SNMP: expected OCTET STRING")?;
        // msgFlags OCTET STRING (SIZE(1)): authFlag, privFlag,
        // reportableFlag in bits 0-2.
        let [flags] = e.value else {
            return Err(PacketError::InvalidHeader(
                "SNMP: msgFlags must be one octet",
            ));
        };
        let flags = *flags;
        self.push(buf, &fd[FD_MSG_FLAGS], FieldValue::U8(flags), &e);
        self.push(buf, &fd[FD_AUTH_FLAG], FieldValue::U8(flags & 0x01), &e);
        self.push(
            buf,
            &fd[FD_PRIV_FLAG],
            FieldValue::U8((flags >> 1) & 0x01),
            &e,
        );
        self.push(
            buf,
            &fd[FD_REPORTABLE_FLAG],
            FieldValue::U8((flags >> 2) & 0x01),
            &e,
        );
        let (model, e) = h.next_integer()?;
        self.push(buf, &fd[FD_SECURITY_MODEL], FieldValue::I32(model), &e);
        h.finish()?;

        let params = c.next_expect(Tag::OCTET_STRING, "SNMP: expected OCTET STRING")?;
        if model != SECURITY_MODEL_USM || !self.usm(buf, &params)? {
            self.push(
                buf,
                &fd[FD_SECURITY_PARAMETERS],
                FieldValue::Bytes(params.value),
                &params,
            );
        }

        // ScopedPduData ::= CHOICE { plaintext ScopedPDU, encryptedPDU
        // OCTET STRING }
        let msg_data = c.next()?;
        if msg_data.is_universal(Tag::OCTET_STRING) && !msg_data.tag.constructed {
            self.push(
                buf,
                &fd[FD_ENCRYPTED_PDU],
                FieldValue::Bytes(msg_data.value),
                &msg_data,
            );
            return Ok(());
        }
        if !(msg_data.is_universal(Tag::SEQUENCE) && msg_data.tag.constructed) {
            return Err(PacketError::InvalidHeader("SNMP: expected SEQUENCE"));
        }
        // ScopedPDU ::= SEQUENCE { contextEngineID OCTET STRING,
        // contextName OCTET STRING, data ANY }
        let mut s = Cursor::over(self.data, &msg_data);
        let e = s.next_expect(Tag::OCTET_STRING, "SNMP: expected OCTET STRING")?;
        self.push(
            buf,
            &fd[FD_CONTEXT_ENGINE_ID],
            FieldValue::Bytes(e.value),
            &e,
        );
        let e = s.next_expect(Tag::OCTET_STRING, "SNMP: expected OCTET STRING")?;
        self.push(buf, &fd[FD_CONTEXT_NAME], FieldValue::Bytes(e.value), &e);
        let e = s.next()?;
        self.pdu_or_data(buf, e)?;
        s.finish()
    }

    /// USM security parameters carried in msgSecurityParameters. Returns
    /// `false` (with nothing pushed) when they are not a well-formed
    /// `UsmSecurityParameters`, so the caller keeps the raw octets.
    ///
    /// RFC 3414, Section 2.4 — <https://www.rfc-editor.org/rfc/rfc3414#section-2.4>.
    fn usm(
        &mut self,
        buf: &mut DissectBuffer<'pkt>,
        params: &Element<'pkt>,
    ) -> Result<bool, PacketError> {
        let mut outer = Cursor::over(self.data, params);
        let Ok(sequence) = outer.next_expect(Tag::SEQUENCE, "") else {
            return Ok(false);
        };
        if !outer.is_empty() {
            return Ok(false);
        }
        // Read all six elements before pushing anything.
        let mut c = Cursor::over(self.data, &sequence);
        let parsed = (|| {
            let engine_id = c.next_expect(Tag::OCTET_STRING, "")?;
            let (boots, boots_e) = c.next_integer()?;
            let (time, time_e) = c.next_integer()?;
            let user = c.next_expect(Tag::OCTET_STRING, "")?;
            let auth = c.next_expect(Tag::OCTET_STRING, "")?;
            let privacy = c.next_expect(Tag::OCTET_STRING, "")?;
            c.finish()?;
            Ok::<_, PacketError>([
                (FieldValue::Bytes(engine_id.value), engine_id),
                (FieldValue::I32(boots), boots_e),
                (FieldValue::I32(time), time_e),
                (FieldValue::Bytes(user.value), user),
                (FieldValue::Bytes(auth.value), auth),
                (FieldValue::Bytes(privacy.value), privacy),
            ])
        })();
        let Ok(elements) = parsed else {
            return Ok(false);
        };

        let fd = FIELD_DESCRIPTORS;
        let idx = buf.begin_container(&fd[FD_USM], FieldValue::Object(0..0), self.range(&sequence));
        for (descriptor, (value, e)) in USM_CHILDREN.iter().zip(elements) {
            self.push(buf, descriptor, value, &e);
        }
        buf.end_container(idx);
        Ok(true)
    }

    /// A PDU (context-specific constructed element), or anything else as
    /// raw data.
    fn pdu_or_data(
        &mut self,
        buf: &mut DissectBuffer<'pkt>,
        e: Element<'pkt>,
    ) -> Result<(), PacketError> {
        let fd = FIELD_DESCRIPTORS;
        if e.tag.class != TagClass::ContextSpecific || !e.tag.constructed || e.tag.number > 0xff {
            self.push(
                buf,
                &fd[FD_DATA],
                FieldValue::Bytes(&self.data[e.start..e.end]),
                &e,
            );
            return Ok(());
        }
        let c = &PDU_CHILDREN;
        let idx = buf.begin_container(&fd[FD_PDU], FieldValue::Object(0..0), self.range(&e));
        let tag_element = Element {
            tag: e.tag,
            start: e.start,
            value_start: e.start,
            end: e.value_start,
            value: &[],
        };
        self.push(
            buf,
            &c[PDU_TYPE],
            FieldValue::U8(e.tag.number as u8),
            &tag_element,
        );
        let mut p = Cursor::over(self.data, &e);
        match e.tag.number {
            PDU_TRAP_V1 => {
                self.trap_v1(buf, &mut p)?;
                p.finish()?;
            }
            0..=8 => {
                // RFC 3416, Section 3 — <https://www.rfc-editor.org/rfc/rfc3416#section-3>:
                // PDU and BulkPDU share one layout:
                // request-id, two INTEGERs, variable-bindings.
                let (request_id, r) = p.next_integer()?;
                self.push(buf, &c[PDU_REQUEST_ID], FieldValue::I32(request_id), &r);
                let (a, ea) = p.next_integer()?;
                let (b, eb) = p.next_integer()?;
                let (fa, fb) = if e.tag.number == PDU_GET_BULK {
                    (PDU_NON_REPEATERS, PDU_MAX_REPETITIONS)
                } else {
                    (PDU_ERROR_STATUS, PDU_ERROR_INDEX)
                };
                self.push(buf, &c[fa], FieldValue::I32(a), &ea);
                self.push(buf, &c[fb], FieldValue::I32(b), &eb);
                self.varbinds(buf, &mut p)?;
                p.finish()?;
            }
            _ => {
                if !e.value.is_empty() {
                    let body = Element {
                        tag: e.tag,
                        start: e.value_start,
                        value_start: e.value_start,
                        end: e.end,
                        value: e.value,
                    };
                    self.push(buf, &c[PDU_DATA], FieldValue::Bytes(e.value), &body);
                }
            }
        }
        buf.end_container(idx);
        Ok(())
    }

    /// SNMPv1 Trap-PDU. RFC 1157, Section 4.1.6 —
    /// <https://www.rfc-editor.org/rfc/rfc1157#section-4.1.6>.
    fn trap_v1(
        &mut self,
        buf: &mut DissectBuffer<'pkt>,
        p: &mut Cursor<'pkt>,
    ) -> Result<(), PacketError> {
        let c = &PDU_CHILDREN;
        let e = p.next_expect(Tag::OBJECT_IDENTIFIER, "SNMP: expected OBJECT IDENTIFIER")?;
        self.push(buf, &c[PDU_ENTERPRISE], FieldValue::Bytes(e.value), &e);
        // NetworkAddress ::= CHOICE { internet IpAddress }
        let e = p.next()?;
        let addr: [u8; 4] = match (e.is_application(0), <[u8; 4]>::try_from(e.value)) {
            (true, Ok(addr)) => addr,
            _ => return Err(PacketError::InvalidHeader("SNMP: expected IpAddress")),
        };
        self.push(buf, &c[PDU_AGENT_ADDR], FieldValue::Ipv4Addr(addr), &e);
        let (generic, e) = p.next_integer()?;
        self.push(buf, &c[PDU_GENERIC_TRAP], FieldValue::I32(generic), &e);
        let (specific, e) = p.next_integer()?;
        self.push(buf, &c[PDU_SPECIFIC_TRAP], FieldValue::I32(specific), &e);
        // TimeTicks ::= [APPLICATION 3] IMPLICIT INTEGER (0..4294967295)
        let e = p.next()?;
        let ticks = match (e.is_application(3), unsigned(e.value, 4)) {
            (true, Some(t)) => t as u32,
            _ => return Err(PacketError::InvalidHeader("SNMP: expected TimeTicks")),
        };
        self.push(buf, &c[PDU_TIME_STAMP], FieldValue::U32(ticks), &e);
        self.varbinds(buf, p)
    }

    /// VarBindList. RFC 3416, Section 3 —
    /// <https://www.rfc-editor.org/rfc/rfc3416#section-3>.
    fn varbinds(
        &mut self,
        buf: &mut DissectBuffer<'pkt>,
        p: &mut Cursor<'pkt>,
    ) -> Result<(), PacketError> {
        let list = p.next_expect(Tag::SEQUENCE, "SNMP: expected SEQUENCE")?;
        let idx = buf.begin_container(
            &PDU_CHILDREN[PDU_VARBINDS],
            FieldValue::Array(0..0),
            self.range(&list),
        );
        let mut items = Cursor::over(self.data, &list);
        while !items.is_empty() {
            let vb = items.next_expect(Tag::SEQUENCE, "SNMP: expected SEQUENCE")?;
            let mut v = Cursor::over(self.data, &vb);
            let name = v.next_expect(Tag::OBJECT_IDENTIFIER, "SNMP: expected OBJECT IDENTIFIER")?;
            let value = v.next()?;
            v.finish()?;
            let obj = buf.begin_container(&FD_VARBIND, FieldValue::Object(0..0), self.range(&vb));
            self.push(
                buf,
                &VARBIND_CHILDREN[VB_NAME],
                FieldValue::Bytes(name.value),
                &name,
            );
            let identifier = self.data[value.start];
            self.push(
                buf,
                &VARBIND_CHILDREN[VB_VALUE_TYPE],
                FieldValue::U8(identifier),
                &value,
            );
            if let Some((descriptor, decoded)) = decode_value(&value) {
                self.push(buf, descriptor, decoded, &value);
            }
            buf.end_container(obj);
        }
        buf.end_container(idx);
        Ok(())
    }
}

/// Decode a variable-binding value (`ObjectSyntax`, RFC 3416, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc3416#section-3>). `NULL` and the
/// `noSuchObject`, `noSuchInstance` and `endOfMibView` exceptions carry no
/// value. Values that do not fit their type are kept as raw bytes.
fn decode_value<'pkt>(e: &Element<'pkt>) -> Option<(&'static FieldDescriptor, FieldValue<'pkt>)> {
    let plain = &VARBIND_CHILDREN[VB_VALUE];
    let raw = FieldValue::Bytes(e.value);
    if e.tag.constructed {
        // RFC 3417, Section 8 — <https://www.rfc-editor.org/rfc/rfc3417#section-8>:
        // simple types use the primitive form.
        return Some((plain, raw));
    }
    let value = match (e.tag.class, e.tag.number) {
        (TagClass::Universal, Tag::NULL) | (TagClass::ContextSpecific, 0..=2) => return None,
        (TagClass::Universal, Tag::INTEGER) => integer(e.value).map_or(raw, FieldValue::I32),
        (TagClass::Universal, Tag::OBJECT_IDENTIFIER) => return Some((&FD_VALUE_OID, raw)),
        // IpAddress ::= [APPLICATION 0] IMPLICIT OCTET STRING (SIZE (4))
        (TagClass::Application, 0) => {
            <[u8; 4]>::try_from(e.value).map_or(raw, FieldValue::Ipv4Addr)
        }
        // Counter32 [1], Unsigned32 / Gauge32 [2], TimeTicks [3]:
        // IMPLICIT INTEGER (0..4294967295)
        (TagClass::Application, 1..=3) => {
            unsigned(e.value, 4).map_or(raw, |v| FieldValue::U32(v as u32))
        }
        // Counter64 ::= [APPLICATION 6] IMPLICIT INTEGER
        // (0..18446744073709551615)
        (TagClass::Application, 6) => unsigned(e.value, 8).map_or(raw, FieldValue::U64),
        // OCTET STRING, Opaque [APPLICATION 4] and anything else.
        _ => raw,
    };
    Some((plain, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::Range;

    // # RFC 1157 / RFC 1901 / RFC 3416 / RFC 3412 / RFC 3414 (SNMP) Coverage
    //
    // | RFC Section       | Description                                     | Test                                  |
    // |-------------------|-------------------------------------------------|---------------------------------------|
    // | 1157 §4           | SNMPv1 message, community, GetRequest           | v1_get_request                        |
    // | 1157 §4.1.6       | SNMPv1 Trap-PDU                                 | v1_trap                               |
    // | 1901 §3           | SNMPv2c message                                 | v2c_response_counter64_end_of_mib     |
    // | 3416 §3           | Response, Counter64, endOfMibView, exceptions   | v2c_response_counter64_end_of_mib     |
    // | 3416 §3           | Application types (IpAddress ... Opaque)        | v2c_application_types                 |
    // | 3416 §3           | GetBulkRequest non-repeaters / max-repetitions  | v2c_get_bulk                          |
    // | 3416 §3           | SNMPv2-Trap                                     | v2c_trap                              |
    // | 3416 §3           | Unknown PDU tag kept as raw data                | unknown_pdu_raw                       |
    // | 3412 §6           | SNMPv3 msgGlobalData, flags, scopedPDU          | v3_discovery_report                   |
    // | 3414 §2.4         | USM security parameters                         | v3_discovery_report                   |
    // | 3412 §6           | encryptedPDU kept as bytes (authPriv)           | v3_auth_priv_encrypted                |
    // | 3412 §6           | Non-USM security parameters kept raw            | v3_non_usm_security_parameters_raw    |
    // | 3417 §8           | Long-form length accepted                       | long_form_length                      |
    // | 3417 §8           | Indefinite length rejected                      | indefinite_length_rejected            |
    // | X.690 8.1.3       | Truncated message / inner overrun               | truncated_message                     |
    // | 3416 §3           | Malformed structure rejected, buffer rolled back| malformed_structure_rejected          |
    // | —                 | Unknown version kept as raw data                | unknown_version_raw                   |
    // | X.690 8.19        | OID formatting                                  | oid_formatting                        |

    // -----------------------------------------------------------------------
    // BER builders
    // -----------------------------------------------------------------------

    fn tlv(identifier: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![identifier];
        let len = value.len();
        if len < 0x80 {
            v.push(len as u8);
        } else if len < 0x100 {
            v.extend_from_slice(&[0x81, len as u8]);
        } else {
            v.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
        }
        v.extend_from_slice(value);
        v
    }

    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }

    fn int(v: i32) -> Vec<u8> {
        let bytes = v.to_be_bytes();
        let mut start = 0;
        while start < 3
            && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
                || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0))
        {
            start += 1;
        }
        tlv(0x02, &bytes[start..])
    }

    fn octets(v: &[u8]) -> Vec<u8> {
        tlv(0x04, v)
    }

    /// OID 1.3.6.1.2.1.1.<last>.0 (system group).
    fn sys_oid(last: u8) -> Vec<u8> {
        tlv(0x06, &[0x2b, 6, 1, 2, 1, 1, last, 0])
    }

    fn varbind(name: Vec<u8>, value: Vec<u8>) -> Vec<u8> {
        seq(&[name, value])
    }

    fn pdu(tag: u8, request_id: i32, a: i32, b: i32, varbinds: &[Vec<u8>]) -> Vec<u8> {
        tlv(
            0xa0 | tag,
            &[int(request_id), int(a), int(b), seq(varbinds)].concat(),
        )
    }

    fn community_message(version: i32, community: &[u8], pdu: Vec<u8>) -> Vec<u8> {
        seq(&[int(version), octets(community), pdu])
    }

    // -----------------------------------------------------------------------
    // Navigation helpers
    // -----------------------------------------------------------------------

    fn children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        range: &Range<u32>,
    ) -> Vec<&'a Field<'pkt>> {
        let fields = buf.fields();
        let mut out = Vec::new();
        let mut idx = range.start;
        while idx < range.end {
            let f = &fields[idx as usize];
            out.push(f);
            idx = match f.value.as_container_range() {
                Some(r) => r.end.max(idx + 1),
                None => idx + 1,
            };
        }
        out
    }

    fn child<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        range: &Range<u32>,
        name: &str,
    ) -> Option<&'a Field<'pkt>> {
        children(buf, range).into_iter().find(|f| f.name() == name)
    }

    fn range_of(f: &Field<'_>) -> Range<u32> {
        f.value.as_container_range().unwrap().clone()
    }

    fn top<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> Option<&'a Field<'pkt>> {
        let r = buf.layers()[0].field_range.clone();
        child(buf, &r, name)
    }

    fn pdu_range(buf: &DissectBuffer<'_>) -> Range<u32> {
        range_of(top(buf, "pdu").unwrap())
    }

    fn varbinds(buf: &DissectBuffer<'_>) -> Vec<Range<u32>> {
        let p = pdu_range(buf);
        let vbs = range_of(child(buf, &p, "varbinds").unwrap());
        children(buf, &vbs).into_iter().map(range_of).collect()
    }

    fn oid_string(buf: &DissectBuffer<'_>, data: &[u8], field: &Field<'_>) -> String {
        let mut out = Vec::new();
        let ctx = FormatContext {
            packet_data: data,
            scratch: buf.scratch(),
            layer_range: 0..data.len() as u32,
            field_range: field.range.start as u32..field.range.end as u32,
        };
        (field.descriptor.format_fn.unwrap())(&field.value, &ctx, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn dissect(data: &[u8]) -> DissectBuffer<'_> {
        let mut buf = DissectBuffer::new();
        let res = SnmpDissector.dissect(data, &mut buf, 0).unwrap();
        assert_eq!(res.bytes_consumed, data.len());
        assert_eq!(res.next, DispatchHint::End);
        buf
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn v1_get_request() {
        let data = community_message(
            0,
            b"public",
            pdu(0, 0x1234, 0, 0, &[varbind(sys_oid(1), tlv(0x05, &[]))]),
        );
        let buf = dissect(&data);
        assert_eq!(buf.layers()[0].name, "SNMP");
        assert_eq!(buf.layers()[0].range, 0..data.len());
        assert_eq!(top(&buf, "version").unwrap().value, FieldValue::I32(0));
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "version_name"),
            Some("SNMPv1")
        );
        assert_eq!(
            top(&buf, "community").unwrap().value,
            FieldValue::Bytes(b"public")
        );
        assert_eq!(top(&buf, "community").unwrap().range, 5..13);
        assert!(top(&buf, "msg_id").is_none());

        let p = pdu_range(&buf);
        assert_eq!(child(&buf, &p, "type").unwrap().value, FieldValue::U8(0));
        assert_eq!(
            buf.resolve_nested_display_name(&p, "type_name"),
            Some("get-request")
        );
        assert_eq!(
            child(&buf, &p, "request_id").unwrap().value,
            FieldValue::I32(0x1234)
        );
        assert_eq!(
            buf.resolve_nested_display_name(&p, "error_status_name"),
            Some("noError")
        );
        assert_eq!(
            child(&buf, &p, "error_index").unwrap().value,
            FieldValue::I32(0)
        );
        let vbs = varbinds(&buf);
        assert_eq!(vbs.len(), 1);
        let name = child(&buf, &vbs[0], "name").unwrap();
        assert_eq!(oid_string(&buf, &data, name), "\"1.3.6.1.2.1.1.1.0\"");
        assert_eq!(
            child(&buf, &vbs[0], "value_type").unwrap().value,
            FieldValue::U8(0x05)
        );
        assert_eq!(
            buf.resolve_nested_display_name(&vbs[0], "value_type_name"),
            Some("NULL")
        );
        assert!(child(&buf, &vbs[0], "value").is_none());
    }

    #[test]
    fn v2c_response_counter64_end_of_mib() {
        let counter64 = tlv(0x46, &[0x00, 0xff, 0, 0, 0, 0, 0, 0, 1]);
        let data = community_message(
            1,
            b"private",
            pdu(
                2,
                -5,
                0,
                0,
                &[
                    varbind(sys_oid(3), counter64),
                    varbind(sys_oid(4), tlv(0x82, &[])),
                    varbind(sys_oid(5), tlv(0x80, &[])),
                    varbind(sys_oid(6), tlv(0x81, &[])),
                ],
            ),
        );
        let buf = dissect(&data);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "version_name"),
            Some("SNMPv2c")
        );
        let p = pdu_range(&buf);
        assert_eq!(
            buf.resolve_nested_display_name(&p, "type_name"),
            Some("response")
        );
        assert_eq!(
            child(&buf, &p, "request_id").unwrap().value,
            FieldValue::I32(-5)
        );
        let vbs = varbinds(&buf);
        assert_eq!(
            child(&buf, &vbs[0], "value").unwrap().value,
            FieldValue::U64(0xff00_0000_0000_0001)
        );
        for (vb, name) in [
            (&vbs[1], "endOfMibView"),
            (&vbs[2], "noSuchObject"),
            (&vbs[3], "noSuchInstance"),
        ] {
            assert_eq!(
                buf.resolve_nested_display_name(vb, "value_type_name"),
                Some(name)
            );
            assert!(child(&buf, vb, "value").is_none());
        }
    }

    #[test]
    fn v2c_application_types() {
        let data = community_message(
            1,
            b"c",
            pdu(
                2,
                1,
                0,
                0,
                &[
                    varbind(sys_oid(1), int(-2)),
                    varbind(sys_oid(1), octets(b"Linux")),
                    varbind(sys_oid(2), tlv(0x06, &[0x2b, 6, 1, 4, 1, 0x83, 0x74, 1])),
                    varbind(sys_oid(1), tlv(0x40, &[192, 0, 2, 1])),
                    varbind(sys_oid(1), tlv(0x41, &[0x00, 0xff, 0xff, 0xff, 0xff])),
                    varbind(sys_oid(1), tlv(0x42, &[0x10])),
                    varbind(sys_oid(3), tlv(0x43, &[0x01, 0x00])),
                    varbind(sys_oid(1), tlv(0x44, &[0x9f, 0x78, 0x04])),
                    varbind(sys_oid(1), tlv(0x02, &[1, 2, 3, 4, 5])),
                    varbind(sys_oid(1), tlv(0x40, &[1, 2, 3])),
                    varbind(sys_oid(1), tlv(0x41, &[1, 2, 3, 4, 5, 6])),
                    varbind(sys_oid(1), tlv(0x46, &[1; 10])),
                    varbind(sys_oid(1), tlv(0x45, &[7])),
                ],
            ),
        );
        let buf = dissect(&data);
        let vbs = varbinds(&buf);
        let v = |i: usize| child(&buf, &vbs[i], "value").unwrap().value.clone();
        assert_eq!(v(0), FieldValue::I32(-2));
        assert_eq!(v(1), FieldValue::Bytes(b"Linux"));
        let oid_value = child(&buf, &vbs[2], "value").unwrap();
        assert_eq!(oid_string(&buf, &data, oid_value), "\"1.3.6.1.4.1.500.1\"");
        assert_eq!(v(3), FieldValue::Ipv4Addr([192, 0, 2, 1]));
        assert_eq!(v(4), FieldValue::U32(0xffff_ffff));
        assert_eq!(v(5), FieldValue::U32(0x10));
        assert_eq!(v(6), FieldValue::U32(256));
        assert_eq!(v(7), FieldValue::Bytes(&[0x9f, 0x78, 0x04]));
        assert_eq!(v(8), FieldValue::Bytes(&[1, 2, 3, 4, 5]));
        assert_eq!(v(9), FieldValue::Bytes(&[1, 2, 3]));
        assert_eq!(v(10), FieldValue::Bytes(&[1, 2, 3, 4, 5, 6]));
        assert_eq!(v(11), FieldValue::Bytes(&[1; 10]));
        assert_eq!(v(12), FieldValue::Bytes(&[7]));
        for (i, name) in [
            (0, "INTEGER"),
            (1, "OCTET STRING"),
            (2, "OBJECT IDENTIFIER"),
            (3, "IpAddress"),
            (4, "Counter32"),
            (5, "Gauge32"),
            (6, "TimeTicks"),
            (7, "Opaque"),
        ] {
            assert_eq!(
                buf.resolve_nested_display_name(&vbs[i], "value_type_name"),
                Some(name)
            );
        }
        assert_eq!(
            buf.resolve_nested_display_name(&vbs[12], "value_type_name"),
            None
        );
    }

    #[test]
    fn v2c_get_bulk() {
        let data = community_message(
            1,
            b"public",
            pdu(5, 77, 1, 10, &[varbind(sys_oid(1), tlv(0x05, &[]))]),
        );
        let buf = dissect(&data);
        let p = pdu_range(&buf);
        assert_eq!(
            buf.resolve_nested_display_name(&p, "type_name"),
            Some("get-bulk-request")
        );
        assert_eq!(
            child(&buf, &p, "non_repeaters").unwrap().value,
            FieldValue::I32(1)
        );
        assert_eq!(
            child(&buf, &p, "max_repetitions").unwrap().value,
            FieldValue::I32(10)
        );
        assert!(child(&buf, &p, "error_status").is_none());
    }

    #[test]
    fn v2c_trap() {
        // sysUpTime.0 and snmpTrapOID.0 (linkDown, 1.3.6.1.6.3.1.1.5.3).
        let data = community_message(
            1,
            b"public",
            pdu(
                7,
                9,
                0,
                0,
                &[
                    varbind(sys_oid(3), tlv(0x43, &[0x12, 0x34])),
                    varbind(
                        tlv(0x06, &[0x2b, 6, 1, 6, 3, 1, 1, 4, 1, 0]),
                        tlv(0x06, &[0x2b, 6, 1, 6, 3, 1, 1, 5, 3]),
                    ),
                ],
            ),
        );
        let buf = dissect(&data);
        let p = pdu_range(&buf);
        assert_eq!(
            buf.resolve_nested_display_name(&p, "type_name"),
            Some("snmpV2-trap")
        );
        let vbs = varbinds(&buf);
        assert_eq!(
            oid_string(&buf, &data, child(&buf, &vbs[1], "value").unwrap()),
            "\"1.3.6.1.6.3.1.1.5.3\""
        );
    }

    #[test]
    fn v1_trap() {
        let trap = tlv(
            0xa4,
            &[
                tlv(0x06, &[0x2b, 6, 1, 4, 1, 9]),
                tlv(0x40, &[10, 0, 0, 1]),
                int(2),
                int(0),
                tlv(0x43, &[0x01, 0x02, 0x03]),
                seq(&[varbind(
                    tlv(0x06, &[0x2b, 6, 1, 2, 1, 2, 2, 1, 1, 2]),
                    int(2),
                )]),
            ]
            .concat(),
        );
        let data = community_message(0, b"public", trap);
        let buf = dissect(&data);
        let p = pdu_range(&buf);
        assert_eq!(
            buf.resolve_nested_display_name(&p, "type_name"),
            Some("trap")
        );
        let enterprise = child(&buf, &p, "enterprise").unwrap();
        assert_eq!(oid_string(&buf, &data, enterprise), "\"1.3.6.1.4.1.9\"");
        assert_eq!(
            child(&buf, &p, "agent_addr").unwrap().value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert_eq!(
            buf.resolve_nested_display_name(&p, "generic_trap_name"),
            Some("linkDown")
        );
        assert_eq!(
            child(&buf, &p, "specific_trap").unwrap().value,
            FieldValue::I32(0)
        );
        assert_eq!(
            child(&buf, &p, "time_stamp").unwrap().value,
            FieldValue::U32(0x010203)
        );
        assert!(child(&buf, &p, "request_id").is_none());
        assert_eq!(varbinds(&buf).len(), 1);
    }

    /// SNMPv3 message with the given flags, security model, security
    /// parameters and msgData.
    fn v3_message(flags: u8, model: i32, security: Vec<u8>, msg_data: Vec<u8>) -> Vec<u8> {
        seq(&[
            int(3),
            seq(&[int(0x4c2b), int(65507), octets(&[flags]), int(model)]),
            octets(&security),
            msg_data,
        ])
    }

    fn usm(engine_id: &[u8], boots: i32, time: i32, user: &[u8]) -> Vec<u8> {
        seq(&[
            octets(engine_id),
            int(boots),
            int(time),
            octets(user),
            octets(&[0xaa; 12]),
            octets(&[]),
        ])
    }

    #[test]
    fn v3_discovery_report() {
        // RFC 3414, Section 4 — <https://www.rfc-editor.org/rfc/rfc3414#section-4>:
        // discovery: the engine replies with a Report
        // carrying usmStatsUnknownEngineIDs.
        let report = pdu(
            8,
            0x5d,
            0,
            0,
            &[varbind(
                tlv(0x06, &[0x2b, 6, 1, 6, 3, 15, 1, 1, 4, 0]),
                tlv(0x41, &[1]),
            )],
        );
        let engine = [0x80, 0, 0x1f, 0x88, 0x80, 1, 2, 3, 4];
        let scoped = seq(&[octets(&engine), octets(b"ctx"), report]);
        let data = v3_message(0x04 | 0x01, 3, usm(&engine, 2, 1234, b"alice"), scoped);
        let buf = dissect(&data);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "version_name"),
            Some("SNMPv3")
        );
        assert!(top(&buf, "community").is_none());
        assert_eq!(top(&buf, "msg_id").unwrap().value, FieldValue::I32(0x4c2b));
        assert_eq!(
            top(&buf, "msg_max_size").unwrap().value,
            FieldValue::I32(65507)
        );
        assert_eq!(top(&buf, "msg_flags").unwrap().value, FieldValue::U8(5));
        assert_eq!(
            buf.resolve_display_name(layer, "msg_flags_name"),
            Some("authNoPriv")
        );
        assert_eq!(top(&buf, "auth_flag").unwrap().value, FieldValue::U8(1));
        assert_eq!(top(&buf, "priv_flag").unwrap().value, FieldValue::U8(0));
        assert_eq!(
            top(&buf, "reportable_flag").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "msg_security_model_name"),
            Some("USM")
        );
        assert!(top(&buf, "security_parameters").is_none());
        let u = range_of(top(&buf, "usm").unwrap());
        assert_eq!(
            child(&buf, &u, "authoritative_engine_id").unwrap().value,
            FieldValue::Bytes(&engine)
        );
        assert_eq!(
            child(&buf, &u, "authoritative_engine_boots").unwrap().value,
            FieldValue::I32(2)
        );
        assert_eq!(
            child(&buf, &u, "authoritative_engine_time").unwrap().value,
            FieldValue::I32(1234)
        );
        assert_eq!(
            child(&buf, &u, "user_name").unwrap().value,
            FieldValue::Bytes(b"alice")
        );
        assert_eq!(
            child(&buf, &u, "authentication_parameters").unwrap().value,
            FieldValue::Bytes(&[0xaa; 12])
        );
        assert_eq!(
            child(&buf, &u, "privacy_parameters").unwrap().value,
            FieldValue::Bytes(&[])
        );
        assert_eq!(
            top(&buf, "context_engine_id").unwrap().value,
            FieldValue::Bytes(&engine)
        );
        assert_eq!(
            top(&buf, "context_name").unwrap().value,
            FieldValue::Bytes(b"ctx")
        );
        let p = pdu_range(&buf);
        assert_eq!(
            buf.resolve_nested_display_name(&p, "type_name"),
            Some("report")
        );
        assert_eq!(
            child(&buf, &varbinds(&buf)[0], "value").unwrap().value,
            FieldValue::U32(1)
        );
    }

    #[test]
    fn v3_auth_priv_encrypted() {
        let encrypted = octets(&[0x5a; 40]);
        let data = v3_message(0x03, 3, usm(b"eng", 1, 2, b"bob"), encrypted);
        let buf = dissect(&data);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "msg_flags_name"),
            Some("authPriv")
        );
        assert_eq!(
            top(&buf, "encrypted_pdu").unwrap().value,
            FieldValue::Bytes(&[0x5a; 40])
        );
        assert!(top(&buf, "pdu").is_none());
        assert!(top(&buf, "context_engine_id").is_none());
    }

    #[test]
    fn v3_non_usm_security_parameters_raw() {
        let scoped = seq(&[octets(b""), octets(b""), pdu(0, 1, 0, 0, &[])]);
        // TSM (4): msgSecurityParameters is a zero-length OCTET STRING.
        let data = v3_message(0x04, 4, Vec::new(), scoped.clone());
        let buf = dissect(&data);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "msg_security_model_name"),
            Some("TSM")
        );
        assert_eq!(
            top(&buf, "security_parameters").unwrap().value,
            FieldValue::Bytes(&[])
        );
        assert!(top(&buf, "usm").is_none());
        // USM parameters that are not a valid SEQUENCE stay raw as well.
        let data = v3_message(0x00, 3, vec![1, 2, 3], scoped);
        let buf = dissect(&data);
        assert_eq!(
            top(&buf, "security_parameters").unwrap().value,
            FieldValue::Bytes(&[1, 2, 3])
        );
        assert!(top(&buf, "usm").is_none());
    }

    #[test]
    fn unknown_pdu_raw() {
        let data = community_message(1, b"public", tlv(0xa9, &[1, 2]));
        let buf = dissect(&data);
        let p = pdu_range(&buf);
        assert_eq!(child(&buf, &p, "type").unwrap().value, FieldValue::U8(9));
        assert_eq!(buf.resolve_nested_display_name(&p, "type_name"), None);
        assert_eq!(
            child(&buf, &p, "data").unwrap().value,
            FieldValue::Bytes(&[1, 2])
        );
        // A non-PDU element after the community.
        let data = community_message(1, b"public", octets(&[7]));
        let buf = dissect(&data);
        assert!(top(&buf, "pdu").is_none());
        assert_eq!(
            top(&buf, "data").unwrap().value,
            FieldValue::Bytes(&[4, 1, 7])
        );
    }

    #[test]
    fn unknown_version_raw() {
        let data = seq(&[int(2), octets(b"x"), int(1)]);
        let buf = dissect(&data);
        assert_eq!(top(&buf, "version").unwrap().value, FieldValue::I32(2));
        let layer = &buf.layers()[0];
        assert_eq!(buf.resolve_display_name(layer, "version_name"), None);
        assert_eq!(
            top(&buf, "data").unwrap().value,
            FieldValue::Bytes(&[0x04, 1, b'x', 0x02, 1, 1])
        );
    }

    #[test]
    fn long_form_length() {
        let community = [b'a'; 200];
        let data = community_message(1, &community, pdu(0, 1, 0, 0, &[]));
        assert_eq!(data[1], 0x81);
        let buf = dissect(&data);
        assert_eq!(
            top(&buf, "community").unwrap().value,
            FieldValue::Bytes(&community)
        );
    }

    #[test]
    fn indefinite_length_rejected() {
        // RFC 3417, Section 8 — <https://www.rfc-editor.org/rfc/rfc3417#section-8>:
        // "use of the indefinite form encoding is
        // prohibited."
        let mut buf = DissectBuffer::new();
        let data = [0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(
            SnmpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(
                "BER indefinite length not supported"
            ))
        );
        let inner = [0x30, 0x05, 0x02, 0x01, 0x00, 0x30, 0x80];
        assert_eq!(
            SnmpDissector.dissect(&inner, &mut buf, 0),
            Err(PacketError::InvalidHeader(
                "BER indefinite length not supported"
            ))
        );
        assert!(buf.layers().is_empty());
        assert_eq!(buf.field_count(), 0);
    }

    #[test]
    fn truncated_message() {
        let data = community_message(1, b"public", pdu(0, 1, 0, 0, &[]));
        let mut buf = DissectBuffer::new();
        assert_eq!(
            SnmpDissector.dissect(&data[..10], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: data.len(),
                actual: 10
            })
        );
        assert_eq!(
            SnmpDissector.dissect(&[], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 1,
                actual: 0
            })
        );
        // An inner element claiming more octets than its SEQUENCE holds.
        let bad = [0x30, 0x03, 0x02, 0x05, 0x00];
        assert_eq!(
            SnmpDissector.dissect(&bad, &mut buf, 0),
            Err(PacketError::InvalidHeader(
                "SNMP: BER element overruns its container"
            ))
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn malformed_structure_rejected() {
        let mut buf = DissectBuffer::new();
        let cases: [(Vec<u8>, &str); 7] = [
            (octets(b"x"), "SNMP message is not a SEQUENCE"),
            (seq(&[octets(b"x")]), "SNMP: expected INTEGER"),
            (seq(&[int(1)]), "SNMP: missing element"),
            (
                seq(&[tlv(0x02, &[1, 2, 3, 4, 5])]),
                "SNMP: INTEGER out of range",
            ),
            (
                community_message(
                    1,
                    b"c",
                    tlv(
                        0xa0,
                        &[int(1).as_slice(), &int(0), &int(0), &int(0)].concat(),
                    ),
                ),
                "SNMP: expected SEQUENCE",
            ),
            (
                community_message(1, b"c", pdu(0, 1, 0, 0, &[seq(&[int(1), int(2)])])),
                "SNMP: expected OBJECT IDENTIFIER",
            ),
            (
                seq(&[int(3), seq(&[int(1), int(484), octets(&[]), int(3)])]),
                "SNMP: msgFlags must be one octet",
            ),
        ];
        for (data, message) in cases {
            let r = SnmpDissector.dissect(&data, &mut DissectBuffer::new(), 0);
            assert_eq!(r, Err(PacketError::InvalidHeader(message)), "{message}");
        }
        // The v1 Trap agent-addr must be an IpAddress.
        let trap = tlv(
            0xa4,
            &[
                tlv(0x06, &[0x2b]),
                octets(&[10, 0, 0, 1]),
                int(0),
                int(0),
                tlv(0x43, &[0]),
                seq(&[]),
            ]
            .concat(),
        );
        let data = community_message(0, b"c", trap);
        assert_eq!(
            SnmpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader("SNMP: expected IpAddress"))
        );
        assert!(buf.layers().is_empty());
        assert_eq!(buf.field_count(), 0);
    }

    #[test]
    fn constructed_primitive_mismatch_rejected() {
        // RFC 3417, Section 8 —
        // <https://www.rfc-editor.org/rfc/rfc3417#section-8>: "the primitive
        // form shall be used for all simple types, i.e., INTEGER, OCTET
        // STRING, and OBJECT IDENTIFIER (either IMPLICIT or explicit). The
        // constructed form of encoding shall be used only for structured
        // types, i.e., a SEQUENCE or an IMPLICIT SEQUENCE."
        let constructed_community = tlv(0x24, &octets(b"public"));
        let data = seq(&[int(1), constructed_community, pdu(0, 1, 0, 0, &[])]);
        assert_eq!(
            SnmpDissector.dissect(&data, &mut DissectBuffer::new(), 0),
            Err(PacketError::InvalidHeader("SNMP: expected OCTET STRING"))
        );
        let data = seq(&[tlv(0x22, &int(1)), octets(b"c")]);
        assert_eq!(
            SnmpDissector.dissect(&data, &mut DissectBuffer::new(), 0),
            Err(PacketError::InvalidHeader("SNMP: expected INTEGER"))
        );
        // A primitive encoding with the SEQUENCE tag number.
        let data = community_message(
            1,
            b"c",
            tlv(0xa0, &[int(1), int(0), int(0), tlv(0x10, &[])].concat()),
        );
        assert_eq!(
            SnmpDissector.dissect(&data, &mut DissectBuffer::new(), 0),
            Err(PacketError::InvalidHeader("SNMP: expected SEQUENCE"))
        );
        // A constructed value in a variable binding is kept as raw bytes.
        let data = community_message(
            1,
            b"c",
            pdu(2, 1, 0, 0, &[varbind(sys_oid(1), tlv(0x22, &int(7)))]),
        );
        let buf = dissect(&data);
        assert_eq!(
            child(&buf, &varbinds(&buf)[0], "value").unwrap().value,
            FieldValue::Bytes(&[0x02, 0x01, 0x07])
        );
    }

    #[test]
    fn trailing_elements_rejected() {
        let extra = octets(b"junk");
        let cases = [
            // After the PDU.
            seq(&[int(1), octets(b"c"), pdu(0, 1, 0, 0, &[]), extra.clone()]),
            // After variable-bindings.
            community_message(
                1,
                b"c",
                tlv(
                    0xa0,
                    &[int(1), int(0), int(0), seq(&[]), extra.clone()].concat(),
                ),
            ),
            // After a VarBind value.
            community_message(
                1,
                b"c",
                pdu(
                    0,
                    1,
                    0,
                    0,
                    &[seq(&[sys_oid(1), tlv(0x05, &[]), extra.clone()])],
                ),
            ),
            // After msgSecurityModel.
            seq(&[
                int(3),
                seq(&[int(1), int(484), octets(&[4]), int(3), extra.clone()]),
                octets(&[]),
                seq(&[octets(b""), octets(b""), pdu(0, 1, 0, 0, &[])]),
            ]),
            // After the ScopedPDU data.
            v3_message(
                4,
                4,
                vec![],
                seq(&[
                    octets(b""),
                    octets(b""),
                    pdu(0, 1, 0, 0, &[]),
                    extra.clone(),
                ]),
            ),
        ];
        for data in cases {
            assert_eq!(
                SnmpDissector.dissect(&data, &mut DissectBuffer::new(), 0),
                Err(PacketError::InvalidHeader(
                    "SNMP: unexpected trailing element"
                ))
            );
        }
        // Extra elements in UsmSecurityParameters: kept as raw parameters.
        let mut params = usm(b"e", 1, 2, b"u");
        params[1] += extra.len() as u8;
        params.extend_from_slice(&extra);
        let data = v3_message(
            4,
            3,
            params.clone(),
            seq(&[octets(b""), octets(b""), pdu(0, 1, 0, 0, &[])]),
        );
        let buf = dissect(&data);
        assert!(top(&buf, "usm").is_none());
        assert_eq!(
            top(&buf, "security_parameters").unwrap().value,
            FieldValue::Bytes(&params)
        );
    }

    #[test]
    fn negative_unsigned_values_kept_raw() {
        // RFC 3416, Section 3 — <https://www.rfc-editor.org/rfc/rfc3416#section-3>:
        // Counter32 is INTEGER (0..4294967295); a
        // two's-complement encoding with bit 8 set is negative.
        let data = community_message(
            1,
            b"c",
            pdu(
                2,
                1,
                0,
                0,
                &[
                    varbind(sys_oid(1), tlv(0x41, &[0xff])),
                    varbind(sys_oid(1), tlv(0x46, &[0x80, 0, 0, 0, 0, 0, 0, 0])),
                    varbind(sys_oid(1), tlv(0x41, &[0x7f])),
                ],
            ),
        );
        let buf = dissect(&data);
        let vbs = varbinds(&buf);
        let v = |i: usize| child(&buf, &vbs[i], "value").unwrap().value.clone();
        assert_eq!(v(0), FieldValue::Bytes(&[0xff]));
        assert_eq!(v(1), FieldValue::Bytes(&[0x80, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(v(2), FieldValue::U32(0x7f));
    }

    #[test]
    fn oid_formatting() {
        let mut buf = DissectBuffer::new();
        let cases: [(&[u8], &str); 6] = [
            (&[0x2b, 6, 1], "\"1.3.6.1\""),
            (&[0x00], "\"0.0\""),
            (&[0x88, 0x37, 0x03], "\"2.999.3\""),
            (&[], "\"\""),
            // Last subidentifier with the continuation bit set: hex.
            (&[0x2b, 0x86], "\"2b86\""),
            // Subidentifier overflowing 64 bits: hex.
            (
                &[
                    0x2b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
                ],
                "\"2bffffffffffffffffff7f\"",
            ),
        ];
        for (contents, expected) in cases {
            buf.clear();
            let value = FieldValue::Bytes(contents);
            let ctx = FormatContext {
                packet_data: contents,
                scratch: &[],
                layer_range: 0..0,
                field_range: 0..0,
            };
            let mut out = Vec::new();
            format_oid(&value, &ctx, &mut out).unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), expected);
        }
        let ctx = FormatContext {
            packet_data: &[],
            scratch: &[],
            layer_range: 0..0,
            field_range: 0..0,
        };
        let mut out = Vec::new();
        format_oid(&FieldValue::U8(1), &ctx, &mut out).unwrap();
        assert_eq!(out, b"\"\"");
    }

    #[test]
    fn display_fns_cover_all_values() {
        let v = FieldValue::U16(0);
        for f in [
            version_name,
            security_level_name,
            security_model_name,
            pdu_type_name,
            error_status_name,
            generic_trap_name,
            value_type_name,
        ] {
            assert_eq!(f(&v, &[]), None);
        }
        assert_eq!(
            security_level_name(&FieldValue::U8(2), &[]),
            Some("reserved")
        );
        assert_eq!(security_model_name(&FieldValue::I32(0), &[]), Some("any"));
        assert_eq!(
            security_model_name(&FieldValue::I32(1), &[]),
            Some("SNMPv1")
        );
        assert_eq!(
            security_model_name(&FieldValue::I32(2), &[]),
            Some("SNMPv2c")
        );
        assert_eq!(security_model_name(&FieldValue::I32(9), &[]), None);
        let names: Vec<_> = (0..=19)
            .map(|i| error_status_name(&FieldValue::I32(i), &[]))
            .collect();
        assert_eq!(names[18], Some("inconsistentName"));
        assert_eq!(names[19], None);
        assert!(names[..19].iter().all(Option::is_some));
        let traps: Vec<_> = (0..=7)
            .map(|i| generic_trap_name(&FieldValue::I32(i), &[]))
            .collect();
        assert!(traps[..7].iter().all(Option::is_some));
        assert_eq!(traps[7], None);
        for (t, name) in [
            (1, "get-next-request"),
            (3, "set-request"),
            (6, "inform-request"),
        ] {
            assert_eq!(pdu_type_name(&FieldValue::U8(t), &[]), Some(name));
        }
    }

    #[test]
    fn metadata() {
        let d = SnmpDissector;
        assert_eq!(d.name(), "Simple Network Management Protocol");
        assert_eq!(d.short_name(), "SNMP");
        assert_eq!(d.layer(), Some(ProtocolLayer::Application));
        assert_eq!(d.references()[2].id, "RFC 3416");
        assert_eq!(d.field_descriptors()[FD_PDU].name, "pdu");
        assert_eq!((SNMP_PORT, SNMP_TRAP_PORT), (161, 162));
    }
}
