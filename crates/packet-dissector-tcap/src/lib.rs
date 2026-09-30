//! TCAP (Transaction Capabilities Application Part) dissector.
//!
//! Decodes the ITU-T TCAP transaction portion (Unidirectional, Begin, End,
//! Continue, Abort), the dialogue portion (AARQ, AARE, ABRT and AUDT with
//! the application context name) and the components (Invoke, Return Result,
//! Return Error, Reject). Component parameters are kept as raw BER; TC-users
//! such as MAP decode them from the [`Message`] view.
//!
//! ANSI TCAP (T1.114) is not supported.
//!
//! ## References
//! - ITU-T Q.773 (06/97), TCAP formats and encoding:
//!   <https://www.itu.int/rec/T-REC-Q.773>
//! - ITU-T X.690 (02/2021), BER: <https://www.itu.int/rec/T-REC-X.690>

#![deny(missing_docs)]

pub mod ber;

use core::ops::Range;

use ber::{
    CLASS_APPLICATION, CLASS_CONTEXT, CLASS_UNIVERSAL, Children, TAG_EXTERNAL, TAG_INTEGER,
    TAG_NULL, TAG_OID, TAG_SEQUENCE, Tlv,
};
use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{Field, FieldDescriptor, FieldType, FieldValue, FormatContext};
use packet_dissector_core::packet::DissectBuffer;

// Message type tags (APPLICATION class, constructed).
// ITU-T Q.773, clause 3.1 — MessageType ::= CHOICE { unidirectional
// [APPLICATION 1], begin [APPLICATION 2], end [APPLICATION 4], continue
// [APPLICATION 5], abort [APPLICATION 7] }.
const MSG_UNIDIRECTIONAL: u32 = 1;
const MSG_BEGIN: u32 = 2;
const MSG_END: u32 = 4;
const MSG_CONTINUE: u32 = 5;
const MSG_ABORT: u32 = 7;

// Transaction portion elements (APPLICATION class). Q.773, clause 3.1.
const APP_OTID: u32 = 8;
const APP_DTID: u32 = 9;
const APP_P_ABORT_CAUSE: u32 = 10;
const APP_DIALOGUE_PORTION: u32 = 11;
const APP_COMPONENT_PORTION: u32 = 12;

/// `dialogue-as-id` { ccitt recommendation q 773 as(1) dialogue-as(1)
/// version1(1) }, encoded. Q.773, clause 4.2.3.1, Table 37.
pub const DIALOGUE_AS_ID: &[u8] = &[0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01];
/// `uniDialogue-as-id` { ccitt recommendation q 773 as(1) unidialogue-as(2)
/// version1(1) }, encoded. Q.773, clause 4.2.3.1, Table 36.
pub const UNIDIALOGUE_AS_ID: &[u8] = &[0x00, 0x11, 0x86, 0x05, 0x01, 0x02, 0x01];

/// Returns the name of a message type (tag number of the APPLICATION tag).
///
/// ITU-T Q.773, clause 3.1 — <https://www.itu.int/rec/T-REC-Q.773>
fn message_type_name(t: u8) -> Option<&'static str> {
    Some(match u32::from(t) {
        MSG_UNIDIRECTIONAL => "Unidirectional",
        MSG_BEGIN => "Begin",
        MSG_END => "End",
        MSG_CONTINUE => "Continue",
        MSG_ABORT => "Abort",
        _ => return None,
    })
}

/// Returns the name of a P-Abort cause.
///
/// ITU-T Q.773, clause 3.1 — <https://www.itu.int/rec/T-REC-Q.773>
fn p_abort_cause_name(cause: i32) -> Option<&'static str> {
    Some(match cause {
        0 => "unrecognizedMessageType",
        1 => "unrecognizedTransactionID",
        2 => "badlyFormattedTransactionPortion",
        3 => "incorrectTransactionPortion",
        4 => "resourceLimitation",
        _ => return None,
    })
}

/// Returns the name of a component type (context-specific tag number).
///
/// ITU-T Q.773, clause 3.1 — <https://www.itu.int/rec/T-REC-Q.773>
pub fn component_type_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "invoke",
        2 => "returnResultLast",
        3 => "returnError",
        4 => "reject",
        7 => "returnResultNotLast",
        _ => return None,
    })
}

/// Returns the name of a Reject problem type (context-specific tag number).
///
/// ITU-T Q.773, clause 3.1 — <https://www.itu.int/rec/T-REC-Q.773>
fn problem_type_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0 => "generalProblem",
        1 => "invokeProblem",
        2 => "returnResultProblem",
        3 => "returnErrorProblem",
        _ => return None,
    })
}

/// Returns the name of a Reject problem code within its problem type.
///
/// ITU-T Q.773, clause 3.1 — <https://www.itu.int/rec/T-REC-Q.773>
fn problem_code_name(problem_type: u8, code: i32) -> Option<&'static str> {
    Some(match (problem_type, code) {
        (0, 0) => "unrecognizedComponent",
        (0, 1) => "mistypedComponent",
        (0, 2) => "badlyStructuredComponent",
        (1, 0) => "duplicateInvokeID",
        (1, 1) => "unrecognizedOperation",
        (1, 2) => "mistypedParameter",
        (1, 3) => "resourceLimitation",
        (1, 4) => "initiatingRelease",
        (1, 5) => "unrecognizedLinkedID",
        (1, 6) => "linkedResponseUnexpected",
        (1, 7) => "unexpectedLinkedOperation",
        (2, 0) => "unrecognizedInvokeID",
        (2, 1) => "returnResultUnexpected",
        (2, 2) => "mistypedParameter",
        (3, 0) => "unrecognizedInvokeID",
        (3, 1) => "returnErrorUnexpected",
        (3, 2) => "unrecognizedError",
        (3, 3) => "unexpectedError",
        (3, 4) => "mistypedParameter",
        _ => return None,
    })
}

/// Returns the name of a dialogue PDU. The AUDT-apdu of the unstructured
/// dialogue shares tag [APPLICATION 0] with the AARQ-apdu.
///
/// ITU-T Q.773, clauses 3.2.1 and 3.2.2 — <https://www.itu.int/rec/T-REC-Q.773>
fn dialogue_pdu_name(tag: u8, unidialogue: bool) -> Option<&'static str> {
    Some(match (tag, unidialogue) {
        (0, false) => "dialogueRequest (AARQ-apdu)",
        (1, false) => "dialogueResponse (AARE-apdu)",
        (4, false) => "dialogueAbort (ABRT-apdu)",
        (0, true) => "unidialoguePDU (AUDT-apdu)",
        _ => return None,
    })
}

/// Returns the name of an Associate-result.
///
/// ITU-T Q.773, clause 3.2.1 — <https://www.itu.int/rec/T-REC-Q.773>
fn associate_result_name(r: i32) -> Option<&'static str> {
    Some(match r {
        0 => "accepted",
        1 => "reject-permanent",
        _ => return None,
    })
}

/// Returns the name of an Associate-source-diagnostic alternative
/// (context-specific tag number) or of an ABRT-source.
///
/// ITU-T Q.773, clause 3.2.1 — <https://www.itu.int/rec/T-REC-Q.773>
fn diagnostic_source_name(s: u8) -> Option<&'static str> {
    Some(match s {
        1 => "dialogue-service-user",
        2 => "dialogue-service-provider",
        _ => return None,
    })
}

/// Returns the name of an Associate-source-diagnostic value.
///
/// ITU-T Q.773, clause 3.2.1 — <https://www.itu.int/rec/T-REC-Q.773>
fn diagnostic_name(source: u8, d: i32) -> Option<&'static str> {
    Some(match (source, d) {
        (_, 0) => "null",
        (_, 1) => "no-reason-given",
        (1, 2) => "application-context-name-not-supported",
        (2, 2) => "no-common-dialogue-portion",
        _ => return None,
    })
}

/// Returns the name of an ABRT-source.
///
/// ITU-T Q.773, clause 3.2.1 — <https://www.itu.int/rec/T-REC-Q.773>
fn abort_source_name(s: i32) -> Option<&'static str> {
    Some(match s {
        0 => "dialogue-service-user",
        1 => "dialogue-service-provider",
        _ => return None,
    })
}

/// Writes an OBJECT IDENTIFIER value (the contents octets in a
/// [`FieldValue::Bytes`]) as a quoted dotted string, or as quoted
/// hexadecimal when the encoding is malformed.
pub fn format_oid(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let FieldValue::Bytes(b) = value else {
        return w.write_all(b"\"\"");
    };
    w.write_all(b"\"")?;
    if !ber::write_oid(b, w)? {
        for octet in *b {
            write!(w, "{octet:02x}")?;
        }
    }
    w.write_all(b"\"")
}

/// An INTEGER value together with the range of its contents octets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Int {
    /// The decoded value.
    pub value: i32,
    /// Range of the contents octets.
    pub range: Range<usize>,
}

/// An operation or error code. ITU-T Q.773, clause 3.1 — the OPERATION and
/// ERROR macros' value is a CHOICE of `localValue INTEGER` and
/// `globalValue OBJECT IDENTIFIER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Code {
    /// Local value.
    Local(Int),
    /// Global value; the range of the OBJECT IDENTIFIER contents octets.
    Global(Range<usize>),
}

/// A decoded dialogue control PDU. ITU-T Q.773, clause 3.2.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialoguePdu {
    /// Tag number of the PDU's [APPLICATION n] tag (0 AARQ / AUDT, 1 AARE,
    /// 4 ABRT).
    pub tag: u8,
    /// Whether the dialogue is unstructured (the PDU is an AUDT-apdu).
    pub unidialogue: bool,
    /// Range of the whole PDU element.
    pub range: Range<usize>,
    /// Contents of `protocol-version` \[0\].
    pub protocol_version: Option<Range<usize>>,
    /// Contents of the `application-context-name` OBJECT IDENTIFIER.
    pub application_context_name: Option<Range<usize>>,
    /// `result` \[2\] (AARE).
    pub result: Option<Int>,
    /// `result-source-diagnostic` \[3\] (AARE): the alternative's tag number
    /// (1 dialogue-service-user, 2 dialogue-service-provider) and value.
    pub diagnostic: Option<(u8, Int)>,
    /// `abort-source` \[0\] (ABRT).
    pub abort_source: Option<Int>,
    /// Range of the `user-information` \[30\] element.
    pub user_information: Option<Range<usize>>,
}

/// The dialogue portion. ITU-T Q.773, clause 4.2.3.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dialogue {
    /// Range of the whole dialogue portion element.
    pub range: Range<usize>,
    /// Contents of the EXTERNAL's direct-reference OBJECT IDENTIFIER.
    pub direct_reference: Option<Range<usize>>,
    /// The dialogue control PDU, when the direct reference is the structured
    /// or unstructured dialogue abstract syntax.
    pub pdu: Option<DialoguePdu>,
    /// Range of the EXTERNAL's encoding element when it is not a dialogue
    /// PDU (e.g. user information of a user-defined abstract syntax).
    pub user_data: Option<Range<usize>>,
}

/// A parsed TCAP message: a zero-copy view into the input.
///
/// All ranges are offsets into [`Message::data`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    /// The input the message was parsed from.
    pub data: &'a [u8],
    /// Tag number of the message type (1 Unidirectional, 2 Begin, 4 End,
    /// 5 Continue, 7 Abort).
    pub message_type: u8,
    /// Offset just past the message.
    pub end: usize,
    /// Contents of the Originating Transaction ID.
    pub otid: Option<Range<usize>>,
    /// Contents of the Destination Transaction ID.
    pub dtid: Option<Range<usize>>,
    /// P-Abort cause (Abort).
    pub p_abort_cause: Option<Int>,
    /// Dialogue portion (or the u-abortCause of an Abort).
    pub dialogue: Option<Dialogue>,
    /// Range of the component portion element.
    pub component_portion: Option<Range<usize>>,
    component_contents: Option<Range<usize>>,
}

/// Maps a BER error at the top level of `data` to a [`PacketError`].
fn packet_error(e: ber::BerError, data: &[u8]) -> PacketError {
    match e {
        ber::BerError::Truncated { needed } if needed > data.len() => PacketError::Truncated {
            expected: needed,
            actual: data.len(),
        },
        _ => PacketError::InvalidHeader("malformed TCAP message"),
    }
}

/// Decodes an INTEGER element.
fn int(tlv: &Tlv, data: &[u8]) -> Option<Int> {
    Some(Int {
        value: ber::integer(tlv.value(data))?,
        range: tlv.contents.clone(),
    })
}

/// Decodes an operation or error code element.
fn code(tlv: &Tlv, data: &[u8]) -> Option<Code> {
    if tlv.is(CLASS_UNIVERSAL, false, TAG_INTEGER) {
        int(tlv, data).map(Code::Local)
    } else if tlv.is(CLASS_UNIVERSAL, false, TAG_OID) {
        Some(Code::Global(tlv.contents.clone()))
    } else {
        None
    }
}

impl<'a> Message<'a> {
    /// Parse the TCAP message at the start of `data`.
    ///
    /// Errors when the message element is truncated, malformed or not one
    /// of the five ITU-T message types. Malformed elements inside the
    /// message are skipped.
    pub fn parse(data: &'a [u8]) -> Result<Self, PacketError> {
        let tlv = ber::read(data, 0).map_err(|e| packet_error(e, data))?;
        let known = matches!(
            tlv.number,
            MSG_UNIDIRECTIONAL | MSG_BEGIN | MSG_END | MSG_CONTINUE | MSG_ABORT
        );
        if tlv.class != CLASS_APPLICATION || !tlv.constructed || !known {
            return Err(PacketError::InvalidFieldValue {
                field: "message_type",
                value: u32::from(tlv.first_octet(data)),
            });
        }
        let mut msg = Message {
            data,
            message_type: tlv.number as u8,
            end: tlv.end,
            otid: None,
            dtid: None,
            p_abort_cause: None,
            dialogue: None,
            component_portion: None,
            component_contents: None,
        };
        for child in Children::new(data, tlv.contents.clone()) {
            if child.class != CLASS_APPLICATION {
                continue;
            }
            match (child.number, child.constructed) {
                (APP_OTID, false) if msg.otid.is_none() => msg.otid = Some(child.contents),
                (APP_DTID, false) if msg.dtid.is_none() => msg.dtid = Some(child.contents),
                (APP_P_ABORT_CAUSE, false) if msg.p_abort_cause.is_none() => {
                    msg.p_abort_cause = int(&child, data);
                }
                (APP_DIALOGUE_PORTION, true) if msg.dialogue.is_none() => {
                    msg.dialogue = Some(parse_dialogue(data, &child));
                }
                (APP_COMPONENT_PORTION, true) if msg.component_portion.is_none() => {
                    msg.component_portion = Some(child.start..child.end);
                    msg.component_contents = Some(child.contents);
                }
                _ => {}
            }
        }
        Ok(msg)
    }

    /// Application context name carried by the dialogue portion, if any
    /// (the OBJECT IDENTIFIER contents octets).
    pub fn application_context_name(&self) -> Option<&'a [u8]> {
        let range = self
            .dialogue
            .as_ref()?
            .pdu
            .as_ref()?
            .application_context_name
            .clone()?;
        self.data.get(range)
    }

    /// Iterate the components of the component portion.
    pub fn components(&self) -> Components<'a> {
        Components {
            data: self.data,
            inner: Children::new(self.data, self.component_contents.clone().unwrap_or(0..0)),
        }
    }
}

/// Parses a dialogue portion element (Q.773, clause 4.2.3).
fn parse_dialogue(data: &[u8], portion: &Tlv) -> Dialogue {
    let mut dialogue = Dialogue {
        range: portion.start..portion.end,
        direct_reference: None,
        pdu: None,
        user_data: None,
    };
    // DialoguePortion ::= [APPLICATION 11] EXTERNAL
    let Some(external) = Children::new(data, portion.contents.clone())
        .find(|t| t.is(CLASS_UNIVERSAL, true, TAG_EXTERNAL))
    else {
        return dialogue;
    };
    for part in Children::new(data, external.contents.clone()) {
        if part.is(CLASS_UNIVERSAL, false, TAG_OID) && dialogue.direct_reference.is_none() {
            dialogue.direct_reference = Some(part.contents.clone());
            continue;
        }
        // EXTERNAL encoding CHOICE: single-ASN1-type [0], octet-aligned [1],
        // arbitrary [2] (X.690, clause 8.18).
        if part.class != CLASS_CONTEXT || part.number > 2 {
            continue;
        }
        let reference = dialogue
            .direct_reference
            .clone()
            .and_then(|r| data.get(r))
            .unwrap_or_default();
        let unidialogue = reference == UNIDIALOGUE_AS_ID;
        if part.number == 0 && (reference == DIALOGUE_AS_ID || unidialogue) {
            if let Some(pdu) = Children::new(data, part.contents.clone())
                .next()
                .filter(|t| t.class == CLASS_APPLICATION && t.constructed)
            {
                dialogue.pdu = Some(parse_dialogue_pdu(data, &pdu, unidialogue));
                break;
            }
        }
        dialogue.user_data = Some(part.start..part.end);
        break;
    }
    dialogue
}

/// Parses an AARQ, AARE, ABRT or AUDT apdu (Q.773, clauses 3.2.1, 3.2.2).
fn parse_dialogue_pdu(data: &[u8], pdu: &Tlv, unidialogue: bool) -> DialoguePdu {
    let tag = pdu.number.min(255) as u8;
    let mut out = DialoguePdu {
        tag,
        unidialogue,
        range: pdu.start..pdu.end,
        protocol_version: None,
        application_context_name: None,
        result: None,
        diagnostic: None,
        abort_source: None,
        user_information: None,
    };
    let first_child = |t: &Tlv| Children::new(data, t.contents.clone()).next();
    for f in Children::new(data, pdu.contents.clone()) {
        if f.class != CLASS_CONTEXT {
            continue;
        }
        match (tag, f.number, f.constructed) {
            // ABRT-apdu: abort-source [0] IMPLICIT ABRT-source.
            (4, 0, false) => out.abort_source = int(&f, data),
            // protocol-version [0] IMPLICIT BIT STRING.
            (_, 0, false) => out.protocol_version = Some(f.contents.clone()),
            // application-context-name [1] OBJECT IDENTIFIER.
            (0 | 1, 1, true) => {
                out.application_context_name = first_child(&f)
                    .filter(|t| t.is(CLASS_UNIVERSAL, false, TAG_OID))
                    .map(|t| t.contents);
            }
            // result [2] Associate-result.
            (1, 2, true) => {
                out.result = first_child(&f).and_then(|t| int(&t, data));
            }
            // result-source-diagnostic [3] Associate-source-diagnostic.
            (1, 3, true) => {
                out.diagnostic = first_child(&f)
                    .filter(|alt| alt.class == CLASS_CONTEXT && matches!(alt.number, 1 | 2))
                    .and_then(|alt| {
                        let value = first_child(&alt).and_then(|t| int(&t, data))?;
                        Some((alt.number as u8, value))
                    });
            }
            // user-information [30] IMPLICIT SEQUENCE OF EXTERNAL.
            (_, 30, true) => out.user_information = Some(f.start..f.end),
            _ => {}
        }
    }
    out
}

/// One component. ITU-T Q.773, clause 3.1.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// Component type: the context-specific tag number (1 invoke,
    /// 2 returnResultLast, 3 returnError, 4 reject, 7 returnResultNotLast).
    pub kind: u8,
    /// Range of the whole component element.
    pub range: Range<usize>,
    /// Invoke ID (absent for a Reject whose invoke ID is not derivable).
    pub invoke_id: Option<Int>,
    /// Linked ID (Invoke).
    pub linked_id: Option<Int>,
    /// Operation code (Invoke, and Return Result when a result is present).
    pub opcode: Option<Code>,
    /// Error code (Return Error).
    pub error_code: Option<Code>,
    /// Range of the parameter element (raw BER, defined by the TC-user).
    pub parameter: Option<Range<usize>>,
    /// Reject problem: type (context-specific tag number 0-3) and code.
    pub problem: Option<(u8, Int)>,
}

/// Iterator over the components of a message; see [`Message::components`].
#[derive(Debug, Clone)]
pub struct Components<'a> {
    data: &'a [u8],
    inner: Children<'a>,
}

impl Iterator for Components<'_> {
    type Item = Component;

    fn next(&mut self) -> Option<Component> {
        let tlv = self.inner.next()?;
        Some(parse_component(self.data, &tlv))
    }
}

/// Parses one component element. Elements that do not match the expected
/// structure leave the corresponding fields unset.
fn parse_component(data: &[u8], tlv: &Tlv) -> Component {
    let mut c = Component {
        kind: if tlv.class == CLASS_CONTEXT && tlv.constructed {
            tlv.number.min(255) as u8
        } else {
            0
        },
        range: tlv.start..tlv.end,
        invoke_id: None,
        linked_id: None,
        opcode: None,
        error_code: None,
        parameter: None,
        problem: None,
    };
    if component_type_name(c.kind).is_none() {
        return c;
    }
    let mut fields = Children::new(data, tlv.contents.clone()).peekable();
    // invokeID InvokeIdType (Reject: CHOICE { derivable InvokeIdType,
    // not-derivable NULL }).
    match fields.peek() {
        Some(t) if t.is(CLASS_UNIVERSAL, false, TAG_INTEGER) => {
            c.invoke_id = int(t, data);
            fields.next();
        }
        Some(t) if c.kind == 4 && t.is(CLASS_UNIVERSAL, false, TAG_NULL) => {
            fields.next();
        }
        _ => return c,
    }
    match c.kind {
        // Invoke ::= SEQUENCE { invokeID, linkedID [0] IMPLICIT
        // InvokeIdType OPTIONAL, operationCode, parameter OPTIONAL }
        1 => {
            if let Some(t) = fields.next_if(|t| t.is(CLASS_CONTEXT, false, 0)) {
                c.linked_id = int(&t, data);
            }
            c.opcode = fields.next().and_then(|t| code(&t, data));
            if c.opcode.is_some() {
                c.parameter = fields.next().map(|t| t.start..t.end);
            }
        }
        // ReturnResult ::= SEQUENCE { invokeID, result SEQUENCE {
        // operationCode, parameter } OPTIONAL }
        2 | 7 => {
            if let Some(result) = fields.next_if(|t| t.is(CLASS_UNIVERSAL, true, TAG_SEQUENCE)) {
                let mut inner = Children::new(data, result.contents.clone());
                c.opcode = inner.next().and_then(|t| code(&t, data));
                if c.opcode.is_some() {
                    c.parameter = inner.next().map(|t| t.start..t.end);
                }
            }
        }
        // ReturnError ::= SEQUENCE { invokeID, errorCode, parameter OPTIONAL }
        3 => {
            c.error_code = fields.next().and_then(|t| code(&t, data));
            if c.error_code.is_some() {
                c.parameter = fields.next().map(|t| t.start..t.end);
            }
        }
        // Reject ::= SEQUENCE { invokeID, problem CHOICE { generalProblem
        // [0], invokeProblem [1], returnResultProblem [2],
        // returnErrorProblem [3] } }
        _ => {
            c.problem = fields
                .next()
                .filter(|t| t.class == CLASS_CONTEXT && !t.constructed && t.number <= 3)
                .and_then(|t| Some((t.number as u8, int(&t, data)?)));
        }
    }
    c
}

/// Returns the U8 value of the named sibling field, if present.
fn sibling_u8(siblings: &[Field<'_>], name: &str) -> Option<u8> {
    siblings.iter().find_map(|f| match (f.name(), &f.value) {
        (n, FieldValue::U8(v)) if n == name => Some(*v),
        _ => None,
    })
}

// Indices into `DIALOGUE_FIELDS`.
const DFD_DIALOGUE_AS_ID: usize = 0;
const DFD_PDU_TYPE: usize = 1;
const DFD_PROTOCOL_VERSION: usize = 2;
const DFD_APPLICATION_CONTEXT_NAME: usize = 3;
const DFD_RESULT: usize = 4;
const DFD_RESULT_SOURCE: usize = 5;
const DFD_DIAGNOSTIC: usize = 6;
const DFD_ABORT_SOURCE: usize = 7;
const DFD_USER_INFORMATION: usize = 8;
const DFD_UNIDIALOGUE: usize = 9;

/// Children of the dialogue portion Object.
/// ITU-T Q.773, clauses 3.2 and 4.2.3 — <https://www.itu.int/rec/T-REC-Q.773>
static DIALOGUE_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new(
        "dialogue_as_id",
        "Dialogue Abstract Syntax",
        FieldType::Bytes,
    )
    .optional()
    .with_format_fn(format_oid),
    FieldDescriptor::new("pdu_type", "Dialogue PDU", FieldType::U8)
        .optional()
        .with_display_fn(|v, siblings| match v {
            FieldValue::U8(t) => {
                dialogue_pdu_name(*t, sibling_u8(siblings, "unidialogue") == Some(1))
            }
            _ => None,
        }),
    FieldDescriptor::new("protocol_version", "Protocol Version", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "application_context_name",
        "Application Context Name",
        FieldType::Bytes,
    )
    .optional()
    .with_format_fn(format_oid),
    FieldDescriptor::new("result", "Result", FieldType::I32)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::I32(r) => associate_result_name(*r),
            _ => None,
        }),
    FieldDescriptor::new("result_source", "Result Source", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(s) => diagnostic_source_name(*s),
            _ => None,
        }),
    FieldDescriptor::new("diagnostic", "Result Source Diagnostic", FieldType::I32)
        .optional()
        .with_display_fn(|v, siblings| match v {
            FieldValue::I32(d) => diagnostic_name(sibling_u8(siblings, "result_source")?, *d),
            _ => None,
        }),
    FieldDescriptor::new("abort_source", "Abort Source", FieldType::I32)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::I32(s) => abort_source_name(*s),
            _ => None,
        }),
    FieldDescriptor::new("user_information", "User Information", FieldType::Bytes).optional(),
    // 1 when the dialogue is unstructured (uniDialogue-as-id).
    FieldDescriptor::new("unidialogue", "Unstructured Dialogue", FieldType::U8).optional(),
];

// Indices into `COMPONENT_FIELDS`.
const CFD_COMPONENT_TYPE: usize = 0;
const CFD_INVOKE_ID: usize = 1;
const CFD_LINKED_ID: usize = 2;
const CFD_OPCODE: usize = 3;
const CFD_OPCODE_GLOBAL: usize = 4;
const CFD_ERROR_CODE: usize = 5;
const CFD_ERROR_CODE_GLOBAL: usize = 6;
const CFD_PARAMETER: usize = 7;
const CFD_PROBLEM_TYPE: usize = 8;
const CFD_PROBLEM_CODE: usize = 9;

/// Children of a component Object.
/// ITU-T Q.773, clauses 3.1 and 4.2.2 — <https://www.itu.int/rec/T-REC-Q.773>
static COMPONENT_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("component_type", "Component Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => component_type_name(*t),
            _ => None,
        },
    ),
    FieldDescriptor::new("invoke_id", "Invoke ID", FieldType::I32).optional(),
    FieldDescriptor::new("linked_id", "Linked ID", FieldType::I32).optional(),
    FieldDescriptor::new("opcode", "Operation Code", FieldType::I32).optional(),
    FieldDescriptor::new("opcode_global", "Global Operation Code", FieldType::Bytes)
        .optional()
        .with_format_fn(format_oid),
    FieldDescriptor::new("error_code", "Error Code", FieldType::I32).optional(),
    FieldDescriptor::new("error_code_global", "Global Error Code", FieldType::Bytes)
        .optional()
        .with_format_fn(format_oid),
    FieldDescriptor::new("parameter", "Parameter", FieldType::Bytes).optional(),
    FieldDescriptor::new("problem_type", "Problem Type", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(t) => problem_type_name(*t),
            _ => None,
        }),
    FieldDescriptor::new("problem_code", "Problem Code", FieldType::I32)
        .optional()
        .with_display_fn(|v, siblings| match v {
            FieldValue::I32(c) => problem_code_name(sibling_u8(siblings, "problem_type")?, *c),
            _ => None,
        }),
];

/// Element descriptor of `components`.
static FD_COMPONENT: FieldDescriptor =
    FieldDescriptor::new("component", "Component", FieldType::Object)
        .with_display_fn(|v, children| match v {
            FieldValue::Object(_) => {
                sibling_u8(children, "component_type").and_then(component_type_name)
            }
            _ => None,
        })
        .with_children(COMPONENT_FIELDS);

// Indices into `FIELD_DESCRIPTORS`.
const FD_MESSAGE_TYPE: usize = 0;
const FD_OTID: usize = 1;
const FD_DTID: usize = 2;
const FD_P_ABORT_CAUSE: usize = 3;
const FD_DIALOGUE: usize = 4;
const FD_COMPONENTS: usize = 5;

/// Field descriptors for the TCAP layer.
/// ITU-T Q.773, clause 3.1 — <https://www.itu.int/rec/T-REC-Q.773>
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("message_type", "Message Type", FieldType::U8).with_display_fn(|v, _| {
        match v {
            FieldValue::U8(t) => message_type_name(*t),
            _ => None,
        }
    }),
    FieldDescriptor::new("otid", "Originating Transaction ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("dtid", "Destination Transaction ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("p_abort_cause", "P-Abort Cause", FieldType::I32)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::I32(c) => p_abort_cause_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("dialogue", "Dialogue Portion", FieldType::Object)
        .optional()
        .with_children(DIALOGUE_FIELDS),
    FieldDescriptor::new("components", "Components", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_COMPONENT)),
];

/// Specification references for the TCAP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "ITU-T Q.773",
        "Transaction capabilities formats and encoding",
        "https://www.itu.int/rec/T-REC-Q.773",
    ),
    SpecReference::new(
        "ITU-T X.690",
        "ASN.1 encoding rules: Specification of Basic Encoding Rules (BER)",
        "https://www.itu.int/rec/T-REC-X.690",
    ),
];

/// Push the range `r` (relative to the message input) as a Bytes field.
fn push_bytes<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: &'static FieldDescriptor,
    data: &'pkt [u8],
    r: &Range<usize>,
    offset: usize,
) {
    let value = data.get(r.clone()).unwrap_or_default();
    buf.push_field(
        fd,
        FieldValue::Bytes(value),
        offset + r.start..offset + r.end,
    );
}

/// Push an [`Int`] as an I32 field.
fn push_int(buf: &mut DissectBuffer<'_>, fd: &'static FieldDescriptor, v: &Int, offset: usize) {
    buf.push_field(
        fd,
        FieldValue::I32(v.value),
        offset + v.range.start..offset + v.range.end,
    );
}

/// Push the fields of a parsed TCAP message into the current layer.
///
/// `offset` is the absolute offset of `msg.data`. Used by
/// [`TcapDissector`] and by TC-user dissectors (e.g. MAP) that emit the
/// TCAP layer themselves.
pub fn push_message<'pkt>(msg: &Message<'pkt>, buf: &mut DissectBuffer<'pkt>, offset: usize) {
    let data = msg.data;
    let fd = |i: usize| &FIELD_DESCRIPTORS[i];
    buf.push_field(
        fd(FD_MESSAGE_TYPE),
        FieldValue::U8(msg.message_type),
        offset..offset + 1,
    );
    if let Some(r) = &msg.otid {
        push_bytes(buf, fd(FD_OTID), data, r, offset);
    }
    if let Some(r) = &msg.dtid {
        push_bytes(buf, fd(FD_DTID), data, r, offset);
    }
    if let Some(c) = &msg.p_abort_cause {
        push_int(buf, fd(FD_P_ABORT_CAUSE), c, offset);
    }
    if let Some(d) = &msg.dialogue {
        push_dialogue(d, data, buf, offset);
    }
    if let Some(portion) = &msg.component_portion {
        let idx = buf.begin_container(
            fd(FD_COMPONENTS),
            FieldValue::Array(0..0),
            offset + portion.start..offset + portion.end,
        );
        for c in msg.components() {
            push_component(&c, data, buf, offset);
        }
        buf.end_container(idx);
    }
}

fn push_dialogue<'pkt>(
    d: &Dialogue,
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
) {
    let dfd = |i: usize| &DIALOGUE_FIELDS[i];
    let idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_DIALOGUE],
        FieldValue::Object(0..0),
        offset + d.range.start..offset + d.range.end,
    );
    if let Some(r) = &d.direct_reference {
        push_bytes(buf, dfd(DFD_DIALOGUE_AS_ID), data, r, offset);
    }
    if let Some(p) = &d.pdu {
        let pdu_range = offset + p.range.start..offset + p.range.end;
        buf.push_field(
            dfd(DFD_UNIDIALOGUE),
            FieldValue::U8(u8::from(p.unidialogue)),
            pdu_range.clone(),
        );
        buf.push_field(dfd(DFD_PDU_TYPE), FieldValue::U8(p.tag), pdu_range);
        if let Some(r) = &p.protocol_version {
            push_bytes(buf, dfd(DFD_PROTOCOL_VERSION), data, r, offset);
        }
        if let Some(r) = &p.application_context_name {
            push_bytes(buf, dfd(DFD_APPLICATION_CONTEXT_NAME), data, r, offset);
        }
        if let Some(v) = &p.result {
            push_int(buf, dfd(DFD_RESULT), v, offset);
        }
        if let Some((source, v)) = &p.diagnostic {
            buf.push_field(
                dfd(DFD_RESULT_SOURCE),
                FieldValue::U8(*source),
                offset + v.range.start..offset + v.range.end,
            );
            push_int(buf, dfd(DFD_DIAGNOSTIC), v, offset);
        }
        if let Some(v) = &p.abort_source {
            push_int(buf, dfd(DFD_ABORT_SOURCE), v, offset);
        }
        if let Some(r) = &p.user_information {
            push_bytes(buf, dfd(DFD_USER_INFORMATION), data, r, offset);
        }
    }
    if let Some(r) = &d.user_data {
        push_bytes(buf, dfd(DFD_USER_INFORMATION), data, r, offset);
    }
    buf.end_container(idx);
}

fn push_component<'pkt>(
    c: &Component,
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
) {
    let cfd = |i: usize| &COMPONENT_FIELDS[i];
    let idx = buf.begin_container(
        &FD_COMPONENT,
        FieldValue::Object(0..0),
        offset + c.range.start..offset + c.range.end,
    );
    buf.push_field(
        cfd(CFD_COMPONENT_TYPE),
        FieldValue::U8(c.kind),
        offset + c.range.start..offset + c.range.start + 1,
    );
    if let Some(v) = &c.invoke_id {
        push_int(buf, cfd(CFD_INVOKE_ID), v, offset);
    }
    if let Some(v) = &c.linked_id {
        push_int(buf, cfd(CFD_LINKED_ID), v, offset);
    }
    for (code, local, global) in [
        (&c.opcode, CFD_OPCODE, CFD_OPCODE_GLOBAL),
        (&c.error_code, CFD_ERROR_CODE, CFD_ERROR_CODE_GLOBAL),
    ] {
        match code {
            Some(Code::Local(v)) => push_int(buf, cfd(local), v, offset),
            Some(Code::Global(r)) => push_bytes(buf, cfd(global), data, r, offset),
            None => {}
        }
    }
    if let Some(r) = &c.parameter {
        push_bytes(buf, cfd(CFD_PARAMETER), data, r, offset);
    }
    if let Some((t, v)) = &c.problem {
        buf.push_field(
            cfd(CFD_PROBLEM_TYPE),
            FieldValue::U8(*t),
            offset + v.range.start..offset + v.range.end,
        );
        push_int(buf, cfd(CFD_PROBLEM_CODE), v, offset);
    }
    buf.end_container(idx);
}

/// TCAP dissector.
pub struct TcapDissector;

impl Dissector for TcapDissector {
    fn name(&self) -> &'static str {
        "Transaction Capabilities Application Part"
    }

    fn short_name(&self) -> &'static str {
        "TCAP"
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
        let msg = Message::parse(data)?;
        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + msg.end,
        );
        push_message(&msg, buf, offset);
        buf.end_layer();
        Ok(DissectResult::new(msg.end, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests;
