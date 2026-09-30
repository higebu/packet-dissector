//! SCCP (Signalling Connection Control Part) dissector.
//!
//! Decodes every ITU-T SCCP message type (connection-oriented CR / CC /
//! CREF / RLSD / RLC / DT1 / DT2 / AK / ED / EA / RSR / RSC / ERR / IT and
//! connectionless UDT / UDTS / XUDT / XUDTS / LUDT / LUDTS), including the
//! called and calling party addresses with global titles. The SCCP user
//! data is handed to the next dissector by subsystem number
//! ([`DispatchHint::BySccpSsn`]).
//!
//! Segmented XUDT / XUDTS / LUDT / LUDTS messages are not reassembled; only
//! unsegmented user data is dispatched. ANSI SCCP (T1.112) is not
//! supported.
//!
//! ## References
//! - ITU-T Q.713 (03/2001), SCCP formats and codes:
//!   <https://www.itu.int/rec/T-REC-Q.713>
//! - ITU-T Q.704 (07/96), clause 14.2.1 (Service Indicator 3 = SCCP):
//!   <https://www.itu.int/rec/T-REC-Q.704>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, FormatContext};
use packet_dissector_core::packet::DissectBuffer;

// Message type codes. ITU-T Q.713, clause 2.1, Table 1 —
// <https://www.itu.int/rec/T-REC-Q.713>
const MSG_CR: u8 = 0x01;
const MSG_CC: u8 = 0x02;
const MSG_CREF: u8 = 0x03;
const MSG_RLSD: u8 = 0x04;
const MSG_RLC: u8 = 0x05;
const MSG_DT1: u8 = 0x06;
const MSG_DT2: u8 = 0x07;
const MSG_AK: u8 = 0x08;
const MSG_UDT: u8 = 0x09;
const MSG_UDTS: u8 = 0x0a;
const MSG_ED: u8 = 0x0b;
const MSG_EA: u8 = 0x0c;
const MSG_RSR: u8 = 0x0d;
const MSG_RSC: u8 = 0x0e;
const MSG_ERR: u8 = 0x0f;
const MSG_IT: u8 = 0x10;
const MSG_XUDT: u8 = 0x11;
const MSG_XUDTS: u8 = 0x12;
const MSG_LUDT: u8 = 0x13;
const MSG_LUDTS: u8 = 0x14;

// Parameter name codes. ITU-T Q.713, clause 3, Table 2 —
// <https://www.itu.int/rec/T-REC-Q.713>
const PARAM_END_OF_OPTIONAL: u8 = 0x00;
const PARAM_CALLED_PARTY_ADDRESS: u8 = 0x03;
const PARAM_CALLING_PARTY_ADDRESS: u8 = 0x04;
const PARAM_CREDIT: u8 = 0x09;
const PARAM_DATA: u8 = 0x0f;
const PARAM_SEGMENTATION: u8 = 0x10;
const PARAM_HOP_COUNTER: u8 = 0x11;
const PARAM_IMPORTANCE: u8 = 0x12;

/// Size of the Segmentation parameter content.
/// ITU-T Q.713, clause 3.17 — <https://www.itu.int/rec/T-REC-Q.713>
const SEGMENTATION_SIZE: usize = 4;

/// Returns the name of an SCCP message type.
///
/// ITU-T Q.713, clause 2.1, Table 1 — <https://www.itu.int/rec/T-REC-Q.713>
fn message_type_name(msg_type: u8) -> Option<&'static str> {
    Some(match msg_type {
        MSG_CR => "Connection request (CR)",
        MSG_CC => "Connection confirm (CC)",
        MSG_CREF => "Connection refused (CREF)",
        MSG_RLSD => "Released (RLSD)",
        MSG_RLC => "Release complete (RLC)",
        MSG_DT1 => "Data form 1 (DT1)",
        MSG_DT2 => "Data form 2 (DT2)",
        MSG_AK => "Data acknowledgement (AK)",
        MSG_UDT => "Unitdata (UDT)",
        MSG_UDTS => "Unitdata service (UDTS)",
        MSG_ED => "Expedited data (ED)",
        MSG_EA => "Expedited data acknowledgement (EA)",
        MSG_RSR => "Reset request (RSR)",
        MSG_RSC => "Reset confirmation (RSC)",
        MSG_ERR => "Protocol data unit error (ERR)",
        MSG_IT => "Inactivity test (IT)",
        MSG_XUDT => "Extended unitdata (XUDT)",
        MSG_XUDTS => "Extended unitdata service (XUDTS)",
        MSG_LUDT => "Long unitdata (LUDT)",
        MSG_LUDTS => "Long unitdata service (LUDTS)",
        _ => return None,
    })
}

/// Returns the name of a protocol class (bits 1-4 of the Protocol class
/// parameter). ITU-T Q.713, clause 3.6 — <https://www.itu.int/rec/T-REC-Q.713>
fn protocol_class_name(class: u8) -> Option<&'static str> {
    Some(match class {
        0 => "class 0",
        1 => "class 1",
        2 => "class 2",
        3 => "class 3",
        _ => return None,
    })
}

/// Returns the name of the message handling (bits 5-8 of the Protocol class
/// parameter of a connectionless class).
///
/// ITU-T Q.713, clause 3.6 — <https://www.itu.int/rec/T-REC-Q.713>
fn message_handling_name(handling: u8) -> Option<&'static str> {
    Some(match handling {
        0 => "no special options",
        8 => "return message on error",
        _ => return None,
    })
}

/// Returns the name of a release cause.
///
/// ITU-T Q.713, clause 3.11 — <https://www.itu.int/rec/T-REC-Q.713>
fn release_cause_name(cause: u8) -> Option<&'static str> {
    Some(match cause {
        0x00 => "end user originated",
        0x01 => "end user congestion",
        0x02 => "end user failure",
        0x03 => "SCCP user originated",
        0x04 => "remote procedure error",
        0x05 => "inconsistent connection data",
        0x06 => "access failure",
        0x07 => "access congestion",
        0x08 => "subsystem failure",
        0x09 => "subsystem congestion",
        0x0a => "MTP failure",
        0x0b => "network congestion",
        0x0c => "expiration of reset timer",
        0x0d => "expiration of receive inactivity timer",
        0x0f => "unqualified",
        0x10 => "SCCP failure",
        _ => return None,
    })
}

/// Returns the name of a return cause.
///
/// ITU-T Q.713, clause 3.12 — <https://www.itu.int/rec/T-REC-Q.713>
fn return_cause_name(cause: u8) -> Option<&'static str> {
    Some(match cause {
        0x00 => "no translation for an address of such nature",
        0x01 => "no translation for this specific address",
        0x02 => "subsystem congestion",
        0x03 => "subsystem failure",
        0x04 => "unequipped user",
        0x05 => "MTP failure",
        0x06 => "network congestion",
        0x07 => "unqualified",
        0x08 => "error in message transport",
        0x09 => "error in local processing",
        0x0a => "destination cannot perform reassembly",
        0x0b => "SCCP failure",
        0x0c => "hop counter violation",
        0x0d => "segmentation not supported",
        0x0e => "segmentation failure",
        _ => return None,
    })
}

/// Returns the name of a reset cause.
///
/// ITU-T Q.713, clause 3.13 — <https://www.itu.int/rec/T-REC-Q.713>
fn reset_cause_name(cause: u8) -> Option<&'static str> {
    Some(match cause {
        0x00 => "end user originated",
        0x01 => "SCCP user originated",
        0x02 => "message out of order - incorrect P(S)",
        0x03 => "message out of order - incorrect P(R)",
        0x04 => "remote procedure error - message out of window",
        0x05 => "remote procedure error - incorrect P(S) after (re)initialization",
        0x06 => "remote procedure error - general",
        0x07 => "remote end user operational",
        0x08 => "network operational",
        0x09 => "access operational",
        0x0a => "network congestion",
        0x0c => "unqualified",
        _ => return None,
    })
}

/// Returns the name of an error cause.
///
/// ITU-T Q.713, clause 3.14 — <https://www.itu.int/rec/T-REC-Q.713>
fn error_cause_name(cause: u8) -> Option<&'static str> {
    Some(match cause {
        0x00 => "local reference number (LRN) mismatch - unassigned destination LRN",
        0x01 => "local reference number (LRN) mismatch - inconsistent source LRN",
        0x02 => "point code mismatch",
        0x03 => "service class mismatch",
        0x04 => "unqualified",
        _ => return None,
    })
}

/// Returns the name of a refusal cause.
///
/// ITU-T Q.713, clause 3.15 — <https://www.itu.int/rec/T-REC-Q.713>
fn refusal_cause_name(cause: u8) -> Option<&'static str> {
    Some(match cause {
        0x00 => "end user originated",
        0x01 => "end user congestion",
        0x02 => "end user failure",
        0x03 => "SCCP user originated",
        0x04 => "destination address unknown",
        0x05 => "destination inaccessible",
        0x06 => "network resource - QoS not available/non-transient",
        0x07 => "network resource - QoS not available/transient",
        0x08 => "access failure",
        0x09 => "access congestion",
        0x0a => "subsystem failure",
        0x0b => "subsystem congestion",
        0x0c => "expiration of the connection establishment timer",
        0x0d => "incompatible user data",
        0x0f => "unqualified",
        0x10 => "hop counter violation",
        0x11 => "SCCP failure",
        0x12 => "no translation for an address of such nature",
        0x13 => "unequipped user",
        _ => return None,
    })
}

/// Returns the name of a global title indicator.
///
/// ITU-T Q.713, clause 3.4.1 — <https://www.itu.int/rec/T-REC-Q.713>
fn global_title_indicator_name(gti: u8) -> Option<&'static str> {
    Some(match gti {
        0 => "no global title included",
        1 => "global title includes nature of address indicator only",
        2 => "global title includes translation type only",
        3 => "global title includes translation type, numbering plan and encoding scheme",
        4 => {
            "global title includes translation type, numbering plan, encoding scheme and nature of address indicator"
        }
        _ => return None,
    })
}

/// Returns the name of the routing indicator (bit 7 of the address
/// indicator). ITU-T Q.713, clause 3.4.1 — <https://www.itu.int/rec/T-REC-Q.713>
fn routing_indicator_name(ri: u8) -> Option<&'static str> {
    Some(match ri {
        0 => "Route on GT",
        1 => "Route on SSN",
        _ => return None,
    })
}

/// Returns the name of a subsystem number.
///
/// ITU-T Q.713, clause 3.4.2.2 — <https://www.itu.int/rec/T-REC-Q.713>
fn ssn_name(ssn: u8) -> Option<&'static str> {
    Some(match ssn {
        0x00 => "SSN not known/not used",
        0x01 => "SCCP management",
        0x03 => "ISDN user part",
        0x04 => "operation, maintenance and administration part (OMAP)",
        0x05 => "mobile application part (MAP)",
        0x06 => "home location register (HLR)",
        0x07 => "visitor location register (VLR)",
        0x08 => "mobile switching centre (MSC)",
        0x09 => "equipment identifier centre (EIC)",
        0x0a => "authentication centre (AUC)",
        0x0b => "ISDN supplementary services",
        0x0d => "broadband ISDN edge-to-edge applications",
        0x0e => "TC test responder",
        _ => return None,
    })
}

/// Returns the name of a nature of address indicator.
///
/// ITU-T Q.713, clause 3.4.2.3.1 — <https://www.itu.int/rec/T-REC-Q.713>
fn nature_of_address_name(nai: u8) -> Option<&'static str> {
    Some(match nai {
        0 => "unknown",
        1 => "subscriber number",
        2 => "reserved for national use",
        3 => "national significant number",
        4 => "international number",
        _ => return None,
    })
}

/// Returns the name of a numbering plan.
///
/// ITU-T Q.713, clause 3.4.2.3.3 — <https://www.itu.int/rec/T-REC-Q.713>
fn numbering_plan_name(np: u8) -> Option<&'static str> {
    Some(match np {
        0 => "unknown",
        1 => "ISDN/telephony numbering plan (ITU-T E.163 and E.164)",
        2 => "generic numbering plan",
        3 => "data numbering plan (ITU-T X.121)",
        4 => "telex numbering plan (ITU-T F.69)",
        5 => "maritime mobile numbering plan (ITU-T E.210, E.211)",
        6 => "land mobile numbering plan (ITU-T E.212)",
        7 => "ISDN/mobile numbering plan (ITU-T E.214)",
        14 => "private network or network-specific numbering plan",
        _ => return None,
    })
}

/// Returns the name of an encoding scheme.
///
/// ITU-T Q.713, clause 3.4.2.3.3 — <https://www.itu.int/rec/T-REC-Q.713>
fn encoding_scheme_name(es: u8) -> Option<&'static str> {
    Some(match es {
        0 => "unknown",
        1 => "BCD, odd number of digits",
        2 => "BCD, even number of digits",
        3 => "national specific",
        _ => return None,
    })
}

/// Writes BCD address signals, decoded into the scratch buffer as ASCII by
/// [`push_bcd_digits`], as a JSON string.
fn format_digits(
    value: &FieldValue<'_>,
    ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let digits = match value {
        FieldValue::Scratch(r) => ctx
            .scratch
            .get(r.start as usize..r.end as usize)
            .unwrap_or_default(),
        _ => &[],
    };
    w.write_all(b"\"")?;
    w.write_all(digits)?;
    w.write_all(b"\"")
}

// Indices into `ADDRESS_FIELDS`.
const AFD_ADDRESS_INDICATOR: usize = 0;
const AFD_NATIONAL_USE: usize = 1;
const AFD_ROUTING_INDICATOR: usize = 2;
const AFD_GLOBAL_TITLE_INDICATOR: usize = 3;
const AFD_SSN_INDICATOR: usize = 4;
const AFD_POINT_CODE_INDICATOR: usize = 5;
const AFD_POINT_CODE: usize = 6;
const AFD_SSN: usize = 7;
const AFD_TRANSLATION_TYPE: usize = 8;
const AFD_NUMBERING_PLAN: usize = 9;
const AFD_ENCODING_SCHEME: usize = 10;
const AFD_NATURE_OF_ADDRESS: usize = 11;
const AFD_ODD_EVEN: usize = 12;
const AFD_DIGITS: usize = 13;
const AFD_ADDRESS_INFORMATION: usize = 14;

/// Children of a called / calling party address.
///
/// ITU-T Q.713, clauses 3.4 and 3.5 — <https://www.itu.int/rec/T-REC-Q.713>
static ADDRESS_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("address_indicator", "Address Indicator", FieldType::U8),
    FieldDescriptor::new("national_use", "Reserved for National Use", FieldType::U8),
    FieldDescriptor::new("routing_indicator", "Routing Indicator", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(ri) => routing_indicator_name(*ri),
            _ => None,
        },
    ),
    FieldDescriptor::new(
        "global_title_indicator",
        "Global Title Indicator",
        FieldType::U8,
    )
    .with_display_fn(|v, _| match v {
        FieldValue::U8(gti) => global_title_indicator_name(*gti),
        _ => None,
    }),
    FieldDescriptor::new("ssn_indicator", "SSN Indicator", FieldType::U8),
    FieldDescriptor::new(
        "point_code_indicator",
        "Point Code Indicator",
        FieldType::U8,
    ),
    FieldDescriptor::new("point_code", "Signalling Point Code", FieldType::U16).optional(),
    FieldDescriptor::new("ssn", "Subsystem Number", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(ssn) => ssn_name(*ssn),
            _ => None,
        }),
    FieldDescriptor::new("translation_type", "Translation Type", FieldType::U8).optional(),
    FieldDescriptor::new("numbering_plan", "Numbering Plan", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(np) => numbering_plan_name(*np),
            _ => None,
        }),
    FieldDescriptor::new("encoding_scheme", "Encoding Scheme", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(es) => encoding_scheme_name(*es),
            _ => None,
        }),
    FieldDescriptor::new(
        "nature_of_address",
        "Nature of Address Indicator",
        FieldType::U8,
    )
    .optional()
    .with_display_fn(|v, _| match v {
        FieldValue::U8(nai) => nature_of_address_name(*nai),
        _ => None,
    }),
    FieldDescriptor::new("odd_even", "Odd/Even Indicator", FieldType::U8).optional(),
    // BCD address signals decoded to ASCII in the scratch buffer.
    FieldDescriptor::new("digits", "Global Title Digits", FieldType::Bytes)
        .optional()
        .with_format_fn(format_digits),
    // Global title address information that is not BCD, or octets that do
    // not fit the address indicator.
    FieldDescriptor::new(
        "address_information",
        "Address Information",
        FieldType::Bytes,
    )
    .optional(),
];

// Indices into `SEGMENTATION_FIELDS`.
const SFD_FIRST_SEGMENT: usize = 0;
const SFD_CLASS: usize = 1;
const SFD_REMAINING_SEGMENTS: usize = 2;
const SFD_LOCAL_REFERENCE: usize = 3;

/// Children of the Segmentation parameter.
/// ITU-T Q.713, clause 3.17 — <https://www.itu.int/rec/T-REC-Q.713>
static SEGMENTATION_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("first_segment", "First Segment", FieldType::U8),
    FieldDescriptor::new("class", "Class", FieldType::U8),
    FieldDescriptor::new("remaining_segments", "Remaining Segments", FieldType::U8),
    FieldDescriptor::new(
        "local_reference",
        "Segmentation Local Reference",
        FieldType::U32,
    ),
];

// Indices into `UNKNOWN_PARAMETER_FIELDS`.
const UFD_NAME: usize = 0;
const UFD_LENGTH: usize = 1;
const UFD_VALUE: usize = 2;

/// Children of an unrecognised optional parameter.
/// ITU-T Q.713, clause 1.5 — <https://www.itu.int/rec/T-REC-Q.713>
static UNKNOWN_PARAMETER_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("name", "Parameter Name", FieldType::U8),
    FieldDescriptor::new("length", "Length Indicator", FieldType::U8),
    FieldDescriptor::new("value", "Value", FieldType::Bytes),
];

/// Element descriptor of `unknown_parameters`.
static FD_UNKNOWN_PARAMETER: FieldDescriptor =
    FieldDescriptor::new("parameter", "Parameter", FieldType::Object)
        .with_children(UNKNOWN_PARAMETER_FIELDS);

// Indices into `FIELD_DESCRIPTORS`.
const FD_MESSAGE_TYPE: usize = 0;
const FD_DESTINATION_LOCAL_REFERENCE: usize = 1;
const FD_SOURCE_LOCAL_REFERENCE: usize = 2;
const FD_PROTOCOL_CLASS: usize = 3;
const FD_MESSAGE_HANDLING: usize = 4;
const FD_MORE_DATA: usize = 5;
const FD_SEND_SEQUENCE_NUMBER: usize = 6;
const FD_RECEIVE_SEQUENCE_NUMBER: usize = 7;
const FD_CREDIT: usize = 8;
const FD_RELEASE_CAUSE: usize = 9;
const FD_RETURN_CAUSE: usize = 10;
const FD_RESET_CAUSE: usize = 11;
const FD_ERROR_CAUSE: usize = 12;
const FD_REFUSAL_CAUSE: usize = 13;
const FD_HOP_COUNTER: usize = 14;
const FD_CALLED_PARTY_ADDRESS: usize = 15;
const FD_CALLING_PARTY_ADDRESS: usize = 16;
const FD_DATA: usize = 17;
const FD_SEGMENTATION: usize = 18;
const FD_IMPORTANCE: usize = 19;
const FD_UNKNOWN_PARAMETERS: usize = 20;

/// Field descriptors for the SCCP layer. Every field but `message_type`
/// depends on the message type and is therefore optional.
///
/// ITU-T Q.713, clauses 3 and 4 — <https://www.itu.int/rec/T-REC-Q.713>
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("message_type", "Message Type", FieldType::U8).with_display_fn(|v, _| {
        match v {
            FieldValue::U8(t) => message_type_name(*t),
            _ => None,
        }
    }),
    FieldDescriptor::new(
        "destination_local_reference",
        "Destination Local Reference",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new(
        "source_local_reference",
        "Source Local Reference",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("protocol_class", "Protocol Class", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(c) => protocol_class_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("message_handling", "Message Handling", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(h) => message_handling_name(*h),
            _ => None,
        }),
    FieldDescriptor::new("more_data", "More Data", FieldType::U8).optional(),
    FieldDescriptor::new(
        "send_sequence_number",
        "Send Sequence Number P(S)",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "receive_sequence_number",
        "Receive Sequence Number P(R)",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("credit", "Credit", FieldType::U8).optional(),
    FieldDescriptor::new("release_cause", "Release Cause", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(c) => release_cause_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("return_cause", "Return Cause", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(c) => return_cause_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("reset_cause", "Reset Cause", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(c) => reset_cause_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("error_cause", "Error Cause", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(c) => error_cause_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("refusal_cause", "Refusal Cause", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(c) => refusal_cause_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("hop_counter", "Hop Counter", FieldType::U8).optional(),
    FieldDescriptor::new(
        "called_party_address",
        "Called Party Address",
        FieldType::Object,
    )
    .optional()
    .with_children(ADDRESS_FIELDS),
    FieldDescriptor::new(
        "calling_party_address",
        "Calling Party Address",
        FieldType::Object,
    )
    .optional()
    .with_children(ADDRESS_FIELDS),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("segmentation", "Segmentation", FieldType::Object)
        .optional()
        .with_children(SEGMENTATION_FIELDS),
    FieldDescriptor::new("importance", "Importance", FieldType::U8).optional(),
    FieldDescriptor::new(
        "unknown_parameters",
        "Unknown Optional Parameters",
        FieldType::Array,
    )
    .optional()
    .with_children(core::slice::from_ref(&FD_UNKNOWN_PARAMETER)),
];

/// A mandatory fixed parameter. ITU-T Q.713, clause 1.3.
#[derive(Clone, Copy)]
enum Fixed {
    DestinationLocalReference,
    SourceLocalReference,
    ProtocolClass,
    SegmentingReassembling,
    ReceiveSequenceNumber,
    SequencingSegmenting,
    Credit,
    ReleaseCause,
    ReturnCause,
    ResetCause,
    ErrorCause,
    RefusalCause,
    HopCounter,
}

impl Fixed {
    /// Length of the parameter content. ITU-T Q.713, clauses 3.2-3.18.
    fn len(self) -> usize {
        match self {
            Fixed::DestinationLocalReference | Fixed::SourceLocalReference => 3,
            Fixed::SequencingSegmenting => 2,
            _ => 1,
        }
    }
}

/// A mandatory variable parameter. ITU-T Q.713, clause 1.4.
#[derive(Clone, Copy)]
enum Variable {
    CalledPartyAddress,
    CallingPartyAddress,
    Data,
    /// Long data, with a two-octet length indicator (clause 3.20).
    LongData,
}

/// Layout of one message type. ITU-T Q.713, clause 4.
struct Format {
    fixed: &'static [Fixed],
    variable: &'static [Variable],
    /// Whether a pointer to the optional part follows the variable pointers.
    optional: bool,
    /// Whether the pointers are two octets long (LUDT and LUDTS, clause 1.4).
    long_pointers: bool,
}

/// Returns the layout of a message type.
///
/// ITU-T Q.713, clause 4, Tables 3-22 — <https://www.itu.int/rec/T-REC-Q.713>
fn message_format(msg_type: u8) -> Option<Format> {
    use Fixed::*;
    use Variable::*;
    let (fixed, variable, optional, long_pointers): (&[Fixed], &[Variable], bool, bool) =
        match msg_type {
            MSG_CR => (
                &[SourceLocalReference, ProtocolClass],
                &[CalledPartyAddress],
                true,
                false,
            ),
            MSG_CC => (
                &[
                    DestinationLocalReference,
                    SourceLocalReference,
                    ProtocolClass,
                ],
                &[],
                true,
                false,
            ),
            MSG_CREF => (&[DestinationLocalReference, RefusalCause], &[], true, false),
            MSG_RLSD => (
                &[
                    DestinationLocalReference,
                    SourceLocalReference,
                    ReleaseCause,
                ],
                &[],
                true,
                false,
            ),
            MSG_RLC | MSG_RSC => (
                &[DestinationLocalReference, SourceLocalReference],
                &[],
                false,
                false,
            ),
            MSG_DT1 => (
                &[DestinationLocalReference, SegmentingReassembling],
                &[Data],
                false,
                false,
            ),
            MSG_DT2 => (
                &[DestinationLocalReference, SequencingSegmenting],
                &[Data],
                false,
                false,
            ),
            MSG_AK => (
                &[DestinationLocalReference, ReceiveSequenceNumber, Credit],
                &[],
                false,
                false,
            ),
            MSG_UDT => (
                &[ProtocolClass],
                &[CalledPartyAddress, CallingPartyAddress, Data],
                false,
                false,
            ),
            MSG_UDTS => (
                &[ReturnCause],
                &[CalledPartyAddress, CallingPartyAddress, Data],
                false,
                false,
            ),
            MSG_ED => (&[DestinationLocalReference], &[Data], false, false),
            MSG_EA => (&[DestinationLocalReference], &[], false, false),
            // "one pointer (this allows for inclusion of optional parameters
            // in the future)" — clauses 4.14 and 4.16.
            MSG_RSR => (
                &[DestinationLocalReference, SourceLocalReference, ResetCause],
                &[],
                true,
                false,
            ),
            MSG_ERR => (&[DestinationLocalReference, ErrorCause], &[], true, false),
            MSG_IT => (
                &[
                    DestinationLocalReference,
                    SourceLocalReference,
                    ProtocolClass,
                    SequencingSegmenting,
                    Credit,
                ],
                &[],
                false,
                false,
            ),
            MSG_XUDT => (
                &[ProtocolClass, HopCounter],
                &[CalledPartyAddress, CallingPartyAddress, Data],
                true,
                false,
            ),
            MSG_XUDTS => (
                &[ReturnCause, HopCounter],
                &[CalledPartyAddress, CallingPartyAddress, Data],
                true,
                false,
            ),
            MSG_LUDT => (
                &[ProtocolClass, HopCounter],
                &[CalledPartyAddress, CallingPartyAddress, LongData],
                true,
                true,
            ),
            MSG_LUDTS => (
                &[ReturnCause, HopCounter],
                &[CalledPartyAddress, CallingPartyAddress, LongData],
                true,
                true,
            ),
            _ => return None,
        };
    Some(Format {
        fixed,
        variable,
        optional,
        long_pointers,
    })
}

/// Specification references for the SCCP dissector.
static REFERENCES: &[SpecReference] = &[SpecReference::new(
    "ITU-T Q.713",
    "Signalling connection control part formats and codes",
    "https://www.itu.int/rec/T-REC-Q.713",
)];

/// Information gathered while decoding a message, used to pick the next
/// dissector.
#[derive(Default)]
struct Dispatch {
    called_ssn: u8,
    calling_ssn: u8,
    data: Option<core::ops::Range<usize>>,
    /// Set when a Segmentation parameter marks the data as one segment of a
    /// larger message (clause 3.17), which is not reassembled.
    segmented: bool,
}

/// SCCP dissector.
pub struct SccpDissector;

impl Dissector for SccpDissector {
    fn name(&self) -> &'static str {
        "Signalling Connection Control Part"
    }

    fn short_name(&self) -> &'static str {
        "SCCP"
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
        let Some(&msg_type) = data.first() else {
            return Err(PacketError::Truncated {
                expected: 1,
                actual: 0,
            });
        };
        let format = message_format(msg_type).ok_or(PacketError::InvalidFieldValue {
            field: "message_type",
            value: u32::from(msg_type),
        })?;

        // ITU-T Q.713, clause 4.1.4 — "type F parameters and the pointers for
        // the type V parameters must be sent in the order specified in the
        // following tables. The pointer to the optional parameter block occurs
        // after all pointers to variable parameters."
        let fixed_len: usize = format.fixed.iter().map(|f| f.len()).sum();
        let pointer_size = if format.long_pointers { 2 } else { 1 };
        let pointers_start = 1 + fixed_len;
        let pointer_count = format.variable.len() + usize::from(format.optional);
        let header_len = pointers_start + pointer_count * pointer_size;
        if data.len() < header_len {
            return Err(PacketError::Truncated {
                expected: header_len,
                actual: data.len(),
            });
        }

        // Validate every mandatory variable parameter before pushing
        // anything, so an error leaves the buffer untouched.
        let mut variable: [Option<(Variable, core::ops::Range<usize>)>; 3] = [None, None, None];
        for (i, kind) in format.variable.iter().enumerate() {
            let pointer_at = pointers_start + i * pointer_size;
            let start = pointer_target(data, pointer_at, format.long_pointers).ok_or(
                PacketError::InvalidHeader(
                    "SCCP pointer to a mandatory variable parameter is zero",
                ),
            )?;
            let range = variable_parameter(data, start, *kind)?;
            if range.is_empty()
                && matches!(
                    kind,
                    Variable::CalledPartyAddress | Variable::CallingPartyAddress
                )
            {
                return Err(PacketError::InvalidHeader("SCCP party address is empty"));
            }
            if let Some(slot) = variable.get_mut(i) {
                *slot = Some((*kind, range));
            }
        }
        // ITU-T Q.713, clause 1.4 — "If the message type indicates that an
        // optional part is possible, but there is no optional part included in
        // this particular message, then a pointer field containing all zeros
        // will be used."
        let optional_start = if format.optional {
            let pointer_at = pointers_start + format.variable.len() * pointer_size;
            match pointer_target(data, pointer_at, format.long_pointers) {
                Some(start) if start >= data.len() => {
                    return Err(PacketError::Truncated {
                        expected: start + 1,
                        actual: data.len(),
                    });
                }
                start => start,
            }
        } else {
            None
        };

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + data.len(),
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_TYPE],
            FieldValue::U8(msg_type),
            offset..offset + 1,
        );

        let mut pos = 1;
        for fixed in format.fixed {
            push_fixed(*fixed, &data[pos..pos + fixed.len()], offset + pos, buf);
            pos += fixed.len();
        }

        let mut dispatch = Dispatch::default();
        for (kind, range) in variable.iter().flatten() {
            let content = &data[range.clone()];
            let abs = offset + range.start..offset + range.end;
            match kind {
                Variable::CalledPartyAddress => {
                    dispatch.called_ssn =
                        push_address(FD_CALLED_PARTY_ADDRESS, content, abs.start, buf);
                }
                Variable::CallingPartyAddress => {
                    dispatch.calling_ssn =
                        push_address(FD_CALLING_PARTY_ADDRESS, content, abs.start, buf);
                }
                Variable::Data | Variable::LongData => {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_DATA],
                        FieldValue::Bytes(content),
                        abs.clone(),
                    );
                    dispatch.data = Some(abs);
                }
            }
        }

        if let Some(start) = optional_start {
            let mandatory = mandatory_parameters(&format);
            push_optional_part(data, start, offset, mandatory, &mut dispatch, buf);
        }
        buf.end_layer();

        // The user data is dispatched by subsystem number; data in one
        // segment of a segmented message is not reassembled (clause 3.17).
        if let Some(range) = dispatch.data {
            let has_ssn = dispatch.called_ssn != 0 || dispatch.calling_ssn != 0;
            if !range.is_empty() && has_ssn && !dispatch.segmented {
                return Ok(DissectResult::with_embedded_payload(
                    data.len(),
                    DispatchHint::BySccpSsn {
                        called: dispatch.called_ssn,
                        calling: dispatch.calling_ssn,
                    },
                    range,
                ));
            }
        }
        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

/// Returns the offset of the parameter a pointer at `pointer_at` refers to,
/// or `None` for a zero pointer.
///
/// ITU-T Q.713, clause 2.3 — "The pointer value (in binary) gives the number
/// of octets between the most significant octet of the pointer itself
/// (included) and the first octet (not included) of the parameter associated
/// with that pointer". A two-octet pointer (LUDT, LUDTS) is sent less
/// significant octet first (clause 1.4), so its most significant octet is the
/// second one. <https://www.itu.int/rec/T-REC-Q.713>
fn pointer_target(data: &[u8], pointer_at: usize, long: bool) -> Option<usize> {
    let (value, msb_at) = if long {
        let lsb = *data.get(pointer_at)?;
        let msb = *data.get(pointer_at + 1)?;
        (usize::from(u16::from_le_bytes([lsb, msb])), pointer_at + 1)
    } else {
        (usize::from(*data.get(pointer_at)?), pointer_at)
    };
    (value != 0).then_some(msb_at + value)
}

/// Returns the content range of the mandatory variable parameter whose
/// length indicator is at `start`.
///
/// ITU-T Q.713, clause 2.2 — "The length indicator does not include the
/// parameter name octet or the length indicator octet." Long data has a
/// two-octet length indicator, less significant octet first (clause 1.2).
fn variable_parameter(
    data: &[u8],
    start: usize,
    kind: Variable,
) -> Result<core::ops::Range<usize>, PacketError> {
    let li_size = if matches!(kind, Variable::LongData) {
        2
    } else {
        1
    };
    let content_start = start + li_size;
    if content_start > data.len() {
        return Err(PacketError::Truncated {
            expected: content_start,
            actual: data.len(),
        });
    }
    let len = if li_size == 2 {
        usize::from(u16::from_le_bytes([data[start], data[start + 1]]))
    } else {
        usize::from(data[start])
    };
    let end = content_start + len;
    if end > data.len() {
        return Err(PacketError::Truncated {
            expected: end,
            actual: data.len(),
        });
    }
    Ok(content_start..end)
}

/// Reads a three-octet local reference, less significant octet first like
/// the other multi-octet SCCP fields (ITU-T Q.713, clauses 1.2, 1.4 and
/// 3.4.2.1).
fn local_reference(v: &[u8]) -> u32 {
    match v {
        [a, b, c, ..] => u32::from_le_bytes([*a, *b, *c, 0]),
        _ => 0,
    }
}

/// Push one mandatory fixed parameter. `v` holds exactly `fixed.len()`
/// octets.
fn push_fixed(fixed: Fixed, v: &[u8], off: usize, buf: &mut DissectBuffer<'_>) {
    let first = v.first().copied().unwrap_or_default();
    let fd = |i: usize| &FIELD_DESCRIPTORS[i];
    match fixed {
        // ITU-T Q.713, clauses 3.2 and 3.3 — three-octet reference numbers.
        Fixed::DestinationLocalReference => buf.push_field(
            fd(FD_DESTINATION_LOCAL_REFERENCE),
            FieldValue::U32(local_reference(v)),
            off..off + 3,
        ),
        Fixed::SourceLocalReference => buf.push_field(
            fd(FD_SOURCE_LOCAL_REFERENCE),
            FieldValue::U32(local_reference(v)),
            off..off + 3,
        ),
        // ITU-T Q.713, clause 3.6 — bits 1-4 are the protocol class; for the
        // connectionless classes 0 and 1, bits 5-8 specify message handling,
        // otherwise they are spare.
        Fixed::ProtocolClass => {
            let class = first & 0x0f;
            buf.push_field(fd(FD_PROTOCOL_CLASS), FieldValue::U8(class), off..off + 1);
            if class <= 1 {
                buf.push_field(
                    fd(FD_MESSAGE_HANDLING),
                    FieldValue::U8(first >> 4),
                    off..off + 1,
                );
            }
        }
        // ITU-T Q.713, clause 3.7 — "Bit 1 is used for the more data
        // indication".
        Fixed::SegmentingReassembling => {
            buf.push_field(fd(FD_MORE_DATA), FieldValue::U8(first & 0x01), off..off + 1);
        }
        // ITU-T Q.713, clause 3.8 — "Bits 8-2 contain the receive sequence
        // number P(R)".
        Fixed::ReceiveSequenceNumber => buf.push_field(
            fd(FD_RECEIVE_SEQUENCE_NUMBER),
            FieldValue::U8(first >> 1),
            off..off + 1,
        ),
        // ITU-T Q.713, clause 3.9 — P(S) in bits 8-2 of octet 1; P(R) in bits
        // 8-2 and the more data indication in bit 1 of octet 2.
        Fixed::SequencingSegmenting => {
            let second = v.get(1).copied().unwrap_or_default();
            buf.push_field(
                fd(FD_SEND_SEQUENCE_NUMBER),
                FieldValue::U8(first >> 1),
                off..off + 1,
            );
            buf.push_field(
                fd(FD_RECEIVE_SEQUENCE_NUMBER),
                FieldValue::U8(second >> 1),
                off + 1..off + 2,
            );
            buf.push_field(
                fd(FD_MORE_DATA),
                FieldValue::U8(second & 0x01),
                off + 1..off + 2,
            );
        }
        Fixed::Credit => buf.push_field(fd(FD_CREDIT), FieldValue::U8(first), off..off + 1),
        Fixed::ReleaseCause => {
            buf.push_field(fd(FD_RELEASE_CAUSE), FieldValue::U8(first), off..off + 1)
        }
        Fixed::ReturnCause => {
            buf.push_field(fd(FD_RETURN_CAUSE), FieldValue::U8(first), off..off + 1)
        }
        Fixed::ResetCause => {
            buf.push_field(fd(FD_RESET_CAUSE), FieldValue::U8(first), off..off + 1)
        }
        Fixed::ErrorCause => {
            buf.push_field(fd(FD_ERROR_CAUSE), FieldValue::U8(first), off..off + 1)
        }
        Fixed::RefusalCause => {
            buf.push_field(fd(FD_REFUSAL_CAUSE), FieldValue::U8(first), off..off + 1)
        }
        Fixed::HopCounter => {
            buf.push_field(fd(FD_HOP_COUNTER), FieldValue::U8(first), off..off + 1)
        }
    }
}

/// Push a called or calling party address (`v` is the non-empty parameter
/// content at absolute offset `off`) as the `fd` Object.
///
/// Returns the subsystem number, or 0 when the address carries none.
///
/// ITU-T Q.713, clause 3.4 — <https://www.itu.int/rec/T-REC-Q.713>
fn push_address<'pkt>(fd: usize, v: &'pkt [u8], off: usize, buf: &mut DissectBuffer<'pkt>) -> u8 {
    let idx = buf.begin_container(
        &FIELD_DESCRIPTORS[fd],
        FieldValue::Object(0..0),
        off..off + v.len(),
    );
    let ssn = push_address_elements(v, off, buf);
    buf.end_container(idx);
    ssn
}

/// Push the address indicator and address elements of a party address.
fn push_address_elements<'pkt>(v: &'pkt [u8], off: usize, buf: &mut DissectBuffer<'pkt>) -> u8 {
    let afd = |i: usize| &ADDRESS_FIELDS[i];
    let ai = v.first().copied().unwrap_or_default();
    // ITU-T Q.713, clause 3.4.1, Figure 4 — bit 8 reserved for national use,
    // bit 7 routing indicator, bits 6-3 global title indicator, bit 2 SSN
    // indicator, bit 1 point code indicator.
    let gti = (ai >> 2) & 0x0f;
    let ssn_indicator = (ai >> 1) & 0x01;
    let pc_indicator = ai & 0x01;
    let ai_range = off..off + 1;
    buf.push_field(
        afd(AFD_ADDRESS_INDICATOR),
        FieldValue::U8(ai),
        ai_range.clone(),
    );
    buf.push_field(
        afd(AFD_NATIONAL_USE),
        FieldValue::U8(ai >> 7),
        ai_range.clone(),
    );
    buf.push_field(
        afd(AFD_ROUTING_INDICATOR),
        FieldValue::U8((ai >> 6) & 0x01),
        ai_range.clone(),
    );
    buf.push_field(
        afd(AFD_GLOBAL_TITLE_INDICATOR),
        FieldValue::U8(gti),
        ai_range.clone(),
    );
    buf.push_field(
        afd(AFD_SSN_INDICATOR),
        FieldValue::U8(ssn_indicator),
        ai_range.clone(),
    );
    buf.push_field(
        afd(AFD_POINT_CODE_INDICATOR),
        FieldValue::U8(pc_indicator),
        ai_range,
    );

    // ITU-T Q.713, clause 3.4.2 — "The various elements, when provided,
    // occur in the order: point code, subsystem number, global title".
    let mut pos = 1;
    let mut ssn = 0;
    // Pushes the octets from `pos` on as raw address information.
    let push_rest = |pos: usize, buf: &mut DissectBuffer<'pkt>| {
        if let Some(rest) = v.get(pos..).filter(|r| !r.is_empty()) {
            buf.push_field(
                afd(AFD_ADDRESS_INFORMATION),
                FieldValue::Bytes(rest),
                off + pos..off + v.len(),
            );
        }
    };

    // ITU-T Q.713, clause 3.4.2.1 — two octets, "Bits 7 and 8 in the second
    // octet are set to zero"; the less significant octet comes first.
    if pc_indicator == 1 {
        let Some(&[lsb, msb]) = v.get(pos..pos + 2) else {
            push_rest(pos, buf);
            return ssn;
        };
        buf.push_field(
            afd(AFD_POINT_CODE),
            FieldValue::U16(u16::from_le_bytes([lsb, msb]) & 0x3fff),
            off + pos..off + pos + 2,
        );
        pos += 2;
    }
    // ITU-T Q.713, clause 3.4.2.2 — one octet.
    if ssn_indicator == 1 {
        let Some(&s) = v.get(pos) else {
            return ssn;
        };
        ssn = s;
        buf.push_field(afd(AFD_SSN), FieldValue::U8(s), off + pos..off + pos + 1);
        pos += 1;
    }

    // ITU-T Q.713, clause 3.4.2.3 — global title formats by GTI.
    let header_len = match gti {
        0 => 0,
        1 | 2 => 1,
        3 => 2,
        4 => 3,
        // Spare or reserved global title indicator: format unknown.
        _ => {
            push_rest(pos, buf);
            return ssn;
        }
    };
    let Some(header) = v.get(pos..pos + header_len) else {
        push_rest(pos, buf);
        return ssn;
    };
    let h = |i: usize| header.get(i).copied().unwrap_or_default();
    let hoff = off + pos;
    // `Some(odd)` when the address information is BCD.
    let bcd = match gti {
        // Clause 3.4.2.3.1 — odd/even indicator (bit 8) and nature of
        // address indicator (bits 7-1); the address signals are BCD.
        1 => {
            buf.push_field(afd(AFD_ODD_EVEN), FieldValue::U8(h(0) >> 7), hoff..hoff + 1);
            buf.push_field(
                afd(AFD_NATURE_OF_ADDRESS),
                FieldValue::U8(h(0) & 0x7f),
                hoff..hoff + 1,
            );
            Some(h(0) >> 7 == 1)
        }
        // Clause 3.4.2.3.2 — translation type only; the encoding is implied
        // by the translation type (national use).
        2 => {
            buf.push_field(
                afd(AFD_TRANSLATION_TYPE),
                FieldValue::U8(h(0)),
                hoff..hoff + 1,
            );
            None
        }
        // Clauses 3.4.2.3.3 and 3.4.2.3.4 — translation type, numbering plan
        // (bits 8-5) and encoding scheme (bits 4-1), then for GTI 0100 the
        // nature of address indicator (bits 7-1).
        3 | 4 => {
            buf.push_field(
                afd(AFD_TRANSLATION_TYPE),
                FieldValue::U8(h(0)),
                hoff..hoff + 1,
            );
            buf.push_field(
                afd(AFD_NUMBERING_PLAN),
                FieldValue::U8(h(1) >> 4),
                hoff + 1..hoff + 2,
            );
            let es = h(1) & 0x0f;
            buf.push_field(
                afd(AFD_ENCODING_SCHEME),
                FieldValue::U8(es),
                hoff + 1..hoff + 2,
            );
            if gti == 4 {
                buf.push_field(
                    afd(AFD_NATURE_OF_ADDRESS),
                    FieldValue::U8(h(2) & 0x7f),
                    hoff + 2..hoff + 3,
                );
            }
            // Encoding scheme 0001 "BCD, odd number of digits" and 0010
            // "BCD, even number of digits".
            match es {
                1 => Some(true),
                2 => Some(false),
                _ => None,
            }
        }
        _ => None,
    };
    pos += header_len;
    match (gti, bcd) {
        (0, _) => push_rest(pos, buf),
        (_, Some(odd)) => {
            let signals = v.get(pos..).unwrap_or_default();
            push_bcd_digits(signals, odd, off + pos..off + v.len(), buf);
        }
        (_, None) => push_rest(pos, buf),
    }
    ssn
}

/// Decode BCD address signals into the scratch buffer as ASCII and push the
/// `digits` field.
///
/// ITU-T Q.713, clause 3.4.2.3.1, Figure 8 — two address signals per octet,
/// the first in bits 4-1; "In case of an odd number of address signals, a
/// filler code 0000 is inserted after the last address signal." Codes 0-9
/// are digits; codes 1011 (code 11), 1100 (code 12), 1111 (ST) and the spare
/// codes are written as the hexadecimal letters `A`-`F`.
fn push_bcd_digits(
    signals: &[u8],
    odd: bool,
    range: core::ops::Range<usize>,
    buf: &mut DissectBuffer<'_>,
) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let start = buf.scratch_len();
    for (i, octet) in signals.iter().enumerate() {
        buf.extend_scratch(&[HEX[usize::from(octet & 0x0f)]]);
        let last = i + 1 == signals.len();
        if !(last && odd) {
            buf.extend_scratch(&[HEX[usize::from(octet >> 4)]]);
        }
    }
    buf.push_field(
        &ADDRESS_FIELDS[AFD_DIGITS],
        FieldValue::Scratch(start..buf.scratch_len()),
        range,
    );
}

/// Iterator over the parameters of the optional part.
///
/// ITU-T Q.713, clause 1.5 — "Each optional parameter will include the
/// parameter name (one octet) and the length indicator (one octet) followed
/// by the parameter contents." Iteration ends at the end of optional
/// parameters octet (clause 1.6), or at a parameter that does not fit the
/// message, since the following parameter boundaries cannot be known.
struct OptionalParameters<'pkt> {
    data: &'pkt [u8],
    pos: usize,
}

impl<'pkt> Iterator for OptionalParameters<'pkt> {
    /// Parameter name, offset of the name octet, and content.
    type Item = (u8, usize, &'pkt [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let name = *self.data.get(self.pos)?;
        if name == PARAM_END_OF_OPTIONAL {
            return None;
        }
        let len = usize::from(*self.data.get(self.pos + 1)?);
        let content = self.data.get(self.pos + 2..self.pos + 2 + len)?;
        let at = self.pos;
        self.pos += 2 + len;
        Some((name, at, content))
    }
}

/// Bit of a parameter name in a set of already present parameters.
fn param_bit(name: u8) -> u32 {
    1u32.checked_shl(u32::from(name)).unwrap_or(0)
}

/// Parameters of the fixed and mandatory variable parts, as a set of
/// [`param_bit`]s. Long data shares the `data` field and counts as Data.
fn mandatory_parameters(format: &Format) -> u32 {
    let fixed = format.fixed.iter().map(|f| match f {
        Fixed::Credit => param_bit(PARAM_CREDIT),
        Fixed::HopCounter => param_bit(PARAM_HOP_COUNTER),
        _ => 0,
    });
    let variable = format.variable.iter().map(|v| match v {
        Variable::CalledPartyAddress => param_bit(PARAM_CALLED_PARTY_ADDRESS),
        Variable::CallingPartyAddress => param_bit(PARAM_CALLING_PARTY_ADDRESS),
        Variable::Data | Variable::LongData => param_bit(PARAM_DATA),
    });
    fixed.chain(variable).fold(0, |acc, bit| acc | bit)
}

/// Returns whether an optional parameter is decoded into named fields, and
/// records it in `seen`. A parameter that is already present (in the
/// mandatory part or earlier in the optional part), unrecognised, or of the
/// wrong length is listed in `unknown_parameters` instead, so the named
/// fields and the dispatched data always come from the first occurrence.
fn classify_optional(name: u8, content: &[u8], seen: &mut u32) -> bool {
    if *seen & param_bit(name) != 0 {
        return false;
    }
    let known = match name {
        PARAM_CREDIT | PARAM_HOP_COUNTER | PARAM_IMPORTANCE => content.len() == 1,
        PARAM_CALLED_PARTY_ADDRESS | PARAM_CALLING_PARTY_ADDRESS => !content.is_empty(),
        PARAM_DATA => true,
        PARAM_SEGMENTATION => content.len() == SEGMENTATION_SIZE,
        _ => false,
    };
    if known {
        *seen |= param_bit(name);
    }
    known
}

/// Push the optional part starting at `start` (relative to `data`);
/// `mandatory` is the set of parameters already present
/// ([`mandatory_parameters`]).
fn push_optional_part<'pkt>(
    data: &'pkt [u8],
    start: usize,
    offset: usize,
    mandatory: u32,
    dispatch: &mut Dispatch,
    buf: &mut DissectBuffer<'pkt>,
) {
    let params = || OptionalParameters { data, pos: start };
    let mut seen = mandatory;
    let mut any_unknown = false;
    for (name, at, content) in params() {
        if !classify_optional(name, content, &mut seen) {
            any_unknown = true;
            continue;
        }
        let first = content.first().copied().unwrap_or_default();
        let coff = offset + at + 2;
        let crange = coff..coff + content.len();
        let fd = |i: usize| &FIELD_DESCRIPTORS[i];
        match name {
            PARAM_CREDIT => buf.push_field(fd(FD_CREDIT), FieldValue::U8(first), crange),
            PARAM_HOP_COUNTER => buf.push_field(fd(FD_HOP_COUNTER), FieldValue::U8(first), crange),
            // ITU-T Q.713, clause 3.19 — "Bits 1-3 are binary coded to
            // indicate the importance of the messages."
            PARAM_IMPORTANCE => {
                buf.push_field(fd(FD_IMPORTANCE), FieldValue::U8(first & 0x07), crange)
            }
            PARAM_CALLED_PARTY_ADDRESS => {
                dispatch.called_ssn = push_address(FD_CALLED_PARTY_ADDRESS, content, coff, buf);
            }
            PARAM_CALLING_PARTY_ADDRESS => {
                dispatch.calling_ssn = push_address(FD_CALLING_PARTY_ADDRESS, content, coff, buf);
            }
            PARAM_DATA => {
                buf.push_field(fd(FD_DATA), FieldValue::Bytes(content), crange.clone());
                dispatch.data = Some(crange);
            }
            // ITU-T Q.713, clause 3.17 — F (bit 8), C (bit 7), remaining
            // segments (bits 4-1), then the three-octet segmentation local
            // reference.
            _ => {
                let first_segment = first >> 7;
                let remaining = first & 0x0f;
                let sfd = |i: usize| &SEGMENTATION_FIELDS[i];
                let idx =
                    buf.begin_container(fd(FD_SEGMENTATION), FieldValue::Object(0..0), crange);
                buf.push_field(
                    sfd(SFD_FIRST_SEGMENT),
                    FieldValue::U8(first_segment),
                    coff..coff + 1,
                );
                buf.push_field(
                    sfd(SFD_CLASS),
                    FieldValue::U8((first >> 6) & 0x01),
                    coff..coff + 1,
                );
                buf.push_field(
                    sfd(SFD_REMAINING_SEGMENTS),
                    FieldValue::U8(remaining),
                    coff..coff + 1,
                );
                buf.push_field(
                    sfd(SFD_LOCAL_REFERENCE),
                    FieldValue::U32(local_reference(content.get(1..).unwrap_or_default())),
                    coff + 1..coff + 4,
                );
                buf.end_container(idx);
                dispatch.segmented = !(first_segment == 1 && remaining == 0);
            }
        }
    }

    if !any_unknown {
        return;
    }
    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_UNKNOWN_PARAMETERS],
        FieldValue::Array(0..0),
        offset + start..offset + data.len(),
    );
    // Replay the classification from the same starting set.
    let mut seen = mandatory;
    for (name, at, content) in params() {
        if classify_optional(name, content, &mut seen) {
            continue;
        }
        let abs = offset + at;
        let ufd = |i: usize| &UNKNOWN_PARAMETER_FIELDS[i];
        let idx = buf.begin_container(
            &FD_UNKNOWN_PARAMETER,
            FieldValue::Object(0..0),
            abs..abs + 2 + content.len(),
        );
        buf.push_field(ufd(UFD_NAME), FieldValue::U8(name), abs..abs + 1);
        buf.push_field(
            ufd(UFD_LENGTH),
            FieldValue::U8(content.len() as u8),
            abs + 1..abs + 2,
        );
        buf.push_field(
            ufd(UFD_VALUE),
            FieldValue::Bytes(content),
            abs + 2..abs + 2 + content.len(),
        );
        buf.end_container(idx);
    }
    buf.end_container(array_idx);
}

#[cfg(test)]
mod tests {
    //! # ITU-T Q.713 (SCCP) Coverage
    //!
    //! | Clause     | Description                                     | Test                                  |
    //! |------------|-------------------------------------------------|---------------------------------------|
    //! | 1.4, 2.3   | Pointers to mandatory variable parameters       | parse_udt_gt_route                    |
    //! | 2.1        | Message type codes (names)                      | name_tables                           |
    //! | 2.1, 3     | Name table sizes and display functions          | display_fns_and_name_table_sizes      |
    //! | 2.1        | Unknown message type                            | reject_unknown_message_type           |
    //! | 3.4.1      | Address indicator                               | parse_udt_gt_route                    |
    //! | 3.4.2.1    | Signalling point code (14 bits, LSB first)      | parse_udt_ssn_route_with_pc           |
    //! | 3.4.2.2    | Subsystem number                                | parse_udt_ssn_route_with_pc           |
    //! | 3.4.2.3.1  | GTI 0001: NAI + BCD digits (odd)                | parse_gti1_odd_digits                 |
    //! | 3.4.2.3.2  | GTI 0010: translation type only                 | parse_gti2_translation_type_only      |
    //! | 3.4.2.3.3  | GTI 0011: TT, NP, ES                            | parse_gti3                            |
    //! | 3.4.2.3.4  | GTI 0100: TT, NP, ES, NAI + BCD digits (even)   | parse_udt_gt_route                    |
    //! | 3.4.2.3    | Non-BCD / spare GTI address kept raw            | parse_non_bcd_and_spare_gti           |
    //! | 3.4        | Address shorter than its indicator implies      | parse_short_address                   |
    //! | 3.5        | Calling address of the AI octet only            | parse_calling_address_indicator_only  |
    //! | 3.6        | Protocol class / message handling               | parse_udt_gt_route                    |
    //! | 3.7-3.10   | DT1 / DT2 / AK / IT fixed parameters            | parse_connection_oriented_data        |
    //! | 3.11-3.15  | Cause parameters                                | parse_cause_messages                  |
    //! | 3.17       | Segmentation (segment not dispatched)           | parse_xudt_segmented                  |
    //! | 3.18-3.19  | Hop counter, Importance                         | parse_xudt_optional_part              |
    //! | 3.20       | Long data, two-octet pointers (LUDT)            | parse_ludt                            |
    //! | 4.2        | CR with optional calling address and data       | parse_cr_optional_part                |
    //! | 4.11       | UDTS return cause                               | parse_cause_messages                  |
    //! | 1.5, 1.6   | Unknown optional parameter / end octet          | parse_xudt_optional_part              |
    //! | 1.5        | Malformed optional part stops                   | parse_malformed_optional_part         |
    //! | 1.5        | Optional duplicate of a present parameter       | optional_duplicates_are_unknown       |
    //! | 1.3        | Truncated fixed part                            | truncated_fixed_part                  |
    //! | 1.4        | Pointer / parameter beyond the message          | truncated_variable_parameter          |
    //! | 1.4        | Zero pointer to a mandatory parameter           | reject_zero_mandatory_pointer         |
    //! | 1.4        | Empty party address                             | reject_empty_address                  |

    use super::*;
    use packet_dissector_core::field::Field;

    fn dissect(data: &[u8]) -> (DissectBuffer<'_>, DissectResult) {
        let mut buf = DissectBuffer::new();
        let r = SccpDissector.dissect(data, &mut buf, 0).unwrap();
        (buf, r)
    }

    fn field<'a>(buf: &'a DissectBuffer<'a>, name: &str) -> &'a FieldValue<'a> {
        &buf.field_by_name(&buf.layers()[0], name)
            .unwrap_or_else(|| panic!("no field {name}"))
            .value
    }

    fn has_field(buf: &DissectBuffer<'_>, name: &str) -> bool {
        buf.field_by_name(&buf.layers()[0], name).is_some()
    }

    fn object<'a>(buf: &'a DissectBuffer<'a>, name: &str) -> &'a [Field<'a>] {
        let FieldValue::Object(r) = field(buf, name) else {
            panic!("{name} is not an object")
        };
        buf.nested_fields(r)
    }

    fn get<'a>(fields: &'a [Field<'a>], name: &str) -> &'a FieldValue<'a> {
        &fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("no field {name}"))
            .value
    }

    fn has(fields: &[Field<'_>], name: &str) -> bool {
        fields.iter().any(|f| f.name() == name)
    }

    fn digits<'a>(buf: &'a DissectBuffer<'a>, fields: &[Field<'_>]) -> &'a str {
        let FieldValue::Scratch(r) = get(fields, "digits") else {
            panic!("digits is not scratch")
        };
        core::str::from_utf8(&buf.scratch()[r.start as usize..r.end as usize]).unwrap()
    }

    /// Called party: RI=GT, GTI=4, SSN=6 (HLR); TT=0, NP=1 (E.164),
    /// ES=2 (BCD even), NAI=4 (international), digits 12345678.
    const CALLED_GT: &[u8] = &[0x12, 0x06, 0x00, 0x12, 0x04, 0x21, 0x43, 0x65, 0x87];
    /// Calling party: RI=GT, GTI=4, SSN=7 (VLR); TT=0, NP=1, ES=1 (BCD
    /// odd), NAI=4, digits 98765.
    const CALLING_GT: &[u8] = &[0x12, 0x07, 0x00, 0x11, 0x04, 0x89, 0x67, 0x05];

    /// Build a UDT with the given class octet, addresses and data.
    fn udt(class: u8, called: &[u8], calling: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = vec![MSG_UDT, class];
        // Three pointers: each counts from its own octet.
        let p1 = 3u8;
        let p2 = p1 - 1 + 1 + called.len() as u8;
        let p3 = p2 - 1 + 1 + calling.len() as u8;
        m.extend_from_slice(&[p1, p2, p3]);
        m.push(called.len() as u8);
        m.extend_from_slice(called);
        m.push(calling.len() as u8);
        m.extend_from_slice(calling);
        m.push(data.len() as u8);
        m.extend_from_slice(data);
        m
    }

    #[test]
    fn parse_udt_gt_route() {
        let user = [0x62, 0x03, 0x48, 0x01, 0x01]; // TCAP Begin start
        let data = udt(0x80, CALLED_GT, CALLING_GT, &user);
        let (buf, r) = dissect(&data);
        assert_eq!(r.bytes_consumed, data.len());
        assert_eq!(
            r.next,
            DispatchHint::BySccpSsn {
                called: 6,
                calling: 7
            }
        );
        let start = data.len() - user.len();
        assert_eq!(r.embedded_payload, Some(start..data.len()));
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "SCCP");
        assert_eq!(layer.range, 0..data.len());
        assert_eq!(*field(&buf, "message_type"), FieldValue::U8(MSG_UDT));
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("Unitdata (UDT)")
        );
        assert_eq!(*field(&buf, "protocol_class"), FieldValue::U8(0));
        assert_eq!(*field(&buf, "message_handling"), FieldValue::U8(8));
        assert_eq!(
            buf.resolve_display_name(layer, "message_handling_name"),
            Some("return message on error")
        );
        assert_eq!(*field(&buf, "data"), FieldValue::Bytes(&user));

        let called = object(&buf, "called_party_address");
        assert_eq!(*get(called, "address_indicator"), FieldValue::U8(0x12));
        assert_eq!(*get(called, "national_use"), FieldValue::U8(0));
        assert_eq!(*get(called, "routing_indicator"), FieldValue::U8(0));
        assert_eq!(*get(called, "global_title_indicator"), FieldValue::U8(4));
        assert_eq!(*get(called, "ssn_indicator"), FieldValue::U8(1));
        assert_eq!(*get(called, "point_code_indicator"), FieldValue::U8(0));
        assert!(!has(called, "point_code"));
        assert_eq!(*get(called, "ssn"), FieldValue::U8(6));
        assert_eq!(*get(called, "translation_type"), FieldValue::U8(0));
        assert_eq!(*get(called, "numbering_plan"), FieldValue::U8(1));
        assert_eq!(*get(called, "encoding_scheme"), FieldValue::U8(2));
        assert_eq!(*get(called, "nature_of_address"), FieldValue::U8(4));
        assert_eq!(digits(&buf, called), "12345678");

        let calling = object(&buf, "calling_party_address");
        assert_eq!(*get(calling, "ssn"), FieldValue::U8(7));
        assert_eq!(*get(calling, "encoding_scheme"), FieldValue::U8(1));
        assert_eq!(digits(&buf, calling), "98765");
    }

    #[test]
    fn digits_format_fn_writes_string() {
        let data = udt(0x00, CALLED_GT, CALLING_GT, &[1]);
        let (buf, _) = dissect(&data);
        let called = object(&buf, "called_party_address");
        let f = called.iter().find(|f| f.name() == "digits").unwrap();
        let ctx = FormatContext {
            packet_data: &data,
            scratch: buf.scratch(),
            layer_range: 0..data.len() as u32,
            field_range: f.range.start as u32..f.range.end as u32,
        };
        let mut out = Vec::new();
        (f.descriptor.format_fn.unwrap())(&f.value, &ctx, &mut out).unwrap();
        assert_eq!(out, b"\"12345678\"");
        let mut out = Vec::new();
        format_digits(&FieldValue::U8(1), &ctx, &mut out).unwrap();
        assert_eq!(out, b"\"\"");
    }

    #[test]
    fn parse_udt_ssn_route_with_pc() {
        // RI=SSN, SSN and PC present: AI=0x43, PC=0x0321 (LSB first), SSN=8.
        let called = [0x43, 0x21, 0x03, 0x08];
        let calling = [0x43, 0xff, 0x3f, 0x07];
        let data = udt(0x01, &called, &calling, &[0xaa]);
        let (buf, r) = dissect(&data);
        assert_eq!(
            r.next,
            DispatchHint::BySccpSsn {
                called: 8,
                calling: 7
            }
        );
        assert_eq!(*field(&buf, "message_handling"), FieldValue::U8(0));
        let c = object(&buf, "called_party_address");
        assert_eq!(*get(c, "routing_indicator"), FieldValue::U8(1));
        assert_eq!(*get(c, "point_code"), FieldValue::U16(0x0321));
        assert_eq!(*get(c, "ssn"), FieldValue::U8(8));
        let c = object(&buf, "calling_party_address");
        // Bits 7 and 8 of the second point code octet are not part of the
        // 14-bit point code (clause 3.4.2.1).
        assert_eq!(*get(c, "point_code"), FieldValue::U16(0x3fff));
    }

    #[test]
    fn parse_gti1_odd_digits() {
        // GTI=1: O/E + NAI, then BCD digits (clause 3.4.2.3.1).
        let called = [0x04, 0x84, 0x21, 0x43, 0x05]; // odd, NAI=4, 12345
        let data = udt(0x00, &called, CALLING_GT, &[1]);
        let (buf, _) = dissect(&data);
        let c = object(&buf, "called_party_address");
        assert_eq!(*get(c, "odd_even"), FieldValue::U8(1));
        assert_eq!(*get(c, "nature_of_address"), FieldValue::U8(4));
        assert_eq!(digits(&buf, c), "12345");
    }

    #[test]
    fn parse_gti2_translation_type_only() {
        let called = [0x08, 0x11, 0x99, 0x88];
        let data = udt(0x00, &called, CALLING_GT, &[1]);
        let (buf, r) = dissect(&data);
        let c = object(&buf, "called_party_address");
        assert_eq!(*get(c, "translation_type"), FieldValue::U8(0x11));
        assert_eq!(
            *get(c, "address_information"),
            FieldValue::Bytes(&[0x99, 0x88])
        );
        assert!(!has(c, "digits"));
        // No SSN in the called address: the calling SSN is still offered.
        assert_eq!(
            r.next,
            DispatchHint::BySccpSsn {
                called: 0,
                calling: 7
            }
        );
    }

    #[test]
    fn parse_gti3() {
        // GTI=3: TT, NP/ES, digits; BCD digits 0xB, 0xC and 0xF decode to
        // hexadecimal letters.
        let called = [0x0c, 0x00, 0x12, 0xcb, 0x0f];
        let data = udt(0x00, &called, CALLING_GT, &[1]);
        let (buf, _) = dissect(&data);
        let c = object(&buf, "called_party_address");
        assert_eq!(*get(c, "numbering_plan"), FieldValue::U8(1));
        assert_eq!(*get(c, "encoding_scheme"), FieldValue::U8(2));
        assert!(!has(c, "nature_of_address"));
        assert_eq!(digits(&buf, c), "BCF0");
    }

    #[test]
    fn parse_non_bcd_and_spare_gti() {
        // GTI=4 with ES=3 (national specific) keeps the address raw.
        let called = [0x12, 0x06, 0x00, 0x13, 0x04, 0xab];
        // GTI=5 (spare) keeps everything after the SSN raw.
        let calling = [0x16, 0x07, 0x01, 0x02];
        let data = udt(0x00, &called, &calling, &[1]);
        let (buf, _) = dissect(&data);
        let c = object(&buf, "called_party_address");
        assert_eq!(*get(c, "address_information"), FieldValue::Bytes(&[0xab]));
        let c = object(&buf, "calling_party_address");
        assert_eq!(*get(c, "global_title_indicator"), FieldValue::U8(5));
        assert_eq!(
            *get(c, "address_information"),
            FieldValue::Bytes(&[0x01, 0x02])
        );
    }

    #[test]
    fn parse_short_address() {
        // PC indicated but only one octet follows; GT header cut short.
        let called = [0x01, 0x05];
        let calling = [0x12, 0x07, 0x00];
        let data = udt(0x00, &called, &calling, &[1]);
        let (buf, r) = dissect(&data);
        let c = object(&buf, "called_party_address");
        assert!(!has(c, "point_code"));
        assert_eq!(*get(c, "address_information"), FieldValue::Bytes(&[0x05]));
        let c = object(&buf, "calling_party_address");
        assert_eq!(*get(c, "ssn"), FieldValue::U8(7));
        assert!(!has(c, "translation_type"));
        assert_eq!(*get(c, "address_information"), FieldValue::Bytes(&[0x00]));
        assert_eq!(
            r.next,
            DispatchHint::BySccpSsn {
                called: 0,
                calling: 7
            }
        );
        // SSN indicated but missing.
        let data = udt(0x00, &[0x42], &[0x42], &[1]);
        let (buf, r) = dissect(&data);
        assert!(!has(object(&buf, "called_party_address"), "ssn"));
        assert_eq!(r.next, DispatchHint::End);
    }

    #[test]
    fn parse_calling_address_indicator_only() {
        // Clause 3.5 — the calling party address may consist of the address
        // indicator octet only, with bits 1 to 7 coded all zeros.
        let data = udt(0x00, CALLED_GT, &[0x00], &[1]);
        let (buf, r) = dissect(&data);
        let c = object(&buf, "calling_party_address");
        assert_eq!(c.len(), 6);
        assert_eq!(
            r.next,
            DispatchHint::BySccpSsn {
                called: 6,
                calling: 0
            }
        );
    }

    #[test]
    fn parse_connection_oriented_data() {
        // DT1: DLR, segmenting/reassembling (M=1), pointer, data.
        let data = [MSG_DT1, 0x01, 0x02, 0x03, 0x01, 0x01, 0x02, 0xaa, 0xbb];
        let (buf, r) = dissect(&data);
        assert_eq!(
            *field(&buf, "destination_local_reference"),
            FieldValue::U32(0x030201)
        );
        assert_eq!(*field(&buf, "more_data"), FieldValue::U8(1));
        assert_eq!(*field(&buf, "data"), FieldValue::Bytes(&[0xaa, 0xbb]));
        // No addresses: no SSN to dispatch on.
        assert_eq!(r.next, DispatchHint::End);

        // DT2: sequencing/segmenting P(S)=5, P(R)=6, M=0.
        let data = [MSG_DT2, 0, 0, 1, 0x0a, 0x0c, 0x01, 0x01, 0x55];
        let (buf, _) = dissect(&data);
        assert_eq!(*field(&buf, "send_sequence_number"), FieldValue::U8(5));
        assert_eq!(*field(&buf, "receive_sequence_number"), FieldValue::U8(6));
        assert_eq!(*field(&buf, "more_data"), FieldValue::U8(0));

        // AK: receive sequence number P(R)=3, credit 7.
        let data = [MSG_AK, 0, 0, 1, 0x06, 0x07];
        let (buf, r) = dissect(&data);
        assert_eq!(*field(&buf, "receive_sequence_number"), FieldValue::U8(3));
        assert_eq!(*field(&buf, "credit"), FieldValue::U8(7));
        assert_eq!(r.bytes_consumed, 6);

        // IT: class 2, the class 2 spare nibble is not message handling.
        let data = [MSG_IT, 0, 0, 1, 0, 0, 2, 0xf2, 0, 0, 0];
        let (buf, _) = dissect(&data);
        assert_eq!(
            *field(&buf, "source_local_reference"),
            FieldValue::U32(0x020000)
        );
        assert_eq!(*field(&buf, "protocol_class"), FieldValue::U8(2));
        assert!(!has_field(&buf, "message_handling"));

        // ED with data, EA / RLC / RSC fixed only.
        let (buf, _) = dissect(&[MSG_ED, 0, 0, 1, 0x01, 0x01, 0x77]);
        assert_eq!(*field(&buf, "data"), FieldValue::Bytes(&[0x77]));
        for t in [MSG_EA, MSG_RLC, MSG_RSC] {
            let m = [t, 0, 0, 1, 0, 0, 2];
            let (buf, _) = dissect(&m);
            assert!(has_field(&buf, "destination_local_reference"));
        }
    }

    #[test]
    fn parse_cause_messages() {
        let (buf, _) = dissect(&[MSG_CREF, 0, 0, 1, 0x13, 0x00]);
        assert_eq!(*field(&buf, "refusal_cause"), FieldValue::U8(0x13));
        let (buf, _) = dissect(&[MSG_RLSD, 0, 0, 1, 0, 0, 2, 0x03, 0x00]);
        assert_eq!(*field(&buf, "release_cause"), FieldValue::U8(0x03));
        let (buf, _) = dissect(&[MSG_RSR, 0, 0, 1, 0, 0, 2, 0x0c, 0x00]);
        assert_eq!(*field(&buf, "reset_cause"), FieldValue::U8(0x0c));
        let (buf, _) = dissect(&[MSG_ERR, 0, 0, 1, 0x02, 0x00]);
        assert_eq!(*field(&buf, "error_cause"), FieldValue::U8(0x02));
        // CC with an optional part pointer of zero.
        let (buf, _) = dissect(&[MSG_CC, 0, 0, 1, 0, 0, 2, 0x02, 0x00]);
        assert_eq!(*field(&buf, "protocol_class"), FieldValue::U8(2));

        let mut data = udt(0x00, CALLED_GT, CALLING_GT, &[0x62]);
        data[0] = MSG_UDTS;
        data[1] = 0x01;
        let (buf, r) = dissect(&data);
        assert_eq!(*field(&buf, "return_cause"), FieldValue::U8(1));
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "return_cause_name"),
            Some("no translation for this specific address")
        );
        assert!(matches!(r.next, DispatchHint::BySccpSsn { .. }));
    }

    /// XUDT: class, hop counter, four pointers, addresses, data, optional.
    fn xudt(optional: &[u8]) -> Vec<u8> {
        let called = CALLED_GT;
        let calling = CALLING_GT;
        let data = [0x62, 0x00];
        let mut m = vec![MSG_XUDT, 0x81, 0x0f];
        let p1 = 4u8;
        let p2 = p1 - 1 + 1 + called.len() as u8;
        let p3 = p2 - 1 + 1 + calling.len() as u8;
        let p4 = if optional.is_empty() {
            0
        } else {
            p3 - 1 + 1 + data.len() as u8
        };
        m.extend_from_slice(&[p1, p2, p3, p4]);
        m.push(called.len() as u8);
        m.extend_from_slice(called);
        m.push(calling.len() as u8);
        m.extend_from_slice(calling);
        m.push(data.len() as u8);
        m.extend_from_slice(&data);
        m.extend_from_slice(optional);
        m
    }

    #[test]
    fn parse_xudt_optional_part() {
        let optional = [
            PARAM_IMPORTANCE,
            1,
            0x05,
            0x7e, // unknown (national) parameter
            2,
            0xab,
            0xcd,
            PARAM_END_OF_OPTIONAL,
        ];
        let data = xudt(&optional);
        let (buf, r) = dissect(&data);
        assert_eq!(*field(&buf, "protocol_class"), FieldValue::U8(1));
        assert_eq!(*field(&buf, "hop_counter"), FieldValue::U8(15));
        assert_eq!(*field(&buf, "importance"), FieldValue::U8(5));
        let FieldValue::Array(ur) = field(&buf, "unknown_parameters") else {
            panic!()
        };
        let u = buf.nested_fields(ur);
        assert_eq!(*get(u, "name"), FieldValue::U8(0x7e));
        assert_eq!(*get(u, "length"), FieldValue::U8(2));
        assert_eq!(*get(u, "value"), FieldValue::Bytes(&[0xab, 0xcd]));
        assert!(matches!(r.next, DispatchHint::BySccpSsn { .. }));

        // No optional part.
        let m = xudt(&[]);
        let (buf, _) = dissect(&m);
        assert!(!has_field(&buf, "importance"));
        assert!(!has_field(&buf, "unknown_parameters"));
    }

    #[test]
    fn optional_duplicates_are_unknown() {
        // XUDT has a fixed hop counter and a mandatory Data parameter; an
        // optional Data, Hop counter or a second Importance must not replace
        // them.
        let optional = [
            PARAM_DATA,
            1,
            0xee,
            PARAM_HOP_COUNTER,
            1,
            0x01,
            PARAM_IMPORTANCE,
            1,
            0x02,
            PARAM_IMPORTANCE,
            1,
            0x07,
            PARAM_END_OF_OPTIONAL,
        ];
        let m = xudt(&optional);
        let (buf, r) = dissect(&m);
        assert_eq!(*field(&buf, "hop_counter"), FieldValue::U8(15));
        assert_eq!(*field(&buf, "data"), FieldValue::Bytes(&[0x62, 0x00]));
        assert_eq!(*field(&buf, "importance"), FieldValue::U8(2));
        let layer = &buf.layers()[0];
        let count = |n: &str| {
            buf.layer_fields(layer)
                .iter()
                .filter(|f| f.name() == n)
                .count()
        };
        assert_eq!(count("data"), 1);
        assert_eq!(count("hop_counter"), 1);
        assert_eq!(count("importance"), 1);
        let FieldValue::Array(ur) = field(&buf, "unknown_parameters") else {
            panic!()
        };
        let names: Vec<_> = buf
            .nested_fields(ur)
            .iter()
            .filter(|f| f.name() == "name")
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(
            names,
            [
                FieldValue::U8(PARAM_DATA),
                FieldValue::U8(PARAM_HOP_COUNTER),
                FieldValue::U8(PARAM_IMPORTANCE)
            ]
        );
        let data_start = m.len() - optional.len() - 2;
        assert_eq!(r.embedded_payload, Some(data_start..data_start + 2));
        assert_eq!(param_bit(40), 0);
    }

    #[test]
    fn parse_xudt_segmented() {
        // Segmentation: F=1, class 1, 2 remaining, local reference 0x010203.
        let seg = [PARAM_SEGMENTATION, 4, 0xc2, 0x01, 0x02, 0x03, 0];
        let m = xudt(&seg);
        let (buf, r) = dissect(&m);
        let s = object(&buf, "segmentation");
        assert_eq!(*get(s, "first_segment"), FieldValue::U8(1));
        assert_eq!(*get(s, "class"), FieldValue::U8(1));
        assert_eq!(*get(s, "remaining_segments"), FieldValue::U8(2));
        assert_eq!(*get(s, "local_reference"), FieldValue::U32(0x030201));
        // One segment of a larger message is not dispatched.
        assert_eq!(r.next, DispatchHint::End);

        // A single-segment message (F=1, remaining=0) is dispatched.
        let seg = [PARAM_SEGMENTATION, 4, 0x80, 0, 0, 1, 0];
        let m = xudt(&seg);
        let (_, r) = dissect(&m);
        assert!(matches!(r.next, DispatchHint::BySccpSsn { .. }));

        // Wrong Segmentation length is kept as an unknown parameter.
        let seg = [PARAM_SEGMENTATION, 2, 0x80, 0, 0];
        let m = xudt(&seg);
        let (buf, _) = dissect(&m);
        assert!(!has_field(&buf, "segmentation"));
        assert!(has_field(&buf, "unknown_parameters"));
    }

    #[test]
    fn parse_malformed_optional_part() {
        // Length runs past the message: decoding stops without an error.
        let m = xudt(&[PARAM_IMPORTANCE, 5, 0x01]);
        let (buf, r) = dissect(&m);
        assert!(!has_field(&buf, "importance"));
        assert!(matches!(r.next, DispatchHint::BySccpSsn { .. }));
        // Missing end-of-optional-parameters octet is tolerated.
        let m = xudt(&[PARAM_IMPORTANCE, 1, 0x03]);
        let (buf, _) = dissect(&m);
        assert_eq!(*field(&buf, "importance"), FieldValue::U8(3));
        // Name without length octet.
        let m = xudt(&[PARAM_IMPORTANCE]);
        let (buf, _) = dissect(&m);
        assert!(!has_field(&buf, "importance"));
        // Optional pointer past the end.
        let mut data = xudt(&[PARAM_IMPORTANCE, 1, 0]);
        data[6] = 0xf0;
        let mut b = DissectBuffer::new();
        assert!(matches!(
            SccpDissector.dissect(&data, &mut b, 0),
            Err(PacketError::Truncated { .. })
        ));
    }

    #[test]
    fn parse_cr_optional_part() {
        // CR: SLR, class 2, pointer to called, pointer to optional part.
        let called = [0x42, 0x08]; // RI=SSN, SSN=8
        let mut m = vec![MSG_CR, 0, 0, 5, 0x02, 0x02, 0x04];
        m.push(called.len() as u8);
        m.extend_from_slice(&called);
        m.extend_from_slice(&[PARAM_CREDIT, 1, 0x03]);
        m.extend_from_slice(&[PARAM_CALLING_PARTY_ADDRESS, 2, 0x42, 0x07]);
        m.extend_from_slice(&[PARAM_DATA, 2, 0x01, 0x02]);
        m.extend_from_slice(&[PARAM_HOP_COUNTER, 1, 0x0a]);
        m.push(PARAM_END_OF_OPTIONAL);
        let (buf, r) = dissect(&m);
        assert_eq!(
            *field(&buf, "source_local_reference"),
            FieldValue::U32(0x050000)
        );
        assert_eq!(*field(&buf, "credit"), FieldValue::U8(3));
        assert_eq!(*field(&buf, "hop_counter"), FieldValue::U8(10));
        assert_eq!(
            *get(object(&buf, "calling_party_address"), "ssn"),
            FieldValue::U8(7)
        );
        assert_eq!(*field(&buf, "data"), FieldValue::Bytes(&[1, 2]));
        assert_eq!(
            r.next,
            DispatchHint::BySccpSsn {
                called: 8,
                calling: 7
            }
        );
        let start = m.len() - 1 - 3 - 2;
        assert_eq!(r.embedded_payload, Some(start..start + 2));

        // Optional called party address in CC and an empty optional address
        // (not decodable) kept as an unknown parameter.
        let m = [
            MSG_CC,
            0,
            0,
            1,
            0,
            0,
            2,
            0x02,
            0x01,
            PARAM_CALLED_PARTY_ADDRESS,
            2,
            0x42,
            0x06,
            PARAM_CALLING_PARTY_ADDRESS,
            0,
            0,
        ];
        let (buf, _) = dissect(&m);
        assert_eq!(
            *get(object(&buf, "called_party_address"), "ssn"),
            FieldValue::U8(6)
        );
        assert!(has_field(&buf, "unknown_parameters"));
    }

    #[test]
    fn parse_ludt() {
        // LUDT: class, hop counter, four two-octet pointers (LSB first).
        let called = [0x42, 0x06];
        let calling = [0x42, 0x07];
        let long_data = [0x62u8; 300];
        let mut m = vec![MSG_LUDT, 0x00, 0x05];
        // Pointer n starts at octet 3 + 2n; parameters start at octet 11.
        let called_at = 11usize;
        let calling_at = called_at + 1 + called.len();
        let data_at = calling_at + 1 + calling.len();
        for (i, at) in [called_at, calling_at, data_at].into_iter().enumerate() {
            // Counted from the pointer's most significant (second) octet.
            let msb_at = 3 + 2 * i + 1;
            m.extend_from_slice(&((at - msb_at) as u16).to_le_bytes());
        }
        m.extend_from_slice(&[0, 0]); // no optional part
        m.push(called.len() as u8);
        m.extend_from_slice(&called);
        m.push(calling.len() as u8);
        m.extend_from_slice(&calling);
        m.extend_from_slice(&(long_data.len() as u16).to_le_bytes());
        m.extend_from_slice(&long_data);
        let (buf, r) = dissect(&m);
        assert_eq!(*field(&buf, "data"), FieldValue::Bytes(&long_data));
        assert_eq!(*field(&buf, "hop_counter"), FieldValue::U8(5));
        assert_eq!(r.embedded_payload, Some(data_at + 2..m.len()));

        // LUDTS carries a return cause instead of the protocol class.
        m[0] = MSG_LUDTS;
        m[1] = 0x0d;
        let (buf, _) = dissect(&m);
        assert_eq!(*field(&buf, "return_cause"), FieldValue::U8(0x0d));

        // Long data length beyond the message.
        m.truncate(m.len() - 1);
        let mut b = DissectBuffer::new();
        assert!(matches!(
            SccpDissector.dissect(&m, &mut b, 0),
            Err(PacketError::Truncated { .. })
        ));
    }

    #[test]
    fn empty_data_is_not_dispatched() {
        let data = udt(0x00, CALLED_GT, CALLING_GT, &[]);
        let (_, r) = dissect(&data);
        assert_eq!(r.next, DispatchHint::End);
        assert_eq!(r.embedded_payload, None);
    }

    #[test]
    fn dissect_at_nonzero_offset() {
        let data = udt(0x00, CALLED_GT, CALLING_GT, &[1, 2]);
        let mut buf = DissectBuffer::new();
        let r = SccpDissector.dissect(&data, &mut buf, 40).unwrap();
        assert_eq!(buf.layers()[0].range, 40..40 + data.len());
        assert_eq!(
            r.embedded_payload,
            Some(40 + data.len() - 2..40 + data.len())
        );
    }

    #[test]
    fn truncated_fixed_part() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            SccpDissector.dissect(&[], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 1,
                actual: 0
            })
        );
        // UDT needs the class and three pointers.
        assert_eq!(
            SccpDissector.dissect(&[MSG_UDT, 0, 3], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 5,
                actual: 3
            })
        );
        assert_eq!(
            SccpDissector.dissect(&[MSG_RLC, 0, 0, 1], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 7,
                actual: 4
            })
        );
    }

    #[test]
    fn truncated_variable_parameter() {
        let data = udt(0x00, CALLED_GT, CALLING_GT, &[1, 2, 3]);
        let mut buf = DissectBuffer::new();
        let short = &data[..data.len() - 1];
        assert_eq!(
            SccpDissector.dissect(short, &mut buf, 0),
            Err(PacketError::Truncated {
                expected: data.len(),
                actual: data.len() - 1
            })
        );
        // Pointer to a parameter past the end (length octet missing).
        let mut data = udt(0x00, CALLED_GT, CALLING_GT, &[1]);
        data[4] = 0xf0;
        assert!(matches!(
            SccpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::Truncated { .. })
        ));
    }

    #[test]
    fn reject_zero_mandatory_pointer() {
        let mut data = udt(0x00, CALLED_GT, CALLING_GT, &[1]);
        data[3] = 0;
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            SccpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn reject_empty_address() {
        let data = udt(0x00, &[], CALLING_GT, &[1]);
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            SccpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
        assert!(buf.layers().is_empty());
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn reject_unknown_message_type() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            SccpDissector.dissect(&[0x15, 0, 0], &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "message_type",
                value: 0x15
            })
        );
    }

    #[test]
    fn name_tables() {
        for t in 1..=0x14 {
            assert!(message_type_name(t).is_some(), "{t}");
            assert!(message_format(t).is_some(), "{t}");
        }
        assert_eq!(message_type_name(0), None);
        assert_eq!(message_type_name(0x15), None);
        assert!(message_format(0x15).is_none());
        assert_eq!(protocol_class_name(3), Some("class 3"));
        assert_eq!(protocol_class_name(4), None);
        assert_eq!(message_handling_name(0), Some("no special options"));
        assert_eq!(message_handling_name(1), None);
        assert_eq!(release_cause_name(0x10), Some("SCCP failure"));
        assert_eq!(release_cause_name(0x0e), None);
        assert_eq!(return_cause_name(0x0e), Some("segmentation failure"));
        assert_eq!(return_cause_name(0x0f), None);
        assert_eq!(reset_cause_name(0x0c), Some("unqualified"));
        assert_eq!(reset_cause_name(0x0b), None);
        assert_eq!(error_cause_name(0x04), Some("unqualified"));
        assert_eq!(error_cause_name(0x05), None);
        assert_eq!(refusal_cause_name(0x13), Some("unequipped user"));
        assert_eq!(refusal_cause_name(0x0e), None);
        assert!(global_title_indicator_name(4).is_some());
        assert_eq!(global_title_indicator_name(5), None);
        assert_eq!(routing_indicator_name(1), Some("Route on SSN"));
        assert_eq!(routing_indicator_name(2), None);
        assert_eq!(ssn_name(6), Some("home location register (HLR)"));
        assert_eq!(ssn_name(0x0c), None);
        assert_eq!(nature_of_address_name(4), Some("international number"));
        assert_eq!(nature_of_address_name(5), None);
        assert_eq!(
            numbering_plan_name(7),
            Some("ISDN/mobile numbering plan (ITU-T E.214)")
        );
        assert_eq!(numbering_plan_name(8), None);
        assert_eq!(encoding_scheme_name(3), Some("national specific"));
        assert_eq!(encoding_scheme_name(4), None);
    }

    #[test]
    fn display_functions() {
        let data = udt(0x80, CALLED_GT, CALLING_GT, &[1]);
        let (buf, _) = dissect(&data);
        let mut named = 0;
        for f in buf.fields() {
            if let Some(display) = f.descriptor.display_fn {
                if display(&f.value, &[]).is_some() {
                    named += 1;
                }
                assert_eq!(display(&FieldValue::U16(0), &[]), None);
            }
        }
        // message_type, protocol_class, message_handling, and per address
        // routing_indicator, global_title_indicator, ssn, numbering_plan,
        // encoding_scheme, nature_of_address.
        assert_eq!(named, 3 + 2 * 6);

        let mut named = 0;
        for bytes in [
            &[MSG_CREF, 0, 0, 1, 0x00, 0x00][..],
            &[MSG_RLSD, 0, 0, 1, 0, 0, 2, 0x00, 0x00],
            &[MSG_RSR, 0, 0, 1, 0, 0, 2, 0x00, 0x00],
            &[MSG_ERR, 0, 0, 1, 0x00, 0x00],
        ] {
            let (buf, _) = dissect(bytes);
            for f in buf.fields() {
                if let Some(display) = f.descriptor.display_fn {
                    assert!(display(&f.value, &[]).is_some());
                    assert_eq!(display(&FieldValue::U16(0), &[]), None);
                    named += 1;
                }
            }
        }
        assert_eq!(named, 8);
        let mut data = udt(0x00, CALLED_GT, CALLING_GT, &[1]);
        data[0] = MSG_UDTS;
        let (buf, _) = dissect(&data);
        let f = buf.field_by_name(&buf.layers()[0], "return_cause").unwrap();
        assert_eq!(
            (f.descriptor.display_fn.unwrap())(&FieldValue::U16(0), &[]),
            None
        );
    }

    /// Calls every `display_fn` in the descriptor tree with values of the
    /// descriptor's type (and of a mismatched type), so that no display
    /// closure is left unexercised.
    fn exercise_display_fns(fds: &'static [FieldDescriptor], depth: usize) -> usize {
        let mut calls = 0;
        for fd in fds {
            if let Some(display) = fd.display_fn {
                for v in 0u16..=0x30 {
                    let value = match fd.field_type {
                        FieldType::U8 => FieldValue::U8(v as u8),
                        FieldType::U16 => FieldValue::U16(v),
                        FieldType::U32 => FieldValue::U32(u32::from(v)),
                        FieldType::Object => FieldValue::Object(0..0),
                        _ => FieldValue::Bytes(&[]),
                    };
                    let _ = display(&value, &[]);
                    calls += 1;
                }
                assert_eq!(display(&FieldValue::Bytes(&[]), &[]), None, "{}", fd.name);
            }
            if let Some(children) = fd.children {
                if depth < 4 {
                    calls += exercise_display_fns(children, depth + 1);
                }
            }
        }
        calls
    }

    /// Number of codes in `0..=max` that `name` knows.
    fn known<T: TryFrom<u32> + Copy>(max: u32, name: impl Fn(T) -> Option<&'static str>) -> usize {
        (0..=max)
            .filter_map(|c| T::try_from(c).ok())
            .filter(|c| name(*c).is_some())
            .count()
    }

    #[test]
    fn display_fns_and_name_table_sizes() {
        assert!(exercise_display_fns(FIELD_DESCRIPTORS, 0) > 0);
        assert_eq!(known(255, message_type_name), 20);
        assert_eq!(known(255, protocol_class_name), 4);
        assert_eq!(known(255, message_handling_name), 2);
        assert_eq!(known(255, release_cause_name), 16);
        assert_eq!(known(255, return_cause_name), 15);
        assert_eq!(known(255, reset_cause_name), 12);
        assert_eq!(known(255, error_cause_name), 5);
        assert_eq!(known(255, refusal_cause_name), 19);
        assert_eq!(known(255, global_title_indicator_name), 5);
        assert_eq!(known(255, routing_indicator_name), 2);
        assert_eq!(known(255, ssn_name), 13);
        assert_eq!(known(255, nature_of_address_name), 5);
        assert_eq!(known(255, numbering_plan_name), 9);
        assert_eq!(known(255, encoding_scheme_name), 4);
        assert_eq!(local_reference(&[1, 2]), 0);
    }

    #[test]
    fn field_descriptor_layout() {
        assert_eq!(
            FIELD_DESCRIPTORS[FD_UNKNOWN_PARAMETERS].name,
            "unknown_parameters"
        );
        assert_eq!(FIELD_DESCRIPTORS.len(), FD_UNKNOWN_PARAMETERS + 1);
        assert_eq!(
            ADDRESS_FIELDS[AFD_ADDRESS_INFORMATION].name,
            "address_information"
        );
        assert_eq!(ADDRESS_FIELDS.len(), AFD_ADDRESS_INFORMATION + 1);
        assert_eq!(
            SEGMENTATION_FIELDS[SFD_LOCAL_REFERENCE].name,
            "local_reference"
        );
        assert_eq!(UNKNOWN_PARAMETER_FIELDS[UFD_VALUE].name, "value");
        let d = SccpDissector;
        assert_eq!(d.name(), "Signalling Connection Control Part");
        assert_eq!(d.short_name(), "SCCP");
        assert_eq!(d.references()[0].id, "ITU-T Q.713");
        assert_eq!(d.layer(), Some(ProtocolLayer::Application));
    }
}
