//! M3UA (SS7 MTP3-User Adaptation Layer) dissector.
//!
//! Decodes the Common Message Header, every message class defined by
//! RFC 4666 (MGMT, Transfer, SSNM, ASPSM, ASPTM and RKM) and their
//! parameters. The User Protocol Data of a DATA message is handed to the
//! next dissector by its MTP3 Service Indicator
//! ([`DispatchHint::ByMtp3ServiceIndicator`]), e.g. `3` for SCCP.
//!
//! ## References
//! - RFC 4666 (M3UA; obsoletes RFC 3332): <https://www.rfc-editor.org/rfc/rfc4666>
//! - RFC 4666 errata (4475: Service Indicators are padded to 32-bit
//!   alignment): <https://www.rfc-editor.org/errata/rfc4666>
//! - IANA "Signaling User Adaptation Layer Assignments" (message classes):
//!   <https://www.iana.org/assignments/sigtran-adapt/>
//! - ITU-T Q.704 (07/96), clause 14.2 (Service Indicator and Network
//!   Indicator codes): <https://www.itu.int/rec/T-REC-Q.704>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{Field, FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24, read_be_u32};

/// Size of the Common Message Header.
/// RFC 4666, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.1>
const HEADER_SIZE: usize = 8;

/// Size of a parameter's Tag and Length fields.
/// RFC 4666, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.2>
const PARAM_HEADER_SIZE: usize = 4;

/// The only defined protocol version, "1 Release 1.0".
/// RFC 4666, Section 3.1.1 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.1.1>
const M3UA_VERSION: u8 = 1;

/// Size of the fixed part of the Protocol Data parameter value (OPC, DPC,
/// SI, NI, MP, SLS). RFC 4666, Section 3.3.1 —
/// <https://www.rfc-editor.org/rfc/rfc4666#section-3.3.1>
const PROTOCOL_DATA_FIXED_SIZE: usize = 12;

/// Message Class "Transfer Messages" and Message Type "Payload Data (DATA)".
/// RFC 4666, Section 3.1.2 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.1.2>
const CLASS_TRANSFER: u8 = 1;
const TYPE_DATA: u8 = 1;

// Parameter Tags. RFC 4666, Section 3.2 —
// <https://www.rfc-editor.org/rfc/rfc4666#section-3.2>
const TAG_INFO_STRING: u16 = 0x0004;
const TAG_ROUTING_CONTEXT: u16 = 0x0006;
const TAG_DIAGNOSTIC_INFORMATION: u16 = 0x0007;
const TAG_HEARTBEAT_DATA: u16 = 0x0009;
const TAG_TRAFFIC_MODE_TYPE: u16 = 0x000b;
const TAG_ERROR_CODE: u16 = 0x000c;
const TAG_STATUS: u16 = 0x000d;
const TAG_ASP_IDENTIFIER: u16 = 0x0011;
const TAG_AFFECTED_POINT_CODE: u16 = 0x0012;
const TAG_CORRELATION_ID: u16 = 0x0013;
const TAG_NETWORK_APPEARANCE: u16 = 0x0200;
const TAG_USER_CAUSE: u16 = 0x0204;
const TAG_CONGESTION_INDICATIONS: u16 = 0x0205;
const TAG_CONCERNED_DESTINATION: u16 = 0x0206;
const TAG_ROUTING_KEY: u16 = 0x0207;
const TAG_REGISTRATION_RESULT: u16 = 0x0208;
const TAG_DEREGISTRATION_RESULT: u16 = 0x0209;
const TAG_LOCAL_RK_IDENTIFIER: u16 = 0x020a;
const TAG_DESTINATION_POINT_CODE: u16 = 0x020b;
const TAG_SERVICE_INDICATORS: u16 = 0x020c;
const TAG_ORIGINATING_POINT_CODE_LIST: u16 = 0x020e;
const TAG_PROTOCOL_DATA: u16 = 0x0210;
const TAG_REGISTRATION_STATUS: u16 = 0x0212;
const TAG_DEREGISTRATION_STATUS: u16 = 0x0213;

/// Returns the name of a Message Class.
///
/// RFC 4666, Section 3.1.2 —
/// <https://www.rfc-editor.org/rfc/rfc4666#section-3.1.2>; classes 5-8 and
/// 10-12 ("Reserved for Other SIGTRAN Adaptation Layers" in RFC 4666) are
/// named from the IANA "Signaling User Adaptation Layer Assignments"
/// registry — <https://www.iana.org/assignments/sigtran-adapt/>.
fn message_class_name(class: u8) -> Option<&'static str> {
    Some(match class {
        0 => "Management (MGMT) Messages",
        1 => "Transfer Messages",
        2 => "SS7 Signalling Network Management (SSNM) Messages",
        3 => "ASP State Maintenance (ASPSM) Messages",
        4 => "ASP Traffic Maintenance (ASPTM) Messages",
        5 => "Q.921/Q.931 Boundary Primitives Transport (QPTM) Messages",
        6 => "MTP2 User Adaptation (MAUP) Messages",
        7 => "Connectionless Messages",
        8 => "Connection-Oriented Messages",
        9 => "Routing Key Management (RKM) Messages",
        10 => "Interface Identifier Management (IIM) Messages",
        11 => "M2PA Messages",
        12 => "Security Messages",
        _ => return None,
    })
}

/// Returns the name of a Message Type within an M3UA Message Class.
///
/// RFC 4666, Section 3.1.2 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.1.2>
fn message_type_name(class: u8, msg_type: u8) -> Option<&'static str> {
    Some(match (class, msg_type) {
        // Management (MGMT) Messages (see Section 3.8)
        (0, 0) => "Error (ERR)",
        (0, 1) => "Notify (NTFY)",
        // Transfer Messages (see Section 3.3)
        (1, 1) => "Payload Data (DATA)",
        // SS7 Signalling Network Management (SSNM) Messages (see Section 3.4)
        (2, 1) => "Destination Unavailable (DUNA)",
        (2, 2) => "Destination Available (DAVA)",
        (2, 3) => "Destination State Audit (DAUD)",
        (2, 4) => "Signalling Congestion (SCON)",
        (2, 5) => "Destination User Part Unavailable (DUPU)",
        (2, 6) => "Destination Restricted (DRST)",
        // ASP State Maintenance (ASPSM) Messages (see Section 3.5)
        (3, 1) => "ASP Up (ASPUP)",
        (3, 2) => "ASP Down (ASPDN)",
        (3, 3) => "Heartbeat (BEAT)",
        (3, 4) => "ASP Up Acknowledgement (ASPUP ACK)",
        (3, 5) => "ASP Down Acknowledgement (ASPDN ACK)",
        (3, 6) => "Heartbeat Acknowledgement (BEAT ACK)",
        // ASP Traffic Maintenance (ASPTM) Messages (see Section 3.7)
        (4, 1) => "ASP Active (ASPAC)",
        (4, 2) => "ASP Inactive (ASPIA)",
        (4, 3) => "ASP Active Acknowledgement (ASPAC ACK)",
        (4, 4) => "ASP Inactive Acknowledgement (ASPIA ACK)",
        // Routing Key Management (RKM) Messages (see Section 3.6)
        (9, 1) => "Registration Request (REG REQ)",
        (9, 2) => "Registration Response (REG RSP)",
        (9, 3) => "Deregistration Request (DEREG REQ)",
        (9, 4) => "Deregistration Response (DEREG RSP)",
        _ => return None,
    })
}

/// Returns the name of a Parameter Tag.
///
/// RFC 4666, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.2>
fn parameter_tag_name(tag: u16) -> Option<&'static str> {
    Some(match tag {
        TAG_INFO_STRING => "INFO String",
        TAG_ROUTING_CONTEXT => "Routing Context",
        TAG_DIAGNOSTIC_INFORMATION => "Diagnostic Information",
        TAG_HEARTBEAT_DATA => "Heartbeat Data",
        TAG_TRAFFIC_MODE_TYPE => "Traffic Mode Type",
        TAG_ERROR_CODE => "Error Code",
        TAG_STATUS => "Status",
        TAG_ASP_IDENTIFIER => "ASP Identifier",
        TAG_AFFECTED_POINT_CODE => "Affected Point Code",
        TAG_CORRELATION_ID => "Correlation ID",
        TAG_NETWORK_APPEARANCE => "Network Appearance",
        TAG_USER_CAUSE => "User/Cause",
        TAG_CONGESTION_INDICATIONS => "Congestion Indications",
        TAG_CONCERNED_DESTINATION => "Concerned Destination",
        TAG_ROUTING_KEY => "Routing Key",
        TAG_REGISTRATION_RESULT => "Registration Result",
        TAG_DEREGISTRATION_RESULT => "Deregistration Result",
        TAG_LOCAL_RK_IDENTIFIER => "Local Routing Key Identifier",
        TAG_DESTINATION_POINT_CODE => "Destination Point Code",
        TAG_SERVICE_INDICATORS => "Service Indicators",
        TAG_ORIGINATING_POINT_CODE_LIST => "Originating Point Code List",
        TAG_PROTOCOL_DATA => "Protocol Data",
        TAG_REGISTRATION_STATUS => "Registration Status",
        TAG_DEREGISTRATION_STATUS => "Deregistration Status",
        _ => return None,
    })
}

/// Returns the name of a Service Indicator (MTP3-User Identity).
///
/// ITU-T Q.704 (07/96), clause 14.2.1 — <https://www.itu.int/rec/T-REC-Q.704>
/// for codes 0-10; RFC 4666, Section 3.4.5 —
/// <https://www.rfc-editor.org/rfc/rfc4666#section-3.4.5> — for codes 12-14.
fn service_indicator_name(si: u8) -> Option<&'static str> {
    Some(match si {
        0 => "Signalling network management messages",
        1 => "Signalling network testing and maintenance messages",
        3 => "SCCP",
        4 => "Telephone User Part",
        5 => "ISDN User Part",
        6 => "Data User Part (call and circuit-related messages)",
        7 => "Data User Part (facility registration and cancellation messages)",
        8 => "Reserved for MTP Testing User Part",
        9 => "Broadband ISDN User Part",
        10 => "Satellite ISDN User Part",
        12 => "AAL type 2 Signalling",
        13 => "Bearer Independent Call Control (BICC)",
        14 => "Gateway Control Protocol",
        _ => return None,
    })
}

/// Returns the name of a Network Indicator.
///
/// ITU-T Q.704 (07/96), clause 14.2.2 — <https://www.itu.int/rec/T-REC-Q.704>
fn network_indicator_name(ni: u8) -> Option<&'static str> {
    Some(match ni {
        0 => "International network",
        1 => "Spare (for international use only)",
        2 => "National network",
        3 => "Reserved for national use",
        _ => return None,
    })
}

/// Returns the name of a Traffic Mode Type.
///
/// RFC 4666, Section 3.7.1 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.7.1>
fn traffic_mode_type_name(mode: u32) -> Option<&'static str> {
    Some(match mode {
        1 => "Override",
        2 => "Loadshare",
        3 => "Broadcast",
        _ => return None,
    })
}

/// Returns the name of an Error Code.
///
/// RFC 4666, Section 3.8.1 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.8.1>
fn error_code_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0x01 => "Invalid Version",
        0x03 => "Unsupported Message Class",
        0x04 => "Unsupported Message Type",
        0x05 => "Unsupported Traffic Mode Type",
        0x06 => "Unexpected Message",
        0x07 => "Protocol Error",
        0x09 => "Invalid Stream Identifier",
        0x0d => "Refused - Management Blocking",
        0x0e => "ASP Identifier Required",
        0x0f => "Invalid ASP Identifier",
        0x11 => "Invalid Parameter Value",
        0x12 => "Parameter Field Error",
        0x13 => "Unexpected Parameter",
        0x14 => "Destination Status Unknown",
        0x15 => "Invalid Network Appearance",
        0x16 => "Missing Parameter",
        0x19 => "Invalid Routing Context",
        0x1a => "No Configured AS for ASP",
        0x02 | 0x08 | 0x0a | 0x0b | 0x0c | 0x10 | 0x17 | 0x18 => "Not Used in M3UA",
        _ => return None,
    })
}

/// Returns the name of a Notify Status Type.
///
/// RFC 4666, Section 3.8.2 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.8.2>
fn status_type_name(status_type: u16) -> Option<&'static str> {
    Some(match status_type {
        1 => "Application Server State Change (AS-State_Change)",
        2 => "Other",
        _ => return None,
    })
}

/// Returns the name of a Notify Status Information value, which depends on
/// the Status Type.
///
/// RFC 4666, Section 3.8.2 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.8.2>
fn status_information_name(status_type: u16, info: u16) -> Option<&'static str> {
    Some(match (status_type, info) {
        (1, 1) => "Reserved",
        (1, 2) => "Application Server Inactive (AS-INACTIVE)",
        (1, 3) => "Application Server Active (AS-ACTIVE)",
        (1, 4) => "Application Server Pending (AS-PENDING)",
        (2, 1) => "Insufficient ASP Resources Active in AS",
        (2, 2) => "Alternate ASP Active",
        (2, 3) => "ASP Failure",
        _ => return None,
    })
}

/// Returns the name of an Unavailability Cause.
///
/// RFC 4666, Section 3.4.5 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.4.5>
fn unavailability_cause_name(cause: u16) -> Option<&'static str> {
    Some(match cause {
        0 => "Unknown",
        1 => "Unequipped Remote User",
        2 => "Inaccessible Remote User",
        _ => return None,
    })
}

/// Returns the name of a Congestion Level.
///
/// RFC 4666, Section 3.4.4 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.4.4>
fn congestion_level_name(level: u8) -> Option<&'static str> {
    Some(match level {
        0 => "No Congestion or Undefined",
        1 => "Congestion Level 1",
        2 => "Congestion Level 2",
        3 => "Congestion Level 3",
        _ => return None,
    })
}

/// Returns the name of a Registration Status.
///
/// RFC 4666, Section 3.6.2 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.6.2>
fn registration_status_name(status: u32) -> Option<&'static str> {
    Some(match status {
        0 => "Successfully Registered",
        1 => "Error - Unknown",
        2 => "Error - Invalid DPC",
        3 => "Error - Invalid Network Appearance",
        4 => "Error - Invalid Routing Key",
        5 => "Error - Permission Denied",
        6 => "Error - Cannot Support Unique Routing",
        7 => "Error - Routing Key not Currently Provisioned",
        8 => "Error - Insufficient Resources",
        9 => "Error - Unsupported RK parameter Field",
        10 => "Error - Unsupported/Invalid Traffic Handling Mode",
        11 => "Error - Routing Key Change Refused",
        12 => "Error - Routing Key Already Registered",
        _ => return None,
    })
}

/// Returns the name of a Deregistration Status.
///
/// RFC 4666, Section 3.6.4 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.6.4>
fn deregistration_status_name(status: u32) -> Option<&'static str> {
    Some(match status {
        0 => "Successfully Deregistered",
        1 => "Error - Unknown",
        2 => "Error - Invalid Routing Context",
        3 => "Error - Permission Denied",
        4 => "Error - Not Registered",
        5 => "Error - ASP Currently Active for Routing Context",
        _ => return None,
    })
}

/// Returns the U8 value of the named sibling field, if present.
fn sibling_u8(siblings: &[Field<'_>], name: &str) -> Option<u8> {
    siblings.iter().find_map(|f| match (f.name(), &f.value) {
        (n, FieldValue::U8(v)) if n == name => Some(*v),
        _ => None,
    })
}

/// Returns the U16 value of the named sibling field, if present.
fn sibling_u16(siblings: &[Field<'_>], name: &str) -> Option<u16> {
    siblings.iter().find_map(|f| match (f.name(), &f.value) {
        (n, FieldValue::U16(v)) if n == name => Some(*v),
        _ => None,
    })
}

// Indices into `FIELD_DESCRIPTORS`.
const FD_VERSION: usize = 0;
const FD_RESERVED: usize = 1;
const FD_MESSAGE_CLASS: usize = 2;
const FD_MESSAGE_TYPE: usize = 3;
const FD_LENGTH: usize = 4;
const FD_PARAMETERS: usize = 5;

// Indices into `PARAM_FIELDS`.
const PFD_TAG: usize = 0;
const PFD_LENGTH: usize = 1;
const PFD_VALUE: usize = 2;
const PFD_INFO_STRING: usize = 3;
const PFD_ROUTING_CONTEXTS: usize = 4;
const PFD_TRAFFIC_MODE_TYPE: usize = 5;
const PFD_ERROR_CODE: usize = 6;
const PFD_STATUS_TYPE: usize = 7;
const PFD_STATUS_INFORMATION: usize = 8;
const PFD_ASP_IDENTIFIER: usize = 9;
const PFD_POINT_CODES: usize = 10;
const PFD_CORRELATION_ID: usize = 11;
const PFD_NETWORK_APPEARANCE: usize = 12;
const PFD_CAUSE: usize = 13;
const PFD_USER: usize = 14;
const PFD_CONGESTION_LEVEL: usize = 15;
const PFD_CONCERNED_DPC: usize = 16;
const PFD_MASK: usize = 17;
const PFD_POINT_CODE: usize = 18;
const PFD_LOCAL_RK_IDENTIFIER: usize = 19;
const PFD_SERVICE_INDICATORS: usize = 20;
const PFD_REGISTRATION_STATUS: usize = 21;
const PFD_DEREGISTRATION_STATUS: usize = 22;
const PFD_PROTOCOL_DATA: usize = 23;
/// Nested parameters of a Routing Key, Registration Result or
/// Deregistration Result. Must stay last: `SUB_PARAM_FIELDS` is every entry
/// before it.
const PFD_PARAMETERS: usize = 24;

// Indices into `POINT_CODE_FIELDS`.
const PCFD_MASK: usize = 0;
const PCFD_POINT_CODE: usize = 1;

// Indices into `PROTOCOL_DATA_FIELDS`.
const PDFD_OPC: usize = 0;
const PDFD_DPC: usize = 1;
const PDFD_SI: usize = 2;
const PDFD_NI: usize = 3;
const PDFD_MP: usize = 4;
const PDFD_SLS: usize = 5;
const PDFD_DATA: usize = 6;

/// Children of a Mask / Point Code entry (Affected Point Code, Originating
/// Point Code List). RFC 4666, Section 3.4.1 —
/// <https://www.rfc-editor.org/rfc/rfc4666#section-3.4.1>
static POINT_CODE_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("mask", "Mask", FieldType::U8),
    FieldDescriptor::new("point_code", "Point Code", FieldType::U32),
];

/// Element descriptor of the `point_codes` array.
static FD_POINT_CODE_ENTRY: FieldDescriptor =
    FieldDescriptor::new("point_code", "Point Code", FieldType::Object)
        .with_children(POINT_CODE_FIELDS);

/// Element descriptor of the `routing_contexts` array.
static FD_ROUTING_CONTEXT: FieldDescriptor =
    FieldDescriptor::new("routing_context", "Routing Context", FieldType::U32);

/// Element descriptor of the `service_indicators` array.
static FD_SERVICE_INDICATOR: FieldDescriptor =
    FieldDescriptor::new("service_indicator", "Service Indicator", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(si) => service_indicator_name(*si),
            _ => None,
        },
    );

/// Children of the Protocol Data parameter.
/// RFC 4666, Section 3.3.1 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.3.1>
static PROTOCOL_DATA_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("opc", "Originating Point Code", FieldType::U32),
    FieldDescriptor::new("dpc", "Destination Point Code", FieldType::U32),
    FieldDescriptor::new("si", "Service Indicator", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(si) => service_indicator_name(*si),
            _ => None,
        },
    ),
    FieldDescriptor::new("ni", "Network Indicator", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(ni) => network_indicator_name(*ni),
            _ => None,
        },
    ),
    FieldDescriptor::new("mp", "Message Priority", FieldType::U8),
    FieldDescriptor::new("sls", "Signalling Link Selection", FieldType::U8),
    FieldDescriptor::new("data", "User Protocol Data", FieldType::Bytes),
];

/// Children of a parameter Object. Every child except `tag` and `length`
/// depends on the Parameter Tag and is therefore optional.
///
/// RFC 4666, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.2>
static PARAM_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("tag", "Parameter Tag", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(t) => parameter_tag_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Parameter Length", FieldType::U16),
    // Opaque (Diagnostic Information, Heartbeat Data), unknown or
    // malformed parameter values.
    FieldDescriptor::new("value", "Parameter Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("info_string", "INFO String", FieldType::Str).optional(),
    FieldDescriptor::new("routing_contexts", "Routing Contexts", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_ROUTING_CONTEXT)),
    FieldDescriptor::new("traffic_mode_type", "Traffic Mode Type", FieldType::U32)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U32(m) => traffic_mode_type_name(*m),
            _ => None,
        }),
    FieldDescriptor::new("error_code", "Error Code", FieldType::U32)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U32(c) => error_code_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("status_type", "Status Type", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(t) => status_type_name(*t),
            _ => None,
        }),
    FieldDescriptor::new("status_information", "Status Information", FieldType::U16)
        .optional()
        .with_display_fn(|v, siblings| match v {
            FieldValue::U16(i) => {
                status_information_name(sibling_u16(siblings, "status_type")?, *i)
            }
            _ => None,
        }),
    FieldDescriptor::new("asp_identifier", "ASP Identifier", FieldType::U32).optional(),
    FieldDescriptor::new("point_codes", "Point Codes", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_POINT_CODE_ENTRY)),
    FieldDescriptor::new("correlation_id", "Correlation ID", FieldType::U32).optional(),
    FieldDescriptor::new("network_appearance", "Network Appearance", FieldType::U32).optional(),
    FieldDescriptor::new("cause", "Unavailability Cause", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(c) => unavailability_cause_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("user", "MTP3-User Identity", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(u) => u8::try_from(*u).ok().and_then(service_indicator_name),
            _ => None,
        }),
    FieldDescriptor::new("congestion_level", "Congestion Level", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(l) => congestion_level_name(*l),
            _ => None,
        }),
    FieldDescriptor::new("concerned_dpc", "Concerned DPC", FieldType::U32).optional(),
    FieldDescriptor::new("mask", "Mask", FieldType::U8).optional(),
    FieldDescriptor::new("point_code", "Point Code", FieldType::U32).optional(),
    FieldDescriptor::new("local_rk_identifier", "Local-RK-Identifier", FieldType::U32).optional(),
    FieldDescriptor::new("service_indicators", "Service Indicators", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_SERVICE_INDICATOR)),
    FieldDescriptor::new("registration_status", "Registration Status", FieldType::U32)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U32(s) => registration_status_name(*s),
            _ => None,
        }),
    FieldDescriptor::new(
        "deregistration_status",
        "Deregistration Status",
        FieldType::U32,
    )
    .optional()
    .with_display_fn(|v, _| match v {
        FieldValue::U32(s) => deregistration_status_name(*s),
        _ => None,
    }),
    FieldDescriptor::new("protocol_data", "Protocol Data", FieldType::Object)
        .optional()
        .with_children(PROTOCOL_DATA_FIELDS),
    FieldDescriptor::new("parameters", "Parameters", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_SUB_PARAMETER)),
];

/// Children of a parameter nested in a Routing Key, Registration Result or
/// Deregistration Result: every entry of `PARAM_FIELDS` except the nested
/// `parameters` array itself.
static SUB_PARAM_FIELDS: &[FieldDescriptor] = PARAM_FIELDS.split_at(PFD_PARAMETERS).0;

/// Resolves a parameter Object's label to its tag name.
fn parameter_display(v: &FieldValue<'_>, children: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::Object(_) => sibling_u16(children, "tag").and_then(parameter_tag_name),
        _ => None,
    }
}

/// Element descriptor of the top-level `parameters` array.
static FD_PARAMETER: FieldDescriptor =
    FieldDescriptor::new("parameter", "Parameter", FieldType::Object)
        .with_display_fn(parameter_display)
        .with_children(PARAM_FIELDS);

/// Element descriptor of a nested `parameters` array.
static FD_SUB_PARAMETER: FieldDescriptor =
    FieldDescriptor::new("parameter", "Parameter", FieldType::Object)
        .with_display_fn(parameter_display)
        .with_children(SUB_PARAM_FIELDS);

/// Field descriptors for the M3UA layer.
/// RFC 4666, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.1>
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U8),
    FieldDescriptor::new("message_class", "Message Class", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(c) => message_class_name(*c),
            _ => None,
        },
    ),
    FieldDescriptor::new("message_type", "Message Type", FieldType::U8).with_display_fn(
        |v, siblings| match v {
            FieldValue::U8(t) => message_type_name(sibling_u8(siblings, "message_class")?, *t),
            _ => None,
        },
    ),
    FieldDescriptor::new("length", "Message Length", FieldType::U32),
    FieldDescriptor::new("parameters", "Parameters", FieldType::Array)
        .with_children(core::slice::from_ref(&FD_PARAMETER)),
];

/// Specification references for the M3UA dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 4666",
        "Signaling System 7 (SS7) Message Transfer Part 3 (MTP3) - User Adaptation Layer (M3UA)",
        "https://www.rfc-editor.org/rfc/rfc4666",
    ),
    SpecReference::new(
        "ITU-T Q.704",
        "Signalling network functions and messages",
        "https://www.itu.int/rec/T-REC-Q.704",
    ),
];

/// M3UA dissector.
pub struct M3uaDissector;

impl Dissector for M3uaDissector {
    fn name(&self) -> &'static str {
        "MTP3 User Adaptation Layer"
    }

    fn short_name(&self) -> &'static str {
        "M3UA"
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
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 4666, Section 3.1.1 — "1      Release 1.0" is the only
        // defined version — https://www.rfc-editor.org/rfc/rfc4666#section-3.1.1
        let version = data[0];
        if version != M3UA_VERSION {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }
        let reserved = data[1];
        let message_class = data[2];
        let message_type = data[3];
        // RFC 4666, Section 3.1.4 — "The Message Length defines the length
        // of the message in octets, including the Common Header." —
        // https://www.rfc-editor.org/rfc/rfc4666#section-3.1.4
        let length = read_be_u32(data, 4)?;
        let msg_len = length as usize;
        if msg_len < HEADER_SIZE {
            return Err(PacketError::InvalidHeader(
                "M3UA Message Length is shorter than the Common Header",
            ));
        }
        if msg_len > data.len() {
            return Err(PacketError::Truncated {
                expected: msg_len,
                actual: data.len(),
            });
        }

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + msg_len,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_RESERVED],
            FieldValue::U8(reserved),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_CLASS],
            FieldValue::U8(message_class),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_TYPE],
            FieldValue::U8(message_type),
            offset + 3..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LENGTH],
            FieldValue::U32(length),
            offset + 4..offset + 8,
        );

        let array_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_PARAMETERS],
            FieldValue::Array(0..0),
            offset + HEADER_SIZE..offset + msg_len,
        );
        let user_data = push_parameters(
            &data[HEADER_SIZE..msg_len],
            offset + HEADER_SIZE,
            false,
            buf,
        );
        buf.end_container(array_idx);
        buf.end_layer();

        // RFC 4666, Section 3.3.1 — the Protocol Data of a DATA message
        // carries the MTP3-User message; its Service Indicator selects the
        // MTP3-User (e.g. 3 = SCCP) —
        // https://www.rfc-editor.org/rfc/rfc4666#section-3.3.1
        if message_class == CLASS_TRANSFER && message_type == TYPE_DATA {
            if let Some((si, range)) = user_data {
                if !range.is_empty() {
                    return Ok(DissectResult::with_embedded_payload(
                        msg_len,
                        DispatchHint::ByMtp3ServiceIndicator(si),
                        range,
                    ));
                }
            }
        }
        Ok(DissectResult::new(msg_len, DispatchHint::End))
    }
}

/// Push the parameters found in `params` (starting at absolute offset
/// `base`) as parameter Objects; `nested` selects the subparameters of a
/// Routing Key, Registration Result or Deregistration Result.
///
/// Returns the Service Indicator and the absolute range of the User
/// Protocol Data of the first well-formed Protocol Data parameter, if any.
///
/// RFC 4666, Section 3.2 — "The Parameter Length does not include any
/// padding octets." A parameter whose Length is below 4 or runs past the
/// enclosing data ends decoding, since the following TLV boundaries cannot
/// be known — <https://www.rfc-editor.org/rfc/rfc4666#section-3.2>
fn push_parameters<'pkt>(
    params: &'pkt [u8],
    base: usize,
    nested: bool,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<(u8, core::ops::Range<usize>)> {
    let element = if nested {
        &FD_SUB_PARAMETER
    } else {
        &FD_PARAMETER
    };
    let mut user_data = None;
    let mut pos = 0;
    while pos + PARAM_HEADER_SIZE <= params.len() {
        let tag = read_be_u16(params, pos).unwrap_or_default();
        let len = read_be_u16(params, pos + 2).unwrap_or_default() as usize;
        if len < PARAM_HEADER_SIZE || pos + len > params.len() {
            break;
        }
        let abs = base + pos;
        let value = &params[pos + PARAM_HEADER_SIZE..pos + len];
        let value_abs = abs + PARAM_HEADER_SIZE;

        let obj_idx = buf.begin_container(element, FieldValue::Object(0..0), abs..abs + len);
        buf.push_field(&PARAM_FIELDS[PFD_TAG], FieldValue::U16(tag), abs..abs + 2);
        buf.push_field(
            &PARAM_FIELDS[PFD_LENGTH],
            FieldValue::U16(len as u16),
            abs + 2..abs + 4,
        );
        match push_parameter_value(tag, value, value_abs, nested, buf) {
            ParamValue::Decoded => {}
            ParamValue::UserData(si, range) => {
                if user_data.is_none() {
                    user_data = Some((si, range));
                }
            }
            ParamValue::Raw => buf.push_field(
                &PARAM_FIELDS[PFD_VALUE],
                FieldValue::Bytes(value),
                value_abs..value_abs + value.len(),
            ),
        }
        buf.end_container(obj_idx);

        // RFC 4666, Section 3.2 — "The total length of a parameter (including
        // Tag, Parameter Length, and Value fields) MUST be a multiple of 4
        // octets." — https://www.rfc-editor.org/rfc/rfc4666#section-3.2
        pos += len.next_multiple_of(4);
    }
    user_data
}

/// Outcome of [`push_parameter_value`].
enum ParamValue {
    /// The value was decoded into fields.
    Decoded,
    /// A Protocol Data value was decoded; carries its Service Indicator and
    /// the absolute range of its User Protocol Data.
    UserData(u8, core::ops::Range<usize>),
    /// Nothing was pushed: the tag is unknown, the value is opaque or it does
    /// not match its specified format. The caller pushes the raw value.
    Raw,
}

/// Push a `u32` value field when `value` is exactly four octets.
fn push_u32<'pkt>(
    fd: usize,
    value: &[u8],
    off: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> ParamValue {
    match (value.len(), read_be_u32(value, 0)) {
        (4, Ok(v)) => {
            buf.push_field(&PARAM_FIELDS[fd], FieldValue::U32(v), off..off + 4);
            ParamValue::Decoded
        }
        _ => ParamValue::Raw,
    }
}

/// Push the decoded fields of one parameter value. `nested` is set for a
/// subparameter.
fn push_parameter_value<'pkt>(
    tag: u16,
    value: &'pkt [u8],
    off: usize,
    nested: bool,
    buf: &mut DissectBuffer<'pkt>,
) -> ParamValue {
    match tag {
        // RFC 4666, Section 3.4.1 — "The optional INFO String parameter can
        // carry any meaningful UTF-8 [10] character string" —
        // https://www.rfc-editor.org/rfc/rfc4666#section-3.4.1
        TAG_INFO_STRING => match core::str::from_utf8(value) {
            Ok(s) => {
                buf.push_field(
                    &PARAM_FIELDS[PFD_INFO_STRING],
                    FieldValue::Str(s),
                    off..off + value.len(),
                );
                ParamValue::Decoded
            }
            Err(_) => ParamValue::Raw,
        },
        // RFC 4666, Section 3.4.1 — "Routing Context: n x 32 bits (unsigned
        // integer)" — https://www.rfc-editor.org/rfc/rfc4666#section-3.4.1
        TAG_ROUTING_CONTEXT => {
            if value.len() % 4 != 0 {
                return ParamValue::Raw;
            }
            let idx = buf.begin_container(
                &PARAM_FIELDS[PFD_ROUTING_CONTEXTS],
                FieldValue::Array(0..0),
                off..off + value.len(),
            );
            for (i, rc) in value.chunks_exact(4).enumerate() {
                let rc_off = off + i * 4;
                buf.push_field(
                    &FD_ROUTING_CONTEXT,
                    FieldValue::U32(read_be_u32(rc, 0).unwrap_or_default()),
                    rc_off..rc_off + 4,
                );
            }
            buf.end_container(idx);
            ParamValue::Decoded
        }
        TAG_TRAFFIC_MODE_TYPE => push_u32(PFD_TRAFFIC_MODE_TYPE, value, off, buf),
        TAG_ERROR_CODE => push_u32(PFD_ERROR_CODE, value, off, buf),
        // RFC 4666, Section 3.8.2 — Status Type (16 bits) and Status
        // Information (16 bits) —
        // https://www.rfc-editor.org/rfc/rfc4666#section-3.8.2
        TAG_STATUS => {
            if value.len() != 4 {
                return ParamValue::Raw;
            }
            buf.push_field(
                &PARAM_FIELDS[PFD_STATUS_TYPE],
                FieldValue::U16(read_be_u16(value, 0).unwrap_or_default()),
                off..off + 2,
            );
            buf.push_field(
                &PARAM_FIELDS[PFD_STATUS_INFORMATION],
                FieldValue::U16(read_be_u16(value, 2).unwrap_or_default()),
                off + 2..off + 4,
            );
            ParamValue::Decoded
        }
        TAG_ASP_IDENTIFIER => push_u32(PFD_ASP_IDENTIFIER, value, off, buf),
        // RFC 4666, Section 3.4.1 — "Affected Point Code: n x 32 bits", each
        // a Mask octet followed by a three-octet point code; Section 3.6.1 —
        // the OPC List has "the same [format] as for the Destination Point
        // Code parameter" — https://www.rfc-editor.org/rfc/rfc4666#section-3.4.1
        TAG_AFFECTED_POINT_CODE | TAG_ORIGINATING_POINT_CODE_LIST => {
            if value.is_empty() || value.len() % 4 != 0 {
                return ParamValue::Raw;
            }
            let idx = buf.begin_container(
                &PARAM_FIELDS[PFD_POINT_CODES],
                FieldValue::Array(0..0),
                off..off + value.len(),
            );
            for (i, pc) in value.chunks_exact(4).enumerate() {
                let pc_off = off + i * 4;
                let entry = buf.begin_container(
                    &FD_POINT_CODE_ENTRY,
                    FieldValue::Object(0..0),
                    pc_off..pc_off + 4,
                );
                buf.push_field(
                    &POINT_CODE_FIELDS[PCFD_MASK],
                    FieldValue::U8(pc[0]),
                    pc_off..pc_off + 1,
                );
                buf.push_field(
                    &POINT_CODE_FIELDS[PCFD_POINT_CODE],
                    FieldValue::U32(read_be_u24(pc, 1).unwrap_or_default()),
                    pc_off + 1..pc_off + 4,
                );
                buf.end_container(entry);
            }
            buf.end_container(idx);
            ParamValue::Decoded
        }
        TAG_CORRELATION_ID => push_u32(PFD_CORRELATION_ID, value, off, buf),
        TAG_NETWORK_APPEARANCE => push_u32(PFD_NETWORK_APPEARANCE, value, off, buf),
        // RFC 4666, Section 3.4.5 — Unavailability Cause (16 bits) and
        // MTP3-User Identity (16 bits) —
        // https://www.rfc-editor.org/rfc/rfc4666#section-3.4.5
        TAG_USER_CAUSE => {
            if value.len() != 4 {
                return ParamValue::Raw;
            }
            buf.push_field(
                &PARAM_FIELDS[PFD_CAUSE],
                FieldValue::U16(read_be_u16(value, 0).unwrap_or_default()),
                off..off + 2,
            );
            buf.push_field(
                &PARAM_FIELDS[PFD_USER],
                FieldValue::U16(read_be_u16(value, 2).unwrap_or_default()),
                off + 2..off + 4,
            );
            ParamValue::Decoded
        }
        // RFC 4666, Section 3.4.4 — 24 reserved bits then the 8-bit
        // Congestion Level — https://www.rfc-editor.org/rfc/rfc4666#section-3.4.4
        TAG_CONGESTION_INDICATIONS => {
            if value.len() != 4 {
                return ParamValue::Raw;
            }
            buf.push_field(
                &PARAM_FIELDS[PFD_CONGESTION_LEVEL],
                FieldValue::U8(value[3]),
                off + 3..off + 4,
            );
            ParamValue::Decoded
        }
        // RFC 4666, Section 3.4.4 — 8 reserved bits then the three-octet
        // Concerned DPC — https://www.rfc-editor.org/rfc/rfc4666#section-3.4.4
        TAG_CONCERNED_DESTINATION => {
            if value.len() != 4 {
                return ParamValue::Raw;
            }
            buf.push_field(
                &PARAM_FIELDS[PFD_CONCERNED_DPC],
                FieldValue::U32(read_be_u24(value, 1).unwrap_or_default()),
                off + 1..off + 4,
            );
            ParamValue::Decoded
        }
        // RFC 4666, Sections 3.6.1, 3.6.2 and 3.6.4 — these parameters
        // contain subparameters in the same TLV format. None of the defined
        // subparameters contains subparameters itself, so a nested one is
        // kept raw (which also bounds the recursion depth) —
        // https://www.rfc-editor.org/rfc/rfc4666#section-3.6.1
        TAG_ROUTING_KEY | TAG_REGISTRATION_RESULT | TAG_DEREGISTRATION_RESULT if !nested => {
            let idx = buf.begin_container(
                &PARAM_FIELDS[PFD_PARAMETERS],
                FieldValue::Array(0..0),
                off..off + value.len(),
            );
            push_parameters(value, off, true, buf);
            buf.end_container(idx);
            ParamValue::Decoded
        }
        TAG_LOCAL_RK_IDENTIFIER => push_u32(PFD_LOCAL_RK_IDENTIFIER, value, off, buf),
        // RFC 4666, Section 3.6.1 — "Mask = 0" then the Destination Point
        // Code — https://www.rfc-editor.org/rfc/rfc4666#section-3.6.1
        TAG_DESTINATION_POINT_CODE => {
            if value.len() != 4 {
                return ParamValue::Raw;
            }
            buf.push_field(
                &PARAM_FIELDS[PFD_MASK],
                FieldValue::U8(value[0]),
                off..off + 1,
            );
            buf.push_field(
                &PARAM_FIELDS[PFD_POINT_CODE],
                FieldValue::U32(read_be_u24(value, 1).unwrap_or_default()),
                off + 1..off + 4,
            );
            ParamValue::Decoded
        }
        // RFC 4666, Section 3.6.1 — "Service Indicators (SI): n X 8-bit
        // integers"; the padding is not part of the Parameter Length —
        // https://www.rfc-editor.org/rfc/rfc4666#section-3.6.1
        TAG_SERVICE_INDICATORS => {
            if value.is_empty() {
                return ParamValue::Raw;
            }
            let idx = buf.begin_container(
                &PARAM_FIELDS[PFD_SERVICE_INDICATORS],
                FieldValue::Array(0..0),
                off..off + value.len(),
            );
            for (i, si) in value.iter().enumerate() {
                buf.push_field(
                    &FD_SERVICE_INDICATOR,
                    FieldValue::U8(*si),
                    off + i..off + i + 1,
                );
            }
            buf.end_container(idx);
            ParamValue::Decoded
        }
        TAG_PROTOCOL_DATA => push_protocol_data(value, off, buf),
        TAG_REGISTRATION_STATUS => push_u32(PFD_REGISTRATION_STATUS, value, off, buf),
        TAG_DEREGISTRATION_STATUS => push_u32(PFD_DEREGISTRATION_STATUS, value, off, buf),
        // Diagnostic Information and Heartbeat Data are opaque octet strings
        // (RFC 4666, Sections 3.8.1 and 3.5.5 —
        // https://www.rfc-editor.org/rfc/rfc4666#section-3.8.1,
        // https://www.rfc-editor.org/rfc/rfc4666#section-3.5.5); every other
        // tag is unknown.
        _ => ParamValue::Raw,
    }
}

/// Push the Protocol Data parameter value.
///
/// RFC 4666, Section 3.3.1 — OPC (32 bits), DPC (32 bits), SI, NI, MP and
/// SLS (8 bits each), then the User Protocol Data —
/// <https://www.rfc-editor.org/rfc/rfc4666#section-3.3.1>
fn push_protocol_data<'pkt>(
    value: &'pkt [u8],
    off: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> ParamValue {
    if value.len() < PROTOCOL_DATA_FIXED_SIZE {
        return ParamValue::Raw;
    }
    let si = value[8];
    let idx = buf.begin_container(
        &PARAM_FIELDS[PFD_PROTOCOL_DATA],
        FieldValue::Object(0..0),
        off..off + value.len(),
    );
    buf.push_field(
        &PROTOCOL_DATA_FIELDS[PDFD_OPC],
        FieldValue::U32(read_be_u32(value, 0).unwrap_or_default()),
        off..off + 4,
    );
    buf.push_field(
        &PROTOCOL_DATA_FIELDS[PDFD_DPC],
        FieldValue::U32(read_be_u32(value, 4).unwrap_or_default()),
        off + 4..off + 8,
    );
    buf.push_field(
        &PROTOCOL_DATA_FIELDS[PDFD_SI],
        FieldValue::U8(si),
        off + 8..off + 9,
    );
    buf.push_field(
        &PROTOCOL_DATA_FIELDS[PDFD_NI],
        FieldValue::U8(value[9]),
        off + 9..off + 10,
    );
    buf.push_field(
        &PROTOCOL_DATA_FIELDS[PDFD_MP],
        FieldValue::U8(value[10]),
        off + 10..off + 11,
    );
    buf.push_field(
        &PROTOCOL_DATA_FIELDS[PDFD_SLS],
        FieldValue::U8(value[11]),
        off + 11..off + 12,
    );
    let data_start = off + PROTOCOL_DATA_FIXED_SIZE;
    let data_end = off + value.len();
    buf.push_field(
        &PROTOCOL_DATA_FIELDS[PDFD_DATA],
        FieldValue::Bytes(&value[PROTOCOL_DATA_FIXED_SIZE..]),
        data_start..data_end,
    );
    buf.end_container(idx);
    ParamValue::UserData(si, data_start..data_end)
}

#[cfg(test)]
mod tests {
    //! # RFC 4666 (M3UA) Coverage
    //!
    //! | RFC Section | Description                                   | Test                                   |
    //! |-------------|-----------------------------------------------|----------------------------------------|
    //! | 3.1         | Common Message Header                         | parse_aspup_ack_header_only            |
    //! | 3.1.1       | Version must be 1                             | reject_unknown_version                 |
    //! | 3.1.2       | Message classes and types (names)             | message_class_and_type_names           |
    //! | 3.1.4       | Message Length shorter than header            | reject_length_below_header             |
    //! | 3.1.4       | Message Length beyond captured data           | truncated_message_length               |
    //! | 3.1.4       | Final padding outside the Message Length      | final_padding_not_in_length            |
    //! | 3.1         | Header shorter than 8 octets                  | truncated_header                       |
    //! | 3.2         | TLV parameters padded to 4 octets             | parse_aspup_with_asp_id_and_info       |
    //! | 3.2         | Parameter Length < 4 stops parameter decoding | malformed_parameter_length_stops       |
    //! | 3.2         | Parameter overrunning the message             | parameter_overrun_stops                |
    //! | 3.2         | Unknown tag / wrong value length kept raw     | unknown_and_malformed_parameters_raw   |
    //! | 3.3.1       | DATA: NA, RC, Protocol Data, Correlation Id   | parse_data_dispatches_by_si            |
    //! | 3.3.1       | DATA without user data is not dispatched      | parse_data_empty_user_data             |
    //! | 3.3.1       | Protocol Data shorter than 12 octets          | parse_data_short_protocol_data         |
    //! | 3.4.1       | DUNA: Affected Point Code list                | parse_duna_affected_point_codes        |
    //! | 3.4.4       | SCON: Concerned Destination, Congestion       | parse_scon                             |
    //! | 3.4.5       | DUPU: User/Cause                              | parse_dupu                             |
    //! | 3.5.5       | BEAT: Heartbeat Data                          | parse_beat_heartbeat_data              |
    //! | 3.6.1       | REG REQ: nested Routing Key                   | parse_reg_req_routing_key              |
    //! | 3.6.1       | Nested Routing Key kept raw (no recursion)    | nested_routing_key_is_raw              |
    //! | 3.6.2       | REG RSP: Registration Result                  | parse_reg_rsp                          |
    //! | 3.6.4       | DEREG RSP: Deregistration Result              | parse_dereg_rsp                        |
    //! | 3.7.1       | ASPAC: Traffic Mode Type, Routing Contexts    | parse_aspac                            |
    //! | 3.8.1       | ERR: Error Code, Diagnostic Information       | parse_err                              |
    //! | 3.8.2       | NTFY: Status Type / Information               | parse_ntfy                             |
    //! | 3.2 et al.  | Name tables                                   | name_tables                            |
    //! | Q.704 14.2  | SI / NI names                                 | name_tables                            |
    //! | 3.1.2-3.8   | Name table sizes and display functions        | display_fns_and_name_table_sizes       |
    //! | 3.6.1       | Empty Service Indicators kept raw             | empty_service_indicators_raw           |

    use super::*;

    /// Build an M3UA message from its class, type and pre-encoded parameters.
    fn msg(class: u8, msg_type: u8, params: &[u8]) -> Vec<u8> {
        let mut m = vec![1, 0, class, msg_type];
        m.extend_from_slice(&((HEADER_SIZE + params.len()) as u32).to_be_bytes());
        m.extend_from_slice(params);
        m
    }

    /// Encode one parameter TLV, padded to 4 octets (RFC 4666, Section 3.2).
    fn param(tag: u16, value: &[u8]) -> Vec<u8> {
        let mut p = tag.to_be_bytes().to_vec();
        p.extend_from_slice(&((PARAM_HEADER_SIZE + value.len()) as u16).to_be_bytes());
        p.extend_from_slice(value);
        while p.len() % 4 != 0 {
            p.push(0);
        }
        p
    }

    fn dissect(data: &[u8]) -> (DissectBuffer<'_>, DissectResult) {
        let mut buf = DissectBuffer::new();
        let r = M3uaDissector.dissect(data, &mut buf, 0).unwrap();
        (buf, r)
    }

    /// Top-level parameter Objects of the M3UA layer.
    fn params<'a>(buf: &'a DissectBuffer<'a>) -> Vec<&'a [Field<'a>]> {
        let layer = &buf.layers()[0];
        let FieldValue::Array(r) = &buf.field_by_name(layer, "parameters").unwrap().value else {
            panic!("parameters is not an array");
        };
        objects(buf, r)
    }

    /// Direct Object children of an Array.
    fn objects<'a>(buf: &'a DissectBuffer<'a>, r: &core::ops::Range<u32>) -> Vec<&'a [Field<'a>]> {
        let all = buf.nested_fields(r);
        let mut out = Vec::new();
        let mut i = 0;
        while i < all.len() {
            let FieldValue::Object(cr) = &all[i].value else {
                panic!("array element is not an object");
            };
            out.push(buf.nested_fields(cr));
            i += 1 + (cr.end - cr.start) as usize;
        }
        out
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

    #[test]
    fn parse_aspup_ack_header_only() {
        let data = msg(3, 4, &[]);
        let (buf, r) = dissect(&data);
        assert_eq!(r.bytes_consumed, 8);
        assert_eq!(r.next, DispatchHint::End);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "M3UA");
        assert_eq!(layer.range, 0..8);
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "reserved").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U32(8)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_class_name"),
            Some("ASP State Maintenance (ASPSM) Messages")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("ASP Up Acknowledgement (ASPUP ACK)")
        );
        assert!(params(&buf).is_empty());
    }

    #[test]
    fn parse_aspup_with_asp_id_and_info() {
        let mut p = param(TAG_ASP_IDENTIFIER, &7u32.to_be_bytes());
        p.extend(param(TAG_INFO_STRING, b"hello")); // 9 octets, 3 padding
        let data = msg(3, 1, &p);
        let (buf, r) = dissect(&data);
        assert_eq!(r.bytes_consumed, data.len());
        let ps = params(&buf);
        assert_eq!(ps.len(), 2);
        assert_eq!(*get(ps[0], "tag"), FieldValue::U16(TAG_ASP_IDENTIFIER));
        assert_eq!(*get(ps[0], "length"), FieldValue::U16(8));
        assert_eq!(*get(ps[0], "asp_identifier"), FieldValue::U32(7));
        assert_eq!(*get(ps[1], "length"), FieldValue::U16(9));
        assert_eq!(*get(ps[1], "info_string"), FieldValue::Str("hello"));
        // Parameter Object ranges exclude the padding.
        let layer = &buf.layers()[0];
        let FieldValue::Array(ar) = &buf.field_by_name(layer, "parameters").unwrap().value else {
            panic!()
        };
        let elems = buf.nested_fields(ar);
        assert_eq!(elems[0].range, 8..16);
        let second = elems
            .iter()
            .filter(|f| matches!(f.value, FieldValue::Object(_)))
            .nth(1)
            .unwrap();
        assert_eq!(second.range, 16..25);
    }

    #[test]
    fn parse_aspac() {
        let mut p = param(TAG_TRAFFIC_MODE_TYPE, &2u32.to_be_bytes());
        let mut rc = 10u32.to_be_bytes().to_vec();
        rc.extend_from_slice(&20u32.to_be_bytes());
        p.extend(param(TAG_ROUTING_CONTEXT, &rc));
        let data = msg(4, 1, &p);
        let (buf, _) = dissect(&data);
        let ps = params(&buf);
        assert_eq!(*get(ps[0], "traffic_mode_type"), FieldValue::U32(2));
        let FieldValue::Array(r) = get(ps[1], "routing_contexts") else {
            panic!()
        };
        let rcs: Vec<_> = buf
            .nested_fields(r)
            .iter()
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(rcs, [FieldValue::U32(10), FieldValue::U32(20)]);
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "message_type_name"),
            Some("ASP Active (ASPAC)")
        );
    }

    /// DATA message with Network Appearance, Routing Context, Protocol Data
    /// and Correlation Id (RFC 4666, Section 3.3.1).
    fn data_message(user_data: &[u8]) -> Vec<u8> {
        let mut pd = Vec::new();
        pd.extend_from_slice(&0x0000_0102u32.to_be_bytes()); // OPC
        pd.extend_from_slice(&0x0000_0304u32.to_be_bytes()); // DPC
        pd.extend_from_slice(&[3, 2, 0, 5]); // SI=SCCP, NI=national, MP, SLS
        pd.extend_from_slice(user_data);
        let mut p = param(TAG_NETWORK_APPEARANCE, &9u32.to_be_bytes());
        p.extend(param(TAG_ROUTING_CONTEXT, &1u32.to_be_bytes()));
        p.extend(param(TAG_PROTOCOL_DATA, &pd));
        p.extend(param(TAG_CORRELATION_ID, &0xABCDu32.to_be_bytes()));
        msg(1, 1, &p)
    }

    #[test]
    fn parse_data_dispatches_by_si() {
        let user = [0x09, 0x80, 0x03, 0x0e, 0x19]; // start of an SCCP UDT
        let data = data_message(&user);
        let (buf, r) = dissect(&data);
        assert_eq!(r.bytes_consumed, data.len());
        assert_eq!(r.next, DispatchHint::ByMtp3ServiceIndicator(3));
        // Header 8 + NA 8 + RC 8 + Protocol Data TLV header 4 + fixed 12.
        let start = 8 + 8 + 8 + 4 + 12;
        assert_eq!(r.embedded_payload, Some(start..start + user.len()));
        let ps = params(&buf);
        assert_eq!(*get(ps[0], "network_appearance"), FieldValue::U32(9));
        assert_eq!(*get(ps[3], "correlation_id"), FieldValue::U32(0xABCD));
        let FieldValue::Object(r) = get(ps[2], "protocol_data") else {
            panic!()
        };
        let pd = buf.nested_fields(r);
        assert_eq!(*get(pd, "opc"), FieldValue::U32(0x0102));
        assert_eq!(*get(pd, "dpc"), FieldValue::U32(0x0304));
        assert_eq!(*get(pd, "si"), FieldValue::U8(3));
        assert_eq!(*get(pd, "ni"), FieldValue::U8(2));
        assert_eq!(*get(pd, "mp"), FieldValue::U8(0));
        assert_eq!(*get(pd, "sls"), FieldValue::U8(5));
        assert_eq!(*get(pd, "data"), FieldValue::Bytes(&user));
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "message_type_name"),
            Some("Payload Data (DATA)")
        );
    }

    #[test]
    fn parse_data_empty_user_data() {
        let data = data_message(&[]);
        let (_, r) = dissect(&data);
        assert_eq!(r.next, DispatchHint::End);
        assert_eq!(r.embedded_payload, None);
    }

    #[test]
    fn parse_data_short_protocol_data() {
        let data = msg(1, 1, &param(TAG_PROTOCOL_DATA, &[0; 11]));
        let (buf, r) = dissect(&data);
        assert_eq!(r.next, DispatchHint::End);
        let ps = params(&buf);
        assert!(!has(ps[0], "protocol_data"));
        assert_eq!(*get(ps[0], "value"), FieldValue::Bytes(&[0; 11]));
    }

    #[test]
    fn parse_duna_affected_point_codes() {
        let mut apc = vec![0, 0x00, 0x08, 0x01];
        apc.extend_from_slice(&[3, 0x00, 0x10, 0x00]);
        let mut p = param(TAG_AFFECTED_POINT_CODE, &apc);
        p.extend(param(TAG_INFO_STRING, b""));
        let data = msg(2, 1, &p);
        let (buf, _) = dissect(&data);
        let ps = params(&buf);
        let FieldValue::Array(r) = get(ps[0], "point_codes") else {
            panic!()
        };
        let pcs = objects(&buf, r);
        assert_eq!(pcs.len(), 2);
        assert_eq!(*get(pcs[0], "mask"), FieldValue::U8(0));
        assert_eq!(*get(pcs[0], "point_code"), FieldValue::U32(0x0801));
        assert_eq!(*get(pcs[1], "mask"), FieldValue::U8(3));
        assert_eq!(*get(pcs[1], "point_code"), FieldValue::U32(0x1000));
        // A zero-length INFO String is not an error (Section 3.4.1).
        assert_eq!(*get(ps[1], "info_string"), FieldValue::Str(""));
    }

    #[test]
    fn parse_scon() {
        let mut p = param(TAG_AFFECTED_POINT_CODE, &[0, 0, 0, 1]);
        p.extend(param(TAG_CONCERNED_DESTINATION, &[0, 0x01, 0x02, 0x03]));
        p.extend(param(TAG_CONGESTION_INDICATIONS, &[0, 0, 0, 2]));
        let data = msg(2, 4, &p);
        let (buf, _) = dissect(&data);
        let ps = params(&buf);
        assert_eq!(*get(ps[1], "concerned_dpc"), FieldValue::U32(0x010203));
        assert_eq!(*get(ps[2], "congestion_level"), FieldValue::U8(2));
    }

    #[test]
    fn parse_dupu() {
        let mut p = param(TAG_AFFECTED_POINT_CODE, &[0, 0, 0, 1]);
        p.extend(param(TAG_USER_CAUSE, &[0, 2, 0, 5]));
        let data = msg(2, 5, &p);
        let (buf, _) = dissect(&data);
        let ps = params(&buf);
        assert_eq!(*get(ps[1], "cause"), FieldValue::U16(2));
        assert_eq!(*get(ps[1], "user"), FieldValue::U16(5));
    }

    #[test]
    fn parse_beat_heartbeat_data() {
        let data = msg(3, 3, &param(TAG_HEARTBEAT_DATA, &[1, 2, 3, 4, 5]));
        let (buf, _) = dissect(&data);
        let ps = params(&buf);
        assert_eq!(*get(ps[0], "value"), FieldValue::Bytes(&[1, 2, 3, 4, 5]));
    }

    #[test]
    fn parse_reg_req_routing_key() {
        let mut rk = param(TAG_LOCAL_RK_IDENTIFIER, &1u32.to_be_bytes());
        rk.extend(param(TAG_TRAFFIC_MODE_TYPE, &1u32.to_be_bytes()));
        rk.extend(param(TAG_DESTINATION_POINT_CODE, &[0, 0, 0x12, 0x34]));
        rk.extend(param(TAG_SERVICE_INDICATORS, &[3, 5, 14])); // padded
        rk.extend(param(TAG_ORIGINATING_POINT_CODE_LIST, &[0, 0, 0, 7]));
        let data = msg(9, 1, &param(TAG_ROUTING_KEY, &rk));
        let (buf, r) = dissect(&data);
        assert_eq!(r.bytes_consumed, data.len());
        let ps = params(&buf);
        assert_eq!(ps.len(), 1);
        let FieldValue::Array(nr) = get(ps[0], "parameters") else {
            panic!()
        };
        let sub = objects(&buf, nr);
        assert_eq!(sub.len(), 5);
        assert_eq!(*get(sub[0], "local_rk_identifier"), FieldValue::U32(1));
        assert_eq!(*get(sub[1], "traffic_mode_type"), FieldValue::U32(1));
        assert_eq!(*get(sub[2], "mask"), FieldValue::U8(0));
        assert_eq!(*get(sub[2], "point_code"), FieldValue::U32(0x1234));
        let FieldValue::Array(sir) = get(sub[3], "service_indicators") else {
            panic!()
        };
        let sis: Vec<_> = buf
            .nested_fields(sir)
            .iter()
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(
            sis,
            [FieldValue::U8(3), FieldValue::U8(5), FieldValue::U8(14)]
        );
        assert!(has(sub[4], "point_codes"));
    }

    #[test]
    fn nested_routing_key_is_raw() {
        // A Routing Key inside a Routing Key is not a defined subparameter;
        // arbitrarily deep nesting must not recurse.
        let mut inner = param(TAG_LOCAL_RK_IDENTIFIER, &1u32.to_be_bytes());
        for _ in 0..20_000 {
            inner = param(TAG_ROUTING_KEY, &inner);
            if inner.len() > 60_000 {
                break;
            }
        }
        let data = msg(9, 1, &param(TAG_ROUTING_KEY, &inner));
        let (buf, _) = dissect(&data);
        let ps = params(&buf);
        let FieldValue::Array(nr) = get(ps[0], "parameters") else {
            panic!()
        };
        let sub = objects(&buf, nr);
        assert_eq!(sub.len(), 1);
        assert_eq!(*get(sub[0], "tag"), FieldValue::U16(TAG_ROUTING_KEY));
        assert!(has(sub[0], "value"));
        assert!(!has(sub[0], "parameters"));
    }

    #[test]
    fn parse_reg_rsp() {
        let mut rr = param(TAG_LOCAL_RK_IDENTIFIER, &1u32.to_be_bytes());
        rr.extend(param(TAG_REGISTRATION_STATUS, &0u32.to_be_bytes()));
        rr.extend(param(TAG_ROUTING_CONTEXT, &100u32.to_be_bytes()));
        let data = msg(9, 2, &param(TAG_REGISTRATION_RESULT, &rr));
        let (buf, _) = dissect(&data);
        let ps = params(&buf);
        let FieldValue::Array(nr) = get(ps[0], "parameters") else {
            panic!()
        };
        let sub = objects(&buf, nr);
        assert_eq!(*get(sub[1], "registration_status"), FieldValue::U32(0));
        assert!(has(sub[2], "routing_contexts"));
    }

    #[test]
    fn parse_dereg_rsp() {
        let mut dr = param(TAG_ROUTING_CONTEXT, &100u32.to_be_bytes());
        dr.extend(param(TAG_DEREGISTRATION_STATUS, &4u32.to_be_bytes()));
        let data = msg(9, 4, &param(TAG_DEREGISTRATION_RESULT, &dr));
        let (buf, _) = dissect(&data);
        let ps = params(&buf);
        let FieldValue::Array(nr) = get(ps[0], "parameters") else {
            panic!()
        };
        let sub = objects(&buf, nr);
        assert_eq!(*get(sub[1], "deregistration_status"), FieldValue::U32(4));
    }

    #[test]
    fn parse_err() {
        let mut p = param(TAG_ERROR_CODE, &0x1au32.to_be_bytes());
        p.extend(param(TAG_DIAGNOSTIC_INFORMATION, &[0xde, 0xad]));
        let data = msg(0, 0, &p);
        let (buf, _) = dissect(&data);
        let ps = params(&buf);
        assert_eq!(*get(ps[0], "error_code"), FieldValue::U32(0x1a));
        assert_eq!(*get(ps[1], "value"), FieldValue::Bytes(&[0xde, 0xad]));
    }

    #[test]
    fn parse_ntfy() {
        let mut p = param(TAG_STATUS, &[0, 1, 0, 3]);
        p.extend(param(TAG_ASP_IDENTIFIER, &5u32.to_be_bytes()));
        let data = msg(0, 1, &p);
        let (buf, _) = dissect(&data);
        let ps = params(&buf);
        assert_eq!(*get(ps[0], "status_type"), FieldValue::U16(1));
        assert_eq!(*get(ps[0], "status_information"), FieldValue::U16(3));
        let info = ps[0]
            .iter()
            .find(|f| f.name() == "status_information")
            .unwrap();
        assert_eq!(
            (info.descriptor.display_fn.unwrap())(&info.value, ps[0]),
            Some("Application Server Active (AS-ACTIVE)")
        );
    }

    #[test]
    fn unknown_and_malformed_parameters_raw() {
        let mut p = param(0x7777, &[1, 2]);
        p.extend(param(TAG_ROUTING_CONTEXT, &[0, 0, 1])); // not n x 32 bits
        p.extend(param(TAG_ASP_IDENTIFIER, &[0; 3]));
        p.extend(param(TAG_STATUS, &[0; 5]));
        p.extend(param(TAG_AFFECTED_POINT_CODE, &[0; 5]));
        p.extend(param(TAG_INFO_STRING, &[0xff, 0xfe]));
        p.extend(param(TAG_USER_CAUSE, &[0; 3]));
        p.extend(param(TAG_CONGESTION_INDICATIONS, &[0; 3]));
        p.extend(param(TAG_CONCERNED_DESTINATION, &[0; 3]));
        p.extend(param(TAG_DESTINATION_POINT_CODE, &[0; 8]));
        let data = msg(0, 1, &p);
        let (buf, _) = dissect(&data);
        let ps = params(&buf);
        assert_eq!(ps.len(), 10);
        for p in &ps {
            assert!(has(p, "value"), "{p:?}");
            assert_eq!(p.len(), 3, "{p:?}");
        }
    }

    #[test]
    fn malformed_parameter_length_stops() {
        let mut p = param(TAG_ASP_IDENTIFIER, &1u32.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x04, 0x00, 0x02]); // Length 2 < 4
        p.extend(param(TAG_ASP_IDENTIFIER, &2u32.to_be_bytes()));
        let data = msg(3, 1, &p);
        let (buf, r) = dissect(&data);
        assert_eq!(r.bytes_consumed, data.len());
        assert_eq!(params(&buf).len(), 1);
    }

    #[test]
    fn parameter_overrun_stops() {
        let mut p = param(TAG_ASP_IDENTIFIER, &1u32.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x11, 0x00, 0x20, 0, 0, 0, 0]); // Length 32
        let data = msg(3, 1, &p);
        let (buf, _) = dissect(&data);
        assert_eq!(params(&buf).len(), 1);
    }

    #[test]
    fn final_padding_not_in_length() {
        // RFC 4666, Section 3.1.4 — "A receiver SHOULD accept the message
        // whether or not the final parameter padding is included in the
        // message length."
        let mut data = msg(3, 1, &param(TAG_INFO_STRING, b"abc"));
        data.truncate(data.len() - 1);
        let len = data.len() as u32;
        data[4..8].copy_from_slice(&len.to_be_bytes());
        data.push(0); // padding outside the Message Length
        let (buf, r) = dissect(&data);
        assert_eq!(r.bytes_consumed, 15);
        assert_eq!(*get(params(&buf)[0], "info_string"), FieldValue::Str("abc"));
    }

    #[test]
    fn truncated_header() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            M3uaDissector.dissect(&[1, 0, 3, 1, 0, 0, 0], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 8,
                actual: 7
            })
        );
    }

    #[test]
    fn truncated_message_length() {
        let mut data = msg(3, 1, &param(TAG_ASP_IDENTIFIER, &1u32.to_be_bytes()));
        data.truncate(12);
        let mut buf = DissectBuffer::new();
        assert_eq!(
            M3uaDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 16,
                actual: 12
            })
        );
    }

    #[test]
    fn reject_unknown_version() {
        let mut data = msg(3, 1, &[]);
        data[0] = 2;
        let mut buf = DissectBuffer::new();
        assert_eq!(
            M3uaDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 2
            })
        );
    }

    #[test]
    fn reject_length_below_header() {
        let mut data = msg(3, 1, &[]);
        data[7] = 4;
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            M3uaDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn dissect_at_nonzero_offset() {
        let data = msg(3, 1, &param(TAG_ASP_IDENTIFIER, &1u32.to_be_bytes()));
        let mut buf = DissectBuffer::new();
        M3uaDissector.dissect(&data, &mut buf, 100).unwrap();
        assert_eq!(buf.layers()[0].range, 100..116);
    }

    #[test]
    fn message_class_and_type_names() {
        assert_eq!(
            message_class_name(9),
            Some("Routing Key Management (RKM) Messages")
        );
        assert_eq!(message_class_name(11), Some("M2PA Messages"));
        assert_eq!(message_class_name(13), None);
        assert_eq!(message_type_name(0, 0), Some("Error (ERR)"));
        assert_eq!(
            message_type_name(2, 6),
            Some("Destination Restricted (DRST)")
        );
        assert_eq!(
            message_type_name(3, 6),
            Some("Heartbeat Acknowledgement (BEAT ACK)")
        );
        assert_eq!(
            message_type_name(4, 4),
            Some("ASP Inactive Acknowledgement (ASPIA ACK)")
        );
        assert_eq!(
            message_type_name(9, 3),
            Some("Deregistration Request (DEREG REQ)")
        );
        assert_eq!(message_type_name(1, 0), None);
        assert_eq!(message_type_name(5, 1), None);
    }

    #[test]
    fn name_tables() {
        assert_eq!(parameter_tag_name(TAG_PROTOCOL_DATA), Some("Protocol Data"));
        assert_eq!(parameter_tag_name(0x0001), None);
        assert_eq!(service_indicator_name(3), Some("SCCP"));
        assert_eq!(
            service_indicator_name(13),
            Some("Bearer Independent Call Control (BICC)")
        );
        assert_eq!(service_indicator_name(2), None);
        assert_eq!(service_indicator_name(15), None);
        assert_eq!(network_indicator_name(2), Some("National network"));
        assert_eq!(network_indicator_name(4), None);
        assert_eq!(traffic_mode_type_name(3), Some("Broadcast"));
        assert_eq!(traffic_mode_type_name(0), None);
        assert_eq!(error_code_name(0x1a), Some("No Configured AS for ASP"));
        assert_eq!(error_code_name(0x02), Some("Not Used in M3UA"));
        assert_eq!(error_code_name(0x1b), None);
        assert_eq!(status_type_name(2), Some("Other"));
        assert_eq!(status_type_name(3), None);
        assert_eq!(status_information_name(2, 3), Some("ASP Failure"));
        assert_eq!(status_information_name(1, 5), None);
        assert_eq!(unavailability_cause_name(1), Some("Unequipped Remote User"));
        assert_eq!(unavailability_cause_name(3), None);
        assert_eq!(congestion_level_name(3), Some("Congestion Level 3"));
        assert_eq!(congestion_level_name(4), None);
        assert_eq!(
            registration_status_name(12),
            Some("Error - Routing Key Already Registered")
        );
        assert_eq!(registration_status_name(13), None);
        assert_eq!(
            deregistration_status_name(5),
            Some("Error - ASP Currently Active for Routing Context")
        );
        assert_eq!(deregistration_status_name(6), None);
    }

    #[test]
    fn display_functions() {
        let data = {
            let mut p = param(TAG_USER_CAUSE, &[0, 1, 0, 3]);
            p.extend(param(TAG_SERVICE_INDICATORS, &[5]));
            msg(2, 5, &p)
        };
        let (buf, _) = dissect(&data);
        let layer = &buf.layers()[0];
        let FieldValue::Array(r) = &buf.field_by_name(layer, "parameters").unwrap().value else {
            panic!()
        };
        let mut seen = 0;
        for f in buf.nested_fields(r) {
            let Some(display) = f.descriptor.display_fn else {
                continue;
            };
            let siblings: &[Field<'_>] = match &f.value {
                FieldValue::Object(cr) => buf.nested_fields(cr),
                _ => &[],
            };
            let name = display(&f.value, siblings);
            match f.name() {
                "parameter" => assert!(name.is_some()),
                "cause" => assert_eq!(name, Some("Unequipped Remote User")),
                "user" => assert_eq!(name, Some("SCCP")),
                "service_indicator" => assert_eq!(name, Some("ISDN User Part")),
                "tag" => assert!(name.is_some()),
                _ => continue,
            }
            seen += 1;
        }
        assert_eq!(seen, 7);
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
        // RFC 4666, Section 3.1.2 and the IANA registry: classes 0-12.
        assert_eq!(known(255, message_class_name), 13);
        let types: usize = (0..=255u8)
            .map(|c| known(255, |t: u8| message_type_name(c, t)))
            .sum();
        assert_eq!(types, 2 + 1 + 6 + 6 + 4 + 4);
        assert_eq!(known(0xffff, parameter_tag_name), 24);
        assert_eq!(known(255, service_indicator_name), 13);
        assert_eq!(known(255, network_indicator_name), 4);
        assert_eq!(known(255, traffic_mode_type_name), 3);
        assert_eq!(known(255, error_code_name), 26);
        assert_eq!(known(255, status_type_name), 2);
        let infos: usize = (0..=4u16)
            .map(|t| known(255, |i: u16| status_information_name(t, i)))
            .sum();
        assert_eq!(infos, 7);
        assert_eq!(known(255, unavailability_cause_name), 3);
        assert_eq!(known(255, congestion_level_name), 4);
        assert_eq!(known(255, registration_status_name), 13);
        assert_eq!(known(255, deregistration_status_name), 6);
    }

    #[test]
    fn empty_service_indicators_raw() {
        let data = msg(9, 1, &param(TAG_SERVICE_INDICATORS, &[]));
        let (buf, _) = dissect(&data);
        assert_eq!(*get(params(&buf)[0], "value"), FieldValue::Bytes(&[]));
    }

    #[test]
    fn field_descriptor_layout() {
        assert_eq!(FIELD_DESCRIPTORS[FD_VERSION].name, "version");
        assert_eq!(FIELD_DESCRIPTORS[FD_RESERVED].name, "reserved");
        assert_eq!(FIELD_DESCRIPTORS[FD_MESSAGE_CLASS].name, "message_class");
        assert_eq!(FIELD_DESCRIPTORS[FD_MESSAGE_TYPE].name, "message_type");
        assert_eq!(FIELD_DESCRIPTORS[FD_LENGTH].name, "length");
        assert_eq!(FIELD_DESCRIPTORS[FD_PARAMETERS].name, "parameters");
        assert_eq!(PARAM_FIELDS[PFD_PARAMETERS].name, "parameters");
        assert_eq!(PARAM_FIELDS.len(), PFD_PARAMETERS + 1);
        assert_eq!(SUB_PARAM_FIELDS.len(), PFD_PARAMETERS);
        assert_eq!(PROTOCOL_DATA_FIELDS[PDFD_DATA].name, "data");
        let d = M3uaDissector;
        assert_eq!(d.name(), "MTP3 User Adaptation Layer");
        assert_eq!(d.short_name(), "M3UA");
        assert_eq!(d.field_descriptors().len(), 6);
        assert_eq!(d.references()[0].id, "RFC 4666");
        assert_eq!(d.layer(), Some(ProtocolLayer::Application));
    }
}
