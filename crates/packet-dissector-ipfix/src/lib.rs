//! NetFlow v5, NetFlow v9 and IPFIX flow export dissectors.
//!
//! [`IpfixDissector`] decodes IPFIX Messages (version 10),
//! [`NetflowV9Dissector`] NetFlow v9 Export Packets and
//! [`NetflowV5Dissector`] NetFlow v5 datagrams. [`NetflowDissector`] picks
//! one of them by the version number that starts every export packet.
//!
//! Data Records are described by Templates that are usually sent in an
//! earlier message. The IPFIX and NetFlow v9 dissectors keep the Templates
//! they have seen per Transport Session, Observation Domain and Template ID
//! (RFC 7011, Section 8 — <https://www.rfc-editor.org/rfc/rfc7011#section-8>)
//! and decode later Data Sets with them; a Data Set whose Template has not
//! been seen is emitted as raw bytes.
//!
//! Like TCP stream reassembly, this state follows the packets each dissector
//! instance is given, in the order it is given them: a Data Set is decoded
//! only if the packet carrying its Template was dissected earlier by the same
//! instance (for example, the same `DissectorRegistry`). Dissect a capture
//! in order with one registry, and use a new registry for another capture.
//!
//! ## References
//! - RFC 7011 (IPFIX protocol): <https://www.rfc-editor.org/rfc/rfc7011>
//! - RFC 7012 (IPFIX Information Model): <https://www.rfc-editor.org/rfc/rfc7012>
//! - RFC 3954 (NetFlow version 9): <https://www.rfc-editor.org/rfc/rfc3954>
//! - IANA IPFIX Information Elements:
//!   <https://www.iana.org/assignments/ipfix/>
//! - Cisco NetFlow Export Datagram Format (NetFlow v5):
//!   <https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html>

#![deny(missing_docs)]

mod ie;
mod template;

pub use ie::{DataType, information_element, information_element_name};

use std::sync::{Mutex, PoisonError};

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{Field, FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

use template::{FieldSpec, SessionKey, TemplateCache};

/// IANA-assigned port for IPFIX over UDP, TCP and SCTP.
///
/// RFC 7011, Section 10.1 — <https://www.rfc-editor.org/rfc/rfc7011#section-10.1>:
/// "By default, the Collecting Process listens for connections on SCTP,
/// TCP, and/or UDP port 4739."
pub const IPFIX_PORT: u16 = 4739;

/// Version number of IPFIX. RFC 7011, Section 3.1 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.1>: "The value of this
/// field is 0x000a for the current version".
const IPFIX_VERSION: u16 = 10;
/// Version number of NetFlow v9. RFC 3954, Section 5.1 —
/// <https://www.rfc-editor.org/rfc/rfc3954#section-5.1>.
const NETFLOW_V9_VERSION: u16 = 9;
/// Version number of NetFlow v5 (Cisco, Table B-3).
const NETFLOW_V5_VERSION: u16 = 5;

/// IPFIX Message Header size. RFC 7011, Section 3.1 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.1>.
const IPFIX_HEADER_SIZE: usize = 16;
/// NetFlow v9 Packet Header size. RFC 3954, Section 5.1 —
/// <https://www.rfc-editor.org/rfc/rfc3954#section-5.1>.
const NETFLOW_V9_HEADER_SIZE: usize = 20;
/// NetFlow v5 header size (Cisco, Table B-3).
const NETFLOW_V5_HEADER_SIZE: usize = 24;
/// NetFlow v5 flow record size (Cisco, Table B-4).
const NETFLOW_V5_RECORD_SIZE: usize = 48;

/// Set Header size. RFC 7011, Section 3.3.2 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.3.2>.
const SET_HEADER_SIZE: usize = 4;

/// Field Length marking a variable-length Information Element.
/// RFC 7011, Section 7 — <https://www.rfc-editor.org/rfc/rfc7011#section-7>.
const VARIABLE_LENGTH: u16 = 65535;

/// First Template ID usable for Data Sets. RFC 7011, Section 3.4.1 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.1>.
const MIN_DATA_SET_ID: u16 = 256;

/// IPFIX Template Set ID. RFC 7011, Section 3.3.2 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.3.2>.
const IPFIX_TEMPLATE_SET_ID: u16 = 2;
/// IPFIX Options Template Set ID. RFC 7011, Section 3.3.2 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.3.2>.
const IPFIX_OPTIONS_TEMPLATE_SET_ID: u16 = 3;
/// NetFlow v9 Template FlowSet ID. RFC 3954, Section 5.2 —
/// <https://www.rfc-editor.org/rfc/rfc3954#section-5.2>.
const V9_TEMPLATE_FLOWSET_ID: u16 = 0;
/// NetFlow v9 Options Template FlowSet ID. RFC 3954, Section 6.1 —
/// <https://www.rfc-editor.org/rfc/rfc3954#section-6.1>.
const V9_OPTIONS_TEMPLATE_FLOWSET_ID: u16 = 1;

// ---------------------------------------------------------------------------
// Display functions
// ---------------------------------------------------------------------------

/// Name of an IPFIX Set ID. RFC 7011, Section 3.3.2 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.3.2>: "A value of 2 is
/// reserved for Template Sets. A value of 3 is reserved for Options Template
/// Sets. Values from 4 to 255 are reserved for future use. Values 256 and
/// above are used for Data Sets. The Set ID values of 0 and 1 are not used,
/// for historical reasons [RFC3954]."
/// [RFC3954]: <https://www.rfc-editor.org/rfc/rfc3954>
fn ipfix_set_id_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::U16(IPFIX_TEMPLATE_SET_ID) => Some("Template Set"),
        FieldValue::U16(IPFIX_OPTIONS_TEMPLATE_SET_ID) => Some("Options Template Set"),
        FieldValue::U16(id) if *id >= MIN_DATA_SET_ID => Some("Data Set"),
        FieldValue::U16(_) => Some("Reserved"),
        _ => None,
    }
}

/// Name of a NetFlow v9 FlowSet ID. RFC 3954, Sections 5.2, 5.3 and 6.1 —
/// <https://www.rfc-editor.org/rfc/rfc3954#section-5.2>.
fn v9_flowset_id_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::U16(V9_TEMPLATE_FLOWSET_ID) => Some("Template FlowSet"),
        FieldValue::U16(V9_OPTIONS_TEMPLATE_FLOWSET_ID) => Some("Options Template FlowSet"),
        FieldValue::U16(id) if *id >= MIN_DATA_SET_ID => Some("Data FlowSet"),
        FieldValue::U16(_) => Some("Reserved"),
        _ => None,
    }
}

/// Name of an IANA Information Element; enterprise-specific elements (with
/// an `enterprise_number` sibling) are not in the IANA registry.
fn ipfix_element_name(v: &FieldValue<'_>, siblings: &[Field<'_>]) -> Option<&'static str> {
    if siblings.iter().any(|f| f.name() == "enterprise_number") {
        return None;
    }
    match v {
        FieldValue::U16(id) => information_element_name(*id),
        _ => None,
    }
}

/// IPFIX Information Element matching a NetFlow v9 Field Type.
///
/// RFC 7012, Section 4 — <https://www.rfc-editor.org/rfc/rfc7012#section-4>:
/// "Within this range, Information Element identifier values in the
/// sub-range of 1-127 are compatible with field types used by NetFlow
/// version 9 [RFC3954] for historical reasons." Higher field types are
/// vendor-defined in NetFlow v9 and are not interpreted.
/// [RFC3954]: <https://www.rfc-editor.org/rfc/rfc3954>
fn v9_field_type(id: u16) -> Option<(&'static str, DataType)> {
    if (1..=127).contains(&id) {
        information_element(id)
    } else {
        None
    }
}

/// Name of a NetFlow v9 Field Type (see [`v9_field_type`]).
fn v9_field_type_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::U16(id) => v9_field_type(*id).map(|(name, _)| name),
        _ => None,
    }
}

/// Name of a NetFlow v9 Options Template scope field type.
///
/// RFC 3954, Section 6.1 — <https://www.rfc-editor.org/rfc/rfc3954#section-6.1>:
/// "1 System, 2 Interface, 3 Line Card, 4 Cache, 5 Template".
fn v9_scope_type_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::U16(1) => Some("System"),
        FieldValue::U16(2) => Some("Interface"),
        FieldValue::U16(3) => Some("Line Card"),
        FieldValue::U16(4) => Some("Cache"),
        FieldValue::U16(5) => Some("Template"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Field descriptors
// ---------------------------------------------------------------------------

/// Children of an IPFIX Field Specifier. RFC 7011, Section 3.2 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.2>.
static IPFIX_SPEC_CHILDREN: [FieldDescriptor; 3] = [
    FieldDescriptor::new("element_id", "Information Element ID", FieldType::U16)
        .with_display_fn(ipfix_element_name),
    FieldDescriptor::new("field_length", "Field Length", FieldType::U16),
    FieldDescriptor::new("enterprise_number", "Enterprise Number", FieldType::U32).optional(),
];
const SPEC_ID: usize = 0;
const SPEC_LENGTH: usize = 1;
const SPEC_ENTERPRISE: usize = 2;

/// Children of a NetFlow v9 field definition. RFC 3954, Section 5.2 —
/// <https://www.rfc-editor.org/rfc/rfc3954#section-5.2>.
static V9_SPEC_CHILDREN: [FieldDescriptor; 2] = [
    FieldDescriptor::new("field_type", "Field Type", FieldType::U16)
        .with_display_fn(v9_field_type_name),
    FieldDescriptor::new("field_length", "Field Length", FieldType::U16),
];

/// Children of a NetFlow v9 scope field definition. RFC 3954, Section 6.1 —
/// <https://www.rfc-editor.org/rfc/rfc3954#section-6.1>.
static V9_SCOPE_SPEC_CHILDREN: [FieldDescriptor; 2] = [
    FieldDescriptor::new("scope_field_type", "Scope Field Type", FieldType::U16)
        .with_display_fn(v9_scope_type_name),
    FieldDescriptor::new("field_length", "Scope Field Length", FieldType::U16),
];

static FD_IPFIX_SPEC: FieldDescriptor =
    FieldDescriptor::new("field_specifier", "Field Specifier", FieldType::Object)
        .with_children(&IPFIX_SPEC_CHILDREN);
static FD_V9_SPEC: FieldDescriptor =
    FieldDescriptor::new("field", "Field", FieldType::Object).with_children(&V9_SPEC_CHILDREN);
static FD_V9_SCOPE_SPEC: FieldDescriptor =
    FieldDescriptor::new("scope_field", "Scope Field", FieldType::Object)
        .with_children(&V9_SCOPE_SPEC_CHILDREN);

/// Children of an IPFIX Template or Options Template Record.
/// RFC 7011, Sections 3.4.1 and 3.4.2.2 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.1>.
static IPFIX_TEMPLATE_CHILDREN: [FieldDescriptor; 5] = [
    FieldDescriptor::new("template_id", "Template ID", FieldType::U16),
    FieldDescriptor::new("field_count", "Field Count", FieldType::U16),
    FieldDescriptor::new("scope_field_count", "Scope Field Count", FieldType::U16).optional(),
    FieldDescriptor::new("scope_fields", "Scope Field Specifiers", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_IPFIX_SPEC)),
    FieldDescriptor::new("fields", "Field Specifiers", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_IPFIX_SPEC)),
];
const IT_TEMPLATE_ID: usize = 0;
const IT_FIELD_COUNT: usize = 1;
const IT_SCOPE_FIELD_COUNT: usize = 2;
const IT_SCOPE_FIELDS: usize = 3;
const IT_FIELDS: usize = 4;

/// Children of a NetFlow v9 Template or Options Template Record.
/// RFC 3954, Sections 5.2 and 6.1 —
/// <https://www.rfc-editor.org/rfc/rfc3954#section-5.2>.
static V9_TEMPLATE_CHILDREN: [FieldDescriptor; 6] = [
    FieldDescriptor::new("template_id", "Template ID", FieldType::U16),
    FieldDescriptor::new("field_count", "Field Count", FieldType::U16).optional(),
    FieldDescriptor::new("option_scope_length", "Option Scope Length", FieldType::U16).optional(),
    FieldDescriptor::new("option_length", "Option Length", FieldType::U16).optional(),
    FieldDescriptor::new("scope_fields", "Scope Fields", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_V9_SCOPE_SPEC)),
    FieldDescriptor::new("fields", "Fields", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_V9_SPEC)),
];
const VT_TEMPLATE_ID: usize = 0;
const VT_FIELD_COUNT: usize = 1;
const VT_OPTION_SCOPE_LENGTH: usize = 2;
const VT_OPTION_LENGTH: usize = 3;
const VT_SCOPE_FIELDS: usize = 4;
const VT_FIELDS: usize = 5;

static FD_IPFIX_TEMPLATE: FieldDescriptor =
    FieldDescriptor::new("template", "Template Record", FieldType::Object)
        .with_children(&IPFIX_TEMPLATE_CHILDREN);
static FD_V9_TEMPLATE: FieldDescriptor =
    FieldDescriptor::new("template", "Template Record", FieldType::Object)
        .with_children(&V9_TEMPLATE_CHILDREN);

/// Children of one decoded IPFIX field value.
static IPFIX_VALUE_CHILDREN: [FieldDescriptor; 3] = [
    FieldDescriptor::new("element_id", "Information Element ID", FieldType::U16)
        .with_display_fn(ipfix_element_name),
    FieldDescriptor::new("enterprise_number", "Enterprise Number", FieldType::U32).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Any),
];
/// Children of one decoded NetFlow v9 field value.
static V9_VALUE_CHILDREN: [FieldDescriptor; 2] = [
    FieldDescriptor::new("field_type", "Field Type", FieldType::U16)
        .with_display_fn(v9_field_type_name),
    FieldDescriptor::new("value", "Value", FieldType::Any),
];
/// Children of one decoded NetFlow v9 scope value.
static V9_SCOPE_VALUE_CHILDREN: [FieldDescriptor; 2] = [
    FieldDescriptor::new("scope_field_type", "Scope Field Type", FieldType::U16)
        .with_display_fn(v9_scope_type_name),
    FieldDescriptor::new("value", "Value", FieldType::Any),
];

static FD_IPFIX_VALUE: FieldDescriptor =
    FieldDescriptor::new("field", "Field Value", FieldType::Object)
        .with_children(&IPFIX_VALUE_CHILDREN);
static FD_V9_VALUE: FieldDescriptor =
    FieldDescriptor::new("field", "Field Value", FieldType::Object)
        .with_children(&V9_VALUE_CHILDREN);
static FD_V9_SCOPE_VALUE: FieldDescriptor =
    FieldDescriptor::new("scope_field", "Scope Field Value", FieldType::Object)
        .with_children(&V9_SCOPE_VALUE_CHILDREN);

/// Children of an IPFIX Data Record. RFC 7011, Section 3.4.3 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.3>.
static IPFIX_RECORD_CHILDREN: [FieldDescriptor; 2] = [
    FieldDescriptor::new("scope_fields", "Scope Field Values", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_IPFIX_VALUE)),
    FieldDescriptor::new("fields", "Field Values", FieldType::Array)
        .with_children(core::slice::from_ref(&FD_IPFIX_VALUE)),
];
/// Children of a NetFlow v9 Flow or Options Data Record. RFC 3954,
/// Sections 5.3 and 6.2 — <https://www.rfc-editor.org/rfc/rfc3954#section-5.3>.
static V9_RECORD_CHILDREN: [FieldDescriptor; 2] = [
    FieldDescriptor::new("scope_fields", "Scope Field Values", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_V9_SCOPE_VALUE)),
    FieldDescriptor::new("fields", "Field Values", FieldType::Array)
        .with_children(core::slice::from_ref(&FD_V9_VALUE)),
];
const REC_SCOPE_FIELDS: usize = 0;
const REC_FIELDS: usize = 1;

static FD_IPFIX_RECORD: FieldDescriptor =
    FieldDescriptor::new("record", "Data Record", FieldType::Object)
        .with_children(&IPFIX_RECORD_CHILDREN);
static FD_V9_RECORD: FieldDescriptor =
    FieldDescriptor::new("record", "Data Record", FieldType::Object)
        .with_children(&V9_RECORD_CHILDREN);

/// Children of an IPFIX Set. RFC 7011, Section 3.3 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.3>.
static IPFIX_SET_CHILDREN: [FieldDescriptor; 6] = [
    FieldDescriptor::new("set_id", "Set ID", FieldType::U16).with_display_fn(ipfix_set_id_name),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("templates", "Template Records", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_IPFIX_TEMPLATE)),
    FieldDescriptor::new("records", "Data Records", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_IPFIX_RECORD)),
    FieldDescriptor::new("data", "Undecoded Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("padding", "Padding", FieldType::Bytes).optional(),
];
/// Children of a NetFlow v9 FlowSet. RFC 3954, Section 5 —
/// <https://www.rfc-editor.org/rfc/rfc3954#section-5>.
static V9_FLOWSET_CHILDREN: [FieldDescriptor; 6] = [
    FieldDescriptor::new("flowset_id", "FlowSet ID", FieldType::U16)
        .with_display_fn(v9_flowset_id_name),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("templates", "Template Records", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_V9_TEMPLATE)),
    FieldDescriptor::new("records", "Data Records", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_V9_RECORD)),
    FieldDescriptor::new("data", "Undecoded Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("padding", "Padding", FieldType::Bytes).optional(),
];
const SET_ID: usize = 0;
const SET_LENGTH: usize = 1;
const SET_TEMPLATES: usize = 2;
const SET_RECORDS: usize = 3;
const SET_DATA: usize = 4;
const SET_PADDING: usize = 5;

static FD_IPFIX_SET: FieldDescriptor =
    FieldDescriptor::new("set", "Set", FieldType::Object).with_children(&IPFIX_SET_CHILDREN);
static FD_V9_FLOWSET: FieldDescriptor =
    FieldDescriptor::new("flowset", "FlowSet", FieldType::Object)
        .with_children(&V9_FLOWSET_CHILDREN);

/// IPFIX Message fields. RFC 7011, Section 3.1 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.1>.
static IPFIX_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version Number", FieldType::U16),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("export_time", "Export Time", FieldType::U32),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U32),
    FieldDescriptor::new(
        "observation_domain_id",
        "Observation Domain ID",
        FieldType::U32,
    ),
    FieldDescriptor::new("sets", "Sets", FieldType::Array)
        .with_children(core::slice::from_ref(&FD_IPFIX_SET)),
];
const IH_VERSION: usize = 0;
const IH_LENGTH: usize = 1;
const IH_EXPORT_TIME: usize = 2;
const IH_SEQUENCE: usize = 3;
const IH_DOMAIN: usize = 4;
const IH_SETS: usize = 5;

/// NetFlow v9 Export Packet fields. RFC 3954, Section 5.1 —
/// <https://www.rfc-editor.org/rfc/rfc3954#section-5.1>.
static V9_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U16),
    FieldDescriptor::new("count", "Count", FieldType::U16),
    FieldDescriptor::new("sys_uptime", "sysUpTime", FieldType::U32),
    FieldDescriptor::new("unix_secs", "UNIX Secs", FieldType::U32),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U32),
    FieldDescriptor::new("source_id", "Source ID", FieldType::U32),
    FieldDescriptor::new("flowsets", "FlowSets", FieldType::Array)
        .with_children(core::slice::from_ref(&FD_V9_FLOWSET)),
];
const VH_VERSION: usize = 0;
const VH_COUNT: usize = 1;
const VH_SYS_UPTIME: usize = 2;
const VH_UNIX_SECS: usize = 3;
const VH_SEQUENCE: usize = 4;
const VH_SOURCE_ID: usize = 5;
const VH_FLOWSETS: usize = 6;

/// NetFlow v5 flow record fields (Cisco, Table B-4).
static V5_RECORD_CHILDREN: [FieldDescriptor; 18] = [
    FieldDescriptor::new("src_addr", "Source IP Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("dst_addr", "Destination IP Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("next_hop", "Next Hop", FieldType::Ipv4Addr),
    FieldDescriptor::new("input", "Input Interface", FieldType::U16),
    FieldDescriptor::new("output", "Output Interface", FieldType::U16),
    FieldDescriptor::new("packets", "Packets", FieldType::U32),
    FieldDescriptor::new("octets", "Octets", FieldType::U32),
    FieldDescriptor::new("first", "First", FieldType::U32),
    FieldDescriptor::new("last", "Last", FieldType::U32),
    FieldDescriptor::new("src_port", "Source Port", FieldType::U16),
    FieldDescriptor::new("dst_port", "Destination Port", FieldType::U16),
    FieldDescriptor::new("tcp_flags", "TCP Flags", FieldType::U8),
    FieldDescriptor::new("protocol", "Protocol", FieldType::U8),
    FieldDescriptor::new("tos", "Type of Service", FieldType::U8),
    FieldDescriptor::new("src_as", "Source AS", FieldType::U16),
    FieldDescriptor::new("dst_as", "Destination AS", FieldType::U16),
    FieldDescriptor::new("src_mask", "Source Mask", FieldType::U8),
    FieldDescriptor::new("dst_mask", "Destination Mask", FieldType::U8),
];

const V5R_SRC_ADDR: usize = 0;
const V5R_DST_ADDR: usize = 1;
const V5R_NEXT_HOP: usize = 2;
const V5R_INPUT: usize = 3;
const V5R_OUTPUT: usize = 4;
const V5R_PACKETS: usize = 5;
const V5R_OCTETS: usize = 6;
const V5R_FIRST: usize = 7;
const V5R_LAST: usize = 8;
const V5R_SRC_PORT: usize = 9;
const V5R_DST_PORT: usize = 10;
const V5R_TCP_FLAGS: usize = 11;
const V5R_PROTOCOL: usize = 12;
const V5R_TOS: usize = 13;
const V5R_SRC_AS: usize = 14;
const V5R_DST_AS: usize = 15;
const V5R_SRC_MASK: usize = 16;
const V5R_DST_MASK: usize = 17;

static FD_V5_RECORD: FieldDescriptor =
    FieldDescriptor::new("record", "Flow Record", FieldType::Object)
        .with_children(&V5_RECORD_CHILDREN);

/// NetFlow v5 header fields (Cisco, Table B-3).
static V5_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U16),
    FieldDescriptor::new("count", "Count", FieldType::U16),
    FieldDescriptor::new("sys_uptime", "SysUptime", FieldType::U32),
    FieldDescriptor::new("unix_secs", "UNIX Seconds", FieldType::U32),
    FieldDescriptor::new("unix_nsecs", "UNIX Nanoseconds", FieldType::U32),
    FieldDescriptor::new("flow_sequence", "Flow Sequence", FieldType::U32),
    FieldDescriptor::new("engine_type", "Engine Type", FieldType::U8),
    FieldDescriptor::new("engine_id", "Engine ID", FieldType::U8),
    FieldDescriptor::new("sampling_mode", "Sampling Mode", FieldType::U8),
    FieldDescriptor::new("sampling_interval", "Sampling Interval", FieldType::U16),
    FieldDescriptor::new("records", "Flow Records", FieldType::Array)
        .with_children(core::slice::from_ref(&FD_V5_RECORD)),
];
const V5H_VERSION: usize = 0;
const V5H_COUNT: usize = 1;
const V5H_SYS_UPTIME: usize = 2;
const V5H_ENGINE_TYPE: usize = 6;
const V5H_ENGINE_ID: usize = 7;
const V5H_SAMPLING_MODE: usize = 8;
const V5H_SAMPLING_INTERVAL: usize = 9;
const V5H_RECORDS: usize = 10;

// ---------------------------------------------------------------------------
// References
// ---------------------------------------------------------------------------

static RFC_7011: SpecReference = SpecReference::new(
    "RFC 7011",
    "Specification of the IP Flow Information Export (IPFIX) Protocol for the Exchange of Flow Information",
    "https://www.rfc-editor.org/rfc/rfc7011",
);
static RFC_7012: SpecReference = SpecReference::new(
    "RFC 7012",
    "Information Model for IP Flow Information Export (IPFIX)",
    "https://www.rfc-editor.org/rfc/rfc7012",
);
static RFC_3954: SpecReference = SpecReference::new(
    "RFC 3954",
    "Cisco Systems NetFlow Services Export Version 9",
    "https://www.rfc-editor.org/rfc/rfc3954",
);
static CISCO_V5: SpecReference = SpecReference::new(
    "Cisco NetFlow v5",
    "NetFlow Export Datagram Format",
    "https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html",
);

static IPFIX_REFERENCES: [SpecReference; 2] = [RFC_7011, RFC_7012];
static V9_REFERENCES: [SpecReference; 2] = [RFC_3954, RFC_7012];
static V5_REFERENCES: [SpecReference; 1] = [CISCO_V5];
static ALL_REFERENCES: [SpecReference; 4] = [RFC_7011, RFC_7012, RFC_3954, CISCO_V5];

// ---------------------------------------------------------------------------
// Set parsing shared by NetFlow v9 and IPFIX
// ---------------------------------------------------------------------------

/// Wire format of a Template-based export protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// IPFIX (RFC 7011, <https://www.rfc-editor.org/rfc/rfc7011>).
    Ipfix,
    /// NetFlow v9 (RFC 3954, <https://www.rfc-editor.org/rfc/rfc3954>).
    V9,
}

impl Format {
    fn set_descriptor(self) -> &'static FieldDescriptor {
        match self {
            Self::Ipfix => &FD_IPFIX_SET,
            Self::V9 => &FD_V9_FLOWSET,
        }
    }

    fn set_children(self) -> &'static [FieldDescriptor; 6] {
        match self {
            Self::Ipfix => &IPFIX_SET_CHILDREN,
            Self::V9 => &V9_FLOWSET_CHILDREN,
        }
    }

    fn record_descriptor(self) -> &'static FieldDescriptor {
        match self {
            Self::Ipfix => &FD_IPFIX_RECORD,
            Self::V9 => &FD_V9_RECORD,
        }
    }

    fn record_children(self) -> &'static [FieldDescriptor; 2] {
        match self {
            Self::Ipfix => &IPFIX_RECORD_CHILDREN,
            Self::V9 => &V9_RECORD_CHILDREN,
        }
    }

    fn template_set_id(self) -> u16 {
        match self {
            Self::Ipfix => IPFIX_TEMPLATE_SET_ID,
            Self::V9 => V9_TEMPLATE_FLOWSET_ID,
        }
    }

    fn options_template_set_id(self) -> u16 {
        match self {
            Self::Ipfix => IPFIX_OPTIONS_TEMPLATE_SET_ID,
            Self::V9 => V9_OPTIONS_TEMPLATE_FLOWSET_ID,
        }
    }
}

/// Big-endian `u16` at `pos`, if it lies before `end`.
fn u16_at(data: &[u8], pos: usize, end: usize) -> Option<u16> {
    let bytes = data.get(pos..pos.checked_add(2).filter(|&e| e <= end)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Big-endian `u32` at `pos`, if it lies before `end`.
fn u32_at(data: &[u8], pos: usize, end: usize) -> Option<u32> {
    let bytes = data.get(pos..pos.checked_add(4).filter(|&e| e <= end)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read the Field Specifier at `pos`; returns it and its encoded size.
///
/// IPFIX: RFC 7011, Section 3.2 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.2>: "If this bit is
/// one, the Information Element identifier identifies an
/// enterprise-specific Information Element, and the Enterprise Number field
/// MUST be present." NetFlow v9 field definitions are a 16-bit Field Type
/// and a 16-bit Field Length (RFC 3954, Section 5.2 —
/// <https://www.rfc-editor.org/rfc/rfc3954#section-5.2>).
fn read_spec(format: Format, data: &[u8], pos: usize, end: usize) -> Option<(FieldSpec, usize)> {
    let raw_id = u16_at(data, pos, end)?;
    let length = u16_at(data, pos + 2, end)?;
    if format == Format::Ipfix && raw_id & 0x8000 != 0 {
        let pen = u32_at(data, pos + 4, end)?;
        return Some((
            FieldSpec {
                id: raw_id & 0x7fff,
                length,
                enterprise: Some(pen),
            },
            8,
        ));
    }
    Some((
        FieldSpec {
            id: raw_id,
            length,
            enterprise: None,
        },
        4,
    ))
}

/// Iterator over `count` Field Specifiers that have already been validated
/// with [`read_spec`].
struct SpecIter<'a> {
    format: Format,
    data: &'a [u8],
    pos: usize,
    end: usize,
    remaining: usize,
}

impl Iterator for SpecIter<'_> {
    type Item = FieldSpec;

    fn next(&mut self) -> Option<FieldSpec> {
        if self.remaining == 0 {
            return None;
        }
        let (spec, size) = read_spec(self.format, self.data, self.pos, self.end)?;
        self.pos += size;
        self.remaining -= 1;
        Some(spec)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for SpecIter<'_> {}

/// Check that the Sets between `start` and `end` tile the message exactly.
///
/// RFC 7011, Section 3.3.2 — <https://www.rfc-editor.org/rfc/rfc7011#section-3.3.2>:
/// "Total length of the Set, in octets, including the Set Header, all
/// records, and the optional padding. Because an individual Set MAY contain
/// multiple records, the Length value MUST be used to determine the
/// position of the next Set." RFC 3954, Section 5.2 —
/// <https://www.rfc-editor.org/rfc/rfc3954#section-5.2> defines the FlowSet
/// Length the same way.
fn validate_sets(data: &[u8], start: usize, end: usize) -> Result<(), PacketError> {
    let mut pos = start;
    while pos < end {
        let Some(length) = u16_at(data, pos + 2, end) else {
            return Err(PacketError::InvalidHeader(
                "trailing octets shorter than a Set Header",
            ));
        };
        let length = usize::from(length);
        if length < SET_HEADER_SIZE || length > end - pos {
            return Err(PacketError::InvalidFieldValue {
                field: "set_length",
                value: length as u32,
            });
        }
        pos += length;
    }
    Ok(())
}

/// State shared by the Sets of one message.
struct SetContext<'c> {
    format: Format,
    cache: &'c mut TemplateCache,
    session: SessionKey,
    domain: u32,
    /// Absolute offset of `data[0]` in the packet.
    offset: usize,
}

impl SetContext<'_> {
    /// Absolute byte range of `start..end` within `data`.
    fn range(&self, start: usize, end: usize) -> core::ops::Range<usize> {
        self.offset + start..self.offset + end
    }

    /// Push one Set / FlowSet object per Set between `start` and `end`
    /// (already checked by [`validate_sets`]).
    fn dissect_sets<'pkt>(
        &mut self,
        data: &'pkt [u8],
        start: usize,
        end: usize,
        buf: &mut DissectBuffer<'pkt>,
    ) {
        let children = self.format.set_children();
        let mut pos = start;
        while let (Some(set_id), Some(length)) =
            (u16_at(data, pos, end), u16_at(data, pos + 2, end))
        {
            let set_end = pos + usize::from(length);
            let body = pos + SET_HEADER_SIZE;
            let idx = buf.begin_container(
                self.format.set_descriptor(),
                FieldValue::Object(0..0),
                self.range(pos, set_end),
            );
            buf.push_field(
                &children[SET_ID],
                FieldValue::U16(set_id),
                self.range(pos, pos + 2),
            );
            buf.push_field(
                &children[SET_LENGTH],
                FieldValue::U16(length),
                self.range(pos + 2, body),
            );
            if set_id == self.format.template_set_id() {
                self.dissect_template_set(data, set_id, false, body, set_end, buf);
            } else if set_id == self.format.options_template_set_id() {
                self.dissect_template_set(data, set_id, true, body, set_end, buf);
            } else if set_id >= MIN_DATA_SET_ID {
                self.dissect_data_set(data, set_id, body, set_end, buf);
            } else if body < set_end {
                // RFC 7011, Section 3.3.2 —
                // <https://www.rfc-editor.org/rfc/rfc7011#section-3.3.2>:
                // Set IDs 4-255 are "reserved for future use"; their contents
                // are not interpreted.
                buf.push_field(
                    &children[SET_DATA],
                    FieldValue::Bytes(&data[body..set_end]),
                    self.range(body, set_end),
                );
            }
            buf.end_container(idx);
            pos = set_end;
        }
    }

    /// Template Set / Options Template Set (IPFIX) or Template FlowSet /
    /// Options Template FlowSet (NetFlow v9).
    fn dissect_template_set<'pkt>(
        &mut self,
        data: &'pkt [u8],
        set_id: u16,
        options: bool,
        body: usize,
        end: usize,
        buf: &mut DissectBuffer<'pkt>,
    ) {
        // Template Records and withdrawals update the Template cache for
        // later messages (RFC 7011, Section 8 —
        // <https://www.rfc-editor.org/rfc/rfc7011#section-8>).
        buf.mark_cross_packet_state();
        let children = self.format.set_children();
        let arr = buf.begin_container(
            &children[SET_TEMPLATES],
            FieldValue::Array(0..0),
            self.range(body, end),
        );
        let mut tail = None;
        let mut pos = body;
        while pos < end {
            // RFC 7011, Section 3.3.1 —
            // <https://www.rfc-editor.org/rfc/rfc7011#section-3.3.1>:
            // "the padding octet(s) MUST be composed of octets with value zero
            // (0)." RFC 3954, Section 6.1 —
            // <https://www.rfc-editor.org/rfc/rfc3954#section-6.1>: "Padding
            // SHOULD be using zeros."
            let rest = &data[pos..end];
            if rest.iter().all(|&b| b == 0) {
                tail = Some((SET_PADDING, pos));
                break;
            }
            if rest.len() < 4 {
                tail = Some((SET_DATA, pos));
                break;
            }
            let next = match self.format {
                Format::Ipfix => self.ipfix_template_record(data, set_id, options, pos, end, buf),
                Format::V9 => self.v9_template_record(data, options, pos, end, buf),
            };
            match next {
                Some(next) => pos = next,
                None => {
                    tail = Some((SET_DATA, pos));
                    break;
                }
            }
        }
        buf.end_container(arr);
        if let Some((which, start)) = tail {
            buf.push_field(
                &children[which],
                FieldValue::Bytes(&data[start..end]),
                self.range(start, end),
            );
        }
    }

    /// One IPFIX Template Record, Options Template Record or Template
    /// Withdrawal at `pos`. Returns the position after it, or `None` (with
    /// nothing pushed) when it does not fit in the Set.
    ///
    /// RFC 7011, Sections 3.4.1, 3.4.2.2 and 8.1 —
    /// <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.1>.
    fn ipfix_template_record<'pkt>(
        &mut self,
        data: &'pkt [u8],
        set_id: u16,
        options: bool,
        pos: usize,
        end: usize,
        buf: &mut DissectBuffer<'pkt>,
    ) -> Option<usize> {
        let children = &IPFIX_TEMPLATE_CHILDREN;
        let template_id = u16_at(data, pos, end)?;
        let field_count = u16_at(data, pos + 2, end)?;

        if field_count == 0 {
            // RFC 7011, Section 8.1 —
            // <https://www.rfc-editor.org/rfc/rfc7011#section-8.1>:
            // "A Template Withdrawal consists of a Template Record for the
            // Template ID to be withdrawn, with a Field Count of 0." Template
            // ID 2 (or 3) withdraws all (Options) Templates of the Observation
            // Domain.
            let idx = buf.begin_container(
                &FD_IPFIX_TEMPLATE,
                FieldValue::Object(0..0),
                self.range(pos, pos + 4),
            );
            self.push_template_header(buf, children, template_id, field_count, pos);
            buf.end_container(idx);
            // RFC 7011, Section 8.4 —
            // <https://www.rfc-editor.org/rfc/rfc7011#section-8.4>:
            // "Template Withdrawals (Section 8.1) MUST NOT be sent by Exporting
            // Processes exporting via UDP and MUST be ignored by Collecting
            // Processes collecting via UDP."
            if self.session.transport != template::TRANSPORT_UDP {
                if template_id == set_id {
                    self.cache.withdraw_all(&self.session, self.domain, options);
                } else {
                    self.cache.withdraw(&self.session, self.domain, template_id);
                }
            }
            return Some(pos + 4);
        }

        let (header_len, scope_count) = if options {
            (6, u16_at(data, pos + 4, end)?)
        } else {
            (4, 0)
        };
        // RFC 7011, Section 3.4.2.2 —
        // <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.2.2>: "A scope
        // field count of N specifies that the first N Field Specifiers in
        // the Template Record are Scope Fields. The Scope Field Count MUST
        // NOT be zero."
        if scope_count > field_count || (options && scope_count == 0) {
            return None;
        }
        let specs_start = pos + header_len;
        let mut record_end = specs_start;
        for _ in 0..field_count {
            let (_, size) = read_spec(Format::Ipfix, data, record_end, end)?;
            record_end += size;
        }

        let idx = buf.begin_container(
            &FD_IPFIX_TEMPLATE,
            FieldValue::Object(0..0),
            self.range(pos, record_end),
        );
        self.push_template_header(buf, children, template_id, field_count, pos);
        let mut spec_pos = specs_start;
        if options {
            buf.push_field(
                &children[IT_SCOPE_FIELD_COUNT],
                FieldValue::U16(scope_count),
                self.range(pos + 4, pos + 6),
            );
            spec_pos = self.push_specs(
                buf,
                &children[IT_SCOPE_FIELDS],
                true,
                data,
                spec_pos,
                end,
                usize::from(scope_count),
            );
        }
        self.push_specs(
            buf,
            &children[IT_FIELDS],
            false,
            data,
            spec_pos,
            end,
            usize::from(field_count - scope_count),
        );
        buf.end_container(idx);

        // RFC 7011, Section 3.4.1 —
        // <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.1>:
        // "Each Template Record is given a unique Template ID in the range 256
        // to 65535."
        if template_id >= MIN_DATA_SET_ID {
            self.cache.insert(
                &self.session,
                self.domain,
                template_id,
                options.then_some(usize::from(scope_count)),
                SpecIter {
                    format: Format::Ipfix,
                    data,
                    pos: specs_start,
                    end,
                    remaining: usize::from(field_count),
                },
            );
        }
        Some(record_end)
    }

    /// One NetFlow v9 Template Record or Options Template Record at `pos`.
    /// Returns the position after it, or `None` (with nothing pushed) when
    /// it is malformed.
    ///
    /// RFC 3954, Sections 5.2 and 6.1 —
    /// <https://www.rfc-editor.org/rfc/rfc3954#section-5.2>.
    fn v9_template_record<'pkt>(
        &mut self,
        data: &'pkt [u8],
        options: bool,
        pos: usize,
        end: usize,
        buf: &mut DissectBuffer<'pkt>,
    ) -> Option<usize> {
        let children = &V9_TEMPLATE_CHILDREN;
        let template_id = u16_at(data, pos, end)?;
        let (header_len, scope_count, field_count) = if options {
            // RFC 3954, Section 6.1 —
            // <https://www.rfc-editor.org/rfc/rfc3954#section-6.1>:
            // "Option Scope Length: The length in bytes of any Scope field
            // definition contained in the Options Template Record"; each
            // definition is 4 octets.
            let scope_len = u16_at(data, pos + 2, end)?;
            let option_len = u16_at(data, pos + 4, end)?;
            if scope_len % 4 != 0 || option_len % 4 != 0 {
                return None;
            }
            (6, usize::from(scope_len / 4), usize::from(option_len / 4))
        } else {
            (4, 0, usize::from(u16_at(data, pos + 2, end)?))
        };
        let specs_start = pos + header_len;
        let record_end = specs_start + 4 * (scope_count + field_count);
        if record_end > end {
            return None;
        }

        let idx = buf.begin_container(
            &FD_V9_TEMPLATE,
            FieldValue::Object(0..0),
            self.range(pos, record_end),
        );
        buf.push_field(
            &children[VT_TEMPLATE_ID],
            FieldValue::U16(template_id),
            self.range(pos, pos + 2),
        );
        let mut spec_pos = specs_start;
        if options {
            buf.push_field(
                &children[VT_OPTION_SCOPE_LENGTH],
                FieldValue::U16((scope_count * 4) as u16),
                self.range(pos + 2, pos + 4),
            );
            buf.push_field(
                &children[VT_OPTION_LENGTH],
                FieldValue::U16((field_count * 4) as u16),
                self.range(pos + 4, pos + 6),
            );
            if scope_count > 0 {
                spec_pos = self.push_specs(
                    buf,
                    &children[VT_SCOPE_FIELDS],
                    true,
                    data,
                    spec_pos,
                    end,
                    scope_count,
                );
            }
        } else {
            buf.push_field(
                &children[VT_FIELD_COUNT],
                FieldValue::U16(field_count as u16),
                self.range(pos + 2, pos + 4),
            );
        }
        if field_count > 0 {
            self.push_specs(
                buf,
                &children[VT_FIELDS],
                false,
                data,
                spec_pos,
                end,
                field_count,
            );
        }
        buf.end_container(idx);

        // RFC 3954, Section 5.2 —
        // <https://www.rfc-editor.org/rfc/rfc3954#section-5.2>:
        // "Template IDs of Data FlowSets are numbered from 256 to 65535."
        let total = scope_count + field_count;
        if template_id >= MIN_DATA_SET_ID && total > 0 {
            self.cache.insert(
                &self.session,
                self.domain,
                template_id,
                options.then_some(scope_count),
                SpecIter {
                    format: Format::V9,
                    data,
                    pos: specs_start,
                    end,
                    remaining: total,
                },
            );
        }
        Some(record_end)
    }

    /// Template ID and Field Count of an IPFIX Template Record header.
    fn push_template_header(
        &self,
        buf: &mut DissectBuffer<'_>,
        children: &'static [FieldDescriptor; 5],
        template_id: u16,
        field_count: u16,
        pos: usize,
    ) {
        buf.push_field(
            &children[IT_TEMPLATE_ID],
            FieldValue::U16(template_id),
            self.range(pos, pos + 2),
        );
        buf.push_field(
            &children[IT_FIELD_COUNT],
            FieldValue::U16(field_count),
            self.range(pos + 2, pos + 4),
        );
    }

    /// Push `count` validated Field Specifiers as an array; returns the
    /// position after the last one.
    #[allow(clippy::too_many_arguments)]
    fn push_specs(
        &self,
        buf: &mut DissectBuffer<'_>,
        array: &'static FieldDescriptor,
        scope: bool,
        data: &[u8],
        start: usize,
        end: usize,
        count: usize,
    ) -> usize {
        let idx = buf.begin_container(array, FieldValue::Array(0..0), self.range(start, start));
        let mut pos = start;
        for _ in 0..count {
            let Some((spec, size)) = read_spec(self.format, data, pos, end) else {
                break;
            };
            let (object, children): (&'static FieldDescriptor, &'static [FieldDescriptor]) =
                match (self.format, scope) {
                    (Format::Ipfix, _) => (&FD_IPFIX_SPEC, &IPFIX_SPEC_CHILDREN),
                    (Format::V9, false) => (&FD_V9_SPEC, &V9_SPEC_CHILDREN),
                    (Format::V9, true) => (&FD_V9_SCOPE_SPEC, &V9_SCOPE_SPEC_CHILDREN),
                };
            let obj = buf.begin_container(
                object,
                FieldValue::Object(0..0),
                self.range(pos, pos + size),
            );
            buf.push_field(
                &children[SPEC_ID],
                FieldValue::U16(spec.id),
                self.range(pos, pos + 2),
            );
            buf.push_field(
                &children[SPEC_LENGTH],
                FieldValue::U16(spec.length),
                self.range(pos + 2, pos + 4),
            );
            if let Some(pen) = spec.enterprise {
                buf.push_field(
                    &IPFIX_SPEC_CHILDREN[SPEC_ENTERPRISE],
                    FieldValue::U32(pen),
                    self.range(pos + 4, pos + 8),
                );
            }
            buf.end_container(obj);
            pos += size;
        }
        buf.end_container(idx);
        if let Some(field) = buf.field_mut(idx as usize) {
            field.range = self.range(start, pos);
        }
        pos
    }

    /// Data Set: decode the Data Records with the stored Template, or keep
    /// the Set contents as raw bytes when the Template is unknown.
    ///
    /// RFC 7011, Section 3.4.3 — <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.3>:
    /// "Interpretation of the Data Record format can be done only if the
    /// Template Record corresponding to the Template ID is available at the
    /// Collecting Process."
    fn dissect_data_set<'pkt>(
        &self,
        data: &'pkt [u8],
        set_id: u16,
        body: usize,
        end: usize,
        buf: &mut DissectBuffer<'pkt>,
    ) {
        // Decoded with a Template from an earlier message, or kept raw
        // because none arrived: either way the result depends on them.
        buf.mark_cross_packet_state();
        let children = self.format.set_children();
        let template = self.cache.get(&self.session, self.domain, set_id);
        let min_record_len = template.map_or(0, |t| {
            t.fields
                .iter()
                .map(|f| match self.variable_length(f) {
                    true => 1,
                    false => usize::from(f.length),
                })
                .sum()
        });
        let Some(template) = template.filter(|_| min_record_len > 0) else {
            if body < end {
                buf.push_field(
                    &children[SET_DATA],
                    FieldValue::Bytes(&data[body..end]),
                    self.range(body, end),
                );
            }
            return;
        };

        let arr = buf.begin_container(
            &children[SET_RECORDS],
            FieldValue::Array(0..0),
            self.range(body, end),
        );
        let mut tail = None;
        let mut pos = body;
        while pos < end {
            // RFC 7011, Section 3.3.1 —
            // <https://www.rfc-editor.org/rfc/rfc7011#section-3.3.1>:
            // "The padding length MUST be shorter than any allowable record in
            // this Set."
            if end - pos < min_record_len {
                tail = Some((SET_PADDING, pos));
                break;
            }
            match self.record_end(template, data, pos, end) {
                Some(record_end) => {
                    self.push_record(template, data, pos, record_end, buf);
                    pos = record_end;
                }
                None => {
                    tail = Some((SET_DATA, pos));
                    break;
                }
            }
        }
        buf.end_container(arr);
        if let Some((which, start)) = tail {
            buf.push_field(
                &children[which],
                FieldValue::Bytes(&data[start..end]),
                self.range(start, end),
            );
        }
    }

    /// Whether `spec` is a variable-length IPFIX Information Element.
    fn variable_length(&self, spec: &FieldSpec) -> bool {
        self.format == Format::Ipfix && spec.length == VARIABLE_LENGTH
    }

    /// Range of the value of `spec` starting at `pos`.
    ///
    /// RFC 7011, Section 7 — <https://www.rfc-editor.org/rfc/rfc7011#section-7>:
    /// "The length is carried in the octet before the Information Element"
    /// and "In this case, the first octet of the Length field MUST be 255,
    /// and the length is carried in the second and third octets".
    fn value_range(
        &self,
        spec: &FieldSpec,
        data: &[u8],
        pos: usize,
        end: usize,
    ) -> Option<(usize, usize)> {
        let (start, length) = if self.variable_length(spec) {
            match *data.get(pos).filter(|_| pos < end)? {
                255 => (pos + 3, usize::from(u16_at(data, pos + 1, end)?)),
                short => (pos + 1, usize::from(short)),
            }
        } else {
            (pos, usize::from(spec.length))
        };
        let value_end = start + length;
        (value_end <= end).then_some((start, value_end))
    }

    /// End of the Data Record starting at `pos`, if it fits before `end`.
    fn record_end(
        &self,
        template: &template::Template,
        data: &[u8],
        pos: usize,
        end: usize,
    ) -> Option<usize> {
        let mut p = pos;
        for spec in &template.fields {
            p = self.value_range(spec, data, p, end)?.1;
        }
        Some(p)
    }

    /// Push one Data Record (already checked by [`Self::record_end`]).
    fn push_record<'pkt>(
        &self,
        template: &template::Template,
        data: &'pkt [u8],
        pos: usize,
        end: usize,
        buf: &mut DissectBuffer<'pkt>,
    ) {
        let children = self.format.record_children();
        let rec = buf.begin_container(
            self.format.record_descriptor(),
            FieldValue::Object(0..0),
            self.range(pos, end),
        );
        let (scope, fields) = template
            .fields
            .split_at(template.scope_count.min(template.fields.len()));
        let mut p = pos;
        if !scope.is_empty() {
            p = self.push_values(buf, &children[REC_SCOPE_FIELDS], true, scope, data, p, end);
        }
        self.push_values(buf, &children[REC_FIELDS], false, fields, data, p, end);
        buf.end_container(rec);
    }

    /// Push the values of `specs` starting at `pos` as an array; returns the
    /// position after the last value.
    #[allow(clippy::too_many_arguments)]
    fn push_values<'pkt>(
        &self,
        buf: &mut DissectBuffer<'pkt>,
        array: &'static FieldDescriptor,
        scope: bool,
        specs: &[FieldSpec],
        data: &'pkt [u8],
        start: usize,
        end: usize,
    ) -> usize {
        let idx = buf.begin_container(array, FieldValue::Array(0..0), self.range(start, start));
        let mut pos = start;
        for spec in specs {
            let Some((value_start, value_end)) = self.value_range(spec, data, pos, end) else {
                break;
            };
            let bytes = &data[value_start..value_end];
            let value_range = self.range(value_start, value_end);
            let obj = match (self.format, scope) {
                (Format::Ipfix, _) => {
                    let obj = buf.begin_container(
                        &FD_IPFIX_VALUE,
                        FieldValue::Object(0..0),
                        self.range(pos, value_end),
                    );
                    buf.push_field(
                        &IPFIX_VALUE_CHILDREN[0],
                        FieldValue::U16(spec.id),
                        value_range.clone(),
                    );
                    let data_type = match spec.enterprise {
                        Some(pen) => {
                            buf.push_field(
                                &IPFIX_VALUE_CHILDREN[1],
                                FieldValue::U32(pen),
                                value_range.clone(),
                            );
                            None
                        }
                        None => information_element(spec.id).map(|(_, t)| t),
                    };
                    buf.push_field(
                        &IPFIX_VALUE_CHILDREN[2],
                        ie::decode_value(data_type, bytes),
                        value_range,
                    );
                    obj
                }
                (Format::V9, false) => {
                    let obj = buf.begin_container(
                        &FD_V9_VALUE,
                        FieldValue::Object(0..0),
                        value_range.clone(),
                    );
                    buf.push_field(
                        &V9_VALUE_CHILDREN[0],
                        FieldValue::U16(spec.id),
                        value_range.clone(),
                    );
                    let data_type = v9_field_type(spec.id).map(|(_, t)| t);
                    buf.push_field(
                        &V9_VALUE_CHILDREN[1],
                        ie::decode_value(data_type, bytes),
                        value_range,
                    );
                    obj
                }
                (Format::V9, true) => {
                    let obj = buf.begin_container(
                        &FD_V9_SCOPE_VALUE,
                        FieldValue::Object(0..0),
                        value_range.clone(),
                    );
                    buf.push_field(
                        &V9_SCOPE_VALUE_CHILDREN[0],
                        FieldValue::U16(spec.id),
                        value_range.clone(),
                    );
                    buf.push_field(
                        &V9_SCOPE_VALUE_CHILDREN[1],
                        ie::decode_unsigned(bytes),
                        value_range,
                    );
                    obj
                }
            };
            buf.end_container(obj);
            pos = value_end;
        }
        buf.end_container(idx);
        if let Some(field) = buf.field_mut(idx as usize) {
            field.range = self.range(start, pos);
        }
        pos
    }
}

/// Push a fixed-width header field read from `data`.
fn push_header<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    descriptor: &'static FieldDescriptor,
    value: FieldValue<'pkt>,
    offset: usize,
    start: usize,
    end: usize,
) {
    buf.push_field(descriptor, value, offset + start..offset + end);
}

// ---------------------------------------------------------------------------
// Dissectors
// ---------------------------------------------------------------------------

/// IPFIX (version 10) dissector with a per-session Template cache.
///
/// A message with a Template, Options Template or Data Set reads or
/// updates the cache and calls
/// [`DissectBuffer::mark_cross_packet_state`].
#[derive(Debug, Default)]
pub struct IpfixDissector {
    templates: Mutex<TemplateCache>,
}

impl IpfixDissector {
    /// Create a dissector with an empty Template cache.
    pub fn new() -> Self {
        Self::default()
    }
}

/// NetFlow v9 dissector with a per-session Template cache.
///
/// A message with a Template, Options Template or Data FlowSet reads or
/// updates the cache and calls
/// [`DissectBuffer::mark_cross_packet_state`].
#[derive(Debug, Default)]
pub struct NetflowV9Dissector {
    templates: Mutex<TemplateCache>,
}

impl NetflowV9Dissector {
    /// Create a dissector with an empty Template cache.
    pub fn new() -> Self {
        Self::default()
    }
}

/// NetFlow v5 dissector (fixed-format records, no Templates).
#[derive(Debug, Clone, Copy, Default)]
pub struct NetflowV5Dissector;

/// NetFlow / IPFIX dissector that selects [`NetflowV5Dissector`],
/// [`NetflowV9Dissector`] or [`IpfixDissector`] by the version number in
/// the first two octets of the export packet.
///
/// NetFlow has no IANA-assigned port; use this dissector for "decode as"
/// on the collector port an exporter is configured with.
#[derive(Debug, Default)]
pub struct NetflowDissector {
    v9: NetflowV9Dissector,
    ipfix: IpfixDissector,
}

impl NetflowDissector {
    /// Create a dissector with empty Template caches.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Dissector for IpfixDissector {
    fn name(&self) -> &'static str {
        "IP Flow Information Export"
    }

    fn short_name(&self) -> &'static str {
        "IPFIX"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        IPFIX_FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        &IPFIX_REFERENCES
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
        if data.len() < IPFIX_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: IPFIX_HEADER_SIZE,
                actual: data.len(),
            });
        }
        let version = read_be_u16(data, 0)?;
        if version != IPFIX_VERSION {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }
        // RFC 7011, Section 3.1 —
        // <https://www.rfc-editor.org/rfc/rfc7011#section-3.1>:
        // "Total length of the IPFIX Message, measured in octets, including
        // Message Header and Set(s)."
        let length = read_be_u16(data, 2)?;
        let message_len = usize::from(length);
        if message_len < IPFIX_HEADER_SIZE {
            return Err(PacketError::InvalidFieldValue {
                field: "length",
                value: u32::from(length),
            });
        }
        if data.len() < message_len {
            return Err(PacketError::Truncated {
                expected: message_len,
                actual: data.len(),
            });
        }
        validate_sets(data, IPFIX_HEADER_SIZE, message_len)?;

        let export_time = read_be_u32(data, 4)?;
        let sequence = read_be_u32(data, 8)?;
        let domain = read_be_u32(data, 12)?;
        let session = SessionKey::from_buffer(buf);
        let mut cache = self
            .templates
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        let fd = IPFIX_FIELD_DESCRIPTORS;
        buf.begin_layer(self.short_name(), None, fd, offset..offset + message_len);
        push_header(buf, &fd[IH_VERSION], FieldValue::U16(version), offset, 0, 2);
        push_header(buf, &fd[IH_LENGTH], FieldValue::U16(length), offset, 2, 4);
        push_header(
            buf,
            &fd[IH_EXPORT_TIME],
            FieldValue::U32(export_time),
            offset,
            4,
            8,
        );
        push_header(
            buf,
            &fd[IH_SEQUENCE],
            FieldValue::U32(sequence),
            offset,
            8,
            12,
        );
        push_header(buf, &fd[IH_DOMAIN], FieldValue::U32(domain), offset, 12, 16);
        let sets = buf.begin_container(
            &fd[IH_SETS],
            FieldValue::Array(0..0),
            offset + IPFIX_HEADER_SIZE..offset + message_len,
        );
        SetContext {
            format: Format::Ipfix,
            cache: &mut cache,
            session,
            domain,
            offset,
        }
        .dissect_sets(data, IPFIX_HEADER_SIZE, message_len, buf);
        buf.end_container(sets);
        buf.end_layer();

        Ok(DissectResult::new(message_len, DispatchHint::End))
    }
}

impl Dissector for NetflowV9Dissector {
    fn name(&self) -> &'static str {
        "Cisco NetFlow Version 9"
    }

    fn short_name(&self) -> &'static str {
        "NetFlow-v9"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        V9_FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        &V9_REFERENCES
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
        if data.len() < NETFLOW_V9_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: NETFLOW_V9_HEADER_SIZE,
                actual: data.len(),
            });
        }
        let version = read_be_u16(data, 0)?;
        if version != NETFLOW_V9_VERSION {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }
        // The v9 header carries no packet length; the Export Packet spans
        // the whole datagram (RFC 3954, Section 3.3 —
        // <https://www.rfc-editor.org/rfc/rfc3954#section-3.3>).
        let end = data.len();
        validate_sets(data, NETFLOW_V9_HEADER_SIZE, end)?;

        let count = read_be_u16(data, 2)?;
        let sys_uptime = read_be_u32(data, 4)?;
        let unix_secs = read_be_u32(data, 8)?;
        let sequence = read_be_u32(data, 12)?;
        // RFC 3954, Section 5.1 —
        // <https://www.rfc-editor.org/rfc/rfc3954#section-5.1>:
        // "NetFlow Collectors SHOULD use the combination of the source IP
        // address and the Source ID field to separate different export streams
        // originating from the same Exporter."
        let source_id = read_be_u32(data, 16)?;
        let session = SessionKey::from_buffer(buf);
        let mut cache = self
            .templates
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        let fd = V9_FIELD_DESCRIPTORS;
        buf.begin_layer(self.short_name(), None, fd, offset..offset + end);
        push_header(buf, &fd[VH_VERSION], FieldValue::U16(version), offset, 0, 2);
        push_header(buf, &fd[VH_COUNT], FieldValue::U16(count), offset, 2, 4);
        push_header(
            buf,
            &fd[VH_SYS_UPTIME],
            FieldValue::U32(sys_uptime),
            offset,
            4,
            8,
        );
        push_header(
            buf,
            &fd[VH_UNIX_SECS],
            FieldValue::U32(unix_secs),
            offset,
            8,
            12,
        );
        push_header(
            buf,
            &fd[VH_SEQUENCE],
            FieldValue::U32(sequence),
            offset,
            12,
            16,
        );
        push_header(
            buf,
            &fd[VH_SOURCE_ID],
            FieldValue::U32(source_id),
            offset,
            16,
            20,
        );
        let flowsets = buf.begin_container(
            &fd[VH_FLOWSETS],
            FieldValue::Array(0..0),
            offset + NETFLOW_V9_HEADER_SIZE..offset + end,
        );
        SetContext {
            format: Format::V9,
            cache: &mut cache,
            session,
            domain: source_id,
            offset,
        }
        .dissect_sets(data, NETFLOW_V9_HEADER_SIZE, end, buf);
        buf.end_container(flowsets);
        buf.end_layer();

        Ok(DissectResult::new(end, DispatchHint::End))
    }
}

impl Dissector for NetflowV5Dissector {
    fn name(&self) -> &'static str {
        "Cisco NetFlow Version 5"
    }

    fn short_name(&self) -> &'static str {
        "NetFlow-v5"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        V5_FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        &V5_REFERENCES
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
        if data.len() < NETFLOW_V5_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: NETFLOW_V5_HEADER_SIZE,
                actual: data.len(),
            });
        }
        let version = read_be_u16(data, 0)?;
        if version != NETFLOW_V5_VERSION {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }
        // Cisco, Table B-3 — "count: Number of flows exported in this
        // packet (1-30)"; each flow record is 48 octets (Table B-4).
        let count = read_be_u16(data, 2)?;
        let total = NETFLOW_V5_HEADER_SIZE + usize::from(count) * NETFLOW_V5_RECORD_SIZE;
        if data.len() < total {
            return Err(PacketError::Truncated {
                expected: total,
                actual: data.len(),
            });
        }

        let fd = V5_FIELD_DESCRIPTORS;
        buf.begin_layer(self.short_name(), None, fd, offset..offset + total);
        push_header(
            buf,
            &fd[V5H_VERSION],
            FieldValue::U16(version),
            offset,
            0,
            2,
        );
        push_header(buf, &fd[V5H_COUNT], FieldValue::U16(count), offset, 2, 4);
        for (i, start) in [4usize, 8, 12, 16].into_iter().enumerate() {
            let value = read_be_u32(data, start)?;
            push_header(
                buf,
                &fd[V5H_SYS_UPTIME + i],
                FieldValue::U32(value),
                offset,
                start,
                start + 4,
            );
        }
        push_header(
            buf,
            &fd[V5H_ENGINE_TYPE],
            FieldValue::U8(data[20]),
            offset,
            20,
            21,
        );
        push_header(
            buf,
            &fd[V5H_ENGINE_ID],
            FieldValue::U8(data[21]),
            offset,
            21,
            22,
        );
        // Cisco, Table B-3 — "sampling_interval: First two bits hold the
        // sampling mode; remaining 14 bits hold value of sampling interval".
        let sampling = read_be_u16(data, 22)?;
        push_header(
            buf,
            &fd[V5H_SAMPLING_MODE],
            FieldValue::U8((sampling >> 14) as u8),
            offset,
            22,
            24,
        );
        push_header(
            buf,
            &fd[V5H_SAMPLING_INTERVAL],
            FieldValue::U16(sampling & 0x3fff),
            offset,
            22,
            24,
        );

        let records = buf.begin_container(
            &fd[V5H_RECORDS],
            FieldValue::Array(0..0),
            offset + NETFLOW_V5_HEADER_SIZE..offset + total,
        );
        let c = &V5_RECORD_CHILDREN;
        for n in 0..usize::from(count) {
            let base = NETFLOW_V5_HEADER_SIZE + n * NETFLOW_V5_RECORD_SIZE;
            let rec = &data[base..base + NETFLOW_V5_RECORD_SIZE];
            let at = offset + base;
            let obj = buf.begin_container(
                &FD_V5_RECORD,
                FieldValue::Object(0..0),
                at..at + NETFLOW_V5_RECORD_SIZE,
            );
            let r = NETFLOW_V5_RECORD_SIZE;
            let addr =
                |p: usize| FieldValue::Ipv4Addr([rec[p], rec[p + 1], rec[p + 2], rec[p + 3]]);
            let w16 = |p: usize| FieldValue::U16(u16_at(rec, p, r).unwrap_or(0));
            let w32 = |p: usize| FieldValue::U32(u32_at(rec, p, r).unwrap_or(0));
            // (descriptor index, value, start, end) per Cisco Table B-4;
            // pad1 (octet 36) and pad2 (octets 46-47) are skipped.
            let values = [
                (V5R_SRC_ADDR, addr(0), 0, 4),
                (V5R_DST_ADDR, addr(4), 4, 8),
                (V5R_NEXT_HOP, addr(8), 8, 12),
                (V5R_INPUT, w16(12), 12, 14),
                (V5R_OUTPUT, w16(14), 14, 16),
                (V5R_PACKETS, w32(16), 16, 20),
                (V5R_OCTETS, w32(20), 20, 24),
                (V5R_FIRST, w32(24), 24, 28),
                (V5R_LAST, w32(28), 28, 32),
                (V5R_SRC_PORT, w16(32), 32, 34),
                (V5R_DST_PORT, w16(34), 34, 36),
                (V5R_TCP_FLAGS, FieldValue::U8(rec[37]), 37, 38),
                (V5R_PROTOCOL, FieldValue::U8(rec[38]), 38, 39),
                (V5R_TOS, FieldValue::U8(rec[39]), 39, 40),
                (V5R_SRC_AS, w16(40), 40, 42),
                (V5R_DST_AS, w16(42), 42, 44),
                (V5R_SRC_MASK, FieldValue::U8(rec[44]), 44, 45),
                (V5R_DST_MASK, FieldValue::U8(rec[45]), 45, 46),
            ];
            for (idx, value, start, end) in values {
                buf.push_field(&c[idx], value, at + start..at + end);
            }
            buf.end_container(obj);
        }
        buf.end_container(records);
        buf.end_layer();

        Ok(DissectResult::new(total, DispatchHint::End))
    }
}

impl Dissector for NetflowDissector {
    fn name(&self) -> &'static str {
        "Cisco NetFlow / IPFIX"
    }

    fn short_name(&self) -> &'static str {
        "NetFlow"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }

    fn references(&self) -> &'static [SpecReference] {
        &ALL_REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
    }

    /// The version-specific dissectors this dispatcher delegates to.
    fn visit_sub_dissectors(&self, visit: &mut dyn FnMut(&dyn Dissector)) {
        visit(&NetflowV5Dissector);
        visit(&self.v9);
        visit(&self.ipfix);
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        let Some(version) = u16_at(data, 0, data.len()) else {
            return Err(PacketError::Truncated {
                expected: 2,
                actual: data.len(),
            });
        };
        match version {
            NETFLOW_V5_VERSION => NetflowV5Dissector.dissect(data, buf, offset),
            NETFLOW_V9_VERSION => self.v9.dissect(data, buf, offset),
            IPFIX_VERSION => self.ipfix.dissect(data, buf, offset),
            _ => Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::Range;

    // # RFC 7011 (IPFIX) Coverage
    //
    // | RFC Section | Description                                   | Test                                         |
    // |-------------|-----------------------------------------------|----------------------------------------------|
    // | 3.1         | Message Header fields                         | ipfix_header_only                            |
    // | 3.1         | Version != 10 rejected                        | ipfix_wrong_version                          |
    // | 3.1         | Length < 16 rejected                          | ipfix_length_too_small                       |
    // | 3.1         | Length beyond captured data (Truncated)       | ipfix_truncated                              |
    // | 3.1         | bytes_consumed = Length (stream framing)      | ipfix_two_messages_in_stream                 |
    // | 3.2         | Field Specifier, Enterprise bit and number    | ipfix_enterprise_specific_element            |
    // | 3.3.1       | Set padding                                   | ipfix_template_and_data_same_message         |
    // | 3.3.1       | Zero padding after Template Records           | ipfix_template_set_trailing_zero_padding     |
    // | 3.3.1       | Non-zero trailer kept as raw data             | ipfix_template_set_nonzero_trailer_raw       |
    // | 3.3.2       | Set Length < 4 / beyond message rejected      | ipfix_set_length_invalid                     |
    // | 3.3.2       | Reserved Set ID kept as raw data              | ipfix_reserved_set_id_raw                    |
    // | 3.4.1       | Template Record                               | ipfix_template_and_data_same_message         |
    // | 3.4.1       | Template ID < 256 not stored                  | ipfix_template_id_below_256_not_stored       |
    // | 3.4.1       | Truncated Template Record kept as raw data    | ipfix_malformed_template_record_raw          |
    // | 3.4.2.2     | Options Template Record, Scope Field Count    | ipfix_options_template_and_data              |
    // | 3.4.2.2     | Scope Field Count > Field Count raw           | ipfix_options_scope_count_exceeds_fields     |
    // | 3.4.2.2     | Scope Field Count 0 kept as raw data          | ipfix_options_zero_scope_count_raw           |
    // | 3.4.3       | Data Records decoded with Template            | ipfix_template_and_data_same_message         |
    // | 3.4.3       | Data Set without Template kept raw            | ipfix_data_without_template_raw              |
    // | 3.4.3       | Zero-length Template records kept raw         | ipfix_zero_length_template_raw               |
    // | 6.1         | Typed values (address, string, counters)      | ipfix_template_and_data_same_message         |
    // | 6.2         | Reduced-size encoding                         | ipfix_template_and_data_same_message         |
    // | 7           | Variable-length IE (1- and 3-octet length)    | ipfix_variable_length_element                |
    // | 7           | Variable-length overrun kept raw              | ipfix_variable_length_overrun_raw            |
    // | 8           | Template reused in later message              | ipfix_template_cached_across_messages        |
    // | 8           | Templates scoped to Observation Domain        | ipfix_template_scoped_by_domain              |
    // | 8           | Templates scoped to Transport Session         | ipfix_template_scoped_by_session             |
    // | 8.1         | Template Withdrawal / All Templates Withdrawal| ipfix_template_withdrawal                    |
    // | 8.1         | New TCP connection does not reuse Templates   | ipfix_template_scoped_by_tcp_connection      |
    // | 8.4         | Withdrawals ignored over UDP                  | ipfix_withdrawal_ignored_over_udp            |
    // | 8.4         | Template redefinition replaces old one        | ipfix_template_redefinition                  |
    // | 8           | Template / Options Template Set uses state    | ipfix_template_sets_mark_cross_packet_state  |
    // | 3.4.3       | Data Set uses state (with or without Template)| ipfix_data_set_marks_cross_packet_state      |
    // | 3.3.2       | Header-only / reserved Set uses no state      | ipfix_other_sets_mark_no_cross_packet_state  |
    //
    // # RFC 3954 (NetFlow v9) Coverage
    //
    // | RFC Section | Description                                   | Test                                         |
    // |-------------|-----------------------------------------------|----------------------------------------------|
    // | 5.1         | Packet Header fields                          | v9_template_and_data                         |
    // | 5.1         | Version != 9 / short header rejected          | v9_invalid_header                            |
    // | 5.2         | Template FlowSet                              | v9_template_and_data                         |
    // | 5.3         | Data FlowSet with padding                     | v9_template_and_data                         |
    // | 5.3         | Data FlowSet without Template kept raw        | v9_data_without_template_raw                 |
    // | 6.1         | Options Template FlowSet, scope types         | v9_options_template_and_data                 |
    // | 6.1         | Scope/Option length not multiple of 4 raw     | v9_options_bad_lengths_raw                   |
    // | 6.2         | Options Data Record                           | v9_options_template_and_data                 |
    // | 7           | Template stored for later packets             | v9_template_cached_across_packets            |
    // | 5.2         | FlowSet Length beyond packet rejected         | v9_flowset_length_invalid                    |
    // | 5.2         | Template with zero Field Count                | v9_template_zero_field_count                 |
    // | 5.2 (7012 §4) | Field types above 127 not interpreted       | v9_field_types_above_127_not_named           |
    // | 7           | Template / Options / Data FlowSet use state   | v9_flowsets_mark_cross_packet_state          |
    // | 5.1         | Header-only packet uses no state              | v9_flowsets_mark_cross_packet_state          |
    //
    // # NetFlow v5 (Cisco NetFlow Export Datagram Format) Coverage
    //
    // | Table | Description                                   | Test                                         |
    // |-------|-----------------------------------------------|----------------------------------------------|
    // | B-3   | Header, sampling mode / interval              | v5_two_records                               |
    // | B-4   | Flow records                                  | v5_two_records                               |
    // | B-3   | Count beyond captured data (Truncated)        | v5_truncated                                 |
    // | B-3   | No Templates, so no cross-packet state        | v5_marks_no_cross_packet_state               |
    // | B-3   | Version != 5 / short header rejected          | v5_invalid_header                            |
    //
    // # Version dispatch
    //
    // | Description                                   | Test                                         |
    // |-----------------------------------------------|----------------------------------------------|
    // | Version 5 / 9 / 10 routed                     | netflow_dispatches_by_version                |
    // | Unknown version / short input rejected        | netflow_rejects_unknown_version              |

    // ---------------------------------------------------------------------------
    // Builders
    // ---------------------------------------------------------------------------

    fn be16(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }

    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    /// A Set (or FlowSet) with the given ID and body.
    fn set(id: u16, body: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&be16(id));
        s.extend_from_slice(&be16((body.len() + 4) as u16));
        s.extend_from_slice(body);
        s
    }

    /// An IPFIX Field Specifier.
    fn ipfix_spec(id: u16, length: u16, enterprise: Option<u32>) -> Vec<u8> {
        let mut s = Vec::new();
        match enterprise {
            Some(pen) => {
                s.extend_from_slice(&be16(id | 0x8000));
                s.extend_from_slice(&be16(length));
                s.extend_from_slice(&be32(pen));
            }
            None => {
                s.extend_from_slice(&be16(id));
                s.extend_from_slice(&be16(length));
            }
        }
        s
    }

    /// An IPFIX Template Record.
    fn ipfix_template(id: u16, specs: &[(u16, u16, Option<u32>)]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&be16(id));
        r.extend_from_slice(&be16(specs.len() as u16));
        for &(ie, len, pen) in specs {
            r.extend_from_slice(&ipfix_spec(ie, len, pen));
        }
        r
    }

    /// An IPFIX Message with the given Observation Domain ID and Sets.
    fn ipfix_message(domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = sets.concat();
        let mut m = Vec::new();
        m.extend_from_slice(&be16(10));
        m.extend_from_slice(&be16((16 + body.len()) as u16));
        m.extend_from_slice(&be32(1_700_000_000)); // Export Time
        m.extend_from_slice(&be32(42)); // Sequence Number
        m.extend_from_slice(&be32(domain));
        m.extend_from_slice(&body);
        m
    }

    /// A NetFlow v9 Export Packet.
    fn v9_packet(source_id: u32, flowsets: &[Vec<u8>]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&be16(9));
        p.extend_from_slice(&be16(2)); // Count
        p.extend_from_slice(&be32(123_456)); // sysUpTime
        p.extend_from_slice(&be32(1_700_000_000)); // UNIX Secs
        p.extend_from_slice(&be32(7)); // Sequence Number
        p.extend_from_slice(&be32(source_id));
        for fs in flowsets {
            p.extend_from_slice(fs);
        }
        p
    }

    /// A NetFlow v9 Template Record (Field Type, Field Length pairs).
    fn v9_template(id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&be16(id));
        r.extend_from_slice(&be16(fields.len() as u16));
        for &(t, l) in fields {
            r.extend_from_slice(&be16(t));
            r.extend_from_slice(&be16(l));
        }
        r
    }

    // ---------------------------------------------------------------------------
    // Navigation helpers
    // ---------------------------------------------------------------------------

    /// Direct children of a container range (skipping grandchildren).
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

    fn layer_field<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> &'a Field<'pkt> {
        let layer = &buf.layers()[0];
        let r = layer.field_range.clone();
        child(buf, &r, name).unwrap()
    }

    /// The `i`-th set of the (only) layer, by container name.
    fn nth_set(buf: &DissectBuffer<'_>, container: &str, i: usize) -> Range<u32> {
        let sets = range_of(layer_field(buf, container));
        range_of(children(buf, &sets)[i])
    }

    /// Values of the `fields` array of record `rec` in a data set.
    fn record_values<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        set: &Range<u32>,
        rec: usize,
        array: &str,
    ) -> Vec<&'a FieldValue<'pkt>> {
        let records = range_of(child(buf, set, "records").unwrap());
        let record = range_of(children(buf, &records)[rec]);
        let fields = range_of(child(buf, &record, array).unwrap());
        children(buf, &fields)
            .into_iter()
            .map(|f| &child(buf, &range_of(f), "value").unwrap().value)
            .collect()
    }

    fn dissect_ipfix<'pkt>(
        d: &IpfixDissector,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
    ) -> DissectResult {
        buf.clear();
        d.dissect(data, buf, 0).unwrap()
    }

    /// Template 256: sourceIPv4Address(4), destinationIPv4Address(4),
    /// octetDeltaCount reduced to 4 octets, protocolIdentifier(1).
    fn flow_template() -> Vec<u8> {
        set(
            2,
            &ipfix_template(
                256,
                &[(8, 4, None), (12, 4, None), (1, 4, None), (4, 1, None)],
            ),
        )
    }

    fn flow_record(src: [u8; 4], dst: [u8; 4], octets: u32, proto: u8) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&src);
        r.extend_from_slice(&dst);
        r.extend_from_slice(&be32(octets));
        r.push(proto);
        r
    }

    // ---------------------------------------------------------------------------
    // IPFIX
    // ---------------------------------------------------------------------------

    #[test]
    fn ipfix_header_only() {
        let d = IpfixDissector::new();
        let data = ipfix_message(5, &[]);
        let mut buf = DissectBuffer::new();
        let res = dissect_ipfix(&d, &data, &mut buf);
        assert_eq!(res.bytes_consumed, 16);
        assert_eq!(res.next, DispatchHint::End);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "IPFIX");
        assert_eq!(layer.range, 0..16);
        assert_eq!(layer_field(&buf, "version").value, FieldValue::U16(10));
        assert_eq!(layer_field(&buf, "length").value, FieldValue::U16(16));
        assert_eq!(
            layer_field(&buf, "export_time").value,
            FieldValue::U32(1_700_000_000)
        );
        assert_eq!(
            layer_field(&buf, "sequence_number").value,
            FieldValue::U32(42)
        );
        assert_eq!(
            layer_field(&buf, "observation_domain_id").value,
            FieldValue::U32(5)
        );
        assert_eq!(
            range_of(layer_field(&buf, "sets")).len(),
            0,
            "no sets expected"
        );
    }

    #[test]
    fn ipfix_wrong_version() {
        let mut data = ipfix_message(0, &[]);
        data[1] = 9;
        let mut buf = DissectBuffer::new();
        assert_eq!(
            IpfixDissector::new().dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 9
            })
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn ipfix_length_too_small() {
        let mut data = ipfix_message(0, &[]);
        data[3] = 15;
        let mut buf = DissectBuffer::new();
        assert_eq!(
            IpfixDissector::new().dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "length",
                value: 15
            })
        );
    }

    #[test]
    fn ipfix_truncated() {
        let data = ipfix_message(0, &[flow_template()]);
        let mut buf = DissectBuffer::new();
        let d = IpfixDissector::new();
        assert_eq!(
            d.dissect(&data[..10], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 16,
                actual: 10
            })
        );
        assert_eq!(
            d.dissect(&data[..20], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: data.len(),
                actual: 20
            })
        );
        // A truncated message must not store its Templates.
        let data_only = ipfix_message(0, &[set(256, &flow_record([1; 4], [2; 4], 1, 6))]);
        let set0 = {
            dissect_ipfix(&d, &data_only, &mut buf);
            nth_set(&buf, "sets", 0)
        };
        assert!(child(&buf, &set0, "data").is_some());
    }

    #[test]
    fn ipfix_two_messages_in_stream() {
        let first = ipfix_message(0, &[]);
        let mut data = first.clone();
        data.extend_from_slice(&ipfix_message(0, &[]));
        let mut buf = DissectBuffer::new();
        let res = dissect_ipfix(&IpfixDissector::new(), &data, &mut buf);
        assert_eq!(res.bytes_consumed, first.len());
    }

    #[test]
    fn ipfix_template_and_data_same_message() {
        let d = IpfixDissector::new();
        let mut body = flow_record([10, 0, 0, 1], [10, 0, 0, 2], 1500, 6);
        body.extend_from_slice(&flow_record([10, 0, 0, 3], [10, 0, 0, 4], 40, 17));
        body.extend_from_slice(&[0, 0]); // padding
        let data = ipfix_message(1, &[flow_template(), set(256, &body)]);
        let mut buf = DissectBuffer::new();
        let res = dissect_ipfix(&d, &data, &mut buf);
        assert_eq!(res.bytes_consumed, data.len());

        // Template Set.
        let tset = nth_set(&buf, "sets", 0);
        assert_eq!(
            child(&buf, &tset, "set_id").unwrap().value,
            FieldValue::U16(2)
        );
        assert_eq!(
            buf.resolve_nested_display_name(&tset, "set_id_name"),
            Some("Template Set")
        );
        assert_eq!(
            child(&buf, &tset, "length").unwrap().value,
            FieldValue::U16(4 + 4 + 16)
        );
        let templates = range_of(child(&buf, &tset, "templates").unwrap());
        let tmpl = range_of(children(&buf, &templates)[0]);
        assert_eq!(
            child(&buf, &tmpl, "template_id").unwrap().value,
            FieldValue::U16(256)
        );
        assert_eq!(
            child(&buf, &tmpl, "field_count").unwrap().value,
            FieldValue::U16(4)
        );
        assert!(child(&buf, &tmpl, "scope_field_count").is_none());
        let specs = range_of(child(&buf, &tmpl, "fields").unwrap());
        let specs = children(&buf, &specs);
        assert_eq!(specs.len(), 4);
        let spec0 = range_of(specs[0]);
        assert_eq!(
            child(&buf, &spec0, "element_id").unwrap().value,
            FieldValue::U16(8)
        );
        assert_eq!(
            buf.resolve_nested_display_name(&spec0, "element_id_name"),
            Some("sourceIPv4Address")
        );
        assert_eq!(
            child(&buf, &spec0, "field_length").unwrap().value,
            FieldValue::U16(4)
        );
        assert!(child(&buf, &spec0, "enterprise_number").is_none());
        assert_eq!(specs[0].range, 24..28);

        // Data Set.
        let dset = nth_set(&buf, "sets", 1);
        assert_eq!(
            buf.resolve_nested_display_name(&dset, "set_id_name"),
            Some("Data Set")
        );
        assert!(child(&buf, &dset, "data").is_none());
        assert_eq!(
            child(&buf, &dset, "padding").unwrap().value,
            FieldValue::Bytes(&[0, 0])
        );
        let r0 = record_values(&buf, &dset, 0, "fields");
        assert_eq!(
            r0,
            vec![
                &FieldValue::Ipv4Addr([10, 0, 0, 1]),
                &FieldValue::Ipv4Addr([10, 0, 0, 2]),
                &FieldValue::U32(1500),
                &FieldValue::U8(6),
            ]
        );
        let r1 = record_values(&buf, &dset, 1, "fields");
        assert_eq!(r1[2], &FieldValue::U32(40));
        assert_eq!(r1[3], &FieldValue::U8(17));

        // Field value objects carry the element ID and name; the value range
        // points at the value octets.
        let records = range_of(child(&buf, &dset, "records").unwrap());
        let rec0 = range_of(children(&buf, &records)[0]);
        assert!(child(&buf, &rec0, "scope_fields").is_none());
        let fields = range_of(child(&buf, &rec0, "fields").unwrap());
        let f0 = range_of(children(&buf, &fields)[0]);
        assert_eq!(
            buf.resolve_nested_display_name(&f0, "element_id_name"),
            Some("sourceIPv4Address")
        );
        let dset_start = 16 + 24;
        assert_eq!(
            child(&buf, &f0, "value").unwrap().range,
            dset_start + 4..dset_start + 8
        );
    }

    #[test]
    fn ipfix_data_without_template_raw() {
        let rec = flow_record([1; 4], [2; 4], 3, 6);
        let data = ipfix_message(0, &[set(300, &rec)]);
        let mut buf = DissectBuffer::new();
        dissect_ipfix(&IpfixDissector::new(), &data, &mut buf);
        let dset = nth_set(&buf, "sets", 0);
        assert_eq!(
            child(&buf, &dset, "data").unwrap().value,
            FieldValue::Bytes(&rec)
        );
        assert!(child(&buf, &dset, "records").is_none());
    }

    #[test]
    fn ipfix_template_cached_across_messages() {
        let d = IpfixDissector::new();
        let mut buf = DissectBuffer::new();
        let tmpl = ipfix_message(1, &[flow_template()]);
        dissect_ipfix(&d, &tmpl, &mut buf);

        let data = ipfix_message(1, &[set(256, &flow_record([1; 4], [2; 4], 3, 6))]);
        dissect_ipfix(&d, &data, &mut buf);
        let dset = nth_set(&buf, "sets", 0);
        assert_eq!(
            record_values(&buf, &dset, 0, "fields")[0],
            &FieldValue::Ipv4Addr([1; 4])
        );
    }

    #[test]
    fn ipfix_template_scoped_by_domain() {
        let d = IpfixDissector::new();
        let mut buf = DissectBuffer::new();
        let msg1 = ipfix_message(1, &[flow_template()]);

        dissect_ipfix(&d, &msg1, &mut buf);
        let data = ipfix_message(2, &[set(256, &flow_record([1; 4], [2; 4], 3, 6))]);
        dissect_ipfix(&d, &data, &mut buf);
        let dset = nth_set(&buf, "sets", 0);
        assert!(child(&buf, &dset, "data").is_some());
    }

    static TEST_TRANSPORT_FIELDS: &[FieldDescriptor] = &[
        FieldDescriptor::new("src_port", "Source Port", FieldType::U16),
        FieldDescriptor::new("dst_port", "Destination Port", FieldType::U16),
    ];
    static TEST_IP_FIELDS: &[FieldDescriptor] = &[
        FieldDescriptor::new("src", "Source", FieldType::Ipv4Addr),
        FieldDescriptor::new("dst", "Destination", FieldType::Ipv4Addr),
    ];
    static TEST_IPV6_FIELDS: &[FieldDescriptor] = &[
        FieldDescriptor::new("src", "Source", FieldType::Ipv6Addr),
        FieldDescriptor::new("dst", "Destination", FieldType::Ipv6Addr),
    ];

    /// Push fake IPv4 and transport layers so the dissector sees a session.
    fn push_session(
        buf: &mut DissectBuffer<'_>,
        transport: &'static str,
        src: [u8; 4],
        sport: u16,
    ) {
        buf.begin_layer("IPv4", None, TEST_IP_FIELDS, 0..0);
        buf.push_field(&TEST_IP_FIELDS[0], FieldValue::Ipv4Addr(src), 0..0);
        buf.push_field(
            &TEST_IP_FIELDS[1],
            FieldValue::Ipv4Addr([192, 0, 2, 1]),
            0..0,
        );
        buf.end_layer();
        buf.begin_layer(transport, None, TEST_TRANSPORT_FIELDS, 0..0);
        buf.push_field(&TEST_TRANSPORT_FIELDS[0], FieldValue::U16(sport), 0..0);
        buf.push_field(&TEST_TRANSPORT_FIELDS[1], FieldValue::U16(4739), 0..0);
        buf.end_layer();
    }

    /// Dissect `data` as if received on the given session; returns the IPFIX
    /// (last) layer's sets container range.
    fn dissect_on_session<'pkt>(
        d: &dyn Dissector,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        transport: &'static str,
        src: [u8; 4],
        sport: u16,
    ) {
        buf.clear();
        push_session(buf, transport, src, sport);
        d.dissect(data, buf, 0).unwrap();
    }

    fn last_layer_first_set(buf: &DissectBuffer<'_>, container: &str) -> Range<u32> {
        let layer = buf.layers().last().unwrap();
        let r = layer.field_range.clone();
        let sets = range_of(child(buf, &r, container).unwrap());
        range_of(children(buf, &sets)[0])
    }

    #[test]
    fn ipfix_template_scoped_by_session() {
        let d = IpfixDissector::new();
        let mut buf = DissectBuffer::new();
        let tmpl = ipfix_message(1, &[flow_template()]);
        let data = ipfix_message(1, &[set(256, &flow_record([1; 4], [2; 4], 3, 6))]);
        dissect_on_session(&d, &tmpl, &mut buf, "UDP", [198, 51, 100, 1], 50000);

        // Same exporter and ports: decoded.
        dissect_on_session(&d, &data, &mut buf, "UDP", [198, 51, 100, 1], 50000);
        let dset = last_layer_first_set(&buf, "sets");
        assert!(child(&buf, &dset, "records").is_some());

        // Different exporter address or port, or another transport: raw.
        for (transport, src, sport) in [
            ("UDP", [198, 51, 100, 2], 50000),
            ("UDP", [198, 51, 100, 1], 50001),
            ("TCP", [198, 51, 100, 1], 50000),
            ("SCTP", [198, 51, 100, 1], 50000),
        ] {
            dissect_on_session(&d, &data, &mut buf, transport, src, sport);
            let dset = last_layer_first_set(&buf, "sets");
            assert!(
                child(&buf, &dset, "data").is_some(),
                "{transport} {src:?} {sport}"
            );
        }

        // IPv6 exporters are keyed by their address as well.
        buf.clear();
        buf.begin_layer("IPv6", None, TEST_IPV6_FIELDS, 0..0);
        buf.push_field(&TEST_IPV6_FIELDS[0], FieldValue::Ipv6Addr([1; 16]), 0..0);
        buf.push_field(&TEST_IPV6_FIELDS[1], FieldValue::Ipv6Addr([2; 16]), 0..0);
        buf.end_layer();
        d.dissect(&tmpl, &mut buf, 0).unwrap();
        buf.clear();
        buf.begin_layer("IPv6", None, TEST_IPV6_FIELDS, 0..0);
        buf.push_field(&TEST_IPV6_FIELDS[0], FieldValue::Ipv6Addr([1; 16]), 0..0);
        buf.push_field(&TEST_IPV6_FIELDS[1], FieldValue::Ipv6Addr([2; 16]), 0..0);
        buf.end_layer();
        d.dissect(&data, &mut buf, 0).unwrap();
        let dset = last_layer_first_set(&buf, "sets");
        assert!(child(&buf, &dset, "records").is_some());
    }

    #[test]
    fn ipfix_enterprise_specific_element() {
        let d = IpfixDissector::new();
        // Template 257: enterprise element 5 of PEN 9 (2 octets), then
        // IANA protocolIdentifier.
        let tmpl = set(2, &ipfix_template(257, &[(5, 2, Some(9)), (4, 1, None)]));
        let data = ipfix_message(0, &[tmpl, set(257, &[0xab, 0xcd, 17, 0])]);
        let mut buf = DissectBuffer::new();
        dissect_ipfix(&d, &data, &mut buf);

        let tset = nth_set(&buf, "sets", 0);
        let templates = range_of(child(&buf, &tset, "templates").unwrap());
        let tmpl = range_of(children(&buf, &templates)[0]);
        let specs = range_of(child(&buf, &tmpl, "fields").unwrap());
        let spec0 = range_of(children(&buf, &specs)[0]);
        assert_eq!(
            child(&buf, &spec0, "element_id").unwrap().value,
            FieldValue::U16(5)
        );
        assert_eq!(
            child(&buf, &spec0, "enterprise_number").unwrap().value,
            FieldValue::U32(9)
        );
        // Not an IANA element, so no name even though IANA element 5 exists.
        assert_eq!(
            buf.resolve_nested_display_name(&spec0, "element_id_name"),
            None
        );

        let dset = nth_set(&buf, "sets", 1);
        let values = record_values(&buf, &dset, 0, "fields");
        assert_eq!(values[0], &FieldValue::Bytes(&[0xab, 0xcd]));
        assert_eq!(values[1], &FieldValue::U8(17));
        let records = range_of(child(&buf, &dset, "records").unwrap());
        let rec0 = range_of(children(&buf, &records)[0]);
        let fields = range_of(child(&buf, &rec0, "fields").unwrap());
        let f0 = range_of(children(&buf, &fields)[0]);
        assert_eq!(
            child(&buf, &f0, "enterprise_number").unwrap().value,
            FieldValue::U32(9)
        );
        // Trailing single zero octet is padding (shorter than a record).
        assert_eq!(
            child(&buf, &dset, "padding").unwrap().value,
            FieldValue::Bytes(&[0])
        );
    }

    #[test]
    fn ipfix_variable_length_element() {
        let d = IpfixDissector::new();
        // interfaceName (82, string) is variable length; ingressInterface (10).
        let tmpl = set(2, &ipfix_template(258, &[(82, 65535, None), (10, 4, None)]));
        let mut body = vec![4];
        body.extend_from_slice(b"eth0");
        body.extend_from_slice(&be32(1));
        body.extend_from_slice(&[255, 0, 4]);
        body.extend_from_slice(b"eth1");
        body.extend_from_slice(&be32(2));
        let data = ipfix_message(0, &[tmpl, set(258, &body)]);
        let mut buf = DissectBuffer::new();
        dissect_ipfix(&d, &data, &mut buf);
        let dset = nth_set(&buf, "sets", 1);
        assert_eq!(
            record_values(&buf, &dset, 0, "fields"),
            vec![&FieldValue::Str("eth0"), &FieldValue::U32(1)]
        );
        assert_eq!(
            record_values(&buf, &dset, 1, "fields"),
            vec![&FieldValue::Str("eth1"), &FieldValue::U32(2)]
        );
        // The value range excludes the length octet(s).
        let records = range_of(child(&buf, &dset, "records").unwrap());
        let rec1 = range_of(children(&buf, &records)[1]);
        let fields = range_of(child(&buf, &rec1, "fields").unwrap());
        let f0 = range_of(children(&buf, &fields)[0]);
        let start = 16 + 4 + 12 + 4 + 9 + 3;
        assert_eq!(child(&buf, &f0, "value").unwrap().range, start..start + 4);
        assert!(child(&buf, &dset, "padding").is_none());
    }

    #[test]
    fn ipfix_variable_length_overrun_raw() {
        let d = IpfixDissector::new();
        let tmpl = set(2, &ipfix_template(258, &[(82, 65535, None)]));
        // First record fine, second claims 10 octets with 3 present.
        let body = [1, b'a', 10, b'x', b'y', b'z'];
        let data = ipfix_message(0, &[tmpl, set(258, &body)]);
        let mut buf = DissectBuffer::new();
        dissect_ipfix(&d, &data, &mut buf);
        let dset = nth_set(&buf, "sets", 1);
        assert_eq!(
            record_values(&buf, &dset, 0, "fields"),
            vec![&FieldValue::Str("a")]
        );
        assert_eq!(
            child(&buf, &dset, "data").unwrap().value,
            FieldValue::Bytes(&[10, b'x', b'y', b'z'])
        );

        // A 3-octet length prefix cut short.
        let data = ipfix_message(0, &[set(258, &[255, 0])]);
        dissect_ipfix(&d, &data, &mut buf);
        let dset = nth_set(&buf, "sets", 0);
        assert_eq!(
            child(&buf, &dset, "data").unwrap().value,
            FieldValue::Bytes(&[255, 0])
        );
    }

    #[test]
    fn ipfix_options_template_and_data() {
        let d = IpfixDissector::new();
        // Options Template 259: scope observationDomainId (149), options
        // exportedMessageTotalCount (41) and exportedFlowRecordTotalCount (42).
        let mut rec = Vec::new();
        rec.extend_from_slice(&be16(259));
        rec.extend_from_slice(&be16(3)); // Field Count
        rec.extend_from_slice(&be16(1)); // Scope Field Count
        rec.extend_from_slice(&ipfix_spec(149, 4, None));
        rec.extend_from_slice(&ipfix_spec(41, 8, None));
        rec.extend_from_slice(&ipfix_spec(42, 8, None));
        rec.extend_from_slice(&[0, 0]); // padding to 4-octet boundary
        let mut body = Vec::new();
        body.extend_from_slice(&be32(7));
        body.extend_from_slice(&100u64.to_be_bytes());
        body.extend_from_slice(&2000u64.to_be_bytes());
        let data = ipfix_message(7, &[set(3, &rec), set(259, &body)]);
        let mut buf = DissectBuffer::new();
        dissect_ipfix(&d, &data, &mut buf);

        let tset = nth_set(&buf, "sets", 0);
        assert_eq!(
            buf.resolve_nested_display_name(&tset, "set_id_name"),
            Some("Options Template Set")
        );
        let templates = range_of(child(&buf, &tset, "templates").unwrap());
        let tmpl = range_of(children(&buf, &templates)[0]);
        assert_eq!(
            child(&buf, &tmpl, "scope_field_count").unwrap().value,
            FieldValue::U16(1)
        );
        let scope = range_of(child(&buf, &tmpl, "scope_fields").unwrap());
        assert_eq!(children(&buf, &scope).len(), 1);
        let opts = range_of(child(&buf, &tmpl, "fields").unwrap());
        assert_eq!(children(&buf, &opts).len(), 2);
        assert_eq!(
            child(&buf, &tset, "padding").unwrap().value,
            FieldValue::Bytes(&[0, 0])
        );

        let dset = nth_set(&buf, "sets", 1);
        assert_eq!(
            record_values(&buf, &dset, 0, "scope_fields"),
            vec![&FieldValue::U32(7)]
        );
        assert_eq!(
            record_values(&buf, &dset, 0, "fields"),
            vec![&FieldValue::U64(100), &FieldValue::U64(2000)]
        );
    }

    #[test]
    fn ipfix_options_scope_count_exceeds_fields() {
        let mut rec = Vec::new();
        rec.extend_from_slice(&be16(259));
        rec.extend_from_slice(&be16(1)); // Field Count
        rec.extend_from_slice(&be16(2)); // Scope Field Count > Field Count
        rec.extend_from_slice(&ipfix_spec(149, 4, None));
        let data = ipfix_message(0, &[set(3, &rec)]);
        let mut buf = DissectBuffer::new();
        let d = IpfixDissector::new();
        dissect_ipfix(&d, &data, &mut buf);
        let tset = nth_set(&buf, "sets", 0);
        assert_eq!(
            child(&buf, &tset, "data").unwrap().value,
            FieldValue::Bytes(&rec)
        );
        // Not stored.
        let data_set = ipfix_message(0, &[set(259, &[0; 4])]);
        dissect_ipfix(&d, &data_set, &mut buf);
        let dset = nth_set(&buf, "sets", 0);
        assert!(child(&buf, &dset, "data").is_some());

        // Options Template header cut short (needs 6 octets).
        let data = ipfix_message(0, &[set(3, &[1, 3, 0, 1, 0])]);
        dissect_ipfix(&d, &data, &mut buf);
        let tset = nth_set(&buf, "sets", 0);
        assert!(child(&buf, &tset, "data").is_some());
    }

    #[test]
    fn ipfix_malformed_template_record_raw() {
        // Field Count 3 but only one Field Specifier present.
        let mut rec = Vec::new();
        rec.extend_from_slice(&be16(256));
        rec.extend_from_slice(&be16(3));
        rec.extend_from_slice(&ipfix_spec(8, 4, None));
        // An enterprise Field Specifier missing its Enterprise Number.
        let mut rec2 = Vec::new();
        rec2.extend_from_slice(&be16(257));
        rec2.extend_from_slice(&be16(1));
        rec2.extend_from_slice(&be16(0x8001));
        rec2.extend_from_slice(&be16(4));
        let d = IpfixDissector::new();
        for rec in [rec, rec2] {
            let data = ipfix_message(0, &[set(2, &rec)]);
            let mut buf = DissectBuffer::new();
            dissect_ipfix(&d, &data, &mut buf);
            let tset = nth_set(&buf, "sets", 0);
            let templates = range_of(child(&buf, &tset, "templates").unwrap());
            assert!(children(&buf, &templates).is_empty());
            assert_eq!(
                child(&buf, &tset, "data").unwrap().value,
                FieldValue::Bytes(&rec)
            );
        }
    }

    #[test]
    fn ipfix_template_id_below_256_not_stored() {
        let d = IpfixDissector::new();
        let mut buf = DissectBuffer::new();
        let tmpl = set(2, &ipfix_template(100, &[(4, 1, None)]));
        let msg2 = ipfix_message(0, &[tmpl]);

        dissect_ipfix(&d, &msg2, &mut buf);
        let tset = nth_set(&buf, "sets", 0);
        let templates = range_of(child(&buf, &tset, "templates").unwrap());
        assert_eq!(children(&buf, &templates).len(), 1);
        assert!(
            d.templates
                .lock()
                .unwrap()
                .get(&SessionKey::default(), 0, 100)
                .is_none()
        );
    }

    #[test]
    fn ipfix_reserved_set_id_raw() {
        let data = ipfix_message(0, &[set(4, &[1, 2, 3, 4]), set(0, &[])]);
        let mut buf = DissectBuffer::new();
        dissect_ipfix(&IpfixDissector::new(), &data, &mut buf);
        let s0 = nth_set(&buf, "sets", 0);
        assert_eq!(
            buf.resolve_nested_display_name(&s0, "set_id_name"),
            Some("Reserved")
        );
        assert_eq!(
            child(&buf, &s0, "data").unwrap().value,
            FieldValue::Bytes(&[1, 2, 3, 4])
        );
        // An empty Set has no data field.
        let s1 = nth_set(&buf, "sets", 1);
        assert!(child(&buf, &s1, "data").is_none());
    }

    #[test]
    fn ipfix_set_length_invalid() {
        let d = IpfixDissector::new();
        // Set Length 2 (< Set Header).
        let mut data = ipfix_message(0, &[set(256, &[1, 2, 3, 4])]);
        data[19] = 2;
        assert_eq!(
            d.dissect(&data, &mut DissectBuffer::new(), 0),
            Err(PacketError::InvalidFieldValue {
                field: "set_length",
                value: 2
            })
        );
        // Set Length beyond the message.
        data[19] = 12;
        assert_eq!(
            d.dissect(&data, &mut DissectBuffer::new(), 0),
            Err(PacketError::InvalidFieldValue {
                field: "set_length",
                value: 12
            })
        );
        // Fewer than 4 octets left for a Set Header.
        let mut data = ipfix_message(0, &[vec![0, 0]]);
        data.truncate(18);
        assert_eq!(
            d.dissect(&data, &mut DissectBuffer::new(), 0),
            Err(PacketError::InvalidHeader(
                "trailing octets shorter than a Set Header"
            ))
        );
    }

    #[test]
    fn ipfix_zero_length_template_raw() {
        let d = IpfixDissector::new();
        let tmpl = set(2, &ipfix_template(260, &[(210, 0, None)]));
        let data = ipfix_message(0, &[tmpl, set(260, &[1, 2])]);
        let mut buf = DissectBuffer::new();
        dissect_ipfix(&d, &data, &mut buf);
        let dset = nth_set(&buf, "sets", 1);
        assert_eq!(
            child(&buf, &dset, "data").unwrap().value,
            FieldValue::Bytes(&[1, 2])
        );
    }

    #[test]
    fn ipfix_template_withdrawal() {
        let d = IpfixDissector::new();
        let mut buf = DissectBuffer::new();
        let rec = || set(256, &flow_record([1; 4], [2; 4], 3, 6));
        // Template, withdrawal of 256, then data: raw.
        let withdraw = set(2, &[1, 0, 0, 0]);
        let data = ipfix_message(0, &[flow_template(), withdraw, rec()]);
        dissect_ipfix(&d, &data, &mut buf);
        let wset = nth_set(&buf, "sets", 1);
        let templates = range_of(child(&buf, &wset, "templates").unwrap());
        let w = range_of(children(&buf, &templates)[0]);
        assert_eq!(
            child(&buf, &w, "field_count").unwrap().value,
            FieldValue::U16(0)
        );
        assert!(child(&buf, &w, "fields").is_none());
        assert!(child(&buf, &nth_set(&buf, "sets", 2), "data").is_some());

        // All Templates Withdrawal (Template ID 2) keeps Options Templates.
        let mut opt = Vec::new();
        opt.extend_from_slice(&be16(300));
        opt.extend_from_slice(&be16(1));
        opt.extend_from_slice(&be16(1));
        opt.extend_from_slice(&ipfix_spec(149, 4, None));
        let data = ipfix_message(
            0,
            &[
                flow_template(),
                set(3, &opt),
                set(2, &[0, 2, 0, 0]),
                rec(),
                set(300, &be32(9)),
            ],
        );
        dissect_ipfix(&d, &data, &mut buf);
        assert!(child(&buf, &nth_set(&buf, "sets", 3), "data").is_some());
        assert!(child(&buf, &nth_set(&buf, "sets", 4), "records").is_some());

        // All Options Templates Withdrawal (Template ID 3).
        let data = ipfix_message(0, &[set(3, &[0, 3, 0, 0]), set(300, &be32(9))]);
        dissect_ipfix(&d, &data, &mut buf);
        assert!(child(&buf, &nth_set(&buf, "sets", 1), "data").is_some());
    }

    #[test]
    fn ipfix_withdrawal_ignored_over_udp() {
        let d = IpfixDissector::new();
        let mut buf = DissectBuffer::new();
        let src = [198, 51, 100, 1];
        let data = ipfix_message(
            0,
            &[
                flow_template(),
                set(2, &[1, 0, 0, 0]),
                set(256, &flow_record([1; 4], [2; 4], 3, 6)),
            ],
        );
        dissect_on_session(&d, &data, &mut buf, "UDP", src, 1000);
        let layer = buf.layers().last().unwrap();
        let r = layer.field_range.clone();
        let sets = range_of(child(&buf, &r, "sets").unwrap());
        let dset = range_of(children(&buf, &sets)[2]);
        assert!(child(&buf, &dset, "records").is_some());

        // Over TCP the withdrawal applies.
        dissect_on_session(&d, &data, &mut buf, "TCP", src, 1000);
        let layer = buf.layers().last().unwrap();
        let r = layer.field_range.clone();
        let sets = range_of(child(&buf, &r, "sets").unwrap());
        let dset = range_of(children(&buf, &sets)[2]);
        assert!(child(&buf, &dset, "data").is_some());
    }

    #[test]
    fn ipfix_template_redefinition() {
        let d = IpfixDissector::new();
        let mut buf = DissectBuffer::new();
        let msg3 = ipfix_message(0, &[flow_template()]);

        dissect_ipfix(&d, &msg3, &mut buf);
        let redefined = set(2, &ipfix_template(256, &[(4, 1, None)]));
        let msg4 = ipfix_message(0, &[redefined]);

        dissect_ipfix(&d, &msg4, &mut buf);
        let msg5 = ipfix_message(0, &[set(256, &[6, 17])]);

        dissect_ipfix(&d, &msg5, &mut buf);
        let dset = nth_set(&buf, "sets", 0);
        assert_eq!(
            record_values(&buf, &dset, 1, "fields"),
            vec![&FieldValue::U8(17)]
        );
    }

    #[test]
    fn ipfix_template_set_trailing_zero_padding() {
        let mut body = ipfix_template(256, &[(4, 1, None)]);
        body.extend_from_slice(&[0, 0, 0, 0]);
        let data = ipfix_message(0, &[set(2, &body)]);
        let mut buf = DissectBuffer::new();
        dissect_ipfix(&IpfixDissector::new(), &data, &mut buf);
        let tset = nth_set(&buf, "sets", 0);
        let templates = range_of(child(&buf, &tset, "templates").unwrap());
        assert_eq!(children(&buf, &templates).len(), 1);
        assert_eq!(
            child(&buf, &tset, "padding").unwrap().value,
            FieldValue::Bytes(&[0, 0, 0, 0])
        );
    }

    #[test]
    fn ipfix_metadata() {
        let d = IpfixDissector::new();
        assert_eq!(d.name(), "IP Flow Information Export");
        assert_eq!(d.short_name(), "IPFIX");
        assert_eq!(d.layer(), Some(ProtocolLayer::Application));
        assert_eq!(d.references()[0].id, "RFC 7011");
        assert_eq!(d.field_descriptors()[IH_SETS].name, "sets");
        assert_eq!(IPFIX_PORT, 4739);
    }

    // ---------------------------------------------------------------------------
    // NetFlow v9
    // ---------------------------------------------------------------------------

    #[test]
    fn v9_template_and_data() {
        let d = NetflowV9Dissector::new();
        // IN_BYTES(1)=4, IPV4_SRC_ADDR(8)=4, L4_SRC_PORT(7)=2.
        let tmpl = set(0, &v9_template(256, &[(1, 4), (8, 4), (7, 2)]));
        let mut body = Vec::new();
        body.extend_from_slice(&be32(999));
        body.extend_from_slice(&[10, 1, 1, 1]);
        body.extend_from_slice(&be16(443));
        body.extend_from_slice(&[0, 0]); // padding to 4 octets
        let data = v9_packet(3, &[tmpl, set(256, &body)]);
        let mut buf = DissectBuffer::new();
        let res = d.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(res.bytes_consumed, data.len());
        assert_eq!(buf.layers()[0].name, "NetFlow-v9");
        assert_eq!(layer_field(&buf, "version").value, FieldValue::U16(9));
        assert_eq!(layer_field(&buf, "count").value, FieldValue::U16(2));
        assert_eq!(
            layer_field(&buf, "sys_uptime").value,
            FieldValue::U32(123_456)
        );
        assert_eq!(
            layer_field(&buf, "unix_secs").value,
            FieldValue::U32(1_700_000_000)
        );
        assert_eq!(
            layer_field(&buf, "sequence_number").value,
            FieldValue::U32(7)
        );
        assert_eq!(layer_field(&buf, "source_id").value, FieldValue::U32(3));

        let tset = nth_set(&buf, "flowsets", 0);
        assert_eq!(
            buf.resolve_nested_display_name(&tset, "flowset_id_name"),
            Some("Template FlowSet")
        );
        let templates = range_of(child(&buf, &tset, "templates").unwrap());
        let t = range_of(children(&buf, &templates)[0]);
        let fields = range_of(child(&buf, &t, "fields").unwrap());
        let f0 = range_of(children(&buf, &fields)[0]);
        assert_eq!(
            child(&buf, &f0, "field_type").unwrap().value,
            FieldValue::U16(1)
        );
        assert_eq!(
            buf.resolve_nested_display_name(&f0, "field_type_name"),
            Some("octetDeltaCount")
        );

        let dset = nth_set(&buf, "flowsets", 1);
        assert_eq!(
            buf.resolve_nested_display_name(&dset, "flowset_id_name"),
            Some("Data FlowSet")
        );
        assert_eq!(
            record_values(&buf, &dset, 0, "fields"),
            vec![
                &FieldValue::U32(999),
                &FieldValue::Ipv4Addr([10, 1, 1, 1]),
                &FieldValue::U16(443)
            ]
        );
        assert_eq!(
            child(&buf, &dset, "padding").unwrap().value,
            FieldValue::Bytes(&[0, 0])
        );
    }

    #[test]
    fn v9_data_without_template_raw() {
        let data = v9_packet(0, &[set(260, &[1, 2, 3, 4])]);
        let mut buf = DissectBuffer::new();
        NetflowV9Dissector::new()
            .dissect(&data, &mut buf, 0)
            .unwrap();
        let dset = nth_set(&buf, "flowsets", 0);
        assert_eq!(
            child(&buf, &dset, "data").unwrap().value,
            FieldValue::Bytes(&[1, 2, 3, 4])
        );
    }

    #[test]
    fn v9_template_cached_across_packets() {
        let d = NetflowV9Dissector::new();
        let mut buf = DissectBuffer::new();
        let tmpl = v9_packet(1, &[set(0, &v9_template(256, &[(4, 1)]))]);
        d.dissect(&tmpl, &mut buf, 0).unwrap();
        buf.clear();
        let data = v9_packet(1, &[set(256, &[6, 17, 0, 0])]);
        d.dissect(&data, &mut buf, 0).unwrap();
        let dset = nth_set(&buf, "flowsets", 0);
        assert_eq!(
            record_values(&buf, &dset, 3, "fields"),
            vec![&FieldValue::U8(0)]
        );
        // Another Source ID does not share Templates.
        buf.clear();
        let data = v9_packet(2, &[set(256, &[6, 17, 0, 0])]);
        d.dissect(&data, &mut buf, 0).unwrap();
        assert!(child(&buf, &nth_set(&buf, "flowsets", 0), "data").is_some());
    }

    #[test]
    fn v9_options_template_and_data() {
        let d = NetflowV9Dissector::new();
        // Options Template 257: scope System (1) length 4; options
        // SAMPLING_INTERVAL (34) length 4, SAMPLING_ALGORITHM (35) length 1.
        let mut rec = Vec::new();
        rec.extend_from_slice(&be16(257));
        rec.extend_from_slice(&be16(4)); // Option Scope Length
        rec.extend_from_slice(&be16(8)); // Option Length
        rec.extend_from_slice(&be16(1));
        rec.extend_from_slice(&be16(4));
        rec.extend_from_slice(&be16(34));
        rec.extend_from_slice(&be16(4));
        rec.extend_from_slice(&be16(35));
        rec.extend_from_slice(&be16(1));
        rec.extend_from_slice(&[0, 0]); // padding
        let mut body = Vec::new();
        body.extend_from_slice(&[192, 0, 2, 1]);
        body.extend_from_slice(&be32(100));
        body.push(2);
        body.extend_from_slice(&[0, 0, 0]);
        let data = v9_packet(0, &[set(1, &rec), set(257, &body)]);
        let mut buf = DissectBuffer::new();
        d.dissect(&data, &mut buf, 0).unwrap();

        let tset = nth_set(&buf, "flowsets", 0);
        assert_eq!(
            buf.resolve_nested_display_name(&tset, "flowset_id_name"),
            Some("Options Template FlowSet")
        );
        let templates = range_of(child(&buf, &tset, "templates").unwrap());
        let t = range_of(children(&buf, &templates)[0]);
        assert_eq!(
            child(&buf, &t, "option_scope_length").unwrap().value,
            FieldValue::U16(4)
        );
        assert_eq!(
            child(&buf, &t, "option_length").unwrap().value,
            FieldValue::U16(8)
        );
        assert!(child(&buf, &t, "field_count").is_none());
        let scope = range_of(child(&buf, &t, "scope_fields").unwrap());
        let s0 = range_of(children(&buf, &scope)[0]);
        assert_eq!(
            buf.resolve_nested_display_name(&s0, "scope_field_type_name"),
            Some("System")
        );
        assert_eq!(
            child(&buf, &tset, "padding").unwrap().value,
            FieldValue::Bytes(&[0, 0])
        );

        let dset = nth_set(&buf, "flowsets", 1);
        assert_eq!(
            record_values(&buf, &dset, 0, "scope_fields"),
            vec![&FieldValue::U32(0xc000_0201)]
        );
        assert_eq!(
            record_values(&buf, &dset, 0, "fields"),
            vec![&FieldValue::U32(100), &FieldValue::U8(2)]
        );
        let records = range_of(child(&buf, &dset, "records").unwrap());
        let r0 = range_of(children(&buf, &records)[0]);
        let scope = range_of(child(&buf, &r0, "scope_fields").unwrap());
        let sv = range_of(children(&buf, &scope)[0]);
        assert_eq!(
            buf.resolve_nested_display_name(&sv, "scope_field_type_name"),
            Some("System")
        );
        assert_eq!(
            child(&buf, &dset, "padding").unwrap().value,
            FieldValue::Bytes(&[0, 0, 0])
        );
    }

    #[test]
    fn v9_options_bad_lengths_raw() {
        let d = NetflowV9Dissector::new();
        for (scope_len, opt_len) in [(3u16, 4u16), (4, 5), (4, 40)] {
            let mut rec = Vec::new();
            rec.extend_from_slice(&be16(257));
            rec.extend_from_slice(&be16(scope_len));
            rec.extend_from_slice(&be16(opt_len));
            rec.extend_from_slice(&[0, 1, 0, 4, 0, 34, 0, 4]);
            let data = v9_packet(0, &[set(1, &rec)]);
            let mut buf = DissectBuffer::new();
            d.dissect(&data, &mut buf, 0).unwrap();
            let tset = nth_set(&buf, "flowsets", 0);
            assert_eq!(
                child(&buf, &tset, "data").unwrap().value,
                FieldValue::Bytes(&rec),
                "{scope_len} {opt_len}"
            );
        }
    }

    #[test]
    fn v9_template_zero_field_count() {
        let d = NetflowV9Dissector::new();
        let data = v9_packet(0, &[set(0, &[1, 0, 0, 0, 1, 1, 0, 1, 0, 10, 0, 4])]);
        let mut buf = DissectBuffer::new();
        d.dissect(&data, &mut buf, 0).unwrap();
        let tset = nth_set(&buf, "flowsets", 0);
        let templates = range_of(child(&buf, &tset, "templates").unwrap());
        let t = children(&buf, &templates);
        assert_eq!(t.len(), 2);
        assert_eq!(
            child(&buf, &range_of(t[0]), "field_count").unwrap().value,
            FieldValue::U16(0)
        );
        // The field-less Template is not stored; the other one is.
        buf.clear();
        let data = v9_packet(0, &[set(256, &[1, 2, 3, 4]), set(257, &[0, 0, 0, 9])]);
        d.dissect(&data, &mut buf, 0).unwrap();
        assert!(child(&buf, &nth_set(&buf, "flowsets", 0), "data").is_some());
        assert_eq!(
            record_values(&buf, &nth_set(&buf, "flowsets", 1), 0, "fields"),
            vec![&FieldValue::U32(9)]
        );
    }

    #[test]
    fn v9_invalid_header() {
        let d = NetflowV9Dissector::new();
        let mut buf = DissectBuffer::new();
        let data = v9_packet(0, &[]);
        assert_eq!(
            d.dissect(&data[..19], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 20,
                actual: 19
            })
        );
        let mut bad = data.clone();
        bad[1] = 10;
        assert_eq!(
            d.dissect(&bad, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 10
            })
        );
    }

    #[test]
    fn v9_flowset_length_invalid() {
        let d = NetflowV9Dissector::new();
        let mut buf = DissectBuffer::new();
        let mut data = v9_packet(0, &[set(256, &[0; 4])]);
        data[23] = 100;
        assert_eq!(
            d.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "set_length",
                value: 100
            })
        );
    }

    #[test]
    fn v9_metadata() {
        let d = NetflowV9Dissector::new();
        assert_eq!(d.name(), "Cisco NetFlow Version 9");
        assert_eq!(d.short_name(), "NetFlow-v9");
        assert_eq!(d.layer(), Some(ProtocolLayer::Application));
        assert_eq!(d.references()[0].id, "RFC 3954");
        assert_eq!(d.field_descriptors()[VH_FLOWSETS].name, "flowsets");
    }

    // ---------------------------------------------------------------------------
    // NetFlow v5
    // ---------------------------------------------------------------------------

    fn v5_packet(count: u16, records: usize) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&be16(5));
        p.extend_from_slice(&be16(count));
        p.extend_from_slice(&be32(1000)); // SysUptime
        p.extend_from_slice(&be32(1_700_000_000)); // unix_secs
        p.extend_from_slice(&be32(5)); // unix_nsecs
        p.extend_from_slice(&be32(77)); // flow_sequence
        p.push(1); // engine_type
        p.push(2); // engine_id
        p.extend_from_slice(&be16(0x4064)); // mode 1, interval 100
        for i in 0..records {
            let i = i as u8;
            p.extend_from_slice(&[10, 0, 0, i]); // srcaddr
            p.extend_from_slice(&[10, 0, 1, i]); // dstaddr
            p.extend_from_slice(&[10, 0, 2, 1]); // nexthop
            p.extend_from_slice(&be16(3)); // input
            p.extend_from_slice(&be16(4)); // output
            p.extend_from_slice(&be32(10)); // dPkts
            p.extend_from_slice(&be32(1400)); // dOctets
            p.extend_from_slice(&be32(900)); // First
            p.extend_from_slice(&be32(950)); // Last
            p.extend_from_slice(&be16(1234)); // srcport
            p.extend_from_slice(&be16(80)); // dstport
            p.push(0); // pad1
            p.push(0x1b); // tcp_flags
            p.push(6); // prot
            p.push(0x10); // tos
            p.extend_from_slice(&be16(65001)); // src_as
            p.extend_from_slice(&be16(65002)); // dst_as
            p.push(24); // src_mask
            p.push(16); // dst_mask
            p.extend_from_slice(&[0, 0]); // pad2
        }
        p
    }

    #[test]
    fn v5_two_records() {
        let data = v5_packet(2, 2);
        let mut buf = DissectBuffer::new();
        let res = NetflowV5Dissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(res.bytes_consumed, 24 + 96);
        assert_eq!(buf.layers()[0].name, "NetFlow-v5");
        assert_eq!(layer_field(&buf, "count").value, FieldValue::U16(2));
        assert_eq!(layer_field(&buf, "sys_uptime").value, FieldValue::U32(1000));
        assert_eq!(layer_field(&buf, "unix_nsecs").value, FieldValue::U32(5));
        assert_eq!(
            layer_field(&buf, "flow_sequence").value,
            FieldValue::U32(77)
        );
        assert_eq!(layer_field(&buf, "engine_type").value, FieldValue::U8(1));
        assert_eq!(layer_field(&buf, "engine_id").value, FieldValue::U8(2));
        assert_eq!(layer_field(&buf, "sampling_mode").value, FieldValue::U8(1));
        assert_eq!(
            layer_field(&buf, "sampling_interval").value,
            FieldValue::U16(100)
        );
        let records = range_of(layer_field(&buf, "records"));
        let recs = children(&buf, &records);
        assert_eq!(recs.len(), 2);
        let r1 = range_of(recs[1]);
        let get = |n| child(&buf, &r1, n).unwrap().value.clone();
        assert_eq!(get("src_addr"), FieldValue::Ipv4Addr([10, 0, 0, 1]));
        assert_eq!(get("dst_addr"), FieldValue::Ipv4Addr([10, 0, 1, 1]));
        assert_eq!(get("next_hop"), FieldValue::Ipv4Addr([10, 0, 2, 1]));
        assert_eq!(get("input"), FieldValue::U16(3));
        assert_eq!(get("output"), FieldValue::U16(4));
        assert_eq!(get("packets"), FieldValue::U32(10));
        assert_eq!(get("octets"), FieldValue::U32(1400));
        assert_eq!(get("first"), FieldValue::U32(900));
        assert_eq!(get("last"), FieldValue::U32(950));
        assert_eq!(get("src_port"), FieldValue::U16(1234));
        assert_eq!(get("dst_port"), FieldValue::U16(80));
        assert_eq!(get("tcp_flags"), FieldValue::U8(0x1b));
        assert_eq!(get("protocol"), FieldValue::U8(6));
        assert_eq!(get("tos"), FieldValue::U8(0x10));
        assert_eq!(get("src_as"), FieldValue::U16(65001));
        assert_eq!(get("dst_as"), FieldValue::U16(65002));
        assert_eq!(get("src_mask"), FieldValue::U8(24));
        assert_eq!(get("dst_mask"), FieldValue::U8(16));
        assert_eq!(recs[1].range, 72..120);
        assert_eq!(
            child(&buf, &r1, "protocol").unwrap().range,
            72 + 38..72 + 39
        );
    }

    #[test]
    fn v5_truncated() {
        let data = v5_packet(2, 1);
        let mut buf = DissectBuffer::new();
        assert_eq!(
            NetflowV5Dissector.dissect(&data, &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 120,
                actual: 72
            })
        );
    }

    #[test]
    fn v5_invalid_header() {
        let data = v5_packet(0, 0);
        let mut buf = DissectBuffer::new();
        assert_eq!(
            NetflowV5Dissector.dissect(&data[..23], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 24,
                actual: 23
            })
        );
        let mut bad = data.clone();
        bad[1] = 7;
        assert_eq!(
            NetflowV5Dissector.dissect(&bad, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 7
            })
        );
        let d = NetflowV5Dissector;
        assert_eq!(d.name(), "Cisco NetFlow Version 5");
        assert_eq!(d.short_name(), "NetFlow-v5");
        assert_eq!(d.layer(), Some(ProtocolLayer::Application));
        assert_eq!(d.references()[0].id, "Cisco NetFlow v5");
        assert_eq!(d.field_descriptors().len(), 11);
    }

    // ---------------------------------------------------------------------------
    // Version dispatch
    // ---------------------------------------------------------------------------

    /// Whether dissecting `data` with `d` reports cross-packet state use.
    fn marks_state(d: &dyn Dissector, data: &[u8]) -> bool {
        let mut buf = DissectBuffer::new();
        d.dissect(data, &mut buf, 0).unwrap();
        buf.used_cross_packet_state()
    }

    #[test]
    fn ipfix_template_sets_mark_cross_packet_state() {
        let d = IpfixDissector::new();
        assert!(marks_state(&d, &ipfix_message(0, &[flow_template()])));
        let mut rec = Vec::new();
        rec.extend_from_slice(&be16(259));
        rec.extend_from_slice(&be16(1)); // Field Count
        rec.extend_from_slice(&be16(1)); // Scope Field Count
        rec.extend_from_slice(&ipfix_spec(149, 4, None));
        assert!(marks_state(&d, &ipfix_message(0, &[set(3, &rec)])));
        // Withdrawals change the cache too.
        let withdrawal = set(2, &[&be16(256)[..], &be16(0)[..]].concat());
        assert!(marks_state(&d, &ipfix_message(0, &[withdrawal])));
    }

    #[test]
    fn ipfix_data_set_marks_cross_packet_state() {
        let d = IpfixDissector::new();
        let data = ipfix_message(0, &[set(256, &flow_record([1; 4], [2; 4], 3, 6))]);
        // Decoded raw without a Template: the result still depends on the
        // Templates that earlier messages did not carry.
        assert!(marks_state(&d, &data));
        assert!(marks_state(&d, &ipfix_message(0, &[flow_template()])));
        assert!(marks_state(&d, &data));
    }

    #[test]
    fn ipfix_other_sets_mark_no_cross_packet_state() {
        let d = IpfixDissector::new();
        assert!(!marks_state(&d, &ipfix_message(0, &[])));
        assert!(!marks_state(
            &d,
            &ipfix_message(0, &[set(4, &[1, 2, 3, 4]), set(0, &[])])
        ));
    }

    #[test]
    fn v9_flowsets_mark_cross_packet_state() {
        let d = NetflowV9Dissector::new();
        assert!(!marks_state(&d, &v9_packet(0, &[])));
        let tmpl = set(0, &v9_template(256, &[(8, 4)]));
        assert!(marks_state(&d, &v9_packet(0, &[tmpl])));
        let mut rec = Vec::new();
        rec.extend_from_slice(&be16(257));
        rec.extend_from_slice(&be16(4)); // Option Scope Length
        rec.extend_from_slice(&be16(4)); // Option Length
        rec.extend_from_slice(&be16(1));
        rec.extend_from_slice(&be16(4));
        rec.extend_from_slice(&be16(34));
        rec.extend_from_slice(&be16(4));
        assert!(marks_state(&d, &v9_packet(0, &[set(1, &rec)])));
        assert!(marks_state(&d, &v9_packet(0, &[set(256, &[10, 0, 0, 1])])));
    }

    #[test]
    fn v5_marks_no_cross_packet_state() {
        assert!(!marks_state(&NetflowV5Dissector, &v5_packet(1, 1)));
        let d = NetflowDissector::new();
        assert!(!marks_state(&d, &v5_packet(1, 1)));
        // The version dispatcher passes the flag through from v9 and IPFIX.
        assert!(marks_state(&d, &ipfix_message(0, &[flow_template()])));
        assert!(marks_state(
            &d,
            &v9_packet(0, &[set(0, &v9_template(256, &[(8, 4)]))])
        ));
    }

    #[test]
    fn netflow_dispatches_by_version() {
        let d = NetflowDissector::new();
        for (data, name) in [
            (v5_packet(1, 1), "NetFlow-v5"),
            (v9_packet(0, &[]), "NetFlow-v9"),
            (ipfix_message(0, &[]), "IPFIX"),
        ] {
            let mut buf = DissectBuffer::new();
            let res = d.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(res.bytes_consumed, data.len());
            assert_eq!(buf.layers()[0].name, name);
        }
        // Templates persist in the dispatcher's own caches.
        let tmpl = ipfix_message(0, &[flow_template()]);
        let mut buf = DissectBuffer::new();
        d.dissect(&tmpl, &mut buf, 0).unwrap();
        buf.clear();
        let data = ipfix_message(0, &[set(256, &flow_record([1; 4], [2; 4], 3, 6))]);
        d.dissect(&data, &mut buf, 0).unwrap();
        assert!(child(&buf, &nth_set(&buf, "sets", 0), "records").is_some());
        assert_eq!(d.short_name(), "NetFlow");
        assert_eq!(d.name(), "Cisco NetFlow / IPFIX");
        assert!(d.field_descriptors().is_empty());
        assert_eq!(d.references().len(), 4);
        assert_eq!(d.layer(), Some(ProtocolLayer::Application));
    }

    #[test]
    fn netflow_rejects_unknown_version() {
        let d = NetflowDissector::new();
        let mut buf = DissectBuffer::new();
        assert_eq!(
            d.dissect(&[0], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            d.dissect(&[0, 8, 0, 0], &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 8
            })
        );
    }

    static TEST_TCP_FIELDS: &[FieldDescriptor] = &[
        FieldDescriptor::new("src_port", "Source Port", FieldType::U16),
        FieldDescriptor::new("dst_port", "Destination Port", FieldType::U16),
        FieldDescriptor::new("stream_id", "Stream ID", FieldType::U32),
    ];

    /// Push a fake TCP layer carrying a connection's `stream_id`.
    fn push_tcp_connection(buf: &mut DissectBuffer<'_>, stream_id: u32) {
        buf.begin_layer("TCP", None, TEST_TCP_FIELDS, 0..0);
        buf.push_field(&TEST_TCP_FIELDS[0], FieldValue::U16(50000), 0..0);
        buf.push_field(&TEST_TCP_FIELDS[1], FieldValue::U16(4739), 0..0);
        buf.push_field(&TEST_TCP_FIELDS[2], FieldValue::U32(stream_id), 0..0);
        buf.end_layer();
    }

    #[test]
    fn ipfix_template_scoped_by_tcp_connection() {
        // RFC 7011, Section 8.1 —
        // <https://www.rfc-editor.org/rfc/rfc7011#section-8.1>:
        // "The end of a Transport Session implicitly withdraws all the
        // Templates used within the Transport Session": a new TCP connection
        // reusing the 4-tuple gets a new stream ID.
        let d = IpfixDissector::new();
        let tmpl = ipfix_message(1, &[flow_template()]);
        let data = ipfix_message(1, &[set(256, &flow_record([1; 4], [2; 4], 3, 6))]);
        let mut buf = DissectBuffer::new();
        push_tcp_connection(&mut buf, 7);
        d.dissect(&tmpl, &mut buf, 0).unwrap();

        let mut buf = DissectBuffer::new();
        push_tcp_connection(&mut buf, 7);
        d.dissect(&data, &mut buf, 0).unwrap();
        assert!(child(&buf, &last_layer_first_set(&buf, "sets"), "records").is_some());

        let mut buf = DissectBuffer::new();
        push_tcp_connection(&mut buf, 8);
        d.dissect(&data, &mut buf, 0).unwrap();
        assert!(child(&buf, &last_layer_first_set(&buf, "sets"), "data").is_some());
    }

    #[test]
    fn v9_field_types_above_127_not_named() {
        // RFC 7012, Section 4 —
        // <https://www.rfc-editor.org/rfc/rfc7012#section-4>:
        // only identifiers 1-127 are compatible with NetFlow v9 field types.
        let d = NetflowV9Dissector::new();
        let tmpl = set(0, &v9_template(256, &[(127, 4), (128, 4)]));
        let data = v9_packet(0, &[tmpl, set(256, &[0, 0, 0, 1, 0, 0, 0, 2])]);
        let mut buf = DissectBuffer::new();
        d.dissect(&data, &mut buf, 0).unwrap();
        let tset = nth_set(&buf, "flowsets", 0);
        let templates = range_of(child(&buf, &tset, "templates").unwrap());
        let t = range_of(children(&buf, &templates)[0]);
        let fields = range_of(child(&buf, &t, "fields").unwrap());
        let f1 = range_of(children(&buf, &fields)[1]);
        assert_eq!(
            buf.resolve_nested_display_name(&f1, "field_type_name"),
            None
        );
        // bgpNextAdjacentAsNumber (128) is unsigned32 in IPFIX, but not a
        // NetFlow v9 field type: kept raw.
        assert_eq!(
            record_values(&buf, &nth_set(&buf, "flowsets", 1), 0, "fields"),
            vec![
                &FieldValue::Bytes(&[0, 0, 0, 1]),
                &FieldValue::Bytes(&[0, 0, 0, 2])
            ]
        );
    }

    #[test]
    fn ipfix_template_set_nonzero_trailer_raw() {
        // RFC 7011, Section 3.3.1 —
        // <https://www.rfc-editor.org/rfc/rfc7011#section-3.3.1>:
        // "the padding octet(s) MUST be composed of octets with value zero
        // (0)."
        let mut body = ipfix_template(256, &[(4, 1, None)]);
        body.extend_from_slice(&[0xff, 0xff]);
        let data = ipfix_message(0, &[set(2, &body)]);
        let mut buf = DissectBuffer::new();
        dissect_ipfix(&IpfixDissector::new(), &data, &mut buf);
        let tset = nth_set(&buf, "sets", 0);
        assert!(child(&buf, &tset, "padding").is_none());
        assert_eq!(
            child(&buf, &tset, "data").unwrap().value,
            FieldValue::Bytes(&[0xff, 0xff])
        );
    }

    #[test]
    fn ipfix_options_zero_scope_count_raw() {
        // RFC 7011, Section 3.4.2.2 —
        // <https://www.rfc-editor.org/rfc/rfc7011#section-3.4.2.2>:
        // "The Scope Field Count MUST NOT be zero."
        let mut rec = Vec::new();
        rec.extend_from_slice(&be16(259));
        rec.extend_from_slice(&be16(1));
        rec.extend_from_slice(&be16(0));
        rec.extend_from_slice(&ipfix_spec(41, 8, None));
        let d = IpfixDissector::new();
        let data = ipfix_message(0, &[set(3, &rec), set(259, &[0; 8])]);
        let mut buf = DissectBuffer::new();
        dissect_ipfix(&d, &data, &mut buf);
        assert_eq!(
            child(&buf, &nth_set(&buf, "sets", 0), "data")
                .unwrap()
                .value,
            FieldValue::Bytes(&rec)
        );
        assert!(child(&buf, &nth_set(&buf, "sets", 1), "data").is_some());
    }

    #[test]
    fn display_fns_handle_unexpected_values() {
        let v = FieldValue::U8(0);
        assert_eq!(ipfix_set_id_name(&v, &[]), None);
        assert_eq!(v9_flowset_id_name(&v, &[]), None);
        assert_eq!(ipfix_element_name(&v, &[]), None);
        assert_eq!(v9_field_type_name(&v, &[]), None);
        assert_eq!(v9_scope_type_name(&v, &[]), None);
        assert_eq!(
            v9_flowset_id_name(&FieldValue::U16(5), &[]),
            Some("Reserved")
        );
        for (id, name) in [
            (2, "Interface"),
            (3, "Line Card"),
            (4, "Cache"),
            (5, "Template"),
        ] {
            assert_eq!(v9_scope_type_name(&FieldValue::U16(id), &[]), Some(name));
        }
        assert_eq!(v9_scope_type_name(&FieldValue::U16(6), &[]), None);
    }

    #[test]
    fn visit_sub_dissectors_lists_embedded_layers() {
        let mut names = Vec::new();
        NetflowDissector::new().visit_sub_dissectors(&mut |d| names.push(d.short_name()));
        assert_eq!(names, ["NetFlow-v5", "NetFlow-v9", "IPFIX"]);
    }
}
