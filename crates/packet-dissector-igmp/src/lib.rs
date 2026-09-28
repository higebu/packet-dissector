//! IGMP (Internet Group Management Protocol) dissector.
//!
//! ## References
//! - RFC 1112: <https://www.rfc-editor.org/rfc/rfc1112> (IGMPv1, updated by RFC 2236)
//! - RFC 2236: <https://www.rfc-editor.org/rfc/rfc2236> (IGMPv2, updated by RFC 3376 and RFC 9776)
//! - RFC 9776: <https://www.rfc-editor.org/rfc/rfc9776> (IGMPv3; obsoletes RFC 3376)
//! - RFC 4604: <https://www.rfc-editor.org/rfc/rfc4604> (SSM semantics for IGMPv3/MLDv2)
//! - RFC 4286: <https://www.rfc-editor.org/rfc/rfc4286> (Multicast Router Discovery)
//! - IANA "IGMP Type Numbers": <https://www.iana.org/assignments/igmp-type-numbers>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_ipv4_addr};

/// Specification references for the IGMP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 1112",
        "Host extensions for IP multicasting",
        "https://www.rfc-editor.org/rfc/rfc1112",
    ),
    SpecReference::new(
        "RFC 2236",
        "Internet Group Management Protocol, Version 2",
        "https://www.rfc-editor.org/rfc/rfc2236",
    ),
    SpecReference::new(
        "RFC 9776",
        "Internet Group Management Protocol, Version 3",
        "https://www.rfc-editor.org/rfc/rfc9776",
    ),
    SpecReference::new(
        "RFC 4604",
        "Using Internet Group Management Protocol Version 3 (IGMPv3) and Multicast \
         Listener Discovery Protocol Version 2 (MLDv2) for Source-Specific Multicast",
        "https://www.rfc-editor.org/rfc/rfc4604",
    ),
    SpecReference::new(
        "RFC 4286",
        "Multicast Router Discovery",
        "https://www.rfc-editor.org/rfc/rfc4286",
    ),
];

/// Returns a human-readable name for well-known IGMP type values.
///
/// RFC 1112, Section 6.2 — <https://www.rfc-editor.org/rfc/rfc1112#section-6.2>
/// RFC 2236, Section 2 — <https://www.rfc-editor.org/rfc/rfc2236#section-2>
/// RFC 9776, Section 4 — <https://www.rfc-editor.org/rfc/rfc9776#section-4>
/// RFC 4286, Section 8 — <https://www.rfc-editor.org/rfc/rfc4286#section-8>
/// IANA "IGMP Type Numbers" — <https://www.iana.org/assignments/igmp-type-numbers>
fn igmp_type_name(v: u8) -> Option<&'static str> {
    match v {
        TYPE_MEMBERSHIP_QUERY => Some("Membership Query"),
        TYPE_V1_REPORT => Some("IGMPv1 Membership Report"),
        0x13 => Some("DVMRP"),
        0x14 => Some("PIM version 1"),
        TYPE_V2_REPORT => Some("IGMPv2 Membership Report"),
        TYPE_V2_LEAVE => Some("Leave Group"),
        0x1e => Some("Multicast Traceroute Response"),
        0x1f => Some("Multicast Traceroute"),
        TYPE_V3_REPORT => Some("IGMPv3 Membership Report"),
        TYPE_MRD_ADVERTISEMENT => Some("Multicast Router Advertisement"),
        TYPE_MRD_SOLICITATION => Some("Multicast Router Solicitation"),
        TYPE_MRD_TERMINATION => Some("Multicast Router Termination"),
        _ => None,
    }
}

/// Membership Query.
/// RFC 2236, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc2236#section-2.1>
const TYPE_MEMBERSHIP_QUERY: u8 = 0x11;
/// IGMPv1 Membership Report.
/// RFC 1112, Appendix I — <https://www.rfc-editor.org/rfc/rfc1112#appendix-I>
const TYPE_V1_REPORT: u8 = 0x12;
/// IGMPv2 Membership Report.
/// RFC 2236, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc2236#section-2.1>
const TYPE_V2_REPORT: u8 = 0x16;
/// IGMPv2 Leave Group.
/// RFC 2236, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc2236#section-2.1>
const TYPE_V2_LEAVE: u8 = 0x17;
/// IGMPv3 Membership Report.
/// RFC 9776, Section 4 — <https://www.rfc-editor.org/rfc/rfc9776#section-4>
const TYPE_V3_REPORT: u8 = 0x22;
/// Multicast Router Advertisement.
/// RFC 4286, Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc4286#section-3.2.1>
const TYPE_MRD_ADVERTISEMENT: u8 = 0x30;
/// Multicast Router Solicitation.
/// RFC 4286, Section 4.1.1 — <https://www.rfc-editor.org/rfc/rfc4286#section-4.1.1>
const TYPE_MRD_SOLICITATION: u8 = 0x31;
/// Multicast Router Termination.
/// RFC 4286, Section 5.1.1 — <https://www.rfc-editor.org/rfc/rfc4286#section-5.1.1>
const TYPE_MRD_TERMINATION: u8 = 0x32;

/// Size of the fields shared by every IGMP message: Type(1) + byte 1(1) +
/// Checksum(2). Also the full size of an MRD Solicitation / Termination.
///
/// RFC 4286, Sections 4.1 and 5.1 — <https://www.rfc-editor.org/rfc/rfc4286#section-4.1>
const COMMON_HEADER_SIZE: usize = 4;

/// Returns a human-readable name for IGMPv3 group record type values.
///
/// RFC 9776, Section 4.2.12 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.2.12>
fn igmpv3_record_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("MODE_IS_INCLUDE"),
        2 => Some("MODE_IS_EXCLUDE"),
        3 => Some("CHANGE_TO_INCLUDE_MODE"),
        4 => Some("CHANGE_TO_EXCLUDE_MODE"),
        5 => Some("ALLOW_NEW_SOURCES"),
        6 => Some("BLOCK_OLD_SOURCES"),
        _ => None,
    }
}

/// Decodes an IGMPv3 exponential field value (used by Max Resp Code and QQIC).
///
/// RFC 9776, Section 4.1.1 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1.1>
/// RFC 9776, Section 4.1.7 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1.7>
///
/// If `code < 128`, the value equals `code`. Otherwise, the value is computed
/// as `(mant | 0x10) << (exp + 3)` where `mant` is bits 0–3 and `exp` is
/// bits 4–6 of the code byte.
fn decode_exp_field(code: u8) -> u32 {
    if code < 128 {
        u32::from(code)
    } else {
        let mant = u32::from(code & 0x0F);
        let exp = u32::from((code >> 4) & 0x07);
        (mant | 0x10) << (exp + 3)
    }
}

/// Minimum IGMP header size: Type(1) + Max Resp Time(1) + Checksum(2) + Group Address(4).
///
/// RFC 2236, Section 2 — <https://www.rfc-editor.org/rfc/rfc2236#section-2>
const HEADER_SIZE: usize = 8;

/// Minimum IGMPv3 Membership Query size.
///
/// RFC 9776, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1>
const V3_QUERY_MIN_SIZE: usize = 12;

/// IGMPv3 Membership Report header size before group records.
///
/// RFC 9776, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.2>
const V3_REPORT_HEADER_SIZE: usize = 8;

/// Minimum size of a single IGMPv3 group record header:
/// Record Type(1) + Aux Data Len(1) + Number of Sources(2) + Multicast Address(4).
///
/// RFC 9776, Section 4.2.1–4.2.4 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.2>
const GROUP_RECORD_HEADER_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// Field descriptor indices
// ---------------------------------------------------------------------------

/// Field descriptor index for `type`.
const FD_TYPE: usize = 0;
/// Field descriptor index for `max_resp_time`.
const FD_MAX_RESP_TIME: usize = 1;
/// Field descriptor index for `checksum`.
const FD_CHECKSUM: usize = 2;
/// Field descriptor index for `group_address`.
const FD_GROUP_ADDRESS: usize = 3;
/// Field descriptor index for `max_resp_time_value` (decoded).
const FD_MAX_RESP_TIME_VALUE: usize = 4;
/// Field descriptor index for IGMPv3 Query `flags` (byte 8 bits 0–3; RFC 9776 §4.1.4).
const FD_QUERY_FLAGS: usize = 5;
/// Field descriptor index for `suppress_router_processing` (S flag).
const FD_S_FLAG: usize = 6;
/// Field descriptor index for `qrv`.
const FD_QRV: usize = 7;
/// Field descriptor index for `qqic` (raw).
const FD_QQIC: usize = 8;
/// Field descriptor index for `qqic_value` (decoded).
const FD_QQIC_VALUE: usize = 9;
/// Field descriptor index for `num_sources`.
const FD_NUM_SOURCES: usize = 10;
/// Field descriptor index for `sources`.
const FD_SOURCES: usize = 11;
/// Field descriptor index for IGMPv3 Report `flags` (bytes 4–5; RFC 9776 §4.2.3).
const FD_REPORT_FLAGS: usize = 12;
/// Field descriptor index for `num_group_records`.
const FD_NUM_GROUP_RECORDS: usize = 13;
/// Field descriptor index for `group_records`.
const FD_GROUP_RECORDS: usize = 14;
/// Field descriptor index for `code` (byte 1 of a type whose body is not decoded).
const FD_CODE: usize = 15;
/// Field descriptor index for `data` (body of a type that is not decoded).
const FD_DATA: usize = 16;
/// Field descriptor index for MRD `advertisement_interval` (RFC 4286 §3.2.2).
///   <https://www.rfc-editor.org/rfc/rfc4286#section-3.2.2>
const FD_ADVERTISEMENT_INTERVAL: usize = 17;
/// Field descriptor index for MRD `query_interval` (RFC 4286 §3.2.4).
///   <https://www.rfc-editor.org/rfc/rfc4286#section-3.2.4>
const FD_QUERY_INTERVAL: usize = 18;
/// Field descriptor index for MRD `robustness_variable` (RFC 4286 §3.2.5).
///   <https://www.rfc-editor.org/rfc/rfc4286#section-3.2.5>
const FD_ROBUSTNESS_VARIABLE: usize = 19;
/// Field descriptor index for MRD `reserved` (RFC 4286 §4.1.2, §5.1.2).
///   <https://www.rfc-editor.org/rfc/rfc4286#section-4.1.2>
const FD_RESERVED: usize = 20;
/// Field descriptor index for the derived `query_version` (RFC 9776 §7.1).
///   <https://www.rfc-editor.org/rfc/rfc9776#section-7.1>
const FD_QUERY_VERSION: usize = 21;

// ---------------------------------------------------------------------------
// Child field descriptor indices — source address
// ---------------------------------------------------------------------------

/// Child field descriptor index for source `address`.
const SC_ADDRESS: usize = 0;

/// Child field descriptors for source address Array elements.
static SOURCE_CHILDREN: &[FieldDescriptor] = &[FieldDescriptor::new(
    "address",
    "Source Address",
    FieldType::Ipv4Addr,
)];

// ---------------------------------------------------------------------------
// Child field descriptor indices — group record
// ---------------------------------------------------------------------------

/// Child field descriptor index for group record `record_type`.
const GRC_RECORD_TYPE: usize = 0;
/// Child field descriptor index for group record `aux_data_len`.
const GRC_AUX_DATA_LEN: usize = 1;
/// Child field descriptor index for group record `num_sources`.
const GRC_NUM_SOURCES: usize = 2;
/// Child field descriptor index for group record `multicast_address`.
const GRC_MULTICAST_ADDRESS: usize = 3;
/// Child field descriptor index for group record `sources`.
const GRC_SOURCES: usize = 4;
/// Child field descriptor index for group record `aux_data`.
const GRC_AUX_DATA: usize = 5;

/// Container descriptor for an IGMPv3 group record Object.
///
/// The outer label resolves to the record type name (e.g.
/// `MODE_IS_INCLUDE`) by looking up the inner `record_type` field,
/// avoiding collision with the inner "Record Type" label.
static FD_GROUP_RECORD: FieldDescriptor = FieldDescriptor {
    name: "group_record",
    display_name: "Group Record",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("record_type", FieldValue::U8(t)) => igmpv3_record_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Child field descriptors for IGMPv3 group record Array elements.
static GROUP_RECORD_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "record_type",
        display_name: "Record Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => igmpv3_record_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("aux_data_len", "Aux Data Len", FieldType::U8),
    FieldDescriptor::new("num_sources", "Number of Sources", FieldType::U16),
    FieldDescriptor::new(
        "multicast_address",
        "Multicast Address",
        FieldType::Ipv4Addr,
    ),
    FieldDescriptor::new("sources", "Source Addresses", FieldType::Array)
        .with_children(SOURCE_CHILDREN),
    FieldDescriptor::new("aux_data", "Auxiliary Data", FieldType::Bytes).optional(),
];

// ---------------------------------------------------------------------------
// Top-level field descriptors
// ---------------------------------------------------------------------------

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => igmp_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    // Not present for MRD messages or types whose body is not decoded.
    FieldDescriptor::new("max_resp_time", "Max Resp Time", FieldType::U8).optional(),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    FieldDescriptor {
        name: "group_address",
        display_name: "Group Address",
        field_type: FieldType::Ipv4Addr,
        // Not present in IGMPv3 Reports (0x22)
        optional: true,
        children: None,
        display_fn: None,
        format_fn: None,
    },
    FieldDescriptor::new(
        "max_resp_time_value",
        "Max Resp Time (decoded)",
        FieldType::U32,
    )
    .optional(),
    // IGMPv3 Query byte 8, bits 0–3 (RFC 9776 §4.1.4 — IANA "IGMP Type Numbers" registry).
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new(
        "suppress_router_processing",
        "Suppress Router-Side Processing",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("qrv", "Querier's Robustness Variable", FieldType::U8).optional(),
    FieldDescriptor::new("qqic", "Querier's Query Interval Code", FieldType::U8).optional(),
    FieldDescriptor::new(
        "qqic_value",
        "Querier's Query Interval (decoded)",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("num_sources", "Number of Sources", FieldType::U16).optional(),
    FieldDescriptor::new("sources", "Source Addresses", FieldType::Array)
        .optional()
        .with_children(SOURCE_CHILDREN),
    // IGMPv3 Report bytes 4–5 (RFC 9776 §4.2.3 — IANA "IGMP Type Numbers" registry;
    // formerly "Reserved" in RFC 3376 §4.2).
    FieldDescriptor::new("flags", "Flags", FieldType::U16).optional(),
    FieldDescriptor::new(
        "num_group_records",
        "Number of Group Records",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("group_records", "Group Records", FieldType::Array)
        .optional()
        .with_children(GROUP_RECORD_CHILDREN),
    // Types whose body is not decoded (unknown, DVMRP, PIMv1, mtrace).
    FieldDescriptor::new("code", "Code", FieldType::U8).optional(),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    // Multicast Router Discovery (RFC 4286).
    //   <https://www.rfc-editor.org/rfc/rfc4286>
    FieldDescriptor::new(
        "advertisement_interval",
        "Advertisement Interval",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("query_interval", "Query Interval", FieldType::U16).optional(),
    FieldDescriptor::new("robustness_variable", "Robustness Variable", FieldType::U16).optional(),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U8).optional(),
    // Derived from the message length and Max Resp Code (RFC 9776 §7.1).
    //   <https://www.rfc-editor.org/rfc/rfc9776#section-7.1>
    FieldDescriptor::new("query_version", "Query Version", FieldType::U8).optional(),
];

/// Per-type header layout shared by the fixed fields of every IGMP message.
struct TypeLayout {
    /// Minimum message length in octets.
    min_len: usize,
    /// Field descriptor index used for byte 1.
    byte1_fd: usize,
    /// Whether bytes 4–7 carry a Group Address.
    has_group_address: bool,
}

/// Returns the fixed-header layout of an IGMP message type.
///
/// This is the single place that classifies types; the body decoding in
/// `dissect` only handles types whose layout it lists here.
fn type_layout(igmp_type: u8) -> TypeLayout {
    match igmp_type {
        // Queries, v1/v2 Reports and Leave Group: Max Resp Time / Code in
        // byte 1 and a Group Address in bytes 4–7.
        //   RFC 2236, Section 2 — <https://www.rfc-editor.org/rfc/rfc2236#section-2>
        //   RFC 9776, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1>
        TYPE_MEMBERSHIP_QUERY | TYPE_V1_REPORT | TYPE_V2_REPORT | TYPE_V2_LEAVE => TypeLayout {
            min_len: HEADER_SIZE,
            byte1_fd: FD_MAX_RESP_TIME,
            has_group_address: true,
        },
        // IGMPv3 Report: byte 1 is Reserved (kept as `max_resp_time` for
        // compatibility); bytes 4–7 are Flags and the record count.
        //   RFC 9776, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.2>
        TYPE_V3_REPORT => TypeLayout {
            min_len: HEADER_SIZE,
            byte1_fd: FD_MAX_RESP_TIME,
            has_group_address: false,
        },
        // MRD Advertisement: Advertisement Interval in byte 1.
        //   RFC 4286, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc4286#section-3.2>
        TYPE_MRD_ADVERTISEMENT => TypeLayout {
            min_len: HEADER_SIZE,
            byte1_fd: FD_ADVERTISEMENT_INTERVAL,
            has_group_address: false,
        },
        // MRD Solicitation / Termination: 4-octet messages, Reserved byte 1.
        //   RFC 4286, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc4286#section-4.1>
        //   RFC 4286, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc4286#section-5.1>
        TYPE_MRD_SOLICITATION | TYPE_MRD_TERMINATION => TypeLayout {
            min_len: COMMON_HEADER_SIZE,
            byte1_fd: FD_RESERVED,
            has_group_address: false,
        },
        // Other types: only the common Type / Code / Checksum layout is
        // assumed; the body is kept as raw data.
        _ => TypeLayout {
            min_len: COMMON_HEADER_SIZE,
            byte1_fd: FD_CODE,
            has_group_address: false,
        },
    }
}

/// IGMP dissector supporting IGMPv1 (RFC 1112), IGMPv2 (RFC 2236), and
/// IGMPv3 (RFC 9776, which obsoletes RFC 3376).
pub struct IgmpDissector;

/// Push a list of IPv4 source addresses into the buffer as Object elements
/// within an already-opened Array container.
fn push_source_list(
    buf: &mut DissectBuffer<'_>,
    data: &[u8],
    offset: usize,
    base: usize,
    count: usize,
) -> Result<(), PacketError> {
    for i in 0..count {
        let pos = base + i * 4;
        let addr = read_ipv4_addr(data, pos)?;
        let abs = offset + pos;
        let obj_idx = buf.begin_container(
            &SOURCE_CHILDREN[SC_ADDRESS],
            FieldValue::Object(0..0),
            abs..abs + 4,
        );
        buf.push_field(
            &SOURCE_CHILDREN[SC_ADDRESS],
            FieldValue::Ipv4Addr(addr),
            abs..abs + 4,
        );
        buf.end_container(obj_idx);
    }
    Ok(())
}

/// Push IGMPv3 query source addresses into the buffer.
fn push_query_sources(
    buf: &mut DissectBuffer<'_>,
    data: &[u8],
    offset: usize,
    num_sources: u16,
) -> Result<(), PacketError> {
    let available = (data.len().saturating_sub(V3_QUERY_MIN_SIZE)) / 4;
    let count = (num_sources as usize).min(available);
    let end = V3_QUERY_MIN_SIZE + count * 4;
    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_SOURCES],
        FieldValue::Array(0..0),
        offset + V3_QUERY_MIN_SIZE..offset + end,
    );
    push_source_list(buf, data, offset, V3_QUERY_MIN_SIZE, count)?;
    buf.end_container(array_idx);
    Ok(())
}

/// Push IGMPv3 Membership Report group records into the buffer (RFC 3376 Section 4.2).
fn push_group_records<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    num_records: u16,
) -> Result<(), PacketError> {
    let mut pos = V3_REPORT_HEADER_SIZE;

    let records_array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_GROUP_RECORDS],
        FieldValue::Array(0..0),
        offset + V3_REPORT_HEADER_SIZE..offset + V3_REPORT_HEADER_SIZE,
    );

    for _ in 0..num_records {
        if pos + GROUP_RECORD_HEADER_SIZE > data.len() {
            break;
        }

        let record_type = data[pos];
        let aux_data_len = data[pos + 1]; // in 32-bit words
        let num_sources = read_be_u16(data, pos + 2)?;
        let mcast_addr = read_ipv4_addr(data, pos + 4)?;

        let sources_bytes = num_sources as usize * 4;
        let aux_bytes = aux_data_len as usize * 4;
        let record_size = GROUP_RECORD_HEADER_SIZE + sources_bytes + aux_bytes;

        if pos + record_size > data.len() {
            break;
        }

        let abs_pos = offset + pos;
        let obj_idx = buf.begin_container(
            &FD_GROUP_RECORD,
            FieldValue::Object(0..0),
            abs_pos..abs_pos + record_size,
        );

        buf.push_field(
            &GROUP_RECORD_CHILDREN[GRC_RECORD_TYPE],
            FieldValue::U8(record_type),
            abs_pos..abs_pos + 1,
        );
        buf.push_field(
            &GROUP_RECORD_CHILDREN[GRC_AUX_DATA_LEN],
            FieldValue::U8(aux_data_len),
            abs_pos + 1..abs_pos + 2,
        );
        buf.push_field(
            &GROUP_RECORD_CHILDREN[GRC_NUM_SOURCES],
            FieldValue::U16(num_sources),
            abs_pos + 2..abs_pos + 4,
        );
        buf.push_field(
            &GROUP_RECORD_CHILDREN[GRC_MULTICAST_ADDRESS],
            FieldValue::Ipv4Addr(mcast_addr),
            abs_pos + 4..abs_pos + 8,
        );

        let src_base = pos + GROUP_RECORD_HEADER_SIZE;
        let src_array_idx = buf.begin_container(
            &GROUP_RECORD_CHILDREN[GRC_SOURCES],
            FieldValue::Array(0..0),
            offset + src_base..offset + src_base + sources_bytes,
        );
        push_source_list(buf, data, offset, src_base, num_sources as usize)?;
        buf.end_container(src_array_idx);

        if aux_bytes > 0 {
            let aux_start = src_base + sources_bytes;
            buf.push_field(
                &GROUP_RECORD_CHILDREN[GRC_AUX_DATA],
                FieldValue::Bytes(&data[aux_start..aux_start + aux_bytes]),
                offset + aux_start..offset + aux_start + aux_bytes,
            );
        }

        buf.end_container(obj_idx);

        pos += record_size;
    }

    // Update the array container's range end
    if let Some(field) = buf.field_mut(records_array_idx as usize) {
        field.range = offset + V3_REPORT_HEADER_SIZE..offset + pos;
    }
    buf.end_container(records_array_idx);
    Ok(())
}

impl Dissector for IgmpDissector {
    fn name(&self) -> &'static str {
        "Internet Group Management Protocol"
    }

    fn short_name(&self) -> &'static str {
        "IGMP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Network)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        let Some(&igmp_type) = data.first() else {
            return Err(PacketError::Truncated {
                expected: COMMON_HEADER_SIZE,
                actual: 0,
            });
        };

        let layout = type_layout(igmp_type);
        if data.len() < layout.min_len {
            return Err(PacketError::Truncated {
                expected: layout.min_len,
                actual: data.len(),
            });
        }

        let total_len = data.len();
        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_len,
        );

        // Common header fields.
        // RFC 2236, Section 2 — <https://www.rfc-editor.org/rfc/rfc2236#section-2>
        // RFC 9776, Section 4 — <https://www.rfc-editor.org/rfc/rfc9776#section-4>
        // RFC 4286, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc4286#section-3.2>
        let byte1 = data[1];
        let checksum = read_be_u16(data, 2)?;

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TYPE],
            FieldValue::U8(igmp_type),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[layout.byte1_fd],
            FieldValue::U8(byte1),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM],
            FieldValue::U16(checksum),
            offset + 2..offset + 4,
        );

        if layout.has_group_address {
            let group_addr = read_ipv4_addr(data, 4)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_GROUP_ADDRESS],
                FieldValue::Ipv4Addr(group_addr),
                offset + 4..offset + 8,
            );
        }

        // RFC 9776, Section 7.1 — Query Version Distinctions.
        //   <https://www.rfc-editor.org/rfc/rfc9776#section-7.1>
        // "Query Messages that do not match any of the above conditions
        // (e.g., a Query of length 10 octets) MUST be silently ignored."
        if igmp_type == TYPE_MEMBERSHIP_QUERY {
            let query_version = match data.len() {
                HEADER_SIZE if byte1 == 0 => Some(1),
                HEADER_SIZE => Some(2),
                n if n >= V3_QUERY_MIN_SIZE => Some(3),
                _ => None,
            };
            if let Some(v) = query_version {
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_QUERY_VERSION],
                    FieldValue::U8(v),
                    offset..offset + total_len,
                );
            }
        }

        match igmp_type {
            // Membership Query (0x11)
            // RFC 2236, Section 2 — <https://www.rfc-editor.org/rfc/rfc2236#section-2>
            // RFC 9776, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1>
            // IGMPv3 query: at least 12 bytes.
            TYPE_MEMBERSHIP_QUERY if data.len() >= V3_QUERY_MIN_SIZE => {
                // Decoded Max Resp Time.
                // RFC 9776, Section 4.1.1 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1.1>
                let decoded_mrt = decode_exp_field(byte1);
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_MAX_RESP_TIME_VALUE],
                    FieldValue::U32(decoded_mrt),
                    offset + 1..offset + 2,
                );

                // Byte 8: Flags(4) + S(1) + QRV(3).
                // RFC 9776, Section 4.1.4 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1.4> (Flags)
                // RFC 9776, Section 4.1.5 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1.5> (S Flag)
                // RFC 9776, Section 4.1.6 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1.6> (QRV)
                let flags_byte = data[8];
                let flags = (flags_byte >> 4) & 0x0F;
                let s_flag = (flags_byte >> 3) & 0x01;
                let qrv = flags_byte & 0x07;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_QUERY_FLAGS],
                    FieldValue::U8(flags),
                    offset + 8..offset + 9,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_S_FLAG],
                    FieldValue::U8(s_flag),
                    offset + 8..offset + 9,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_QRV],
                    FieldValue::U8(qrv),
                    offset + 8..offset + 9,
                );

                // Byte 9: QQIC.
                // RFC 9776, Section 4.1.7 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1.7>
                let qqic = data[9];
                let decoded_qqic = decode_exp_field(qqic);
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_QQIC],
                    FieldValue::U8(qqic),
                    offset + 9..offset + 10,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_QQIC_VALUE],
                    FieldValue::U32(decoded_qqic),
                    offset + 9..offset + 10,
                );

                // Bytes 10–11: Number of Sources.
                // RFC 9776, Section 4.1.8 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1.8>
                let num_sources = read_be_u16(data, 10)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_NUM_SOURCES],
                    FieldValue::U16(num_sources),
                    offset + 10..offset + 12,
                );

                // Source addresses (graceful truncation per Postel's law).
                // RFC 9776, Section 4.1.9 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1.9>
                push_query_sources(buf, data, offset, num_sources)?;
            }

            // IGMPv1 Membership Report (0x12)
            // RFC 1112, Section 6.2 — <https://www.rfc-editor.org/rfc/rfc1112#section-6.2>
            // IGMPv2 Membership Report (0x16) / Leave Group (0x17)
            // RFC 2236, Section 3 — <https://www.rfc-editor.org/rfc/rfc2236#section-3>
            TYPE_MEMBERSHIP_QUERY | TYPE_V1_REPORT | TYPE_V2_REPORT | TYPE_V2_LEAVE => {}

            // IGMPv3 Membership Report (0x22).
            // RFC 9776, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.2>
            TYPE_V3_REPORT => {
                // Bytes 4–5: Flags (IANA "IGMP Type Numbers" registry;
                // formerly "Reserved" in RFC 3376 §4.2).
                // RFC 9776, Section 4.2.3 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.2.3>
                let flags = read_be_u16(data, 4)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_REPORT_FLAGS],
                    FieldValue::U16(flags),
                    offset + 4..offset + 6,
                );

                // Bytes 6–7: Number of Group Records.
                // RFC 9776, Section 4.2.4 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.2.4>
                let num_records = read_be_u16(data, 6)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_NUM_GROUP_RECORDS],
                    FieldValue::U16(num_records),
                    offset + 6..offset + 8,
                );

                // Group records (graceful truncation per Postel's law).
                push_group_records(buf, data, offset, num_records)?;
            }

            // Multicast Router Advertisement (0x30).
            // RFC 4286, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc4286#section-3.2>
            TYPE_MRD_ADVERTISEMENT => {
                // RFC 4286, Section 3.2.4 — Query Interval (seconds).
                //   <https://www.rfc-editor.org/rfc/rfc4286#section-3.2.4>
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_QUERY_INTERVAL],
                    FieldValue::U16(read_be_u16(data, 4)?),
                    offset + 4..offset + 6,
                );
                // RFC 4286, Section 3.2.5 — Robustness Variable.
                //   <https://www.rfc-editor.org/rfc/rfc4286#section-3.2.5>
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_ROBUSTNESS_VARIABLE],
                    FieldValue::U16(read_be_u16(data, 6)?),
                    offset + 6..offset + 8,
                );
            }

            // Multicast Router Solicitation (0x31) / Termination (0x32).
            // RFC 4286, Sections 4.1 and 5.1 — no fields beyond the common
            // header. RFC 4286, Section 2 — "Any data beyond the fixed
            // message format MUST be ignored."
            //   <https://www.rfc-editor.org/rfc/rfc4286#section-2>
            TYPE_MRD_SOLICITATION | TYPE_MRD_TERMINATION => {}

            // Other types (unknown, or registered in the IANA "IGMP Type
            // Numbers" registry without a decoder here): the body is kept
            // as raw data.
            _ => {
                if total_len > COMMON_HEADER_SIZE {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_DATA],
                        FieldValue::Bytes(&data[COMMON_HEADER_SIZE..]),
                        offset + COMMON_HEADER_SIZE..offset + total_len,
                    );
                }
            }
        }

        buf.end_layer();

        Ok(DissectResult::new(total_len, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC Coverage
    //
    // | RFC Section    | Description                          | Test                                         |
    // |----------------|--------------------------------------|----------------------------------------------|
    // | RFC 9776 4.1.1 | Exponential field decoding (linear)  | decode_exp_field_linear                      |
    // | RFC 9776 4.1.1 | Exponential field decoding (exp)     | decode_exp_field_exponential                 |
    // | RFC 2236 2     | Membership Query (general)           | parse_igmpv2_membership_query_general        |
    // | RFC 2236 2     | Membership Query (group-specific)    | parse_igmpv2_membership_query_group_specific |
    // | RFC 1112 6.2   | IGMPv1 Membership Report             | parse_igmpv1_membership_report               |
    // | RFC 2236 3     | IGMPv2 Membership Report             | parse_igmpv2_membership_report               |
    // | RFC 2236 3     | Leave Group                          | parse_igmpv2_leave_group                     |
    // | RFC 9776 4.1   | IGMPv3 Query (no sources)            | parse_igmpv3_query_no_sources                |
    // | RFC 9776 4.1   | IGMPv3 Query (with sources)          | parse_igmpv3_query_with_sources              |
    // | RFC 9776 4.1.1 | IGMPv3 Query (exponential fields)    | parse_igmpv3_query_exponential_fields        |
    // | RFC 9776 4.1.4 | IGMPv3 Query Flags field             | parse_igmpv3_query_with_flags                |
    // | RFC 9776 4.2   | IGMPv3 Report (single record)        | parse_igmpv3_report_single_record            |
    // | RFC 9776 4.2   | IGMPv3 Report (multiple records)     | parse_igmpv3_report_multiple_records         |
    // | RFC 9776 4.2   | IGMPv3 Report (aux data)             | parse_igmpv3_report_with_aux_data            |
    // | RFC 9776 4.2.3 | IGMPv3 Report Flags field            | parse_igmpv3_report_with_flags               |
    // | ---            | Truncated packet                     | parse_truncated                              |
    // | ---            | IGMPv3 query truncated sources       | parse_igmpv3_query_truncated_sources         |
    // | ---            | IGMPv3 report truncated record       | parse_igmpv3_report_truncated_record         |
    // | ---            | Unknown IGMP type                    | parse_unknown_type                           |
    // | RFC 4286 3.2   | MRD Advertisement                    | parse_mrd_advertisement                      |
    // | RFC 4286 4.1   | MRD Solicitation (4 octets)          | parse_mrd_solicitation                       |
    // | RFC 4286 5.1   | MRD Termination (4 octets)           | parse_mrd_termination                        |
    // | RFC 4286 2     | MRD trailing data ignored            | parse_mrd_solicitation                       |
    // | RFC 4286 3.2   | MRD Advertisement truncated          | parse_mrd_advertisement_truncated            |
    // | RFC 4286 8     | MRD type names                       | igmp_type_names_from_iana_registry           |
    // | IANA registry  | DVMRP / PIMv1 / mtrace type names    | igmp_type_names_from_iana_registry           |
    // | ---            | Unknown type shorter than 8 octets   | parse_unknown_type_short                     |
    // | RFC 9776 7.1   | Query version (v1 / v2 / v3)         | query_version_distinctions                   |
    // | ---            | Offset handling                      | parse_with_offset                            |
    // | ---            | Dissector metadata                   | dissector_metadata                           |

    #[test]
    fn decode_exp_field_linear() {
        // RFC 9776, Section 4.1.1 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1.1>
        // values 0–127 are returned as-is.
        assert_eq!(decode_exp_field(0), 0);
        assert_eq!(decode_exp_field(1), 1);
        assert_eq!(decode_exp_field(100), 100);
        assert_eq!(decode_exp_field(127), 127);
    }

    #[test]
    fn decode_exp_field_exponential() {
        // RFC 9776, Section 4.1.1 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1.1>
        // value 128 (0x80) → (0 | 0x10) << (0 + 3) = 128
        assert_eq!(decode_exp_field(0x80), 128);
        // value 0xFF → (0xF | 0x10) << (0x7 + 3) = 31 << 10 = 31744
        assert_eq!(decode_exp_field(0xFF), 31744);
        // value 0x90 → (0 | 0x10) << (1 + 3) = 16 << 4 = 256
        assert_eq!(decode_exp_field(0x90), 256);
    }

    #[test]
    fn dissector_metadata() {
        let d = IgmpDissector;
        assert_eq!(d.name(), "Internet Group Management Protocol");
        assert_eq!(d.short_name(), "IGMP");
        assert_eq!(d.field_descriptors().len(), FIELD_DESCRIPTORS.len());
    }

    /// Build an IGMPv2 General Query: type=0x11, max_resp_time=100, group=0.0.0.0
    fn build_v2_general_query() -> Vec<u8> {
        vec![
            0x11, // type = Membership Query
            0x64, // max_resp_time = 100 (10 seconds)
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x00, // group address = 0.0.0.0 (general)
        ]
    }

    /// Count the number of Object containers within an Array range.
    fn count_array_objects(buf: &DissectBuffer, array_range: &core::ops::Range<u32>) -> usize {
        let mut count = 0;
        let mut i = array_range.start;
        while i < array_range.end {
            if let Some(field) = buf.fields().get(i as usize) {
                if let FieldValue::Object(ref r) = field.value {
                    count += 1;
                    i = r.end; // skip children
                    continue;
                }
            }
            i += 1;
        }
        count
    }

    /// Get the Object range for the nth element in an Array.
    fn nth_object_range(
        buf: &DissectBuffer,
        array_range: &core::ops::Range<u32>,
        index: usize,
    ) -> core::ops::Range<u32> {
        let mut obj_count = 0;
        let mut i = array_range.start;
        while i < array_range.end {
            if let Some(field) = buf.fields().get(i as usize) {
                if let FieldValue::Object(ref r) = field.value {
                    if obj_count == index {
                        return r.clone();
                    }
                    obj_count += 1;
                    i = r.end; // skip children
                    continue;
                }
            }
            i += 1;
        }
        panic!("Object at index {index} not found in array");
    }

    /// Get a named field value from an Object's fields.
    fn obj_field_value<'a>(
        buf: &'a DissectBuffer,
        obj_range: &core::ops::Range<u32>,
        name: &str,
    ) -> &'a FieldValue<'a> {
        let fields = buf.nested_fields(obj_range);
        &fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("field '{name}' not found"))
            .value
    }

    #[test]
    fn parse_igmpv2_membership_query_general() {
        let raw = build_v2_general_query();
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(&raw, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("IGMP").unwrap();
        assert_eq!(layer.name, "IGMP");
        assert_eq!(
            buf.field_by_name(layer, "type").unwrap().value,
            FieldValue::U8(0x11)
        );
        assert_eq!(
            buf.field_by_name(layer, "max_resp_time").unwrap().value,
            FieldValue::U8(0x64)
        );
        assert_eq!(
            buf.field_by_name(layer, "group_address").unwrap().value,
            FieldValue::Ipv4Addr([0, 0, 0, 0])
        );
        // display_fn check
        let type_field = buf.field_by_name(layer, "type").unwrap();
        let display = type_field.descriptor.display_fn.unwrap()(&type_field.value, &[]);
        assert_eq!(display, Some("Membership Query"));
    }

    #[test]
    fn parse_igmpv2_membership_query_group_specific() {
        let raw: &[u8] = &[
            0x11, 0x64, 0x00, 0x00, // type, max_resp_time, checksum
            0xEF, 0x01, 0x02, 0x03, // group = 239.1.2.3
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("IGMP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "group_address").unwrap().value,
            FieldValue::Ipv4Addr([239, 1, 2, 3])
        );
    }

    #[test]
    fn parse_igmpv1_membership_report() {
        let raw: &[u8] = &[
            0x12, 0x00, 0x00, 0x00, // type = 0x12 (v1 report), max_resp=0
            0xE0, 0x00, 0x00, 0x01, // group = 224.0.0.1
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("IGMP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "type").unwrap().value,
            FieldValue::U8(0x12)
        );
        let type_field = buf.field_by_name(layer, "type").unwrap();
        let display = type_field.descriptor.display_fn.unwrap()(&type_field.value, &[]);
        assert_eq!(display, Some("IGMPv1 Membership Report"));
        assert_eq!(
            buf.field_by_name(layer, "group_address").unwrap().value,
            FieldValue::Ipv4Addr([224, 0, 0, 1])
        );
    }

    #[test]
    fn parse_igmpv2_membership_report() {
        let raw: &[u8] = &[
            0x16, 0x00, 0x00, 0x00, // type = 0x16 (v2 report)
            0xEF, 0x01, 0x01, 0x01, // group = 239.1.1.1
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("IGMP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "type").unwrap().value,
            FieldValue::U8(0x16)
        );
        let type_field = buf.field_by_name(layer, "type").unwrap();
        let display = type_field.descriptor.display_fn.unwrap()(&type_field.value, &[]);
        assert_eq!(display, Some("IGMPv2 Membership Report"));
    }

    #[test]
    fn parse_igmpv2_leave_group() {
        let raw: &[u8] = &[
            0x17, 0x00, 0x00, 0x00, // type = 0x17 (leave)
            0xEF, 0x02, 0x03, 0x04, // group = 239.2.3.4
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("IGMP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "type").unwrap().value,
            FieldValue::U8(0x17)
        );
        let type_field = buf.field_by_name(layer, "type").unwrap();
        let display = type_field.descriptor.display_fn.unwrap()(&type_field.value, &[]);
        assert_eq!(display, Some("Leave Group"));
    }

    #[test]
    fn parse_igmpv3_query_no_sources() {
        // RFC 9776, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1>
        // 12-byte query with 0 sources, all Flags/S/QRV bits zero.
        let raw: &[u8] = &[
            0x11, 0x64, 0x00, 0x00, // type, max_resp_code=100, checksum
            0xE0, 0x00, 0x00, 0x01, // group = 224.0.0.1
            0x00, // Flags=0, S=0, QRV=0
            0x7B, // QQIC = 123
            0x00, 0x00, // num_sources = 0
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "max_resp_time_value")
                .unwrap()
                .value,
            FieldValue::U32(100)
        );
        // RFC 9776 §4.1.4: Flags (bits 0–3 of byte 8)
        assert_eq!(
            buf.field_by_name(layer, "flags").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "suppress_router_processing")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "qrv").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "qqic").unwrap().value,
            FieldValue::U8(123)
        );
        assert_eq!(
            buf.field_by_name(layer, "qqic_value").unwrap().value,
            FieldValue::U32(123)
        );
        assert_eq!(
            buf.field_by_name(layer, "num_sources").unwrap().value,
            FieldValue::U16(0)
        );
    }

    #[test]
    fn parse_igmpv3_query_with_flags() {
        // RFC 9776, Section 4.1.4 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1.4>
        // Byte 8 = 0xAB = Flags(1010)=0xA, S(1)=1, QRV(011)=3
        let raw: &[u8] = &[
            0x11, 0x64, 0x00, 0x00, // type, max_resp_code, checksum
            0xE0, 0x00, 0x00, 0x01, // group
            0xAB, // Flags=0xA, S=1, QRV=3
            0x00, // QQIC
            0x00, 0x00, // num_sources = 0
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "flags").unwrap().value,
            FieldValue::U8(0xA)
        );
        assert_eq!(
            buf.field_by_name(layer, "suppress_router_processing")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "qrv").unwrap().value,
            FieldValue::U8(3)
        );
    }

    #[test]
    fn parse_igmpv3_query_with_sources() {
        // RFC 9776, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1>
        // Query with 2 sources.
        let raw: &[u8] = &[
            0x11, 0x64, 0x00, 0x00, // type, max_resp_code, checksum
            0xEF, 0x01, 0x02, 0x03, // group = 239.1.2.3
            0x0B, // Flags=0, S=1, QRV=3
            0x0A, // QQIC = 10
            0x00, 0x02, // num_sources = 2
            0x0A, 0x00, 0x00, 0x01, // source 1 = 10.0.0.1
            0x0A, 0x00, 0x00, 0x02, // source 2 = 10.0.0.2
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "suppress_router_processing")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "qrv").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.field_by_name(layer, "num_sources").unwrap().value,
            FieldValue::U16(2)
        );

        // Verify sources array
        let sources_field = buf.field_by_name(layer, "sources").unwrap();
        if let FieldValue::Array(ref sources_range) = sources_field.value {
            assert_eq!(count_array_objects(&buf, sources_range), 2);
            let obj0 = nth_object_range(&buf, sources_range, 0);
            assert_eq!(
                *obj_field_value(&buf, &obj0, "address"),
                FieldValue::Ipv4Addr([10, 0, 0, 1])
            );
            let obj1 = nth_object_range(&buf, sources_range, 1);
            assert_eq!(
                *obj_field_value(&buf, &obj1, "address"),
                FieldValue::Ipv4Addr([10, 0, 0, 2])
            );
        } else {
            panic!("expected Array for sources");
        }
    }

    #[test]
    fn parse_igmpv3_query_exponential_fields() {
        // RFC 9776, Section 4.1.1 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.1.1>
        // max_resp_code=0x80 (128), QQIC=0xFF (31744)
        let raw: &[u8] = &[
            0x11, 0x80, 0x00, 0x00, // type, max_resp_code=128
            0x00, 0x00, 0x00, 0x00, // group = 0.0.0.0
            0x00, // Flags=0, S=0, QRV=0
            0xFF, // QQIC = 0xFF
            0x00, 0x00, // num_sources = 0
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "max_resp_time_value")
                .unwrap()
                .value,
            FieldValue::U32(128)
        );
        assert_eq!(
            buf.field_by_name(layer, "qqic_value").unwrap().value,
            FieldValue::U32(31744)
        );
    }

    #[test]
    fn parse_igmpv3_report_single_record() {
        // RFC 9776, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.2>
        // v3 report with 1 group record, 0 sources.
        let raw: &[u8] = &[
            0x22, 0x00, 0x00, 0x00, // type = 0x22, reserved, checksum
            0x00, 0x00, // flags (RFC 9776 §4.2.3)
            0x00, 0x01, // num_group_records = 1
            // Group Record: MODE_IS_INCLUDE, aux=0, num_src=0
            0x01, 0x00, 0x00, 0x00, // record_type=1, aux_data_len=0, num_sources=0
            0xEF, 0x01, 0x01, 0x01, // multicast_address = 239.1.1.1
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "type").unwrap().value,
            FieldValue::U8(0x22)
        );
        let type_field = buf.field_by_name(layer, "type").unwrap();
        let display = type_field.descriptor.display_fn.unwrap()(&type_field.value, &[]);
        assert_eq!(display, Some("IGMPv3 Membership Report"));

        // group_address should NOT be present for 0x22
        assert!(buf.field_by_name(layer, "group_address").is_none());

        // RFC 9776 §4.2.3: Flags field (formerly "Reserved" in RFC 3376).
        assert_eq!(
            buf.field_by_name(layer, "flags").unwrap().value,
            FieldValue::U16(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "num_group_records").unwrap().value,
            FieldValue::U16(1)
        );

        let records_field = buf.field_by_name(layer, "group_records").unwrap();
        if let FieldValue::Array(ref records_range) = records_field.value {
            assert_eq!(count_array_objects(&buf, records_range), 1);
            let obj0 = nth_object_range(&buf, records_range, 0);
            let children = buf.nested_fields(&obj0);
            assert_eq!(children[0].value, FieldValue::U8(1)); // record_type
            // display_fn on record_type
            let rt_display =
                children[0].descriptor.display_fn.unwrap()(&children[0].value, children);
            assert_eq!(rt_display, Some("MODE_IS_INCLUDE"));
            assert_eq!(
                *obj_field_value(&buf, &obj0, "multicast_address"),
                FieldValue::Ipv4Addr([239, 1, 1, 1])
            );
        } else {
            panic!("expected Array for group_records");
        }
    }

    #[test]
    fn parse_igmpv3_report_multiple_records() {
        // RFC 9776, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.2>
        // v3 report with 2 group records.
        let raw: &[u8] = &[
            0x22, 0x00, 0x00, 0x00, // type, reserved, checksum
            0x00, 0x00, // flags (RFC 9776 §4.2.3)
            0x00, 0x02, // num_group_records = 2
            // Record 1: MODE_IS_EXCLUDE, aux=0, num_src=0
            0x02, 0x00, 0x00, 0x00, 0xEF, 0x01, 0x01, 0x01,
            // Record 2: CHANGE_TO_INCLUDE_MODE, aux=0, num_src=1
            0x03, 0x00, 0x00, 0x01, 0xEF, 0x02, 0x02, 0x02, 0x0A, 0x00, 0x00,
            0x01, // source = 10.0.0.1
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let records_field = buf.field_by_name(layer, "group_records").unwrap();
        if let FieldValue::Array(ref records_range) = records_field.value {
            assert_eq!(count_array_objects(&buf, records_range), 2);

            // Record 1
            let obj0 = nth_object_range(&buf, records_range, 0);
            let c0 = buf.nested_fields(&obj0);
            assert_eq!(c0[0].value, FieldValue::U8(2));
            let d = c0[0].descriptor.display_fn.unwrap()(&c0[0].value, c0);
            assert_eq!(d, Some("MODE_IS_EXCLUDE"));

            // Record 2 with source
            let obj1 = nth_object_range(&buf, records_range, 1);
            let c1 = buf.nested_fields(&obj1);
            assert_eq!(c1[0].value, FieldValue::U8(3));
            let d = c1[0].descriptor.display_fn.unwrap()(&c1[0].value, c1);
            assert_eq!(d, Some("CHANGE_TO_INCLUDE_MODE"));
            // Check source within record 2
            let src_field = c1.iter().find(|f| f.name() == "sources").unwrap();
            if let FieldValue::Array(ref srcs_range) = src_field.value {
                assert_eq!(count_array_objects(&buf, srcs_range), 1);
                let src_obj = nth_object_range(&buf, srcs_range, 0);
                assert_eq!(
                    *obj_field_value(&buf, &src_obj, "address"),
                    FieldValue::Ipv4Addr([10, 0, 0, 1])
                );
            }
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn parse_igmpv3_report_with_aux_data() {
        // RFC 9776, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.2.2>
        // Record with aux_data_len=1 (4 bytes).
        let raw: &[u8] = &[
            0x22, 0x00, 0x00, 0x00, // type, reserved, checksum
            0x00, 0x00, // flags
            0x00, 0x01, // num_group_records = 1
            // Record: MODE_IS_INCLUDE, aux_data_len=1, num_src=0
            0x01, 0x01, 0x00, 0x00, // record_type=1, aux=1, num_src=0
            0xEF, 0x03, 0x03, 0x03, // multicast_address
            0xDE, 0xAD, 0xBE, 0xEF, // aux data (4 bytes)
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let records_field = buf.field_by_name(layer, "group_records").unwrap();
        if let FieldValue::Array(ref records_range) = records_field.value {
            assert_eq!(count_array_objects(&buf, records_range), 1);
            let obj0 = nth_object_range(&buf, records_range, 0);
            let children = buf.nested_fields(&obj0);
            assert_eq!(children.len(), 6); // includes aux_data
            assert_eq!(
                *obj_field_value(&buf, &obj0, "aux_data"),
                FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
            );
        }
    }

    #[test]
    fn parse_igmpv3_report_with_flags() {
        // RFC 9776, Section 4.2.3 — <https://www.rfc-editor.org/rfc/rfc9776#section-4.2.3>
        // Non-zero Flags field (formerly "Reserved" in RFC 3376 §4.2).
        let raw: &[u8] = &[
            0x22, 0x00, 0x00, 0x00, // type, reserved, checksum
            0xAB, 0xCD, // flags = 0xABCD
            0x00, 0x00, // num_group_records = 0
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "flags").unwrap().value,
            FieldValue::U16(0xABCD)
        );
    }

    #[test]
    fn parse_truncated() {
        let raw: &[u8] = &[0x11, 0x00, 0x00]; // only 3 bytes
        let mut buf = DissectBuffer::new();
        let result = IgmpDissector.dissect(raw, &mut buf, 0);
        assert!(result.is_err());
        if let Err(PacketError::Truncated { expected, actual }) = result {
            assert_eq!(expected, 8);
            assert_eq!(actual, 3);
        }
    }

    #[test]
    fn parse_igmpv3_query_truncated_sources() {
        // Claims 2 sources but only has room for 1 — graceful truncation
        let raw: &[u8] = &[
            0x11, 0x64, 0x00, 0x00, // type, max_resp_code, checksum
            0x00, 0x00, 0x00, 0x00, // group
            0x00, // flags
            0x00, // QQIC
            0x00, 0x02, // num_sources = 2
            0x0A, 0x00, 0x00, 0x01, // source 1 only (missing source 2)
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let sources_field = buf.field_by_name(layer, "sources").unwrap();
        if let FieldValue::Array(ref sources_range) = sources_field.value {
            assert_eq!(count_array_objects(&buf, sources_range), 1); // gracefully parsed 1 of 2
        }
    }

    #[test]
    fn parse_igmpv3_report_truncated_record() {
        // Claims 2 records but data ends after 1
        let raw: &[u8] = &[
            0x22, 0x00, 0x00, 0x00, // type, reserved, checksum
            0x00, 0x00, // flags
            0x00, 0x02, // num_group_records = 2
            // Only 1 complete record
            0x01, 0x00, 0x00, 0x00, 0xEF, 0x01, 0x01, 0x01,
            // Truncated second record (only 4 bytes)
            0x02, 0x00, 0x00, 0x00,
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let records_field = buf.field_by_name(layer, "group_records").unwrap();
        if let FieldValue::Array(ref records_range) = records_field.value {
            assert_eq!(count_array_objects(&buf, records_range), 1); // gracefully parsed 1 of 2
        }
    }

    #[test]
    fn parse_unknown_type() {
        let raw: &[u8] = &[
            0xFF, 0x00, 0x00, 0x00, // unknown type
            0xE0, 0x00, 0x00, 0x01, // group
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "type").unwrap().value,
            FieldValue::U8(0xFF)
        );
        // display_fn returns None for unknown type
        let type_field = buf.field_by_name(layer, "type").unwrap();
        let display = type_field.descriptor.display_fn.unwrap()(&type_field.value, &[]);
        assert_eq!(display, None);
        // The body of an unknown type is not interpreted.
        assert_eq!(
            buf.field_by_name(layer, "code").unwrap().value,
            FieldValue::U8(0)
        );
        let data = buf.field_by_name(layer, "data").unwrap();
        assert_eq!(data.value, FieldValue::Bytes(&[0xE0, 0x00, 0x00, 0x01]));
        assert_eq!(data.range, 4..8);
        assert!(buf.field_by_name(layer, "group_address").is_none());
        assert!(buf.field_by_name(layer, "max_resp_time").is_none());
    }

    #[test]
    fn parse_unknown_type_short() {
        // An unknown type (e.g. 0x40) is not bound to the 8-octet layout.
        let raw: &[u8] = &[0x40, 0x07, 0x12, 0x34];
        let mut buf = DissectBuffer::new();
        let result = IgmpDissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 4);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "code").unwrap().value,
            FieldValue::U8(7)
        );
        assert_eq!(
            buf.field_by_name(layer, "checksum").unwrap().value,
            FieldValue::U16(0x1234)
        );
        assert!(buf.field_by_name(layer, "data").is_none());

        let mut buf = DissectBuffer::new();
        let err = IgmpDissector.dissect(&raw[..3], &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 3
            }
        ));
        let mut buf = DissectBuffer::new();
        let err = IgmpDissector.dissect(&[], &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 0
            }
        ));
    }

    #[test]
    fn parse_mrd_advertisement() {
        // RFC 4286, Section 3.2 — interval 20 s, QQI 125 s, robustness 2.
        //   <https://www.rfc-editor.org/rfc/rfc4286#section-3.2>
        let raw: &[u8] = &[0x30, 0x14, 0xcf, 0x6c, 0x00, 0x7d, 0x00, 0x02];
        let mut buf = DissectBuffer::new();
        let result = IgmpDissector.dissect(raw, &mut buf, 20).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "type_name"),
            Some("Multicast Router Advertisement")
        );
        let ai = buf.field_by_name(layer, "advertisement_interval").unwrap();
        assert_eq!(ai.value, FieldValue::U8(20));
        assert_eq!(ai.range, 21..22);
        assert_eq!(
            buf.field_by_name(layer, "checksum").unwrap().value,
            FieldValue::U16(0xcf6c)
        );
        let qi = buf.field_by_name(layer, "query_interval").unwrap();
        assert_eq!(qi.value, FieldValue::U16(125));
        assert_eq!(qi.range, 24..26);
        let rv = buf.field_by_name(layer, "robustness_variable").unwrap();
        assert_eq!(rv.value, FieldValue::U16(2));
        assert_eq!(rv.range, 26..28);
        assert!(buf.field_by_name(layer, "group_address").is_none());
        assert!(buf.field_by_name(layer, "max_resp_time").is_none());
    }

    #[test]
    fn parse_mrd_advertisement_truncated() {
        let raw: &[u8] = &[0x30, 0x14, 0xcf, 0x6c, 0x00, 0x7d];
        let mut buf = DissectBuffer::new();
        let err = IgmpDissector.dissect(raw, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 6
            }
        ));
    }

    #[test]
    fn parse_mrd_solicitation() {
        // RFC 4286, Section 4.1 — 4-octet Solicitation.
        //   <https://www.rfc-editor.org/rfc/rfc4286#section-4.1>
        let raw: &[u8] = &[0x31, 0x00, 0xce, 0xff];
        let mut buf = DissectBuffer::new();
        let result = IgmpDissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 4);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "type_name"),
            Some("Multicast Router Solicitation")
        );
        assert_eq!(
            buf.field_by_name(layer, "reserved").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "checksum").unwrap().value,
            FieldValue::U16(0xceff)
        );
        assert!(buf.field_by_name(layer, "group_address").is_none());
        assert!(buf.field_by_name(layer, "max_resp_time").is_none());

        // RFC 4286, Section 2 — "Any data beyond the fixed message format
        // MUST be ignored."
        //   <https://www.rfc-editor.org/rfc/rfc4286#section-2>
        let raw: &[u8] = &[0x31, 0x00, 0xce, 0xff, 0xde, 0xad, 0xbe, 0xef];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(buf.layer_fields(layer).len(), 3);
    }

    #[test]
    fn parse_mrd_termination() {
        // RFC 4286, Section 5.1 — 4-octet Termination.
        //   <https://www.rfc-editor.org/rfc/rfc4286#section-5.1>
        let raw: &[u8] = &[0x32, 0x00, 0xcd, 0xff];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "type_name"),
            Some("Multicast Router Termination")
        );
        assert_eq!(buf.layer_fields(layer).len(), 3);
    }

    #[test]
    fn igmp_type_names_from_iana_registry() {
        for (t, name) in [
            (0x13, "DVMRP"),
            (0x14, "PIM version 1"),
            (0x1e, "Multicast Traceroute Response"),
            (0x1f, "Multicast Traceroute"),
            (0x30, "Multicast Router Advertisement"),
            (0x31, "Multicast Router Solicitation"),
            (0x32, "Multicast Router Termination"),
        ] {
            assert_eq!(igmp_type_name(t), Some(name), "type {t:#x}");
        }
        // Named but body not decoded: DVMRP message is kept as raw data.
        let raw: &[u8] = &[0x13, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xff];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "code").unwrap().value,
            FieldValue::U8(2)
        );
        assert!(buf.field_by_name(layer, "group_address").is_none());
    }

    #[test]
    fn query_version_distinctions() {
        // RFC 9776, Section 7.1 — Query Version Distinctions.
        //   <https://www.rfc-editor.org/rfc/rfc9776#section-7.1>
        let cases: [(&[u8], Option<u8>); 4] = [
            (&[0x11, 0x00, 0, 0, 0, 0, 0, 0], Some(1)),
            (&[0x11, 0x64, 0, 0, 0, 0, 0, 0], Some(2)),
            (&[0x11, 0x64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], Some(3)),
            (&[0x11, 0x64, 0, 0, 0, 0, 0, 0, 0, 0], None),
        ];
        for (raw, expected) in cases {
            let mut buf = DissectBuffer::new();
            IgmpDissector.dissect(raw, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            let qv = buf
                .field_by_name(layer, "query_version")
                .map(|f| f.value.clone());
            assert_eq!(qv, expected.map(FieldValue::U8), "len {}", raw.len());
        }
        // Not a query: no query_version.
        let raw: &[u8] = &[0x16, 0x00, 0, 0, 239, 1, 1, 1];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();
        assert!(
            buf.field_by_name(&buf.layers()[0], "query_version")
                .is_none()
        );
    }

    #[test]
    fn parse_with_offset() {
        let raw: &[u8] = &[
            0x16, 0x00, 0x00, 0x00, // v2 report
            0xEF, 0x01, 0x01, 0x01, // group
        ];
        let offset = 34; // e.g. Ethernet(14) + IPv4(20)
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, offset).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 34..42);
        assert_eq!(buf.field_by_name(layer, "type").unwrap().range, 34..35);
        assert_eq!(
            buf.field_by_name(layer, "group_address").unwrap().range,
            38..42
        );
    }

    #[test]
    fn group_record_container_resolves_to_record_type_name() {
        // IGMPv3 Report with one MODE_IS_INCLUDE record so the container
        // label resolves to "MODE_IS_INCLUDE" instead of duplicating the
        // inner "Record Type" label.
        let raw: &[u8] = &[
            0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0xEF, 0x01,
            0x01, 0x01,
        ];
        let mut buf = DissectBuffer::new();
        IgmpDissector.dissect(raw, &mut buf, 0).unwrap();

        let (idx, field) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "group_record")
            .expect("group_record container not found");
        assert!(matches!(field.value, FieldValue::Object(_)));
        assert_eq!(field.display_name(), "Group Record");
        assert_eq!(
            buf.resolve_container_display_name(idx as u32),
            Some("MODE_IS_INCLUDE")
        );
    }

    #[test]
    fn test_references_and_layer() {
        let dissector = IgmpDissector;
        let refs = dissector.references();
        assert!(!refs.is_empty());
        for r in refs {
            assert!(!r.id.is_empty());
            assert!(r.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Network));
    }
}
