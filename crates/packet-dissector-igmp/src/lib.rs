//! IGMP (Internet Group Management Protocol) dissector.
//!
//! ## References
//! - RFC 1112: <https://www.rfc-editor.org/rfc/rfc1112> (IGMPv1)
//! - RFC 2236: <https://www.rfc-editor.org/rfc/rfc2236> (IGMPv2)
//! - RFC 3376: <https://www.rfc-editor.org/rfc/rfc3376> (IGMPv3)

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_ipv4_addr};

/// Returns a human-readable name for well-known IGMP type values.
///
/// RFC 1112 Section 6.2, RFC 2236 Section 2, RFC 3376 Section 4.
fn igmp_type_name(v: u8) -> Option<&'static str> {
    match v {
        0x11 => Some("Membership Query"),
        0x12 => Some("IGMPv1 Membership Report"),
        0x16 => Some("IGMPv2 Membership Report"),
        0x17 => Some("Leave Group"),
        0x22 => Some("IGMPv3 Membership Report"),
        _ => None,
    }
}

/// Returns a human-readable name for IGMPv3 group record type values.
///
/// RFC 3376 Section 4.2.12.
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

/// Decodes an IGMPv3 exponential field value.
///
/// RFC 3376 Section 4.1.1: If `code < 128`, the value equals `code`.
/// Otherwise, the value is computed as `(mant | 0x10) << (exp + 3)` where
/// `mant` is bits 0–3 and `exp` is bits 4–6 of the code byte.
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
const HEADER_SIZE: usize = 8;

/// Minimum IGMPv3 Membership Query size (RFC 3376 Section 4.1).
const V3_QUERY_MIN_SIZE: usize = 12;

/// IGMPv3 Membership Report header size before group records (RFC 3376 Section 4.2).
const V3_REPORT_HEADER_SIZE: usize = 8;

/// Minimum size of a single IGMPv3 group record header (RFC 3376 Section 4.2.4).
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
/// Field descriptor index for `suppress_router_processing` (S flag).
const FD_S_FLAG: usize = 5;
/// Field descriptor index for `qrv`.
const FD_QRV: usize = 6;
/// Field descriptor index for `qqic` (raw).
const FD_QQIC: usize = 7;
/// Field descriptor index for `qqic_value` (decoded).
const FD_QQIC_VALUE: usize = 8;
/// Field descriptor index for `num_sources`.
const FD_NUM_SOURCES: usize = 9;
/// Field descriptor index for `sources`.
const FD_SOURCES: usize = 10;
/// Field descriptor index for `reserved`.
const FD_RESERVED: usize = 11;
/// Field descriptor index for `num_group_records`.
const FD_NUM_GROUP_RECORDS: usize = 12;
/// Field descriptor index for `group_records`.
const FD_GROUP_RECORDS: usize = 13;

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
    FieldDescriptor::new("max_resp_time", "Max Resp Time", FieldType::U8),
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
    FieldDescriptor::new("reserved", "Reserved", FieldType::U16).optional(),
    FieldDescriptor::new(
        "num_group_records",
        "Number of Group Records",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("group_records", "Group Records", FieldType::Array)
        .optional()
        .with_children(GROUP_RECORD_CHILDREN),
];

/// IGMP dissector supporting IGMPv1 (RFC 1112), IGMPv2 (RFC 2236), and
/// IGMPv3 (RFC 3376).
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
            &GROUP_RECORD_CHILDREN[GRC_RECORD_TYPE],
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

        let total_len = data.len();
        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_len,
        );

        // Common header fields (RFC 2236 Section 2)
        let igmp_type = data[0];
        let max_resp_time = data[1];
        let checksum = read_be_u16(data, 2)?;

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TYPE],
            FieldValue::U8(igmp_type),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MAX_RESP_TIME],
            FieldValue::U8(max_resp_time),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM],
            FieldValue::U16(checksum),
            offset + 2..offset + 4,
        );

        // Group address is present for all types except IGMPv3 Report (0x22)
        if igmp_type != 0x22 {
            let group_addr = read_ipv4_addr(data, 4)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_GROUP_ADDRESS],
                FieldValue::Ipv4Addr(group_addr),
                offset + 4..offset + 8,
            );
        }

        match igmp_type {
            // Membership Query (0x11) — RFC 2236 Section 2 / RFC 3376 Section 4.1
            0x11 => {
                // IGMPv3 query: longer than 8 bytes (RFC 3376 Section 4.1)
                if data.len() >= V3_QUERY_MIN_SIZE {
                    // Decoded Max Resp Time (RFC 3376 Section 4.1.1)
                    let decoded_mrt = decode_exp_field(max_resp_time);
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_MAX_RESP_TIME_VALUE],
                        FieldValue::U32(decoded_mrt),
                        offset + 1..offset + 2,
                    );

                    // Byte 8: Resv(4) + S(1) + QRV(3) — RFC 3376 Section 4.1.6–4.1.7
                    let flags_byte = data[8];
                    let s_flag = (flags_byte >> 3) & 0x01;
                    let qrv = flags_byte & 0x07;
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

                    // Byte 9: QQIC — RFC 3376 Section 4.1.8
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

                    // Bytes 10–11: Number of Sources — RFC 3376 Section 4.1.9
                    let num_sources = read_be_u16(data, 10)?;
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_NUM_SOURCES],
                        FieldValue::U16(num_sources),
                        offset + 10..offset + 12,
                    );

                    // Source addresses (graceful truncation per Postel's law)
                    push_query_sources(buf, data, offset, num_sources)?;
                }
            }

            // IGMPv1 Membership Report (0x12) — RFC 1112 Section 6.2
            // IGMPv2 Membership Report (0x16) — RFC 2236 Section 3
            // Leave Group (0x17) — RFC 2236 Section 3
            0x12 | 0x16 | 0x17 => {}

            // IGMPv3 Membership Report (0x22) — RFC 3376 Section 4.2
            0x22 => {
                // Bytes 4–5: Reserved
                let reserved = read_be_u16(data, 4)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_RESERVED],
                    FieldValue::U16(reserved),
                    offset + 4..offset + 6,
                );

                // Bytes 6–7: Number of Group Records
                let num_records = read_be_u16(data, 6)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_NUM_GROUP_RECORDS],
                    FieldValue::U16(num_records),
                    offset + 6..offset + 8,
                );

                // Group records (graceful truncation per Postel's law)
                push_group_records(buf, data, offset, num_records)?;
            }

            // Unknown type — group_address already pushed above
            _ => {}
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
    // | RFC Section | Description                          | Test                                         |
    // |-------------|--------------------------------------|----------------------------------------------|
    // | RFC 3376 4.1.1 | Exponential field decoding (linear)  | decode_exp_field_linear                  |
    // | RFC 3376 4.1.1 | Exponential field decoding (exp)     | decode_exp_field_exponential             |
    // | RFC 2236 2  | Membership Query (general)           | parse_igmpv2_membership_query_general        |
    // | RFC 2236 2  | Membership Query (group-specific)    | parse_igmpv2_membership_query_group_specific |
    // | RFC 1112 6.2| IGMPv1 Membership Report             | parse_igmpv1_membership_report               |
    // | RFC 2236 3  | IGMPv2 Membership Report             | parse_igmpv2_membership_report               |
    // | RFC 2236 3  | Leave Group                          | parse_igmpv2_leave_group                     |
    // | RFC 3376 4.1| IGMPv3 Query (no sources)            | parse_igmpv3_query_no_sources                |
    // | RFC 3376 4.1| IGMPv3 Query (with sources)          | parse_igmpv3_query_with_sources              |
    // | RFC 3376 4.1.1| IGMPv3 Query (exponential fields)  | parse_igmpv3_query_exponential_fields        |
    // | RFC 3376 4.2| IGMPv3 Report (single record)        | parse_igmpv3_report_single_record            |
    // | RFC 3376 4.2| IGMPv3 Report (multiple records)     | parse_igmpv3_report_multiple_records         |
    // | RFC 3376 4.2| IGMPv3 Report (aux data)             | parse_igmpv3_report_with_aux_data            |
    // | ---         | Truncated packet                     | parse_truncated                              |
    // | ---         | IGMPv3 query truncated sources       | parse_igmpv3_query_truncated_sources         |
    // | ---         | IGMPv3 report truncated record       | parse_igmpv3_report_truncated_record         |
    // | ---         | Unknown IGMP type                    | parse_unknown_type                           |
    // | ---         | Offset handling                      | parse_with_offset                            |
    // | ---         | Dissector metadata                   | dissector_metadata                           |

    #[test]
    fn decode_exp_field_linear() {
        // RFC 3376 Section 4.1.1: values 0–127 are returned as-is.
        assert_eq!(decode_exp_field(0), 0);
        assert_eq!(decode_exp_field(1), 1);
        assert_eq!(decode_exp_field(100), 100);
        assert_eq!(decode_exp_field(127), 127);
    }

    #[test]
    fn decode_exp_field_exponential() {
        // RFC 3376 Section 4.1.1: value 128 (0x80) → (0 | 0x10) << (0 + 3) = 128
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
        // RFC 3376 Section 4.1: 12-byte query with 0 sources
        let raw: &[u8] = &[
            0x11, 0x64, 0x00, 0x00, // type, max_resp_code=100, checksum
            0xE0, 0x00, 0x00, 0x01, // group = 224.0.0.1
            0x00, // Resv=0, S=0, QRV=0
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
    fn parse_igmpv3_query_with_sources() {
        // RFC 3376 Section 4.1: query with 2 sources
        let raw: &[u8] = &[
            0x11, 0x64, 0x00, 0x00, // type, max_resp_code, checksum
            0xEF, 0x01, 0x02, 0x03, // group = 239.1.2.3
            0x0B, // Resv=0, S=1, QRV=3
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
        // RFC 3376 Section 4.1.1: max_resp_code=0x80 (128), QQIC=0xFF (31744)
        let raw: &[u8] = &[
            0x11, 0x80, 0x00, 0x00, // type, max_resp_code=128
            0x00, 0x00, 0x00, 0x00, // group = 0.0.0.0
            0x00, // Resv=0, S=0, QRV=0
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
        // RFC 3376 Section 4.2: v3 report with 1 group record, 0 sources
        let raw: &[u8] = &[
            0x22, 0x00, 0x00, 0x00, // type = 0x22, reserved, checksum
            0x00, 0x00, // reserved
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
        // RFC 3376 Section 4.2: v3 report with 2 group records
        let raw: &[u8] = &[
            0x22, 0x00, 0x00, 0x00, // type, reserved, checksum
            0x00, 0x00, // reserved
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
        // RFC 3376 Section 4.2: record with aux_data_len=1 (4 bytes)
        let raw: &[u8] = &[
            0x22, 0x00, 0x00, 0x00, // type, reserved, checksum
            0x00, 0x00, // reserved
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
            0x00, 0x00, // reserved
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
        assert_eq!(
            buf.field_by_name(layer, "group_address").unwrap().value,
            FieldValue::Ipv4Addr([224, 0, 0, 1])
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
}
