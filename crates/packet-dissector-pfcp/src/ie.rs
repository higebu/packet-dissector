//! Generic PFCP IE (Information Element) TLV parser.
//!
//! 3GPP TS 29.244, Section 8.1.1 — IE TLV format:
//! - Octets 1-2: Type (16 bits)
//! - Octets 3-4: Length (16 bits, excludes 4-byte header)
//! - Octets 5..n: IE data (or Enterprise ID + data for vendor IEs)

use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

use crate::ie_parsers;

static FD_INLINE_LENGTH: FieldDescriptor = FieldDescriptor::new("length", "Length", FieldType::U16);

static FD_INLINE_TYPE: FieldDescriptor = FieldDescriptor {
    name: "type",
    display_name: "Type",
    field_type: FieldType::U32,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U32(t) => Some(ie_type_name(*t as u16)),
        _ => None,
    }),
    format_fn: None,
};

/// Child field descriptors for each IE element in the `ies` array.
///
/// These describe the common fields present in every parsed IE object.
pub static IE_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U32,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U32(t) => Some(ie_type_name(*t as u16)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("value", "Value", FieldType::Bytes),
];

/// IE header size: Type(2) + Length(2) = 4 bytes.
///
/// 3GPP TS 29.244, Section 8.1.1.
pub const IE_HEADER_SIZE: usize = 4;

/// Maximum recursion depth for Grouped IEs (stack overflow guard).
///
/// 3GPP TS 29.244, Section 8.1.1.
pub const MAX_GROUPED_DEPTH: usize = 8;

/// Parse a sequence of IEs from the given data, pushing fields into `buf`.
///
/// `base_offset` is the byte offset in the original packet where `data` starts.
/// `depth` tracks recursion depth for grouped IEs; callers at the top level pass `0`.
///
/// 3GPP TS 29.244, Section 8.1.1.
pub fn parse_ies<'pkt>(
    data: &'pkt [u8],
    base_offset: usize,
    depth: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    let mut pos = 0;

    while pos + IE_HEADER_SIZE <= data.len() {
        let ie_type = read_be_u16(data, pos)?;
        let ie_length = read_be_u16(data, pos + 2)? as usize;

        // Bounds check — truncated IE
        if pos + IE_HEADER_SIZE + ie_length > data.len() {
            break;
        }

        let ie_data = &data[pos + IE_HEADER_SIZE..pos + IE_HEADER_SIZE + ie_length];
        let ie_offset = base_offset + pos + IE_HEADER_SIZE;

        let ie_start = base_offset + pos;
        let ie_end = ie_start + IE_HEADER_SIZE + ie_length;

        // Each IE is an Object in the array
        let obj_idx =
            buf.begin_container(&FD_INLINE_TYPE, FieldValue::Object(0..0), ie_start..ie_end);

        buf.push_field(
            &FD_INLINE_TYPE,
            FieldValue::U32(u32::from(ie_type)),
            ie_start..ie_start + 2,
        );
        buf.push_field(
            &FD_INLINE_LENGTH,
            FieldValue::U16(ie_length as u16),
            ie_start + 2..ie_start + 4,
        );

        let field_count_before = buf.field_count();
        let value = ie_parsers::parse_ie_value(ie_type, ie_data, ie_offset, depth, buf);

        // If parse_ie_value pushed container fields directly into the buffer
        // (Object or Array sentinel with 0..0 range), the value is already
        // present. Otherwise, push the returned value as a "value" field.
        let was_pushed_inline = buf.field_count() > field_count_before;

        if !was_pushed_inline {
            buf.push_field(
                &IE_CHILD_FIELDS[2],
                value,
                ie_start + IE_HEADER_SIZE..ie_end,
            );
        }

        buf.end_container(obj_idx);

        pos += IE_HEADER_SIZE + ie_length;
    }

    Ok(())
}

/// Returns the human-readable name for a PFCP IE type code.
///
/// 3GPP TS 29.244, Table 8.1.2-1.
pub fn ie_type_name(ie_type: u16) -> &'static str {
    match ie_type {
        1 => "Create PDR",
        2 => "PDI",
        3 => "Create FAR",
        4 => "Forwarding Parameters",
        5 => "Duplicating Parameters",
        6 => "Create URR",
        7 => "Create QER",
        8 => "Created PDR",
        9 => "Update PDR",
        10 => "Update FAR",
        11 => "Update Forwarding Parameters",
        12 => "Update BAR (Session Report Response)",
        13 => "Update URR",
        14 => "Update QER",
        15 => "Remove PDR",
        16 => "Remove FAR",
        17 => "Remove URR",
        18 => "Remove QER",
        19 => "Cause",
        20 => "Source Interface",
        21 => "F-TEID",
        22 => "Network Instance",
        23 => "SDF Filter",
        24 => "Application ID",
        25 => "Gate Status",
        26 => "MBR",
        27 => "GBR",
        28 => "QER Correlation ID",
        29 => "Precedence",
        30 => "Transport Level Marking",
        31 => "Volume Threshold",
        32 => "Time Threshold",
        33 => "Monitoring Time",
        34 => "Subsequent Volume Threshold",
        35 => "Subsequent Time Threshold",
        36 => "Inactivity Detection Time",
        37 => "Reporting Triggers",
        38 => "Redirect Information",
        39 => "Report Type",
        40 => "Offending IE",
        41 => "Forwarding Policy",
        42 => "Destination Interface",
        43 => "UP Function Features",
        44 => "Apply Action",
        45 => "Downlink Data Service Information",
        46 => "Downlink Data Notification Delay",
        47 => "DL Buffering Duration",
        48 => "DL Buffering Suggested Packet Count",
        49 => "PFCPSMReq-Flags",
        50 => "PFCPSRRsp-Flags",
        51 => "Load Control Information",
        52 => "Sequence Number",
        53 => "Metric",
        54 => "Overload Control Information",
        55 => "Timer",
        56 => "PDR ID",
        57 => "F-SEID",
        58 => "Application ID PFDs",
        59 => "PFD Context",
        60 => "Node ID",
        61 => "PFD Contents",
        62 => "Measurement Method",
        63 => "Usage Report Trigger",
        64 => "Measurement Period",
        65 => "FQ-CSID",
        66 => "Volume Measurement",
        67 => "Duration Measurement",
        68 => "Application Detection Information",
        69 => "Time of First Packet",
        70 => "Time of Last Packet",
        71 => "Quota Holding Time",
        72 => "Dropped DL Traffic Threshold",
        73 => "Volume Quota",
        74 => "Time Quota",
        75 => "Start Time",
        76 => "End Time",
        77 => "Query URR",
        78 => "Usage Report (Session Modification Response)",
        79 => "Usage Report (Session Deletion Response)",
        80 => "Usage Report (Session Report Request)",
        81 => "URR ID",
        82 => "Linked URR ID",
        83 => "Downlink Data Report",
        84 => "Outer Header Creation",
        85 => "Create BAR",
        86 => "Update BAR (Session Modification Request)",
        87 => "Remove BAR",
        88 => "BAR ID",
        89 => "CP Function Features",
        90 => "Usage Information",
        91 => "Application Instance ID",
        92 => "Flow Information",
        93 => "UE IP Address",
        94 => "Packet Rate",
        95 => "Outer Header Removal",
        96 => "Recovery Time Stamp",
        97 => "DL Flow Level Marking",
        98 => "Header Enrichment",
        99 => "Error Indication Report",
        100 => "Measurement Information",
        101 => "Node Report Type",
        102 => "User Plane Path Failure Report",
        103 => "Remote GTP-U Peer",
        104 => "UR-SEQN",
        105 => "Update Duplicating Parameters",
        106 => "Activate Predefined Rules",
        107 => "Deactivate Predefined Rules",
        108 => "FAR ID",
        109 => "QER ID",
        110 => "OCI Flags",
        111 => "Pfcp Association Release Request",
        112 => "Graceful Release Period",
        113 => "PDN Type",
        114 => "Failed Rule ID",
        115 => "Time Quota Mechanism",
        116 => "User Plane IP Resource Information",
        117 => "User Plane Inactivity Timer",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::Field;

    /// Helper to get a named field from an Object's children in the buffer.
    fn obj_field_buf<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        obj_range: &core::ops::Range<u32>,
        name: &str,
    ) -> Option<&'a Field<'pkt>> {
        buf.nested_fields(obj_range)
            .iter()
            .find(|f| f.name() == name)
    }

    #[test]
    fn empty_data() {
        let mut buf = DissectBuffer::new();
        parse_ies(&[], 0, 0, &mut buf).unwrap();
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn single_ie_cause() {
        // Type=19 (Cause), Length=1, Data=[0x01] (Request accepted)
        let data = [0x00, 0x13, 0x00, 0x01, 0x01];
        let mut buf = DissectBuffer::new();
        parse_ies(&data, 0, 0, &mut buf).unwrap();

        // Should have at least 1 Object (the IE)
        assert!(!buf.fields().is_empty());

        // First field is the IE Object
        let ie = &buf.fields()[0];
        match &ie.value {
            FieldValue::Object(r) => {
                let type_f = obj_field_buf(&buf, r, "type").unwrap();
                assert_eq!(type_f.value, FieldValue::U32(19));

                let length_f = obj_field_buf(&buf, r, "length").unwrap();
                assert_eq!(length_f.value, FieldValue::U16(1));

                let value_f = obj_field_buf(&buf, r, "value").unwrap();
                // The value is an Object containing cause_value
                match &value_f.value {
                    FieldValue::Object(vr) => {
                        let cause_f = obj_field_buf(&buf, vr, "cause_value").unwrap();
                        assert_eq!(cause_f.value, FieldValue::U8(1));
                    }
                    _ => panic!("expected Object for cause value"),
                }

                // Check type display name
                assert_eq!(
                    buf.resolve_nested_display_name(r, "type_name"),
                    Some("Cause")
                );
            }
            _ => panic!("expected Object"),
        }

        // Check range covers the entire IE.
        assert_eq!(ie.range, 0..5);
    }

    #[test]
    fn single_ie_recovery_time_stamp() {
        // Type=96 (Recovery Time Stamp), Length=4, Data=[0x12, 0x34, 0x56, 0x78]
        let data = [0x00, 0x60, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78];
        let mut buf = DissectBuffer::new();
        parse_ies(&data, 0, 0, &mut buf).unwrap();

        let ie = &buf.fields()[0];
        match &ie.value {
            FieldValue::Object(r) => {
                let type_f = obj_field_buf(&buf, r, "type").unwrap();
                assert_eq!(type_f.value, FieldValue::U32(96));
                assert_eq!(
                    buf.resolve_nested_display_name(r, "type_name"),
                    Some("Recovery Time Stamp")
                );

                let length_f = obj_field_buf(&buf, r, "length").unwrap();
                assert_eq!(length_f.value, FieldValue::U16(4));

                let value_f = obj_field_buf(&buf, r, "value").unwrap();
                match &value_f.value {
                    FieldValue::Object(vr) => {
                        let ts_f = obj_field_buf(&buf, vr, "recovery_time_stamp").unwrap();
                        assert_eq!(ts_f.value, FieldValue::U32(0x12345678));
                    }
                    _ => panic!("expected Object for recovery time stamp value"),
                }
            }
            _ => panic!("expected Object"),
        }
        assert_eq!(ie.range, 0..8);
    }

    #[test]
    fn multiple_ies() {
        // IE 1: Type=19 (Cause), Length=1, Data=[0x01]
        // IE 2: Type=96 (Recovery Time Stamp), Length=4, Data=[0xAA,0xBB,0xCC,0xDD]
        let data = [
            0x00, 0x13, 0x00, 0x01, 0x01, // IE 1
            0x00, 0x60, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, // IE 2
        ];
        let mut buf = DissectBuffer::new();
        parse_ies(&data, 0, 0, &mut buf).unwrap();

        // Find all top-level Object fields
        let objects: Vec<_> = buf
            .fields()
            .iter()
            .enumerate()
            .filter(|(_, f)| f.value.is_object())
            .collect();

        // We should have at least 2 top-level IE objects + nested value objects
        // The first Object at index 0 is IE1, its children include a value Object
        let ie1 = &buf.fields()[0];
        match &ie1.value {
            FieldValue::Object(r) => {
                let type_f = obj_field_buf(&buf, r, "type").unwrap();
                assert_eq!(type_f.value, FieldValue::U32(19));
            }
            _ => panic!("expected Object"),
        }
        assert_eq!(ie1.range, 0..5);

        // Find the second top-level IE (range 5..13)
        let ie2 = objects.iter().find(|(_, f)| f.range == (5..13)).unwrap().1;
        match &ie2.value {
            FieldValue::Object(r) => {
                let type_f = obj_field_buf(&buf, r, "type").unwrap();
                assert_eq!(type_f.value, FieldValue::U32(96));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn truncated_ie_header() {
        // Only 3 bytes — not enough for a 4-byte header.
        let data = [0x00, 0x13, 0x00];
        let mut buf = DissectBuffer::new();
        parse_ies(&data, 0, 0, &mut buf).unwrap();
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn truncated_ie_data() {
        // Header says length=10 but only 2 bytes of data follow.
        let data = [0x00, 0x13, 0x00, 0x0A, 0xAA, 0xBB];
        let mut buf = DissectBuffer::new();
        parse_ies(&data, 0, 0, &mut buf).unwrap();
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn non_zero_base_offset() {
        // Type=19, Length=1, Data=[0x01]
        let data = [0x00, 0x13, 0x00, 0x01, 0x01];
        let base_offset = 100;
        let mut buf = DissectBuffer::new();
        parse_ies(&data, base_offset, 0, &mut buf).unwrap();

        // The first field is the IE Object
        let ie = &buf.fields()[0];
        assert_eq!(ie.range, 100..105);

        match &ie.value {
            FieldValue::Object(r) => {
                let type_f = obj_field_buf(&buf, r, "type").unwrap();
                assert_eq!(type_f.range, 100..102);
                let length_f = obj_field_buf(&buf, r, "length").unwrap();
                assert_eq!(length_f.range, 102..104);
                let value_f = obj_field_buf(&buf, r, "value").unwrap();
                assert_eq!(value_f.range, 104..105);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn ie_type_name_known_types() {
        assert_eq!(ie_type_name(1), "Create PDR");
        assert_eq!(ie_type_name(2), "PDI");
        assert_eq!(ie_type_name(3), "Create FAR");
        assert_eq!(ie_type_name(19), "Cause");
        assert_eq!(ie_type_name(20), "Source Interface");
        assert_eq!(ie_type_name(21), "F-TEID");
        assert_eq!(ie_type_name(22), "Network Instance");
        assert_eq!(ie_type_name(29), "Precedence");
        assert_eq!(ie_type_name(39), "Report Type");
        assert_eq!(ie_type_name(40), "Offending IE");
        assert_eq!(ie_type_name(44), "Apply Action");
        assert_eq!(ie_type_name(57), "F-SEID");
        assert_eq!(ie_type_name(60), "Node ID");
        assert_eq!(ie_type_name(96), "Recovery Time Stamp");
        assert_eq!(ie_type_name(108), "FAR ID");
        assert_eq!(ie_type_name(109), "QER ID");
    }

    #[test]
    fn ie_type_name_unknown() {
        assert_eq!(ie_type_name(0), "Unknown");
        assert_eq!(ie_type_name(118), "Unknown");
        assert_eq!(ie_type_name(1000), "Unknown");
        assert_eq!(ie_type_name(65535), "Unknown");
    }

    #[test]
    fn ie_with_node_id_ipv4() {
        // Type=60 (Node ID), Length=5, Data=[0x00, 192, 168, 1, 1]
        let data = [0x00, 0x3C, 0x00, 0x05, 0x00, 192, 168, 1, 1];
        let mut buf = DissectBuffer::new();
        parse_ies(&data, 0, 0, &mut buf).unwrap();

        let ie = &buf.fields()[0];
        match &ie.value {
            FieldValue::Object(r) => {
                let type_f = obj_field_buf(&buf, r, "type").unwrap();
                assert_eq!(type_f.value, FieldValue::U32(60));
                let value_f = obj_field_buf(&buf, r, "value").unwrap();
                match &value_f.value {
                    FieldValue::Object(vr) => {
                        let nid_type = obj_field_buf(&buf, vr, "node_id_type").unwrap();
                        assert_eq!(nid_type.value, FieldValue::U8(0));
                        let nid_val = obj_field_buf(&buf, vr, "node_id_value").unwrap();
                        assert_eq!(nid_val.value, FieldValue::Ipv4Addr([192, 168, 1, 1]));
                    }
                    _ => panic!("expected Object"),
                }
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn ie_with_network_instance_plain_utf8() {
        // Type=22 (Network Instance), Length=8, Data=b"internet"
        let data = [
            0x00, 0x16, 0x00, 0x08, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't',
        ];
        let mut buf = DissectBuffer::new();
        parse_ies(&data, 0, 0, &mut buf).unwrap();

        let ie = &buf.fields()[0];
        match &ie.value {
            FieldValue::Object(r) => {
                let type_f = obj_field_buf(&buf, r, "type").unwrap();
                assert_eq!(type_f.value, FieldValue::U32(22));
                assert_eq!(
                    buf.resolve_nested_display_name(r, "type_name"),
                    Some("Network Instance")
                );
                let value_f = obj_field_buf(&buf, r, "value").unwrap();
                match &value_f.value {
                    FieldValue::Object(vr) => {
                        let ni = obj_field_buf(&buf, vr, "network_instance").unwrap();
                        assert_eq!(ni.value, FieldValue::Bytes(b"internet" as &[u8]));
                    }
                    _ => panic!("expected Object"),
                }
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn ie_with_network_instance_dns_label() {
        // Type=22 (Network Instance), Length=9, DNS-encoded "foo.bar"
        let data = [
            0x00, 0x16, 0x00, 0x09, 3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 0,
        ];
        let mut buf = DissectBuffer::new();
        parse_ies(&data, 0, 0, &mut buf).unwrap();

        let ie = &buf.fields()[0];
        match &ie.value {
            FieldValue::Object(r) => {
                let type_f = obj_field_buf(&buf, r, "type").unwrap();
                assert_eq!(type_f.value, FieldValue::U32(22));
                let value_f = obj_field_buf(&buf, r, "value").unwrap();
                match &value_f.value {
                    FieldValue::Object(vr) => {
                        let ni = obj_field_buf(&buf, vr, "network_instance").unwrap();
                        // Now stored as raw bytes (zero-copy)
                        assert_eq!(
                            ni.value,
                            FieldValue::Bytes(&[3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 0])
                        );
                    }
                    _ => panic!("expected Object"),
                }
            }
            _ => panic!("expected Object"),
        }
    }
}
