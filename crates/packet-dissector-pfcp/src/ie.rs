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
        118 => "Aggregated URRs",
        119 => "Multiplier",
        120 => "Aggregated URR ID",
        121 => "Subsequent Volume Quota",
        122 => "Subsequent Time Quota",
        123 => "RQI",
        124 => "QFI",
        125 => "Query URR Reference",
        126 => "Additional Usage Reports Information",
        127 => "Create Traffic Endpoint",
        128 => "Created Traffic Endpoint",
        129 => "Update Traffic Endpoint",
        130 => "Remove Traffic Endpoint",
        131 => "Traffic Endpoint ID",
        132 => "Ethernet Packet Filter",
        133 => "MAC Address",
        134 => "C-TAG",
        135 => "S-TAG",
        136 => "Ethertype",
        137 => "Proxying",
        138 => "Ethernet Filter ID",
        139 => "Ethernet Filter Properties",
        140 => "Suggested Buffering Packets Count",
        141 => "User ID",
        142 => "Ethernet PDU Session Information",
        143 => "Ethernet Traffic Information",
        144 => "MAC Addresses Detected",
        145 => "MAC Addresses Removed",
        146 => "Ethernet Inactivity Timer",
        147 => "Additional Monitoring Time",
        148 => "Event Quota",
        149 => "Event Threshold",
        150 => "Subsequent Event Quota",
        151 => "Subsequent Event Threshold",
        152 => "Trace Information",
        153 => "Framed-Route",
        154 => "Framed-Routing",
        155 => "Framed-IPv6-Route",
        156 => "Time Stamp",
        157 => "Averaging Window",
        158 => "Paging Policy Indicator",
        159 => "APN/DNN",
        160 => "3GPP Interface Type",
        161 => "PFCPSRReq-Flags",
        162 => "PFCPAUReq-Flags",
        163 => "Activation Time",
        164 => "Deactivation Time",
        165 => "Create MAR",
        166 => "3GPP Access Forwarding Action Information",
        167 => "Non-3GPP Access Forwarding Action Information",
        168 => "Remove MAR",
        169 => "Update MAR",
        170 => "MAR ID",
        171 => "Steering Functionality",
        172 => "Steering Mode",
        173 => "Weight",
        174 => "Priority",
        175 => "Update 3GPP Access Forwarding Action Information",
        176 => "Update Non-3GPP Access Forwarding Action Information",
        177 => "UE IP address Pool Identity",
        178 => "Alternative SMF IP Address",
        179 => "Packet Replication and Detection Carry-On Information",
        180 => "SMF Set ID",
        181 => "Quota Validity Time",
        182 => "Number of Reports",
        183 => "PFCP Session Retention Information",
        184 => "PFCPASRsp-Flags",
        185 => "CP PFCP Entity IP Address",
        186 => "PFCPSEReq-Flags",
        187 => "User Plane Path Recovery Report",
        188 => "IP Multicast Addressing Info",
        189 => "Join IP Multicast Information IE",
        190 => "Leave IP Multicast Information IE",
        191 => "IP Multicast Address",
        192 => "Source IP Address",
        193 => "Packet Rate Status",
        194 => "Create Bridge/Router Info",
        195 => "Created Bridge/Router Info",
        196 => "Port Number",
        197 => "NW-TT Port Number",
        198 => "5GS User Plane Node ID",
        199 => "TSC Management Information (Session Modification Request)",
        200 => "TSC Management Information (Session Modification Response)",
        201 => "TSC Management Information (Session Report Request)",
        202 => "Port Management Information Container",
        203 => "Clock Drift Control Information",
        204 => "Requested Clock Drift Information",
        205 => "Clock Drift Report",
        206 => "Time Domain Number",
        207 => "Time Offset Threshold",
        208 => "Cumulative rateRatio Threshold",
        209 => "Time Offset Measurement",
        210 => "Cumulative rateRatio Measurement",
        211 => "Remove SRR",
        212 => "Create SRR",
        213 => "Update SRR",
        214 => "Session Report",
        215 => "SRR ID",
        216 => "Access Availability Control Information",
        217 => "Requested Access Availability Information",
        218 => "Access Availability Report",
        219 => "Access Availability Information",
        220 => "Provide ATSSS Control Information",
        221 => "ATSSS Control Parameters",
        222 => "MPTCP Control Information",
        223 => "ATSSS-LL Control Information",
        224 => "PMF Control Information",
        225 => "MPTCP Parameters",
        226 => "ATSSS-LL Parameters",
        227 => "PMF Parameters",
        228 => "MPTCP Address Information",
        229 => "Link-Specific Multipath IP Address",
        230 => "PMF Address Information",
        231 => "ATSSS-LL Information",
        232 => "Data Network Access Identifier",
        233 => "UE IP address Pool Information",
        234 => "Average Packet Delay",
        235 => "Minimum Packet Delay",
        236 => "Maximum Packet Delay",
        237 => "QoS Report Trigger",
        238 => "GTP-U Path QoS Control Information",
        239 => "GTP-U Path QoS Report",
        240 => "QoS Information in GTP-U Path QoS Report",
        241 => "GTP-U Path Interface Type",
        242 => "QoS Monitoring per QoS flow Control Information",
        243 => "Requested QoS Monitoring",
        244 => "Reporting Frequency",
        245 => "Packet Delay Thresholds",
        246 => "Minimum Wait Time",
        247 => "QoS Monitoring Report",
        248 => "QoS Monitoring Measurement",
        249 => "MT-EDT Control Information",
        250 => "DL Data Packets Size",
        251 => "QER Control Indications",
        252 => "Packet Rate Status Report",
        253 => "NF Instance ID",
        254 => "Ethernet Context Information",
        255 => "Redundant Transmission Parameters",
        256 => "Updated PDR",
        257 => "S-NSSAI",
        258 => "IP Version",
        259 => "PFCPASReq-Flags",
        260 => "Data Status",
        261 => "Provide RDS Configuration Information",
        262 => "RDS Configuration Information",
        263 => "Query Packet Rate Status",
        264 => "Packet Rate Status Report (Session Modification Response)",
        265 => "Multipath Applicable Indication",
        266 => "User Plane Node Management Information Container",
        267 => "UE IP Address Usage Information",
        268 => "Number of UE IP Addresses",
        269 => "Validity Timer",
        270 => "Redundant Transmission Forwarding Parameters",
        271 => "Transport Delay Reporting",
        272 => "Partial Failure Information",
        274 => "Offending IE Information",
        275 => "RAT Type",
        276 => "L2TP Tunnel Information",
        277 => "L2TP Session Information",
        278 => "L2TP User Authentication",
        279 => "Created L2TP Session",
        280 => "LNS Address",
        281 => "Tunnel Preference",
        282 => "Calling Number",
        283 => "Called Number",
        284 => "L2TP Session Indications",
        285 => "DNS Server Address",
        286 => "NBNS Server Address",
        287 => "Maximum Receive Unit",
        288 => "Thresholds",
        289 => "Steering Mode Indicator",
        290 => "PFCP Session Change Info",
        291 => "Group ID",
        292 => "CP IP Address",
        293 => "IP Address and Port Number Replacement",
        294 => "DNS Query/Response Filter",
        295 => "Direct Reporting Information",
        296 => "Event Notification URI",
        297 => "Notification Correlation ID",
        298 => "Reporting Flags",
        299 => "Predefined Rules Name",
        300 => "MBS Session N4mb Control Information",
        301 => "MBS Multicast Parameters",
        302 => "Add MBS Unicast Parameters",
        303 => "MBS Session N4mb Information",
        304 => "Remove MBS Unicast Parameters",
        305 => "MBS Session Identifier",
        306 => "Multicast Transport Information",
        307 => "MBSN4mbReq-Flags",
        308 => "Local Ingress Tunnel",
        309 => "MBS Unicast Parameters ID",
        310 => "MBS Session N4 Control Information",
        311 => "MBS Session N4 Information",
        312 => "MBSN4Resp-Flags",
        313 => "Tunnel Password",
        314 => "Area Session ID",
        315 => "Peer UP Restart Report",
        316 => "DSCP to PPI Control Information",
        317 => "DSCP to PPI Mapping Information",
        318 => "PFCPSDRsp-Flags",
        319 => "QER Indications",
        320 => "Vendor-Specific Node Report Type",
        321 => "Configured Time Domain",
        322 => "Metadata",
        323 => "Traffic Parameter Measurement Control Information",
        324 => "Traffic Parameter Measurement Report",
        325 => "Traffic Parameter Threshold",
        326 => "DL Periodicity",
        327 => "N6 Jitter Measurement",
        328 => "Traffic Parameter Measurement Indication",
        329 => "UL Periodicity",
        330 => "MPQUIC Control Information",
        331 => "MPQUIC Parameters",
        332 => "MPQUIC Address Information",
        333 => "Transport Mode",
        334 => "Protocol Description",
        335 => "Reporting Suggestion Info",
        336 => "TL-Container",
        337 => "Measurement Indication",
        338 => "HPLMN S-NSSAI",
        339 => "Media Transport Protocol",
        340 => "RTP Header Extension Information",
        341 => "RTP Payload Information",
        342 => "RTP Header Extension Type",
        343 => "RTP Header Extension ID",
        344 => "RTP Payload Type",
        345 => "RTP Payload Format",
        346 => "Extended DL Buffering Notification Policy",
        347 => "MT-SDT Control Information",
        348 => "Reporting Thresholds",
        349 => "RTP Header Extension Additional Information",
        350 => "Mapped N6 IP Address",
        351 => "N6 Routing Information",
        352 => "URI",
        353 => "UE Level Measurements Configuration",
        354 => "N6 Delay Measurement Protocols",
        355 => "N6 Delay Measurement Control Information",
        356 => "N6 Delay Measurement Report",
        357 => "N6 Delay Measurement Information",
        358 => "Measurement Endpoint Address",
        359 => "Operator Configurable UPF Capability",
        360 => "Packet Inspection Functionality",
        361 => "Header Handling Control Rule",
        362 => "Header Handling Reporting Control Info",
        363 => "Header Handling Control Information",
        364 => "Header Detection Reference",
        365 => "Header Detection Support Information",
        366 => "Reporting Endpoint ID",
        367 => "Header Handling Control Reference",
        368 => "Header Handling Action",
        369 => "Header Information",
        370 => "Header Value",
        371 => "Header Handling Condition",
        372 => "Header Handling Control ID",
        373 => "Header Handling Control Rule ID",
        374 => "On-path N6 Connection Information",
        375 => "Measurement Reporting Type",
        376 => "N6 Delay Measurement Failure Information",
        377 => "N6 Delay Measurement Control Information ID",
        378 => "Protocol Specific Configuration Parameters",
        379 => "Measurement Endpoint Port Number",
        380 => "Header Handling Reporting Indication",
        382 => "SMF Change Reason",
        383 => "Extended Transport Level Marking",
        384 => "PDU Set Importance",
        385 => "MoQ Control Information",
        386 => "MoQ Information",
        387 => "MoQ Relay IP Address",
        388 => "Media Related Information Transfer Info",
        389 => "Reporting Control Information",
        390 => "Security Mode (STAMP)",
        391 => "HMAC Key (STAMP)",
        392 => "Security Mode (OWAMP or TWAMP)",
        393 => "Key ID and Shared Secret (OWAMP or TWAMP)",
        394 => "Remaining Data Reporting Indication",
        395 => "Expedited Transfer Indication",
        396 => "Session Reflector Mode (STAMP)",
        397 => "PFD Partial Failure Information",
        398 => "Transport Level Marking Indications",
        399 => "Redundant N3/N9 Transmission Information",
        400 => "Local N3/N9 Tunnel Information",
        401 => "Remote N3/N9 Tunnel Information",
        402 => "Binding Indication",
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
    fn ie_type_name_extended_types() {
        // Spot-check IE names across the 118-402 range.
        assert_eq!(ie_type_name(118), "Aggregated URRs");
        assert_eq!(ie_type_name(120), "Aggregated URR ID");
        assert_eq!(ie_type_name(124), "QFI");
        assert_eq!(ie_type_name(131), "Traffic Endpoint ID");
        assert_eq!(ie_type_name(141), "User ID");
        assert_eq!(ie_type_name(159), "APN/DNN");
        assert_eq!(ie_type_name(170), "MAR ID");
        assert_eq!(ie_type_name(180), "SMF Set ID");
        assert_eq!(ie_type_name(198), "5GS User Plane Node ID");
        assert_eq!(ie_type_name(215), "SRR ID");
        assert_eq!(ie_type_name(253), "NF Instance ID");
        assert_eq!(ie_type_name(257), "S-NSSAI");
        assert_eq!(ie_type_name(275), "RAT Type");
        assert_eq!(ie_type_name(280), "LNS Address");
        assert_eq!(ie_type_name(305), "MBS Session Identifier");
        assert_eq!(ie_type_name(322), "Metadata");
        assert_eq!(ie_type_name(352), "URI");
        assert_eq!(ie_type_name(384), "PDU Set Importance");
        assert_eq!(ie_type_name(402), "Binding Indication");
    }

    #[test]
    fn ie_type_name_unknown() {
        // Reserved / Spare / unassigned values.
        assert_eq!(ie_type_name(0), "Unknown");
        assert_eq!(ie_type_name(273), "Unknown"); // Spare
        assert_eq!(ie_type_name(381), "Unknown"); // Spare
        assert_eq!(ie_type_name(403), "Unknown");
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
