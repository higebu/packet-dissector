//! Generic GTPv2-C IE (Information Element) TLIV parser.
//!
//! 3GPP TS 29.274, Section 8.2.1 — IE TLIV format:
//! - Octet 1: Type (8 bits)
//! - Octets 2-3: Length (16 bits, excludes 4-byte header)
//! - Octet 4: Spare (4 bits) | Instance (4 bits)
//! - Octets 5..n: IE data

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

use crate::ie_parsers;

static FD_INLINE_EXTENDED_TYPE: FieldDescriptor = FieldDescriptor {
    name: "extended_type",
    display_name: "Extended Type",
    field_type: FieldType::U16,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U16(t) => Some(extended_ie_type_name(*t)),
        _ => None,
    }),
    format_fn: None,
};

static FD_INLINE_INSTANCE: FieldDescriptor =
    FieldDescriptor::new("instance", "Instance", FieldType::U8);

static FD_INLINE_LENGTH: FieldDescriptor = FieldDescriptor::new("length", "Length", FieldType::U16);

static FD_INLINE_TYPE: FieldDescriptor = FieldDescriptor {
    name: "type",
    display_name: "Type",
    field_type: FieldType::U32,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U32(t) => Some(ie_type_name(*t as u8)),
        _ => None,
    }),
    format_fn: None,
};

/// Child field descriptors for each IE element in the `ies` array.
///
/// These describe the common fields present in every parsed IE object.
/// The `value` field's internal structure varies by IE type (e.g., Cause,
/// Bearer Context) and is not described statically.
pub static IE_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U32,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U32(t) => Some(ie_type_name(*t as u8)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("instance", "Instance", FieldType::U8),
    FieldDescriptor::new("value", "Value", FieldType::Bytes),
];

/// IE header size: Type(1) + Length(2) + Spare/Instance(1) = 4 bytes.
///
/// 3GPP TS 29.274, Section 8.2.1.
pub const IE_HEADER_SIZE: usize = 4;

/// Parse a sequence of IEs from the given data, pushing into `buf`.
///
/// `base_offset` is the byte offset in the original packet where `data` starts.
///
/// 3GPP TS 29.274, Section 8.2.1.
pub fn parse_ies<'pkt>(data: &'pkt [u8], base_offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let mut pos = 0;

    while pos + IE_HEADER_SIZE <= data.len() {
        let ie_type = data[pos];
        let ie_length = read_be_u16(data, pos + 1).unwrap_or_default() as usize;
        let instance = data[pos + 3] & 0x0F;

        // Bounds check — truncated IE
        if pos + IE_HEADER_SIZE + ie_length > data.len() {
            break;
        }

        let ie_data = &data[pos + IE_HEADER_SIZE..pos + IE_HEADER_SIZE + ie_length];
        let ie_offset = base_offset + pos + IE_HEADER_SIZE;

        let ie_start = base_offset + pos;
        let ie_end = ie_start + IE_HEADER_SIZE + ie_length;

        // Always expose the on-wire IE type (octet 1) as "type".
        let type_code = u32::from(ie_type);

        // Begin the Object container for this IE
        let obj_idx =
            buf.begin_container(&FD_INLINE_TYPE, FieldValue::Object(0..0), ie_start..ie_end);

        buf.push_field(
            &FD_INLINE_TYPE,
            FieldValue::U32(type_code),
            ie_start..ie_start + 1,
        );
        buf.push_field(
            &FD_INLINE_LENGTH,
            FieldValue::U16(ie_length as u16),
            ie_start + 1..ie_start + 3,
        );
        buf.push_field(
            &FD_INLINE_INSTANCE,
            FieldValue::U8(instance),
            ie_start + 3..ie_start + 4,
        );

        // 3GPP TS 29.274, Section 8.2.1A — IE Type Extension
        let is_extended_ie_type = ie_type == 254 && ie_length >= 2;

        if is_extended_ie_type {
            let ext_type = read_be_u16(ie_data, 0).unwrap_or_default();
            buf.push_field(
                &FD_INLINE_EXTENDED_TYPE,
                FieldValue::U16(ext_type),
                ie_start + IE_HEADER_SIZE..ie_start + IE_HEADER_SIZE + 2,
            );

            let value = ie_parsers::parse_extended_ie_value(ext_type, &ie_data[2..], ie_offset + 2);
            buf.push_field(
                &IE_CHILD_FIELDS[3],
                value,
                ie_start + IE_HEADER_SIZE..ie_end,
            );
        } else {
            // parse_ie_value pushes the "value" field (and its children if Object/Array)
            // directly into buf.
            let value_range = ie_start + IE_HEADER_SIZE..ie_end;
            ie_parsers::push_ie_value(
                ie_type,
                ie_data,
                ie_offset,
                &IE_CHILD_FIELDS[3],
                &value_range,
                buf,
            );
        }

        buf.end_container(obj_idx);

        pos += IE_HEADER_SIZE + ie_length;
    }
}

/// Returns the human-readable name for a GTPv2-C IE type code.
///
/// 3GPP TS 29.274, Table 8.1-1.
pub fn ie_type_name(ie_type: u8) -> &'static str {
    match ie_type {
        1 => "IMSI",
        2 => "Cause",
        3 => "Recovery",
        51 => "STN-SR",
        71 => "APN",
        72 => "AMBR",
        73 => "EBI",
        74 => "IP Address",
        75 => "MEI",
        76 => "MSISDN",
        77 => "Indication",
        78 => "PCO",
        79 => "PAA",
        80 => "Bearer QoS",
        81 => "Flow QoS",
        82 => "RAT Type",
        83 => "Serving Network",
        84 => "Bearer TFT",
        85 => "TAD",
        86 => "ULI",
        87 => "F-TEID",
        88 => "TMSI",
        89 => "Global CN-Id",
        90 => "S103PDF",
        91 => "S1-U Data Forwarding",
        92 => "Delay Value",
        93 => "Bearer Context",
        94 => "Charging ID",
        95 => "Charging Characteristics",
        96 => "Trace Information",
        97 => "Bearer Flags",
        99 => "PDN Type",
        100 => "PTI",
        103 => "MM Context (GSM Key and Triplets)",
        104 => "MM Context (UMTS Key, Used Cipher and Quintuplets)",
        105 => "MM Context (GSM Key, Used Cipher and Quintuplets)",
        106 => "MM Context (UMTS Key and Quintuplets)",
        107 => "MM Context (EPS Security Context, Quadruplets and Quintuplets)",
        108 => "MM Context (UMTS Key, Quadruplets and Quintuplets)",
        109 => "PDN Connection",
        110 => "PDU Numbers",
        111 => "P-TMSI",
        112 => "P-TMSI Signature",
        113 => "Hop Counter",
        114 => "UE Time Zone",
        115 => "Trace Reference",
        116 => "Complete Request Message",
        117 => "GUTI",
        118 => "F-Container",
        119 => "F-Cause",
        120 => "PLMN ID",
        121 => "Target Identification",
        123 => "Packet Flow ID",
        124 => "RAB Context",
        125 => "Source RNC PDCP Context Info",
        126 => "Port Number",
        127 => "APN Restriction",
        128 => "Selection Mode",
        129 => "Source Identification",
        131 => "Change Reporting Action",
        132 => "FQ-CSID",
        133 => "Channel Needed",
        134 => "eMLPP Priority",
        135 => "Node Type",
        136 => "FQDN",
        137 => "TI",
        138 => "MBMS Session Duration",
        139 => "MBMS Service Area",
        140 => "MBMS Session Identifier",
        141 => "MBMS Flow Identifier",
        142 => "MBMS IP Multicast Distribution",
        143 => "MBMS Distribution Acknowledge",
        144 => "RFSP Index",
        145 => "UCI",
        146 => "CSG Information Reporting Action",
        147 => "CSG ID",
        148 => "CMI",
        149 => "Service Indicator",
        150 => "Detach Type",
        151 => "LDN",
        152 => "Node Features",
        153 => "MBMS Time to Data Transfer",
        154 => "Throttling",
        155 => "ARP",
        156 => "EPC Timer",
        157 => "Signalling Priority Indication",
        158 => "TMGI",
        159 => "Additional MM context for SRVCC",
        160 => "Additional flags for SRVCC",
        162 => "MDT Configuration",
        163 => "APCO",
        164 => "Absolute Time of MBMS Data Transfer",
        165 => "H(e)NB Information Reporting",
        166 => "IPv4 Configuration Parameters",
        167 => "Change to Report Flags",
        168 => "Action Indication",
        169 => "TWAN Identifier",
        170 => "ULI Timestamp",
        171 => "MBMS Flags",
        172 => "RAN/NAS Cause",
        173 => "CN Operator Selection Entity",
        174 => "Trusted WLAN Mode Indication",
        175 => "Node Number",
        176 => "Node Identifier",
        177 => "Presence Reporting Area Action",
        178 => "Presence Reporting Area Information",
        179 => "TWAN Identifier Timestamp",
        180 => "Overload Control Information",
        181 => "Load Control Information",
        182 => "Metric",
        183 => "Sequence Number",
        184 => "APN and Relative Capacity",
        185 => "WLAN Offloadability Indication",
        186 => "Paging and Service Information",
        187 => "Integer Number",
        188 => "Millisecond Time Stamp",
        189 => "Monitoring Event Information",
        190 => "ECGI List",
        191 => "Remote UE Context",
        192 => "Remote User ID",
        193 => "Remote UE IP Information",
        194 => "CIoT Optimizations Support Indication",
        195 => "SCEF PDN Connection",
        196 => "Header Compression Configuration",
        197 => "ePCO",
        198 => "Serving PLMN Rate Control",
        199 => "Counter",
        200 => "Mapped UE Usage Type",
        201 => "Secondary RAT Usage Data Report",
        202 => "UP Function Selection Indication Flags",
        203 => "Maximum Packet Loss Rate",
        204 => "APN Rate Control Status",
        205 => "Extended Trace Information",
        206 => "Monitoring Event Extension Information",
        207 => "Additional RRM Policy Index",
        208 => "V2X Context",
        209 => "PC5 QoS Parameters",
        210 => "Services Authorized",
        211 => "Bit Rate",
        212 => "PC5 QoS Flow",
        213 => "SGi PtP Tunnel Address",
        214 => "PGW Change Info",
        215 => "PGW Set FQDN",
        254 => "IE Type Extension",
        255 => "Private Extension",
        _ => "Unknown",
    }
}

/// Returns the name for an extended IE type code.
///
/// 3GPP TS 29.274, Section 8.2.1A.
fn extended_ie_type_name(_ext_type: u16) -> &'static str {
    // Extended IE types are not commonly encountered; return generic name.
    "Extended IE"
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::FieldValue;

    /// Helper to parse IEs and return the buffer.
    fn parse_ies_buf<'a>(data: &'a [u8], base_offset: usize) -> DissectBuffer<'a> {
        let mut buf = DissectBuffer::new();
        parse_ies(data, base_offset, &mut buf);
        buf
    }

    /// Count the number of top-level Object containers pushed (each IE is one Object).
    fn count_ies(buf: &DissectBuffer<'_>) -> usize {
        buf.fields()
            .iter()
            .filter(|f| matches!(f.value, FieldValue::Object(_)))
            .count()
    }

    /// Get the Nth top-level Object range from the buffer.
    /// Top-level Objects are those whose range starts before any child.
    fn ie_object_range(buf: &DissectBuffer<'_>, index: usize) -> Option<core::ops::Range<u32>> {
        // Top-level IE objects are at the outermost level.
        // We find them by iterating and tracking nesting.
        let mut found = 0;
        let mut i = 0;
        while i < buf.fields().len() {
            if let FieldValue::Object(ref r) = buf.fields()[i].value {
                if found == index {
                    return Some(r.clone());
                }
                found += 1;
                // Skip to end of this Object's children
                i = r.end as usize;
            } else {
                i += 1;
            }
        }
        None
    }

    /// Find a field by name within an Object's range.
    fn nested_field_value<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        obj_range: &core::ops::Range<u32>,
        name: &str,
    ) -> Option<&'a FieldValue<'pkt>> {
        buf.nested_fields(obj_range)
            .iter()
            .find(|f| f.name() == name)
            .map(|f| &f.value)
    }

    #[test]
    fn empty_data() {
        let buf = parse_ies_buf(&[], 0);
        assert_eq!(count_ies(&buf), 0);
    }

    #[test]
    fn single_ie_recovery() {
        // Type=3 (Recovery), Length=1 (big-endian), Spare/Instance=0x00, Data=[0x05]
        let data = [0x03, 0x00, 0x01, 0x00, 0x05];
        let buf = parse_ies_buf(&data, 0);

        let ie_range = ie_object_range(&buf, 0).unwrap();
        assert_eq!(
            nested_field_value(&buf, &ie_range, "type"),
            Some(&FieldValue::U32(3))
        );
        assert_eq!(
            buf.resolve_nested_display_name(&ie_range, "type_name"),
            Some("Recovery")
        );
        assert_eq!(
            nested_field_value(&buf, &ie_range, "length"),
            Some(&FieldValue::U16(1))
        );
        assert_eq!(
            nested_field_value(&buf, &ie_range, "instance"),
            Some(&FieldValue::U8(0))
        );

        // The value for Recovery (type 3) is an Object with restart_counter field.
        let value = nested_field_value(&buf, &ie_range, "value").unwrap();
        match value {
            FieldValue::Object(val_range) => {
                let rc = buf
                    .nested_fields(val_range)
                    .iter()
                    .find(|f| f.name() == "restart_counter")
                    .map(|f| &f.value);
                assert_eq!(rc, Some(&FieldValue::U8(5)));
            }
            _ => panic!("expected Object for value"),
        }

        // Check range covers the entire IE.
        assert_eq!(buf.fields()[0].range, 0..5);
    }

    #[test]
    fn multiple_ies() {
        // Two Recovery IEs back to back.
        let data = [
            0x03, 0x00, 0x01, 0x00, 0x0A, // IE 1
            0x03, 0x00, 0x01, 0x01, 0x14, // IE 2
        ];
        let buf = parse_ies_buf(&data, 0);

        let ie1_range = ie_object_range(&buf, 0).unwrap();
        let val1 = nested_field_value(&buf, &ie1_range, "value").unwrap();
        match val1 {
            FieldValue::Object(val_range) => {
                let rc = buf
                    .nested_fields(val_range)
                    .iter()
                    .find(|f| f.name() == "restart_counter")
                    .map(|f| &f.value);
                assert_eq!(rc, Some(&FieldValue::U8(0x0A)));
            }
            _ => panic!("expected Object"),
        }
        assert_eq!(buf.fields()[0].range, 0..5);

        let ie2_range = ie_object_range(&buf, 1).unwrap();
        assert_eq!(
            nested_field_value(&buf, &ie2_range, "instance"),
            Some(&FieldValue::U8(1))
        );
        let val2 = nested_field_value(&buf, &ie2_range, "value").unwrap();
        match val2 {
            FieldValue::Object(val_range) => {
                let rc = buf
                    .nested_fields(val_range)
                    .iter()
                    .find(|f| f.name() == "restart_counter")
                    .map(|f| &f.value);
                assert_eq!(rc, Some(&FieldValue::U8(0x14)));
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn truncated_ie_header() {
        // Only 3 bytes — not enough for a 4-byte header.
        let data = [0x03, 0x00, 0x01];
        let buf = parse_ies_buf(&data, 0);
        assert_eq!(count_ies(&buf), 0);
    }

    #[test]
    fn truncated_ie_data() {
        // Header says length=10 but only 2 bytes of data follow.
        let data = [0x03, 0x00, 0x0A, 0x00, 0xAA, 0xBB];
        let buf = parse_ies_buf(&data, 0);
        assert_eq!(count_ies(&buf), 0);
    }

    #[test]
    fn extended_ie_type_254() {
        // Type=254, Length=4, Instance=0, Data=[0x00, 0x01, 0xAA, 0xBB]
        let data = [0xFE, 0x00, 0x04, 0x00, 0x00, 0x01, 0xAA, 0xBB];
        let buf = parse_ies_buf(&data, 0);

        let ie_range = ie_object_range(&buf, 0).unwrap();
        assert_eq!(
            nested_field_value(&buf, &ie_range, "type"),
            Some(&FieldValue::U32(254))
        );
        assert_eq!(
            buf.resolve_nested_display_name(&ie_range, "type_name"),
            Some("IE Type Extension")
        );
        assert_eq!(
            nested_field_value(&buf, &ie_range, "extended_type"),
            Some(&FieldValue::U16(1))
        );
        assert_eq!(
            buf.resolve_nested_display_name(&ie_range, "extended_type_name"),
            Some("Extended IE")
        );
        assert_eq!(
            nested_field_value(&buf, &ie_range, "value"),
            Some(&FieldValue::Bytes(&[0xAA, 0xBB]))
        );
        assert_eq!(buf.fields()[0].range, 0..8);
    }

    #[test]
    fn ie_type_name_known_types() {
        assert_eq!(ie_type_name(1), "IMSI");
        assert_eq!(ie_type_name(2), "Cause");
        assert_eq!(ie_type_name(3), "Recovery");
        assert_eq!(ie_type_name(51), "STN-SR");
        assert_eq!(ie_type_name(71), "APN");
        assert_eq!(ie_type_name(72), "AMBR");
        assert_eq!(ie_type_name(73), "EBI");
        assert_eq!(ie_type_name(74), "IP Address");
        assert_eq!(ie_type_name(75), "MEI");
        assert_eq!(ie_type_name(76), "MSISDN");
        assert_eq!(ie_type_name(77), "Indication");
        assert_eq!(ie_type_name(78), "PCO");
        assert_eq!(ie_type_name(79), "PAA");
        assert_eq!(ie_type_name(80), "Bearer QoS");
        assert_eq!(ie_type_name(81), "Flow QoS");
        assert_eq!(ie_type_name(82), "RAT Type");
        assert_eq!(ie_type_name(83), "Serving Network");
        assert_eq!(ie_type_name(84), "Bearer TFT");
        assert_eq!(ie_type_name(85), "TAD");
        assert_eq!(ie_type_name(86), "ULI");
        assert_eq!(ie_type_name(87), "F-TEID");
        assert_eq!(ie_type_name(88), "TMSI");
        assert_eq!(ie_type_name(89), "Global CN-Id");
        assert_eq!(ie_type_name(90), "S103PDF");
        assert_eq!(ie_type_name(91), "S1-U Data Forwarding");
        assert_eq!(ie_type_name(92), "Delay Value");
        assert_eq!(ie_type_name(93), "Bearer Context");
        assert_eq!(ie_type_name(94), "Charging ID");
        assert_eq!(ie_type_name(95), "Charging Characteristics");
        assert_eq!(ie_type_name(96), "Trace Information");
        assert_eq!(ie_type_name(97), "Bearer Flags");
        assert_eq!(ie_type_name(99), "PDN Type");
        assert_eq!(ie_type_name(100), "PTI");
        assert_eq!(ie_type_name(103), "MM Context (GSM Key and Triplets)");
        assert_eq!(
            ie_type_name(104),
            "MM Context (UMTS Key, Used Cipher and Quintuplets)"
        );
        assert_eq!(
            ie_type_name(105),
            "MM Context (GSM Key, Used Cipher and Quintuplets)"
        );
        assert_eq!(ie_type_name(106), "MM Context (UMTS Key and Quintuplets)");
        assert_eq!(
            ie_type_name(107),
            "MM Context (EPS Security Context, Quadruplets and Quintuplets)"
        );
        assert_eq!(
            ie_type_name(108),
            "MM Context (UMTS Key, Quadruplets and Quintuplets)"
        );
        assert_eq!(ie_type_name(109), "PDN Connection");
        assert_eq!(ie_type_name(110), "PDU Numbers");
        assert_eq!(ie_type_name(111), "P-TMSI");
        assert_eq!(ie_type_name(112), "P-TMSI Signature");
        assert_eq!(ie_type_name(113), "Hop Counter");
        assert_eq!(ie_type_name(114), "UE Time Zone");
        assert_eq!(ie_type_name(115), "Trace Reference");
        assert_eq!(ie_type_name(116), "Complete Request Message");
        assert_eq!(ie_type_name(117), "GUTI");
        assert_eq!(ie_type_name(118), "F-Container");
        assert_eq!(ie_type_name(119), "F-Cause");
        assert_eq!(ie_type_name(120), "PLMN ID");
        assert_eq!(ie_type_name(121), "Target Identification");
        assert_eq!(ie_type_name(123), "Packet Flow ID");
        assert_eq!(ie_type_name(124), "RAB Context");
        assert_eq!(ie_type_name(125), "Source RNC PDCP Context Info");
        assert_eq!(ie_type_name(126), "Port Number");
        assert_eq!(ie_type_name(127), "APN Restriction");
        assert_eq!(ie_type_name(128), "Selection Mode");
        assert_eq!(ie_type_name(129), "Source Identification");
        assert_eq!(ie_type_name(131), "Change Reporting Action");
        assert_eq!(ie_type_name(132), "FQ-CSID");
        assert_eq!(ie_type_name(133), "Channel Needed");
        assert_eq!(ie_type_name(134), "eMLPP Priority");
        assert_eq!(ie_type_name(135), "Node Type");
        assert_eq!(ie_type_name(136), "FQDN");
        assert_eq!(ie_type_name(137), "TI");
        assert_eq!(ie_type_name(138), "MBMS Session Duration");
        assert_eq!(ie_type_name(139), "MBMS Service Area");
        assert_eq!(ie_type_name(140), "MBMS Session Identifier");
        assert_eq!(ie_type_name(141), "MBMS Flow Identifier");
        assert_eq!(ie_type_name(142), "MBMS IP Multicast Distribution");
        assert_eq!(ie_type_name(143), "MBMS Distribution Acknowledge");
        assert_eq!(ie_type_name(144), "RFSP Index");
        assert_eq!(ie_type_name(145), "UCI");
        assert_eq!(ie_type_name(146), "CSG Information Reporting Action");
        assert_eq!(ie_type_name(147), "CSG ID");
        assert_eq!(ie_type_name(148), "CMI");
        assert_eq!(ie_type_name(149), "Service Indicator");
        assert_eq!(ie_type_name(150), "Detach Type");
        assert_eq!(ie_type_name(151), "LDN");
        assert_eq!(ie_type_name(152), "Node Features");
        assert_eq!(ie_type_name(153), "MBMS Time to Data Transfer");
        assert_eq!(ie_type_name(154), "Throttling");
        assert_eq!(ie_type_name(155), "ARP");
        assert_eq!(ie_type_name(156), "EPC Timer");
        assert_eq!(ie_type_name(157), "Signalling Priority Indication");
        assert_eq!(ie_type_name(158), "TMGI");
        assert_eq!(ie_type_name(159), "Additional MM context for SRVCC");
        assert_eq!(ie_type_name(160), "Additional flags for SRVCC");
        assert_eq!(ie_type_name(162), "MDT Configuration");
        assert_eq!(ie_type_name(163), "APCO");
        assert_eq!(ie_type_name(164), "Absolute Time of MBMS Data Transfer");
        assert_eq!(ie_type_name(165), "H(e)NB Information Reporting");
        assert_eq!(ie_type_name(166), "IPv4 Configuration Parameters");
        assert_eq!(ie_type_name(167), "Change to Report Flags");
        assert_eq!(ie_type_name(168), "Action Indication");
        assert_eq!(ie_type_name(169), "TWAN Identifier");
        assert_eq!(ie_type_name(170), "ULI Timestamp");
        assert_eq!(ie_type_name(171), "MBMS Flags");
        assert_eq!(ie_type_name(172), "RAN/NAS Cause");
        assert_eq!(ie_type_name(173), "CN Operator Selection Entity");
        assert_eq!(ie_type_name(174), "Trusted WLAN Mode Indication");
        assert_eq!(ie_type_name(175), "Node Number");
        assert_eq!(ie_type_name(176), "Node Identifier");
        assert_eq!(ie_type_name(177), "Presence Reporting Area Action");
        assert_eq!(ie_type_name(178), "Presence Reporting Area Information");
        assert_eq!(ie_type_name(179), "TWAN Identifier Timestamp");
        assert_eq!(ie_type_name(180), "Overload Control Information");
        assert_eq!(ie_type_name(181), "Load Control Information");
        assert_eq!(ie_type_name(182), "Metric");
        assert_eq!(ie_type_name(183), "Sequence Number");
        assert_eq!(ie_type_name(184), "APN and Relative Capacity");
        assert_eq!(ie_type_name(185), "WLAN Offloadability Indication");
        assert_eq!(ie_type_name(186), "Paging and Service Information");
        assert_eq!(ie_type_name(187), "Integer Number");
        assert_eq!(ie_type_name(188), "Millisecond Time Stamp");
        assert_eq!(ie_type_name(189), "Monitoring Event Information");
        assert_eq!(ie_type_name(190), "ECGI List");
        assert_eq!(ie_type_name(191), "Remote UE Context");
        assert_eq!(ie_type_name(192), "Remote User ID");
        assert_eq!(ie_type_name(193), "Remote UE IP Information");
        assert_eq!(ie_type_name(194), "CIoT Optimizations Support Indication");
        assert_eq!(ie_type_name(195), "SCEF PDN Connection");
        assert_eq!(ie_type_name(196), "Header Compression Configuration");
        assert_eq!(ie_type_name(197), "ePCO");
        assert_eq!(ie_type_name(198), "Serving PLMN Rate Control");
        assert_eq!(ie_type_name(199), "Counter");
        assert_eq!(ie_type_name(200), "Mapped UE Usage Type");
        assert_eq!(ie_type_name(201), "Secondary RAT Usage Data Report");
        assert_eq!(ie_type_name(202), "UP Function Selection Indication Flags");
        assert_eq!(ie_type_name(203), "Maximum Packet Loss Rate");
        assert_eq!(ie_type_name(204), "APN Rate Control Status");
        assert_eq!(ie_type_name(205), "Extended Trace Information");
        assert_eq!(ie_type_name(206), "Monitoring Event Extension Information");
        assert_eq!(ie_type_name(207), "Additional RRM Policy Index");
        assert_eq!(ie_type_name(208), "V2X Context");
        assert_eq!(ie_type_name(209), "PC5 QoS Parameters");
        assert_eq!(ie_type_name(210), "Services Authorized");
        assert_eq!(ie_type_name(211), "Bit Rate");
        assert_eq!(ie_type_name(212), "PC5 QoS Flow");
        assert_eq!(ie_type_name(213), "SGi PtP Tunnel Address");
        assert_eq!(ie_type_name(214), "PGW Change Info");
        assert_eq!(ie_type_name(215), "PGW Set FQDN");
        assert_eq!(ie_type_name(254), "IE Type Extension");
        assert_eq!(ie_type_name(255), "Private Extension");
    }

    #[test]
    fn ie_type_name_unknown() {
        assert_eq!(ie_type_name(0), "Unknown");
        assert_eq!(ie_type_name(4), "Unknown");
        assert_eq!(ie_type_name(98), "Unknown");
        assert_eq!(ie_type_name(130), "Unknown");
        assert_eq!(ie_type_name(161), "Unknown");
        assert_eq!(ie_type_name(253), "Unknown");
    }

    #[test]
    fn non_zero_base_offset() {
        // Type=3, Length=1, Instance=0, Data=[0x07]
        let data = [0x03, 0x00, 0x01, 0x00, 0x07];
        let base_offset = 100;
        let buf = parse_ies_buf(&data, base_offset);

        // The range should be shifted by base_offset.
        assert_eq!(buf.fields()[0].range, 100..105);

        let ie_range = ie_object_range(&buf, 0).unwrap();
        let fields = buf.nested_fields(&ie_range);
        let type_field = fields.iter().find(|f| f.name() == "type").unwrap();
        assert_eq!(type_field.range, 100..101);
        let length_field = fields.iter().find(|f| f.name() == "length").unwrap();
        assert_eq!(length_field.range, 101..103);
        let instance_field = fields.iter().find(|f| f.name() == "instance").unwrap();
        assert_eq!(instance_field.range, 103..104);
        let value_field = fields.iter().find(|f| f.name() == "value").unwrap();
        assert_eq!(value_field.range, 104..105);
    }

    #[test]
    fn instance_field_extraction() {
        // Instance is the lower nibble of octet 4.
        // Octet 4 = 0x3A → spare=0x3, instance=0xA
        let data = [0x03, 0x00, 0x01, 0x3A, 0x05];
        let buf = parse_ies_buf(&data, 0);

        let ie_range = ie_object_range(&buf, 0).unwrap();
        assert_eq!(
            nested_field_value(&buf, &ie_range, "instance"),
            Some(&FieldValue::U8(0x0A))
        );
    }
}
