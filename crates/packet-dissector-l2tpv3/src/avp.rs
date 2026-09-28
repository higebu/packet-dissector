//! L2TPv3 AVP (Attribute Value Pair) parser.
//!
//! ## References
//! - RFC 3931, Section 5.1: <https://www.rfc-editor.org/rfc/rfc3931#section-5.1>
//! - RFC 3931, Section 5.4: <https://www.rfc-editor.org/rfc/rfc3931#section-5.4>
//! - RFC 3931, Section 10.1: <https://www.rfc-editor.org/rfc/rfc3931#section-10.1>
//! - RFC 2661, Section 4.4: <https://www.rfc-editor.org/rfc/rfc2661#section-4.4>
//! - IANA L2TP Control Message Attribute Value Pairs:
//!   <https://www.iana.org/assignments/l2tp-parameters/l2tp-parameters.xhtml#l2tp-parameters-1>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

static FD_INLINE_ATTRIBUTE_TYPE: FieldDescriptor =
    FieldDescriptor::new("attribute_type", "Attribute Type", FieldType::U16);

static FD_INLINE_HIDDEN: FieldDescriptor = FieldDescriptor::new("hidden", "Hidden", FieldType::U8);

static FD_INLINE_LENGTH: FieldDescriptor = FieldDescriptor::new("length", "Length", FieldType::U16);

static FD_INLINE_MANDATORY: FieldDescriptor =
    FieldDescriptor::new("mandatory", "Mandatory", FieldType::U8);

static FD_INLINE_VALUE: FieldDescriptor = FieldDescriptor::new("value", "Value", FieldType::Bytes);

static FD_INLINE_VENDOR_ID: FieldDescriptor =
    FieldDescriptor::new("vendor_id", "Vendor ID", FieldType::U16);

/// Map an IETF (Vendor ID=0) Attribute Type to its AVP name.
///
/// The Attribute Type number space is shared by L2TPv2 and L2TPv3.
/// RFC 3931, Section 10.1 — "This number space is managed by IANA as per
/// [RFC3438]."
/// <https://www.rfc-editor.org/rfc/rfc3931#section-10.1>
///
/// Names follow the IANA "L2TP Control Message Attribute Value Pairs"
/// registry, with the trailing "AVP" dropped. Where RFC 3931, Section 5.4
/// gives an existing type a new name, the L2TPv3 name is used
/// (15 Serial Number, 34 Circuit Errors); type 13 uses the RFC 2661,
/// Section 4.4.3 heading "Challenge Response".
/// <https://www.rfc-editor.org/rfc/rfc3931#section-5.4>
/// <https://www.iana.org/assignments/l2tp-parameters/l2tp-parameters.xhtml#l2tp-parameters-1>
pub(crate) fn avp_name(attribute_type: u16) -> Option<&'static str> {
    match attribute_type {
        // RFC 2661 — https://www.rfc-editor.org/rfc/rfc2661
        0 => Some("Message Type"),
        1 => Some("Result Code"),
        2 => Some("Protocol Version"),
        3 => Some("Framing Capabilities"),
        4 => Some("Bearer Capabilities"),
        5 => Some("Tie Breaker"),
        6 => Some("Firmware Revision"),
        7 => Some("Host Name"),
        8 => Some("Vendor Name"),
        9 => Some("Assigned Tunnel ID"),
        10 => Some("Receive Window Size"),
        11 => Some("Challenge"),
        12 => Some("Q.931 Cause Code"),
        13 => Some("Challenge Response"),
        14 => Some("Assigned Session ID"),
        15 => Some("Serial Number"),
        16 => Some("Minimum BPS"),
        17 => Some("Maximum BPS"),
        18 => Some("Bearer Type"),
        19 => Some("Framing Type"),
        21 => Some("Called Number"),
        22 => Some("Calling Number"),
        23 => Some("Sub-Address"),
        24 => Some("(Tx) Connect Speed BPS"),
        25 => Some("Physical Channel ID"),
        26 => Some("Initial Received LCP CONFREQ"),
        27 => Some("Last Sent LCP CONFREQ"),
        28 => Some("Last Received LCP CONFREQ"),
        29 => Some("Proxy Authen Type"),
        30 => Some("Proxy Authen Name"),
        31 => Some("Proxy Authen Challenge"),
        32 => Some("Proxy Authen ID"),
        33 => Some("Proxy Authen Response"),
        34 => Some("Circuit Errors"),
        35 => Some("ACCM"),
        36 => Some("Random Vector"),
        37 => Some("Private Group ID"),
        38 => Some("Rx Connect Speed"),
        39 => Some("Sequencing Required"),
        // RFC 3301 — https://www.rfc-editor.org/rfc/rfc3301
        40 => Some("Rx Minimum BPS"),
        41 => Some("Rx Maximum BPS"),
        42 => Some("Service Category"),
        43 => Some("Service Name"),
        44 => Some("Calling Sub-Address"),
        45 => Some("VPI/VCI Identifier"),
        // RFC 3145 — https://www.rfc-editor.org/rfc/rfc3145
        46 => Some("PPP Disconnect Cause Code"),
        // RFC 3308 — https://www.rfc-editor.org/rfc/rfc3308
        47 => Some("CCDS"),
        48 => Some("SDS"),
        // RFC 3437 — https://www.rfc-editor.org/rfc/rfc3437
        49 => Some("LCP Want Options"),
        50 => Some("LCP Allow Options"),
        51 => Some("LNS Last Sent LCP Confreq"),
        52 => Some("LNS Last Received LCP Confreq"),
        // RFC 3573 — https://www.rfc-editor.org/rfc/rfc3573
        53 => Some("Modem On-Hold Capable"),
        54 => Some("Modem On-Hold Status"),
        // RFC 3817 — https://www.rfc-editor.org/rfc/rfc3817
        55 => Some("PPPoE Relay"),
        56 => Some("PPPoE Relay Response Capability"),
        57 => Some("PPPoE Relay Forward Capability"),
        // RFC 3931 — https://www.rfc-editor.org/rfc/rfc3931
        58 => Some("Extended Vendor ID"),
        59 => Some("Message Digest"),
        60 => Some("Router ID"),
        61 => Some("Assigned Control Connection ID"),
        62 => Some("Pseudowire Capabilities List"),
        63 => Some("Local Session ID"),
        64 => Some("Remote Session ID"),
        65 => Some("Assigned Cookie"),
        66 => Some("Remote End ID"),
        67 => Some("Application Code"),
        68 => Some("Pseudowire Type"),
        69 => Some("L2-Specific Sublayer"),
        70 => Some("Data Sequencing"),
        71 => Some("Circuit Status"),
        72 => Some("Preferred Language"),
        73 => Some("Control Message Authentication Nonce"),
        74 => Some("Tx Connect Speed"),
        75 => Some("Rx Connect Speed"),
        // RFC 4951 — https://www.rfc-editor.org/rfc/rfc4951
        76 => Some("Failover Capability"),
        77 => Some("Tunnel Recovery"),
        78 => Some("Suggested Control Sequence"),
        79 => Some("Failover Session State"),
        // RFC 4045 — https://www.rfc-editor.org/rfc/rfc4045
        80 => Some("Multicast Capability"),
        81 => Some("New Outgoing Sessions"),
        82 => Some("New Outgoing Sessions Acknowledgement"),
        83 => Some("Withdraw Outgoing Sessions"),
        84 => Some("Multicast Packets Priority"),
        // RFC 4591 — https://www.rfc-editor.org/rfc/rfc4591
        85 => Some("Frame-Relay Header Length"),
        // RFC 4454 — https://www.rfc-editor.org/rfc/rfc4454
        86 => Some("ATM Maximum Concatenated Cells"),
        87 => Some("OAM Emulation Required"),
        88 => Some("ATM Alarm Status"),
        // RFC 4667 — https://www.rfc-editor.org/rfc/rfc4667
        89 => Some("Attachment Group Identifier"),
        90 => Some("Local End Identifier"),
        91 => Some("Interface Maximum Transmission Unit"),
        // RFC 4720 — https://www.rfc-editor.org/rfc/rfc4720
        92 => Some("FCS Retention"),
        // draft-ietf-l2tpext-tunnel-switching-06 — https://datatracker.ietf.org/doc/draft-ietf-l2tpext-tunnel-switching-06/
        93 => Some("Tunnel Switching Aggregator ID"),
        // RFC 4623 — https://www.rfc-editor.org/rfc/rfc4623
        94 => Some("Maximum Receive Unit (MRU)"),
        95 => Some("Maximum Reassembled Receive Unit (MRRU)"),
        // RFC 5085 — https://www.rfc-editor.org/rfc/rfc5085
        96 => Some("VCCV Capability"),
        // RFC 5515 — https://www.rfc-editor.org/rfc/rfc5515
        97 => Some("Connect Speed Update"),
        98 => Some("Connect Speed Update Enable"),
        // RFC 5611 — https://www.rfc-editor.org/rfc/rfc5611
        99 => Some("TDM Pseudowire"),
        100 => Some("RTP"),
        // RFC 6073 — https://www.rfc-editor.org/rfc/rfc6073
        101 => Some("PW Switching Point"),
        // RFC 7886 — https://www.rfc-editor.org/rfc/rfc7886
        102 => Some("S-BFD Target Discriminator ID"),
        // RFC 9601 — https://www.rfc-editor.org/rfc/rfc9601
        103 => Some("ECN Capability"),
        // 20 is Reserved (RFC 2661); 104-65535 are unassigned.
        _ => None,
    }
}

/// Container descriptor for an L2TPv3 AVP entry.
///
/// `display_fn` resolves the outer container's label to the AVP name by
/// looking up the inner `vendor_id` and `attribute_type` fields.
/// When `vendor_id == 0`, the Attribute Type is mapped via [`avp_name`];
/// otherwise the label is "Vendor-Specific AVP".
static FD_AVP: FieldDescriptor = FieldDescriptor {
    name: "avp",
    display_name: "AVP",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| {
        let FieldValue::Object(_) = v else {
            return None;
        };
        let vendor_id = children.iter().find_map(|f| match (f.name(), &f.value) {
            ("vendor_id", FieldValue::U16(v)) => Some(*v),
            _ => None,
        })?;
        let attribute_type = children.iter().find_map(|f| match (f.name(), &f.value) {
            ("attribute_type", FieldValue::U16(t)) => Some(*t),
            _ => None,
        })?;
        if vendor_id == 0 {
            avp_name(attribute_type)
        } else {
            Some("Vendor-Specific AVP")
        }
    }),
    format_fn: None,
};

/// Minimum AVP size: M(1 bit) + H(1 bit) + rsvd(4 bits) + Length(10 bits) +
/// Vendor ID(16 bits) + Attribute Type(16 bits) = 6 octets.
///
/// RFC 3931, Section 5.1 — "The Length ... is calculated as 6 + the length of
/// the Attribute Value field in octets."
const MIN_AVP_SIZE: usize = 6;

/// AVP child field descriptors for Array elements.
pub(crate) static AVP_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("mandatory", "Mandatory", FieldType::U8),
    FieldDescriptor::new("hidden", "Hidden", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("vendor_id", "Vendor ID", FieldType::U16),
    FieldDescriptor::new("attribute_type", "Attribute Type", FieldType::U16),
    FieldDescriptor::new("value", "Value", FieldType::Bytes),
];

/// Parse a sequence of L2TPv3 AVPs from the given buffer.
///
/// `buf` contains AVP data starting at byte 0. `buf_offset` is the absolute
/// byte position of `buf[0]` in the original packet, used for accurate byte
/// ranges.
///
/// RFC 3931, Section 5.1 — AVP format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |M|H| rsvd  |      Length       |           Vendor ID           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Attribute Type        |        Attribute Value ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub(crate) fn parse_avps<'pkt>(data: &'pkt [u8], buf_offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let mut pos = 0;

    while pos + MIN_AVP_SIZE <= data.len() {
        // RFC 3931, Section 5.1 — First two octets: M, H, reserved, Length
        let Ok(first_word) = read_be_u16(data, pos) else {
            break;
        };

        // Bit 15: Mandatory (M)
        let m_flag = ((first_word >> 15) & 1) as u8;
        // Bit 14: Hidden (H)
        let h_flag = ((first_word >> 14) & 1) as u8;
        // Bits 9-0: Length (10 bits)
        let length = (first_word & 0x03FF) as usize;

        if length < MIN_AVP_SIZE || pos + length > data.len() {
            break;
        }

        // RFC 3931, Section 5.1 — Vendor ID (2 octets)
        let Ok(vendor_id) = read_be_u16(data, pos + 2) else {
            break;
        };
        // RFC 3931, Section 5.1 — Attribute Type (2 octets)
        let Ok(attribute_type) = read_be_u16(data, pos + 4) else {
            break;
        };

        let value_data = &data[pos + MIN_AVP_SIZE..pos + length];

        let abs = buf_offset + pos;
        let obj_idx = buf.begin_container(&FD_AVP, FieldValue::Object(0..0), abs..abs + length);
        buf.push_field(&FD_INLINE_MANDATORY, FieldValue::U8(m_flag), abs..abs + 1);
        buf.push_field(&FD_INLINE_HIDDEN, FieldValue::U8(h_flag), abs..abs + 1);
        buf.push_field(
            &FD_INLINE_LENGTH,
            FieldValue::U16(length as u16),
            abs..abs + 2,
        );
        buf.push_field(
            &FD_INLINE_VENDOR_ID,
            FieldValue::U16(vendor_id),
            abs + 2..abs + 4,
        );
        buf.push_field(
            &FD_INLINE_ATTRIBUTE_TYPE,
            FieldValue::U16(attribute_type),
            abs + 4..abs + 6,
        );
        buf.push_field(
            &FD_INLINE_VALUE,
            FieldValue::Bytes(value_data),
            abs + MIN_AVP_SIZE..abs + length,
        );
        buf.end_container(obj_idx);

        pos += length;
    }
}

/// Extract the message type from the first AVP if it is the Message Type AVP
/// (Vendor ID=0, Attribute Type=0).
///
/// RFC 3931, Section 5.4.1 — "The Message Type AVP ... MUST be the first AVP
/// in a control message."
pub(crate) fn extract_message_type(buf: &[u8]) -> Option<u16> {
    if buf.len() < MIN_AVP_SIZE {
        return None;
    }

    let first_word = read_be_u16(buf, 0).ok()?;
    let length = (first_word & 0x03FF) as usize;

    if length < MIN_AVP_SIZE {
        return None;
    }

    let vendor_id = read_be_u16(buf, 2).ok()?;
    let attribute_type = read_be_u16(buf, 4).ok()?;

    // RFC 3931, Section 5.4.1 — Message Type AVP: Vendor ID=0, Type=0,
    // Value is a 2-byte message type code.
    if vendor_id == 0 && attribute_type == 0 && length >= MIN_AVP_SIZE + 2 && buf.len() >= length {
        Some(read_be_u16(buf, 6).ok()?)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 3931 (L2TPv3 AVP) Coverage
    //
    // | RFC Section | Description            | Test                       |
    // |-------------|------------------------|----------------------------|
    // | 5.1         | AVP format             | parse_avp_basic            |
    // | 5.1         | Mandatory bit          | parse_avp_mandatory        |
    // | 5.1         | Hidden bit             | parse_avp_hidden           |
    // | 5.1         | Multiple AVPs          | parse_avps_multiple        |
    // | 5.1         | Truncated AVP          | parse_avp_truncated        |
    // | 5.1         | Length too small        | parse_avp_length_too_small |
    // | 5.4.1       | Message Type extraction | extract_message_type_sccrq |
    // | 5.4.1       | Non-message-type AVP   | extract_message_type_wrong |
    // | 5.4, 10.1   | AVP names (IANA)       | avp_name_matches_iana_registry |
    // | 5.4.4       | Session AVP names      | avp_container_resolves_l2tpv3_session_avps |

    #[test]
    fn parse_avp_basic() {
        let data: &[u8] = &[0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..8);
        parse_avps(data, 100, &mut buf);
        buf.end_layer();

        let fields = buf.fields();
        // Should have 1 Object container + 6 children = 7 fields
        assert!(fields[0].value.is_object());
        let obj_range = fields[0].value.as_container_range().unwrap();
        let children = buf.nested_fields(obj_range);
        assert_eq!(children.len(), 6);
        assert_eq!(children[0].value, FieldValue::U8(0)); // mandatory
        assert_eq!(children[1].value, FieldValue::U8(0)); // hidden
        assert_eq!(children[2].value, FieldValue::U16(8)); // length
        assert_eq!(children[3].value, FieldValue::U16(0)); // vendor_id
        assert_eq!(children[4].value, FieldValue::U16(0)); // attribute_type
        assert_eq!(children[5].value, FieldValue::Bytes(&[0x00, 0x01])); // value
    }

    #[test]
    fn parse_avp_mandatory() {
        let data: &[u8] = &[0x80, 0x06, 0x00, 0x00, 0x00, 0x63];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..6);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();
        let obj_range = buf.fields()[0].value.as_container_range().unwrap();
        let children = buf.nested_fields(obj_range);
        assert_eq!(children[0].value, FieldValue::U8(1)); // mandatory=1
        assert_eq!(children[1].value, FieldValue::U8(0)); // hidden=0
    }

    #[test]
    fn parse_avp_hidden() {
        let data: &[u8] = &[0x40, 0x06, 0x00, 0x00, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..6);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();
        let obj_range = buf.fields()[0].value.as_container_range().unwrap();
        let children = buf.nested_fields(obj_range);
        assert_eq!(children[0].value, FieldValue::U8(0)); // mandatory=0
        assert_eq!(children[1].value, FieldValue::U8(1)); // hidden=1
    }

    #[test]
    fn parse_avps_multiple() {
        let data: &[u8] = &[
            0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x07, 0x00, 0x00, 0x00, 0x02,
            0xAB,
        ];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..15);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();
        let objs: Vec<_> = buf
            .fields()
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(objs.len(), 2);
        assert_eq!(objs[0].range, 0..8);
        assert_eq!(objs[1].range, 8..15);
    }

    #[test]
    fn parse_avp_truncated() {
        let data: &[u8] = &[0x00, 0x08, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..4);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();
        assert!(buf.fields().iter().all(|f| !f.value.is_object()));
    }

    #[test]
    fn parse_avp_length_too_small() {
        let data: &[u8] = &[0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..6);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();
        assert!(buf.fields().iter().all(|f| !f.value.is_object()));
    }

    #[test]
    fn avp_container_resolves_to_avp_name() {
        // Message Type AVP: Vendor=0, Type=0 → "Message Type".
        let data: &[u8] = &[0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..8);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();

        assert!(buf.fields()[0].value.is_object());
        assert_eq!(buf.fields()[0].descriptor.display_name, "AVP");
        assert_eq!(buf.resolve_container_display_name(0), Some("Message Type"),);
    }

    #[test]
    fn avp_name_matches_iana_registry() {
        // IANA "L2TP Control Message Attribute Value Pairs"; the number space
        // is shared by L2TPv2 and L2TPv3 (RFC 3931, Section 10.1).
        // https://www.iana.org/assignments/l2tp-parameters/l2tp-parameters.xhtml#l2tp-parameters-1
        let expected: &[(u16, &str)] = &[
            (0, "Message Type"),
            (1, "Result Code"),
            (2, "Protocol Version"),
            (3, "Framing Capabilities"),
            (4, "Bearer Capabilities"),
            (5, "Tie Breaker"),
            (6, "Firmware Revision"),
            (7, "Host Name"),
            (8, "Vendor Name"),
            (9, "Assigned Tunnel ID"),
            (10, "Receive Window Size"),
            (11, "Challenge"),
            (12, "Q.931 Cause Code"),
            (13, "Challenge Response"),
            (14, "Assigned Session ID"),
            (15, "Serial Number"),
            (16, "Minimum BPS"),
            (17, "Maximum BPS"),
            (18, "Bearer Type"),
            (19, "Framing Type"),
            (21, "Called Number"),
            (22, "Calling Number"),
            (23, "Sub-Address"),
            (24, "(Tx) Connect Speed BPS"),
            (25, "Physical Channel ID"),
            (26, "Initial Received LCP CONFREQ"),
            (27, "Last Sent LCP CONFREQ"),
            (28, "Last Received LCP CONFREQ"),
            (29, "Proxy Authen Type"),
            (30, "Proxy Authen Name"),
            (31, "Proxy Authen Challenge"),
            (32, "Proxy Authen ID"),
            (33, "Proxy Authen Response"),
            (34, "Circuit Errors"),
            (35, "ACCM"),
            (36, "Random Vector"),
            (37, "Private Group ID"),
            (38, "Rx Connect Speed"),
            (39, "Sequencing Required"),
            (40, "Rx Minimum BPS"),
            (41, "Rx Maximum BPS"),
            (42, "Service Category"),
            (43, "Service Name"),
            (44, "Calling Sub-Address"),
            (45, "VPI/VCI Identifier"),
            (46, "PPP Disconnect Cause Code"),
            (47, "CCDS"),
            (48, "SDS"),
            (49, "LCP Want Options"),
            (50, "LCP Allow Options"),
            (51, "LNS Last Sent LCP Confreq"),
            (52, "LNS Last Received LCP Confreq"),
            (53, "Modem On-Hold Capable"),
            (54, "Modem On-Hold Status"),
            (55, "PPPoE Relay"),
            (56, "PPPoE Relay Response Capability"),
            (57, "PPPoE Relay Forward Capability"),
            (58, "Extended Vendor ID"),
            (59, "Message Digest"),
            (60, "Router ID"),
            (61, "Assigned Control Connection ID"),
            (62, "Pseudowire Capabilities List"),
            (63, "Local Session ID"),
            (64, "Remote Session ID"),
            (65, "Assigned Cookie"),
            (66, "Remote End ID"),
            (67, "Application Code"),
            (68, "Pseudowire Type"),
            (69, "L2-Specific Sublayer"),
            (70, "Data Sequencing"),
            (71, "Circuit Status"),
            (72, "Preferred Language"),
            (73, "Control Message Authentication Nonce"),
            (74, "Tx Connect Speed"),
            (75, "Rx Connect Speed"),
            (76, "Failover Capability"),
            (77, "Tunnel Recovery"),
            (78, "Suggested Control Sequence"),
            (79, "Failover Session State"),
            (80, "Multicast Capability"),
            (81, "New Outgoing Sessions"),
            (82, "New Outgoing Sessions Acknowledgement"),
            (83, "Withdraw Outgoing Sessions"),
            (84, "Multicast Packets Priority"),
            (85, "Frame-Relay Header Length"),
            (86, "ATM Maximum Concatenated Cells"),
            (87, "OAM Emulation Required"),
            (88, "ATM Alarm Status"),
            (89, "Attachment Group Identifier"),
            (90, "Local End Identifier"),
            (91, "Interface Maximum Transmission Unit"),
            (92, "FCS Retention"),
            (93, "Tunnel Switching Aggregator ID"),
            (94, "Maximum Receive Unit (MRU)"),
            (95, "Maximum Reassembled Receive Unit (MRRU)"),
            (96, "VCCV Capability"),
            (97, "Connect Speed Update"),
            (98, "Connect Speed Update Enable"),
            (99, "TDM Pseudowire"),
            (100, "RTP"),
            (101, "PW Switching Point"),
            (102, "S-BFD Target Discriminator ID"),
            (103, "ECN Capability"),
        ];
        for &(t, name) in expected {
            assert_eq!(avp_name(t), Some(name), "attribute type {t}");
        }
        // 20 is Reserved (RFC 2661); 104 and above are unassigned.
        for t in [20u16, 104, 1000, u16::MAX] {
            assert_eq!(avp_name(t), None, "attribute type {t}");
        }
    }

    #[test]
    fn avp_container_resolves_l2tpv3_session_avps() {
        // Serial Number (15) and Local Session ID (63), RFC 3931, Section 5.4.4.
        let data: &[u8] = &[
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x07, // Serial Number = 7
            0x80, 0x0a, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00,
            0x2a, // Local Session ID = 42
        ];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..20);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();

        let objs: Vec<u32> = buf
            .fields()
            .iter()
            .enumerate()
            .filter(|(_, f)| f.value.is_object())
            .map(|(i, _)| i as u32)
            .collect();
        assert_eq!(objs.len(), 2);
        assert_eq!(
            buf.resolve_container_display_name(objs[0]),
            Some("Serial Number")
        );
        assert_eq!(
            buf.resolve_container_display_name(objs[1]),
            Some("Local Session ID")
        );
    }

    #[test]
    fn avp_container_vendor_specific_label() {
        // Non-zero Vendor ID → "Vendor-Specific AVP".
        let data: &[u8] = &[0x00, 0x08, 0x12, 0x34, 0x00, 0x01, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..8);
        parse_avps(data, 0, &mut buf);
        buf.end_layer();

        assert!(buf.fields()[0].value.is_object());
        assert_eq!(
            buf.resolve_container_display_name(0),
            Some("Vendor-Specific AVP"),
        );
    }

    #[test]
    fn extract_message_type_sccrq() {
        let buf: &[u8] = &[
            0x80, 0x08, // M=1, Length=8
            0x00, 0x00, // Vendor=0
            0x00, 0x00, // Type=0
            0x00, 0x01, // Value: SCCRQ (1)
        ];
        assert_eq!(extract_message_type(buf), Some(1));
    }

    #[test]
    fn extract_message_type_wrong() {
        // Non-message-type AVP (Vendor=0, Type=2)
        let buf: &[u8] = &[0x80, 0x08, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03];
        assert_eq!(extract_message_type(buf), None);
    }

    #[test]
    fn extract_message_type_empty() {
        assert_eq!(extract_message_type(&[]), None);
    }
}
