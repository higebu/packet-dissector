//! L2TPv2 control message AVP (Attribute Value Pair) parser.
//!
//! ## References
//! - RFC 2661, Section 3.2 (Control Message Types): <https://www.rfc-editor.org/rfc/rfc2661#section-3.2>
//! - RFC 2661, Section 4.1 (AVP Format): <https://www.rfc-editor.org/rfc/rfc2661#section-4.1>
//! - RFC 2661, Section 4.3 (Hiding of AVP Attribute Values): <https://www.rfc-editor.org/rfc/rfc2661#section-4.3>
//! - RFC 2661, Section 4.4 (AVP Summary): <https://www.rfc-editor.org/rfc/rfc2661#section-4.4>
//! - IANA L2TP parameters: <https://www.iana.org/assignments/l2tp-parameters/l2tp-parameters.xhtml>

use packet_dissector_core::field::{Field, FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Returns the name of a control message type.
///
/// RFC 2661, Section 3.2, and the IANA "Message Type AVP (Attribute Type 0)
/// Values" registry (shared with L2TPv3).
/// <https://www.rfc-editor.org/rfc/rfc2661#section-3.2>
/// <https://www.iana.org/assignments/l2tp-parameters/l2tp-parameters.xhtml#l2tp-parameters-2>
pub(crate) fn message_type_name(code: u16) -> Option<&'static str> {
    match code {
        1 => Some("SCCRQ"),
        2 => Some("SCCRP"),
        3 => Some("SCCCN"),
        4 => Some("StopCCN"),
        6 => Some("HELLO"),
        7 => Some("OCRQ"),
        8 => Some("OCRP"),
        9 => Some("OCCN"),
        10 => Some("ICRQ"),
        11 => Some("ICRP"),
        12 => Some("ICCN"),
        14 => Some("CDN"),
        15 => Some("WEN"),
        16 => Some("SLI"),
        // RFC 3573 — https://www.rfc-editor.org/rfc/rfc3573
        17 => Some("MDMST"),
        // RFC 3817 — https://www.rfc-editor.org/rfc/rfc3817
        18 => Some("SRRQ"),
        19 => Some("SRRP"),
        20 => Some("ACK"),
        // RFC 4951, Sections 4.1-4.2 — https://www.rfc-editor.org/rfc/rfc4951#section-4.1
        21 => Some("FSQ"),
        22 => Some("FSR"),
        // RFC 4045 — https://www.rfc-editor.org/rfc/rfc4045
        23 => Some("MSRQ"),
        24 => Some("MSRP"),
        25 => Some("MSE"),
        26 => Some("MSI"),
        27 => Some("MSEN"),
        // RFC 5515 — https://www.rfc-editor.org/rfc/rfc5515
        28 => Some("CSUN"),
        29 => Some("CSURQ"),
        _ => None,
    }
}

/// Map an IETF (Vendor ID=0) Attribute Type to its AVP name.
///
/// Names follow the IANA "L2TP Control Message Attribute Value Pairs"
/// registry (shared with L2TPv3), with the trailing "AVP" dropped; the
/// RFC 2661 headings are used for 13 (Section 4.4.3, Challenge Response),
/// 15 (Section 4.4.4, Call Serial Number) and 34 (Section 4.4.6, Call
/// Errors).
/// <https://www.rfc-editor.org/rfc/rfc2661#section-4.4>
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
        15 => Some("Call Serial Number"),
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
        34 => Some("Call Errors"),
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
        // <https://www.rfc-editor.org/rfc/rfc2661>
        _ => None,
    }
}

/// Minimum AVP size: M, H, reserved and Length (2) + Vendor ID (2) +
/// Attribute Type (2).
///
/// RFC 2661, Section 4.1 — "The Length may be calculated as 6 + the length
/// of the Attribute Value field in octets."
/// <https://www.rfc-editor.org/rfc/rfc2661#section-4.1>
pub(crate) const MIN_AVP_SIZE: usize = 6;

// Attribute Types with typed values (RFC 2661, Section 4.4).
// <https://www.rfc-editor.org/rfc/rfc2661#section-4.4>
const ATTR_MESSAGE_TYPE: u16 = 0;
const ATTR_RESULT_CODE: u16 = 1;
const ATTR_PROTOCOL_VERSION: u16 = 2;
const ATTR_FRAMING_CAPABILITIES: u16 = 3;
const ATTR_BEARER_CAPABILITIES: u16 = 4;
const ATTR_FIRMWARE_REVISION: u16 = 6;
const ATTR_HOST_NAME: u16 = 7;
const ATTR_VENDOR_NAME: u16 = 8;
const ATTR_ASSIGNED_TUNNEL_ID: u16 = 9;
const ATTR_RECEIVE_WINDOW_SIZE: u16 = 10;
const ATTR_ASSIGNED_SESSION_ID: u16 = 14;
const ATTR_CALL_SERIAL_NUMBER: u16 = 15;
const ATTR_MINIMUM_BPS: u16 = 16;
const ATTR_MAXIMUM_BPS: u16 = 17;
const ATTR_BEARER_TYPE: u16 = 18;
const ATTR_FRAMING_TYPE: u16 = 19;
const ATTR_CALLED_NUMBER: u16 = 21;
const ATTR_CALLING_NUMBER: u16 = 22;
const ATTR_SUB_ADDRESS: u16 = 23;
const ATTR_TX_CONNECT_SPEED: u16 = 24;
const ATTR_PHYSICAL_CHANNEL_ID: u16 = 25;
const ATTR_PROXY_AUTHEN_TYPE: u16 = 29;
const ATTR_PROXY_AUTHEN_NAME: u16 = 30;
const ATTR_RX_CONNECT_SPEED: u16 = 38;

fn sibling_u16(siblings: &[Field<'_>], name: &str) -> Option<u16> {
    siblings.iter().find_map(|f| match (f.name(), &f.value) {
        (n, FieldValue::U16(v)) if n == name => Some(*v),
        _ => None,
    })
}

/// Container descriptor for an AVP; the label resolves to the AVP name.
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
        if sibling_u16(children, "vendor_id")? != 0 {
            return Some("Vendor-Specific AVP");
        }
        avp_name(sibling_u16(children, "attribute_type")?)
    }),
    format_fn: None,
};

/// Child field descriptors of an AVP Object.
pub(crate) static AVP_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("mandatory", "Mandatory", FieldType::U8),
    FieldDescriptor::new("hidden", "Hidden", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("vendor_id", "Vendor ID", FieldType::U16),
    FieldDescriptor::new("attribute_type", "Attribute Type", FieldType::U16),
    FieldDescriptor::new("value", "Value", FieldType::Bytes),
    FieldDescriptor {
        name: "typed_value",
        display_name: "Typed Value",
        field_type: FieldType::Any,
        optional: true,
        children: None,
        display_fn: Some(|v, siblings| match v {
            FieldValue::U16(t) if sibling_u16(siblings, "attribute_type")? == ATTR_MESSAGE_TYPE => {
                message_type_name(*t)
            }
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("result_code", "Result Code", FieldType::U16).optional(),
    FieldDescriptor::new("error_code", "Error Code", FieldType::U16).optional(),
    FieldDescriptor::new("error_message", "Error Message", FieldType::Str).optional(),
    FieldDescriptor::new("protocol_version", "Protocol Version", FieldType::U8).optional(),
    FieldDescriptor::new("protocol_revision", "Protocol Revision", FieldType::U8).optional(),
];

const AFD_MANDATORY: usize = 0;
const AFD_HIDDEN: usize = 1;
const AFD_LENGTH: usize = 2;
const AFD_VENDOR_ID: usize = 3;
const AFD_ATTRIBUTE_TYPE: usize = 4;
const AFD_VALUE: usize = 5;
const AFD_TYPED_VALUE: usize = 6;
const AFD_RESULT_CODE: usize = 7;
const AFD_ERROR_CODE: usize = 8;
const AFD_ERROR_MESSAGE: usize = 9;
const AFD_PROTOCOL_VERSION: usize = 10;
const AFD_PROTOCOL_REVISION: usize = 11;

/// Decode the Attribute Value of an IETF (Vendor ID 0), non-hidden AVP.
/// Values whose length does not match the AVP definition are left raw.
///
/// RFC 2661, Section 4.4 — <https://www.rfc-editor.org/rfc/rfc2661#section-4.4>
fn decode_value<'pkt>(buf: &mut DissectBuffer<'pkt>, attr: u16, value: &'pkt [u8], off: usize) {
    let f = AVP_CHILD_FIELDS;
    let range = off..off + value.len();
    match (attr, value.len()) {
        (
            ATTR_MESSAGE_TYPE
            | ATTR_FIRMWARE_REVISION
            | ATTR_ASSIGNED_TUNNEL_ID
            | ATTR_RECEIVE_WINDOW_SIZE
            | ATTR_ASSIGNED_SESSION_ID
            | ATTR_PROXY_AUTHEN_TYPE,
            2,
        ) => {
            let v = read_be_u16(value, 0).unwrap_or_default();
            buf.push_field(&f[AFD_TYPED_VALUE], FieldValue::U16(v), range);
        }
        (
            ATTR_FRAMING_CAPABILITIES
            | ATTR_BEARER_CAPABILITIES
            | ATTR_CALL_SERIAL_NUMBER
            | ATTR_MINIMUM_BPS
            | ATTR_MAXIMUM_BPS
            | ATTR_BEARER_TYPE
            | ATTR_FRAMING_TYPE
            | ATTR_TX_CONNECT_SPEED
            | ATTR_PHYSICAL_CHANNEL_ID
            | ATTR_RX_CONNECT_SPEED,
            4,
        ) => {
            let v = read_be_u32(value, 0).unwrap_or_default();
            buf.push_field(&f[AFD_TYPED_VALUE], FieldValue::U32(v), range);
        }
        (
            ATTR_HOST_NAME
            | ATTR_VENDOR_NAME
            | ATTR_CALLED_NUMBER
            | ATTR_CALLING_NUMBER
            | ATTR_SUB_ADDRESS
            | ATTR_PROXY_AUTHEN_NAME,
            1..,
        ) => {
            if let Ok(s) = core::str::from_utf8(value) {
                buf.push_field(&f[AFD_TYPED_VALUE], FieldValue::Str(s), range);
            }
        }
        // RFC 2661, Section 4.4.3 — "|      Ver      |     Rev       |".
        // <https://www.rfc-editor.org/rfc/rfc2661#section-4.4.3>
        (ATTR_PROTOCOL_VERSION, 2) => {
            buf.push_field(
                &f[AFD_PROTOCOL_VERSION],
                FieldValue::U8(value[0]),
                off..off + 1,
            );
            buf.push_field(
                &f[AFD_PROTOCOL_REVISION],
                FieldValue::U8(value[1]),
                off + 1..off + 2,
            );
        }
        // RFC 2661, Section 4.4.2 — "The Result Code is a 2 octet unsigned
        // integer.  The optional Error Code is a 2 octet unsigned integer.
        // An optional Error Message can follow the Error Code field."
        // <https://www.rfc-editor.org/rfc/rfc2661#section-4.4.2>
        (ATTR_RESULT_CODE, 2..) => {
            let rc = read_be_u16(value, 0).unwrap_or_default();
            buf.push_field(&f[AFD_RESULT_CODE], FieldValue::U16(rc), off..off + 2);
            if value.len() >= 4 {
                let ec = read_be_u16(value, 2).unwrap_or_default();
                buf.push_field(&f[AFD_ERROR_CODE], FieldValue::U16(ec), off + 2..off + 4);
                if value.len() > 4 {
                    if let Ok(msg) = core::str::from_utf8(&value[4..]) {
                        buf.push_field(
                            &f[AFD_ERROR_MESSAGE],
                            FieldValue::Str(msg),
                            off + 4..range.end,
                        );
                    }
                }
            }
        }
        _ => {}
    }
}

/// Parse a sequence of AVPs, pushing one Object per AVP.
///
/// RFC 2661, Section 4.1 — AVP format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |M|H| rsvd  |      Length       |           Vendor ID           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Attribute Type        |        Attribute Value...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// Walking stops at the first AVP whose Length is invalid.
/// <https://www.rfc-editor.org/rfc/rfc2661#section-4.1>
pub(crate) fn parse_avps<'pkt>(data: &'pkt [u8], base: usize, buf: &mut DissectBuffer<'pkt>) {
    let f = AVP_CHILD_FIELDS;
    let mut pos = 0;
    while pos + MIN_AVP_SIZE <= data.len() {
        let first = read_be_u16(data, pos).unwrap_or_default();
        let m_flag = (first >> 15) as u8 & 1;
        let h_flag = (first >> 14) as u8 & 1;
        let length = (first & 0x03FF) as usize;
        if length < MIN_AVP_SIZE || pos + length > data.len() {
            break;
        }
        let vendor_id = read_be_u16(data, pos + 2).unwrap_or_default();
        let attr = read_be_u16(data, pos + 4).unwrap_or_default();
        let value = &data[pos + MIN_AVP_SIZE..pos + length];
        let abs = base + pos;
        let obj = buf.begin_container(&FD_AVP, FieldValue::Object(0..0), abs..abs + length);
        buf.push_field(&f[AFD_MANDATORY], FieldValue::U8(m_flag), abs..abs + 1);
        buf.push_field(&f[AFD_HIDDEN], FieldValue::U8(h_flag), abs..abs + 1);
        buf.push_field(&f[AFD_LENGTH], FieldValue::U16(length as u16), abs..abs + 2);
        buf.push_field(
            &f[AFD_VENDOR_ID],
            FieldValue::U16(vendor_id),
            abs + 2..abs + 4,
        );
        buf.push_field(
            &f[AFD_ATTRIBUTE_TYPE],
            FieldValue::U16(attr),
            abs + 4..abs + 6,
        );
        buf.push_field(
            &f[AFD_VALUE],
            FieldValue::Bytes(value),
            abs + 6..abs + length,
        );
        // RFC 2661, Section 4.3 — a hidden value is encrypted; vendor AVPs
        // have vendor-defined formats. Both stay raw.
        // <https://www.rfc-editor.org/rfc/rfc2661#section-4.3>
        if h_flag == 0 && vendor_id == 0 {
            decode_value(buf, attr, value, abs + 6);
        }
        buf.end_container(obj);
        pos += length;
    }
}

/// Return the Message Type carried by the first AVP, if it is a
/// non-hidden IETF Message Type AVP.
///
/// RFC 2661, Section 4.4.1 — "The Message Type AVP MUST be the first AVP in
/// a message".
/// <https://www.rfc-editor.org/rfc/rfc2661#section-4.4.1>
pub(crate) fn extract_message_type(data: &[u8]) -> Option<u16> {
    let first = read_be_u16(data, 0).ok()?;
    let length = (first & 0x03FF) as usize;
    let hidden = first & 0x4000 != 0;
    if length != MIN_AVP_SIZE + 2 || data.len() < length || hidden {
        return None;
    }
    if read_be_u16(data, 2).ok()? != 0 || read_be_u16(data, 4).ok()? != ATTR_MESSAGE_TYPE {
        return None;
    }
    read_be_u16(data, 6).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr_type(v: u16) -> Field<'static> {
        Field {
            descriptor: &AVP_CHILD_FIELDS[4],
            value: FieldValue::U16(v),
            range: 0..2,
        }
    }

    #[test]
    fn typed_value_display_fn() {
        // RFC 2661, Section 4.4.1 — Message Type AVP (Attribute Type 0).
        // <https://www.rfc-editor.org/rfc/rfc2661#section-4.4.1>
        let display = AVP_CHILD_FIELDS[6].display_fn.unwrap();
        assert_eq!(
            display(&FieldValue::U16(1), &[attr_type(ATTR_MESSAGE_TYPE)]),
            Some("SCCRQ")
        );
        assert_eq!(display(&FieldValue::U16(1), &[attr_type(7)]), None);
        assert_eq!(display(&FieldValue::U8(1), &[attr_type(0)]), None);
    }

    #[test]
    fn avp_display_fn_requires_object() {
        let display = FD_AVP.display_fn.unwrap();
        assert_eq!(display(&FieldValue::U8(0), &[attr_type(0)]), None);
    }

    #[test]
    fn extract_message_type_rejects_non_message_type_avp() {
        // RFC 2661, Section 4.4.1 — M=1, Length=8, Vendor 0, Type 0.
        // <https://www.rfc-editor.org/rfc/rfc2661#section-4.4.1>
        assert_eq!(extract_message_type(&[0x80, 8, 0, 0, 0, 0, 0, 1]), Some(1));
        // Hidden bit set.
        assert_eq!(extract_message_type(&[0xC0, 8, 0, 0, 0, 0, 0, 1]), None);
        // Wrong attribute type.
        assert_eq!(extract_message_type(&[0x80, 8, 0, 0, 0, 7, 0, 1]), None);
        // Truncated.
        assert_eq!(extract_message_type(&[0x80, 8, 0, 0]), None);
    }
}
