//! L2TPv3 AVP (Attribute Value Pair) parser.
//!
//! ## References
//! - RFC 3931, Section 5.1: <https://www.rfc-editor.org/rfc/rfc3931#section-5.1>
//! - RFC 3931, Section 5.4: <https://www.rfc-editor.org/rfc/rfc3931#section-5.4>
//! - RFC 3931, Section 10.1: <https://www.rfc-editor.org/rfc/rfc3931#section-10.1>
//! - RFC 2661, Section 4.4: <https://www.rfc-editor.org/rfc/rfc2661#section-4.4>
//! - IANA L2TP Control Message Attribute Value Pairs:
//!   <https://www.iana.org/assignments/l2tp-parameters/l2tp-parameters.xhtml#l2tp-parameters-1>

use packet_dissector_core::field::{Field, FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32, read_be_u64};

static FD_INLINE_ATTRIBUTE_TYPE: FieldDescriptor =
    FieldDescriptor::new("attribute_type", "Attribute Type", FieldType::U16);

static FD_INLINE_HIDDEN: FieldDescriptor = FieldDescriptor::new("hidden", "Hidden", FieldType::U8);

static FD_INLINE_LENGTH: FieldDescriptor = FieldDescriptor::new("length", "Length", FieldType::U16);

static FD_INLINE_MANDATORY: FieldDescriptor =
    FieldDescriptor::new("mandatory", "Mandatory", FieldType::U8);

static FD_INLINE_VALUE: FieldDescriptor = FieldDescriptor::new("value", "Value", FieldType::Bytes);

static FD_INLINE_VENDOR_ID: FieldDescriptor =
    FieldDescriptor::new("vendor_id", "Vendor ID", FieldType::U16);

/// Return the `U16` value of the sibling field called `name`.
fn sibling_u16(siblings: &[Field<'_>], name: &str) -> Option<u16> {
    siblings.iter().find_map(|f| match (f.name(), &f.value) {
        (n, FieldValue::U16(v)) if n == name => Some(*v),
        _ => None,
    })
}

/// Name of an enumerated AVP value, keyed by the sibling Attribute Type.
fn typed_value_name(v: &FieldValue<'_>, siblings: &[Field<'_>]) -> Option<&'static str> {
    let FieldValue::U16(value) = v else {
        return None;
    };
    match sibling_u16(siblings, "attribute_type")? {
        ATTR_MESSAGE_TYPE => crate::l2tpv3_message_type_name(*value),
        ATTR_PSEUDOWIRE_TYPE => pseudowire_type_name(*value),
        ATTR_L2_SPECIFIC_SUBLAYER => l2_specific_sublayer_name(*value),
        ATTR_DATA_SEQUENCING => data_sequencing_name(*value),
        _ => None,
    }
}

/// IANA "L2TPv3 Pseudowire Types" registry.
/// <https://www.iana.org/assignments/l2tp-parameters/l2tp-parameters.xhtml#l2tp-parameters-34>
pub(crate) fn pseudowire_type_name(v: u16) -> Option<&'static str> {
    match v {
        0x0001 => Some("Frame Relay DLCI Pseudowire Type"),
        0x0002 => Some("ATM AAL5 SDU VCC transport"),
        0x0003 => Some("ATM Cell transparent Port Mode"),
        0x0004 => Some("Ethernet VLAN Pseudowire Type"),
        0x0005 => Some("Ethernet Pseudowire Type"),
        0x0006 => Some("HDLC Pseudowire Type"),
        0x0009 => Some("ATM Cell transport VCC Mode"),
        0x000A => Some("ATM Cell transport VPC Mode"),
        0x000C => Some("MPEG-TS Payload Type (MPTPW)"),
        0x000D => Some("Packet Streaming Protocol (PSPPW)"),
        0x0011 => Some("Structure-agnostic E1 circuit"),
        0x0012 => Some("Structure-agnostic T1 (DS1) circuit"),
        0x0013 => Some("Structure-agnostic E3 circuit"),
        0x0014 => Some("Structure-agnostic T3 (DS3) circuit"),
        0x0015 => Some("CESoPSN basic mode"),
        0x0017 => Some("CESoPSN TDM with CAS"),
        _ => None,
    }
}

/// IANA "L2-Specific Sublayer Type" registry (RFC 3931, Section 5.4.4).
/// <https://www.rfc-editor.org/rfc/rfc3931#section-5.4.4>
/// <https://www.iana.org/assignments/l2tp-parameters/l2tp-parameters.xhtml#l2tp-parameters-37>
fn l2_specific_sublayer_name(v: u16) -> Option<&'static str> {
    match v {
        0 => Some("No L2-Specific Sublayer"),
        1 => Some("Default L2-Specific Sublayer present"),
        2 => Some("ATM-Specific Sublayer present"),
        3 => Some("MPT-Specific Sublayer"),
        4 => Some("PSP-Specific Sublayer"),
        _ => None,
    }
}

/// IANA "Data Sequencing Level" registry (RFC 3931, Section 5.4.4).
/// <https://www.rfc-editor.org/rfc/rfc3931#section-5.4.4>
/// <https://www.iana.org/assignments/l2tp-parameters/l2tp-parameters.xhtml#l2tp-parameters-38>
fn data_sequencing_name(v: u16) -> Option<&'static str> {
    match v {
        0 => Some("No incoming data packets require sequencing."),
        1 => Some("Only non-IP data packets require sequencing."),
        2 => Some("All incoming data packets require sequencing."),
        _ => None,
    }
}

// Attribute Types with typed values (RFC 3931, Section 5.4).
// <https://www.rfc-editor.org/rfc/rfc3931#section-5.4>
const ATTR_MESSAGE_TYPE: u16 = 0;
const ATTR_RESULT_CODE: u16 = 1;
const ATTR_FIRMWARE_REVISION: u16 = 6;
const ATTR_HOST_NAME: u16 = 7;
const ATTR_VENDOR_NAME: u16 = 8;
const ATTR_RECEIVE_WINDOW_SIZE: u16 = 10;
const ATTR_SERIAL_NUMBER: u16 = 15;
const ATTR_ROUTER_ID: u16 = 60;
const ATTR_ASSIGNED_CCID: u16 = 61;
const ATTR_PW_CAPABILITIES: u16 = 62;
const ATTR_LOCAL_SESSION_ID: u16 = 63;
const ATTR_REMOTE_SESSION_ID: u16 = 64;
const ATTR_PSEUDOWIRE_TYPE: u16 = 68;
const ATTR_L2_SPECIFIC_SUBLAYER: u16 = 69;
const ATTR_DATA_SEQUENCING: u16 = 70;
const ATTR_CIRCUIT_STATUS: u16 = 71;
const ATTR_PREFERRED_LANGUAGE: u16 = 72;
const ATTR_TX_CONNECT_SPEED: u16 = 74;
const ATTR_RX_CONNECT_SPEED: u16 = 75;

// Indices into [`AVP_CHILD_FIELDS`] of the decoded-value fields.
const AFD_TYPED_VALUE: usize = 6;
const AFD_RESULT_CODE: usize = 7;
const AFD_ERROR_CODE: usize = 8;
const AFD_ERROR_MESSAGE: usize = 9;
const AFD_CIRCUIT_NEW: usize = 10;
const AFD_CIRCUIT_ACTIVE: usize = 11;
const AFD_PW_TYPES: usize = 12;

// RFC 3931, Section 5.4.3 — https://www.rfc-editor.org/rfc/rfc3931#section-5.4.3
static FD_PW_TYPE_ITEM: FieldDescriptor =
    FieldDescriptor::new("pw_type", "Pseudowire Type", FieldType::U16).with_display_fn(|v, _| {
        match v {
            FieldValue::U16(t) => pseudowire_type_name(*t),
            _ => None,
        }
    });

/// Decode the Attribute Value of an IETF (Vendor ID 0), non-hidden AVP.
///
/// RFC 3931, Section 5.4 — <https://www.rfc-editor.org/rfc/rfc3931#section-5.4>.
/// Values whose length does not match the AVP definition are left raw.
fn decode_value<'pkt>(buf: &mut DissectBuffer<'pkt>, attr: u16, value: &'pkt [u8], off: usize) {
    let range = off..off + value.len();
    match (attr, value.len()) {
        (
            ATTR_MESSAGE_TYPE
            | ATTR_FIRMWARE_REVISION
            | ATTR_RECEIVE_WINDOW_SIZE
            | ATTR_PSEUDOWIRE_TYPE
            | ATTR_L2_SPECIFIC_SUBLAYER
            | ATTR_DATA_SEQUENCING,
            2,
        ) => {
            let v = read_be_u16(value, 0).unwrap_or_default();
            buf.push_field(
                &AVP_CHILD_FIELDS[AFD_TYPED_VALUE],
                FieldValue::U16(v),
                range,
            );
        }
        (
            ATTR_SERIAL_NUMBER
            | ATTR_ROUTER_ID
            | ATTR_ASSIGNED_CCID
            | ATTR_LOCAL_SESSION_ID
            | ATTR_REMOTE_SESSION_ID,
            4,
        ) => {
            let v = read_be_u32(value, 0).unwrap_or_default();
            buf.push_field(
                &AVP_CHILD_FIELDS[AFD_TYPED_VALUE],
                FieldValue::U32(v),
                range,
            );
        }
        // RFC 3931, Section 5.4.4 — "Connect Speed in bps (64 bits)".
        // <https://www.rfc-editor.org/rfc/rfc3931#section-5.4.4>
        (ATTR_TX_CONNECT_SPEED | ATTR_RX_CONNECT_SPEED, 8) => {
            let v = read_be_u64(value, 0).unwrap_or_default();
            buf.push_field(
                &AVP_CHILD_FIELDS[AFD_TYPED_VALUE],
                FieldValue::U64(v),
                range,
            );
        }
        (ATTR_HOST_NAME | ATTR_VENDOR_NAME | ATTR_PREFERRED_LANGUAGE, 1..) => {
            if let Ok(s) = core::str::from_utf8(value) {
                buf.push_field(
                    &AVP_CHILD_FIELDS[AFD_TYPED_VALUE],
                    FieldValue::Str(s),
                    range,
                );
            }
        }
        // RFC 3931, Section 5.4.2 — Result Code (2), optional Error Code
        // (2) and optional Error Message.
        // <https://www.rfc-editor.org/rfc/rfc3931#section-5.4.2>
        (ATTR_RESULT_CODE, 2..) => {
            let rc = read_be_u16(value, 0).unwrap_or_default();
            buf.push_field(
                &AVP_CHILD_FIELDS[AFD_RESULT_CODE],
                FieldValue::U16(rc),
                off..off + 2,
            );
            if value.len() >= 4 {
                let ec = read_be_u16(value, 2).unwrap_or_default();
                buf.push_field(
                    &AVP_CHILD_FIELDS[AFD_ERROR_CODE],
                    FieldValue::U16(ec),
                    off + 2..off + 4,
                );
                if value.len() > 4 {
                    if let Ok(msg) = core::str::from_utf8(&value[4..]) {
                        buf.push_field(
                            &AVP_CHILD_FIELDS[AFD_ERROR_MESSAGE],
                            FieldValue::Str(msg),
                            off + 4..off + value.len(),
                        );
                    }
                }
            }
        }
        // RFC 3931, Section 5.4.3 — a list of 2-octet Pseudowire Types.
        // <https://www.rfc-editor.org/rfc/rfc3931#section-5.4.3>
        (ATTR_PW_CAPABILITIES, n) if n > 0 && n % 2 == 0 => {
            let idx = buf.begin_container(
                &AVP_CHILD_FIELDS[AFD_PW_TYPES],
                FieldValue::Array(0..0),
                range,
            );
            for (i, c) in value.chunks_exact(2).enumerate() {
                let at = off + 2 * i;
                buf.push_field(
                    &FD_PW_TYPE_ITEM,
                    FieldValue::U16(u16::from_be_bytes([c[0], c[1]])),
                    at..at + 2,
                );
            }
            buf.end_container(idx);
        }
        // RFC 3931, Section 5.4.5 — "|         Reserved          |N|A|".
        // <https://www.rfc-editor.org/rfc/rfc3931#section-5.4.5>
        (ATTR_CIRCUIT_STATUS, 2) => {
            let v = read_be_u16(value, 0).unwrap_or_default();
            buf.push_field(
                &AVP_CHILD_FIELDS[AFD_TYPED_VALUE],
                FieldValue::U16(v),
                range.clone(),
            );
            buf.push_field(
                &AVP_CHILD_FIELDS[AFD_CIRCUIT_NEW],
                FieldValue::U8(((v >> 1) & 1) as u8),
                range.clone(),
            );
            buf.push_field(
                &AVP_CHILD_FIELDS[AFD_CIRCUIT_ACTIVE],
                FieldValue::U8((v & 1) as u8),
                range,
            );
        }
        _ => {}
    }
}

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
    FieldDescriptor {
        name: "typed_value",
        display_name: "Typed Value",
        field_type: FieldType::Any,
        optional: true,
        children: None,
        display_fn: Some(typed_value_name),
        format_fn: None,
    },
    FieldDescriptor::new("result_code", "Result Code", FieldType::U16).optional(),
    FieldDescriptor::new("error_code", "Error Code", FieldType::U16).optional(),
    FieldDescriptor::new("error_message", "Error Message", FieldType::Str).optional(),
    FieldDescriptor::new("new", "New (N)", FieldType::U8).optional(),
    FieldDescriptor::new("active", "Active (A)", FieldType::U8).optional(),
    FieldDescriptor::new("pw_types", "Pseudowire Capabilities", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_PW_TYPE_ITEM)),
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
        // RFC 3931, Section 5.3 — a hidden value is encrypted; vendor AVPs
        // have vendor-defined formats. Both stay raw.
        // <https://www.rfc-editor.org/rfc/rfc3931#section-5.3>
        if h_flag == 0 && vendor_id == 0 {
            decode_value(buf, attribute_type, value_data, abs + MIN_AVP_SIZE);
        }
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
    // | 5.4.1       | Message Type value (FSQ, RFC 4951) | typed_message_type_and_names |
    // | 5.4.2       | Result Code / Error Code / Message | typed_result_code |
    // | 5.4.3-5.4.4 | CCID, Session IDs, Router ID       | typed_session_and_connection_ids |
    // | 5.4.3-5.4.4 | Host Name, Tx/Rx Connect Speed     | typed_strings_and_speeds |
    // | 5.4.3-5.4.4 | PW Type, L2SS, Data Sequencing, PW Capabilities | typed_pseudowire_and_sublayer |
    // | 5.4.5       | Circuit Status A/N bits            | typed_circuit_status |
    // | 5.3         | Hidden / vendor AVPs stay raw      | hidden_and_vendor_avps_are_not_typed |

    #[test]
    fn parse_avp_basic() {
        let data: &[u8] = &[0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..8);
        parse_avps(data, 100, &mut buf);
        buf.end_layer();

        let fields = buf.fields();
        // 1 Object container + 6 header/value children + typed Message Type
        assert!(fields[0].value.is_object());
        let obj_range = fields[0].value.as_container_range().unwrap();
        let children = buf.nested_fields(obj_range);
        assert_eq!(children.len(), 7);
        assert_eq!(children[0].value, FieldValue::U8(0)); // mandatory
        assert_eq!(children[1].value, FieldValue::U8(0)); // hidden
        assert_eq!(children[2].value, FieldValue::U16(8)); // length
        assert_eq!(children[3].value, FieldValue::U16(0)); // vendor_id
        assert_eq!(children[4].value, FieldValue::U16(0)); // attribute_type
        assert_eq!(children[5].value, FieldValue::Bytes(&[0x00, 0x01])); // value
        assert_eq!(children[6].value, FieldValue::U16(1)); // typed_value
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

    /// Build an AVP (M=1, Vendor ID 0, not hidden).
    fn avp(attr: u16, value: &[u8]) -> Vec<u8> {
        let len = (6 + value.len()) as u16;
        let mut v = (0x8000 | len).to_be_bytes().to_vec();
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&attr.to_be_bytes());
        v.extend_from_slice(value);
        v
    }

    /// Parse `data` and return the (flat) fields of the first AVP Object.
    fn first_avp(data: &[u8]) -> (DissectBuffer<'_>, core::ops::Range<u32>) {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..data.len());
        parse_avps(data, 0, &mut buf);
        buf.end_layer();
        let r = buf.fields()[0].value.as_container_range().unwrap().clone();
        (buf, r)
    }

    fn get<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        r: &core::ops::Range<u32>,
        name: &str,
    ) -> Option<&'a FieldValue<'pkt>> {
        buf.nested_fields(r)
            .iter()
            .find(|f| f.name() == name)
            .map(|f| &f.value)
    }

    #[test]
    fn typed_message_type_and_names() {
        // RFC 4951, Sections 4.1-4.2 — FSQ (21) / FSR (22).
        // <https://www.rfc-editor.org/rfc/rfc4951#section-4.1>
        let data = avp(0, &[0, 21]);
        let (buf, r) = first_avp(&data);
        assert_eq!(get(&buf, &r, "typed_value"), Some(&FieldValue::U16(21)));
        assert_eq!(
            buf.resolve_nested_display_name(&r, "typed_value_name"),
            Some("FSQ")
        );
    }

    #[test]
    fn typed_result_code() {
        // RFC 3931, Section 5.4.2 — Result Code, Error Code, Error Message.
        // <https://www.rfc-editor.org/rfc/rfc3931#section-5.4.2>
        let data = avp(1, &[0, 2, 0, 6, b'b', b'a', b'd']);
        let (buf, r) = first_avp(&data);
        assert_eq!(get(&buf, &r, "result_code"), Some(&FieldValue::U16(2)));
        assert_eq!(get(&buf, &r, "error_code"), Some(&FieldValue::U16(6)));
        assert_eq!(
            get(&buf, &r, "error_message"),
            Some(&FieldValue::Str("bad"))
        );
        // Result Code only.
        let data = avp(1, &[0, 1]);
        let (buf, r) = first_avp(&data);
        assert_eq!(get(&buf, &r, "result_code"), Some(&FieldValue::U16(1)));
        assert!(get(&buf, &r, "error_code").is_none());
    }

    #[test]
    fn typed_session_and_connection_ids() {
        for (attr, v) in [(61u16, 0x1122_3344u32), (63, 7), (64, 8), (60, 9), (15, 10)] {
            let data = avp(attr, &v.to_be_bytes());
            let (buf, r) = first_avp(&data);
            assert_eq!(
                get(&buf, &r, "typed_value"),
                Some(&FieldValue::U32(v)),
                "{attr}"
            );
        }
    }

    #[test]
    fn typed_strings_and_speeds() {
        let data = avp(7, b"lac");
        let (buf, r) = first_avp(&data);
        assert_eq!(get(&buf, &r, "typed_value"), Some(&FieldValue::Str("lac")));
        // RFC 3931, Section 5.4.4 — 64-bit Tx/Rx Connect Speed.
        // <https://www.rfc-editor.org/rfc/rfc3931#section-5.4.4>
        let data = avp(74, &1_000_000_000u64.to_be_bytes());
        let (buf, r) = first_avp(&data);
        assert_eq!(
            get(&buf, &r, "typed_value"),
            Some(&FieldValue::U64(1_000_000_000))
        );
        // Wrong length: no typed value.
        let data = avp(74, &[0, 1]);
        let (buf, r) = first_avp(&data);
        assert!(get(&buf, &r, "typed_value").is_none());
        // Invalid UTF-8 host name: no typed value.
        let data = avp(7, &[0xff]);
        let (buf, r) = first_avp(&data);
        assert!(get(&buf, &r, "typed_value").is_none());
    }

    #[test]
    fn typed_pseudowire_and_sublayer() {
        let data = avp(68, &[0, 5]);
        let (buf, r) = first_avp(&data);
        assert_eq!(
            buf.resolve_nested_display_name(&r, "typed_value_name"),
            Some("Ethernet Pseudowire Type")
        );
        let data = avp(69, &[0, 1]);
        let (buf, r) = first_avp(&data);
        assert_eq!(
            buf.resolve_nested_display_name(&r, "typed_value_name"),
            Some("Default L2-Specific Sublayer present")
        );
        let data = avp(70, &[0, 2]);
        let (buf, r) = first_avp(&data);
        assert_eq!(
            buf.resolve_nested_display_name(&r, "typed_value_name"),
            Some("All incoming data packets require sequencing.")
        );
        // RFC 3931, Section 5.4.3 — Pseudowire Capabilities List.
        // <https://www.rfc-editor.org/rfc/rfc3931#section-5.4.3>
        let data = avp(62, &[0, 4, 0, 5]);
        let (buf, r) = first_avp(&data);
        let FieldValue::Array(a) = get(&buf, &r, "pw_types").unwrap() else {
            panic!("pw_types");
        };
        let items = buf.nested_fields(a);
        assert_eq!(items.len(), 2);
        assert_eq!(items[1].value, FieldValue::U16(5));
    }

    #[test]
    fn typed_circuit_status() {
        // RFC 3931, Section 5.4.5 — N (bit 14) and A (bit 15).
        // <https://www.rfc-editor.org/rfc/rfc3931#section-5.4.5>
        let data = avp(71, &[0, 3]);
        let (buf, r) = first_avp(&data);
        assert_eq!(get(&buf, &r, "active"), Some(&FieldValue::U8(1)));
        assert_eq!(get(&buf, &r, "new"), Some(&FieldValue::U8(1)));
        let data = avp(71, &[0, 1]);
        let (buf, r) = first_avp(&data);
        assert_eq!(get(&buf, &r, "new"), Some(&FieldValue::U8(0)));
    }

    #[test]
    fn hidden_and_vendor_avps_are_not_typed() {
        // Hidden (H=1): RFC 3931, Section 5.3 — value is encrypted.
        // <https://www.rfc-editor.org/rfc/rfc3931#section-5.3>
        let mut data = avp(61, &[0, 0, 0, 1]);
        data[0] |= 0x40;
        let (buf, r) = first_avp(&data);
        assert!(get(&buf, &r, "typed_value").is_none());
        // Vendor-specific.
        let mut data = avp(61, &[0, 0, 0, 1]);
        data[3] = 9;
        let (buf, r) = first_avp(&data);
        assert!(get(&buf, &r, "typed_value").is_none());
    }

    #[test]
    fn enumerated_value_names() {
        // IANA "L2TPv3 Pseudowire Types" registry.
        // <https://www.iana.org/assignments/l2tp-parameters/l2tp-parameters.xhtml#l2tp-parameters-34>
        for (v, name) in [
            (0x0001, "Frame Relay DLCI Pseudowire Type"),
            (0x0002, "ATM AAL5 SDU VCC transport"),
            (0x0003, "ATM Cell transparent Port Mode"),
            (0x0004, "Ethernet VLAN Pseudowire Type"),
            (0x0005, "Ethernet Pseudowire Type"),
            (0x0006, "HDLC Pseudowire Type"),
            (0x0009, "ATM Cell transport VCC Mode"),
            (0x000A, "ATM Cell transport VPC Mode"),
            (0x000C, "MPEG-TS Payload Type (MPTPW)"),
            (0x000D, "Packet Streaming Protocol (PSPPW)"),
            (0x0011, "Structure-agnostic E1 circuit"),
            (0x0012, "Structure-agnostic T1 (DS1) circuit"),
            (0x0013, "Structure-agnostic E3 circuit"),
            (0x0014, "Structure-agnostic T3 (DS3) circuit"),
            (0x0015, "CESoPSN basic mode"),
            (0x0017, "CESoPSN TDM with CAS"),
        ] {
            assert_eq!(pseudowire_type_name(v), Some(name));
        }
        assert_eq!(pseudowire_type_name(0x0007), None);
        // RFC 3931, Section 5.4.4 — L2-Specific Sublayer / Data Sequencing.
        // <https://www.rfc-editor.org/rfc/rfc3931#section-5.4.4>
        for v in 0..=4 {
            assert!(l2_specific_sublayer_name(v).is_some());
        }
        assert_eq!(l2_specific_sublayer_name(5), None);
        for v in 0..=2 {
            assert!(data_sequencing_name(v).is_some());
        }
        assert_eq!(data_sequencing_name(3), None);
    }

    #[test]
    fn display_fns_resolve_names() {
        let siblings = [Field {
            descriptor: &AVP_CHILD_FIELDS[4],
            value: FieldValue::U16(ATTR_PSEUDOWIRE_TYPE),
            range: 0..2,
        }];
        assert_eq!(
            typed_value_name(&FieldValue::U16(5), &siblings),
            Some("Ethernet Pseudowire Type")
        );
        assert_eq!(typed_value_name(&FieldValue::U8(5), &siblings), None);
        let other = [Field {
            descriptor: &AVP_CHILD_FIELDS[4],
            value: FieldValue::U16(ATTR_HOST_NAME),
            range: 0..2,
        }];
        assert_eq!(typed_value_name(&FieldValue::U16(5), &other), None);

        let display = FD_PW_TYPE_ITEM.display_fn.unwrap();
        assert_eq!(
            display(&FieldValue::U16(4), &[]),
            Some("Ethernet VLAN Pseudowire Type")
        );
        assert_eq!(display(&FieldValue::U8(4), &[]), None);
    }
}
