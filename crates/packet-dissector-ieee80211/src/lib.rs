//! IEEE 802.11 (wireless LAN) MAC frame dissector (`LINKTYPE_IEEE802_11`, 105).
//!
//! Decodes the MAC header of Management, Control, Data and Extension frames
//! (Frame Control, Duration/ID, the address fields selected by the frame type
//! and the To DS / From DS bits, Sequence Control, QoS Control and HT
//! Control), then:
//!
//! - Data frames: the IEEE 802.2 LLC header of the MSDU, shared with the
//!   Ethernet crate, dispatched by DSAP so that SNAP (LLC SAP 0xAA) leads to
//!   the EtherType table; A-MSDU subframes each get their own chain.
//!   Protected frames show the CCMP/GCMP (or WEP) header and leave the body
//!   opaque.
//! - Management frames: the fixed fields of the frame body and the element
//!   list (see the `element` module).
//! - Control frames: the address fields; the rest is kept as raw bytes.
//!
//! When the frame follows a radiotap header, its Flags field says whether
//! the frame ends with the 4-octet FCS and whether padding follows the MAC
//! header.
//!
//! ## References
//! - IEEE Std 802.11-2020, 9.2 (MAC frame formats), 9.3 (format of
//!   individual frame types), 9.4.1 (fields that are not elements), 9.4.2
//!   (elements), 12.5.3.2 (CCMP MPDU format), 12.5.5.2 (GCMP MPDU format),
//!   12.3.2.2 (WEP MPDU format): <https://standards.ieee.org/ieee/802.11/7028/>
//! - IEEE Std 802-2014, Clause 10 (SNAP): <https://standards.ieee.org/ieee/802/5813/>
//! - RFC 1042 (LLC/SNAP encapsulation of EtherTypes):
//!   <https://www.rfc-editor.org/rfc/rfc1042>
//! - Link-layer header types (`LINKTYPE_IEEE802_11` = 105):
//!   <https://www.tcpdump.org/linktypes.html>
//! - Radiotap Flags field (FCS at end, data padding):
//!   <https://www.radiotap.org/fields/Flags>

#![deny(missing_docs)]

mod element;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{Field, FieldDescriptor, FieldType, FieldValue, MacAddr};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ethernet::llc::{self, LlcHeader};

/// Frame Control (2) + Duration/ID (2).
const FC_DURATION_SIZE: usize = 4;
/// Size of an address field.
const ADDR_SIZE: usize = 6;
/// Frame Control, Duration, Address 1-3 and Sequence Control —
/// IEEE Std 802.11-2020, 9.3.2.1 (Data) and 9.3.3.2 (Management).
const THREE_ADDR_HEADER_SIZE: usize = 24;
/// Frame Control, Duration and Address 1 (RA) — 9.3.1.3 (CTS), 9.3.1.4 (Ack).
const RA_HEADER_SIZE: usize = 10;
/// Frame Control, Duration, Address 1 (RA) and Address 2 (TA) — 9.3.1.2 (RTS).
const RA_TA_HEADER_SIZE: usize = 16;
/// Control Wrapper: RA, Carried Frame Control (2), HT Control (4) — 9.3.1.9.
const CONTROL_WRAPPER_HEADER_SIZE: usize = 16;
/// QoS Control field size — 9.2.4.5.
const QOS_CONTROL_SIZE: usize = 2;
/// HT Control field size — 9.2.4.6.
const HT_CONTROL_SIZE: usize = 4;
/// FCS field size — 9.2.4.8.
const FCS_SIZE: usize = 4;
/// WEP IV (3) + Key ID octet — 12.3.2.2.
const WEP_HEADER_SIZE: usize = 4;
/// CCMP/GCMP header: PN0, PN1, reserved, Key ID octet, PN2-PN5 — 12.5.3.2.
const EXT_IV_HEADER_SIZE: usize = 8;
/// A-MSDU subframe header: DA (6), SA (6), Length (2) — 9.3.2.2.2.
const AMSDU_SUBFRAME_HEADER_SIZE: usize = 14;

/// Frame types — IEEE Std 802.11-2020, 9.2.4.1.3, Table 9-1.
const TYPE_MANAGEMENT: u8 = 0;
const TYPE_CONTROL: u8 = 1;
const TYPE_DATA: u8 = 2;
const TYPE_EXTENSION: u8 = 3;

/// Management subtypes — Table 9-1.
const MGMT_ASSOC_REQ: u8 = 0;
const MGMT_ASSOC_RESP: u8 = 1;
const MGMT_REASSOC_REQ: u8 = 2;
const MGMT_REASSOC_RESP: u8 = 3;
const MGMT_PROBE_REQ: u8 = 4;
const MGMT_PROBE_RESP: u8 = 5;
const MGMT_TIMING_ADVERTISEMENT: u8 = 6;
const MGMT_BEACON: u8 = 8;
const MGMT_DISASSOC: u8 = 10;
const MGMT_AUTH: u8 = 11;
const MGMT_DEAUTH: u8 = 12;
const MGMT_ACTION: u8 = 13;
const MGMT_ACTION_NO_ACK: u8 = 14;

/// Control subtypes whose header ends after Address 1 (RA) — Table 9-1.
const CTRL_CONTROL_FRAME_EXTENSION: u8 = 6;
const CTRL_CONTROL_WRAPPER: u8 = 7;
const CTRL_CTS: u8 = 12;
const CTRL_ACK: u8 = 13;

/// Data subtype bit 2: the frame has no Frame Body (Null, QoS Null,
/// CF-Poll/-Ack without data) — 9.2.4.1.3.
const DATA_SUBTYPE_NO_DATA: u8 = 0x4;
/// Data subtype bit 3: QoS subtypes, which carry a QoS Control field.
const DATA_SUBTYPE_QOS: u8 = 0x8;

/// Frame Control flag bits (second octet) — 9.2.4.1.1, Figure 9-3.
const FLAG_TO_DS: u8 = 0x01;
const FLAG_FROM_DS: u8 = 0x02;
const FLAG_MORE_FRAGMENTS: u8 = 0x04;
const FLAG_RETRY: u8 = 0x08;
const FLAG_POWER_MANAGEMENT: u8 = 0x10;
const FLAG_MORE_DATA: u8 = 0x20;
const FLAG_PROTECTED: u8 = 0x40;
const FLAG_ORDER: u8 = 0x80;

/// Key ID octet bit 5: Extended IV (CCMP/GCMP/TKIP) — 12.5.3.2, Figure 12-16.
const KEY_ID_OCTET_EXT_IV: u8 = 0x20;

/// QoS Control A-MSDU Present bit (bit 7) — 9.2.4.5.1, Table 9-10.
const QOS_AMSDU_PRESENT: u16 = 0x0080;

/// Authentication algorithms whose Authentication frame body continues
/// with elements — 9.4.1.1: Open System (0), Shared Key (1), Fast BSS
/// Transition (2).
const AUTH_ALGORITHMS_WITH_ELEMENTS: [u16; 3] = [0, 1, 2];

/// Vendor-specific (protected / unprotected) Action categories, whose
/// category is followed by an OUI instead of an Action field — Table 9-51.
const CATEGORY_VENDOR_SPECIFIC_PROTECTED: u8 = 126;
const CATEGORY_VENDOR_SPECIFIC: u8 = 127;

/// Radiotap Flags: the frame includes the FCS — <https://www.radiotap.org/fields/Flags>.
const RADIOTAP_FLAG_FCS: u8 = 0x10;
/// Radiotap Flags: padding between the 802.11 header and the payload, to a
/// 32-bit boundary.
const RADIOTAP_FLAG_DATA_PAD: u8 = 0x20;

// Descriptor indices into FIELD_DESCRIPTORS.
const FD_FRAME_CONTROL: usize = 0;
const FD_PROTOCOL_VERSION: usize = 1;
const FD_TYPE: usize = 2;
const FD_SUBTYPE: usize = 3;
const FD_TO_DS: usize = 4;
const FD_FROM_DS: usize = 5;
const FD_MORE_FRAGMENTS: usize = 6;
const FD_RETRY: usize = 7;
const FD_POWER_MANAGEMENT: usize = 8;
const FD_MORE_DATA: usize = 9;
const FD_PROTECTED: usize = 10;
const FD_ORDER: usize = 11;
const FD_DURATION: usize = 12;
const FD_ADDR1: usize = 13;
const FD_ADDR2: usize = 14;
const FD_ADDR3: usize = 15;
const FD_FRAGMENT_NUMBER: usize = 16;
const FD_SEQUENCE_NUMBER: usize = 17;
const FD_ADDR4: usize = 18;
const FD_DA: usize = 19;
const FD_SA: usize = 20;
const FD_BSSID: usize = 21;
const FD_QOS_CONTROL: usize = 22;
const FD_QOS_TID: usize = 23;
const FD_QOS_EOSP: usize = 24;
const FD_QOS_ACK_POLICY: usize = 25;
const FD_QOS_AMSDU_PRESENT: usize = 26;
const FD_HT_CONTROL: usize = 27;
const FD_CARRIED_FRAME_CONTROL: usize = 28;
const FD_WEP_IV: usize = 29;
const FD_KEY_ID: usize = 30;
const FD_EXT_IV: usize = 31;
const FD_PN: usize = 32;
const FD_ENCRYPTED_DATA: usize = 33;
const FD_TIMESTAMP: usize = 34;
const FD_BEACON_INTERVAL: usize = 35;
const FD_CAPABILITY_INFO: usize = 36;
const FD_LISTEN_INTERVAL: usize = 37;
const FD_CURRENT_AP: usize = 38;
const FD_STATUS_CODE: usize = 39;
const FD_ASSOCIATION_ID: usize = 40;
const FD_REASON_CODE: usize = 41;
const FD_AUTH_ALGORITHM: usize = 42;
const FD_AUTH_SEQ: usize = 43;
const FD_CATEGORY: usize = 44;
const FD_ACTION_CODE: usize = 45;
const FD_ELEMENTS: usize = 46;
const FD_LLC_DSAP: usize = 47;
const FD_LLC_SSAP: usize = 48;
const FD_LLC_CONTROL: usize = 49;
const FD_LLC_CONTROL_EXT: usize = 50;
const FD_AMSDU_SUBFRAMES: usize = 51;
const FD_BODY: usize = 52;
const FD_FCS: usize = 53;

// Descriptor indices into AMSDU_SUBFRAME_FIELDS.
const AF_DA: usize = 0;
const AF_SA: usize = 1;
const AF_LENGTH: usize = 2;
const AF_LLC_DSAP: usize = 3;

/// Children of one A-MSDU subframe — IEEE Std 802.11-2020, 9.3.2.2.2.
static AMSDU_SUBFRAME_FIELDS: [FieldDescriptor; 7] = [
    FieldDescriptor::new("da", "Destination Address", FieldType::MacAddr),
    FieldDescriptor::new("sa", "Source Address", FieldType::MacAddr),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    llc::DSAP_FIELD,
    llc::SSAP_FIELD,
    llc::CONTROL_FIELD,
    llc::CONTROL_EXT_FIELD,
];

/// A-MSDU subframe Object descriptor.
static AMSDU_SUBFRAME: FieldDescriptor =
    FieldDescriptor::new("subframe", "A-MSDU Subframe", FieldType::Object)
        .with_children(&AMSDU_SUBFRAME_FIELDS);

/// Display name of the frame type.
fn type_display(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::U8(t) => frame_type_name(*t),
        _ => None,
    }
}

/// Display name of the subtype, which depends on the sibling `type` field.
fn subtype_display(v: &FieldValue<'_>, siblings: &[Field<'_>]) -> Option<&'static str> {
    let frame_type = siblings.iter().find_map(|f| match (f.name(), &f.value) {
        ("type", FieldValue::U8(t)) => Some(*t),
        _ => None,
    })?;
    match v {
        FieldValue::U8(s) => subtype_name(frame_type, *s),
        _ => None,
    }
}

static FIELD_DESCRIPTORS: [FieldDescriptor; 54] = [
    FieldDescriptor::new("frame_control", "Frame Control", FieldType::U16),
    FieldDescriptor::new("protocol_version", "Protocol Version", FieldType::U8),
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(type_display),
    FieldDescriptor::new("subtype", "Subtype", FieldType::U8).with_display_fn(subtype_display),
    FieldDescriptor::new("to_ds", "To DS", FieldType::U8),
    FieldDescriptor::new("from_ds", "From DS", FieldType::U8),
    FieldDescriptor::new("more_fragments", "More Fragments", FieldType::U8),
    FieldDescriptor::new("retry", "Retry", FieldType::U8),
    FieldDescriptor::new("power_management", "Power Management", FieldType::U8),
    FieldDescriptor::new("more_data", "More Data", FieldType::U8),
    FieldDescriptor::new("protected", "Protected Frame", FieldType::U8),
    FieldDescriptor::new("order", "+HTC/Order", FieldType::U8),
    FieldDescriptor::new("duration", "Duration/ID", FieldType::U16).optional(),
    FieldDescriptor::new("addr1", "Address 1 (RA)", FieldType::MacAddr).optional(),
    FieldDescriptor::new("addr2", "Address 2 (TA)", FieldType::MacAddr).optional(),
    FieldDescriptor::new("addr3", "Address 3", FieldType::MacAddr).optional(),
    FieldDescriptor::new("fragment_number", "Fragment Number", FieldType::U8).optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("addr4", "Address 4", FieldType::MacAddr).optional(),
    FieldDescriptor::new("da", "Destination Address", FieldType::MacAddr).optional(),
    FieldDescriptor::new("sa", "Source Address", FieldType::MacAddr).optional(),
    FieldDescriptor::new("bssid", "BSSID", FieldType::MacAddr).optional(),
    FieldDescriptor::new("qos_control", "QoS Control", FieldType::U16).optional(),
    FieldDescriptor::new("qos_tid", "TID", FieldType::U8).optional(),
    FieldDescriptor::new("qos_eosp", "EOSP", FieldType::U8).optional(),
    FieldDescriptor::new("qos_ack_policy", "Ack Policy", FieldType::U8).optional(),
    FieldDescriptor::new("qos_amsdu_present", "A-MSDU Present", FieldType::U8).optional(),
    FieldDescriptor::new("ht_control", "HT Control", FieldType::U32).optional(),
    FieldDescriptor::new(
        "carried_frame_control",
        "Carried Frame Control",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("wep_iv", "WEP IV", FieldType::Bytes).optional(),
    FieldDescriptor::new("key_id", "Key ID", FieldType::U8).optional(),
    FieldDescriptor::new("ext_iv", "Ext IV", FieldType::U8).optional(),
    // TKIP also sets Ext IV but orders its TSC octets differently
    // (12.5.2.2); the frame does not say which cipher is in use, so the
    // header is always read with the CCMP/GCMP layout.
    FieldDescriptor::new("pn", "Packet Number (CCMP/GCMP)", FieldType::U64).optional(),
    FieldDescriptor::new("encrypted_data", "Encrypted Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("timestamp", "Timestamp", FieldType::U64).optional(),
    FieldDescriptor::new("beacon_interval", "Beacon Interval (TU)", FieldType::U16).optional(),
    FieldDescriptor::new("capability_info", "Capability Information", FieldType::U16).optional(),
    FieldDescriptor::new("listen_interval", "Listen Interval", FieldType::U16).optional(),
    FieldDescriptor::new("current_ap", "Current AP Address", FieldType::MacAddr).optional(),
    FieldDescriptor::new("status_code", "Status Code", FieldType::U16).optional(),
    FieldDescriptor::new("association_id", "Association ID", FieldType::U16).optional(),
    FieldDescriptor::new("reason_code", "Reason Code", FieldType::U16).optional(),
    FieldDescriptor::new(
        "auth_algorithm",
        "Authentication Algorithm Number",
        FieldType::U16,
    )
    .optional()
    .with_display_fn(|v, _| match v {
        FieldValue::U16(a) => auth_algorithm_name(*a),
        _ => None,
    }),
    FieldDescriptor::new(
        "auth_seq",
        "Authentication Transaction Sequence Number",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("category", "Category", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(c) => category_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("action_code", "Action", FieldType::U8).optional(),
    FieldDescriptor::new("elements", "Elements", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&element::ELEMENT)),
    llc::DSAP_FIELD,
    llc::SSAP_FIELD,
    llc::CONTROL_FIELD,
    llc::CONTROL_EXT_FIELD,
    FieldDescriptor::new("amsdu_subframes", "A-MSDU Subframes", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&AMSDU_SUBFRAME)),
    FieldDescriptor::new("body", "Frame Body", FieldType::Bytes).optional(),
    FieldDescriptor::new("fcs", "FCS", FieldType::U32).optional(),
];

static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "IEEE 802.11-2020",
        "IEEE Standard for Information Technology--Telecommunications and Information \
         Exchange between Systems - Local and Metropolitan Area Networks--Specific \
         Requirements - Part 11: Wireless LAN Medium Access Control (MAC) and Physical \
         Layer (PHY) Specifications",
        "https://standards.ieee.org/ieee/802.11/7028/",
    ),
    SpecReference::new(
        "LINKTYPE_IEEE802_11",
        "Link-layer header types: LINKTYPE_IEEE802_11",
        "https://www.tcpdump.org/linktypes.html",
    ),
];

/// Frame type names — IEEE Std 802.11-2020, Table 9-1.
fn frame_type_name(frame_type: u8) -> Option<&'static str> {
    Some(match frame_type {
        TYPE_MANAGEMENT => "Management",
        TYPE_CONTROL => "Control",
        TYPE_DATA => "Data",
        TYPE_EXTENSION => "Extension",
        _ => return None,
    })
}

/// Subtype names — IEEE Std 802.11-2020, Table 9-1 (Control subtype 2,
/// Trigger, from IEEE Std 802.11ax-2021).
fn subtype_name(frame_type: u8, subtype: u8) -> Option<&'static str> {
    Some(match (frame_type, subtype) {
        (TYPE_MANAGEMENT, 0) => "Association Request",
        (TYPE_MANAGEMENT, 1) => "Association Response",
        (TYPE_MANAGEMENT, 2) => "Reassociation Request",
        (TYPE_MANAGEMENT, 3) => "Reassociation Response",
        (TYPE_MANAGEMENT, 4) => "Probe Request",
        (TYPE_MANAGEMENT, 5) => "Probe Response",
        (TYPE_MANAGEMENT, 6) => "Timing Advertisement",
        (TYPE_MANAGEMENT, 8) => "Beacon",
        (TYPE_MANAGEMENT, 9) => "ATIM",
        (TYPE_MANAGEMENT, 10) => "Disassociation",
        (TYPE_MANAGEMENT, 11) => "Authentication",
        (TYPE_MANAGEMENT, 12) => "Deauthentication",
        (TYPE_MANAGEMENT, 13) => "Action",
        (TYPE_MANAGEMENT, 14) => "Action No Ack",
        (TYPE_CONTROL, 2) => "Trigger",
        (TYPE_CONTROL, 3) => "TACK",
        (TYPE_CONTROL, 4) => "Beamforming Report Poll",
        (TYPE_CONTROL, 5) => "VHT NDP Announcement",
        (TYPE_CONTROL, 6) => "Control Frame Extension",
        (TYPE_CONTROL, 7) => "Control Wrapper",
        (TYPE_CONTROL, 8) => "Block Ack Request",
        (TYPE_CONTROL, 9) => "Block Ack",
        (TYPE_CONTROL, 10) => "PS-Poll",
        (TYPE_CONTROL, 11) => "RTS",
        (TYPE_CONTROL, 12) => "CTS",
        (TYPE_CONTROL, 13) => "Ack",
        (TYPE_CONTROL, 14) => "CF-End",
        (TYPE_CONTROL, 15) => "CF-End +CF-Ack",
        (TYPE_DATA, 0) => "Data",
        (TYPE_DATA, 4) => "Null",
        (TYPE_DATA, 8) => "QoS Data",
        (TYPE_DATA, 9) => "QoS Data +CF-Ack",
        (TYPE_DATA, 10) => "QoS Data +CF-Poll",
        (TYPE_DATA, 11) => "QoS Data +CF-Ack +CF-Poll",
        (TYPE_DATA, 12) => "QoS Null",
        (TYPE_DATA, 14) => "QoS CF-Poll",
        (TYPE_DATA, 15) => "QoS CF-Ack +CF-Poll",
        (TYPE_EXTENSION, 0) => "DMG Beacon",
        (TYPE_EXTENSION, 1) => "S1G Beacon",
        _ => return None,
    })
}

/// Authentication Algorithm Number names — IEEE Std 802.11-2020, 9.4.1.1.
fn auth_algorithm_name(algorithm: u16) -> Option<&'static str> {
    Some(match algorithm {
        0 => "Open System",
        1 => "Shared Key",
        2 => "Fast BSS Transition",
        3 => "SAE",
        4 => "FILS Shared Key without PFS",
        5 => "FILS Shared Key with PFS",
        6 => "FILS Public Key",
        65535 => "Vendor specific",
        _ => return None,
    })
}

/// Action frame category names — IEEE Std 802.11-2020, Table 9-51.
fn category_name(category: u8) -> Option<&'static str> {
    Some(match category {
        0 => "Spectrum management",
        1 => "QoS",
        3 => "Block Ack",
        4 => "Public",
        5 => "Radio Measurement",
        6 => "Fast BSS Transition",
        7 => "HT",
        8 => "SA Query",
        9 => "Protected Dual of Public Action",
        10 => "WNM",
        11 => "Unprotected WNM",
        12 => "TDLS",
        13 => "Mesh",
        14 => "Multihop",
        15 => "Self-protected",
        16 => "DMG",
        18 => "Fast Session Transfer",
        19 => "Robust AV Streaming",
        20 => "Unprotected DMG",
        21 => "VHT",
        CATEGORY_VENDOR_SPECIFIC_PROTECTED => "Vendor-specific Protected",
        CATEGORY_VENDOR_SPECIFIC => "Vendor-specific",
        _ => return None,
    })
}

fn read_u16(data: &[u8], pos: usize) -> u16 {
    u16::from_le_bytes([data[pos], data[pos + 1]])
}

fn read_mac(data: &[u8], pos: usize) -> MacAddr {
    let mut addr = [0u8; ADDR_SIZE];
    addr.copy_from_slice(&data[pos..pos + ADDR_SIZE]);
    MacAddr(addr)
}

/// Flags field of a radiotap header that immediately precedes this frame,
/// or 0 when the frame does not follow one.
///
/// Only the layer's top-level `flags` field (first radiotap namespace) is
/// used, not one nested in a further namespace element. Like the TCP
/// dissector reading the enclosing IP layer, this looks the preceding layer
/// up by name, so the radiotap crate needs no dependency on this one.
fn radiotap_flags(buf: &DissectBuffer<'_>, offset: usize) -> u8 {
    let Some(layer) = buf
        .layers()
        .last()
        .filter(|l| l.name == "Radiotap" && l.range.end == offset)
    else {
        return 0;
    };
    let fields = buf.layer_fields(layer);
    let mut i = 0;
    while let Some(field) = fields.get(i) {
        if let ("flags", FieldValue::U8(flags)) = (field.name(), &field.value) {
            return *flags;
        }
        // Skip the children of a container field.
        i += field
            .value
            .as_container_range()
            .map_or(1, |r| (r.end - r.start) as usize + 1);
    }
    0
}

/// Decoded Frame Control field — IEEE Std 802.11-2020, 9.2.4.1.
#[derive(Clone, Copy)]
struct FrameControl {
    raw: u16,
    version: u8,
    frame_type: u8,
    subtype: u8,
    flags: u8,
}

impl FrameControl {
    fn parse(raw: u16) -> Self {
        let [first, flags] = raw.to_le_bytes();
        Self {
            raw,
            version: first & 0x03,
            frame_type: (first >> 2) & 0x03,
            subtype: first >> 4,
            flags,
        }
    }

    fn flag(&self, bit: u8) -> bool {
        self.flags & bit != 0
    }

    fn is_qos_data(&self) -> bool {
        self.frame_type == TYPE_DATA && self.subtype & DATA_SUBTYPE_QOS != 0
    }
}

/// Length of the MAC header for a protocol version 0 frame.
fn mac_header_len(fc: &FrameControl) -> usize {
    match fc.frame_type {
        // 9.3.3.2 — HT Control is present when +HTC is 1.
        TYPE_MANAGEMENT => {
            THREE_ADDR_HEADER_SIZE
                + if fc.flag(FLAG_ORDER) {
                    HT_CONTROL_SIZE
                } else {
                    0
                }
        }
        // 9.3.2.1 — Address 4 when To DS and From DS are both 1; QoS Control
        // in QoS subtypes; HT Control in QoS frames with +HTC set to 1.
        TYPE_DATA => {
            let mut len = THREE_ADDR_HEADER_SIZE;
            if fc.flag(FLAG_TO_DS) && fc.flag(FLAG_FROM_DS) {
                len += ADDR_SIZE;
            }
            if fc.is_qos_data() {
                len += QOS_CONTROL_SIZE;
                if fc.flag(FLAG_ORDER) {
                    len += HT_CONTROL_SIZE;
                }
            }
            len
        }
        TYPE_CONTROL => match fc.subtype {
            CTRL_CTS | CTRL_ACK | CTRL_CONTROL_FRAME_EXTENSION => RA_HEADER_SIZE,
            CTRL_CONTROL_WRAPPER => CONTROL_WRAPPER_HEADER_SIZE,
            // Reserved subtypes: format unknown past Duration.
            0 | 1 => FC_DURATION_SIZE,
            _ => RA_TA_HEADER_SIZE,
        },
        // Extension frames (DMG / S1G Beacon) are kept as a raw body.
        _ => FC_DURATION_SIZE,
    }
}

/// Length of the fixed (non-element) fields at the start of a Management
/// frame body — IEEE Std 802.11-2020, 9.3.3.
fn management_fixed_len(subtype: u8) -> usize {
    match subtype {
        // Capability Information, Listen Interval.
        MGMT_ASSOC_REQ => 4,
        // Capability Information, Status Code, AID.
        MGMT_ASSOC_RESP | MGMT_REASSOC_RESP => 6,
        // Capability Information, Listen Interval, Current AP Address.
        MGMT_REASSOC_REQ => 10,
        // Timestamp, Beacon Interval, Capability Information.
        MGMT_PROBE_RESP | MGMT_BEACON => 12,
        // Timestamp, Capability Information.
        MGMT_TIMING_ADVERTISEMENT => 10,
        // Reason Code.
        MGMT_DISASSOC | MGMT_DEAUTH => 2,
        // Algorithm Number, Transaction Sequence Number, Status Code.
        MGMT_AUTH => 6,
        // Category.
        MGMT_ACTION | MGMT_ACTION_NO_ACK => 1,
        _ => 0,
    }
}

/// How the octets after the MAC header are decoded.
enum Body {
    /// No octets follow the MAC header.
    None,
    /// Protected frame: security header of `header_len` octets, then the
    /// encrypted payload.
    Protected { header_len: usize },
    /// Management frame body with `fixed` octets of fixed fields.
    Management { fixed: usize },
    /// Data frame MSDU with its LLC header.
    Llc(LlcHeader),
    /// Data frame carrying an A-MSDU.
    Amsdu,
    /// Anything else, kept as raw bytes.
    Raw,
}

/// Decoding context for one frame.
struct Frame<'a, 'pkt> {
    data: &'pkt [u8],
    buf: &'a mut DissectBuffer<'pkt>,
    offset: usize,
}

impl<'pkt> Frame<'_, 'pkt> {
    fn push(&mut self, fd: usize, value: FieldValue<'pkt>, pos: usize, len: usize) {
        self.buf.push_field(
            &FIELD_DESCRIPTORS[fd],
            value,
            self.offset + pos..self.offset + pos + len,
        );
    }

    fn push_u16(&mut self, fd: usize, pos: usize) {
        let v = read_u16(self.data, pos);
        self.push(fd, FieldValue::U16(v), pos, 2);
    }

    fn push_addr(&mut self, fd: usize, pos: usize) {
        let addr = read_mac(self.data, pos);
        self.push(fd, FieldValue::MacAddr(addr), pos, ADDR_SIZE);
    }

    fn push_bytes(&mut self, fd: usize, start: usize, end: usize) {
        if start < end {
            self.push(
                fd,
                FieldValue::Bytes(&self.data[start..end]),
                start,
                end - start,
            );
        }
    }

    /// Frame Control subfields — 9.2.4.1.
    fn push_frame_control(&mut self, fc: &FrameControl) {
        self.push(FD_FRAME_CONTROL, FieldValue::U16(fc.raw), 0, 2);
        self.push(FD_PROTOCOL_VERSION, FieldValue::U8(fc.version), 0, 1);
        self.push(FD_TYPE, FieldValue::U8(fc.frame_type), 0, 1);
        self.push(FD_SUBTYPE, FieldValue::U8(fc.subtype), 0, 1);
        for (fd, bit) in [
            (FD_TO_DS, FLAG_TO_DS),
            (FD_FROM_DS, FLAG_FROM_DS),
            (FD_MORE_FRAGMENTS, FLAG_MORE_FRAGMENTS),
            (FD_RETRY, FLAG_RETRY),
            (FD_POWER_MANAGEMENT, FLAG_POWER_MANAGEMENT),
            (FD_MORE_DATA, FLAG_MORE_DATA),
            (FD_PROTECTED, FLAG_PROTECTED),
            (FD_ORDER, FLAG_ORDER),
        ] {
            self.push(fd, FieldValue::U8(u8::from(fc.flag(bit))), 1, 1);
        }
    }

    /// Sequence Control — 9.2.4.4: Fragment Number (bits 0-3), Sequence
    /// Number (bits 4-15).
    fn push_sequence_control(&mut self, pos: usize) {
        let sc = read_u16(self.data, pos);
        self.push(
            FD_FRAGMENT_NUMBER,
            FieldValue::U8((sc & 0x0F) as u8),
            pos,
            2,
        );
        self.push(FD_SEQUENCE_NUMBER, FieldValue::U16(sc >> 4), pos, 2);
    }

    /// QoS Control — 9.2.4.5: TID (bits 0-3), EOSP (bit 4), Ack Policy
    /// (bits 5-6), A-MSDU Present (bit 7).
    fn push_qos_control(&mut self, pos: usize) {
        let qos = read_u16(self.data, pos);
        self.push(FD_QOS_CONTROL, FieldValue::U16(qos), pos, 2);
        self.push(FD_QOS_TID, FieldValue::U8((qos & 0x0F) as u8), pos, 1);
        self.push(FD_QOS_EOSP, FieldValue::U8(((qos >> 4) & 1) as u8), pos, 1);
        self.push(
            FD_QOS_ACK_POLICY,
            FieldValue::U8(((qos >> 5) & 3) as u8),
            pos,
            1,
        );
        self.push(
            FD_QOS_AMSDU_PRESENT,
            FieldValue::U8(((qos >> 7) & 1) as u8),
            pos,
            1,
        );
    }

    fn push_ht_control(&mut self, pos: usize) {
        let d = self.data;
        let v = u32::from_le_bytes([d[pos], d[pos + 1], d[pos + 2], d[pos + 3]]);
        self.push(FD_HT_CONTROL, FieldValue::U32(v), pos, HT_CONTROL_SIZE);
    }

    /// Push the MAC header of a protocol version 0 frame (after Frame
    /// Control), whose length [`mac_header_len`] has already checked.
    fn push_mac_header(&mut self, fc: &FrameControl, amsdu: bool) {
        self.push_u16(FD_DURATION, 2);
        match fc.frame_type {
            TYPE_MANAGEMENT => {
                self.push_addr(FD_ADDR1, 4);
                self.push_addr(FD_ADDR2, 10);
                self.push_addr(FD_ADDR3, 16);
                self.push_sequence_control(22);
                // 9.3.3.2 — DA, SA and BSSID are Address 1, 2 and 3.
                self.push_addr(FD_DA, 4);
                self.push_addr(FD_SA, 10);
                self.push_addr(FD_BSSID, 16);
                if fc.flag(FLAG_ORDER) {
                    self.push_ht_control(THREE_ADDR_HEADER_SIZE);
                }
            }
            TYPE_DATA => {
                self.push_addr(FD_ADDR1, 4);
                self.push_addr(FD_ADDR2, 10);
                self.push_addr(FD_ADDR3, 16);
                self.push_sequence_control(22);
                let mut pos = THREE_ADDR_HEADER_SIZE;
                let four_addr = fc.flag(FLAG_TO_DS) && fc.flag(FLAG_FROM_DS);
                if four_addr {
                    self.push_addr(FD_ADDR4, pos);
                    pos += ADDR_SIZE;
                }
                self.push_data_roles(fc, amsdu);
                if fc.is_qos_data() {
                    self.push_qos_control(pos);
                    pos += QOS_CONTROL_SIZE;
                    if fc.flag(FLAG_ORDER) {
                        self.push_ht_control(pos);
                    }
                }
            }
            TYPE_CONTROL => {
                let header_len = mac_header_len(fc);
                if header_len >= RA_HEADER_SIZE {
                    self.push_addr(FD_ADDR1, 4);
                }
                if fc.subtype == CTRL_CONTROL_WRAPPER {
                    // 9.3.1.9 — Carried Frame Control, HT Control.
                    self.push_u16(FD_CARRIED_FRAME_CONTROL, 10);
                    self.push_ht_control(12);
                } else if header_len == RA_TA_HEADER_SIZE {
                    self.push_addr(FD_ADDR2, 10);
                }
            }
            _ => {}
        }
    }

    /// DA / SA / BSSID of a Data frame — IEEE Std 802.11-2020, 9.3.2.1,
    /// Table 9-30. For an A-MSDU the addresses name the BSSID instead of the
    /// SA / DA (which the subframes carry), so only the BSSID is derived.
    fn push_data_roles(&mut self, fc: &FrameControl, amsdu: bool) {
        const A1: usize = 4;
        const A2: usize = 10;
        const A3: usize = 16;
        const A4: usize = 24;
        let (da, sa, bssid) = match (fc.flag(FLAG_TO_DS), fc.flag(FLAG_FROM_DS)) {
            (false, false) => (Some(A1), Some(A2), Some(A3)),
            (false, true) => (Some(A1), Some(A3), Some(A2)),
            (true, false) => (Some(A3), Some(A2), Some(A1)),
            (true, true) => (Some(A3), Some(A4), None),
        };
        if !amsdu {
            if let Some(pos) = da {
                self.push_addr(FD_DA, pos);
            }
            if let Some(pos) = sa {
                self.push_addr(FD_SA, pos);
            }
        }
        if let Some(pos) = bssid {
            self.push_addr(FD_BSSID, pos);
        }
    }

    /// Security header of a protected frame and the opaque payload —
    /// 12.3.2.2 (WEP: IV, Key ID octet) and 12.5.3.2 / 12.5.5.2 (CCMP /
    /// GCMP: PN0, PN1, reserved, Key ID octet, PN2-PN5).
    fn push_protected(&mut self, pos: usize, header_len: usize, end: usize) {
        let d = self.data;
        let key_octet = d[pos + 3];
        if header_len == EXT_IV_HEADER_SIZE {
            let pn = u64::from_le_bytes([
                d[pos],
                d[pos + 1],
                d[pos + 4],
                d[pos + 5],
                d[pos + 6],
                d[pos + 7],
                0,
                0,
            ]);
            self.push(FD_PN, FieldValue::U64(pn), pos, EXT_IV_HEADER_SIZE);
        } else {
            self.push_bytes(FD_WEP_IV, pos, pos + 3);
        }
        self.push(
            FD_EXT_IV,
            FieldValue::U8(u8::from(key_octet & KEY_ID_OCTET_EXT_IV != 0)),
            pos + 3,
            1,
        );
        self.push(FD_KEY_ID, FieldValue::U8(key_octet >> 6), pos + 3, 1);
        self.push_bytes(FD_ENCRYPTED_DATA, pos + header_len, end);
    }

    /// Fixed fields and elements of a Management frame body — 9.3.3.
    fn push_management(&mut self, subtype: u8, pos: usize, fixed: usize, end: usize) {
        let mut p = pos;
        let elements = match subtype {
            MGMT_BEACON | MGMT_PROBE_RESP | MGMT_TIMING_ADVERTISEMENT => {
                let d = self.data;
                let mut ts = [0u8; 8];
                ts.copy_from_slice(&d[p..p + 8]);
                self.push(FD_TIMESTAMP, FieldValue::U64(u64::from_le_bytes(ts)), p, 8);
                p += 8;
                if subtype != MGMT_TIMING_ADVERTISEMENT {
                    self.push_u16(FD_BEACON_INTERVAL, p);
                    p += 2;
                }
                self.push_u16(FD_CAPABILITY_INFO, p);
                true
            }
            MGMT_ASSOC_REQ | MGMT_REASSOC_REQ => {
                self.push_u16(FD_CAPABILITY_INFO, p);
                self.push_u16(FD_LISTEN_INTERVAL, p + 2);
                if subtype == MGMT_REASSOC_REQ {
                    self.push_addr(FD_CURRENT_AP, p + 4);
                }
                true
            }
            MGMT_ASSOC_RESP | MGMT_REASSOC_RESP => {
                self.push_u16(FD_CAPABILITY_INFO, p);
                self.push_u16(FD_STATUS_CODE, p + 2);
                self.push_u16(FD_ASSOCIATION_ID, p + 4);
                true
            }
            MGMT_PROBE_REQ => true,
            MGMT_DISASSOC | MGMT_DEAUTH => {
                self.push_u16(FD_REASON_CODE, p);
                true
            }
            MGMT_AUTH => {
                let algorithm = read_u16(self.data, p);
                self.push_u16(FD_AUTH_ALGORITHM, p);
                self.push_u16(FD_AUTH_SEQ, p + 2);
                self.push_u16(FD_STATUS_CODE, p + 4);
                // Other algorithms (SAE, FILS, …) carry algorithm-specific
                // fields before any elements.
                AUTH_ALGORITHMS_WITH_ELEMENTS.contains(&algorithm)
            }
            MGMT_ACTION | MGMT_ACTION_NO_ACK => {
                let category = self.data[p];
                self.push(FD_CATEGORY, FieldValue::U8(category), p, 1);
                // 9.6 — the Action field follows the category, except for
                // vendor-specific categories where an OUI follows.
                let vendor = matches!(
                    category,
                    CATEGORY_VENDOR_SPECIFIC_PROTECTED | CATEGORY_VENDOR_SPECIFIC
                );
                if !vendor && p + 1 < end {
                    self.push(FD_ACTION_CODE, FieldValue::U8(self.data[p + 1]), p + 1, 1);
                    p += 1;
                }
                self.push_bytes(FD_BODY, p + 1, end);
                return;
            }
            _ => false,
        };
        let body_start = pos + fixed;
        if elements {
            element::push_elements(
                self.buf,
                &FIELD_DESCRIPTORS[FD_ELEMENTS],
                self.data,
                body_start,
                end,
                self.offset,
            );
        } else {
            self.push_bytes(FD_BODY, body_start, end);
        }
    }

    /// A-MSDU subframes — 9.3.2.2.2: DA, SA, Length (big-endian, as in an
    /// IEEE 802.3 frame), MSDU, then padding so that each subframe but the
    /// last is a multiple of 4 octets. Each MSDU is recorded as an embedded
    /// payload dispatched by its LLC header.
    fn push_amsdu(&mut self, start: usize, end: usize) {
        let array = self.buf.begin_container(
            &FIELD_DESCRIPTORS[FD_AMSDU_SUBFRAMES],
            FieldValue::Array(0..0),
            self.offset + start..self.offset + end,
        );
        let mut pos = start;
        while pos + AMSDU_SUBFRAME_HEADER_SIZE <= end {
            let d = self.data;
            let len = usize::from(u16::from_be_bytes([d[pos + 12], d[pos + 13]]));
            let msdu_start = pos + AMSDU_SUBFRAME_HEADER_SIZE;
            let msdu_end = (msdu_start + len).min(end);
            let abs = self.offset + pos;
            let obj = self.buf.begin_container(
                &AMSDU_SUBFRAME,
                FieldValue::Object(0..0),
                abs..self.offset + msdu_end,
            );
            self.buf.push_field(
                &AMSDU_SUBFRAME_FIELDS[AF_DA],
                FieldValue::MacAddr(read_mac(d, pos)),
                abs..abs + ADDR_SIZE,
            );
            self.buf.push_field(
                &AMSDU_SUBFRAME_FIELDS[AF_SA],
                FieldValue::MacAddr(read_mac(d, pos + ADDR_SIZE)),
                abs + ADDR_SIZE..abs + 2 * ADDR_SIZE,
            );
            self.buf.push_field(
                &AMSDU_SUBFRAME_FIELDS[AF_LENGTH],
                FieldValue::U16(len as u16),
                abs + 12..abs + AMSDU_SUBFRAME_HEADER_SIZE,
            );
            if let Ok(llc) = LlcHeader::parse(&d[msdu_start..msdu_end]) {
                let llc_fields = [
                    &AMSDU_SUBFRAME_FIELDS[AF_LLC_DSAP],
                    &AMSDU_SUBFRAME_FIELDS[AF_LLC_DSAP + 1],
                    &AMSDU_SUBFRAME_FIELDS[AF_LLC_DSAP + 2],
                    &AMSDU_SUBFRAME_FIELDS[AF_LLC_DSAP + 3],
                ];
                llc.push_fields(self.buf, llc_fields, self.offset + msdu_start);
                let payload_start = msdu_start + llc.header_len();
                if payload_start < msdu_end {
                    self.buf.push_embedded_payload(
                        self.offset + payload_start..self.offset + msdu_end,
                        llc.next_hint(),
                    );
                }
            }
            self.buf.end_container(obj);
            let subframe_len = AMSDU_SUBFRAME_HEADER_SIZE + len;
            pos += subframe_len.next_multiple_of(4);
        }
        self.buf.end_container(array);
    }
}

/// IEEE 802.11 MAC frame dissector.
pub struct Ieee80211Dissector;

impl Dissector for Ieee80211Dissector {
    fn name(&self) -> &'static str {
        "IEEE 802.11 Wireless LAN"
    }

    fn short_name(&self) -> &'static str {
        "IEEE802.11"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Link)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        let rt_flags = radiotap_flags(buf, offset);
        let fcs_len = if rt_flags & RADIOTAP_FLAG_FCS != 0 {
            FCS_SIZE
        } else {
            0
        };
        // Octets of the MPDU before the FCS.
        let end = data.len().saturating_sub(fcs_len);
        let need = |len: usize| {
            if len > end {
                Err(PacketError::Truncated {
                    expected: len + fcs_len,
                    actual: data.len(),
                })
            } else {
                Ok(())
            }
        };

        need(2)?;
        let fc = FrameControl::parse(read_u16(data, 0));

        // Only protocol version 0 is decoded past Frame Control (PV1 frames
        // of IEEE 802.11ah use a different header).
        let (header_len, body) = if fc.version != 0 {
            (2, Body::Raw)
        } else {
            let mac_len = mac_header_len(&fc);
            need(mac_len)?;
            let mut header_len = mac_len;
            let has_payload = matches!(fc.frame_type, TYPE_MANAGEMENT | TYPE_DATA);
            // Radiotap "data pad": the payload starts at a 32-bit boundary.
            if has_payload && rt_flags & RADIOTAP_FLAG_DATA_PAD != 0 {
                header_len = header_len.next_multiple_of(4).min(end);
            }
            let body = if header_len == end {
                Body::None
            } else if has_payload && fc.flag(FLAG_PROTECTED) {
                need(header_len + WEP_HEADER_SIZE)?;
                if data[header_len + 3] & KEY_ID_OCTET_EXT_IV != 0 {
                    need(header_len + EXT_IV_HEADER_SIZE)?;
                    Body::Protected {
                        header_len: EXT_IV_HEADER_SIZE,
                    }
                } else {
                    Body::Protected {
                        header_len: WEP_HEADER_SIZE,
                    }
                }
            } else if fc.frame_type == TYPE_MANAGEMENT {
                let fixed = management_fixed_len(fc.subtype);
                need(header_len + fixed)?;
                Body::Management { fixed }
            } else if fc.frame_type == TYPE_DATA && fc.subtype & DATA_SUBTYPE_NO_DATA == 0 {
                let qos_pos = mac_len
                    - QOS_CONTROL_SIZE
                    - if fc.flag(FLAG_ORDER) {
                        HT_CONTROL_SIZE
                    } else {
                        0
                    };
                if fc.is_qos_data() && read_u16(data, qos_pos) & QOS_AMSDU_PRESENT != 0 {
                    Body::Amsdu
                } else {
                    // A body too short for an LLC header (e.g. cut by the
                    // snapshot length) is kept as raw bytes.
                    match LlcHeader::parse_at(data, header_len, end) {
                        Ok(llc) => Body::Llc(llc),
                        Err(_) => Body::Raw,
                    }
                }
            } else {
                Body::Raw
            };
            (header_len, body)
        };

        let consumed = match &body {
            Body::Llc(llc) => header_len + llc.header_len(),
            _ => data.len(),
        };
        buf.begin_layer(
            self.short_name(),
            None,
            &FIELD_DESCRIPTORS,
            offset..offset + consumed,
        );
        let mut frame = Frame { data, buf, offset };
        frame.push_frame_control(&fc);
        if fc.version == 0 {
            frame.push_mac_header(&fc, matches!(body, Body::Amsdu));
        }
        let mut result = DissectResult::new(consumed, DispatchHint::End);
        match body {
            Body::None => {}
            Body::Protected { header_len: len } => frame.push_protected(header_len, len, end),
            Body::Management { fixed } => frame.push_management(fc.subtype, header_len, fixed, end),
            Body::Llc(llc) => {
                llc.push_fields(
                    frame.buf,
                    [
                        &FIELD_DESCRIPTORS[FD_LLC_DSAP],
                        &FIELD_DESCRIPTORS[FD_LLC_SSAP],
                        &FIELD_DESCRIPTORS[FD_LLC_CONTROL],
                        &FIELD_DESCRIPTORS[FD_LLC_CONTROL_EXT],
                    ],
                    offset + header_len,
                );
                result =
                    DissectResult::new(consumed, llc.next_hint()).with_payload_len(end - consumed);
            }
            Body::Amsdu => frame.push_amsdu(header_len, end),
            Body::Raw => frame.push_bytes(FD_BODY, header_len, end),
        }
        if fcs_len > 0 {
            let fcs = u32::from_le_bytes([data[end], data[end + 1], data[end + 2], data[end + 3]]);
            frame.push(FD_FCS, FieldValue::U32(fcs), end, FCS_SIZE);
        }
        frame.buf.end_layer();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    //! # IEEE Std 802.11-2020 Coverage
    //!
    //! | Clause                    | Description                                      | Test                                  |
    //! |---------------------------|--------------------------------------------------|---------------------------------------|
    //! | 9.2.4.1                   | Frame Control truncated                          | truncated_frame_control               |
    //! | 9.2.4.1                   | Protocol version ≠ 0: Frame Control only         | protocol_version_1_frame_control_only |
    //! | 9.2.4.1.3, Table 9-1      | Type / subtype names                             | type_and_subtype_names                |
    //! | 9.3.2.1, 9.2.4.5          | QoS Data, To DS, LLC/SNAP dispatch               | qos_data_to_ds_llc_snap               |
    //! | 9.3.2.1, Table 9-30       | Four-address (WDS) data frame                    | four_address_data_frame               |
    //! | 9.3.2.1, Table 9-30       | From DS data frame, non-QoS                      | from_ds_data_frame                    |
    //! | 9.3.2.1, 9.2.4.6          | QoS Data with +HTC (HT Control)                  | qos_data_with_ht_control              |
    //! | 9.3.2.1                   | Null / QoS Null (no frame body)                  | null_data_frames                      |
    //! | 9.3.2.2.2                 | A-MSDU subframes with padding                    | amsdu_subframes                       |
    //! | 12.5.3.2                  | Protected data: CCMP header, opaque body         | protected_data_ccmp                   |
    //! | 12.3.2.2                  | Protected data: WEP header                       | protected_data_wep                    |
    //! | 9.3.3.3                   | Beacon: fixed fields, SSID/Rates/DS/RSN/vendor   | beacon_with_ssid_and_rsn              |
    //! | 9.3.3.2                   | Management +HTC (HT Control)                     | management_with_ht_control            |
    //! | 9.3.3.5-9.3.3.11          | Assoc/Reassoc Req/Resp, Probe Req, Timing Adv.   | association_and_probe_frames          |
    //! | 9.3.3.12                  | Authentication: Open System elements, SAE raw    | authentication_frames                 |
    //! | 9.3.3.8, 9.3.3.13         | Disassociation / Deauthentication reason         | deauthentication_reason               |
    //! | 9.3.3.14, 9.6             | Action and vendor-specific Action                | action_frames                         |
    //! | 9.3.3.4                   | ATIM (empty body)                                | atim_frame                            |
    //! | 9.3.1.2-9.3.1.9           | RTS / CTS / Ack / Block Ack / Control Wrapper    | control_frames                        |
    //! | 9.3.4                     | Extension frame kept as body                     | extension_frame                       |
    //! | 9.4.2.1                   | Element ID Extension, truncated element          | element_extension_and_truncation      |
    //! | 9.4.2.24                  | RSNE truncated at field boundaries               | rsn_truncated                         |
    //! | 9.2.4.8, radiotap Flags   | FCS at end (radiotap flag 0x10)                  | radiotap_fcs_flag                     |
    //! | radiotap Flags            | Data padding (radiotap flag 0x20)                | radiotap_data_pad_flag                |
    //! | radiotap Flags            | Flags of a further namespace are not applied     | radiotap_flags_in_further_namespace_ignored |
    //! | 9.3.2.1                   | Body shorter than an LLC header kept raw         | data_body_shorter_than_llc_is_raw     |
    //! | 9.3                       | Truncated MAC header / fixed fields / security   | truncated_frames                      |

    use super::*;

    const BSSID: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const STA: [u8; 6] = [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB];
    const DST: [u8; 6] = [0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01];
    const SRC4: [u8; 6] = [0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

    /// MAC header of a frame with three addresses and Sequence Control
    /// (fragment 0, sequence 0x123).
    fn header(
        frame_type: u8,
        subtype: u8,
        flags: u8,
        a1: [u8; 6],
        a2: [u8; 6],
        a3: [u8; 6],
    ) -> Vec<u8> {
        let mut f = vec![(subtype << 4) | (frame_type << 2), flags, 0x3A, 0x01];
        f.extend_from_slice(&a1);
        f.extend_from_slice(&a2);
        f.extend_from_slice(&a3);
        f.extend_from_slice(&0x1230u16.to_le_bytes());
        f
    }

    fn dissect(data: &[u8]) -> (DissectBuffer<'_>, DissectResult) {
        let mut buf = DissectBuffer::new();
        let result = Ieee80211Dissector.dissect(data, &mut buf, 0).unwrap();
        (buf, result)
    }

    /// Fields of `fields` that are not children of a container in it.
    fn top_level<'a>(fields: &'a [Field<'a>]) -> Vec<&'a Field<'a>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < fields.len() {
            out.push(&fields[i]);
            i += match fields[i].value.as_container_range() {
                Some(r) => (r.end - r.start) as usize + 1,
                None => 1,
            };
        }
        out
    }

    fn field<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> Option<&'a Field<'a>> {
        let layer = buf
            .layers()
            .iter()
            .find(|l| l.name == "IEEE802.11")
            .unwrap();
        top_level(buf.layer_fields(layer))
            .into_iter()
            .find(|f| f.name() == name)
    }

    fn value<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> Option<&'a FieldValue<'a>> {
        field(buf, name).map(|f| &f.value)
    }

    fn mac(a: [u8; 6]) -> FieldValue<'static> {
        FieldValue::MacAddr(MacAddr(a))
    }

    /// Elements of the Array field `name`, each as its children.
    fn items<'a>(
        buf: &'a DissectBuffer<'_>,
        fields: &'a [Field<'a>],
        name: &str,
    ) -> Vec<&'a [Field<'a>]> {
        let f = top_level(fields)
            .into_iter()
            .find(|f| f.name() == name)
            .unwrap();
        let FieldValue::Array(range) = &f.value else {
            panic!("{name} is not an array");
        };
        top_level(buf.nested_fields(range))
            .into_iter()
            .map(|f| match &f.value {
                FieldValue::Object(r) => buf.nested_fields(r),
                _ => core::slice::from_ref(f),
            })
            .collect()
    }

    fn layer_items<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> Vec<&'a [Field<'a>]> {
        items(buf, buf.layer_fields(&buf.layers()[0]), name)
    }

    fn child<'a>(fields: &'a [Field<'a>], name: &str) -> Option<&'a FieldValue<'a>> {
        top_level(fields)
            .into_iter()
            .find(|f| f.name() == name)
            .map(|f| &f.value)
    }

    #[test]
    fn truncated_frame_control() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            Ieee80211Dissector.dissect(&[0x80], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 2,
                actual: 1
            })
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn protocol_version_1_frame_control_only() {
        let data = [0x01, 0x00, 0xAA, 0xBB];
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(value(&buf, "protocol_version"), Some(&FieldValue::U8(1)));
        assert!(value(&buf, "duration").is_none());
        assert_eq!(value(&buf, "body"), Some(&FieldValue::Bytes(&[0xAA, 0xBB])));
    }

    #[test]
    fn type_and_subtype_names() {
        let data = header(
            TYPE_MANAGEMENT,
            MGMT_PROBE_REQ,
            0,
            [0xFF; 6],
            STA,
            [0xFF; 6],
        );
        let (buf, _) = dissect(&data);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "type_name"),
            Some("Management")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "subtype_name"),
            Some("Probe Request")
        );
        for (t, s, name) in [
            (TYPE_CONTROL, 11, "RTS"),
            (TYPE_CONTROL, 2, "Trigger"),
            (TYPE_DATA, 8, "QoS Data"),
            (TYPE_DATA, 12, "QoS Null"),
            (TYPE_EXTENSION, 0, "DMG Beacon"),
        ] {
            assert_eq!(subtype_name(t, s), Some(name));
        }
        assert_eq!(subtype_name(TYPE_DATA, 13), None);
        assert_eq!(subtype_name(TYPE_MANAGEMENT, 7), None);
        assert_eq!(frame_type_name(TYPE_EXTENSION), Some("Extension"));
        assert_eq!(frame_type_name(4), None);
        assert_eq!(auth_algorithm_name(3), Some("SAE"));
        assert_eq!(auth_algorithm_name(9), None);
        assert_eq!(
            category_name(CATEGORY_VENDOR_SPECIFIC),
            Some("Vendor-specific")
        );
        assert_eq!(category_name(17), None);
    }

    #[test]
    fn qos_data_to_ds_llc_snap() {
        // To DS: Address 1 = BSSID, Address 2 = SA, Address 3 = DA.
        let mut data = header(TYPE_DATA, 8, FLAG_TO_DS, BSSID, STA, DST);
        data.extend_from_slice(&[0x05, 0x00]); // QoS Control: TID 5
        data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
        data.extend_from_slice(&[0x45; 20]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 29);
        assert_eq!(result.next, DispatchHint::ByLlcSap(0xAA));
        assert_eq!(result.payload_len, Some(data.len() - 29));
        assert_eq!(buf.layers()[0].range, 0..29);
        assert_eq!(value(&buf, "type"), Some(&FieldValue::U8(TYPE_DATA)));
        assert_eq!(value(&buf, "subtype"), Some(&FieldValue::U8(8)));
        assert_eq!(value(&buf, "to_ds"), Some(&FieldValue::U8(1)));
        assert_eq!(value(&buf, "from_ds"), Some(&FieldValue::U8(0)));
        assert_eq!(value(&buf, "duration"), Some(&FieldValue::U16(0x013A)));
        assert_eq!(value(&buf, "addr1"), Some(&mac(BSSID)));
        assert_eq!(value(&buf, "bssid"), Some(&mac(BSSID)));
        assert_eq!(value(&buf, "sa"), Some(&mac(STA)));
        assert_eq!(value(&buf, "da"), Some(&mac(DST)));
        assert_eq!(field(&buf, "da").unwrap().range, 16..22);
        assert_eq!(value(&buf, "fragment_number"), Some(&FieldValue::U8(0)));
        assert_eq!(
            value(&buf, "sequence_number"),
            Some(&FieldValue::U16(0x123))
        );
        assert_eq!(value(&buf, "qos_tid"), Some(&FieldValue::U8(5)));
        assert_eq!(value(&buf, "qos_amsdu_present"), Some(&FieldValue::U8(0)));
        assert_eq!(value(&buf, "llc_dsap"), Some(&FieldValue::U8(0xAA)));
        assert_eq!(value(&buf, "llc_control"), Some(&FieldValue::U8(0x03)));
        assert!(value(&buf, "addr4").is_none());
        assert!(value(&buf, "ht_control").is_none());
        assert!(value(&buf, "fcs").is_none());
    }

    #[test]
    fn four_address_data_frame() {
        let mut data = header(TYPE_DATA, 0, FLAG_TO_DS | FLAG_FROM_DS, BSSID, STA, DST);
        data.extend_from_slice(&SRC4);
        data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x86, 0xDD]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 33);
        assert_eq!(value(&buf, "addr4"), Some(&mac(SRC4)));
        assert_eq!(value(&buf, "da"), Some(&mac(DST)));
        assert_eq!(value(&buf, "sa"), Some(&mac(SRC4)));
        assert!(value(&buf, "bssid").is_none());
        assert!(value(&buf, "qos_control").is_none());
    }

    #[test]
    fn from_ds_data_frame() {
        // From DS: Address 1 = DA, Address 2 = BSSID, Address 3 = SA.
        let mut data = header(TYPE_DATA, 0, FLAG_FROM_DS | FLAG_ORDER, DST, BSSID, STA);
        data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 27);
        assert_eq!(value(&buf, "da"), Some(&mac(DST)));
        assert_eq!(value(&buf, "bssid"), Some(&mac(BSSID)));
        assert_eq!(value(&buf, "sa"), Some(&mac(STA)));
        // Order in a non-QoS Data frame does not add HT Control.
        assert_eq!(value(&buf, "order"), Some(&FieldValue::U8(1)));
        assert!(value(&buf, "ht_control").is_none());

        // To DS = From DS = 0: Address 1 = DA, 2 = SA, 3 = BSSID.
        let mut data = header(TYPE_DATA, 0, 0, DST, STA, BSSID);
        data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06]);
        let (buf, _) = dissect(&data);
        assert_eq!(value(&buf, "da"), Some(&mac(DST)));
        assert_eq!(value(&buf, "sa"), Some(&mac(STA)));
        assert_eq!(value(&buf, "bssid"), Some(&mac(BSSID)));
    }

    #[test]
    fn qos_data_with_ht_control() {
        let mut data = header(TYPE_DATA, 8, FLAG_TO_DS | FLAG_ORDER, BSSID, STA, DST);
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 33);
        assert_eq!(
            value(&buf, "ht_control"),
            Some(&FieldValue::U32(0x1234_5678))
        );
        assert_eq!(field(&buf, "ht_control").unwrap().range, 26..30);
    }

    #[test]
    fn null_data_frames() {
        let data = header(
            TYPE_DATA,
            4,
            FLAG_TO_DS | FLAG_POWER_MANAGEMENT,
            BSSID,
            STA,
            BSSID,
        );
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 24);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(value(&buf, "power_management"), Some(&FieldValue::U8(1)));
        assert!(value(&buf, "body").is_none());

        // QoS Null followed by stray octets: kept as body, not LLC.
        let mut data = header(TYPE_DATA, 12, FLAG_TO_DS, BSSID, STA, BSSID);
        data.extend_from_slice(&[0x07, 0x00, 0xDE, 0xAD]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(value(&buf, "qos_tid"), Some(&FieldValue::U8(7)));
        assert_eq!(value(&buf, "body"), Some(&FieldValue::Bytes(&[0xDE, 0xAD])));
        assert!(value(&buf, "llc_dsap").is_none());
    }

    #[test]
    fn amsdu_subframes() {
        let mut data = header(TYPE_DATA, 8, FLAG_FROM_DS, DST, BSSID, BSSID);
        data.extend_from_slice(&[0x80, 0x00]); // QoS Control: A-MSDU Present
        let body_start = data.len();
        // Subframe 1: 14 + 10 = 24 octets, already a multiple of 4.
        data.extend_from_slice(&DST);
        data.extend_from_slice(&STA);
        data.extend_from_slice(&10u16.to_be_bytes());
        data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00]);
        // Subframe 2: 14 + 9 = 23 octets → 1 padding octet before subframe 3.
        data.extend_from_slice(&DST);
        data.extend_from_slice(&SRC4);
        data.extend_from_slice(&9u16.to_be_bytes());
        data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x86, 0xDD, 0x60]);
        data.push(0x00);
        // Subframe 3: MSDU shorter than an LLC header, no payload recorded.
        data.extend_from_slice(&DST);
        data.extend_from_slice(&SRC4);
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(&[0xAA, 0xAA]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(value(&buf, "bssid"), Some(&mac(BSSID)));
        assert!(value(&buf, "da").is_none());
        assert!(value(&buf, "sa").is_none());
        let subframes = layer_items(&buf, "amsdu_subframes");
        assert_eq!(subframes.len(), 3);
        assert_eq!(child(subframes[0], "sa"), Some(&mac(STA)));
        assert_eq!(child(subframes[0], "length"), Some(&FieldValue::U16(10)));
        assert_eq!(child(subframes[0], "llc_dsap"), Some(&FieldValue::U8(0xAA)));
        assert_eq!(child(subframes[1], "sa"), Some(&mac(SRC4)));
        assert!(child(subframes[2], "llc_dsap").is_none());
        let payloads = buf.embedded_payloads();
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0].range, body_start + 17..body_start + 24);
        assert_eq!(payloads[0].next, DispatchHint::ByLlcSap(0xAA));
        assert_eq!(payloads[1].range, body_start + 41..body_start + 47);
    }

    #[test]
    fn data_body_shorter_than_llc_is_raw() {
        let mut data = header(TYPE_DATA, 0, 0, BSSID, STA, DST);
        data.extend_from_slice(&[0xAA, 0xAA]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(result.bytes_consumed, 26);
        assert_eq!(value(&buf, "body"), Some(&FieldValue::Bytes(&[0xAA, 0xAA])));
        assert!(value(&buf, "llc_dsap").is_none());
    }

    #[test]
    fn protected_data_ccmp() {
        let mut data = header(TYPE_DATA, 8, FLAG_TO_DS | FLAG_PROTECTED, BSSID, STA, DST);
        data.extend_from_slice(&[0x00, 0x00]);
        // PN0, PN1, reserved, Key ID octet (Ext IV, key 1), PN2..PN5.
        data.extend_from_slice(&[0x01, 0x02, 0x00, 0x60, 0x03, 0x04, 0x05, 0x06]);
        data.extend_from_slice(&[0xEE; 12]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(value(&buf, "protected"), Some(&FieldValue::U8(1)));
        assert_eq!(value(&buf, "pn"), Some(&FieldValue::U64(0x0605_0403_0201)));
        assert_eq!(value(&buf, "ext_iv"), Some(&FieldValue::U8(1)));
        assert_eq!(value(&buf, "key_id"), Some(&FieldValue::U8(1)));
        assert_eq!(
            value(&buf, "encrypted_data"),
            Some(&FieldValue::Bytes(&[0xEE; 12]))
        );
        assert!(value(&buf, "llc_dsap").is_none());
        assert!(value(&buf, "wep_iv").is_none());
    }

    #[test]
    fn protected_data_wep() {
        let mut data = header(TYPE_DATA, 0, FLAG_TO_DS | FLAG_PROTECTED, BSSID, STA, DST);
        data.extend_from_slice(&[0x11, 0x22, 0x33, 0x80, 0xEE, 0xEE]);
        let (buf, _) = dissect(&data);
        assert_eq!(
            value(&buf, "wep_iv"),
            Some(&FieldValue::Bytes(&[0x11, 0x22, 0x33]))
        );
        assert_eq!(value(&buf, "ext_iv"), Some(&FieldValue::U8(0)));
        assert_eq!(value(&buf, "key_id"), Some(&FieldValue::U8(2)));
        assert_eq!(
            value(&buf, "encrypted_data"),
            Some(&FieldValue::Bytes(&[0xEE, 0xEE]))
        );
        assert!(value(&buf, "pn").is_none());
    }

    /// RSN element: version 1, group CCMP-128, pairwise CCMP-128, AKM PSK,
    /// capabilities 0x000C, one PMKID, group management BIP-CMAC-128.
    fn rsn_element() -> Vec<u8> {
        let mut info = vec![0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04];
        info.extend_from_slice(&[0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04]);
        info.extend_from_slice(&[0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02]);
        info.extend_from_slice(&[0x0C, 0x00]);
        info.extend_from_slice(&[0x01, 0x00]);
        info.extend_from_slice(&[0x5A; 16]);
        info.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x06]);
        let mut e = vec![48, info.len() as u8];
        e.extend_from_slice(&info);
        e
    }

    #[test]
    fn beacon_with_ssid_and_rsn() {
        let mut data = header(TYPE_MANAGEMENT, MGMT_BEACON, 0, [0xFF; 6], BSSID, BSSID);
        data.extend_from_slice(&0x0000_0001_0203_0405u64.to_le_bytes());
        data.extend_from_slice(&100u16.to_le_bytes());
        data.extend_from_slice(&0x0431u16.to_le_bytes());
        data.extend_from_slice(&[0, 4, b't', b'e', b's', b't']);
        data.extend_from_slice(&[1, 4, 0x82, 0x84, 0x8B, 0x96]);
        data.extend_from_slice(&[3, 1, 6]);
        data.extend_from_slice(&rsn_element());
        data.extend_from_slice(&[50, 2, 0x0C, 0x12]);
        data.extend_from_slice(&[221, 5, 0x00, 0x50, 0xF2, 0x02, 0x01]);
        data.extend_from_slice(&[5, 2, 0x00, 0x01]); // TIM kept as data
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(value(&buf, "da"), Some(&mac([0xFF; 6])));
        assert_eq!(value(&buf, "bssid"), Some(&mac(BSSID)));
        assert_eq!(
            value(&buf, "timestamp"),
            Some(&FieldValue::U64(0x0000_0001_0203_0405))
        );
        assert_eq!(value(&buf, "beacon_interval"), Some(&FieldValue::U16(100)));
        assert_eq!(
            value(&buf, "capability_info"),
            Some(&FieldValue::U16(0x0431))
        );
        let elements = layer_items(&buf, "elements");
        assert_eq!(elements.len(), 7);
        assert_eq!(child(elements[0], "id"), Some(&FieldValue::U8(0)));
        assert_eq!(
            child(elements[0], "ssid"),
            Some(&FieldValue::Bytes(b"test"))
        );
        let rates = items(&buf, elements[1], "rates");
        assert_eq!(rates.len(), 4);
        assert_eq!(rates[0][0].value, FieldValue::U8(0x82));
        assert_eq!(
            child(elements[2], "current_channel"),
            Some(&FieldValue::U8(6))
        );
        let rsn = elements[3];
        assert_eq!(child(rsn, "rsn_version"), Some(&FieldValue::U16(1)));
        assert_eq!(
            child(rsn, "group_cipher"),
            Some(&FieldValue::U32(0x000F_AC04))
        );
        assert_eq!(child(rsn, "pairwise_count"), Some(&FieldValue::U16(1)));
        let pairwise = items(&buf, rsn, "pairwise_ciphers");
        assert_eq!(pairwise[0][0].value, FieldValue::U32(0x000F_AC04));
        let akm = items(&buf, rsn, "akm_suites");
        assert_eq!(akm[0][0].value, FieldValue::U32(0x000F_AC02));
        assert_eq!(
            child(rsn, "rsn_capabilities"),
            Some(&FieldValue::U16(0x000C))
        );
        assert_eq!(child(rsn, "pmkid_count"), Some(&FieldValue::U16(1)));
        assert_eq!(
            items(&buf, rsn, "pmkids")[0][0].value,
            FieldValue::Bytes(&[0x5A; 16])
        );
        assert_eq!(
            child(rsn, "group_mgmt_cipher"),
            Some(&FieldValue::U32(0x000F_AC06))
        );
        assert!(child(rsn, "data").is_none());
        assert_eq!(items(&buf, elements[4], "rates").len(), 2);
        assert_eq!(
            child(elements[5], "vendor_oui"),
            Some(&FieldValue::U32(0x0000_50F2))
        );
        assert_eq!(
            child(elements[5], "data"),
            Some(&FieldValue::Bytes(&[0x02, 0x01]))
        );
        assert_eq!(
            child(elements[6], "data"),
            Some(&FieldValue::Bytes(&[0x00, 0x01]))
        );

        // Display names resolve through the descriptors.
        let id_fd = &element::ELEMENT_FIELDS[0];
        let display = id_fd.display_fn.unwrap();
        assert_eq!(display(&FieldValue::U8(48), &[]), Some("RSN"));
        assert_eq!(element::cipher_suite_name(0x000F_AC04), Some("CCMP-128"));
        assert_eq!(element::cipher_suite_name(0x0050_F204), None);
        assert_eq!(element::cipher_suite_name(0x000F_AC03), None);
        assert_eq!(element::akm_suite_name(0x000F_AC08), Some("SAE"));
        assert_eq!(element::akm_suite_name(0x000F_AC63), None);
        assert_eq!(element::akm_suite_name(0x0050_F202), None);
        assert_eq!(element::element_name(2), None);
    }

    #[test]
    fn management_with_ht_control() {
        let mut data = header(
            TYPE_MANAGEMENT,
            MGMT_ACTION_NO_ACK,
            FLAG_ORDER,
            BSSID,
            STA,
            BSSID,
        );
        data.extend_from_slice(&0x0000_0003u32.to_le_bytes());
        data.extend_from_slice(&[21, 2, 0xAB]); // VHT category, action 2
        let (buf, _) = dissect(&data);
        assert_eq!(value(&buf, "ht_control"), Some(&FieldValue::U32(3)));
        assert_eq!(value(&buf, "category"), Some(&FieldValue::U8(21)));
        assert_eq!(field(&buf, "category").unwrap().range, 28..29);
        assert_eq!(value(&buf, "action_code"), Some(&FieldValue::U8(2)));
        assert_eq!(value(&buf, "body"), Some(&FieldValue::Bytes(&[0xAB])));
    }

    #[test]
    fn association_and_probe_frames() {
        let mut data = header(TYPE_MANAGEMENT, MGMT_ASSOC_REQ, 0, BSSID, STA, BSSID);
        data.extend_from_slice(&[0x31, 0x04, 0x0A, 0x00, 0, 2, b'a', b'p']);
        let (buf, _) = dissect(&data);
        assert_eq!(
            value(&buf, "capability_info"),
            Some(&FieldValue::U16(0x0431))
        );
        assert_eq!(value(&buf, "listen_interval"), Some(&FieldValue::U16(10)));
        assert_eq!(layer_items(&buf, "elements").len(), 1);

        let mut data = header(TYPE_MANAGEMENT, MGMT_REASSOC_REQ, 0, BSSID, STA, BSSID);
        data.extend_from_slice(&[0x31, 0x04, 0x0A, 0x00]);
        data.extend_from_slice(&DST);
        let (buf, _) = dissect(&data);
        assert_eq!(value(&buf, "current_ap"), Some(&mac(DST)));
        assert!(layer_items(&buf, "elements").is_empty());

        for subtype in [MGMT_ASSOC_RESP, MGMT_REASSOC_RESP] {
            let mut data = header(TYPE_MANAGEMENT, subtype, 0, STA, BSSID, BSSID);
            data.extend_from_slice(&[0x31, 0x04, 0x00, 0x00, 0x01, 0xC0]);
            let (buf, _) = dissect(&data);
            assert_eq!(value(&buf, "status_code"), Some(&FieldValue::U16(0)));
            assert_eq!(
                value(&buf, "association_id"),
                Some(&FieldValue::U16(0xC001))
            );
        }

        let mut data = header(
            TYPE_MANAGEMENT,
            MGMT_PROBE_REQ,
            0,
            [0xFF; 6],
            STA,
            [0xFF; 6],
        );
        data.extend_from_slice(&[0, 0]); // wildcard SSID
        let (buf, _) = dissect(&data);
        let elements = layer_items(&buf, "elements");
        assert_eq!(child(elements[0], "ssid"), Some(&FieldValue::Bytes(&[])));

        let mut data = header(TYPE_MANAGEMENT, MGMT_PROBE_RESP, 0, STA, BSSID, BSSID);
        data.extend_from_slice(&[0; 12]);
        let (buf, _) = dissect(&data);
        assert_eq!(value(&buf, "beacon_interval"), Some(&FieldValue::U16(0)));

        let mut data = header(
            TYPE_MANAGEMENT,
            MGMT_TIMING_ADVERTISEMENT,
            0,
            STA,
            BSSID,
            BSSID,
        );
        data.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00]);
        let (buf, _) = dissect(&data);
        assert_eq!(value(&buf, "timestamp"), Some(&FieldValue::U64(1)));
        assert!(value(&buf, "beacon_interval").is_none());
        assert_eq!(field(&buf, "capability_info").unwrap().range, 32..34);
    }

    #[test]
    fn authentication_frames() {
        let mut data = header(TYPE_MANAGEMENT, MGMT_AUTH, 0, BSSID, STA, BSSID);
        data.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[221, 3, 0x00, 0x10, 0x18]);
        let (buf, _) = dissect(&data);
        assert_eq!(value(&buf, "auth_algorithm"), Some(&FieldValue::U16(0)));
        assert_eq!(value(&buf, "auth_seq"), Some(&FieldValue::U16(1)));
        assert_eq!(value(&buf, "status_code"), Some(&FieldValue::U16(0)));
        let elements = layer_items(&buf, "elements");
        assert_eq!(
            child(elements[0], "vendor_oui"),
            Some(&FieldValue::U32(0x0000_1018))
        );
        assert!(child(elements[0], "data").is_none());

        // SAE commit: group and scalar are not elements.
        let mut data = header(TYPE_MANAGEMENT, MGMT_AUTH, 0, BSSID, STA, BSSID);
        data.extend_from_slice(&[0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x00]);
        let (buf, _) = dissect(&data);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "auth_algorithm_name"),
            Some("SAE")
        );
        assert_eq!(value(&buf, "body"), Some(&FieldValue::Bytes(&[0x13, 0x00])));
        assert!(value(&buf, "elements").is_none());
    }

    #[test]
    fn deauthentication_reason() {
        for subtype in [MGMT_DEAUTH, MGMT_DISASSOC] {
            let mut data = header(TYPE_MANAGEMENT, subtype, 0, STA, BSSID, BSSID);
            data.extend_from_slice(&[0x07, 0x00]);
            let (buf, _) = dissect(&data);
            assert_eq!(value(&buf, "reason_code"), Some(&FieldValue::U16(7)));
        }
    }

    #[test]
    fn action_frames() {
        let mut data = header(TYPE_MANAGEMENT, MGMT_ACTION, 0, BSSID, STA, BSSID);
        data.extend_from_slice(&[3, 0, 0x01, 0x02]); // Block Ack, ADDBA Request
        let (buf, _) = dissect(&data);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "category_name"),
            Some("Block Ack")
        );
        assert_eq!(value(&buf, "action_code"), Some(&FieldValue::U8(0)));
        assert_eq!(value(&buf, "body"), Some(&FieldValue::Bytes(&[0x01, 0x02])));

        // Vendor-specific: an OUI follows the category, no Action field.
        let mut data = header(TYPE_MANAGEMENT, MGMT_ACTION, 0, BSSID, STA, BSSID);
        data.extend_from_slice(&[127, 0x00, 0x50, 0xF2, 0x09]);
        let (buf, _) = dissect(&data);
        assert!(value(&buf, "action_code").is_none());
        assert_eq!(
            value(&buf, "body"),
            Some(&FieldValue::Bytes(&[0x00, 0x50, 0xF2, 0x09]))
        );

        // Category only.
        let mut data = header(TYPE_MANAGEMENT, MGMT_ACTION, 0, BSSID, STA, BSSID);
        data.push(4);
        let (buf, _) = dissect(&data);
        assert!(value(&buf, "action_code").is_none());
        assert!(value(&buf, "body").is_none());
    }

    #[test]
    fn atim_frame() {
        let data = header(TYPE_MANAGEMENT, 9, 0, STA, BSSID, BSSID);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 24);
        assert!(value(&buf, "elements").is_none());
        assert!(value(&buf, "body").is_none());

        // Reserved management subtype with a body keeps it raw.
        let mut data = header(TYPE_MANAGEMENT, 15, 0, STA, BSSID, BSSID);
        data.push(0x42);
        let (buf, _) = dissect(&data);
        assert_eq!(value(&buf, "body"), Some(&FieldValue::Bytes(&[0x42])));
    }

    #[test]
    fn control_frames() {
        // RTS: RA, TA.
        let mut data = vec![0xB4, 0x00, 0x2C, 0x01];
        data.extend_from_slice(&BSSID);
        data.extend_from_slice(&STA);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 16);
        assert_eq!(value(&buf, "addr1"), Some(&mac(BSSID)));
        assert_eq!(value(&buf, "addr2"), Some(&mac(STA)));
        assert!(value(&buf, "sequence_number").is_none());
        assert!(value(&buf, "bssid").is_none());

        // CTS and Ack: RA only.
        for first in [0xC4, 0xD4] {
            let mut data = vec![first, 0x00, 0x00, 0x00];
            data.extend_from_slice(&STA);
            let (buf, result) = dissect(&data);
            assert_eq!(result.bytes_consumed, 10);
            assert_eq!(value(&buf, "addr1"), Some(&mac(STA)));
            assert!(value(&buf, "addr2").is_none());
        }

        // Block Ack: RA, TA, then BA Control / Information kept as body.
        let mut data = vec![0x94, 0x00, 0x00, 0x00];
        data.extend_from_slice(&STA);
        data.extend_from_slice(&BSSID);
        data.extend_from_slice(&[0x05, 0x00, 0x10, 0x00]);
        let (buf, _) = dissect(&data);
        assert_eq!(
            value(&buf, "body"),
            Some(&FieldValue::Bytes(&[0x05, 0x00, 0x10, 0x00]))
        );

        // Control Wrapper: RA, Carried Frame Control, HT Control, carried frame.
        let mut data = vec![0x74, 0x00, 0x00, 0x00];
        data.extend_from_slice(&STA);
        data.extend_from_slice(&[0xC4, 0x00]);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&[0xAB]);
        let (buf, _) = dissect(&data);
        assert_eq!(
            value(&buf, "carried_frame_control"),
            Some(&FieldValue::U16(0x00C4))
        );
        assert_eq!(value(&buf, "ht_control"), Some(&FieldValue::U32(1)));
        assert_eq!(value(&buf, "body"), Some(&FieldValue::Bytes(&[0xAB])));

        // Reserved control subtype: Frame Control and Duration only.
        let data = [0x04, 0x00, 0x00, 0x00, 0x01];
        let (buf, _) = dissect(&data);
        assert!(value(&buf, "addr1").is_none());
        assert_eq!(value(&buf, "body"), Some(&FieldValue::Bytes(&[0x01])));
    }

    #[test]
    fn extension_frame() {
        let data = [0x0C, 0x00, 0x00, 0x00, 0x01, 0x02];
        let (buf, result) = dissect(&data);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(value(&buf, "type"), Some(&FieldValue::U8(TYPE_EXTENSION)));
        assert_eq!(value(&buf, "body"), Some(&FieldValue::Bytes(&[0x01, 0x02])));
    }

    #[test]
    fn element_extension_and_truncation() {
        let mut data = header(
            TYPE_MANAGEMENT,
            MGMT_PROBE_REQ,
            0,
            [0xFF; 6],
            STA,
            [0xFF; 6],
        );
        data.extend_from_slice(&[255, 3, 35, 0x01, 0x02]); // HE Capabilities
        data.extend_from_slice(&[255, 0]); // extension element without ID
        data.extend_from_slice(&[3, 2, 1, 2]); // DSSS with bad length → data
        data.extend_from_slice(&[221, 2, 0x00, 0x50]); // vendor without full OUI
        data.extend_from_slice(&[7, 10, 0x55]); // truncated: ends the list
        let (buf, _) = dissect(&data);
        let elements = layer_items(&buf, "elements");
        assert_eq!(elements.len(), 4);
        assert_eq!(child(elements[0], "ext_id"), Some(&FieldValue::U8(35)));
        assert_eq!(
            child(elements[0], "data"),
            Some(&FieldValue::Bytes(&[1, 2]))
        );
        let ext_fd = &element::ELEMENT_FIELDS[2];
        assert_eq!(
            (ext_fd.display_fn.unwrap())(&FieldValue::U8(35), &[]),
            Some("HE Capabilities")
        );
        assert_eq!((ext_fd.display_fn.unwrap())(&FieldValue::U8(1), &[]), None);
        assert!(child(elements[1], "ext_id").is_none());
        assert_eq!(
            child(elements[2], "data"),
            Some(&FieldValue::Bytes(&[1, 2]))
        );
        assert!(child(elements[2], "current_channel").is_none());
        assert_eq!(
            child(elements[3], "data"),
            Some(&FieldValue::Bytes(&[0x00, 0x50]))
        );
    }

    #[test]
    fn rsn_truncated() {
        let full = rsn_element();
        // Cut the information after each field boundary and inside lists.
        for (info_len, last) in [
            (0usize, None),
            (2, Some("rsn_version")),
            (6, Some("group_cipher")),
            (8, Some("pairwise_count")),
            (10, Some("pairwise_count")), // list needs 4 octets
            (12, Some("pairwise_ciphers")),
            (14, Some("akm_count")),
            (18, Some("akm_suites")),
            (20, Some("rsn_capabilities")),
            (22, Some("pmkid_count")),
            (30, Some("pmkid_count")),
            (38, Some("pmkids")),
            (40, Some("pmkids")),
        ] {
            let mut data = header(
                TYPE_MANAGEMENT,
                MGMT_PROBE_REQ,
                0,
                [0xFF; 6],
                STA,
                [0xFF; 6],
            );
            data.extend_from_slice(&[48, info_len as u8]);
            data.extend_from_slice(&full[2..2 + info_len]);
            let (buf, _) = dissect(&data);
            let elements = layer_items(&buf, "elements");
            let names: Vec<_> = top_level(elements[0]).iter().map(|f| f.name()).collect();
            let decoded: Vec<_> = names
                .iter()
                .copied()
                .filter(|n| !matches!(*n, "id" | "length" | "data"))
                .collect();
            assert_eq!(decoded.last().copied(), last, "info_len {info_len}");
            let has_data = names.contains(&"data");
            let decoded_all = matches!(info_len, 0 | 2 | 6 | 8 | 12 | 14 | 18 | 20 | 22 | 38);
            assert_eq!(has_data, !decoded_all, "info_len {info_len}");
        }
    }

    static RT_FLAGS: FieldDescriptor = FieldDescriptor::new("flags", "Flags", FieldType::U8);

    /// Buffer holding a radiotap layer of `len` octets with the given Flags.
    fn radiotap_buf<'a>(flags: u8, len: usize) -> DissectBuffer<'a> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Radiotap", None, core::slice::from_ref(&RT_FLAGS), 0..len);
        buf.push_field(&RT_FLAGS, FieldValue::U8(flags), 0..1);
        buf.end_layer();
        buf
    }

    #[test]
    fn radiotap_fcs_flag() {
        let mut data = header(TYPE_DATA, 0, FLAG_TO_DS, BSSID, STA, DST);
        data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45]);
        data.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let mut buf = radiotap_buf(0x10, 8);
        let result = Ieee80211Dissector.dissect(&data, &mut buf, 8).unwrap();
        assert_eq!(result.bytes_consumed, 27);
        assert_eq!(result.payload_len, Some(6));
        let fcs = field(&buf, "fcs").unwrap();
        assert_eq!(fcs.value, FieldValue::U32(0xDEAD_BEEF));
        assert_eq!(fcs.range, 8 + 33..8 + 37);

        // A beacon with FCS: the elements end before the FCS.
        let mut data = header(TYPE_MANAGEMENT, MGMT_BEACON, 0, [0xFF; 6], BSSID, BSSID);
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&[0, 1, b'x']);
        data.extend_from_slice(&[1, 2, 3, 4]);
        let mut buf = radiotap_buf(0x10, 8);
        Ieee80211Dissector.dissect(&data, &mut buf, 8).unwrap();
        let elements = layer_items_named(&buf, "elements");
        assert_eq!(elements, 1);
        assert_eq!(value(&buf, "fcs"), Some(&FieldValue::U32(0x0403_0201)));

        // Radiotap layer not adjacent (different offset): no FCS.
        let mut buf = radiotap_buf(0x10, 8);
        Ieee80211Dissector.dissect(&data, &mut buf, 20).unwrap();
        assert!(value(&buf, "fcs").is_none());

        // Truncation reports the FCS octets in the expected length.
        let mut buf = radiotap_buf(0x10, 8);
        assert_eq!(
            Ieee80211Dissector.dissect(&data[..20], &mut buf, 8),
            Err(PacketError::Truncated {
                expected: 28,
                actual: 20
            })
        );
        // A body shorter than an LLC header before the FCS stays raw.
        let mut data = header(TYPE_DATA, 0, FLAG_TO_DS, BSSID, STA, DST);
        data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]);
        let mut buf = radiotap_buf(0x10, 8);
        Ieee80211Dissector.dissect(&data, &mut buf, 8).unwrap();
        assert_eq!(value(&buf, "body"), Some(&FieldValue::Bytes(&[0xAA, 0xAA])));
        assert_eq!(value(&buf, "fcs"), Some(&FieldValue::U32(3)));
    }

    static RT_NAMESPACES: FieldDescriptor =
        FieldDescriptor::new("namespaces", "Namespaces", FieldType::Array);

    #[test]
    fn radiotap_flags_in_further_namespace_ignored() {
        // Flags only inside a further namespace element: not applied.
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Radiotap", None, core::slice::from_ref(&RT_FLAGS), 0..8);
        let idx = buf.begin_container(&RT_NAMESPACES, FieldValue::Array(0..0), 4..8);
        buf.push_field(&RT_FLAGS, FieldValue::U8(0x10), 4..5);
        buf.end_container(idx);
        buf.end_layer();
        let data = header(TYPE_MANAGEMENT, 9, 0, STA, BSSID, BSSID);
        Ieee80211Dissector.dissect(&data, &mut buf, 8).unwrap();
        assert!(value(&buf, "fcs").is_none());
        assert_eq!(
            value(&buf, "sequence_number"),
            Some(&FieldValue::U16(0x123))
        );
    }

    fn layer_items_named(buf: &DissectBuffer<'_>, name: &str) -> usize {
        let layer = buf
            .layers()
            .iter()
            .find(|l| l.name == "IEEE802.11")
            .unwrap();
        items(buf, buf.layer_fields(layer), name).len()
    }

    #[test]
    fn radiotap_data_pad_flag() {
        // QoS Data: 26-octet header, padded to 28 before the LLC header.
        let mut data = header(TYPE_DATA, 8, FLAG_TO_DS, BSSID, STA, DST);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
        let mut buf = radiotap_buf(0x20, 8);
        let result = Ieee80211Dissector.dissect(&data, &mut buf, 8).unwrap();
        assert_eq!(result.bytes_consumed, 31);
        assert_eq!(field(&buf, "llc_dsap").unwrap().range, 8 + 28..8 + 29);
    }

    #[test]
    fn truncated_frames() {
        let beacon = header(TYPE_MANAGEMENT, MGMT_BEACON, 0, [0xFF; 6], BSSID, BSSID);
        assert_eq!(
            Ieee80211Dissector.dissect(&beacon[..23], &mut DissectBuffer::new(), 0),
            Err(PacketError::Truncated {
                expected: 24,
                actual: 23
            })
        );
        // Beacon fixed fields need 12 octets.
        let mut data = beacon.clone();
        data.extend_from_slice(&[0; 5]);
        assert_eq!(
            Ieee80211Dissector.dissect(&data, &mut DissectBuffer::new(), 0),
            Err(PacketError::Truncated {
                expected: 36,
                actual: 29
            })
        );
        // Four-address data frame needs Address 4.
        let data = header(TYPE_DATA, 0, FLAG_TO_DS | FLAG_FROM_DS, BSSID, STA, DST);
        assert_eq!(
            Ieee80211Dissector.dissect(&data, &mut DissectBuffer::new(), 0),
            Err(PacketError::Truncated {
                expected: 30,
                actual: 24
            })
        );
        // Protected frame: WEP header, then Ext IV header.
        let mut data = header(TYPE_DATA, 0, FLAG_PROTECTED, BSSID, STA, DST);
        data.extend_from_slice(&[0x01, 0x02]);
        assert_eq!(
            Ieee80211Dissector.dissect(&data, &mut DissectBuffer::new(), 0),
            Err(PacketError::Truncated {
                expected: 28,
                actual: 26
            })
        );
        data.extend_from_slice(&[0x00, 0x20]);
        assert_eq!(
            Ieee80211Dissector.dissect(&data, &mut DissectBuffer::new(), 0),
            Err(PacketError::Truncated {
                expected: 32,
                actual: 28
            })
        );
        // CTS needs Address 1.
        assert_eq!(
            Ieee80211Dissector.dissect(
                &[0xC4, 0x00, 0x00, 0x00, 0x01],
                &mut DissectBuffer::new(),
                0
            ),
            Err(PacketError::Truncated {
                expected: 10,
                actual: 5
            })
        );
    }

    #[test]
    fn dissector_metadata() {
        let d = Ieee80211Dissector;
        assert_eq!(d.name(), "IEEE 802.11 Wireless LAN");
        assert_eq!(d.short_name(), "IEEE802.11");
        assert_eq!(d.layer(), Some(ProtocolLayer::Link));
        assert!(!d.references().is_empty());
        let fds = d.field_descriptors();
        assert_eq!(fds[FD_FCS].name, "fcs");
        assert_eq!(fds[FD_LLC_DSAP].name, "llc_dsap");
        assert_eq!(fds[FD_ELEMENTS].name, "elements");
        let mut names: Vec<_> = fds.iter().map(|f| f.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), fds.len(), "duplicate field names");
    }
}
