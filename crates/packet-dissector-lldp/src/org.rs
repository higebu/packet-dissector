//! Decoders for well-known LLDP Organizationally Specific TLVs (type 127).
//!
//! Each decoder handles one (OUI, subtype) pair with a fixed layout and runs
//! only when the information string has the specified length; anything else
//! keeps just the raw `info` field, so a malformed organizationally specific
//! TLV never aborts the LLDPDU.
//!
//! ## References
//! - IEEE 802.1AB-2005, Annex F (IEEE 802.1 TLVs, subtypes 1–4) and Annex G
//!   (IEEE 802.3 TLVs, subtypes 1–4): <https://standards.ieee.org/standard/802_1AB-2005.html>
//! - IEEE 802.1Q-2022, Annex D (IEEE 802.1 TLVs, incl. D.2.7 Link
//!   Aggregation and D.2.9–D.2.12 DCBX): <https://standards.ieee.org/ieee/802.1Q/10323/>
//! - IEEE 802.3-2022, Clause 79 (IEEE 802.3 TLVs, incl. 79.3.2 Power via MDI
//!   and 79.3.5 EEE): <https://standards.ieee.org/ieee/802.3/10422/>
//! - ANSI/TIA-1057 (LLDP-MED): <https://tiaonline.org/>
//! - IEEE 802.1 organizationally specific TLV assignments:
//!   <https://www.ieee802.org/1/files/public/802-1-assigned-numbers/IEEE-802-1-organizationally-specific-TLVs-for-LLDP-2011-10-04.pdf>

use packet_dissector_core::field::{
    Field, FieldDescriptor, FieldType, FieldValue, format_utf8_lossy,
};
use packet_dissector_core::packet::DissectBuffer;

/// IEEE 802.1 OUI 00-80-C2 (IEEE 802.1AB-2005, Figure F-1).
pub(crate) const OUI_IEEE_802_1: [u8; 3] = [0x00, 0x80, 0xC2];
/// IEEE 802.3 OUI 00-12-0F (IEEE 802.1AB-2005, Figure G-1).
pub(crate) const OUI_IEEE_802_3: [u8; 3] = [0x00, 0x12, 0x0F];
/// TIA OUI 00-12-BB used by LLDP-MED (ANSI/TIA-1057).
pub(crate) const OUI_TIA_MED: [u8; 3] = [0x00, 0x12, 0xBB];

/// Returns the name of an organizationally specific TLV subtype.
pub(crate) fn org_subtype_name(oui: &[u8], subtype: u8) -> Option<&'static str> {
    match (oui, subtype) {
        // IEEE 802.1 assignments (IEEE 802.1Q-2022, Table D-1; IEEE 802.1
        // organizationally specific TLV assignments list).
        (o, s) if o == OUI_IEEE_802_1 => match s {
            1 => Some("Port VLAN ID"),
            2 => Some("Port And Protocol VLAN ID"),
            3 => Some("VLAN Name"),
            4 => Some("Protocol Identity"),
            5 => Some("VID Usage Digest"),
            6 => Some("Management VID"),
            7 => Some("Link Aggregation"),
            8 => Some("Congestion Notification"),
            9 => Some("ETS Configuration"),
            10 => Some("ETS Recommendation"),
            11 => Some("Priority-based Flow Control Configuration"),
            12 => Some("Application Priority"),
            _ => None,
        },
        // IEEE 802.3-2022, Table 79-1 (subtypes 1–4 also IEEE 802.1AB-2005, Table G-1).
        (o, s) if o == OUI_IEEE_802_3 => match s {
            1 => Some("MAC/PHY Configuration/Status"),
            2 => Some("Power Via MDI"),
            3 => Some("Link Aggregation (deprecated)"),
            4 => Some("Maximum Frame Size"),
            5 => Some("Energy-Efficient Ethernet"),
            _ => None,
        },
        // ANSI/TIA-1057, Table 5.
        (o, s) if o == OUI_TIA_MED => match s {
            1 => Some("LLDP-MED Capabilities"),
            2 => Some("Network Policy"),
            3 => Some("Location Identification"),
            4 => Some("Extended Power-via-MDI"),
            5 => Some("Inventory - Hardware Revision"),
            6 => Some("Inventory - Firmware Revision"),
            7 => Some("Inventory - Software Revision"),
            8 => Some("Inventory - Serial Number"),
            9 => Some("Inventory - Manufacturer Name"),
            10 => Some("Inventory - Model Name"),
            11 => Some("Inventory - Asset ID"),
            _ => None,
        },
        _ => None,
    }
}

/// `display_fn` for `org_subtype`: resolves the name through the sibling
/// `oui` field.
pub(crate) fn org_subtype_display(
    v: &FieldValue<'_>,
    siblings: &[Field<'_>],
) -> Option<&'static str> {
    let FieldValue::U8(subtype) = v else {
        return None;
    };
    siblings.iter().find_map(|f| match (f.name(), &f.value) {
        ("oui", FieldValue::Bytes(oui)) => org_subtype_name(oui, *subtype),
        _ => None,
    })
}

/// Names of LLDP-MED device types (ANSI/TIA-1057, Section 10.2.2.2).
fn med_device_type_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::U8(0) => Some("Type Not Defined"),
        FieldValue::U8(1) => Some("Endpoint Class I"),
        FieldValue::U8(2) => Some("Endpoint Class II"),
        FieldValue::U8(3) => Some("Endpoint Class III"),
        FieldValue::U8(4) => Some("Network Connectivity"),
        _ => None,
    }
}

/// Names of LLDP-MED network policy application types (ANSI/TIA-1057,
/// Section 10.2.3.8).
fn med_app_type_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::U8(1) => Some("Voice"),
        FieldValue::U8(2) => Some("Voice Signaling"),
        FieldValue::U8(3) => Some("Guest Voice"),
        FieldValue::U8(4) => Some("Guest Voice Signaling"),
        FieldValue::U8(5) => Some("Softphone Voice"),
        FieldValue::U8(6) => Some("Video Conferencing"),
        FieldValue::U8(7) => Some("Streaming Video"),
        FieldValue::U8(8) => Some("Video Signaling"),
        _ => None,
    }
}

/// Names of LLDP-MED location data formats (ANSI/TIA-1057, Section 10.2.4.3).
fn med_location_format_name(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::U8(1) => Some("Coordinate-based LCI"),
        FieldValue::U8(2) => Some("Civic Address LCI"),
        FieldValue::U8(3) => Some("ECS ELIN"),
        _ => None,
    }
}

// Indices into [`ORG_FIELDS`].
const FD_PVID: usize = 0;
const FD_PPVID_FLAGS: usize = 1;
const FD_PPVID_SUPPORTED: usize = 2;
const FD_PPVID_ENABLED: usize = 3;
const FD_PPVID: usize = 4;
const FD_VLAN_ID: usize = 5;
const FD_VLAN_NAME_LENGTH: usize = 6;
const FD_VLAN_NAME: usize = 7;
const FD_PROTOCOL_IDENTITY_LENGTH: usize = 8;
const FD_PROTOCOL_IDENTITY: usize = 9;
const FD_AGGREGATION_STATUS: usize = 10;
const FD_AGGREGATION_CAPABLE: usize = 11;
const FD_AGGREGATION_ENABLED: usize = 12;
const FD_AGGREGATED_PORT_ID: usize = 13;
const FD_ETS_WILLING: usize = 14;
const FD_ETS_CBS: usize = 15;
const FD_ETS_MAX_TCS: usize = 16;
const FD_ETS_PRIORITY_ASSIGNMENT: usize = 17;
const FD_ETS_TC_BANDWIDTH: usize = 18;
const FD_ETS_TSA: usize = 19;
const FD_PFC_WILLING: usize = 20;
const FD_PFC_MBC: usize = 21;
const FD_PFC_CAP: usize = 22;
const FD_PFC_ENABLE: usize = 23;
const FD_APP_PRIORITIES: usize = 24;
const FD_AUTONEG_SUPPORT_STATUS: usize = 25;
const FD_AUTONEG_SUPPORTED: usize = 26;
const FD_AUTONEG_ENABLED: usize = 27;
const FD_PMD_AUTONEG_CAPABILITY: usize = 28;
const FD_OPERATIONAL_MAU_TYPE: usize = 29;
const FD_MDI_POWER_SUPPORT: usize = 30;
const FD_PORT_CLASS_PSE: usize = 31;
const FD_PSE_MDI_POWER_SUPPORTED: usize = 32;
const FD_PSE_MDI_POWER_ENABLED: usize = 33;
const FD_PSE_PAIRS_CONTROL: usize = 34;
const FD_PSE_POWER_PAIR: usize = 35;
const FD_POWER_CLASS: usize = 36;
const FD_POWER_TYPE_SOURCE_PRIORITY: usize = 37;
const FD_PD_REQUESTED_POWER: usize = 38;
const FD_PSE_ALLOCATED_POWER: usize = 39;
const FD_MAX_FRAME_SIZE: usize = 40;
const FD_EEE_TX_TW: usize = 41;
const FD_EEE_RX_TW: usize = 42;
const FD_EEE_FALLBACK_RX_TW: usize = 43;
const FD_EEE_ECHO_TX_TW: usize = 44;
const FD_EEE_ECHO_RX_TW: usize = 45;
const FD_MED_CAPABILITIES: usize = 46;
const FD_MED_DEVICE_TYPE: usize = 47;
const FD_MED_APP_TYPE: usize = 48;
const FD_MED_POLICY_UNKNOWN: usize = 49;
const FD_MED_POLICY_TAGGED: usize = 50;
const FD_MED_VLAN_ID: usize = 51;
const FD_MED_L2_PRIORITY: usize = 52;
const FD_MED_DSCP: usize = 53;
const FD_MED_LOCATION_FORMAT: usize = 54;
const FD_MED_LOCATION_DATA: usize = 55;
const FD_MED_POWER_TYPE: usize = 56;
const FD_MED_POWER_SOURCE: usize = 57;
const FD_MED_POWER_PRIORITY: usize = 58;
const FD_MED_POWER_VALUE: usize = 59;
const FD_MED_INVENTORY: usize = 60;

/// Child fields of the decoded `org` object; indexed by the `FD_*` consts.
pub(crate) static ORG_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("pvid", "Port VLAN ID", FieldType::U16).optional(),
    FieldDescriptor::new("ppvid_flags", "Port And Protocol VLAN Flags", FieldType::U8).optional(),
    FieldDescriptor::new(
        "ppvid_supported",
        "Port And Protocol VLAN Supported",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "ppvid_enabled",
        "Port And Protocol VLAN Enabled",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("ppvid", "Port And Protocol VLAN ID", FieldType::U16).optional(),
    FieldDescriptor::new("vlan_id", "VLAN ID", FieldType::U16).optional(),
    FieldDescriptor::new("vlan_name_length", "VLAN Name Length", FieldType::U8).optional(),
    FieldDescriptor::new("vlan_name", "VLAN Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new(
        "protocol_identity_length",
        "Protocol Identity Length",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("protocol_identity", "Protocol Identity", FieldType::Bytes).optional(),
    FieldDescriptor::new("aggregation_status", "Aggregation Status", FieldType::U8).optional(),
    FieldDescriptor::new(
        "aggregation_capable",
        "Aggregation Capability",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "aggregation_enabled",
        "Aggregation Status (in aggregation)",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("aggregated_port_id", "Aggregated Port ID", FieldType::U32).optional(),
    FieldDescriptor::new("ets_willing", "Willing", FieldType::U8).optional(),
    FieldDescriptor::new("ets_cbs", "Credit-based Shaper", FieldType::U8).optional(),
    FieldDescriptor::new("ets_max_tcs", "Max TCs", FieldType::U8).optional(),
    FieldDescriptor::new(
        "ets_priority_assignment",
        "Priority Assignment Table",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("ets_tc_bandwidth", "TC Bandwidth Table", FieldType::Bytes).optional(),
    FieldDescriptor::new("ets_tsa", "TSA Assignment Table", FieldType::Bytes).optional(),
    FieldDescriptor::new("pfc_willing", "Willing", FieldType::U8).optional(),
    FieldDescriptor::new("pfc_mbc", "MACsec Bypass Capability", FieldType::U8).optional(),
    FieldDescriptor::new("pfc_cap", "PFC Capability", FieldType::U8).optional(),
    FieldDescriptor::new("pfc_enable", "PFC Enable", FieldType::U8).optional(),
    FieldDescriptor::new(
        "app_priorities",
        "Application Priority Table",
        FieldType::Array,
    )
    .optional()
    .with_children(APP_PRIORITY_FIELDS),
    FieldDescriptor::new(
        "autoneg_support_status",
        "Auto-negotiation Support/Status",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "autoneg_supported",
        "Auto-negotiation Supported",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("autoneg_enabled", "Auto-negotiation Enabled", FieldType::U8).optional(),
    FieldDescriptor::new(
        "pmd_autoneg_capability",
        "PMD Auto-negotiation Advertised Capability",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "operational_mau_type",
        "Operational MAU Type",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("mdi_power_support", "MDI Power Support", FieldType::U8).optional(),
    FieldDescriptor::new("port_class_pse", "Port Class (1 = PSE)", FieldType::U8).optional(),
    FieldDescriptor::new(
        "pse_mdi_power_supported",
        "PSE MDI Power Supported",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "pse_mdi_power_enabled",
        "PSE MDI Power Enabled",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "pse_pairs_control",
        "PSE Pairs Control Ability",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("pse_power_pair", "PSE Power Pair", FieldType::U8).optional(),
    FieldDescriptor::new("power_class", "Power Class", FieldType::U8).optional(),
    FieldDescriptor::new(
        "power_type_source_priority",
        "Power Type/Source/Priority",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "pd_requested_power",
        "PD Requested Power (0.1 W)",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "pse_allocated_power",
        "PSE Allocated Power (0.1 W)",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("max_frame_size", "Maximum Frame Size", FieldType::U16).optional(),
    FieldDescriptor::new("eee_tx_tw", "Transmit Tw", FieldType::U16).optional(),
    FieldDescriptor::new("eee_rx_tw", "Receive Tw", FieldType::U16).optional(),
    FieldDescriptor::new("eee_fallback_rx_tw", "Fallback Receive Tw", FieldType::U16).optional(),
    FieldDescriptor::new("eee_echo_tx_tw", "Echo Transmit Tw", FieldType::U16).optional(),
    FieldDescriptor::new("eee_echo_rx_tw", "Echo Receive Tw", FieldType::U16).optional(),
    FieldDescriptor::new("med_capabilities", "LLDP-MED Capabilities", FieldType::U16).optional(),
    FieldDescriptor::new("med_device_type", "LLDP-MED Device Type", FieldType::U8)
        .optional()
        .with_display_fn(med_device_type_name),
    FieldDescriptor::new("med_app_type", "Application Type", FieldType::U8)
        .optional()
        .with_display_fn(med_app_type_name),
    FieldDescriptor::new("med_policy_unknown", "Policy Unknown", FieldType::U8).optional(),
    FieldDescriptor::new("med_policy_tagged", "Tagged", FieldType::U8).optional(),
    FieldDescriptor::new("med_vlan_id", "VLAN ID", FieldType::U16).optional(),
    FieldDescriptor::new("med_l2_priority", "L2 Priority", FieldType::U8).optional(),
    FieldDescriptor::new("med_dscp", "DSCP Value", FieldType::U8).optional(),
    FieldDescriptor::new("med_location_format", "Location Data Format", FieldType::U8)
        .optional()
        .with_display_fn(med_location_format_name),
    FieldDescriptor::new("med_location_data", "Location ID Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("med_power_type", "Power Type", FieldType::U8).optional(),
    FieldDescriptor::new("med_power_source", "Power Source", FieldType::U8).optional(),
    FieldDescriptor::new("med_power_priority", "Power Priority", FieldType::U8).optional(),
    FieldDescriptor::new("med_power_value", "Power Value (0.1 W)", FieldType::U16).optional(),
    FieldDescriptor::new("med_inventory", "Inventory", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
];

/// Child fields of one Application Priority table entry
/// (IEEE 802.1Q-2022, D.2.12).
static APP_PRIORITY_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("priority", "Priority", FieldType::U8),
    FieldDescriptor::new("selector", "Selector", FieldType::U8),
    FieldDescriptor::new("protocol_id", "Protocol ID", FieldType::U16),
];

static FD_APP_PRIORITY_ENTRY: FieldDescriptor =
    FieldDescriptor::new("app_priority", "Application Priority", FieldType::Object);

/// Decode the information string of a known organizationally specific TLV
/// into an `org` object (`container`). `base` is the absolute offset of
/// `info`. Unknown pairs and length mismatches push nothing.
pub(crate) fn push_org_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    container: &'static FieldDescriptor,
    oui: &[u8],
    subtype: u8,
    info: &'pkt [u8],
    base: usize,
) {
    let decoder: Option<Decoder> = if oui == OUI_IEEE_802_1 {
        ieee_802_1_decoder(subtype, info)
    } else if oui == OUI_IEEE_802_3 {
        ieee_802_3_decoder(subtype, info)
    } else if oui == OUI_TIA_MED {
        med_decoder(subtype, info)
    } else {
        None
    };
    let Some(decode) = decoder else {
        return;
    };
    let idx = buf.begin_container(container, FieldValue::Object(0..0), base..base + info.len());
    decode(&mut Out { buf, base }, info);
    buf.end_container(idx);
}

/// A decoder for one (OUI, subtype) information string of a checked length.
type Decoder = for<'a, 'pkt> fn(&mut Out<'a, 'pkt>, &'pkt [u8]);

/// Field sink that turns information-string offsets into absolute ranges.
struct Out<'a, 'pkt> {
    buf: &'a mut DissectBuffer<'pkt>,
    base: usize,
}

impl<'pkt> Out<'_, 'pkt> {
    fn push_with(
        &mut self,
        descriptor: &'static FieldDescriptor,
        value: FieldValue<'pkt>,
        start: usize,
        len: usize,
    ) {
        self.buf.push_field(
            descriptor,
            value,
            self.base + start..self.base + start + len,
        );
    }

    /// Begin a container covering `len` octets at `start`.
    fn open(
        &mut self,
        descriptor: &'static FieldDescriptor,
        value: FieldValue<'pkt>,
        start: usize,
        len: usize,
    ) -> u32 {
        self.buf.begin_container(
            descriptor,
            value,
            self.base + start..self.base + start + len,
        )
    }

    fn push(&mut self, fd: usize, value: FieldValue<'pkt>, start: usize, len: usize) {
        self.push_with(&ORG_FIELDS[fd], value, start, len);
    }

    fn u8(&mut self, fd: usize, value: u8, at: usize) {
        self.push(fd, FieldValue::U8(value), at, 1);
    }

    fn u16(&mut self, fd: usize, info: &[u8], at: usize) {
        self.push(
            fd,
            FieldValue::U16(u16::from_be_bytes([info[at], info[at + 1]])),
            at,
            2,
        );
    }

    fn bytes(&mut self, fd: usize, info: &'pkt [u8], start: usize, len: usize) {
        if len > 0 {
            self.push(fd, FieldValue::Bytes(&info[start..start + len]), start, len);
        }
    }

    /// A flag bit of the octet at `at`, as 0 or 1.
    fn bit(&mut self, fd: usize, octet: u8, bit: u8, at: usize) {
        self.u8(fd, (octet >> bit) & 1, at);
    }
}

/// IEEE 802.1 organizationally specific TLVs (OUI 00-80-C2).
fn ieee_802_1_decoder(subtype: u8, info: &[u8]) -> Option<Decoder> {
    let len = info.len();
    let decoder: Decoder = match subtype {
        // IEEE 802.1AB-2005 F.2, Figure F-1 — PVID (2 octets).
        1 if len == 2 => |o, i| o.u16(FD_PVID, i, 0),
        // IEEE 802.1AB-2005 F.3, Figure F-2 / Table F-2 — flags (bit 1
        // supported, bit 2 enabled), PPVID (2 octets).
        2 if len == 3 => |o, i| {
            o.u8(FD_PPVID_FLAGS, i[0], 0);
            o.bit(FD_PPVID_SUPPORTED, i[0], 1, 0);
            o.bit(FD_PPVID_ENABLED, i[0], 2, 0);
            o.u16(FD_PPVID, i, 1);
        },
        // IEEE 802.1AB-2005 F.4, Figure F-3 — VID (2), name length (1), name.
        3 if len >= 3 && 3 + info[2] as usize == len => |o, i| {
            o.u16(FD_VLAN_ID, i, 0);
            o.u8(FD_VLAN_NAME_LENGTH, i[2], 2);
            o.bytes(FD_VLAN_NAME, i, 3, i.len() - 3);
        },
        // IEEE 802.1AB-2005 F.5, Figure F-4 — length (1), protocol identity.
        4 if len >= 1 && 1 + info[0] as usize == len => |o, i| {
            o.u8(FD_PROTOCOL_IDENTITY_LENGTH, i[0], 0);
            o.bytes(FD_PROTOCOL_IDENTITY, i, 1, i.len() - 1);
        },
        // IEEE 802.1Q-2022 D.2.7 — aggregation status (1), port ID (4); same
        // layout as IEEE 802.1AB-2005 G.4.
        7 if len == 5 => push_link_aggregation,
        // IEEE 802.1Q-2022 D.2.9 — willing/CBS/max TCs (1), priority
        // assignment (4), TC bandwidth (8), TSA assignment (8).
        9 if len == 21 => |o, i| {
            o.bit(FD_ETS_WILLING, i[0], 7, 0);
            o.bit(FD_ETS_CBS, i[0], 6, 0);
            o.u8(FD_ETS_MAX_TCS, i[0] & 0x07, 0);
            push_ets_tables(o, i);
        },
        // IEEE 802.1Q-2022 D.2.10 — reserved (1), then the ETS tables.
        10 if len == 21 => push_ets_tables,
        // IEEE 802.1Q-2022 D.2.11 — willing/MBC/PFC cap (1), enable (1).
        11 if len == 2 => |o, i| {
            o.bit(FD_PFC_WILLING, i[0], 7, 0);
            o.bit(FD_PFC_MBC, i[0], 6, 0);
            o.u8(FD_PFC_CAP, i[0] & 0x0F, 0);
            o.u8(FD_PFC_ENABLE, i[1], 1);
        },
        // IEEE 802.1Q-2022 D.2.12 — reserved (1), then 3-octet entries.
        12 if len >= 4 && (len - 1) % 3 == 0 => push_app_priorities,
        _ => return None,
    };
    Some(decoder)
}

/// Link Aggregation status bits 0 (capability) and 1 (status), then the
/// aggregated port ID (IEEE 802.1AB-2005 G.4, Table G-4).
fn push_link_aggregation<'pkt>(o: &mut Out<'_, 'pkt>, i: &'pkt [u8]) {
    o.u8(FD_AGGREGATION_STATUS, i[0], 0);
    o.bit(FD_AGGREGATION_CAPABLE, i[0], 0, 0);
    o.bit(FD_AGGREGATION_ENABLED, i[0], 1, 0);
    o.push(
        FD_AGGREGATED_PORT_ID,
        FieldValue::U32(u32::from_be_bytes([i[1], i[2], i[3], i[4]])),
        1,
        4,
    );
}

/// ETS priority assignment, TC bandwidth and TSA assignment tables after
/// the first octet (IEEE 802.1Q-2022 D.2.9 / D.2.10).
fn push_ets_tables<'pkt>(o: &mut Out<'_, 'pkt>, i: &'pkt [u8]) {
    o.bytes(FD_ETS_PRIORITY_ASSIGNMENT, i, 1, 4);
    o.bytes(FD_ETS_TC_BANDWIDTH, i, 5, 8);
    o.bytes(FD_ETS_TSA, i, 13, 8);
}

/// Application Priority table (IEEE 802.1Q-2022 D.2.12): each entry is
/// priority (3 bits), reserved (2 bits), selector (3 bits), protocol ID (2).
fn push_app_priorities<'pkt>(o: &mut Out<'_, 'pkt>, i: &'pkt [u8]) {
    let arr = o.open(
        &ORG_FIELDS[FD_APP_PRIORITIES],
        FieldValue::Array(0..0),
        1,
        i.len() - 1,
    );
    for (n, e) in i[1..].chunks_exact(3).enumerate() {
        let at = 1 + 3 * n;
        let obj = o.open(&FD_APP_PRIORITY_ENTRY, FieldValue::Object(0..0), at, 3);
        o.push_with(&APP_PRIORITY_FIELDS[0], FieldValue::U8(e[0] >> 5), at, 1);
        o.push_with(&APP_PRIORITY_FIELDS[1], FieldValue::U8(e[0] & 0x07), at, 1);
        o.push_with(
            &APP_PRIORITY_FIELDS[2],
            FieldValue::U16(u16::from_be_bytes([e[1], e[2]])),
            at + 1,
            2,
        );
        o.buf.end_container(obj);
    }
    o.buf.end_container(arr);
}

/// Power Via MDI basic fields (IEEE 802.1AB-2005 G.3, Table G-3).
fn push_power_via_mdi<'pkt>(o: &mut Out<'_, 'pkt>, i: &'pkt [u8]) {
    o.u8(FD_MDI_POWER_SUPPORT, i[0], 0);
    o.bit(FD_PORT_CLASS_PSE, i[0], 0, 0);
    o.bit(FD_PSE_MDI_POWER_SUPPORTED, i[0], 1, 0);
    o.bit(FD_PSE_MDI_POWER_ENABLED, i[0], 2, 0);
    o.bit(FD_PSE_PAIRS_CONTROL, i[0], 3, 0);
    o.u8(FD_PSE_POWER_PAIR, i[1], 1);
    o.u8(FD_POWER_CLASS, i[2], 2);
}

/// IEEE 802.3 organizationally specific TLVs (OUI 00-12-0F).
fn ieee_802_3_decoder(subtype: u8, info: &[u8]) -> Option<Decoder> {
    let len = info.len();
    let decoder: Decoder = match subtype {
        // IEEE 802.1AB-2005 G.2, Figure G-1 / Table G-2 — auto-negotiation
        // support (bit 0) / status (bit 1), PMD capability (2), MAU type (2).
        1 if len == 5 => |o, i| {
            o.u8(FD_AUTONEG_SUPPORT_STATUS, i[0], 0);
            o.bit(FD_AUTONEG_SUPPORTED, i[0], 0, 0);
            o.bit(FD_AUTONEG_ENABLED, i[0], 1, 0);
            o.u16(FD_PMD_AUTONEG_CAPABILITY, i, 1);
            o.u16(FD_OPERATIONAL_MAU_TYPE, i, 3);
        },
        // IEEE 802.3-2022 79.3.2 — the 3 basic octets of IEEE 802.1AB-2005
        // G.3, then (802.3at) type/source/priority (1), PD requested power
        // (2) and PSE allocated power (2). Later extensions stay in `info`.
        2 if (3..8).contains(&len) => push_power_via_mdi,
        2 if len >= 8 => |o, i| {
            push_power_via_mdi(o, i);
            o.u8(FD_POWER_TYPE_SOURCE_PRIORITY, i[3], 3);
            o.u16(FD_PD_REQUESTED_POWER, i, 4);
            o.u16(FD_PSE_ALLOCATED_POWER, i, 6);
        },
        // IEEE 802.1AB-2005 G.4, Figure G-3 — deprecated in favor of the
        // IEEE 802.1 Link Aggregation TLV.
        3 if len == 5 => push_link_aggregation,
        // IEEE 802.1AB-2005 G.5, Figure G-4 — maximum frame size (2).
        4 if len == 2 => |o, i| o.u16(FD_MAX_FRAME_SIZE, i, 0),
        // IEEE 802.3-2022 79.3.5 — Transmit, Receive, Fallback Receive,
        // Echo Transmit and Echo Receive Tw (2 octets each).
        5 if len == 10 => |o, i| {
            o.u16(FD_EEE_TX_TW, i, 0);
            o.u16(FD_EEE_RX_TW, i, 2);
            o.u16(FD_EEE_FALLBACK_RX_TW, i, 4);
            o.u16(FD_EEE_ECHO_TX_TW, i, 6);
            o.u16(FD_EEE_ECHO_RX_TW, i, 8);
        },
        _ => return None,
    };
    Some(decoder)
}

/// LLDP-MED TLVs (OUI 00-12-BB, ANSI/TIA-1057).
fn med_decoder(subtype: u8, info: &[u8]) -> Option<Decoder> {
    let len = info.len();
    let decoder: Decoder = match subtype {
        // 10.2.2 — capabilities (2), device type (1).
        1 if len == 3 => |o, i| {
            o.u16(FD_MED_CAPABILITIES, i, 0);
            o.u8(FD_MED_DEVICE_TYPE, i[2], 2);
        },
        // 10.2.3 — application type (1), then U (1 bit), T (1 bit),
        // X (1 bit), VLAN ID (12 bits), L2 priority (3 bits), DSCP (6 bits).
        2 if len == 4 => |o, i| {
            let bits = u32::from_be_bytes([0, i[1], i[2], i[3]]);
            o.u8(FD_MED_APP_TYPE, i[0], 0);
            o.push(
                FD_MED_POLICY_UNKNOWN,
                FieldValue::U8((bits >> 23) as u8 & 1),
                1,
                1,
            );
            o.push(
                FD_MED_POLICY_TAGGED,
                FieldValue::U8((bits >> 22) as u8 & 1),
                1,
                1,
            );
            o.push(
                FD_MED_VLAN_ID,
                FieldValue::U16((bits >> 9) as u16 & 0x0FFF),
                1,
                2,
            );
            o.push(
                FD_MED_L2_PRIORITY,
                FieldValue::U8((bits >> 6) as u8 & 0x07),
                2,
                2,
            );
            o.push(FD_MED_DSCP, FieldValue::U8(bits as u8 & 0x3F), 3, 1);
        },
        // 10.2.4 — location data format (1), location ID data (raw).
        3 if len >= 1 => |o, i| {
            o.u8(FD_MED_LOCATION_FORMAT, i[0], 0);
            o.bytes(FD_MED_LOCATION_DATA, i, 1, i.len() - 1);
        },
        // 10.2.5 — power type (2 bits), source (2 bits), priority (4 bits),
        // power value (2 octets, 0.1 W).
        4 if len == 3 => |o, i| {
            o.u8(FD_MED_POWER_TYPE, i[0] >> 6, 0);
            o.u8(FD_MED_POWER_SOURCE, (i[0] >> 4) & 0x03, 0);
            o.u8(FD_MED_POWER_PRIORITY, i[0] & 0x0F, 0);
            o.u16(FD_MED_POWER_VALUE, i, 1);
        },
        // 10.2.6 — inventory TLVs carry one string each.
        5..=11 if len >= 1 => |o, i| o.bytes(FD_MED_INVENTORY, i, 0, i.len()),
        _ => return None,
    };
    Some(decoder)
}

#[cfg(test)]
mod tests {
    //! # Organizationally Specific TLV Coverage
    //!
    //! | Spec section                         | Description                        | Test                          |
    //! |--------------------------------------|------------------------------------|-------------------------------|
    //! | 802.1AB-2005 F.2 / 802.1Q D.2.1      | Port VLAN ID                       | org_8021_port_vlan_id         |
    //! | 802.1AB-2005 F.3 / 802.1Q D.2.2      | Port And Protocol VLAN ID          | org_8021_ppvid                |
    //! | 802.1AB-2005 F.4 / 802.1Q D.2.3      | VLAN Name                          | org_8021_vlan_name            |
    //! | 802.1AB-2005 F.5 / 802.1Q D.2.4      | Protocol Identity                  | org_8021_protocol_identity    |
    //! | 802.1Q D.2.7                         | Link Aggregation                   | org_8021_link_aggregation     |
    //! | 802.1Q D.2.9 / D.2.10                | ETS Configuration / Recommendation | org_8021_ets                  |
    //! | 802.1Q D.2.11                        | PFC Configuration                  | org_8021_pfc                  |
    //! | 802.1Q D.2.12                        | Application Priority               | org_8021_app_priority         |
    //! | 802.1AB-2005 G.2 / 802.3 79.3.1      | MAC/PHY Configuration/Status       | org_8023_mac_phy              |
    //! | 802.1AB-2005 G.3 / 802.3 79.3.2      | Power Via MDI (basic, extended)    | org_8023_power_via_mdi        |
    //! | 802.1AB-2005 G.4 / 802.3 79.3.3      | Link Aggregation (deprecated)      | org_8023_link_aggregation     |
    //! | 802.1AB-2005 G.5 / 802.3 79.3.4      | Maximum Frame Size                 | org_8023_max_frame_size       |
    //! | 802.3 79.3.5                         | EEE                                | org_8023_eee                  |
    //! | TIA-1057 10.2.2                      | LLDP-MED Capabilities              | org_med_capabilities          |
    //! | TIA-1057 10.2.3                      | Network Policy                     | org_med_network_policy        |
    //! | TIA-1057 10.2.4                      | Location Identification            | org_med_location              |
    //! | TIA-1057 10.2.5                      | Extended Power-via-MDI             | org_med_extended_power        |
    //! | TIA-1057 10.2.6                      | Inventory TLVs                     | org_med_inventory             |
    //! | 802.1AB-2016 8.6                     | Length mismatch keeps raw info     | org_length_mismatch_not_decoded |
    //! | 802.1AB-2016 8.6                     | Unknown OUI / subtype              | org_unknown_not_decoded       |

    use super::*;
    use crate::LldpDissector;
    use packet_dissector_core::dissector::Dissector;

    /// LLDPDU: mandatory TLVs + one organizationally specific TLV + End.
    fn lldp_with_org(oui: [u8; 3], subtype: u8, info: &[u8]) -> Vec<u8> {
        let mut d = vec![0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        d.extend_from_slice(&[0x04, 0x04, 0x07, b'g', b'e', b'0']);
        d.extend_from_slice(&[0x06, 0x02, 0x00, 0x78]);
        let len = 4 + info.len();
        d.extend_from_slice(&((127u16 << 9) | len as u16).to_be_bytes());
        d.extend_from_slice(&oui);
        d.push(subtype);
        d.extend_from_slice(info);
        d.extend_from_slice(&[0x00, 0x00]);
        d
    }

    /// Offset of the org TLV's information string in `lldp_with_org` data.
    const INFO_OFFSET: usize = 9 + 6 + 4 + 2 + 4;

    /// Fields of the `org` object of TLV index 3 (the org TLV).
    fn org_fields<'a>(buf: &'a DissectBuffer<'_>) -> Option<&'a [Field<'a>]> {
        let layer = buf.layer_by_name("LLDP").unwrap();
        let FieldValue::Array(arr) = &buf.field_by_name(layer, "tlvs").unwrap().value else {
            panic!("tlvs")
        };
        let tlv = buf
            .nested_fields(arr)
            .iter()
            .filter_map(|f| match &f.value {
                FieldValue::Object(o) => Some(buf.nested_fields(o)),
                _ => None,
            })
            .nth(3)
            .unwrap();
        tlv.iter()
            .find(|f| f.name() == "org")
            .map(|f| match &f.value {
                FieldValue::Object(o) => buf.nested_fields(o),
                _ => panic!("org is not an object"),
            })
    }

    fn get<'a>(fields: &'a [Field<'a>], name: &str) -> &'a FieldValue<'a> {
        &fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("{name}"))
            .value
    }

    fn range_of(fields: &[Field<'_>], name: &str) -> core::ops::Range<usize> {
        fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap()
            .range
            .clone()
    }

    #[test]
    fn org_8021_port_vlan_id() {
        let data = lldp_with_org(OUI_IEEE_802_1, 1, &[0x00, 0x64]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "pvid"), FieldValue::U16(100));
        assert_eq!(range_of(o, "pvid"), INFO_OFFSET..INFO_OFFSET + 2);
        assert_eq!(org_subtype_name(&OUI_IEEE_802_1, 1), Some("Port VLAN ID"));
    }

    #[test]
    fn org_8021_ppvid() {
        let data = lldp_with_org(OUI_IEEE_802_1, 2, &[0x06, 0x00, 0x0A]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "ppvid_flags"), FieldValue::U8(0x06));
        assert_eq!(*get(o, "ppvid_supported"), FieldValue::U8(1));
        assert_eq!(*get(o, "ppvid_enabled"), FieldValue::U8(1));
        assert_eq!(*get(o, "ppvid"), FieldValue::U16(10));
    }

    #[test]
    fn org_8021_vlan_name() {
        let data = lldp_with_org(
            OUI_IEEE_802_1,
            3,
            &[0x00, 0x0A, 0x04, b'v', b'o', b'i', b'p'],
        );
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "vlan_id"), FieldValue::U16(10));
        assert_eq!(*get(o, "vlan_name_length"), FieldValue::U8(4));
        assert_eq!(*get(o, "vlan_name"), FieldValue::Bytes(b"voip"));
        assert_eq!(range_of(o, "vlan_name"), INFO_OFFSET + 3..INFO_OFFSET + 7);
        // Name length disagreeing with the TLV length: not decoded.
        let data = lldp_with_org(OUI_IEEE_802_1, 3, &[0x00, 0x0A, 0x05, b'v', b'o']);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(org_fields(&buf).is_none());
    }

    #[test]
    fn org_8021_protocol_identity() {
        let data = lldp_with_org(OUI_IEEE_802_1, 4, &[0x03, 0x88, 0x8E, 0x01]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "protocol_identity_length"), FieldValue::U8(3));
        assert_eq!(
            *get(o, "protocol_identity"),
            FieldValue::Bytes(&[0x88, 0x8E, 0x01])
        );
        let data = lldp_with_org(OUI_IEEE_802_1, 4, &[0x00]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert!(o.iter().all(|f| f.name() != "protocol_identity"));
    }

    #[test]
    fn org_8021_link_aggregation() {
        let data = lldp_with_org(OUI_IEEE_802_1, 7, &[0x03, 0x00, 0x00, 0x01, 0xF4]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "aggregation_status"), FieldValue::U8(3));
        assert_eq!(*get(o, "aggregation_capable"), FieldValue::U8(1));
        assert_eq!(*get(o, "aggregation_enabled"), FieldValue::U8(1));
        assert_eq!(*get(o, "aggregated_port_id"), FieldValue::U32(500));
    }

    #[test]
    fn org_8021_ets() {
        let mut info = vec![0xC3]; // willing, CBS, max TCs 3
        info.extend_from_slice(&[0x01, 0x23, 0x45, 0x67]);
        info.extend_from_slice(&[10, 20, 30, 40, 0, 0, 0, 0]);
        info.extend_from_slice(&[2, 2, 2, 2, 0, 0, 0, 0]);
        let data = lldp_with_org(OUI_IEEE_802_1, 9, &info);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "ets_willing"), FieldValue::U8(1));
        assert_eq!(*get(o, "ets_cbs"), FieldValue::U8(1));
        assert_eq!(*get(o, "ets_max_tcs"), FieldValue::U8(3));
        assert_eq!(
            *get(o, "ets_priority_assignment"),
            FieldValue::Bytes(&info[1..5])
        );
        assert_eq!(*get(o, "ets_tc_bandwidth"), FieldValue::Bytes(&info[5..13]));
        assert_eq!(*get(o, "ets_tsa"), FieldValue::Bytes(&info[13..21]));

        // ETS Recommendation: the first octet is reserved.
        let data = lldp_with_org(OUI_IEEE_802_1, 10, &info);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert!(o.iter().all(|f| f.name() != "ets_willing"));
        assert_eq!(*get(o, "ets_tsa"), FieldValue::Bytes(&info[13..21]));
    }

    #[test]
    fn org_8021_pfc() {
        let data = lldp_with_org(OUI_IEEE_802_1, 11, &[0xC8, 0x08]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "pfc_willing"), FieldValue::U8(1));
        assert_eq!(*get(o, "pfc_mbc"), FieldValue::U8(1));
        assert_eq!(*get(o, "pfc_cap"), FieldValue::U8(8));
        assert_eq!(*get(o, "pfc_enable"), FieldValue::U8(0x08));
    }

    #[test]
    fn org_8021_app_priority() {
        // Reserved octet, then (priority 3, selector 1 = EtherType, 0x8906)
        // and (priority 4, selector 2 = TCP port, 3260).
        let data = lldp_with_org(
            OUI_IEEE_802_1,
            12,
            &[0x00, 0x61, 0x89, 0x06, 0x82, 0x0C, 0xBC],
        );
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        let FieldValue::Array(arr) = get(o, "app_priorities") else {
            panic!("array")
        };
        let entries: Vec<_> = buf
            .nested_fields(arr)
            .iter()
            .filter_map(|f| match &f.value {
                FieldValue::Object(r) => Some(buf.nested_fields(r)),
                _ => None,
            })
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(*get(entries[0], "priority"), FieldValue::U8(3));
        assert_eq!(*get(entries[0], "selector"), FieldValue::U8(1));
        assert_eq!(*get(entries[0], "protocol_id"), FieldValue::U16(0x8906));
        assert_eq!(*get(entries[1], "priority"), FieldValue::U8(4));
        assert_eq!(*get(entries[1], "selector"), FieldValue::U8(2));
        assert_eq!(*get(entries[1], "protocol_id"), FieldValue::U16(3260));
        // Only the reserved octet: nothing to decode.
        let data = lldp_with_org(OUI_IEEE_802_1, 12, &[0x00]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(org_fields(&buf).is_none());
    }

    #[test]
    fn org_8023_mac_phy() {
        let data = lldp_with_org(OUI_IEEE_802_3, 1, &[0x03, 0x6C, 0x03, 0x00, 0x1E]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "autoneg_support_status"), FieldValue::U8(3));
        assert_eq!(*get(o, "autoneg_supported"), FieldValue::U8(1));
        assert_eq!(*get(o, "autoneg_enabled"), FieldValue::U8(1));
        assert_eq!(*get(o, "pmd_autoneg_capability"), FieldValue::U16(0x6C03));
        assert_eq!(*get(o, "operational_mau_type"), FieldValue::U16(30));
    }

    #[test]
    fn org_8023_power_via_mdi() {
        let data = lldp_with_org(OUI_IEEE_802_3, 2, &[0x0F, 0x01, 0x03]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "mdi_power_support"), FieldValue::U8(0x0F));
        assert_eq!(*get(o, "port_class_pse"), FieldValue::U8(1));
        assert_eq!(*get(o, "pse_mdi_power_supported"), FieldValue::U8(1));
        assert_eq!(*get(o, "pse_mdi_power_enabled"), FieldValue::U8(1));
        assert_eq!(*get(o, "pse_pairs_control"), FieldValue::U8(1));
        assert_eq!(*get(o, "pse_power_pair"), FieldValue::U8(1));
        assert_eq!(*get(o, "power_class"), FieldValue::U8(3));
        assert!(o.iter().all(|f| f.name() != "pd_requested_power"));

        // 802.3at extension: type/source/priority, requested, allocated power.
        let data = lldp_with_org(
            OUI_IEEE_802_3,
            2,
            &[0x07, 0x01, 0x04, 0x51, 0x00, 0xFF, 0x00, 0xFF],
        );
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "power_type_source_priority"), FieldValue::U8(0x51));
        assert_eq!(*get(o, "pd_requested_power"), FieldValue::U16(255));
        assert_eq!(*get(o, "pse_allocated_power"), FieldValue::U16(255));

        let data = lldp_with_org(OUI_IEEE_802_3, 2, &[0x07, 0x01]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(org_fields(&buf).is_none());
    }

    #[test]
    fn org_8023_link_aggregation() {
        let data = lldp_with_org(OUI_IEEE_802_3, 3, &[0x01, 0x00, 0x00, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "aggregation_capable"), FieldValue::U8(1));
        assert_eq!(*get(o, "aggregation_enabled"), FieldValue::U8(0));
        assert_eq!(*get(o, "aggregated_port_id"), FieldValue::U32(0));
    }

    #[test]
    fn org_8023_max_frame_size() {
        let data = lldp_with_org(OUI_IEEE_802_3, 4, &[0x05, 0xEE]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "max_frame_size"), FieldValue::U16(1518));
    }

    #[test]
    fn org_8023_eee() {
        let data = lldp_with_org(
            OUI_IEEE_802_3,
            5,
            &[0x00, 0x11, 0x00, 0x12, 0x00, 0x13, 0x00, 0x14, 0x00, 0x15],
        );
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "eee_tx_tw"), FieldValue::U16(0x11));
        assert_eq!(*get(o, "eee_rx_tw"), FieldValue::U16(0x12));
        assert_eq!(*get(o, "eee_fallback_rx_tw"), FieldValue::U16(0x13));
        assert_eq!(*get(o, "eee_echo_tx_tw"), FieldValue::U16(0x14));
        assert_eq!(*get(o, "eee_echo_rx_tw"), FieldValue::U16(0x15));
    }

    #[test]
    fn org_med_capabilities() {
        let data = lldp_with_org(OUI_TIA_MED, 1, &[0x00, 0x33, 0x03]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "med_capabilities"), FieldValue::U16(0x33));
        assert_eq!(*get(o, "med_device_type"), FieldValue::U8(3));
        let f = o.iter().find(|f| f.name() == "med_device_type").unwrap();
        assert_eq!(
            (f.descriptor.display_fn.unwrap())(&f.value, o),
            Some("Endpoint Class III")
        );
        for (v, n) in [
            (0, "Type Not Defined"),
            (1, "Endpoint Class I"),
            (2, "Endpoint Class II"),
            (4, "Network Connectivity"),
        ] {
            assert_eq!(med_device_type_name(&FieldValue::U8(v), &[]), Some(n));
        }
        assert_eq!(med_device_type_name(&FieldValue::U8(5), &[]), None);
    }

    #[test]
    fn org_med_network_policy() {
        // Voice, tagged, VLAN 100, L2 priority 5, DSCP 46.
        let data = lldp_with_org(OUI_TIA_MED, 2, &[0x01, 0x40, 0xC9, 0x6E]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "med_app_type"), FieldValue::U8(1));
        assert_eq!(*get(o, "med_policy_unknown"), FieldValue::U8(0));
        assert_eq!(*get(o, "med_policy_tagged"), FieldValue::U8(1));
        assert_eq!(*get(o, "med_vlan_id"), FieldValue::U16(100));
        assert_eq!(*get(o, "med_l2_priority"), FieldValue::U8(5));
        assert_eq!(*get(o, "med_dscp"), FieldValue::U8(46));
        for v in 1..=8 {
            assert!(med_app_type_name(&FieldValue::U8(v), &[]).is_some());
        }
        assert_eq!(med_app_type_name(&FieldValue::U8(9), &[]), None);
    }

    #[test]
    fn org_med_location() {
        let data = lldp_with_org(OUI_TIA_MED, 3, &[0x03, b'1', b'2', b'3']);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "med_location_format"), FieldValue::U8(3));
        assert_eq!(*get(o, "med_location_data"), FieldValue::Bytes(b"123"));
        for (v, n) in [
            (1, "Coordinate-based LCI"),
            (2, "Civic Address LCI"),
            (3, "ECS ELIN"),
        ] {
            assert_eq!(med_location_format_name(&FieldValue::U8(v), &[]), Some(n));
        }
        assert_eq!(med_location_format_name(&FieldValue::U8(0), &[]), None);
    }

    #[test]
    fn org_med_extended_power() {
        // PD (01), PSE source (01), priority high (2), 15.4 W.
        let data = lldp_with_org(OUI_TIA_MED, 4, &[0x52, 0x00, 0x9A]);
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        let o = org_fields(&buf).unwrap();
        assert_eq!(*get(o, "med_power_type"), FieldValue::U8(1));
        assert_eq!(*get(o, "med_power_source"), FieldValue::U8(1));
        assert_eq!(*get(o, "med_power_priority"), FieldValue::U8(2));
        assert_eq!(*get(o, "med_power_value"), FieldValue::U16(154));
    }

    #[test]
    fn org_med_inventory() {
        for subtype in 5..=11 {
            let data = lldp_with_org(OUI_TIA_MED, subtype, b"v1.2");
            let mut buf = DissectBuffer::new();
            LldpDissector.dissect(&data, &mut buf, 0).unwrap();
            let o = org_fields(&buf).unwrap();
            assert_eq!(*get(o, "med_inventory"), FieldValue::Bytes(b"v1.2"));
            assert!(org_subtype_name(&OUI_TIA_MED, subtype).is_some());
        }
    }

    #[test]
    fn org_length_mismatch_not_decoded() {
        for (oui, subtype, len) in [
            (OUI_IEEE_802_1, 1, 3),
            (OUI_IEEE_802_1, 2, 2),
            (OUI_IEEE_802_1, 3, 2),
            (OUI_IEEE_802_1, 4, 0),
            (OUI_IEEE_802_1, 7, 4),
            (OUI_IEEE_802_1, 9, 20),
            (OUI_IEEE_802_1, 11, 3),
            (OUI_IEEE_802_1, 12, 3),
            (OUI_IEEE_802_3, 1, 4),
            (OUI_IEEE_802_3, 4, 3),
            (OUI_IEEE_802_3, 5, 9),
            (OUI_TIA_MED, 1, 2),
            (OUI_TIA_MED, 2, 5),
            (OUI_TIA_MED, 3, 0),
            (OUI_TIA_MED, 4, 2),
            (OUI_TIA_MED, 8, 0),
        ] {
            let data = lldp_with_org(oui, subtype, &vec![0u8; len]);
            let mut buf = DissectBuffer::new();
            LldpDissector.dissect(&data, &mut buf, 0).unwrap();
            assert!(org_fields(&buf).is_none(), "{oui:?}/{subtype} len {len}");
        }
    }

    #[test]
    fn org_unknown_not_decoded() {
        for (oui, subtype) in [
            (OUI_IEEE_802_1, 0),
            (OUI_IEEE_802_1, 13),
            (OUI_IEEE_802_3, 6),
            (OUI_TIA_MED, 12),
            ([0x00, 0x00, 0x0C], 1),
        ] {
            let data = lldp_with_org(oui, subtype, &[0x00, 0x01]);
            let mut buf = DissectBuffer::new();
            LldpDissector.dissect(&data, &mut buf, 0).unwrap();
            assert!(org_fields(&buf).is_none());
        }
        assert_eq!(org_subtype_name(&[0x00, 0x00, 0x0C], 1), None);
        assert_eq!(
            org_subtype_name(&OUI_IEEE_802_3, 5),
            Some("Energy-Efficient Ethernet")
        );
        assert_eq!(org_subtype_name(&OUI_IEEE_802_1, 13), None);
        assert_eq!(org_subtype_name(&OUI_IEEE_802_3, 6), None);
        assert_eq!(org_subtype_name(&OUI_TIA_MED, 12), None);
    }
}
