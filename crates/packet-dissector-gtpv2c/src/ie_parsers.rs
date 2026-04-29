//! Per-IE-type value parsers for GTPv2-C.
//!
//! 3GPP TS 29.274, Section 8.

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_fqdn_labels};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{
    read_be_u16, read_be_u32, read_be_u64, read_ipv4_addr, read_ipv6_addr,
};

use crate::ie;
use crate::pco;

/// IE value descriptor for label-prefixed (APN / FQDN) payloads.
///
/// Stores the raw label-encoded bytes zero-copy and renders them as a
/// dotted string at serialization time. Overrides the generic IE "value"
/// descriptor for IE types whose payload follows 3GPP TS 23.003 clause 9.1.
static FD_INLINE_APN_FQDN_VALUE: FieldDescriptor =
    FieldDescriptor::new("value", "Value", FieldType::Bytes).with_format_fn(format_fqdn_labels);

static FD_INLINE_BCE: FieldDescriptor = FieldDescriptor::new("bce", "BCE", FieldType::U8);

static FD_INLINE_CAUSE_VALUE: FieldDescriptor = FieldDescriptor {
    name: "cause_value",
    display_name: "Cause Value",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(t) => cause_name(*t),
        _ => None,
    }),
    format_fn: None,
};

static FD_INLINE_CGI: FieldDescriptor = FieldDescriptor::new("cgi", "CGI", FieldType::Object);

static FD_INLINE_CI: FieldDescriptor = FieldDescriptor::new("ci", "CI", FieldType::U16);

static FD_INLINE_CS: FieldDescriptor = FieldDescriptor::new("cs", "CS", FieldType::U8);

static FD_INLINE_DAYLIGHT_SAVING_TIME: FieldDescriptor = FieldDescriptor::new(
    "daylight_saving_time",
    "Daylight Saving Time",
    FieldType::U8,
);

static FD_INLINE_DOWNLINK: FieldDescriptor =
    FieldDescriptor::new("downlink", "APN-AMBR for Downlink", FieldType::U32);

static FD_INLINE_ECGI: FieldDescriptor = FieldDescriptor::new("ecgi", "ECGI", FieldType::Object);

static FD_INLINE_ECI: FieldDescriptor = FieldDescriptor::new("eci", "ECI", FieldType::U32);

static FD_INLINE_ENTERPRISE_ID: FieldDescriptor =
    FieldDescriptor::new("enterprise_id", "Enterprise ID", FieldType::U16);

static FD_INLINE_EXT_MACRO_ENB_ID: FieldDescriptor = FieldDescriptor::new(
    "ext_macro_enb_id",
    "Extended Macro eNB ID",
    FieldType::Bytes,
);

static FD_INLINE_FLAGS: FieldDescriptor = FieldDescriptor::new("flags", "Flags", FieldType::U8);

static FD_INLINE_GBR_DOWNLINK: FieldDescriptor =
    FieldDescriptor::new("gbr_downlink", "GBR Downlink", FieldType::U64);

static FD_INLINE_GBR_UPLINK: FieldDescriptor =
    FieldDescriptor::new("gbr_uplink", "GBR Uplink", FieldType::U64);

static FD_INLINE_INTERFACE_TYPE: FieldDescriptor = FieldDescriptor {
    name: "interface_type",
    display_name: "Interface Type",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(t) => interface_type_name(*t),
        _ => None,
    }),
    format_fn: None,
};

static FD_INLINE_IPV4_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv4_address", "IPv4 Address", FieldType::Ipv4Addr);

static FD_INLINE_IPV6_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv6_address", "IPv6 Address", FieldType::Ipv6Addr);

static FD_INLINE_IPV6_PREFIX_LENGTH: FieldDescriptor =
    FieldDescriptor::new("ipv6_prefix_length", "IPv6 Prefix Length", FieldType::U8);

static FD_INLINE_LAC: FieldDescriptor = FieldDescriptor::new("lac", "LAC", FieldType::U16);

static FD_INLINE_LAI: FieldDescriptor = FieldDescriptor::new("lai", "LAI", FieldType::Object);

static FD_INLINE_MBR_DOWNLINK: FieldDescriptor =
    FieldDescriptor::new("mbr_downlink", "MBR Downlink", FieldType::U64);

static FD_INLINE_MBR_UPLINK: FieldDescriptor =
    FieldDescriptor::new("mbr_uplink", "MBR Uplink", FieldType::U64);

static FD_INLINE_MCC: FieldDescriptor = FieldDescriptor::new("mcc", "MCC", FieldType::Bytes);

static FD_INLINE_MNC: FieldDescriptor = FieldDescriptor::new("mnc", "MNC", FieldType::Bytes);

static FD_INLINE_OFFENDING_IE_INSTANCE: FieldDescriptor = FieldDescriptor::new(
    "offending_ie_instance",
    "Offending IE Instance",
    FieldType::U8,
);

static FD_INLINE_OFFENDING_IE_LENGTH: FieldDescriptor =
    FieldDescriptor::new("offending_ie_length", "Offending IE Length", FieldType::U16);

static FD_INLINE_OFFENDING_IE_TYPE: FieldDescriptor =
    FieldDescriptor::new("offending_ie_type", "Offending IE Type", FieldType::U8);

static FD_INLINE_PCE: FieldDescriptor = FieldDescriptor::new("pce", "PCE", FieldType::U8);

static FD_INLINE_PCI: FieldDescriptor =
    FieldDescriptor::new("pci", "Pre-emption Capability", FieldType::U8);

static FD_INLINE_PDN_TYPE: FieldDescriptor = FieldDescriptor {
    name: "pdn_type",
    display_name: "PDN Type",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(t) => pdn_type_name(*t),
        _ => None,
    }),
    format_fn: None,
};

static FD_INLINE_PL: FieldDescriptor = FieldDescriptor::new("pl", "Priority Level", FieldType::U8);

static FD_INLINE_PROPRIETARY_VALUE: FieldDescriptor =
    FieldDescriptor::new("proprietary_value", "Proprietary Value", FieldType::Bytes);

static FD_INLINE_PVI: FieldDescriptor =
    FieldDescriptor::new("pvi", "Pre-emption Vulnerability", FieldType::U8);

static FD_INLINE_QCI: FieldDescriptor = FieldDescriptor::new("qci", "QCI", FieldType::U8);

static FD_INLINE_RAC: FieldDescriptor = FieldDescriptor::new("rac", "RAC", FieldType::U16);

static FD_INLINE_RAI: FieldDescriptor = FieldDescriptor::new("rai", "RAI", FieldType::Object);

static FD_INLINE_SAC: FieldDescriptor = FieldDescriptor::new("sac", "SAC", FieldType::U16);

static FD_INLINE_SAI: FieldDescriptor = FieldDescriptor::new("sai", "SAI", FieldType::Object);

static FD_INLINE_TAC: FieldDescriptor = FieldDescriptor::new("tac", "TAC", FieldType::U16);

static FD_INLINE_TAI: FieldDescriptor = FieldDescriptor::new("tai", "TAI", FieldType::Object);

static FD_INLINE_TEID: FieldDescriptor =
    FieldDescriptor::new("teid", "TEID/GRE Key", FieldType::U32);

static FD_INLINE_TIMER_UNIT: FieldDescriptor =
    FieldDescriptor::new("timer_unit", "Timer Unit", FieldType::U8);

static FD_INLINE_TIMER_VALUE: FieldDescriptor =
    FieldDescriptor::new("timer_value", "Timer value", FieldType::U8);

static FD_INLINE_TIME_ZONE: FieldDescriptor =
    FieldDescriptor::new("time_zone", "Time Zone", FieldType::U8);

static FD_INLINE_UPLINK: FieldDescriptor =
    FieldDescriptor::new("uplink", "APN-AMBR for Uplink", FieldType::U32);

static FD_INLINE_V4: FieldDescriptor = FieldDescriptor::new("v4", "V4", FieldType::U8);

static FD_INLINE_V6: FieldDescriptor = FieldDescriptor::new("v6", "V6", FieldType::U8);

static FD_HELPER_CHARGING_ID: FieldDescriptor =
    FieldDescriptor::new("charging_id", "Charging ID", FieldType::U32);
static FD_HELPER_DELAY_VALUE: FieldDescriptor =
    FieldDescriptor::new("delay_value", "Delay Value", FieldType::U8);
static FD_HELPER_EBI: FieldDescriptor = FieldDescriptor::new("ebi", "EPS Bearer ID", FieldType::U8);
static FD_HELPER_FLAGS: FieldDescriptor =
    FieldDescriptor::new("flags", "Bearer Flags", FieldType::U8);
static FD_HELPER_HOP_COUNTER: FieldDescriptor =
    FieldDescriptor::new("hop_counter", "Hop Counter", FieldType::U8);
static FD_HELPER_METRIC: FieldDescriptor = FieldDescriptor::new("metric", "Metric", FieldType::U8);
static FD_HELPER_NODE_TYPE: FieldDescriptor = FieldDescriptor {
    name: "node_type",
    display_name: "Node Type",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(t) => node_type_name(*t),
        _ => None,
    }),
    format_fn: None,
};
static FD_HELPER_PDN_TYPE: FieldDescriptor = FieldDescriptor {
    name: "pdn_type",
    display_name: "PDN Type",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(t) => pdn_type_name(*t),
        _ => None,
    }),
    format_fn: None,
};
static FD_HELPER_PORT_NUMBER: FieldDescriptor =
    FieldDescriptor::new("port_number", "Port Number", FieldType::U16);
static FD_HELPER_PTI: FieldDescriptor =
    FieldDescriptor::new("pti", "Procedure Transaction ID", FieldType::U8);
static FD_HELPER_RAT_TYPE: FieldDescriptor = FieldDescriptor {
    name: "rat_type",
    display_name: "RAT Type",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(t) => rat_type_name(*t),
        _ => None,
    }),
    format_fn: None,
};
static FD_HELPER_RESTART_COUNTER: FieldDescriptor =
    FieldDescriptor::new("restart_counter", "Restart Counter", FieldType::U8);
static FD_HELPER_RESTRICTION_TYPE: FieldDescriptor =
    FieldDescriptor::new("restriction_type", "Restriction Type", FieldType::U8);
static FD_HELPER_SELECTION_MODE: FieldDescriptor = FieldDescriptor {
    name: "selection_mode",
    display_name: "Selection Mode",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(t) => selection_mode_name(*t),
        _ => None,
    }),
    format_fn: None,
};
static FD_HELPER_SEQUENCE_NUMBER: FieldDescriptor =
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U32);
static FD_HELPER_CHARGING_CHARACTERISTICS: FieldDescriptor = FieldDescriptor::new(
    "charging_characteristics",
    "Charging Characteristics",
    FieldType::U16,
);

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Push a single-field Object IE with a U8 value (optionally masked).
fn push_single_u8<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    desc: &'static FieldDescriptor,
    mask: u8,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.is_empty() {
        buf.push_field(value_desc, FieldValue::Bytes(&[]), value_range.clone());
        return;
    }
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(desc, FieldValue::U8(data[0] & mask), offset..offset + 1);
    buf.end_container(obj_idx);
}

/// Push a single-field Object IE with a U16 value.
fn push_single_u16<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    desc: &'static FieldDescriptor,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.len() < 2 {
        buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone());
        return;
    }
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(
        desc,
        FieldValue::U16(read_be_u16(data, 0).unwrap_or_default()),
        offset..offset + 2,
    );
    buf.end_container(obj_idx);
}

/// Push a single-field Object IE with a U32 value.
fn push_single_u32<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    desc: &'static FieldDescriptor,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.len() < 4 {
        buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone());
        return;
    }
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(
        desc,
        FieldValue::U32(read_be_u32(data, 0).unwrap_or_default()),
        offset..offset + 4,
    );
    buf.end_container(obj_idx);
}

/// Decode BCD-encoded digits (IMSI, MSISDN, MEI).
///
/// Each byte contains two BCD digits: low nibble first, high nibble second.
/// Nibble value 0xF is used as padding and is skipped.
fn decode_bcd(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &byte in data {
        let low = byte & 0x0F;
        let high = (byte >> 4) & 0x0F;
        if low < 10 {
            s.push((b'0' + low) as char);
        }
        if high < 10 {
            s.push((b'0' + high) as char);
        }
    }
    s
}

/// Decode PLMN (MCC + MNC) from 3 BCD-encoded bytes.
///
/// 3GPP TS 24.008, Section 10.5.1.13:
///   Byte 0: MCC digit 2 | MCC digit 1
///   Byte 1: MNC digit 3 | MCC digit 3
///   Byte 2: MNC digit 2 | MNC digit 1
fn decode_plmn(data: &[u8]) -> (String, String) {
    if data.len() < 3 {
        return (String::new(), String::new());
    }

    let mcc1 = data[0] & 0x0F;
    let mcc2 = (data[0] >> 4) & 0x0F;
    let mcc3 = data[1] & 0x0F;
    let mnc3 = (data[1] >> 4) & 0x0F;
    let mnc1 = data[2] & 0x0F;
    let mnc2 = (data[2] >> 4) & 0x0F;

    let mcc = format!("{mcc1}{mcc2}{mcc3}");
    let mnc = if mnc3 == 0x0F {
        format!("{mnc1}{mnc2}")
    } else {
        format!("{mnc1}{mnc2}{mnc3}")
    };

    (mcc, mnc)
}

/// Push PLMN (MCC+MNC) fields into a buffer using scratch for the string data.
fn push_plmn_fields<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    plmn_len: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    let (mcc, mnc) = decode_plmn(data);
    let mcc_range = buf.push_scratch(mcc.as_bytes());
    let mnc_range = buf.push_scratch(mnc.as_bytes());
    buf.push_field(
        &FD_INLINE_MCC,
        FieldValue::Scratch(mcc_range),
        offset..offset + plmn_len,
    );
    buf.push_field(
        &FD_INLINE_MNC,
        FieldValue::Scratch(mnc_range),
        offset..offset + plmn_len,
    );
}

// ---------------------------------------------------------------------------
// Name lookup functions
// ---------------------------------------------------------------------------

/// Returns the human-readable name for a RAT Type value.
///
/// 3GPP TS 29.274, Table 8.17-1.
fn rat_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("UTRAN"),
        2 => Some("GERAN"),
        3 => Some("WLAN"),
        4 => Some("GAN"),
        5 => Some("HSPA Evolution"),
        6 => Some("EUTRAN (WB-E-UTRAN)"),
        7 => Some("Virtual"),
        8 => Some("EUTRAN-NB-IoT"),
        9 => Some("LTE-M"),
        10 => Some("NR"),
        11 => Some("WB-E-UTRAN(LEO)"),
        12 => Some("WB-E-UTRAN(MEO)"),
        13 => Some("WB-E-UTRAN(GEO)"),
        14 => Some("WB-E-UTRAN(OTHERSAT)"),
        15 => Some("EUTRAN-NB-IoT(LEO)"),
        16 => Some("EUTRAN-NB-IoT(MEO)"),
        17 => Some("EUTRAN-NB-IoT(GEO)"),
        18 => Some("EUTRAN-NB-IoT(OTHERSAT)"),
        19 => Some("LTE-M(LEO)"),
        20 => Some("LTE-M(MEO)"),
        21 => Some("LTE-M(GEO)"),
        22 => Some("LTE-M(OTHERSAT)"),
        _ => None,
    }
}

/// Returns the human-readable name for a Cause value.
///
/// 3GPP TS 29.274, Table 8.4-1.
fn cause_name(v: u8) -> Option<&'static str> {
    match v {
        2 => Some("Local Detach"),
        3 => Some("Complete Detach"),
        4 => Some("RAT changed from 3GPP to Non-3GPP"),
        5 => Some("ISR deactivation"),
        6 => Some("Error Indication received from RNC/eNodeB/S4-SGSN/MME"),
        7 => Some("IMSI Detach Only"),
        8 => Some("Reactivation Requested"),
        9 => Some("PDN reconnection to this APN disallowed"),
        10 => Some("Access changed from Non-3GPP to 3GPP"),
        11 => Some("PDN connection inactivity timer expires"),
        12 => Some("PGW not responding"),
        13 => Some("Network Failure"),
        14 => Some("QoS parameter mismatch"),
        15 => Some("EPS to 5GS Mobility"),
        16 => Some("Request accepted"),
        17 => Some("Request accepted partially"),
        18 => Some("New PDN type due to network preference"),
        19 => Some("New PDN type due to single address bearer only"),
        64 => Some("Context Not Found"),
        65 => Some("Invalid Message Format"),
        66 => Some("Version not supported by next peer"),
        67 => Some("Invalid length"),
        68 => Some("Service not supported"),
        69 => Some("Mandatory IE incorrect"),
        70 => Some("Mandatory IE missing"),
        72 => Some("System failure"),
        73 => Some("No resources available"),
        74 => Some("Semantic error in the TFT operation"),
        75 => Some("Syntactic error in the TFT operation"),
        76 => Some("Semantic errors in packet filter(s)"),
        77 => Some("Syntactic errors in packet filter(s)"),
        78 => Some("Missing or unknown APN"),
        80 => Some("GRE key not found"),
        81 => Some("Relocation failure"),
        82 => Some("Denied in RAT"),
        83 => Some("Preferred PDN type not supported"),
        84 => Some("All dynamic addresses are occupied"),
        85 => Some("UE context without TFT already activated"),
        86 => Some("Protocol type not supported"),
        87 => Some("UE not responding"),
        88 => Some("UE refuses"),
        89 => Some("Service denied"),
        90 => Some("Unable to page UE"),
        91 => Some("No memory available"),
        92 => Some("User authentication failed"),
        93 => Some("APN access denied - no subscription"),
        94 => Some("Request rejected (reason not specified)"),
        95 => Some("P-TMSI Signature mismatch"),
        96 => Some("IMSI/IMEI not known"),
        97 => Some("Semantic error in the TAD operation"),
        98 => Some("Syntactic error in the TAD operation"),
        100 => Some("Remote peer not responding"),
        101 => Some("Collision with network initiated request"),
        102 => Some("Unable to page UE due to Suspension"),
        103 => Some("Conditional IE missing"),
        104 => Some("APN Restriction type Incompatible with currently active PDN connection"),
        105 => Some(
            "Invalid overall length of the triggered response message and a piggybacked initial message",
        ),
        106 => Some("Data forwarding not supported"),
        107 => Some("Invalid reply from remote peer"),
        108 => Some("Fallback to GTPv1"),
        109 => Some("Invalid peer"),
        110 => Some("Temporarily rejected due to handover/TAU/RAU procedure in progress"),
        111 => Some("Modifications not limited to S1-U bearers"),
        112 => Some("Request rejected for a PMIPv6 reason"),
        113 => Some("APN Congestion"),
        114 => Some("Bearer handling not supported"),
        115 => Some("UE already re-attached"),
        116 => Some("Multiple PDN connections for a given APN not allowed"),
        117 => Some("Target access restricted for the subscriber"),
        119 => Some("MME/SGSN refuses due to VPLMN Policy"),
        120 => Some("GTP-C Entity Congestion"),
        121 => Some("Late Overlapping Request"),
        122 => Some("Timed out Request"),
        123 => Some("UE is temporarily not reachable due to power saving"),
        124 => Some("Relocation failure due to NAS message redirection"),
        125 => Some("UE not authorised by OCS or external AAA Server"),
        126 => Some("Multiple accesses to a PDN connection not allowed"),
        127 => Some("Request rejected due to UE capability"),
        128 => Some("S1-U Path Failure"),
        129 => Some("5GC not allowed"),
        130 => Some("PGW mismatch with network slice subscribed by the UE"),
        131 => Some("Rejection due to paging restriction"),
        _ => None,
    }
}

fn pdn_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("IPv4"),
        2 => Some("IPv6"),
        3 => Some("IPv4v6"),
        4 => Some("Non-IP"),
        5 => Some("Ethernet"),
        _ => None,
    }
}

fn selection_mode_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("MS or network provided APN, subscription verified"),
        1 => Some("MS provided APN, subscription not verified"),
        2 => Some("Network provided APN, subscription not verified"),
        _ => None,
    }
}

fn node_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("MME"),
        1 => Some("SGSN"),
        _ => None,
    }
}

fn interface_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("S1-U eNodeB GTP-U interface"),
        1 => Some("S1-U SGW GTP-U interface"),
        2 => Some("S12 RNC GTP-U interface"),
        3 => Some("S12 SGW GTP-U interface"),
        4 => Some("S5/S8 SGW GTP-U interface"),
        5 => Some("S5/S8 PGW GTP-U interface"),
        6 => Some("S5/S8 SGW GTP-C interface"),
        7 => Some("S5/S8 PGW GTP-C interface"),
        8 => Some("S5/S8 SGW PMIPv6 interface"),
        9 => Some("S5/S8 PGW PMIPv6 interface"),
        10 => Some("S11 MME GTP-C interface"),
        11 => Some("S11/S4 SGW GTP-C interface"),
        12 => Some("S10/N26 MME GTP-C interface"),
        13 => Some("S3 MME GTP-C interface"),
        14 => Some("S3 SGSN GTP-C interface"),
        15 => Some("S4 SGSN GTP-U interface"),
        16 => Some("S4 SGW GTP-U interface"),
        17 => Some("S4 SGSN GTP-C interface"),
        18 => Some("S16 SGSN GTP-C interface"),
        19 => Some("eNodeB/gNodeB GTP-U interface for DL data forwarding"),
        20 => Some("eNodeB GTP-U interface for UL data forwarding"),
        21 => Some("RNC GTP-U interface for data forwarding"),
        22 => Some("SGSN GTP-U interface for data forwarding"),
        23 => Some("SGW/UPF GTP-U interface for DL data forwarding"),
        24 => Some("Sm MBMS GW GTP-C interface"),
        25 => Some("Sn MBMS GW GTP-C interface"),
        26 => Some("Sm MME GTP-C interface"),
        27 => Some("Sn SGSN GTP-C interface"),
        28 => Some("SGW GTP-U interface for UL data forwarding"),
        29 => Some("Sn SGSN GTP-U interface"),
        30 => Some("S2b ePDG GTP-C interface"),
        31 => Some("S2b-U ePDG GTP-U interface"),
        32 => Some("S2b PGW GTP-C interface"),
        33 => Some("S2b-U PGW GTP-U interface"),
        34 => Some("S2a TWAN GTP-U interface"),
        35 => Some("S2a TWAN GTP-C interface"),
        36 => Some("S2a PGW GTP-C interface"),
        37 => Some("S2a PGW GTP-U interface"),
        38 => Some("S11 MME GTP-U interface"),
        39 => Some("S11 SGW GTP-U interface"),
        40 => Some("N26 AMF GTP-C interface"),
        41 => Some("N19mb UPF GTP-U interface"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Main dispatch — called from ie.rs
// ---------------------------------------------------------------------------

/// Push the IE "value" field (and any children) into `buf`.
///
/// This is the main entry point from `ie.rs`. It handles all IE types:
/// scalar values get pushed as a simple field, Object values get pushed
/// as Object containers, and grouped IEs get pushed as Array containers.
pub fn push_ie_value<'pkt>(
    ie_type: u8,
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    match ie_type {
        1 => {
            let s = decode_bcd(data);
            let r = buf.push_scratch(s.as_bytes());
            buf.push_field(value_desc, FieldValue::Scratch(r), value_range.clone());
        }
        2 => push_cause(data, offset, value_desc, value_range, buf),
        3 => push_single_u8(
            data,
            offset,
            &FD_HELPER_RESTART_COUNTER,
            0xFF,
            value_desc,
            value_range,
            buf,
        ),
        71 => {
            // APN — keep label-encoded bytes zero-copy; format_fn renders
            // them as a dotted string at serialization time.
            buf.push_field(
                &FD_INLINE_APN_FQDN_VALUE,
                FieldValue::Bytes(data),
                value_range.clone(),
            );
        }
        72 => push_ambr(data, offset, value_desc, value_range, buf),
        73 => push_single_u8(
            data,
            offset,
            &FD_HELPER_EBI,
            0x0F,
            value_desc,
            value_range,
            buf,
        ),
        74 => push_ip_address(data, value_desc, value_range, buf),
        75 => {
            let s = decode_bcd(data);
            let r = buf.push_scratch(s.as_bytes());
            buf.push_field(value_desc, FieldValue::Scratch(r), value_range.clone());
        }
        76 => {
            let s = decode_bcd(data);
            let r = buf.push_scratch(s.as_bytes());
            buf.push_field(value_desc, FieldValue::Scratch(r), value_range.clone());
        }
        77 => buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone()),
        78 => pco::push_pco(data, offset, value_desc, value_range, buf),
        79 => push_paa(data, offset, value_desc, value_range, buf),
        80 => push_bearer_qos(data, offset, value_desc, value_range, buf),
        81 => push_flow_qos(data, offset, value_desc, value_range, buf),
        82 => push_single_u8(
            data,
            offset,
            &FD_HELPER_RAT_TYPE,
            0xFF,
            value_desc,
            value_range,
            buf,
        ),
        83 => push_serving_network(data, offset, value_desc, value_range, buf),
        86 => push_uli(data, offset, value_desc, value_range, buf),
        87 => push_f_teid(data, offset, value_desc, value_range, buf),
        92 => push_single_u8(
            data,
            offset,
            &FD_HELPER_DELAY_VALUE,
            0xFF,
            value_desc,
            value_range,
            buf,
        ),
        // Grouped IEs — recursive parse
        93 | 109 | 180 | 181 | 191 | 195 | 208 | 209 | 214 => {
            let array_idx =
                buf.begin_container(value_desc, FieldValue::Array(0..0), value_range.clone());
            ie::parse_ies(data, offset, buf);
            buf.end_container(array_idx);
        }
        94 => push_single_u32(
            data,
            offset,
            &FD_HELPER_CHARGING_ID,
            value_desc,
            value_range,
            buf,
        ),
        95 => push_single_u16(
            data,
            offset,
            &FD_HELPER_CHARGING_CHARACTERISTICS,
            value_desc,
            value_range,
            buf,
        ),
        97 => push_single_u8(
            data,
            offset,
            &FD_HELPER_FLAGS,
            0xFF,
            value_desc,
            value_range,
            buf,
        ),
        99 => push_single_u8(
            data,
            offset,
            &FD_HELPER_PDN_TYPE,
            0x07,
            value_desc,
            value_range,
            buf,
        ),
        100 => push_single_u8(
            data,
            offset,
            &FD_HELPER_PTI,
            0xFF,
            value_desc,
            value_range,
            buf,
        ),
        113 => push_single_u8(
            data,
            offset,
            &FD_HELPER_HOP_COUNTER,
            0xFF,
            value_desc,
            value_range,
            buf,
        ),
        114 => push_ue_time_zone(data, offset, value_desc, value_range, buf),
        126 => push_single_u16(
            data,
            offset,
            &FD_HELPER_PORT_NUMBER,
            value_desc,
            value_range,
            buf,
        ),
        127 => push_single_u8(
            data,
            offset,
            &FD_HELPER_RESTRICTION_TYPE,
            0xFF,
            value_desc,
            value_range,
            buf,
        ),
        128 => push_single_u8(
            data,
            offset,
            &FD_HELPER_SELECTION_MODE,
            0x03,
            value_desc,
            value_range,
            buf,
        ),
        135 => push_single_u8(
            data,
            offset,
            &FD_HELPER_NODE_TYPE,
            0xFF,
            value_desc,
            value_range,
            buf,
        ),
        136 => {
            // FQDN — same label-prefixed encoding as APN; render via format_fn.
            buf.push_field(
                &FD_INLINE_APN_FQDN_VALUE,
                FieldValue::Bytes(data),
                value_range.clone(),
            );
        }
        155 => push_arp(data, offset, value_desc, value_range, buf),
        156 => push_epc_timer(data, offset, value_desc, value_range, buf),
        163 => pco::push_pco(data, offset, value_desc, value_range, buf), // APCO
        182 => push_single_u8(
            data,
            offset,
            &FD_HELPER_METRIC,
            0xFF,
            value_desc,
            value_range,
            buf,
        ),
        183 => push_single_u32(
            data,
            offset,
            &FD_HELPER_SEQUENCE_NUMBER,
            value_desc,
            value_range,
            buf,
        ),
        187 => push_integer_number(data, value_desc, value_range, buf),
        197 => pco::push_pco(data, offset, value_desc, value_range, buf), // ePCO
        255 => push_private_extension(data, offset, value_desc, value_range, buf),
        _ => buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone()),
    }
}

/// Parse an extended IE type value.
///
/// 3GPP TS 29.274, Section 8.2.1A.
pub fn parse_extended_ie_value(_ext_type: u16, data: &[u8], _offset: usize) -> FieldValue<'_> {
    FieldValue::Bytes(data)
}

// ---------------------------------------------------------------------------
// Individual IE push functions
// ---------------------------------------------------------------------------

fn push_cause<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.is_empty() {
        buf.push_field(value_desc, FieldValue::Bytes(&[]), value_range.clone());
        return;
    }
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(
        &FD_INLINE_CAUSE_VALUE,
        FieldValue::U8(data[0]),
        offset..offset + 1,
    );
    if data.len() >= 2 {
        let cs = (data[1] >> 1) & 0x01;
        let bce = data[1] & 0x01;
        let pce = (data[1] >> 2) & 0x01;
        buf.push_field(&FD_INLINE_CS, FieldValue::U8(cs), offset + 1..offset + 2);
        buf.push_field(&FD_INLINE_BCE, FieldValue::U8(bce), offset + 1..offset + 2);
        buf.push_field(&FD_INLINE_PCE, FieldValue::U8(pce), offset + 1..offset + 2);
    }
    if data.len() >= 6 {
        buf.push_field(
            &FD_INLINE_OFFENDING_IE_TYPE,
            FieldValue::U8(data[2]),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &FD_INLINE_OFFENDING_IE_LENGTH,
            FieldValue::U16(read_be_u16(data, 3).unwrap_or_default()),
            offset + 3..offset + 5,
        );
        buf.push_field(
            &FD_INLINE_OFFENDING_IE_INSTANCE,
            FieldValue::U8(data[5] & 0x0F),
            offset + 5..offset + 6,
        );
    }
    buf.end_container(obj_idx);
}

fn push_ambr<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.len() < 8 {
        buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone());
        return;
    }
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(
        &FD_INLINE_UPLINK,
        FieldValue::U32(read_be_u32(data, 0).unwrap_or_default()),
        offset..offset + 4,
    );
    buf.push_field(
        &FD_INLINE_DOWNLINK,
        FieldValue::U32(read_be_u32(data, 4).unwrap_or_default()),
        offset + 4..offset + 8,
    );
    buf.end_container(obj_idx);
}

fn push_ip_address<'pkt>(
    data: &'pkt [u8],
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    match data.len() {
        4 => buf.push_field(
            value_desc,
            FieldValue::Ipv4Addr(read_ipv4_addr(data, 0).unwrap_or_default()),
            value_range.clone(),
        ),
        16 => buf.push_field(
            value_desc,
            FieldValue::Ipv6Addr(read_ipv6_addr(data, 0).unwrap_or_default()),
            value_range.clone(),
        ),
        _ => buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone()),
    }
}

fn push_paa<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.is_empty() {
        buf.push_field(value_desc, FieldValue::Bytes(&[]), value_range.clone());
        return;
    }
    let pdn_type = data[0] & 0x07;
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(
        &FD_INLINE_PDN_TYPE,
        FieldValue::U8(pdn_type),
        offset..offset + 1,
    );
    match pdn_type {
        1 if data.len() >= 5 => {
            buf.push_field(
                &FD_INLINE_IPV4_ADDRESS,
                FieldValue::Ipv4Addr(read_ipv4_addr(data, 1).unwrap_or_default()),
                offset + 1..offset + 5,
            );
        }
        2 if data.len() >= 18 => {
            buf.push_field(
                &FD_INLINE_IPV6_PREFIX_LENGTH,
                FieldValue::U8(data[1]),
                offset + 1..offset + 2,
            );
            buf.push_field(
                &FD_INLINE_IPV6_ADDRESS,
                FieldValue::Ipv6Addr(read_ipv6_addr(data, 2).unwrap_or_default()),
                offset + 2..offset + 18,
            );
        }
        3 if data.len() >= 22 => {
            buf.push_field(
                &FD_INLINE_IPV6_PREFIX_LENGTH,
                FieldValue::U8(data[1]),
                offset + 1..offset + 2,
            );
            buf.push_field(
                &FD_INLINE_IPV6_ADDRESS,
                FieldValue::Ipv6Addr(read_ipv6_addr(data, 2).unwrap_or_default()),
                offset + 2..offset + 18,
            );
            buf.push_field(
                &FD_INLINE_IPV4_ADDRESS,
                FieldValue::Ipv4Addr(read_ipv4_addr(data, 18).unwrap_or_default()),
                offset + 18..offset + 22,
            );
        }
        _ => {}
    }
    buf.end_container(obj_idx);
}

fn push_bearer_qos<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.len() < 22 {
        buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone());
        return;
    }
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(
        &FD_INLINE_PCI,
        FieldValue::U8((data[0] >> 6) & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_PL,
        FieldValue::U8((data[0] >> 2) & 0x0F),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_PVI,
        FieldValue::U8(data[0] & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_QCI,
        FieldValue::U8(data[1]),
        offset + 1..offset + 2,
    );
    buf.push_field(
        &FD_INLINE_MBR_UPLINK,
        FieldValue::U64(read_5byte_u64(&data[2..7])),
        offset + 2..offset + 7,
    );
    buf.push_field(
        &FD_INLINE_MBR_DOWNLINK,
        FieldValue::U64(read_5byte_u64(&data[7..12])),
        offset + 7..offset + 12,
    );
    buf.push_field(
        &FD_INLINE_GBR_UPLINK,
        FieldValue::U64(read_5byte_u64(&data[12..17])),
        offset + 12..offset + 17,
    );
    buf.push_field(
        &FD_INLINE_GBR_DOWNLINK,
        FieldValue::U64(read_5byte_u64(&data[17..22])),
        offset + 17..offset + 22,
    );
    buf.end_container(obj_idx);
}

fn read_5byte_u64(data: &[u8]) -> u64 {
    (u64::from(data[0]) << 32)
        | (u64::from(data[1]) << 24)
        | (u64::from(data[2]) << 16)
        | (u64::from(data[3]) << 8)
        | u64::from(data[4])
}

fn push_flow_qos<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.len() < 21 {
        buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone());
        return;
    }
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(&FD_INLINE_QCI, FieldValue::U8(data[0]), offset..offset + 1);
    buf.push_field(
        &FD_INLINE_MBR_UPLINK,
        FieldValue::U64(read_5byte_u64(&data[1..6])),
        offset + 1..offset + 6,
    );
    buf.push_field(
        &FD_INLINE_MBR_DOWNLINK,
        FieldValue::U64(read_5byte_u64(&data[6..11])),
        offset + 6..offset + 11,
    );
    buf.push_field(
        &FD_INLINE_GBR_UPLINK,
        FieldValue::U64(read_5byte_u64(&data[11..16])),
        offset + 11..offset + 16,
    );
    buf.push_field(
        &FD_INLINE_GBR_DOWNLINK,
        FieldValue::U64(read_5byte_u64(&data[16..21])),
        offset + 16..offset + 21,
    );
    buf.end_container(obj_idx);
}

fn push_serving_network<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.len() < 3 {
        buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone());
        return;
    }
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    push_plmn_fields(data, offset, 3, buf);
    buf.end_container(obj_idx);
}

fn push_uli<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.is_empty() {
        buf.push_field(value_desc, FieldValue::Bytes(&[]), value_range.clone());
        return;
    }

    let flags = data[0];
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(&FD_INLINE_FLAGS, FieldValue::U8(flags), offset..offset + 1);

    let mut pos: usize = 1;

    // CGI (bit 0)
    if flags & 0x01 != 0 && pos + 7 <= data.len() {
        let sub_idx = buf.begin_container(
            &FD_INLINE_CGI,
            FieldValue::Object(0..0),
            offset + pos..offset + pos + 7,
        );
        push_plmn_fields(&data[pos..], offset + pos, 3, buf);
        buf.push_field(
            &FD_INLINE_LAC,
            FieldValue::U16(read_be_u16(data, pos + 3).unwrap_or_default()),
            offset + pos + 3..offset + pos + 5,
        );
        buf.push_field(
            &FD_INLINE_CI,
            FieldValue::U16(read_be_u16(data, pos + 5).unwrap_or_default()),
            offset + pos + 5..offset + pos + 7,
        );
        buf.end_container(sub_idx);
        pos += 7;
    }

    // SAI (bit 1)
    if flags & 0x02 != 0 && pos + 7 <= data.len() {
        let sub_idx = buf.begin_container(
            &FD_INLINE_SAI,
            FieldValue::Object(0..0),
            offset + pos..offset + pos + 7,
        );
        push_plmn_fields(&data[pos..], offset + pos, 3, buf);
        buf.push_field(
            &FD_INLINE_LAC,
            FieldValue::U16(read_be_u16(data, pos + 3).unwrap_or_default()),
            offset + pos + 3..offset + pos + 5,
        );
        buf.push_field(
            &FD_INLINE_SAC,
            FieldValue::U16(read_be_u16(data, pos + 5).unwrap_or_default()),
            offset + pos + 5..offset + pos + 7,
        );
        buf.end_container(sub_idx);
        pos += 7;
    }

    // RAI (bit 2)
    if flags & 0x04 != 0 && pos + 7 <= data.len() {
        let sub_idx = buf.begin_container(
            &FD_INLINE_RAI,
            FieldValue::Object(0..0),
            offset + pos..offset + pos + 7,
        );
        push_plmn_fields(&data[pos..], offset + pos, 3, buf);
        buf.push_field(
            &FD_INLINE_LAC,
            FieldValue::U16(read_be_u16(data, pos + 3).unwrap_or_default()),
            offset + pos + 3..offset + pos + 5,
        );
        buf.push_field(
            &FD_INLINE_RAC,
            FieldValue::U16(read_be_u16(data, pos + 5).unwrap_or_default()),
            offset + pos + 5..offset + pos + 7,
        );
        buf.end_container(sub_idx);
        pos += 7;
    }

    // TAI (bit 3)
    if flags & 0x08 != 0 && pos + 5 <= data.len() {
        let sub_idx = buf.begin_container(
            &FD_INLINE_TAI,
            FieldValue::Object(0..0),
            offset + pos..offset + pos + 5,
        );
        push_plmn_fields(&data[pos..], offset + pos, 3, buf);
        buf.push_field(
            &FD_INLINE_TAC,
            FieldValue::U16(read_be_u16(data, pos + 3).unwrap_or_default()),
            offset + pos + 3..offset + pos + 5,
        );
        buf.end_container(sub_idx);
        pos += 5;
    }

    // ECGI (bit 4)
    if flags & 0x10 != 0 && pos + 7 <= data.len() {
        let sub_idx = buf.begin_container(
            &FD_INLINE_ECGI,
            FieldValue::Object(0..0),
            offset + pos..offset + pos + 7,
        );
        push_plmn_fields(&data[pos..], offset + pos, 3, buf);
        let eci = read_be_u32(data, pos + 3).unwrap_or_default() & 0x0FFF_FFFF;
        buf.push_field(
            &FD_INLINE_ECI,
            FieldValue::U32(eci),
            offset + pos + 3..offset + pos + 7,
        );
        buf.end_container(sub_idx);
        pos += 7;
    }

    // LAI (bit 5)
    if flags & 0x20 != 0 && pos + 5 <= data.len() {
        let sub_idx = buf.begin_container(
            &FD_INLINE_LAI,
            FieldValue::Object(0..0),
            offset + pos..offset + pos + 5,
        );
        push_plmn_fields(&data[pos..], offset + pos, 3, buf);
        buf.push_field(
            &FD_INLINE_LAC,
            FieldValue::U16(read_be_u16(data, pos + 3).unwrap_or_default()),
            offset + pos + 3..offset + pos + 5,
        );
        buf.end_container(sub_idx);
        pos += 5;
    }

    // Extended Macro eNB ID (bit 6)
    if flags & 0x40 != 0 && pos + 6 <= data.len() {
        buf.push_field(
            &FD_INLINE_EXT_MACRO_ENB_ID,
            FieldValue::Bytes(&data[pos..pos + 6]),
            offset + pos..offset + pos + 6,
        );
        pos += 6;
    }

    if pos < data.len() {
        let _ = pos;
    }

    buf.end_container(obj_idx);
}

fn push_f_teid<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.len() < 5 {
        buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone());
        return;
    }
    let v4 = (data[0] >> 7) & 0x01;
    let v6 = (data[0] >> 6) & 0x01;
    let interface_type = data[0] & 0x3F;
    let teid = read_be_u32(data, 1).unwrap_or_default();

    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(&FD_INLINE_V4, FieldValue::U8(v4), offset..offset + 1);
    buf.push_field(&FD_INLINE_V6, FieldValue::U8(v6), offset..offset + 1);
    buf.push_field(
        &FD_INLINE_INTERFACE_TYPE,
        FieldValue::U8(interface_type),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_TEID,
        FieldValue::U32(teid),
        offset + 1..offset + 5,
    );

    let mut pos: usize = 5;
    if v4 != 0 && pos + 4 <= data.len() {
        buf.push_field(
            &FD_INLINE_IPV4_ADDRESS,
            FieldValue::Ipv4Addr(read_ipv4_addr(data, pos).unwrap_or_default()),
            offset + pos..offset + pos + 4,
        );
        pos += 4;
    }
    if v6 != 0 && pos + 16 <= data.len() {
        buf.push_field(
            &FD_INLINE_IPV6_ADDRESS,
            FieldValue::Ipv6Addr(read_ipv6_addr(data, pos).unwrap_or_default()),
            offset + pos..offset + pos + 16,
        );
    }
    buf.end_container(obj_idx);
}

fn push_ue_time_zone<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.len() < 2 {
        buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone());
        return;
    }
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(
        &FD_INLINE_TIME_ZONE,
        FieldValue::U8(data[0]),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_DAYLIGHT_SAVING_TIME,
        FieldValue::U8(data[1] & 0x03),
        offset + 1..offset + 2,
    );
    buf.end_container(obj_idx);
}

fn push_arp<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.is_empty() {
        buf.push_field(value_desc, FieldValue::Bytes(&[]), value_range.clone());
        return;
    }
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(
        &FD_INLINE_PCI,
        FieldValue::U8((data[0] >> 6) & 0x01),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_PL,
        FieldValue::U8((data[0] >> 2) & 0x0F),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_PVI,
        FieldValue::U8(data[0] & 0x01),
        offset..offset + 1,
    );
    buf.end_container(obj_idx);
}

fn push_epc_timer<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.is_empty() {
        buf.push_field(value_desc, FieldValue::Bytes(&[]), value_range.clone());
        return;
    }
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(
        &FD_INLINE_TIMER_UNIT,
        FieldValue::U8((data[0] >> 5) & 0x07),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_INLINE_TIMER_VALUE,
        FieldValue::U8(data[0] & 0x1F),
        offset..offset + 1,
    );
    buf.end_container(obj_idx);
}

fn push_integer_number<'pkt>(
    data: &'pkt [u8],
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    let value = match data.len() {
        1 => FieldValue::U8(data[0]),
        2 => FieldValue::U16(read_be_u16(data, 0).unwrap_or_default()),
        4 => FieldValue::U32(read_be_u32(data, 0).unwrap_or_default()),
        8 => FieldValue::U64(read_be_u64(data, 0).unwrap_or_default()),
        _ => FieldValue::Bytes(data),
    };
    buf.push_field(value_desc, value, value_range.clone());
}

fn push_private_extension<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &core::ops::Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.len() < 2 {
        buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone());
        return;
    }
    let obj_idx = buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone());
    buf.push_field(
        &FD_INLINE_ENTERPRISE_ID,
        FieldValue::U16(read_be_u16(data, 0).unwrap_or_default()),
        offset..offset + 2,
    );
    buf.push_field(
        &FD_INLINE_PROPRIETARY_VALUE,
        FieldValue::Bytes(&data[2..]),
        offset + 2..offset + data.len(),
    );
    buf.end_container(obj_idx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;

    // Test helper: push an IE value into a fresh buffer and return it.
    fn push_and_get<'a>(ie_type: u8, data: &'a [u8], offset: usize) -> DissectBuffer<'a> {
        let mut buf = DissectBuffer::new();
        static FD_VALUE: FieldDescriptor = FieldDescriptor::new("value", "Value", FieldType::Bytes);
        let range = offset..offset + data.len();
        push_ie_value(ie_type, data, offset, &FD_VALUE, &range, &mut buf);
        buf
    }

    /// Get the first field's value from the buffer.
    fn first_value<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>) -> &'a FieldValue<'pkt> {
        &buf.fields()[0].value
    }

    /// Get a named field value from the first Object container.
    fn obj_field_value<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        name: &str,
    ) -> Option<&'a FieldValue<'pkt>> {
        let FieldValue::Object(ref r) = buf.fields()[0].value else {
            return None;
        };
        buf.nested_fields(r)
            .iter()
            .find(|f| f.name() == name)
            .map(|f| &f.value)
    }

    /// Check if the first Object contains a field with the given name.
    fn obj_has_field(buf: &DissectBuffer<'_>, name: &str) -> bool {
        let FieldValue::Object(ref r) = buf.fields()[0].value else {
            return false;
        };
        buf.nested_fields(r).iter().any(|f| f.name() == name)
    }

    /// Resolve display name on first Object's fields.
    fn obj_display_name<'pkt>(buf: &DissectBuffer<'pkt>, name: &str) -> Option<&'static str> {
        let FieldValue::Object(ref r) = buf.fields()[0].value else {
            return None;
        };
        buf.resolve_nested_display_name(r, name)
    }

    // 1. IMSI (type 1)
    #[test]
    fn imsi_bcd_decode() {
        let buf = push_and_get(1, &[0x21, 0x43, 0x65], 0);
        let FieldValue::Scratch(ref r) = buf.fields()[0].value else {
            panic!("expected Scratch")
        };
        assert_eq!(&buf.scratch()[r.start as usize..r.end as usize], b"123456");
    }

    // 2. Cause (type 2)
    #[test]
    fn cause_one_byte() {
        let buf = push_and_get(2, &[16], 0);
        assert_eq!(
            obj_field_value(&buf, "cause_value"),
            Some(&FieldValue::U8(16))
        );
        assert_eq!(
            obj_display_name(&buf, "cause_value_name"),
            Some("Request accepted")
        );
    }

    #[test]
    fn cause_unknown_no_name() {
        let buf = push_and_get(2, &[0], 0);
        assert_eq!(
            obj_field_value(&buf, "cause_value"),
            Some(&FieldValue::U8(0))
        );
        assert_eq!(obj_display_name(&buf, "cause_value_name"), None);
    }

    #[test]
    fn cause_two_bytes_with_flags() {
        let buf = push_and_get(2, &[16, 0x07], 0);
        assert_eq!(obj_field_value(&buf, "cs"), Some(&FieldValue::U8(1)));
        assert_eq!(obj_field_value(&buf, "bce"), Some(&FieldValue::U8(1)));
        assert_eq!(obj_field_value(&buf, "pce"), Some(&FieldValue::U8(1)));
    }

    #[test]
    fn cause_six_bytes_with_offending_ie() {
        let buf = push_and_get(2, &[16, 0x00, 73, 0x00, 0x01, 0x02], 0);
        assert_eq!(
            obj_field_value(&buf, "offending_ie_type"),
            Some(&FieldValue::U8(73))
        );
        assert_eq!(
            obj_field_value(&buf, "offending_ie_length"),
            Some(&FieldValue::U16(1))
        );
        assert_eq!(
            obj_field_value(&buf, "offending_ie_instance"),
            Some(&FieldValue::U8(0x02))
        );
    }

    #[test]
    fn cause_empty() {
        let buf = push_and_get(2, &[], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[]));
    }

    // 3. Recovery (type 3)
    #[test]
    fn recovery_single_u8() {
        let buf = push_and_get(3, &[42], 0);
        assert_eq!(
            obj_field_value(&buf, "restart_counter"),
            Some(&FieldValue::U8(42))
        );
    }

    #[test]
    fn recovery_empty() {
        let buf = push_and_get(3, &[], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[]));
    }

    // 4. APN (type 71)
    #[test]
    fn apn_dns_labels() {
        // Stored zero-copy as label-encoded bytes; rendered as "foo.bar"
        // by the descriptor's format_fn at serialization time.
        let data = [3, b'f', b'o', b'o', 3, b'b', b'a', b'r'];
        let buf = push_and_get(71, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(&data));
    }

    // 5. AMBR (type 72)
    #[test]
    fn ambr_valid() {
        let mut data = [0u8; 8];
        data[..4].copy_from_slice(&1000u32.to_be_bytes());
        data[4..].copy_from_slice(&2000u32.to_be_bytes());
        let buf = push_and_get(72, &data, 0);
        assert_eq!(
            obj_field_value(&buf, "uplink"),
            Some(&FieldValue::U32(1000))
        );
        assert_eq!(
            obj_field_value(&buf, "downlink"),
            Some(&FieldValue::U32(2000))
        );
    }

    #[test]
    fn ambr_truncated() {
        let buf = push_and_get(72, &[1, 2, 3], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[1, 2, 3]));
    }

    // 6. EBI (type 73)
    #[test]
    fn ebi_masked() {
        let buf = push_and_get(73, &[0xFF], 0);
        assert_eq!(obj_field_value(&buf, "ebi"), Some(&FieldValue::U8(0x0F)));
    }

    // 7. IP Address (type 74)
    #[test]
    fn ip_address_ipv4() {
        let buf = push_and_get(74, &[10, 0, 0, 1], 0);
        assert_eq!(*first_value(&buf), FieldValue::Ipv4Addr([10, 0, 0, 1]));
    }

    #[test]
    fn ip_address_ipv6() {
        let mut data = [0u8; 16];
        data[0] = 0xFE;
        data[1] = 0x80;
        let buf = push_and_get(74, &data, 0);
        assert_eq!(*first_value(&buf), FieldValue::Ipv6Addr(data));
    }

    #[test]
    fn ip_address_unknown_len() {
        let buf = push_and_get(74, &[1, 2, 3], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[1, 2, 3]));
    }

    // 8. MEI (type 75)
    #[test]
    fn mei_bcd() {
        let buf = push_and_get(75, &[0x21, 0x43], 0);
        let FieldValue::Scratch(ref r) = buf.fields()[0].value else {
            panic!("expected Scratch")
        };
        assert_eq!(&buf.scratch()[r.start as usize..r.end as usize], b"1234");
    }

    // 9. MSISDN (type 76)
    #[test]
    fn msisdn_bcd() {
        let buf = push_and_get(76, &[0x21, 0x43], 0);
        let FieldValue::Scratch(ref r) = buf.fields()[0].value else {
            panic!("expected Scratch")
        };
        assert_eq!(&buf.scratch()[r.start as usize..r.end as usize], b"1234");
    }

    // 10. Indication (type 77)
    #[test]
    fn indication_raw_bytes() {
        let buf = push_and_get(77, &[0xAB, 0xCD], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[0xAB, 0xCD]));
    }

    // 11. PAA (type 79)
    #[test]
    fn paa_ipv4() {
        let buf = push_and_get(79, &[0x01, 10, 0, 0, 1], 0);
        assert_eq!(obj_field_value(&buf, "pdn_type"), Some(&FieldValue::U8(1)));
        assert_eq!(obj_display_name(&buf, "pdn_type_name"), Some("IPv4"));
        assert_eq!(
            obj_field_value(&buf, "ipv4_address"),
            Some(&FieldValue::Ipv4Addr([10, 0, 0, 1]))
        );
    }

    #[test]
    fn paa_ipv6() {
        let mut data = [0u8; 18];
        data[0] = 0x02;
        data[1] = 64;
        data[2] = 0xFE;
        data[3] = 0x80;
        let buf = push_and_get(79, &data, 0);
        assert_eq!(obj_field_value(&buf, "pdn_type"), Some(&FieldValue::U8(2)));
        assert_eq!(
            obj_field_value(&buf, "ipv6_prefix_length"),
            Some(&FieldValue::U8(64))
        );
        assert!(matches!(
            obj_field_value(&buf, "ipv6_address"),
            Some(FieldValue::Ipv6Addr(_))
        ));
    }

    #[test]
    fn paa_ipv4v6() {
        let mut data = [0u8; 22];
        data[0] = 0x03;
        data[1] = 64;
        data[18] = 10;
        data[21] = 1;
        let buf = push_and_get(79, &data, 0);
        assert_eq!(obj_field_value(&buf, "pdn_type"), Some(&FieldValue::U8(3)));
        assert_eq!(
            obj_field_value(&buf, "ipv4_address"),
            Some(&FieldValue::Ipv4Addr([10, 0, 0, 1]))
        );
        assert!(matches!(
            obj_field_value(&buf, "ipv6_address"),
            Some(FieldValue::Ipv6Addr(_))
        ));
    }

    #[test]
    fn paa_empty() {
        let buf = push_and_get(79, &[], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[]));
    }

    #[test]
    fn paa_short() {
        let buf = push_and_get(79, &[0x01, 10], 0);
        assert_eq!(obj_field_value(&buf, "pdn_type"), Some(&FieldValue::U8(1)));
    }

    // 12. Bearer QoS (type 80)
    #[test]
    fn bearer_qos_valid() {
        let mut data = [0u8; 22];
        data[0] = 0x55;
        data[1] = 9;
        let buf = push_and_get(80, &data, 0);
        assert_eq!(obj_field_value(&buf, "pci"), Some(&FieldValue::U8(1)));
        assert_eq!(obj_field_value(&buf, "pl"), Some(&FieldValue::U8(5)));
        assert_eq!(obj_field_value(&buf, "pvi"), Some(&FieldValue::U8(1)));
        assert_eq!(obj_field_value(&buf, "qci"), Some(&FieldValue::U8(9)));
    }

    #[test]
    fn bearer_qos_truncated() {
        let buf = push_and_get(80, &[1, 2, 3], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[1, 2, 3]));
    }

    // 13. Flow QoS (type 81)
    #[test]
    fn flow_qos_valid() {
        let mut data = [0u8; 21];
        data[0] = 9;
        let buf = push_and_get(81, &data, 0);
        assert_eq!(obj_field_value(&buf, "qci"), Some(&FieldValue::U8(9)));
        assert!(matches!(
            obj_field_value(&buf, "mbr_uplink"),
            Some(FieldValue::U64(_))
        ));
    }

    #[test]
    fn flow_qos_truncated() {
        let buf = push_and_get(81, &[1, 2], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[1, 2]));
    }

    // 14. RAT Type (type 82)
    #[test]
    fn rat_type_with_name() {
        let buf = push_and_get(82, &[6], 0);
        assert_eq!(obj_field_value(&buf, "rat_type"), Some(&FieldValue::U8(6)));
        assert_eq!(
            obj_display_name(&buf, "rat_type_name"),
            Some("EUTRAN (WB-E-UTRAN)")
        );
    }

    #[test]
    fn rat_type_unknown_no_name() {
        let buf = push_and_get(82, &[255], 0);
        assert_eq!(
            obj_field_value(&buf, "rat_type"),
            Some(&FieldValue::U8(255))
        );
        assert_eq!(obj_display_name(&buf, "rat_type_name"), None);
    }

    // 15. Serving Network (type 83)
    #[test]
    fn serving_network_2digit_mnc() {
        let buf = push_and_get(83, &[0x21, 0xF3, 0x54], 0);
        let FieldValue::Object(ref r) = buf.fields()[0].value else {
            panic!("expected Object")
        };
        let mcc = buf
            .nested_fields(r)
            .iter()
            .find(|f| f.name() == "mcc")
            .unwrap();
        let FieldValue::Scratch(ref mr) = mcc.value else {
            panic!("expected Scratch")
        };
        assert_eq!(&buf.scratch()[mr.start as usize..mr.end as usize], b"123");
        let mnc = buf
            .nested_fields(r)
            .iter()
            .find(|f| f.name() == "mnc")
            .unwrap();
        let FieldValue::Scratch(ref nr) = mnc.value else {
            panic!("expected Scratch")
        };
        assert_eq!(&buf.scratch()[nr.start as usize..nr.end as usize], b"45");
    }

    #[test]
    fn serving_network_3digit_mnc() {
        let buf = push_and_get(83, &[0x13, 0x00, 0x62], 0);
        let FieldValue::Object(ref r) = buf.fields()[0].value else {
            panic!("expected Object")
        };
        let mcc = buf
            .nested_fields(r)
            .iter()
            .find(|f| f.name() == "mcc")
            .unwrap();
        let FieldValue::Scratch(ref mr) = mcc.value else {
            panic!("expected Scratch")
        };
        assert_eq!(&buf.scratch()[mr.start as usize..mr.end as usize], b"310");
        let mnc = buf
            .nested_fields(r)
            .iter()
            .find(|f| f.name() == "mnc")
            .unwrap();
        let FieldValue::Scratch(ref nr) = mnc.value else {
            panic!("expected Scratch")
        };
        assert_eq!(&buf.scratch()[nr.start as usize..nr.end as usize], b"260");
    }

    #[test]
    fn serving_network_truncated() {
        let buf = push_and_get(83, &[0x21, 0xF3], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[0x21, 0xF3]));
    }

    // 16. ULI (type 86)
    #[test]
    fn uli_tai_ecgi() {
        let mut data = vec![0x18u8];
        data.extend_from_slice(&[0x21, 0xF3, 0x54, 0x00, 0x01]);
        data.extend_from_slice(&[0x21, 0xF3, 0x54, 0x00, 0x00, 0x00, 0x01]);
        let buf = push_and_get(86, &data, 0);
        assert!(obj_has_field(&buf, "tai"));
        assert!(obj_has_field(&buf, "ecgi"));
    }

    #[test]
    fn uli_empty() {
        let buf = push_and_get(86, &[], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[]));
    }

    // 17. F-TEID (type 87)
    #[test]
    fn fteid_v4_only() {
        let mut data = vec![0x8A];
        data.extend_from_slice(&0x12345678u32.to_be_bytes());
        data.extend_from_slice(&[10, 0, 0, 1]);
        let buf = push_and_get(87, &data, 0);
        assert_eq!(obj_field_value(&buf, "v4"), Some(&FieldValue::U8(1)));
        assert_eq!(obj_field_value(&buf, "v6"), Some(&FieldValue::U8(0)));
        assert_eq!(
            obj_field_value(&buf, "interface_type"),
            Some(&FieldValue::U8(10))
        );
        assert_eq!(
            obj_display_name(&buf, "interface_type_name"),
            Some("S11 MME GTP-C interface")
        );
        assert_eq!(
            obj_field_value(&buf, "teid"),
            Some(&FieldValue::U32(0x12345678))
        );
        assert_eq!(
            obj_field_value(&buf, "ipv4_address"),
            Some(&FieldValue::Ipv4Addr([10, 0, 0, 1]))
        );
    }

    #[test]
    fn fteid_interface_type_unknown_no_name() {
        let mut data = vec![0x80 | 63];
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&[10, 0, 0, 1]);
        let buf = push_and_get(87, &data, 0);
        assert_eq!(
            obj_field_value(&buf, "interface_type"),
            Some(&FieldValue::U8(63))
        );
        assert_eq!(obj_display_name(&buf, "interface_type_name"), None);
    }

    #[test]
    fn fteid_v6_only() {
        let mut data = vec![0x40 | 10];
        data.extend_from_slice(&0x00000001u32.to_be_bytes());
        let mut ipv6 = [0u8; 16];
        ipv6[0] = 0xFE;
        ipv6[1] = 0x80;
        data.extend_from_slice(&ipv6);
        let buf = push_and_get(87, &data, 0);
        assert_eq!(obj_field_value(&buf, "v6"), Some(&FieldValue::U8(1)));
        assert_eq!(obj_field_value(&buf, "v4"), Some(&FieldValue::U8(0)));
        assert_eq!(
            obj_field_value(&buf, "ipv6_address"),
            Some(&FieldValue::Ipv6Addr(ipv6))
        );
    }

    #[test]
    fn fteid_v4_v6() {
        let mut data = vec![0xC0 | 5];
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&[192, 168, 1, 1]);
        let mut ipv6 = [0u8; 16];
        ipv6[15] = 1;
        data.extend_from_slice(&ipv6);
        let buf = push_and_get(87, &data, 0);
        assert_eq!(obj_field_value(&buf, "v4"), Some(&FieldValue::U8(1)));
        assert_eq!(obj_field_value(&buf, "v6"), Some(&FieldValue::U8(1)));
        assert_eq!(
            obj_field_value(&buf, "ipv4_address"),
            Some(&FieldValue::Ipv4Addr([192, 168, 1, 1]))
        );
        assert_eq!(
            obj_field_value(&buf, "ipv6_address"),
            Some(&FieldValue::Ipv6Addr(ipv6))
        );
    }

    #[test]
    fn fteid_truncated() {
        let buf = push_and_get(87, &[0x80, 0, 0], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[0x80, 0, 0]));
    }

    // 18-37: Simple IEs
    #[test]
    fn delay_value() {
        let buf = push_and_get(92, &[50], 0);
        assert_eq!(
            obj_field_value(&buf, "delay_value"),
            Some(&FieldValue::U8(50))
        );
    }
    #[test]
    fn grouped_ie_with_recovery() {
        let data = [3u8, 0x00, 0x01, 0x00, 42];
        let buf = push_and_get(93, &data, 0);
        assert!(matches!(*first_value(&buf), FieldValue::Array(_)));
    }
    #[test]
    fn charging_id() {
        let data = 0xDEADBEEFu32.to_be_bytes();
        let buf = push_and_get(94, &data, 0);
        assert_eq!(
            obj_field_value(&buf, "charging_id"),
            Some(&FieldValue::U32(0xDEADBEEF))
        );
    }
    #[test]
    fn charging_characteristics() {
        let buf = push_and_get(95, &[0x08, 0x00], 0);
        assert_eq!(
            obj_field_value(&buf, "charging_characteristics"),
            Some(&FieldValue::U16(0x0800))
        );
    }
    #[test]
    fn bearer_flags() {
        let buf = push_and_get(97, &[0x0F], 0);
        assert_eq!(obj_field_value(&buf, "flags"), Some(&FieldValue::U8(0x0F)));
    }
    #[test]
    fn pdn_type_with_name() {
        let buf = push_and_get(99, &[0xFF], 0);
        assert_eq!(
            obj_field_value(&buf, "pdn_type"),
            Some(&FieldValue::U8(0x07))
        );
        assert_eq!(obj_display_name(&buf, "pdn_type_name"), None);
        let buf = push_and_get(99, &[1], 0);
        assert_eq!(obj_field_value(&buf, "pdn_type"), Some(&FieldValue::U8(1)));
        assert_eq!(obj_display_name(&buf, "pdn_type_name"), Some("IPv4"));
    }
    #[test]
    fn pti() {
        let buf = push_and_get(100, &[5], 0);
        assert_eq!(obj_field_value(&buf, "pti"), Some(&FieldValue::U8(5)));
    }
    #[test]
    fn hop_counter() {
        let buf = push_and_get(113, &[3], 0);
        assert_eq!(
            obj_field_value(&buf, "hop_counter"),
            Some(&FieldValue::U8(3))
        );
    }
    #[test]
    fn ue_time_zone() {
        let buf = push_and_get(114, &[0x40, 0x01], 0);
        assert_eq!(
            obj_field_value(&buf, "time_zone"),
            Some(&FieldValue::U8(0x40))
        );
        assert_eq!(
            obj_field_value(&buf, "daylight_saving_time"),
            Some(&FieldValue::U8(0x01))
        );
    }
    #[test]
    fn ue_time_zone_truncated() {
        let buf = push_and_get(114, &[0x40], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[0x40]));
    }
    #[test]
    fn port_number() {
        let buf = push_and_get(126, &[0x1F, 0x90], 0);
        assert_eq!(
            obj_field_value(&buf, "port_number"),
            Some(&FieldValue::U16(8080))
        );
    }
    #[test]
    fn restriction_type() {
        let buf = push_and_get(127, &[2], 0);
        assert_eq!(
            obj_field_value(&buf, "restriction_type"),
            Some(&FieldValue::U8(2))
        );
    }
    #[test]
    fn selection_mode_with_name() {
        let buf = push_and_get(128, &[0xFF], 0);
        assert_eq!(
            obj_field_value(&buf, "selection_mode"),
            Some(&FieldValue::U8(0x03))
        );
        assert_eq!(obj_display_name(&buf, "selection_mode_name"), None);
        let buf = push_and_get(128, &[0], 0);
        assert_eq!(
            obj_field_value(&buf, "selection_mode"),
            Some(&FieldValue::U8(0))
        );
        assert_eq!(
            obj_display_name(&buf, "selection_mode_name"),
            Some("MS or network provided APN, subscription verified")
        );
    }
    #[test]
    fn node_type_with_name() {
        let buf = push_and_get(135, &[1], 0);
        assert_eq!(obj_field_value(&buf, "node_type"), Some(&FieldValue::U8(1)));
        assert_eq!(obj_display_name(&buf, "node_type_name"), Some("SGSN"));
    }
    #[test]
    fn node_type_unknown_no_name() {
        let buf = push_and_get(135, &[2], 0);
        assert_eq!(obj_field_value(&buf, "node_type"), Some(&FieldValue::U8(2)));
        assert_eq!(obj_display_name(&buf, "node_type_name"), None);
    }
    #[test]
    fn fqdn_dns_labels() {
        // Stored zero-copy as label-encoded bytes; rendered as
        // "example.com" by format_fn at serialization time.
        let data = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
        ];
        let buf = push_and_get(136, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(&data));
    }
    #[test]
    fn arp_valid() {
        let buf = push_and_get(155, &[0x69], 0);
        assert_eq!(obj_field_value(&buf, "pci"), Some(&FieldValue::U8(1)));
        assert_eq!(obj_field_value(&buf, "pl"), Some(&FieldValue::U8(10)));
        assert_eq!(obj_field_value(&buf, "pvi"), Some(&FieldValue::U8(1)));
    }
    #[test]
    fn arp_empty() {
        let buf = push_and_get(155, &[], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[]));
    }
    #[test]
    fn epc_timer() {
        let buf = push_and_get(156, &[0x6A], 0);
        assert_eq!(
            obj_field_value(&buf, "timer_unit"),
            Some(&FieldValue::U8(3))
        );
        assert_eq!(
            obj_field_value(&buf, "timer_value"),
            Some(&FieldValue::U8(10))
        );
    }
    #[test]
    fn epc_timer_empty() {
        let buf = push_and_get(156, &[], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[]));
    }
    #[test]
    fn metric() {
        let buf = push_and_get(182, &[99], 0);
        assert_eq!(obj_field_value(&buf, "metric"), Some(&FieldValue::U8(99)));
    }
    #[test]
    fn sequence_number() {
        let data = 0x00010002u32.to_be_bytes();
        let buf = push_and_get(183, &data, 0);
        assert_eq!(
            obj_field_value(&buf, "sequence_number"),
            Some(&FieldValue::U32(0x00010002))
        );
    }

    // 36. Integer Number (type 187)
    #[test]
    fn integer_number_u8() {
        let buf = push_and_get(187, &[42], 0);
        assert_eq!(*first_value(&buf), FieldValue::U8(42));
    }
    #[test]
    fn integer_number_u16() {
        let buf = push_and_get(187, &[0x00, 0x01], 0);
        assert_eq!(*first_value(&buf), FieldValue::U16(1));
    }
    #[test]
    fn integer_number_u32() {
        let buf = push_and_get(187, &[0, 0, 0, 1], 0);
        assert_eq!(*first_value(&buf), FieldValue::U32(1));
    }
    #[test]
    fn integer_number_u64() {
        let buf = push_and_get(187, &[0, 0, 0, 0, 0, 0, 0, 1], 0);
        assert_eq!(*first_value(&buf), FieldValue::U64(1));
    }
    #[test]
    fn integer_number_other() {
        let buf = push_and_get(187, &[1, 2, 3], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[1, 2, 3]));
    }

    // 37. Private Extension (type 255)
    #[test]
    fn private_extension() {
        let buf = push_and_get(255, &[0x00, 0x0A, 0xDE, 0xAD], 0);
        assert_eq!(
            obj_field_value(&buf, "enterprise_id"),
            Some(&FieldValue::U16(10))
        );
        assert_eq!(
            obj_field_value(&buf, "proprietary_value"),
            Some(&FieldValue::Bytes(&[0xDE, 0xAD]))
        );
    }
    #[test]
    fn private_extension_truncated() {
        let buf = push_and_get(255, &[0x01], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[0x01]));
    }

    // 38. Extended IE
    #[test]
    fn extended_ie() {
        let result = parse_extended_ie_value(1, &[0xAA, 0xBB], 0);
        assert_eq!(result, FieldValue::Bytes(&[0xAA, 0xBB]));
    }

    // 39. Unknown type
    #[test]
    fn unknown_type_returns_bytes() {
        let buf = push_and_get(200, &[1, 2, 3], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[1, 2, 3]));
    }

    // ULI sub-type tests
    #[test]
    fn uli_cgi() {
        let mut data = vec![0x01];
        data.extend_from_slice(&[0x21, 0xF3, 0x54, 0x00, 0x01, 0x00, 0x02]);
        let buf = push_and_get(86, &data, 0);
        assert!(obj_has_field(&buf, "cgi"));
    }
    #[test]
    fn uli_sai() {
        let mut data = vec![0x02];
        data.extend_from_slice(&[0x21, 0xF3, 0x54, 0x00, 0x01, 0x00, 0x03]);
        let buf = push_and_get(86, &data, 0);
        assert!(obj_has_field(&buf, "sai"));
    }
    #[test]
    fn uli_rai() {
        let mut data = vec![0x04];
        data.extend_from_slice(&[0x21, 0xF3, 0x54, 0x00, 0x01, 0x00, 0x04]);
        let buf = push_and_get(86, &data, 0);
        assert!(obj_has_field(&buf, "rai"));
    }
    #[test]
    fn uli_lai() {
        let mut data = vec![0x20];
        data.extend_from_slice(&[0x21, 0xF3, 0x54, 0x00, 0x05]);
        let buf = push_and_get(86, &data, 0);
        assert!(obj_has_field(&buf, "lai"));
    }
    #[test]
    fn uli_ext_macro_enb_id() {
        let mut data = vec![0x40];
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let buf = push_and_get(86, &data, 0);
        assert!(obj_has_field(&buf, "ext_macro_enb_id"));
    }

    // Additional single-field edge cases
    #[test]
    fn single_u8_field_empty() {
        let buf = push_and_get(73, &[], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[]));
    }
    #[test]
    fn single_u16_field_truncated() {
        let buf = push_and_get(95, &[0x08], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[0x08]));
    }
    #[test]
    fn single_u32_field_truncated() {
        let buf = push_and_get(94, &[0x00, 0x01], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[0x00, 0x01]));
    }
    #[test]
    fn pdn_type_all_values() {
        let buf = push_and_get(99, &[2], 0);
        assert_eq!(obj_display_name(&buf, "pdn_type_name"), Some("IPv6"));
        let buf = push_and_get(99, &[3], 0);
        assert_eq!(obj_display_name(&buf, "pdn_type_name"), Some("IPv4v6"));
        let buf = push_and_get(99, &[4], 0);
        assert_eq!(obj_display_name(&buf, "pdn_type_name"), Some("Non-IP"));
        let buf = push_and_get(99, &[5], 0);
        assert_eq!(obj_display_name(&buf, "pdn_type_name"), Some("Ethernet"));
    }
    #[test]
    fn selection_mode_values() {
        let buf = push_and_get(128, &[1], 0);
        assert_eq!(
            obj_display_name(&buf, "selection_mode_name"),
            Some("MS provided APN, subscription not verified")
        );
        let buf = push_and_get(128, &[2], 0);
        assert_eq!(
            obj_display_name(&buf, "selection_mode_name"),
            Some("Network provided APN, subscription not verified")
        );
    }
    #[test]
    fn node_type_mme() {
        let buf = push_and_get(135, &[0], 0);
        assert_eq!(obj_field_value(&buf, "node_type"), Some(&FieldValue::U8(0)));
        assert_eq!(obj_display_name(&buf, "node_type_name"), Some("MME"));
    }
    #[test]
    fn bcd_with_f_padding() {
        let buf = push_and_get(1, &[0x21, 0x43, 0xF5], 0);
        let FieldValue::Scratch(ref r) = buf.fields()[0].value else {
            panic!("expected Scratch")
        };
        assert_eq!(&buf.scratch()[r.start as usize..r.end as usize], b"12345");
    }
    #[test]
    fn bcd_all_f_padding() {
        let buf = push_and_get(1, &[0xFF], 0);
        let FieldValue::Scratch(ref r) = buf.fields()[0].value else {
            panic!("expected Scratch")
        };
        assert_eq!(&buf.scratch()[r.start as usize..r.end as usize], b"");
    }
    #[test]
    fn bcd_empty() {
        let buf = push_and_get(1, &[], 0);
        let FieldValue::Scratch(ref r) = buf.fields()[0].value else {
            panic!("expected Scratch")
        };
        assert_eq!(&buf.scratch()[r.start as usize..r.end as usize], b"");
    }
    #[test]
    fn bcd_single_digit() {
        let buf = push_and_get(1, &[0xF1], 0);
        let FieldValue::Scratch(ref r) = buf.fields()[0].value else {
            panic!("expected Scratch")
        };
        assert_eq!(&buf.scratch()[r.start as usize..r.end as usize], b"1");
    }
    #[test]
    fn plmn_short_data() {
        let buf = push_and_get(83, &[0x21], 0);
        assert_eq!(*first_value(&buf), FieldValue::Bytes(&[0x21]));
    }
    #[test]
    fn apn_empty() {
        let buf = push_and_get(71, &[], 0);
        // Zero-copy reference to the empty payload; format_fn would render "".
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(&[]));
    }
    #[test]
    fn apn_zero_length_label() {
        let data = [0x00];
        let buf = push_and_get(71, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(&data));
    }
    #[test]
    fn apn_label_exceeds_data() {
        // Malformed (label length > remaining bytes); format_fn falls back to
        // UTF-8 lossy at display time. Stored bytes are the raw input.
        let data = [10, b'a', b'b', b'c'];
        let buf = push_and_get(71, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(&data));
    }
    #[test]
    fn apn_single_label() {
        let data = [3, b'f', b'o', b'o'];
        let buf = push_and_get(71, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(&data));
    }
    #[test]
    fn paa_unknown_pdn_type() {
        let buf = push_and_get(79, &[0x07], 0);
        assert_eq!(obj_field_value(&buf, "pdn_type"), Some(&FieldValue::U8(7)));
    }
    #[test]
    fn fteid_v4_flag_but_no_address_data() {
        let mut data = vec![0x80 | 10];
        data.extend_from_slice(&1u32.to_be_bytes());
        let buf = push_and_get(87, &data, 0);
        assert_eq!(obj_field_value(&buf, "v4"), Some(&FieldValue::U8(1)));
        assert_eq!(obj_field_value(&buf, "teid"), Some(&FieldValue::U32(1)));
        assert!(!obj_has_field(&buf, "ipv4_address"));
    }
}
