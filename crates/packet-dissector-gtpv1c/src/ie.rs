//! GTPv1-C Information Elements.
//!
//! ## References
//! - 3GPP TS 29.060, Section 7.7:
//!   <https://www.3gpp.org/ftp/Specs/archive/29_series/29.060/>
//! - 3GPP TS 24.008 (PCO, TFT, QoS):
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.008/>
//! - 3GPP TS 29.002 (ISDN-AddressString, TBCD-STRING):
//!   <https://www.3gpp.org/ftp/Specs/archive/29_series/29.002/>

use core::ops::Range;

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, FormatContext};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24, read_be_u32};
use packet_dissector_gtpv2c::ie_parsers::push_plmn_fields;
use packet_dissector_gtpv2c::pco::push_pco;
use packet_dissector_gtpv2c::tft::push_tft;

/// IE type: Cause (TV). 3GPP TS 29.060, Section 7.7.1.
const IE_CAUSE: u8 = 1;
/// IE type: IMSI (TV). Section 7.7.2.
const IE_IMSI: u8 = 2;
/// IE type: Routeing Area Identity (TV). Section 7.7.3.
const IE_RAI: u8 = 3;
/// IE type: TLLI (TV). Section 7.7.4.
const IE_TLLI: u8 = 4;
/// IE type: P-TMSI (TV). Section 7.7.5.
const IE_P_TMSI: u8 = 5;
/// IE type: Reordering Required (TV). Section 7.7.6.
const IE_REORDERING_REQUIRED: u8 = 8;
/// IE type: P-TMSI Signature (TV). Section 7.7.9.
const IE_P_TMSI_SIGNATURE: u8 = 12;
/// IE type: MS Validated (TV). Section 7.7.10.
const IE_MS_VALIDATED: u8 = 13;
/// IE type: Recovery (TV). Section 7.7.11.
const IE_RECOVERY: u8 = 14;
/// IE type: Selection Mode (TV). Section 7.7.12.
const IE_SELECTION_MODE: u8 = 15;
/// IE type: Tunnel Endpoint Identifier Data I (TV). Section 7.7.13.
const IE_TEID_DATA_I: u8 = 16;
/// IE type: Tunnel Endpoint Identifier Control Plane (TV). Section 7.7.14.
const IE_TEID_CONTROL_PLANE: u8 = 17;
/// IE type: Tunnel Endpoint Identifier Data II (TV). Section 7.7.15.
const IE_TEID_DATA_II: u8 = 18;
/// IE type: Teardown Ind (TV). Section 7.7.16.
const IE_TEARDOWN_IND: u8 = 19;
/// IE type: NSAPI (TV). Section 7.7.17.
const IE_NSAPI: u8 = 20;
/// IE type: Charging ID (TV). Section 7.7.26.
const IE_CHARGING_ID: u8 = 127;
/// IE type: End User Address (TLV). Section 7.7.27.
const IE_END_USER_ADDRESS: u8 = 128;
/// IE type: Access Point Name (TLV). Section 7.7.30.
const IE_APN: u8 = 131;
/// IE type: Protocol Configuration Options (TLV). Section 7.7.31.
const IE_PCO: u8 = 132;
/// IE type: GSN Address (TLV). Section 7.7.32.
const IE_GSN_ADDRESS: u8 = 133;
/// IE type: MSISDN (TLV). Section 7.7.33.
const IE_MSISDN: u8 = 134;
/// IE type: Quality of Service Profile (TLV). Section 7.7.34.
const IE_QOS_PROFILE: u8 = 135;
/// IE type: Traffic Flow Template (TLV). Section 7.7.36.
const IE_TFT: u8 = 137;
/// IE type: Common Flags (TLV). Section 7.7.48.
const IE_COMMON_FLAGS: u8 = 148;
/// IE type: RAT Type (TLV). Section 7.7.50.
const IE_RAT_TYPE: u8 = 151;
/// IE type: User Location Information (TLV). Section 7.7.51.
const IE_ULI: u8 = 152;
/// IE type: IMEI(SV) (TLV). Section 7.7.53.
const IE_IMEISV: u8 = 154;
/// IE type: Special IE type for IE Type Extension (TLV). Section 7.7.0A.
const IE_TYPE_EXTENSION: u8 = 238;
/// IE type: Private Extension (TLV). Section 7.7.46.
const IE_PRIVATE_EXTENSION: u8 = 255;

/// Value length of a TV-format IE, or `None` if the type is not assigned.
///
/// 3GPP TS 29.060, Section 7.7.0, Table 37 — "TV format information
/// elements shall always have Length Type of Fixed"; the value length is the
/// "Number of Fixed Octets" column.
fn tv_value_len(ie_type: u8) -> Option<usize> {
    Some(match ie_type {
        1 => 1,
        2 => 8,
        3 => 6,
        4 | 5 => 4,
        8 => 1,
        9 => 28,
        11 => 1,
        12 => 3,
        13..=15 => 1,
        16 | 17 => 4,
        18 => 5,
        19..=21 => 1,
        22 => 9,
        23 | 24 => 1,
        25..=28 => 2,
        29 => 1,
        127 => 4,
        _ => return None,
    })
}

/// Returns the name of a GTPv1-C IE type.
///
/// 3GPP TS 29.060, Section 7.7.0, Table 37 — "Information Elements".
pub fn ie_type_name(ie_type: u8) -> Option<&'static str> {
    Some(match ie_type {
        1 => "Cause",
        2 => "International Mobile Subscriber Identity (IMSI)",
        3 => "Routeing Area Identity (RAI)",
        4 => "Temporary Logical Link Identity (TLLI)",
        5 => "Packet TMSI (P-TMSI)",
        8 => "Reordering Required",
        9 => "Authentication Triplet",
        11 => "MAP Cause",
        12 => "P-TMSI Signature",
        13 => "MS Validated",
        14 => "Recovery",
        15 => "Selection Mode",
        16 => "Tunnel Endpoint Identifier Data I",
        17 => "Tunnel Endpoint Identifier Control Plane",
        18 => "Tunnel Endpoint Identifier Data II",
        19 => "Teardown Ind",
        20 => "NSAPI",
        21 => "RANAP Cause",
        22 => "RAB Context",
        23 => "Radio Priority SMS",
        24 => "Radio Priority",
        25 => "Packet Flow Id",
        26 => "Charging Characteristics",
        27 => "Trace Reference",
        28 => "Trace Type",
        29 => "MS Not Reachable Reason",
        127 => "Charging ID",
        128 => "End User Address",
        129 => "MM Context",
        130 => "PDP Context",
        131 => "Access Point Name",
        132 => "Protocol Configuration Options",
        133 => "GSN Address",
        134 => "MS International PSTN/ISDN Number (MSISDN)",
        135 => "Quality of Service Profile",
        136 => "Authentication Quintuplet",
        137 => "Traffic Flow Template",
        138 => "Target Identification",
        139 => "UTRAN Transparent Container",
        140 => "RAB Setup Information",
        141 => "Extension Header Type List",
        142 => "Trigger Id",
        143 => "OMC Identity",
        144 => "RAN Transparent Container",
        145 => "PDP Context Prioritization",
        146 => "Additional RAB Setup Information",
        147 => "SGSN Number",
        148 => "Common Flags",
        149 => "APN Restriction",
        150 => "Radio Priority LCS",
        151 => "RAT Type",
        152 => "User Location Information",
        153 => "MS Time Zone",
        154 => "IMEI(SV)",
        155 => "CAMEL Charging Information Container",
        156 => "MBMS UE Context",
        157 => "Temporary Mobile Group Identity (TMGI)",
        158 => "RIM Routing Address",
        159 => "MBMS Protocol Configuration Options",
        160 => "MBMS Service Area",
        161 => "Source RNC PDCP context info",
        162 => "Additional Trace Info",
        163 => "Hop Counter",
        164 => "Selected PLMN ID",
        165 => "MBMS Session Identifier",
        166 => "MBMS 2G/3G Indicator",
        167 => "Enhanced NSAPI",
        168 => "MBMS Session Duration",
        169 => "Additional MBMS Trace Info",
        170 => "MBMS Session Repetition Number",
        171 => "MBMS Time To Data Transfer",
        173 => "BSS Container",
        174 => "Cell Identification",
        175 => "PDU Numbers",
        176 => "BSSGP Cause",
        177 => "Required MBMS bearer capabilities",
        178 => "RIM Routing Address Discriminator",
        179 => "List of set-up PFCs",
        180 => "PS Handover XID Parameters",
        181 => "MS Info Change Reporting Action",
        182 => "Direct Tunnel Flags",
        183 => "Correlation-ID",
        184 => "Bearer Control Mode",
        185 => "MBMS Flow Identifier",
        186 => "MBMS IP Multicast Distribution",
        187 => "MBMS Distribution Acknowledgement",
        188 => "Reliable INTER RAT HANDOVER INFO",
        189 => "RFSP Index",
        190 => "Fully Qualified Domain Name (FQDN)",
        191 => "Evolved Allocation/Retention Priority I",
        192 => "Evolved Allocation/Retention Priority II",
        193 => "Extended Common Flags",
        194 => "User CSG Information (UCI)",
        195 => "CSG Information Reporting Action",
        196 => "CSG ID",
        197 => "CSG Membership Indication (CMI)",
        198 => "Aggregate Maximum Bit Rate (AMBR)",
        199 => "UE Network Capability",
        200 => "UE-AMBR",
        201 => "APN-AMBR with NSAPI",
        202 => "GGSN Back-Off Time",
        203 => "Signalling Priority Indication",
        204 => "Signalling Priority Indication with NSAPI",
        205 => "Higher bitrates than 16 Mbps flag",
        207 => "Additional MM context for SRVCC",
        208 => "Additional flags for SRVCC",
        209 => "STN-SR",
        210 => "C-MSISDN",
        211 => "Extended RANAP Cause",
        212 => "eNodeB ID",
        213 => "Selection Mode with NSAPI",
        214 => "ULI Timestamp",
        215 => "Local Home Network ID (LHN-ID) with NSAPI",
        216 => "CN Operator Selection Entity",
        217 => "UE Usage Type",
        218 => "Extended Common Flags II",
        219 => "Node Identifier",
        220 => "CIoT Optimizations Support Indication",
        221 => "SCEF PDN Connection",
        222 => "IOV_updates counter",
        223 => "Mapped UE Usage Type",
        224 => "UP Function Selection Indication Flags",
        238 => "Special IE type for IE Type Extension",
        251 => "Charging Gateway Address",
        255 => "Private Extension",
        _ => return None,
    })
}

/// Returns the name of a GTPv1-C Cause value.
///
/// 3GPP TS 29.060, Section 7.7.1, Table 38 — "Cause Values".
pub fn cause_name(v: u8) -> Option<&'static str> {
    Some(match v {
        0 => "Request IMSI",
        1 => "Request IMEI",
        2 => "Request IMSI and IMEI",
        3 => "No identity needed",
        4 => "MS Refuses",
        5 => "MS is not GPRS Responding",
        6 => "Reactivation Requested",
        7 => "PDP address inactivity timer expires",
        8 => "Network Failure",
        9 => "QoS parameter mismatch",
        128 => "Request accepted",
        129 => "New PDP type due to network preference",
        130 => "New PDP type due to single address bearer only",
        192 => "Non-existent",
        193 => "Invalid message format",
        194 => "IMSI/IMEI not known",
        195 => "MS is GPRS Detached",
        196 => "MS is not GPRS Responding",
        197 => "MS Refuses",
        198 => "Version not supported",
        199 => "No resources available",
        200 => "Service not supported",
        201 => "Mandatory IE incorrect",
        202 => "Mandatory IE missing",
        203 => "Optional IE incorrect",
        204 => "System failure",
        205 => "Roaming restriction",
        206 => "P-TMSI Signature mismatch",
        207 => "GPRS connection suspended",
        208 => "Authentication failure",
        209 => "User authentication failed",
        210 => "Context not found",
        211 => "All dynamic PDP addresses are occupied",
        212 => "No memory is available",
        213 => "Relocation failure",
        214 => "Unknown mandatory extension header",
        215 => "Semantic error in the TFT operation",
        216 => "Syntactic error in the TFT operation",
        217 => "Semantic errors in packet filter(s)",
        218 => "Syntactic errors in packet filter(s)",
        219 => "Missing or unknown APN",
        220 => "Unknown PDP address or PDP type",
        221 => "PDP context without TFT already activated",
        222 => "APN access denied – no subscription",
        223 => "APN Restriction type incompatibility with currently active PDP Contexts",
        224 => "MS MBMS Capabilities Insufficient",
        225 => "Invalid Correlation-ID",
        226 => "MBMS Bearer Context Superseded",
        227 => "Bearer Control Mode violation",
        228 => "Collision with network initiated request",
        229 => "APN Congestion",
        230 => "Bearer handling not supported",
        231 => "Target access restricted for the subscriber",
        232 => "UE is temporarily not reachable due to power saving",
        233 => "Relocation failure due to NAS message redirection",
        _ => return None,
    })
}

/// Selection Mode value names.
///
/// 3GPP TS 29.060, Section 7.7.12, Table 42 — value 3 "shall be interpreted
/// as the value "2"".
fn selection_mode_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("MS or network provided APN, subscribed verified"),
        1 => Some("MS provided APN, subscription not verified"),
        2 | 3 => Some("Network provided APN, subscription not verified"),
        _ => None,
    }
}

/// PDP Type Organisation names. 3GPP TS 29.060, Section 7.7.27, Table 44.
fn pdp_type_organization_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("ETSI"),
        1 => Some("IETF"),
        _ => None,
    }
}

/// PDP Type Number names for a given PDP Type Organisation.
///
/// 3GPP TS 29.060, Section 7.7.27 — Table 45 (ETSI: PPP = 1; Non-IP = 2)
/// and the IETF "Assigned PPP DLL Protocol Numbers" in compressed form
/// (IPv4 = HEX(21), IPv6 = HEX(57)); IPv4v6 is HEX(8D).
fn pdp_type_number_name(org: u8, v: u8) -> Option<&'static str> {
    match (org, v) {
        (0, 1) => Some("PPP"),
        (0, 2) => Some("Non-IP"),
        (1, 0x21) => Some("IPv4"),
        (1, 0x57) => Some("IPv6"),
        (1, 0x8D) => Some("IPv4v6"),
        _ => None,
    }
}

/// RAT Type names. 3GPP TS 29.060, Section 7.7.50, Table 7.7.50.1.
fn rat_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("UTRAN"),
        2 => Some("GERAN"),
        3 => Some("WLAN"),
        4 => Some("GAN"),
        5 => Some("HSPA Evolution"),
        6 => Some("E-UTRAN"),
        _ => None,
    }
}

/// Geographic Location Type names. 3GPP TS 29.060, Section 7.7.51,
/// Table 7.7.51A.
fn geographic_location_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("CGI"),
        1 => Some("SAI"),
        2 => Some("RAI"),
        _ => None,
    }
}

/// Write TBCD-coded digits as a JSON string.
///
/// 3GPP TS 29.002, TBCD-STRING — digits 0-9, "*" (1010), "#" (1011),
/// "a" (1100), "b" (1101), "c" (1110); "1111" is used as filler. The low
/// nibble of each octet carries the earlier digit (TS 29.060, Section 7.7.2).
pub(crate) fn format_tbcd_to(data: &[u8], w: &mut dyn std::io::Write) -> std::io::Result<()> {
    const DIGITS: &[u8; 15] = b"0123456789*#abc";
    w.write_all(b"\"")?;
    for &byte in data {
        for nibble in [byte & 0x0F, byte >> 4] {
            if let Some(&d) = DIGITS.get(usize::from(nibble)) {
                w.write_all(&[d])?;
            }
        }
    }
    w.write_all(b"\"")
}

fn format_tbcd(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    match value {
        FieldValue::Bytes(b) => format_tbcd_to(b, w),
        _ => w.write_all(b"\"\""),
    }
}

/// Container descriptor for one IE; its label resolves to the IE name.
static FD_IE: FieldDescriptor = FieldDescriptor {
    name: "ie",
    display_name: "IE",
    field_type: FieldType::Object,
    optional: false,
    children: Some(IE_FIELD_DESCRIPTORS),
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => ie_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

const FD_TYPE: usize = 0;
const FD_EXTENDED_TYPE: usize = 1;
const FD_LENGTH: usize = 2;
const FD_CAUSE: usize = 3;
const FD_IMSI: usize = 4;
const FD_LAC: usize = 7;
const FD_RAC: usize = 8;
const FD_CI: usize = 9;
const FD_SAC: usize = 10;
const FD_TLLI: usize = 11;
const FD_P_TMSI: usize = 12;
const FD_P_TMSI_SIGNATURE: usize = 13;
const FD_REORDERING_REQUIRED: usize = 14;
const FD_MS_VALIDATED: usize = 15;
const FD_RESTART_COUNTER: usize = 16;
const FD_SELECTION_MODE: usize = 17;
const FD_TEID_DATA_I: usize = 18;
const FD_TEID_CONTROL_PLANE: usize = 19;
const FD_TEID_DATA_II: usize = 20;
const FD_NSAPI: usize = 21;
const FD_TEARDOWN_IND: usize = 22;
const FD_CHARGING_ID: usize = 23;
const FD_PDP_TYPE_ORGANIZATION: usize = 24;
const FD_PDP_TYPE_NUMBER: usize = 25;
const FD_IPV4_ADDRESS: usize = 26;
const FD_IPV6_ADDRESS: usize = 27;
const FD_PDP_ADDRESS: usize = 28;
const FD_APN: usize = 29;
const FD_PCO: usize = 30;
const FD_GSN_ADDRESS: usize = 31;
const FD_NATURE_OF_ADDRESS: usize = 32;
const FD_NUMBERING_PLAN: usize = 33;
const FD_MSISDN: usize = 34;
const FD_ARP: usize = 35;
const FD_QOS_PROFILE_DATA: usize = 36;
const FD_TFT: usize = 37;
const FD_COMMON_FLAGS: usize = 38; // 8 consecutive flag descriptors
const FD_RAT_TYPE: usize = 46;
const FD_GEOGRAPHIC_LOCATION_TYPE: usize = 47;
const FD_IMEISV: usize = 48;
const FD_EXTENSION_IDENTIFIER: usize = 49;
const FD_EXTENSION_VALUE: usize = 50;
const FD_VALUE: usize = 51;

/// Child fields of an IE object (the union over all decoded IE types).
pub(crate) static IE_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => ie_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("extended_type", "IE Type Extension", FieldType::U16).optional(),
    FieldDescriptor::new("length", "Length", FieldType::U16).optional(),
    FieldDescriptor::new("cause", "Cause", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(c) => cause_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("imsi", "IMSI", FieldType::Bytes)
        .optional()
        .with_format_fn(format_tbcd),
    FieldDescriptor::new("mcc", "MCC", FieldType::Bytes).optional(),
    FieldDescriptor::new("mnc", "MNC", FieldType::Bytes).optional(),
    FieldDescriptor::new("lac", "Location Area Code", FieldType::U16).optional(),
    FieldDescriptor::new("rac", "Routing Area Code", FieldType::U8).optional(),
    FieldDescriptor::new("ci", "Cell Identity", FieldType::U16).optional(),
    FieldDescriptor::new("sac", "Service Area Code", FieldType::U16).optional(),
    FieldDescriptor::new("tlli", "TLLI", FieldType::U32).optional(),
    FieldDescriptor::new("p_tmsi", "P-TMSI", FieldType::U32).optional(),
    FieldDescriptor::new("p_tmsi_signature", "P-TMSI Signature", FieldType::U32).optional(),
    FieldDescriptor::new("reordering_required", "Reordering Required", FieldType::U8).optional(),
    FieldDescriptor::new("ms_validated", "MS Validated", FieldType::U8).optional(),
    FieldDescriptor::new("restart_counter", "Restart Counter", FieldType::U8).optional(),
    FieldDescriptor::new("selection_mode", "Selection Mode", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(m) => selection_mode_name(*m),
            _ => None,
        }),
    FieldDescriptor::new(
        "teid_data_i",
        "Tunnel Endpoint Identifier Data I",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new(
        "teid_control_plane",
        "Tunnel Endpoint Identifier Control Plane",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new(
        "teid_data_ii",
        "Tunnel Endpoint Identifier Data II",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("nsapi", "NSAPI", FieldType::U8).optional(),
    FieldDescriptor::new("teardown_ind", "Teardown Ind", FieldType::U8).optional(),
    FieldDescriptor::new("charging_id", "Charging ID", FieldType::U32).optional(),
    FieldDescriptor::new(
        "pdp_type_organization",
        "PDP Type Organisation",
        FieldType::U8,
    )
    .optional()
    .with_display_fn(|v, _| match v {
        FieldValue::U8(o) => pdp_type_organization_name(*o),
        _ => None,
    }),
    FieldDescriptor::new("pdp_type_number", "PDP Type Number", FieldType::U8)
        .optional()
        .with_display_fn(|v, siblings| {
            let org = siblings
                .iter()
                .find(|f| f.name() == "pdp_type_organization")
                .and_then(|f| f.value.as_u8())?;
            match v {
                FieldValue::U8(n) => pdp_type_number_name(org, *n),
                _ => None,
            }
        }),
    FieldDescriptor::new("ipv4_address", "IPv4 Address", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("ipv6_address", "IPv6 Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("pdp_address", "PDP Address", FieldType::Bytes).optional(),
    FieldDescriptor::new("apn", "Access Point Name", FieldType::Bytes)
        .optional()
        .with_format_fn(packet_dissector_core::field::format_fqdn_labels),
    FieldDescriptor::new("pco", "Protocol Configuration Options", FieldType::Any).optional(),
    FieldDescriptor::new("gsn_address", "GSN Address", FieldType::Any).optional(),
    FieldDescriptor::new("nature_of_address", "Nature of Address", FieldType::U8).optional(),
    FieldDescriptor::new("numbering_plan", "Numbering Plan", FieldType::U8).optional(),
    FieldDescriptor::new("msisdn", "MSISDN", FieldType::Bytes)
        .optional()
        .with_format_fn(format_tbcd),
    FieldDescriptor::new(
        "allocation_retention_priority",
        "Allocation/Retention Priority",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("qos_profile_data", "QoS Profile Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("tft", "Traffic Flow Template", FieldType::Any).optional(),
    FieldDescriptor::new(
        "dual_address_bearer_flag",
        "Dual Address Bearer Flag",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "upgrade_qos_supported",
        "Upgrade QoS Supported",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("nrsn", "NRSN", FieldType::U8).optional(),
    FieldDescriptor::new("no_qos_negotiation", "No QoS negotiation", FieldType::U8).optional(),
    FieldDescriptor::new(
        "mbms_counting_information",
        "MBMS Counting Information",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "ran_procedures_ready",
        "RAN Procedures Ready",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("mbms_service_type", "MBMS Service Type", FieldType::U8).optional(),
    FieldDescriptor::new(
        "prohibit_payload_compression",
        "Prohibit Payload Compression",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("rat_type", "RAT Type", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(r) => rat_type_name(*r),
            _ => None,
        }),
    FieldDescriptor::new(
        "geographic_location_type",
        "Geographic Location Type",
        FieldType::U8,
    )
    .optional()
    .with_display_fn(|v, _| match v {
        FieldValue::U8(t) => geographic_location_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("imeisv", "IMEI(SV)", FieldType::Bytes)
        .optional()
        .with_format_fn(format_tbcd),
    FieldDescriptor::new(
        "extension_identifier",
        "Extension Identifier",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("extension_value", "Extension Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// Parse the IEs of a GTPv1-C message.
///
/// `data` is the part of the message after the header (and after any
/// extension headers); `base` is its absolute packet offset. An IE whose
/// extent cannot be determined (an unassigned TV type, or a TLV Length that
/// runs past the message) ends the walk, and the remaining octets are kept
/// as the raw `value` of that IE.
///
/// 3GPP TS 29.060, Section 7.7.0 — "The most significant bit in the Type
/// field is set to 0 when the TV format is used and set to 1 for the TLV
/// format."
pub(crate) fn parse_ies<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], base: usize) {
    let mut pos = 0;
    while pos < data.len() {
        let ie_type = data[pos];
        let start = base + pos;
        let obj = buf.begin_container(&FD_IE, FieldValue::Object(0..0), start..start);
        push(buf, FD_TYPE, FieldValue::U8(ie_type), start..start + 1);

        let extent = if ie_type & 0x80 == 0 {
            tv_value_len(ie_type)
                .filter(|len| pos + 1 + len <= data.len())
                .map(|len| (pos + 1, len))
        } else {
            // TLV: two-octet Length excluding the Type and Length fields.
            match read_be_u16(data, pos + 1).map(usize::from) {
                Ok(len) if pos + 3 + len <= data.len() => {
                    push(
                        buf,
                        FD_LENGTH,
                        FieldValue::U16(len as u16),
                        start + 1..start + 3,
                    );
                    Some((pos + 3, len))
                }
                _ => None,
            }
        };

        let Some((value_pos, value_len)) = extent else {
            push(
                buf,
                FD_VALUE,
                FieldValue::Bytes(&data[pos + 1..]),
                start + 1..base + data.len(),
            );
            close(buf, obj, start..base + data.len());
            break;
        };

        let end = value_pos + value_len;
        push_ie_value(buf, ie_type, &data[value_pos..end], base + value_pos);
        close(buf, obj, start..base + end);
        pos = end;
    }
}

fn close(buf: &mut DissectBuffer<'_>, obj: u32, range: Range<usize>) {
    if let Some(f) = buf.field_mut(obj as usize) {
        f.range = range;
    }
    buf.end_container(obj);
}

fn push<'pkt>(buf: &mut DissectBuffer<'pkt>, fd: usize, value: FieldValue<'pkt>, r: Range<usize>) {
    buf.push_field(&IE_FIELD_DESCRIPTORS[fd], value, r);
}

fn push_raw<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], off: usize) {
    push(buf, FD_VALUE, FieldValue::Bytes(v), off..off + v.len());
}

/// Push the decoded value of one IE. `v` is the IE value (after Type and,
/// for TLV IEs, Length) and `off` its absolute offset. A value too short for
/// its decoder is kept as raw `value` bytes.
fn push_ie_value<'pkt>(buf: &mut DissectBuffer<'pkt>, ie_type: u8, v: &'pkt [u8], off: usize) {
    let decoded = match ie_type {
        IE_CAUSE => push_u8(buf, FD_CAUSE, v, off, 0xFF),
        IE_IMSI => {
            push(buf, FD_IMSI, FieldValue::Bytes(v), off..off + v.len());
            true
        }
        IE_RAI => push_rai(buf, v, off),
        IE_TLLI => push_u32(buf, FD_TLLI, v, off),
        IE_P_TMSI => push_u32(buf, FD_P_TMSI, v, off),
        // Sections 7.7.6, 7.7.10, 7.7.16 — the flag is bit 1.
        IE_REORDERING_REQUIRED => push_u8(buf, FD_REORDERING_REQUIRED, v, off, 0x01),
        IE_MS_VALIDATED => push_u8(buf, FD_MS_VALIDATED, v, off, 0x01),
        IE_TEARDOWN_IND => push_u8(buf, FD_TEARDOWN_IND, v, off, 0x01),
        IE_P_TMSI_SIGNATURE => match read_be_u24(v, 0) {
            Ok(sig) => {
                push(buf, FD_P_TMSI_SIGNATURE, FieldValue::U32(sig), off..off + 3);
                true
            }
            Err(_) => false,
        },
        IE_RECOVERY => push_u8(buf, FD_RESTART_COUNTER, v, off, 0xFF),
        // Section 7.7.12 — the selection mode value is in bits 2-1.
        IE_SELECTION_MODE => push_u8(buf, FD_SELECTION_MODE, v, off, 0x03),
        IE_TEID_DATA_I => push_u32(buf, FD_TEID_DATA_I, v, off),
        IE_TEID_CONTROL_PLANE => push_u32(buf, FD_TEID_CONTROL_PLANE, v, off),
        // Section 7.7.15 — spare (bits 8-5) | NSAPI (bits 4-1), then TEID.
        IE_TEID_DATA_II => match read_be_u32(v, 1) {
            Ok(teid) => {
                push(buf, FD_NSAPI, FieldValue::U8(v[0] & 0x0F), off..off + 1);
                push(
                    buf,
                    FD_TEID_DATA_II,
                    FieldValue::U32(teid),
                    off + 1..off + 5,
                );
                true
            }
            Err(_) => false,
        },
        // Section 7.7.17 — spare (bits 8-5) | NSAPI (bits 4-1).
        IE_NSAPI => push_u8(buf, FD_NSAPI, v, off, 0x0F),
        IE_CHARGING_ID => push_u32(buf, FD_CHARGING_ID, v, off),
        IE_END_USER_ADDRESS => push_end_user_address(buf, v, off),
        IE_APN => {
            push(buf, FD_APN, FieldValue::Bytes(v), off..off + v.len());
            true
        }
        IE_PCO => {
            push_pco(
                v,
                off,
                &IE_FIELD_DESCRIPTORS[FD_PCO],
                &(off..off + v.len()),
                buf,
            );
            true
        }
        IE_GSN_ADDRESS => {
            // Section 7.7.32 / TS 23.003 — an IPv4 (4 octets) or IPv6
            // (16 octets) address.
            let value = match v.len() {
                4 => FieldValue::Ipv4Addr([v[0], v[1], v[2], v[3]]),
                16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(v);
                    FieldValue::Ipv6Addr(a)
                }
                _ => FieldValue::Bytes(v),
            };
            push(buf, FD_GSN_ADDRESS, value, off..off + v.len());
            true
        }
        IE_MSISDN => push_msisdn(buf, v, off),
        IE_QOS_PROFILE => match v.split_first() {
            // Section 7.7.34 — octet 4: Allocation/Retention Priority;
            // octets 5-n: QoS Profile Data (TS 24.008 QoS IE octets 3-m).
            Some((&arp, rest)) => {
                push(buf, FD_ARP, FieldValue::U8(arp), off..off + 1);
                push(
                    buf,
                    FD_QOS_PROFILE_DATA,
                    FieldValue::Bytes(rest),
                    off + 1..off + v.len(),
                );
                true
            }
            None => false,
        },
        IE_TFT => {
            push_tft(
                v,
                off,
                &IE_FIELD_DESCRIPTORS[FD_TFT],
                &(off..off + v.len()),
                buf,
            );
            true
        }
        IE_COMMON_FLAGS => match v.first() {
            // Section 7.7.48 — bit 8 Dual Address Bearer Flag ... bit 1
            // Prohibit Payload Compression.
            Some(&flags) => {
                for i in 0..8 {
                    let bit = (flags >> (7 - i)) & 1;
                    push(buf, FD_COMMON_FLAGS + i, FieldValue::U8(bit), off..off + 1);
                }
                true
            }
            None => false,
        },
        IE_RAT_TYPE => push_u8(buf, FD_RAT_TYPE, v, off, 0xFF),
        IE_ULI => push_uli(buf, v, off),
        IE_IMEISV => {
            push(buf, FD_IMEISV, FieldValue::Bytes(v), off..off + v.len());
            true
        }
        IE_TYPE_EXTENSION => match read_be_u16(v, 0) {
            // Section 7.7.0A — octets 4-5 carry the IE Type Extension.
            Ok(ext) => {
                push(buf, FD_EXTENDED_TYPE, FieldValue::U16(ext), off..off + 2);
                push_raw(buf, &v[2..], off + 2);
                true
            }
            Err(_) => false,
        },
        IE_PRIVATE_EXTENSION => match read_be_u16(v, 0) {
            // Section 7.7.46 — Extension Identifier (2 octets) followed by
            // the Extension Value.
            Ok(id) => {
                push(
                    buf,
                    FD_EXTENSION_IDENTIFIER,
                    FieldValue::U16(id),
                    off..off + 2,
                );
                push(
                    buf,
                    FD_EXTENSION_VALUE,
                    FieldValue::Bytes(&v[2..]),
                    off + 2..off + v.len(),
                );
                true
            }
            Err(_) => false,
        },
        _ => false,
    };
    if !decoded {
        push_raw(buf, v, off);
    }
}

fn push_u8(buf: &mut DissectBuffer<'_>, fd: usize, v: &[u8], off: usize, mask: u8) -> bool {
    match v.first() {
        Some(&b) => {
            push(buf, fd, FieldValue::U8(b & mask), off..off + 1);
            true
        }
        None => false,
    }
}

fn push_u32(buf: &mut DissectBuffer<'_>, fd: usize, v: &[u8], off: usize) -> bool {
    match read_be_u32(v, 0) {
        Ok(x) => {
            push(buf, fd, FieldValue::U32(x), off..off + 4);
            true
        }
        Err(_) => false,
    }
}

/// Section 7.7.3 — MCC/MNC (3 octets), LAC (2 octets), RAC (1 octet).
fn push_rai(buf: &mut DissectBuffer<'_>, v: &[u8], off: usize) -> bool {
    let (Ok(lac), Some(&rac)) = (read_be_u16(v, 3), v.get(5)) else {
        return false;
    };
    push_plmn_fields(v, off, 3, buf);
    push(buf, FD_LAC, FieldValue::U16(lac), off + 3..off + 5);
    push(buf, FD_RAC, FieldValue::U8(rac), off + 5..off + 6);
    true
}

/// Section 7.7.27 — End User Address.
fn push_end_user_address<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], off: usize) -> bool {
    let [o4, number, ref addr @ ..] = *v else {
        return false;
    };
    let org = o4 & 0x0F;
    push(
        buf,
        FD_PDP_TYPE_ORGANIZATION,
        FieldValue::U8(org),
        off..off + 1,
    );
    push(
        buf,
        FD_PDP_TYPE_NUMBER,
        FieldValue::U8(number),
        off + 1..off + 2,
    );
    if addr.is_empty() {
        // "The Length field value shall be 2 in an End User Address
        // information element with no PDP Address."
        return true;
    }
    let a = off + 2;
    let v4 = |x: &[u8]| FieldValue::Ipv4Addr([x[0], x[1], x[2], x[3]]);
    let v6 = |x: &[u8]| {
        let mut b = [0u8; 16];
        b.copy_from_slice(x);
        FieldValue::Ipv6Addr(b)
    };
    match (org, number, addr.len()) {
        (1, 0x21, 4) | (1, 0x8D, 4) => push(buf, FD_IPV4_ADDRESS, v4(addr), a..a + 4),
        (1, 0x57, 16) | (1, 0x8D, 16) => push(buf, FD_IPV6_ADDRESS, v6(addr), a..a + 16),
        // IPv4v6 with both static addresses: IPv4 in octets 6-9, IPv6 in
        // octets 10-25.
        (1, 0x8D, 20) => {
            push(buf, FD_IPV4_ADDRESS, v4(&addr[..4]), a..a + 4);
            push(buf, FD_IPV6_ADDRESS, v6(&addr[4..]), a + 4..a + 20);
        }
        _ => push(
            buf,
            FD_PDP_ADDRESS,
            FieldValue::Bytes(addr),
            a..a + addr.len(),
        ),
    }
    true
}

/// Section 7.7.33 — MSISDN coded as an ISDN-AddressString (TS 29.002):
/// octet 1 is extension (bit 8), nature of address (bits 7-5) and numbering
/// plan (bits 4-1), followed by TBCD digits.
fn push_msisdn<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], off: usize) -> bool {
    let Some((&first, digits)) = v.split_first() else {
        return false;
    };
    push(
        buf,
        FD_NATURE_OF_ADDRESS,
        FieldValue::U8((first >> 4) & 0x07),
        off..off + 1,
    );
    push(
        buf,
        FD_NUMBERING_PLAN,
        FieldValue::U8(first & 0x0F),
        off..off + 1,
    );
    push(
        buf,
        FD_MSISDN,
        FieldValue::Bytes(digits),
        off + 1..off + v.len(),
    );
    true
}

/// Section 7.7.51 — User Location Information.
fn push_uli<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], off: usize) -> bool {
    let Some((&glt, loc)) = v.split_first() else {
        return false;
    };
    push(
        buf,
        FD_GEOGRAPHIC_LOCATION_TYPE,
        FieldValue::U8(glt),
        off..off + 1,
    );
    let l = off + 1;
    // Figures 7.7.51.2-4 — MCC/MNC (octets 5-7), LAC (8-9), then CI, SAC or
    // RAC (10-11; for RAI only octet 10 carries the RAC).
    match (glt, read_be_u16(loc, 3), read_be_u16(loc, 5)) {
        (0..=2, Ok(lac), Ok(last)) => {
            push_plmn_fields(loc, l, 3, buf);
            push(buf, FD_LAC, FieldValue::U16(lac), l + 3..l + 5);
            match glt {
                0 => push(buf, FD_CI, FieldValue::U16(last), l + 5..l + 7),
                1 => push(buf, FD_SAC, FieldValue::U16(last), l + 5..l + 7),
                _ => push(buf, FD_RAC, FieldValue::U8(loc[5]), l + 5..l + 6),
            }
        }
        _ => push_raw(buf, loc, l),
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::Field;

    /// Parse `data` as an IE list and return (IE count, buffer).
    fn parse(data: &[u8]) -> DissectBuffer<'_> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("GTPv1-C", None, &[], 0..data.len());
        parse_ies(&mut buf, data, 100);
        buf.end_layer();
        buf
    }

    /// The child fields of every top-level IE object, in order.
    fn ie_list<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>) -> Vec<&'a [Field<'pkt>]> {
        let fields = buf.fields();
        let mut out = Vec::new();
        let mut i = 0;
        while i < fields.len() {
            if let ("ie", FieldValue::Object(r)) = (fields[i].name(), &fields[i].value) {
                out.push(buf.nested_fields(r));
                i = r.end as usize;
            } else {
                i += 1;
            }
        }
        out
    }

    fn get<'a, 'pkt>(ie: &'a [Field<'pkt>], name: &str) -> &'a FieldValue<'pkt> {
        &ie.iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("field {name} missing"))
            .value
    }

    fn has(ie: &[Field<'_>], name: &str) -> bool {
        ie.iter().any(|f| f.name() == name)
    }

    fn scratch<'a>(buf: &'a DissectBuffer<'_>, v: &FieldValue<'_>) -> &'a [u8] {
        match v {
            FieldValue::Scratch(r) => &buf.scratch()[r.start as usize..r.end as usize],
            other => panic!("expected scratch, got {other:?}"),
        }
    }

    #[test]
    fn tv_cause() {
        let buf = parse(&[1, 128]);
        let ies = ie_list(&buf);
        assert_eq!(ies.len(), 1);
        assert_eq!(get(ies[0], "type"), &FieldValue::U8(1));
        assert_eq!(get(ies[0], "cause"), &FieldValue::U8(128));
        assert!(!has(ies[0], "length"));
        assert_eq!(cause_name(128), Some("Request accepted"));
        assert_eq!(buf.fields()[0].range, 100..102);
    }

    #[test]
    fn tv_imsi_tbcd() {
        // IMSI 001010123456789 (15 digits, filler F in the last high nibble)
        let data = [2, 0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xF9];
        let buf = parse(&data);
        let ies = ie_list(&buf);
        assert_eq!(get(ies[0], "imsi"), &FieldValue::Bytes(&data[1..]));
        let mut out = Vec::new();
        format_tbcd_to(&data[1..], &mut out).unwrap();
        assert_eq!(out, b"\"001010123456789\"");
    }

    #[test]
    fn tv_rai() {
        // MCC 262, MNC 01 (two digits), LAC 0x1234, RAC 0x56
        let buf = parse(&[3, 0x62, 0xF2, 0x10, 0x12, 0x34, 0x56]);
        let ies = ie_list(&buf);
        assert_eq!(scratch(&buf, get(ies[0], "mcc")), b"262");
        assert_eq!(scratch(&buf, get(ies[0], "mnc")), b"01");
        assert_eq!(get(ies[0], "lac"), &FieldValue::U16(0x1234));
        assert_eq!(get(ies[0], "rac"), &FieldValue::U8(0x56));
    }

    #[test]
    fn tv_scalars() {
        let data = [
            4, 0xC0, 0x00, 0x00, 0x01, // TLLI
            5, 0xC0, 0x00, 0x00, 0x02, // P-TMSI
            8, 0xFF, // Reordering Required = 1 (bit 1)
            12, 0x01, 0x02, 0x03, // P-TMSI Signature
            13, 0xFE, // MS Validated = 0
            14, 0x07, // Recovery
            15, 0xFD, // Selection Mode = 1 (spare bits set)
            16, 0x11, 0x22, 0x33, 0x44, // TEID Data I
            17, 0x55, 0x66, 0x77, 0x88, // TEID Control Plane
            18, 0xF5, 0x01, 0x02, 0x03, 0x04, // TEID Data II, NSAPI 5
            19, 0x01, // Teardown Ind
            20, 0x05, // NSAPI
            127, 0xDE, 0xAD, 0xBE, 0xEF, // Charging ID
        ];
        let buf = parse(&data);
        let ies = ie_list(&buf);
        assert_eq!(ies.len(), 13);
        assert_eq!(get(ies[0], "tlli"), &FieldValue::U32(0xC000_0001));
        assert_eq!(get(ies[1], "p_tmsi"), &FieldValue::U32(0xC000_0002));
        assert_eq!(get(ies[2], "reordering_required"), &FieldValue::U8(1));
        assert_eq!(get(ies[3], "p_tmsi_signature"), &FieldValue::U32(0x010203));
        assert_eq!(get(ies[4], "ms_validated"), &FieldValue::U8(0));
        assert_eq!(get(ies[5], "restart_counter"), &FieldValue::U8(7));
        assert_eq!(get(ies[6], "selection_mode"), &FieldValue::U8(1));
        assert_eq!(get(ies[7], "teid_data_i"), &FieldValue::U32(0x1122_3344));
        assert_eq!(
            get(ies[8], "teid_control_plane"),
            &FieldValue::U32(0x5566_7788)
        );
        assert_eq!(get(ies[9], "nsapi"), &FieldValue::U8(5));
        assert_eq!(get(ies[9], "teid_data_ii"), &FieldValue::U32(0x0102_0304));
        assert_eq!(get(ies[10], "teardown_ind"), &FieldValue::U8(1));
        assert_eq!(get(ies[11], "nsapi"), &FieldValue::U8(5));
        assert_eq!(get(ies[12], "charging_id"), &FieldValue::U32(0xDEAD_BEEF));
        assert_eq!(
            selection_mode_name(1),
            Some("MS provided APN, subscription not verified")
        );
    }

    #[test]
    fn tv_without_decoder_keeps_value() {
        // MAP Cause (TV, 1 octet) has no dedicated decoder.
        let buf = parse(&[11, 0x22, 14, 0x01]);
        let ies = ie_list(&buf);
        assert_eq!(ies.len(), 2);
        assert_eq!(get(ies[0], "value"), &FieldValue::Bytes(&[0x22]));
        assert_eq!(get(ies[1], "restart_counter"), &FieldValue::U8(1));
    }

    #[test]
    fn unknown_tv_type_ends_walk() {
        // Type 30 is a reserved TV type whose length is unknown.
        let buf = parse(&[14, 0x01, 30, 0xAA, 0xBB]);
        let ies = ie_list(&buf);
        assert_eq!(ies.len(), 2);
        assert_eq!(get(ies[1], "type"), &FieldValue::U8(30));
        assert_eq!(get(ies[1], "value"), &FieldValue::Bytes(&[0xAA, 0xBB]));
    }

    #[test]
    fn truncated_tv_ends_walk() {
        let buf = parse(&[16, 0x01, 0x02]);
        let ies = ie_list(&buf);
        assert_eq!(ies.len(), 1);
        assert_eq!(get(ies[0], "value"), &FieldValue::Bytes(&[0x01, 0x02]));
    }

    #[test]
    fn tlv_length_past_end_ends_walk() {
        let buf = parse(&[131, 0x00, 0x10, 0x01]);
        let ies = ie_list(&buf);
        assert_eq!(ies.len(), 1);
        assert!(!has(ies[0], "length"));
        assert_eq!(
            get(ies[0], "value"),
            &FieldValue::Bytes(&[0x00, 0x10, 0x01])
        );
    }

    #[test]
    fn tlv_end_user_address_ipv4() {
        let buf = parse(&[128, 0x00, 0x06, 0xF1, 0x21, 10, 0, 0, 1]);
        let ies = ie_list(&buf);
        assert_eq!(get(ies[0], "length"), &FieldValue::U16(6));
        assert_eq!(get(ies[0], "pdp_type_organization"), &FieldValue::U8(1));
        assert_eq!(get(ies[0], "pdp_type_number"), &FieldValue::U8(0x21));
        assert_eq!(
            get(ies[0], "ipv4_address"),
            &FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert!(!has(ies[0], "ipv6_address"));
        assert_eq!(pdp_type_number_name(1, 0x21), Some("IPv4"));
        assert_eq!(pdp_type_number_name(1, 0x57), Some("IPv6"));
        assert_eq!(pdp_type_number_name(1, 0x8D), Some("IPv4v6"));
        assert_eq!(pdp_type_number_name(0, 1), Some("PPP"));
        assert_eq!(pdp_type_number_name(0, 2), Some("Non-IP"));
        assert_eq!(pdp_type_number_name(2, 1), None);
    }

    #[test]
    fn tlv_end_user_address_variants() {
        let mut v6 = vec![128, 0x00, 0x12, 0xF1, 0x57];
        v6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let buf = parse(&v6);
        let ies = ie_list(&buf);
        assert!(matches!(get(ies[0], "ipv6_address"), FieldValue::Ipv6Addr(a) if a[15] == 1));

        // IPv4v6 with both addresses (Length 22)
        let mut both = vec![128, 0x00, 0x16, 0xF1, 0x8D, 192, 0, 2, 1];
        both.extend_from_slice(&[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let buf = parse(&both);
        let ies = ie_list(&buf);
        assert_eq!(
            get(ies[0], "ipv4_address"),
            &FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        assert!(matches!(get(ies[0], "ipv6_address"), FieldValue::Ipv6Addr(a) if a[15] == 2));

        // IPv4v6 with only a static IPv6 address (Length 18)
        let mut v6only = vec![128, 0x00, 0x12, 0xF1, 0x8D];
        v6only.extend_from_slice(&[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        let buf = parse(&v6only);
        let ies = ie_list(&buf);
        assert!(!has(ies[0], "ipv4_address"));
        assert!(matches!(get(ies[0], "ipv6_address"), FieldValue::Ipv6Addr(a) if a[15] == 3));

        // Dynamic address request: no PDP Address (Length 2)
        let buf = parse(&[128, 0x00, 0x02, 0xF1, 0x21]);
        let ies = ie_list(&buf);
        assert!(!has(ies[0], "ipv4_address"));
        assert!(!has(ies[0], "value"));

        // Address length that matches no PDP type keeps the raw address.
        let buf = parse(&[128, 0x00, 0x04, 0xF1, 0x21, 0x01, 0x02]);
        let ies = ie_list(&buf);
        assert_eq!(
            get(ies[0], "pdp_address"),
            &FieldValue::Bytes(&[0x01, 0x02])
        );

        // Too short to hold the PDP type.
        let buf = parse(&[128, 0x00, 0x01, 0xF1]);
        let ies = ie_list(&buf);
        assert_eq!(get(ies[0], "value"), &FieldValue::Bytes(&[0xF1]));
    }

    #[test]
    fn tlv_apn_pco_gsn_msisdn() {
        let data = [
            131, 0x00, 0x09, 8, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't', // APN
            132, 0x00, 0x05, 0x80, 0x00, 0x0D, 0x00, 0x00, // PCO: DNS IPv4 request
            133, 0x00, 0x04, 192, 0, 2, 10, // GSN Address IPv4
            133, 0x00, 0x03, 1, 2, 3, // GSN Address with bad length
            134, 0x00, 0x07, 0x91, 0x94, 0x71, 0x00, 0x10, 0x32, 0xF4, // MSISDN
        ];
        let buf = parse(&data);
        let ies = ie_list(&buf);
        assert_eq!(ies.len(), 5);
        assert_eq!(get(ies[0], "apn"), &FieldValue::Bytes(&data[3..12]));
        assert!(matches!(get(ies[1], "pco"), FieldValue::Object(_)));
        assert_eq!(
            get(ies[2], "gsn_address"),
            &FieldValue::Ipv4Addr([192, 0, 2, 10])
        );
        assert_eq!(get(ies[3], "gsn_address"), &FieldValue::Bytes(&[1, 2, 3]));
        assert_eq!(get(ies[4], "nature_of_address"), &FieldValue::U8(1));
        assert_eq!(get(ies[4], "numbering_plan"), &FieldValue::U8(1));
        let FieldValue::Bytes(digits) = get(ies[4], "msisdn") else {
            panic!("msisdn not bytes")
        };
        let mut out = Vec::new();
        format_tbcd_to(digits, &mut out).unwrap();
        assert_eq!(out, b"\"49170001234\"");
    }

    #[test]
    fn tlv_gsn_address_ipv6() {
        let mut data = vec![133, 0x00, 0x10];
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        let buf = parse(&data);
        let ies = ie_list(&buf);
        assert!(matches!(get(ies[0], "gsn_address"), FieldValue::Ipv6Addr(a) if a[15] == 9));
    }

    #[test]
    fn tlv_qos_tft_rat_uli_imei_flags() {
        let data = [
            135, 0x00, 0x04, 0x02, 0x23, 0x92, 0x1F, // QoS: ARP 2, data 3 octets
            137, 0x00, 0x01, 0x20, // TFT: create new TFT (op 1), 0 filters
            148, 0x00, 0x01,
            0x94, // Common Flags: DAB, No QoS negotiation, RAN Procedures Ready
            151, 0x00, 0x01, 0x01, // RAT Type: UTRAN
            152, 0x00, 0x08, 0x00, 0x62, 0xF2, 0x10, 0x12, 0x34, 0xAB, 0xCD, // ULI CGI
            154, 0x00, 0x08, 0x53, 0x68, 0x40, 0x00, 0x11, 0x22, 0x33, 0x04, // IMEISV
            255, 0x00, 0x04, 0x00, 0x0A, 0xCA, 0xFE, // Private Extension
        ];
        let buf = parse(&data);
        let ies = ie_list(&buf);
        assert_eq!(ies.len(), 7);
        assert_eq!(
            get(ies[0], "allocation_retention_priority"),
            &FieldValue::U8(2)
        );
        assert_eq!(
            get(ies[0], "qos_profile_data"),
            &FieldValue::Bytes(&[0x23, 0x92, 0x1F])
        );
        assert!(matches!(get(ies[1], "tft"), FieldValue::Object(_)));
        assert_eq!(get(ies[2], "dual_address_bearer_flag"), &FieldValue::U8(1));
        assert_eq!(get(ies[2], "upgrade_qos_supported"), &FieldValue::U8(0));
        assert_eq!(get(ies[2], "nrsn"), &FieldValue::U8(0));
        assert_eq!(get(ies[2], "no_qos_negotiation"), &FieldValue::U8(1));
        assert_eq!(get(ies[2], "mbms_counting_information"), &FieldValue::U8(0));
        assert_eq!(get(ies[2], "ran_procedures_ready"), &FieldValue::U8(1));
        assert_eq!(get(ies[2], "mbms_service_type"), &FieldValue::U8(0));
        assert_eq!(
            get(ies[2], "prohibit_payload_compression"),
            &FieldValue::U8(0)
        );
        assert_eq!(get(ies[3], "rat_type"), &FieldValue::U8(1));
        assert_eq!(rat_type_name(1), Some("UTRAN"));
        assert_eq!(rat_type_name(6), Some("E-UTRAN"));
        assert_eq!(rat_type_name(7), None);
        assert_eq!(get(ies[4], "geographic_location_type"), &FieldValue::U8(0));
        assert_eq!(scratch(&buf, get(ies[4], "mcc")), b"262");
        assert_eq!(get(ies[4], "lac"), &FieldValue::U16(0x1234));
        assert_eq!(get(ies[4], "ci"), &FieldValue::U16(0xABCD));
        assert_eq!(get(ies[5], "imeisv"), &FieldValue::Bytes(&data[33..41]));
        assert_eq!(get(ies[6], "extension_identifier"), &FieldValue::U16(10));
        assert_eq!(
            get(ies[6], "extension_value"),
            &FieldValue::Bytes(&[0xCA, 0xFE])
        );
    }

    #[test]
    fn uli_sai_rai_and_unknown() {
        let buf = parse(&[
            152, 0x00, 0x08, 0x01, 0x62, 0xF2, 0x10, 0x00, 0x01, 0x00, 0x02, // SAI
            152, 0x00, 0x08, 0x02, 0x62, 0xF2, 0x10, 0x00, 0x01, 0x07, 0xFF, // RAI
            152, 0x00, 0x03, 0x09, 0xAA, 0xBB, // unknown type
            152, 0x00, 0x04, 0x00, 0x62, 0xF2, 0x10, // CGI too short
        ]);
        let ies = ie_list(&buf);
        assert_eq!(get(ies[0], "sac"), &FieldValue::U16(2));
        assert_eq!(get(ies[1], "rac"), &FieldValue::U8(7));
        assert!(!has(ies[1], "ci"));
        assert_eq!(get(ies[2], "geographic_location_type"), &FieldValue::U8(9));
        assert_eq!(get(ies[2], "value"), &FieldValue::Bytes(&[0xAA, 0xBB]));
        assert_eq!(
            get(ies[3], "value"),
            &FieldValue::Bytes(&[0x62, 0xF2, 0x10])
        );
        assert_eq!(geographic_location_type_name(1), Some("SAI"));
    }

    #[test]
    fn tlv_fixed_length_mismatch_keeps_value() {
        let buf = parse(&[
            151, 0x00, 0x00, // RAT Type with Length 0
            148, 0x00, 0x00, // Common Flags with Length 0
            135, 0x00, 0x00, // QoS Profile with Length 0
            255, 0x00, 0x01, 0x00, // Private Extension too short
            131, 0x00, 0x00, // empty APN
        ]);
        let ies = ie_list(&buf);
        assert_eq!(ies.len(), 5);
        for ie in &ies[..4] {
            assert!(has(ie, "value"), "{ie:?}");
        }
        assert_eq!(get(ies[4], "apn"), &FieldValue::Bytes(&[]));
    }

    #[test]
    fn tlv_without_decoder_keeps_value() {
        // MS Time Zone (153) has no dedicated decoder.
        let buf = parse(&[153, 0x00, 0x02, 0x40, 0x00]);
        let ies = ie_list(&buf);
        assert_eq!(get(ies[0], "value"), &FieldValue::Bytes(&[0x40, 0x00]));
    }

    #[test]
    fn ie_type_extension() {
        // 3GPP TS 29.060, Section 7.7.0A — Length includes the 2-octet
        // IE Type Extension.
        let buf = parse(&[238, 0x00, 0x04, 0x01, 0x00, 0xAB, 0xCD, 14, 0x02]);
        let ies = ie_list(&buf);
        assert_eq!(ies.len(), 2);
        assert_eq!(get(ies[0], "extended_type"), &FieldValue::U16(256));
        assert_eq!(get(ies[0], "value"), &FieldValue::Bytes(&[0xAB, 0xCD]));
        assert_eq!(get(ies[1], "restart_counter"), &FieldValue::U8(2));

        let buf = parse(&[238, 0x00, 0x01, 0x01]);
        let ies = ie_list(&buf);
        assert!(!has(ies[0], "extended_type"));
        assert_eq!(get(ies[0], "value"), &FieldValue::Bytes(&[0x01]));
    }

    #[test]
    fn ie_container_display_name() {
        let buf = parse(&[14, 0x01]);
        assert_eq!(buf.resolve_container_display_name(0), Some("Recovery"));
    }

    #[test]
    fn ie_names() {
        assert_eq!(ie_type_name(1), Some("Cause"));
        assert_eq!(
            ie_type_name(2),
            Some("International Mobile Subscriber Identity (IMSI)")
        );
        assert_eq!(ie_type_name(29), Some("MS Not Reachable Reason"));
        assert_eq!(ie_type_name(127), Some("Charging ID"));
        assert_eq!(ie_type_name(128), Some("End User Address"));
        assert_eq!(
            ie_type_name(224),
            Some("UP Function Selection Indication Flags")
        );
        assert_eq!(
            ie_type_name(238),
            Some("Special IE type for IE Type Extension")
        );
        assert_eq!(ie_type_name(251), Some("Charging Gateway Address"));
        assert_eq!(ie_type_name(255), Some("Private Extension"));
        for v in [0u8, 6, 7, 10, 30, 116, 126, 172, 206, 225, 250] {
            assert_eq!(ie_type_name(v), None, "type {v}");
        }
    }

    #[test]
    fn cause_names() {
        assert_eq!(cause_name(0), Some("Request IMSI"));
        assert_eq!(cause_name(9), Some("QoS parameter mismatch"));
        assert_eq!(
            cause_name(130),
            Some("New PDP type due to single address bearer only")
        );
        assert_eq!(cause_name(192), Some("Non-existent"));
        assert_eq!(
            cause_name(233),
            Some("Relocation failure due to NAS message redirection")
        );
        for v in [10u8, 63, 127, 131, 191, 234, 255] {
            assert_eq!(cause_name(v), None, "cause {v}");
        }
    }

    #[test]
    fn tbcd_special_digits() {
        let mut out = Vec::new();
        format_tbcd_to(&[0xBA, 0xDC, 0xFE], &mut out).unwrap();
        assert_eq!(out, b"\"*#abc\"");
        let mut out = Vec::new();
        format_tbcd_to(&[], &mut out).unwrap();
        assert_eq!(out, b"\"\"");
    }
}
