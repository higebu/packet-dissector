//! 5G NAS information element framing and value decoding.
//!
//! A 5GMM or 5GSM message body is an imperative part of mandatory IEs in a
//! fixed order (formats V, LV and LV-E, no IEI) followed by a non-imperative
//! part of optional IEs, each starting with an IEI (formats TV, TLV and
//! TLV-E). The per-message layouts are in [`crate::messages`].
//!
//! ## References
//! - 3GPP TS 24.501, Section 8.1 (message contents), 9.11 (IEs):
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.501/>
//! - 3GPP TS 24.007, Section 11.2.1.1.4 (IE categories), 11.2.4
//!   (non-imperative part, unknown IEIs):
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.007/>
//! - 3GPP TS 24.008, Section 10.5.3.1 (RAND), 10.5.3.1.1 (AUTN):
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.008/>
//! - 3GPP TS 24.301, Section 9.9.3.4 (authentication response parameter):
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.301/>

use std::io::{self, Write};

use packet_dissector_core::field::{
    FieldDescriptor, FieldType, FieldValue, FormatContext, MacAddr, format_fqdn_labels,
    format_utf8_lossy,
};
use packet_dissector_core::packet::DissectBuffer;

use crate::messages::MessageIes;

// ── IE layout descriptors ──────────────────────────────────────────────

/// Format of a mandatory IE in the imperative part of a message.
///
/// 3GPP TS 24.007, Section 11.2.1.1.4.
#[derive(Clone, Copy)]
pub(crate) enum MandatoryFormat {
    /// Type 1 IE of format V: a half octet.
    Half,
    /// Type 3 IE of format V with a value part of the given octet length.
    V(usize),
    /// Type 4 IE of format LV: one length octet.
    Lv,
    /// Type 6 IE of format LV-E: two length octets.
    LvE,
}

/// Format of a known optional IE in the non-imperative part of a message.
///
/// 3GPP TS 24.007, Section 11.2.1.1.4.
#[derive(Clone, Copy)]
pub(crate) enum OptionalFormat {
    /// Type 1 IE of format TV: half-octet IEI in bits 8 to 5 and a half
    /// octet value in bits 4 to 1.
    Tv1,
    /// Type 3 IE of format TV with a value part of the given octet length
    /// (the total IE length minus the IEI octet).
    Tv(usize),
    /// Type 4 IE of format TLV.
    Tlv,
    /// Type 6 IE of format TLV-E.
    TlvE,
}

/// How the value part of an IE is decoded.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Value {
    /// Opaque value: raw bytes, or a `U8` for a half-octet IE.
    Raw,
    /// Spare half octet (TS 24.501, 9.5); not emitted.
    Spare,
    /// 5GS mobile identity (TS 24.501, 9.11.3.4).
    MobileIdentity,
    /// NAS key set identifier (TS 24.501, 9.11.3.32).
    NasKeySetIdentifier,
    /// 5GS registration type (TS 24.501, 9.11.3.7).
    RegistrationType,
    /// 5GS registration result (TS 24.501, 9.11.3.6).
    RegistrationResult,
    /// 5GMM cause (TS 24.501, 9.11.3.2).
    MmCause,
    /// 5GSM cause (TS 24.501, 9.11.4.2).
    SmCause,
    /// NSSAI (TS 24.501, 9.11.3.37).
    Nssai,
    /// S-NSSAI (TS 24.501, 9.11.2.8).
    SNssai,
    /// 5GS tracking area identity (TS 24.501, 9.11.3.8).
    TrackingAreaIdentity,
    /// 5GS tracking area identity list (TS 24.501, 9.11.3.9).
    TrackingAreaIdentityList,
    /// UE security capability (TS 24.501, 9.11.3.54).
    UeSecurityCapability,
    /// NAS security algorithms (TS 24.501, 9.11.3.34).
    NasSecurityAlgorithms,
    /// Payload container type (TS 24.501, 9.11.3.40).
    PayloadContainerType,
    /// Payload container (TS 24.501, 9.11.3.39).
    PayloadContainer,
    /// PDU session identity 2 (TS 24.501, 9.11.3.41).
    PduSessionIdentity2,
    /// Request type (TS 24.501, 9.11.3.47).
    RequestType,
    /// 5GS identity type (TS 24.501, 9.11.3.3).
    IdentityType,
    /// De-registration type (TS 24.501, 9.11.3.20).
    DeregistrationType,
    /// Service type (TS 24.501, 9.11.3.50).
    ServiceType,
    /// PDU session type (TS 24.501, 9.11.4.11).
    PduSessionType,
    /// SSC mode (TS 24.501, 9.11.4.16).
    SscMode,
    /// DNN (TS 24.501, 9.11.2.1B).
    Dnn,
    /// PDU address (TS 24.501, 9.11.4.10).
    PduAddress,
    /// QoS rules (TS 24.501, 9.11.4.13).
    QosRules,
    /// QoS flow descriptions (TS 24.501, 9.11.4.12).
    QosFlowDescriptions,
    /// Session-AMBR (TS 24.501, 9.11.4.14).
    SessionAmbr,
    /// Integrity protection maximum data rate (TS 24.501, 9.11.4.7).
    IntegrityProtectionMaximumDataRate,
}

/// A mandatory IE of a message, in the order of its message content table.
pub(crate) struct MandatoryIe {
    /// IE name as written in the message content table.
    pub name: &'static str,
    /// IE format.
    pub format: MandatoryFormat,
    /// Value decoder.
    pub value: Value,
}

/// A known optional IE of a message.
pub(crate) struct OptionalIe {
    /// IEI. For a type 1 IE this is the half-octet IEI (bits 8 to 5).
    pub iei: u8,
    /// IE name as written in the message content table.
    pub name: &'static str,
    /// IE format.
    pub format: OptionalFormat,
    /// Value decoder.
    pub value: Value,
}

// ── Name tables ────────────────────────────────────────────────────────

/// 5GMM cause value name.
///
/// 3GPP TS 24.501, Section 9.11.3.2, Table 9.11.3.2.1.
pub(crate) fn mm_cause_name(cause: u8) -> Option<&'static str> {
    Some(match cause {
        3 => "Illegal UE",
        5 => "PEI not accepted",
        6 => "Illegal ME",
        7 => "5GS services not allowed",
        9 => "UE identity cannot be derived by the network",
        10 => "Implicitly de-registered",
        11 => "PLMN not allowed",
        12 => "Tracking area not allowed",
        13 => "Roaming not allowed in this tracking area",
        15 => "No suitable cells in tracking area",
        20 => "MAC failure",
        21 => "Synch failure",
        22 => "Congestion",
        23 => "UE security capabilities mismatch",
        24 => "Security mode rejected, unspecified",
        26 => "Non-5G authentication unacceptable",
        27 => "N1 mode not allowed",
        28 => "Restricted service area",
        31 => "Redirection to EPC required",
        36 => "IAB-node operation not authorized",
        43 => "LADN not available",
        62 => "No network slices available",
        65 => "Maximum number of PDU sessions reached",
        67 => "Insufficient resources for specific slice and DNN",
        69 => "Insufficient resources for specific slice",
        71 => "ngKSI already in use",
        72 => "Non-3GPP access to 5GCN not allowed",
        73 => "Serving network not authorized",
        74 => "Temporarily not authorized for this SNPN",
        75 => "Permanently not authorized for this SNPN",
        76 => "Not authorized for this CAG or authorized for CAG cells only",
        77 => "Wireline access area not allowed",
        78 => "PLMN not allowed to operate at the present UE location",
        79 => "UAS services not allowed",
        80 => "Disaster roaming for the determined PLMN with disaster condition not allowed",
        81 => "Selected N3IWF is not compatible with the allowed NSSAI",
        82 => "Selected TNGF is not compatible with the allowed NSSAI",
        90 => "Payload was not forwarded",
        91 => "DNN not supported or not subscribed in the slice",
        92 => "Insufficient user-plane resources for the PDU session",
        93 => "Onboarding services terminated",
        94 => "User plane positioning not authorized",
        _ => return common_cause_name(cause),
    })
}

/// 5GSM cause value name.
///
/// 3GPP TS 24.501, Section 9.11.4.2, Table 9.11.4.2.1.
pub(crate) fn sm_cause_name(cause: u8) -> Option<&'static str> {
    Some(match cause {
        8 => "Operator determined barring",
        26 => "Insufficient resources",
        27 => "Missing or unknown DNN",
        28 => "Unknown PDU session type",
        29 => "User authentication or authorization failed",
        31 => "Request rejected, unspecified",
        32 => "Service option not supported",
        33 => "Requested service option not subscribed",
        35 => "PTI already in use",
        36 => "Regular deactivation",
        37 => "5GS QoS not accepted",
        38 => "Network failure",
        39 => "Reactivation requested",
        41 => "Semantic error in the TFT operation",
        42 => "Syntactical error in the TFT operation",
        43 => "Invalid PDU session identity",
        44 => "Semantic errors in packet filter(s)",
        45 => "Syntactical error in packet filter(s)",
        46 => "Out of LADN service area",
        47 => "PTI mismatch",
        50 => "PDU session type IPv4 only allowed",
        51 => "PDU session type IPv6 only allowed",
        54 => "PDU session does not exist",
        57 => "PDU session type IPv4v6 only allowed",
        58 => "PDU session type Unstructured only allowed",
        59 => "Unsupported 5QI value",
        61 => "PDU session type Ethernet only allowed",
        67 => "Insufficient resources for specific slice and DNN",
        68 => "Not supported SSC mode",
        69 => "Insufficient resources for specific slice",
        70 => "Missing or unknown DNN in a slice",
        81 => "Invalid PTI value",
        82 => "Maximum data rate per UE for user-plane integrity protection is too low",
        83 => "Semantic error in the QoS operation",
        84 => "Syntactical error in the QoS operation",
        85 => "Invalid mapped EPS bearer identity",
        86 => "UAS services not allowed",
        87 => "QoS differentiation for non-3GPP device identifier(s) not available",
        _ => return common_cause_name(cause),
    })
}

/// Protocol error cause values shared by Tables 9.11.3.2.1 and 9.11.4.2.1
/// of 3GPP TS 24.501.
fn common_cause_name(cause: u8) -> Option<&'static str> {
    Some(match cause {
        95 => "Semantically incorrect message",
        96 => "Invalid mandatory information",
        97 => "Message type non-existent or not implemented",
        98 => "Message type not compatible with the protocol state",
        99 => "Information element non-existent or not implemented",
        100 => "Conditional IE error",
        101 => "Message not compatible with the protocol state",
        111 => "Protocol error, unspecified",
        _ => return None,
    })
}

/// Type of identity name of a 5GS mobile identity.
///
/// 3GPP TS 24.501, Section 9.11.3.4, Table 9.11.3.4.1.
fn type_of_identity_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0 => "No identity",
        1 => "SUCI",
        2 => "5G-GUTI",
        3 => "IMEI",
        4 => "5G-S-TMSI",
        5 => "IMEISV",
        6 => "MAC address",
        7 => "EUI-64",
        _ => return None,
    })
}

/// Type of identity name of a 5GS identity type IE.
///
/// 3GPP TS 24.501, Section 9.11.3.3, Table 9.11.3.3.1. Unlike Table
/// 9.11.3.4.1, value 0 is not "No identity": "All other values are unused
/// and shall be interpreted as \"SUCI\", if received by the UE."
fn identity_type_name(t: u8) -> Option<&'static str> {
    match t {
        0 => None,
        _ => type_of_identity_name(t),
    }
}

/// SUPI format name.
///
/// 3GPP TS 24.501, Section 9.11.3.4, Table 9.11.3.4.1: "All other values
/// are interpreted as IMSI by this version of the protocol."
fn supi_format_name(f: u8) -> Option<&'static str> {
    Some(match f {
        1 => "Network specific identifier",
        2 => "GCI",
        3 => "GLI",
        _ => "IMSI",
    })
}

/// Protection scheme identifier name.
///
/// 3GPP TS 24.501, Section 9.11.3.4, Table 9.11.3.4.1.
fn protection_scheme_name(p: u8) -> Option<&'static str> {
    Some(match p {
        0 => "Null scheme",
        1 => "ECIES scheme profile A",
        2 => "ECIES scheme profile B",
        3..=11 => "Reserved",
        _ => "Operator-specific protection scheme",
    })
}

/// SUPI format "IMSI" (TS 24.501, Table 9.11.3.4.1) as used for decoding.
fn is_imsi_supi_format(f: u8) -> bool {
    !matches!(f, 1..=3)
}

/// 5GS registration type value name.
///
/// 3GPP TS 24.501, Section 9.11.3.7, Table 9.11.3.7.1.
fn registration_type_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "initial registration",
        2 => "mobility registration updating",
        3 => "periodic registration updating",
        4 => "emergency registration",
        5 => "SNPN onboarding registration",
        6 => "disaster roaming mobility registration updating",
        7 => "disaster roaming initial registration",
        _ => return None,
    })
}

/// 5GS registration result value name.
///
/// 3GPP TS 24.501, Section 9.11.3.6, Table 9.11.3.6.1.
fn registration_result_name(r: u8) -> Option<&'static str> {
    Some(match r {
        1 => "3GPP access",
        2 => "Non-3GPP access",
        3 => "3GPP access and non-3GPP access",
        7 => "reserved",
        _ => return None,
    })
}

/// Type of security context flag (TSC) name.
///
/// 3GPP TS 24.501, Section 9.11.3.32, Table 9.11.3.32.1.
fn tsc_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0 => "native security context",
        _ => "mapped security context",
    })
}

/// NAS key set identifier name.
///
/// 3GPP TS 24.501, Section 9.11.3.32, Table 9.11.3.32.1: value "111" is
/// "no key is available (UE to network); reserved (network to UE)".
fn ksi_name(k: u8) -> Option<&'static str> {
    (k == 7).then_some("no key is available (UE to network); reserved (network to UE)")
}

/// Type of list name of a partial tracking area identity list.
///
/// 3GPP TS 24.501, Section 9.11.3.9, Table 9.11.3.9.1.
fn type_of_list_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0 => "list of TACs belonging to one PLMN or SNPN, with non-consecutive TAC values",
        1 => "list of TACs belonging to one PLMN or SNPN, with consecutive TAC values",
        2 => "list of TAIs belonging to different PLMNs",
        _ => return None,
    })
}

/// Type of ciphering algorithm name.
///
/// 3GPP TS 24.501, Section 9.11.3.34, Table 9.11.3.34.1.
fn ciphering_algorithm_name(a: u8) -> Option<&'static str> {
    Some(match a {
        0 => "5G encryption algorithm 5G-EA0 (null ciphering algorithm)",
        1 => "5G encryption algorithm 128-5G-EA1",
        2 => "5G encryption algorithm 128-5G-EA2",
        3 => "5G encryption algorithm 128-5G-EA3",
        4 => "5G encryption algorithm 5G-EA4",
        5 => "5G encryption algorithm 5G-EA5",
        6 => "5G encryption algorithm 5G-EA6",
        7 => "5G encryption algorithm 5G-EA7",
        _ => return None,
    })
}

/// Type of integrity protection algorithm name.
///
/// 3GPP TS 24.501, Section 9.11.3.34, Table 9.11.3.34.1.
fn integrity_algorithm_name(a: u8) -> Option<&'static str> {
    Some(match a {
        0 => "5G integrity algorithm 5G-IA0 (null integrity protection algorithm)",
        1 => "5G integrity algorithm 128-5G-IA1",
        2 => "5G integrity algorithm 128-5G-IA2",
        3 => "5G integrity algorithm 128-5G-IA3",
        4 => "5G integrity algorithm 5G-IA4",
        5 => "5G integrity algorithm 5G-IA5",
        6 => "5G integrity algorithm 5G-IA6",
        7 => "5G integrity algorithm 5G-IA7",
        _ => return None,
    })
}

/// Payload container type value name.
///
/// 3GPP TS 24.501, Section 9.11.3.40, Table 9.11.3.40.1.
fn payload_container_type_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "N1 SM information",
        2 => "SMS",
        3 => "LTE Positioning Protocol (LPP) message container",
        4 => "SOR transparent container",
        5 => "UE policy container",
        6 => "UE parameters update transparent container",
        7 => "Location services message container",
        8 => "CIoT user data container",
        9 => "Service-level-AA container",
        10 => "Event notification",
        11 => "UPP-CMI container",
        12 => "SLPP message container",
        15 => "Multiple payloads",
        _ => return None,
    })
}

/// Payload container type "N1 SM information".
///
/// 3GPP TS 24.501, Section 9.11.3.40, Table 9.11.3.40.1.
const PAYLOAD_CONTAINER_TYPE_N1_SM: u8 = 1;

/// Request type value name.
///
/// 3GPP TS 24.501, Section 9.11.3.47, Table 9.11.3.47.1.
fn request_type_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "initial request",
        2 => "existing PDU session",
        3 => "initial emergency request",
        4 => "existing emergency PDU session",
        5 => "modification request",
        6 => "MA PDU request",
        7 => "reserved",
        _ => return None,
    })
}

/// Access type name of the De-registration type IE.
///
/// 3GPP TS 24.501, Section 9.11.3.20, Table 9.11.3.20.1.
fn access_type_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "3GPP access",
        2 => "Non-3GPP access",
        3 => "3GPP access and non-3GPP access",
        _ => return None,
    })
}

/// Service type value name.
///
/// 3GPP TS 24.501, Section 9.11.3.50, Table 9.11.3.50.1.
fn service_type_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0 => "signalling",
        1 => "data",
        2 => "mobile terminated services",
        3 => "emergency services",
        4 => "emergency services fallback",
        5 => "high priority access",
        6 => "elevated signalling",
        7 | 8 => "unused; shall be interpreted as \"signalling\", if received by the network",
        9..=11 => "unused; shall be interpreted as \"data\", if received by the network",
        _ => return None,
    })
}

/// PDU session type value name.
///
/// 3GPP TS 24.501, Section 9.11.4.11, Table 9.11.4.11.1 (also used by the
/// PDU address IE, Table 9.11.4.10.1).
fn pdu_session_type_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "IPv4",
        2 => "IPv6",
        3 => "IPv4v6",
        4 => "Unstructured",
        5 => "Ethernet",
        7 => "reserved",
        _ => return None,
    })
}

/// SSC mode value name.
///
/// 3GPP TS 24.501, Section 9.11.4.16, Table 9.11.4.16.1.
fn ssc_mode_name(m: u8) -> Option<&'static str> {
    Some(match m {
        1 => "SSC mode 1",
        2 => "SSC mode 2",
        3 => "SSC mode 3",
        4 => "unused; shall be interpreted as \"SSC mode 1\", if received by the network",
        5 => "unused; shall be interpreted as \"SSC mode 2\", if received by the network",
        6 => "unused; shall be interpreted as \"SSC mode 3\", if received by the network",
        _ => return None,
    })
}

/// Maximum data rate per UE for user-plane integrity protection name.
///
/// 3GPP TS 24.501, Section 9.11.4.7, Table 9.11.4.7.2.
fn integrity_max_data_rate_name(r: u8) -> Option<&'static str> {
    Some(match r {
        0 => "64 kbps",
        1 => "NULL",
        0xff => "Full data rate",
        _ => return None,
    })
}

/// Bit rate unit name.
///
/// 3GPP TS 24.501, Section 9.11.4.14, Table 9.11.4.14.1 (Session-AMBR) and
/// Section 9.11.4.12, Table 9.11.4.12.1 (GFBR/MFBR). "Other values shall be
/// interpreted as multiples of 256 Pbps in this version of the protocol."
fn bit_rate_unit_name(u: u8) -> Option<&'static str> {
    Some(match u {
        0 => "value is not used",
        1 => "1 Kbps",
        2 => "4 Kbps",
        3 => "16 Kbps",
        4 => "64 Kbps",
        5 => "256 Kbps",
        6 => "1 Mbps",
        7 => "4 Mbps",
        8 => "16 Mbps",
        9 => "64 Mbps",
        10 => "256 Mbps",
        11 => "1 Gbps",
        12 => "4 Gbps",
        13 => "16 Gbps",
        14 => "64 Gbps",
        15 => "256 Gbps",
        16 => "1 Tbps",
        17 => "4 Tbps",
        18 => "16 Tbps",
        19 => "64 Tbps",
        20 => "256 Tbps",
        21 => "1 Pbps",
        22 => "4 Pbps",
        23 => "16 Pbps",
        24 => "64 Pbps",
        _ => "256 Pbps",
    })
}

/// QoS rule operation code name.
///
/// 3GPP TS 24.501, Section 9.11.4.13, Table 9.11.4.13.1.
fn rule_operation_code_name(op: u8) -> Option<&'static str> {
    Some(match op {
        1 => "Create new QoS rule",
        2 => "Delete existing QoS rule",
        3 => "Modify existing QoS rule and add packet filters",
        4 => "Modify existing QoS rule and replace all packet filters",
        5 => "Modify existing QoS rule and delete packet filters",
        6 => "Modify existing QoS rule without modifying packet filters",
        _ => "Reserved",
    })
}

/// Rule operation code "modify existing QoS rule and delete packet
/// filters", whose packet filter list holds identifiers only.
///
/// 3GPP TS 24.501, Section 9.11.4.13, Figure 9.11.4.13.3.
const RULE_OP_DELETE_PACKET_FILTERS: u8 = 5;

/// Packet filter direction name.
///
/// 3GPP TS 24.501, Section 9.11.4.13, Table 9.11.4.13.1.
fn packet_filter_direction_name(d: u8) -> Option<&'static str> {
    Some(match d {
        1 => "downlink only",
        2 => "uplink only",
        3 => "bidirectional",
        _ => "reserved",
    })
}

/// QoS flow description operation code name.
///
/// 3GPP TS 24.501, Section 9.11.4.12, Table 9.11.4.12.1.
fn flow_operation_code_name(op: u8) -> Option<&'static str> {
    Some(match op {
        1 => "Create new QoS flow description",
        2 => "Delete existing QoS flow description",
        3 => "Modify existing QoS flow description",
        _ => "reserved",
    })
}

/// QoS flow description parameter identifier name.
///
/// 3GPP TS 24.501, Section 9.11.4.12, Table 9.11.4.12.1.
fn parameter_identifier_name(id: u8) -> Option<&'static str> {
    Some(match id {
        0x01 => "5QI",
        0x02 => "GFBR uplink",
        0x03 => "GFBR downlink",
        0x04 => "MFBR uplink",
        0x05 => "MFBR downlink",
        0x06 => "Averaging window",
        0x07 => "EPS bearer identity",
        _ => return None,
    })
}

// ── Format functions ───────────────────────────────────────────────────

/// Write BCD digits as a JSON string, stopping at the first "1111" nibble.
///
/// Non-decimal nibbles other than the end mark are written as hexadecimal
/// digits so abnormal encodings stay visible.
fn write_digits(w: &mut dyn Write, digits: impl Iterator<Item = u8>) -> io::Result<()> {
    w.write_all(b"\"")?;
    for d in digits {
        if d == 0x0f {
            break;
        }
        let c = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        w.write_all(&[c])?;
    }
    w.write_all(b"\"")
}

/// Nibbles of `bytes`, low nibble first.
fn nibbles(bytes: &[u8]) -> impl Iterator<Item = u8> + '_ {
    bytes.iter().flat_map(|b| [b & 0x0f, b >> 4])
}

/// Format BCD digits packed low nibble first (MSIN, routing indicator).
///
/// 3GPP TS 24.501, Section 9.11.3.4.
fn format_bcd(v: &FieldValue<'_>, _ctx: &FormatContext<'_>, w: &mut dyn Write) -> io::Result<()> {
    let FieldValue::Bytes(b) = v else {
        return w.write_all(b"\"\"");
    };
    write_digits(w, nibbles(b))
}

/// Format identity digits of an IMEI or IMEISV: digit 1 is in bits 5 to 8
/// of octet 4 (the first value octet), then two digits per octet.
///
/// 3GPP TS 24.501, Section 9.11.3.4, Figure 9.11.3.4.2.
fn format_identity_digits(
    v: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn Write,
) -> io::Result<()> {
    let FieldValue::Bytes(b) = v else {
        return w.write_all(b"\"\"");
    };
    write_digits(w, nibbles(b).skip(1))
}

/// Format the MCC of a 3-octet PLMN identity.
///
/// 3GPP TS 24.501, Section 9.11.3.4: MCC digit 1 and 2 in octet 1, digit 3
/// in bits 1 to 4 of octet 2 (TS 24.008, Figure 10.5.154).
fn format_mcc(v: &FieldValue<'_>, _ctx: &FormatContext<'_>, w: &mut dyn Write) -> io::Result<()> {
    let &FieldValue::Bytes(&[b0, b1, _]) = v else {
        return w.write_all(b"\"\"");
    };
    write_digits(w, [b0 & 0x0f, b0 >> 4, b1 & 0x0f].into_iter())
}

/// Format the MNC of a 3-octet PLMN identity.
///
/// 3GPP TS 24.501, Section 9.11.3.4: MNC digit 1 and 2 in octet 3, digit 3
/// in bits 5 to 8 of octet 2, coded "1111" for a two-digit MNC.
fn format_mnc(v: &FieldValue<'_>, _ctx: &FormatContext<'_>, w: &mut dyn Write) -> io::Result<()> {
    let &FieldValue::Bytes(&[_, b1, b2]) = v else {
        return w.write_all(b"\"\"");
    };
    write_digits(w, [b2 & 0x0f, b2 >> 4, b1 >> 4].into_iter())
}

// ── Field descriptors ──────────────────────────────────────────────────

macro_rules! named_u8 {
    ($ident:ident, $name:literal, $display:literal, $f:path) => {
        static $ident: FieldDescriptor = FieldDescriptor::new($name, $display, FieldType::U8)
            .optional()
            .with_display_fn(|v, _| match v {
                FieldValue::U8(x) => $f(*x),
                _ => None,
            });
    };
}

macro_rules! plain {
    ($ident:ident, $name:literal, $display:literal, $ty:ident) => {
        static $ident: FieldDescriptor =
            FieldDescriptor::new($name, $display, FieldType::$ty).optional();
    };
}

// Common IE fields.
static FD_IE_NAME: FieldDescriptor = FieldDescriptor::new("name", "Name", FieldType::Str);
plain!(FD_IE_IEI, "iei", "IEI", U8);
plain!(FD_IE_LENGTH_U8, "length", "Length", U8);
plain!(FD_IE_LENGTH_U16, "length", "Length", U16);
plain!(FD_IE_VALUE, "value", "Value", Bytes);
plain!(FD_IE_VALUE_U8, "value", "Value", U8);

// PLMN identity and tracking area.
static FD_MCC: FieldDescriptor = FieldDescriptor::new("mcc", "MCC", FieldType::Bytes)
    .optional()
    .with_format_fn(format_mcc);
static FD_MNC: FieldDescriptor = FieldDescriptor::new("mnc", "MNC", FieldType::Bytes)
    .optional()
    .with_format_fn(format_mnc);
plain!(FD_TAC, "tac", "TAC", U32);

// 5GS mobile identity (9.11.3.4).
named_u8!(
    FD_TYPE_OF_IDENTITY,
    "type_of_identity",
    "Type of Identity",
    type_of_identity_name
);
plain!(
    FD_ODD_EVEN,
    "odd_even_indication",
    "Odd/Even Indication",
    U8
);
static FD_IDENTITY_DIGITS: FieldDescriptor =
    FieldDescriptor::new("identity_digits", "Identity Digits", FieldType::Bytes)
        .optional()
        .with_format_fn(format_identity_digits);
named_u8!(
    FD_SUPI_FORMAT,
    "supi_format",
    "SUPI Format",
    supi_format_name
);
static FD_ROUTING_INDICATOR: FieldDescriptor =
    FieldDescriptor::new("routing_indicator", "Routing Indicator", FieldType::Bytes)
        .optional()
        .with_format_fn(format_bcd);
named_u8!(
    FD_PROTECTION_SCHEME,
    "protection_scheme_id",
    "Protection Scheme Id",
    protection_scheme_name
);
plain!(
    FD_HN_PKI,
    "home_network_public_key_id",
    "Home Network Public Key Identifier",
    U8
);
static FD_MSIN: FieldDescriptor = FieldDescriptor::new("msin", "MSIN", FieldType::Bytes)
    .optional()
    .with_format_fn(format_bcd);
plain!(FD_SCHEME_OUTPUT, "scheme_output", "Scheme Output", Bytes);
static FD_SUCI_NAI: FieldDescriptor =
    FieldDescriptor::new("suci_nai", "SUCI NAI", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy);
plain!(FD_AMF_REGION_ID, "amf_region_id", "AMF Region ID", U8);
plain!(FD_AMF_SET_ID, "amf_set_id", "AMF Set ID", U16);
plain!(FD_AMF_POINTER, "amf_pointer", "AMF Pointer", U8);
plain!(FD_TMSI, "tmsi_5g", "5G-TMSI", U32);
plain!(
    FD_MAURI,
    "mauri",
    "MAC Address Usage Restriction Indication",
    U8
);
plain!(FD_MAC_ADDRESS, "mac_address", "MAC Address", MacAddr);
plain!(FD_EUI64, "eui_64", "EUI-64", Bytes);

// 5GS identity type (9.11.3.3).
named_u8!(
    FD_IDENTITY_TYPE,
    "type_of_identity",
    "Type of Identity",
    identity_type_name
);

// NAS key set identifier (9.11.3.32).
named_u8!(FD_TSC, "tsc", "Type of Security Context", tsc_name);
named_u8!(
    FD_KSI,
    "nas_key_set_identifier",
    "NAS Key Set Identifier",
    ksi_name
);

// 5GS registration type (9.11.3.7).
plain!(FD_FOR, "follow_on_request", "Follow-on Request", U8);
named_u8!(
    FD_REGISTRATION_TYPE,
    "registration_type",
    "5GS Registration Type Value",
    registration_type_name
);

// 5GS registration result (9.11.3.6).
plain!(
    FD_DISASTER_ROAMING_RESULT,
    "disaster_roaming_registration_result",
    "Disaster Roaming Registration Result",
    U8
);
plain!(
    FD_EMERGENCY_REGISTERED,
    "emergency_registered",
    "Emergency Registered",
    U8
);
plain!(
    FD_NSSAA,
    "nssaa_to_be_performed",
    "NSSAA To Be Performed",
    U8
);
plain!(FD_SMS_ALLOWED, "sms_allowed", "SMS Allowed", U8);
named_u8!(
    FD_REGISTRATION_RESULT,
    "registration_result",
    "5GS Registration Result Value",
    registration_result_name
);

// Causes (9.11.3.2, 9.11.4.2).
named_u8!(FD_MM_CAUSE, "cause", "Cause", mm_cause_name);
named_u8!(FD_SM_CAUSE, "cause", "Cause", sm_cause_name);

// S-NSSAI (9.11.2.8) and NSSAI (9.11.3.37).
plain!(FD_SST, "sst", "SST", U8);
plain!(FD_SD, "sd", "SD", U32);
plain!(FD_MAPPED_SST, "mapped_hplmn_sst", "Mapped HPLMN SST", U8);
plain!(FD_MAPPED_SD, "mapped_hplmn_sd", "Mapped HPLMN SD", U32);
static S_NSSAI_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("sst", "SST", FieldType::U8),
    FieldDescriptor::new("sd", "SD", FieldType::U32).optional(),
    FieldDescriptor::new("mapped_hplmn_sst", "Mapped HPLMN SST", FieldType::U8).optional(),
    FieldDescriptor::new("mapped_hplmn_sd", "Mapped HPLMN SD", FieldType::U32).optional(),
];
static FD_S_NSSAI: FieldDescriptor =
    FieldDescriptor::new("s_nssai", "S-NSSAI", FieldType::Object).with_children(S_NSSAI_CHILDREN);
static FD_S_NSSAI_LIST: FieldDescriptor =
    FieldDescriptor::new("s_nssai_list", "S-NSSAI List", FieldType::Array)
        .optional()
        .with_children(S_NSSAI_CHILDREN);

// 5GS tracking area identity list (9.11.3.9).
static TAI_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("mcc", "MCC", FieldType::Bytes).with_format_fn(format_mcc),
    FieldDescriptor::new("mnc", "MNC", FieldType::Bytes).with_format_fn(format_mnc),
    FieldDescriptor::new("tac", "TAC", FieldType::U32),
];
static FD_TAI: FieldDescriptor =
    FieldDescriptor::new("tai", "TAI", FieldType::Object).with_children(TAI_CHILDREN);
named_u8!(
    FD_TYPE_OF_LIST,
    "type_of_list",
    "Type of List",
    type_of_list_name
);
plain!(
    FD_NUMBER_OF_ELEMENTS,
    "number_of_elements",
    "Number of Elements",
    U8
);
static FD_TAIS: FieldDescriptor = FieldDescriptor::new("tais", "TAIs", FieldType::Array)
    .optional()
    .with_children(TAI_CHILDREN);
static PARTIAL_TAI_LIST_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("type_of_list", "Type of List", FieldType::U8),
    FieldDescriptor::new("number_of_elements", "Number of Elements", FieldType::U8),
    FieldDescriptor::new("tais", "TAIs", FieldType::Array).with_children(TAI_CHILDREN),
];
static FD_PARTIAL_TAI_LIST: FieldDescriptor =
    FieldDescriptor::new("partial_tai_list", "Partial TAI List", FieldType::Object)
        .with_children(PARTIAL_TAI_LIST_CHILDREN);
static FD_PARTIAL_TAI_LISTS: FieldDescriptor =
    FieldDescriptor::new("partial_tai_lists", "Partial TAI Lists", FieldType::Array)
        .optional()
        .with_children(PARTIAL_TAI_LIST_CHILDREN);

// UE security capability (9.11.3.54).
plain!(FD_EA_5G, "ea_5g", "5GS Encryption Algorithms", U8);
plain!(FD_IA_5G, "ia_5g", "5GS Integrity Algorithms", U8);
plain!(FD_EEA, "eea", "EPS Encryption Algorithms", U8);
plain!(FD_EIA, "eia", "EPS Integrity Algorithms", U8);

// NAS security algorithms (9.11.3.34).
named_u8!(
    FD_CIPHERING_ALGORITHM,
    "ciphering_algorithm",
    "Type of Ciphering Algorithm",
    ciphering_algorithm_name
);
named_u8!(
    FD_INTEGRITY_ALGORITHM,
    "integrity_algorithm",
    "Type of Integrity Protection Algorithm",
    integrity_algorithm_name
);

// Transport IEs (9.11.3.39, 9.11.3.40, 9.11.3.41, 9.11.3.47).
named_u8!(
    FD_PAYLOAD_CONTAINER_TYPE,
    "payload_container_type",
    "Payload Container Type",
    payload_container_type_name
);
/// Fields of a 5GSM message decoded from an N1 SM payload container.
///
/// An array static, referenced by address, so the recursive schema
/// (`information_elements` → `n1_sm_message` → `information_elements`)
/// does not form an initializer cycle.
static N1_SM_CHILDREN: [FieldDescriptor; 7] = [
    crate::FD_EPD,
    crate::FD_PDU_SESSION_ID,
    crate::FD_PTI,
    crate::FD_SM_MESSAGE_TYPE,
    FD_INFORMATION_ELEMENTS,
    FD_UNDECODED_OCTETS,
    FD_MISSING_MANDATORY_IE,
];
static FD_N1_SM_MESSAGE: FieldDescriptor =
    FieldDescriptor::new("n1_sm_message", "N1 SM Message", FieldType::Object)
        .optional()
        .with_children(&N1_SM_CHILDREN);
plain!(FD_PDU_SESSION_ID, "pdu_session_id", "PDU Session ID", U8);
named_u8!(
    FD_REQUEST_TYPE,
    "request_type",
    "Request Type",
    request_type_name
);

// De-registration type (9.11.3.20) and service type (9.11.3.50).
plain!(FD_SWITCH_OFF, "switch_off", "Switch Off", U8);
plain!(
    FD_REREGISTRATION_REQUIRED,
    "re_registration_required",
    "Re-registration Required",
    U8
);
named_u8!(
    FD_ACCESS_TYPE,
    "access_type",
    "Access Type",
    access_type_name
);
named_u8!(
    FD_SERVICE_TYPE,
    "service_type",
    "Service Type",
    service_type_name
);

// 5GSM IEs (9.11.2.1B, 9.11.4.x).
named_u8!(
    FD_PDU_SESSION_TYPE,
    "pdu_session_type",
    "PDU Session Type",
    pdu_session_type_name
);
named_u8!(FD_SSC_MODE, "ssc_mode", "SSC Mode", ssc_mode_name);
static FD_DNN: FieldDescriptor = FieldDescriptor::new("dnn", "DNN", FieldType::Bytes)
    .optional()
    .with_format_fn(format_fqdn_labels);
plain!(
    FD_SI6LLA,
    "si6lla",
    "SMF's IPv6 Link Local Address Present",
    U8
);
plain!(FD_IPV4_ADDRESS, "ipv4_address", "IPv4 Address", Ipv4Addr);
plain!(
    FD_IPV6_IID,
    "ipv6_interface_identifier",
    "IPv6 Interface Identifier",
    Bytes
);
plain!(
    FD_SMF_IPV6_LLA,
    "smf_ipv6_link_local_address",
    "SMF's IPv6 Link Local Address",
    Ipv6Addr
);
named_u8!(
    FD_UPLINK_RATE,
    "max_data_rate_uplink",
    "Maximum Data Rate for Uplink",
    integrity_max_data_rate_name
);
named_u8!(
    FD_DOWNLINK_RATE,
    "max_data_rate_downlink",
    "Maximum Data Rate for Downlink",
    integrity_max_data_rate_name
);
named_u8!(
    FD_AMBR_DL_UNIT,
    "downlink_unit",
    "Unit for Session-AMBR for Downlink",
    bit_rate_unit_name
);
plain!(
    FD_AMBR_DL,
    "downlink_ambr",
    "Session-AMBR for Downlink",
    U16
);
named_u8!(
    FD_AMBR_UL_UNIT,
    "uplink_unit",
    "Unit for Session-AMBR for Uplink",
    bit_rate_unit_name
);
plain!(FD_AMBR_UL, "uplink_ambr", "Session-AMBR for Uplink", U16);

// QoS rules (9.11.4.13).
named_u8!(
    FD_PF_DIRECTION,
    "packet_filter_direction",
    "Packet Filter Direction",
    packet_filter_direction_name
);
plain!(
    FD_PF_IDENTIFIER,
    "packet_filter_identifier",
    "Packet Filter Identifier",
    U8
);
plain!(FD_PF_CONTENTS, "contents", "Packet Filter Contents", Bytes);
static PACKET_FILTER_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new(
        "packet_filter_direction",
        "Packet Filter Direction",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "packet_filter_identifier",
        "Packet Filter Identifier",
        FieldType::U8,
    ),
    FieldDescriptor::new("length", "Length", FieldType::U8).optional(),
    FieldDescriptor::new("contents", "Packet Filter Contents", FieldType::Bytes).optional(),
];
static FD_PACKET_FILTER: FieldDescriptor =
    FieldDescriptor::new("packet_filter", "Packet Filter", FieldType::Object)
        .with_children(PACKET_FILTER_CHILDREN);
plain!(
    FD_QOS_RULE_ID,
    "qos_rule_identifier",
    "QoS Rule Identifier",
    U8
);
named_u8!(
    FD_RULE_OPERATION_CODE,
    "rule_operation_code",
    "Rule Operation Code",
    rule_operation_code_name
);
plain!(FD_DQR, "dqr", "DQR", U8);
plain!(
    FD_NUMBER_OF_PACKET_FILTERS,
    "number_of_packet_filters",
    "Number of Packet Filters",
    U8
);
static FD_PACKET_FILTERS: FieldDescriptor =
    FieldDescriptor::new("packet_filters", "Packet Filters", FieldType::Array)
        .optional()
        .with_children(PACKET_FILTER_CHILDREN);
plain!(
    FD_QOS_RULE_PRECEDENCE,
    "qos_rule_precedence",
    "QoS Rule Precedence",
    U8
);
plain!(FD_SEGREGATION, "segregation", "Segregation", U8);
plain!(FD_QFI, "qfi", "QoS Flow Identifier", U8);
static QOS_RULE_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("qos_rule_identifier", "QoS Rule Identifier", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("rule_operation_code", "Rule Operation Code", FieldType::U8),
    FieldDescriptor::new("dqr", "DQR", FieldType::U8),
    FieldDescriptor::new(
        "number_of_packet_filters",
        "Number of Packet Filters",
        FieldType::U8,
    ),
    FieldDescriptor::new("packet_filters", "Packet Filters", FieldType::Array)
        .with_children(PACKET_FILTER_CHILDREN),
    FieldDescriptor::new("qos_rule_precedence", "QoS Rule Precedence", FieldType::U8).optional(),
    FieldDescriptor::new("segregation", "Segregation", FieldType::U8).optional(),
    FieldDescriptor::new("qfi", "QoS Flow Identifier", FieldType::U8).optional(),
];
static FD_QOS_RULE: FieldDescriptor =
    FieldDescriptor::new("qos_rule", "QoS Rule", FieldType::Object)
        .with_children(QOS_RULE_CHILDREN);
static FD_QOS_RULES: FieldDescriptor =
    FieldDescriptor::new("qos_rules", "QoS Rules", FieldType::Array)
        .optional()
        .with_children(QOS_RULE_CHILDREN);

// QoS flow descriptions (9.11.4.12).
named_u8!(
    FD_FLOW_OPERATION_CODE,
    "operation_code",
    "Operation Code",
    flow_operation_code_name
);
plain!(FD_E_BIT, "e_bit", "E Bit", U8);
plain!(
    FD_NUMBER_OF_PARAMETERS,
    "number_of_parameters",
    "Number of Parameters",
    U8
);
named_u8!(
    FD_PARAMETER_IDENTIFIER,
    "parameter_identifier",
    "Parameter Identifier",
    parameter_identifier_name
);
plain!(FD_FIVE_QI, "five_qi", "5QI", U8);
named_u8!(FD_BIT_RATE_UNIT, "unit", "Unit", bit_rate_unit_name);
plain!(FD_BIT_RATE, "bit_rate", "Bit Rate", U16);
plain!(
    FD_AVERAGING_WINDOW,
    "averaging_window",
    "Averaging Window",
    U16
);
plain!(
    FD_EPS_BEARER_IDENTITY,
    "eps_bearer_identity",
    "EPS Bearer Identity",
    U8
);
plain!(
    FD_PARAMETER_CONTENTS,
    "contents",
    "Parameter Contents",
    Bytes
);
static PARAMETER_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new(
        "parameter_identifier",
        "Parameter Identifier",
        FieldType::U8,
    ),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("five_qi", "5QI", FieldType::U8).optional(),
    FieldDescriptor::new("unit", "Unit", FieldType::U8).optional(),
    FieldDescriptor::new("bit_rate", "Bit Rate", FieldType::U16).optional(),
    FieldDescriptor::new("averaging_window", "Averaging Window", FieldType::U16).optional(),
    FieldDescriptor::new("eps_bearer_identity", "EPS Bearer Identity", FieldType::U8).optional(),
    FieldDescriptor::new("contents", "Parameter Contents", FieldType::Bytes).optional(),
];
static FD_PARAMETER: FieldDescriptor =
    FieldDescriptor::new("parameter", "Parameter", FieldType::Object)
        .with_children(PARAMETER_CHILDREN);
static FD_PARAMETERS: FieldDescriptor =
    FieldDescriptor::new("parameters", "Parameters", FieldType::Array)
        .optional()
        .with_children(PARAMETER_CHILDREN);
static QOS_FLOW_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("qfi", "QoS Flow Identifier", FieldType::U8),
    FieldDescriptor::new("operation_code", "Operation Code", FieldType::U8),
    FieldDescriptor::new("e_bit", "E Bit", FieldType::U8),
    FieldDescriptor::new(
        "number_of_parameters",
        "Number of Parameters",
        FieldType::U8,
    ),
    FieldDescriptor::new("parameters", "Parameters", FieldType::Array)
        .with_children(PARAMETER_CHILDREN),
];
static FD_QOS_FLOW: FieldDescriptor = FieldDescriptor::new(
    "qos_flow_description",
    "QoS Flow Description",
    FieldType::Object,
)
.with_children(QOS_FLOW_CHILDREN);
static FD_QOS_FLOWS: FieldDescriptor = FieldDescriptor::new(
    "qos_flow_descriptions",
    "QoS Flow Descriptions",
    FieldType::Array,
)
.optional()
.with_children(QOS_FLOW_CHILDREN);

/// Child fields of an `ie` object in `information_elements`.
///
/// `name` is always present. `iei` is present for optional IEs, `length`
/// for LV, LV-E, TLV and TLV-E IEs. The remaining fields depend on the IE
/// type; an IE without a dedicated decoder, or whose value does not match
/// its coding, carries its value part as `value`.
pub(crate) static IE_CHILDREN: &[FieldDescriptor] = &[
    FD_IE_NAME,
    FD_IE_IEI,
    FieldDescriptor::new("length", "Length", FieldType::Any).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Any).optional(),
    // 5GS mobile identity.
    FD_TYPE_OF_IDENTITY,
    FD_ODD_EVEN,
    FD_IDENTITY_DIGITS,
    FD_SUPI_FORMAT,
    FD_MCC,
    FD_MNC,
    FD_ROUTING_INDICATOR,
    FD_PROTECTION_SCHEME,
    FD_HN_PKI,
    FD_MSIN,
    FD_SCHEME_OUTPUT,
    FD_SUCI_NAI,
    FD_AMF_REGION_ID,
    FD_AMF_SET_ID,
    FD_AMF_POINTER,
    FD_TMSI,
    FD_MAURI,
    FD_MAC_ADDRESS,
    FD_EUI64,
    // NAS key set identifier, registration type and result.
    FD_TSC,
    FD_KSI,
    FD_FOR,
    FD_REGISTRATION_TYPE,
    FD_DISASTER_ROAMING_RESULT,
    FD_EMERGENCY_REGISTERED,
    FD_NSSAA,
    FD_SMS_ALLOWED,
    FD_REGISTRATION_RESULT,
    // Causes (5GMM and 5GSM share the name `cause`).
    FD_MM_CAUSE,
    // S-NSSAI, NSSAI, TAI and TAI list.
    FD_SST,
    FD_SD,
    FD_MAPPED_SST,
    FD_MAPPED_SD,
    FD_S_NSSAI_LIST,
    FD_TAC,
    FD_PARTIAL_TAI_LISTS,
    // Security.
    FD_EA_5G,
    FD_IA_5G,
    FD_EEA,
    FD_EIA,
    FD_CIPHERING_ALGORITHM,
    FD_INTEGRITY_ALGORITHM,
    // Transport.
    FD_PAYLOAD_CONTAINER_TYPE,
    FD_N1_SM_MESSAGE,
    FD_PDU_SESSION_ID,
    FD_REQUEST_TYPE,
    FD_SWITCH_OFF,
    FD_REREGISTRATION_REQUIRED,
    FD_ACCESS_TYPE,
    FD_SERVICE_TYPE,
    // 5GSM.
    FD_PDU_SESSION_TYPE,
    FD_SSC_MODE,
    FD_DNN,
    FD_SI6LLA,
    FD_IPV4_ADDRESS,
    FD_IPV6_IID,
    FD_SMF_IPV6_LLA,
    FD_UPLINK_RATE,
    FD_DOWNLINK_RATE,
    FD_AMBR_DL_UNIT,
    FD_AMBR_DL,
    FD_AMBR_UL_UNIT,
    FD_AMBR_UL,
    FD_QOS_RULES,
    FD_QOS_FLOWS,
];

/// One IE object in `information_elements`.
static FD_IE: FieldDescriptor =
    FieldDescriptor::new("ie", "Information Element", FieldType::Object).with_children(IE_CHILDREN);

/// The `information_elements` array of a 5GMM or 5GSM message.
pub(crate) static FD_INFORMATION_ELEMENTS: FieldDescriptor = FieldDescriptor::new(
    "information_elements",
    "Information Elements",
    FieldType::Array,
)
.optional()
.with_children(IE_CHILDREN);

/// Octets of a message body that could not be framed as IEs, or the body
/// of a message type without an IE table.
pub(crate) static FD_UNDECODED_OCTETS: FieldDescriptor =
    FieldDescriptor::new("undecoded_octets", "Undecoded Octets", FieldType::Bytes).optional();

/// Name of the first mandatory IE that is absent or truncated.
pub(crate) static FD_MISSING_MANDATORY_IE: FieldDescriptor = FieldDescriptor::new(
    "missing_mandatory_ie",
    "Missing Mandatory IE",
    FieldType::Str,
)
.optional();

// ── Message body walker ────────────────────────────────────────────────

/// Decoding state carried across the IEs of one message.
#[derive(Default)]
struct MessageContext {
    /// Value of the payload container type IE seen so far in the message.
    ///
    /// 3GPP TS 24.501, Section 9.11.3.39: the payload container contents
    /// are interpreted according to the payload container type.
    payload_container_type: Option<u8>,
}

/// Push the IEs of a message body (the octets after the message type, or
/// after the header for 5GSM) as `information_elements`.
///
/// Mandatory IEs are framed with the message content table; optional IEs
/// with their table entry, or with the rules of TS 24.007, Section 11.2.4
/// when unknown. Octets that cannot be framed are pushed as
/// `undecoded_octets`.
///
/// `allow_n1_sm` controls whether an N1 SM payload container is decoded
/// as a nested 5GSM message.
pub(crate) fn push_message_ies<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    offset: usize,
    ies: &MessageIes,
    allow_n1_sm: bool,
) {
    let mut ctx = MessageContext::default();
    let list_idx = buf.begin_container(
        &FD_INFORMATION_ELEMENTS,
        FieldValue::Array(0..0),
        offset..offset + body.len(),
    );
    let result = push_mandatory(buf, body, offset, ies, &mut ctx, allow_n1_sm)
        .and_then(|pos| push_optional(buf, body, offset, pos, ies, &mut ctx, allow_n1_sm));
    let (framed_end, missing) = match result {
        Ok(()) => (body.len(), None),
        Err(stop) => (stop.pos, stop.missing),
    };
    // Shrink the array range to the octets actually framed as IEs.
    if let Some(field) = buf.field_mut(list_idx as usize) {
        field.range = offset..offset + framed_end;
    }
    buf.end_container(list_idx);
    if framed_end == 0 {
        // No IE could be framed: drop the empty array.
        buf.truncate_fields(list_idx as usize);
    }
    if framed_end < body.len() {
        buf.push_field(
            &FD_UNDECODED_OCTETS,
            FieldValue::Bytes(&body[framed_end..]),
            offset + framed_end..offset + body.len(),
        );
    }
    if let Some(name) = missing {
        buf.push_field(
            &FD_MISSING_MANDATORY_IE,
            FieldValue::Str(name),
            offset + framed_end..offset + body.len(),
        );
    }
}

/// Where framing of a message body stopped.
struct Stop {
    /// Position in the body of the first octet not framed as an IE.
    pos: usize,
    /// Name of the mandatory IE that is absent or truncated, if any.
    missing: Option<&'static str>,
}

/// Push the mandatory IEs; returns the position after the last one, or the
/// position of the first IE that does not fit.
fn push_mandatory<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    offset: usize,
    ies: &MessageIes,
    ctx: &mut MessageContext,
    allow_n1_sm: bool,
) -> Result<usize, Stop> {
    let mut pos = 0;
    // TS 24.501, Section 8.1: "In a (maximal) sequence of consecutive IEs
    // with half octet length, the first IE with half octet length occupies
    // bits 1 to 4 of octet N, the second IE bits 5 to 8 of octet N".
    let mut high_nibble = false;
    for ie in ies.mandatory {
        let (len_size, value_len) = match ie.format {
            MandatoryFormat::Half => {
                let Some(&octet) = body.get(pos) else {
                    return Err(missing(pos, ie.name));
                };
                let nibble = if high_nibble {
                    octet >> 4
                } else {
                    octet & 0x0f
                };
                if ie.value != Value::Spare {
                    let range = offset + pos..offset + pos + 1;
                    let idx = begin_ie(buf, ie.name, None, range.clone());
                    push_half_value(buf, ie.value, nibble, range, ctx);
                    buf.end_container(idx);
                }
                if high_nibble {
                    pos += 1;
                }
                high_nibble = !high_nibble;
                continue;
            }
            // Every odd sequence of half-octet IEs in the message content
            // tables ends with a spare half octet, so an octet-aligned IE
            // never starts in the middle of an octet.
            MandatoryFormat::V(n) => (0, n),
            MandatoryFormat::Lv => match body.get(pos) {
                Some(&l) => (1, usize::from(l)),
                None => return Err(missing(pos, ie.name)),
            },
            MandatoryFormat::LvE => match body.get(pos..pos + 2) {
                Some(&[a, b]) => (2, usize::from(u16::from_be_bytes([a, b]))),
                _ => return Err(missing(pos, ie.name)),
            },
        };
        let end = pos + len_size + value_len;
        if end > body.len() {
            return Err(missing(pos, ie.name));
        }
        let range = offset + pos..offset + end;
        let idx = begin_ie(buf, ie.name, None, range);
        push_length(buf, len_size, value_len, offset + pos);
        let value_start = pos + len_size;
        push_value(
            buf,
            ie.value,
            &body[value_start..end],
            offset + value_start,
            ctx,
            allow_n1_sm,
        );
        buf.end_container(idx);
        pos = end;
    }
    // The tables pair every half-octet IE (see `messages` tests), so the
    // imperative part always ends on an octet boundary.
    Ok(pos)
}

/// A [`Stop`] at `pos` for the mandatory IE `name`.
fn missing(pos: usize, name: &'static str) -> Stop {
    Stop {
        pos,
        missing: Some(name),
    }
}

/// A [`Stop`] at `pos` in the non-imperative part.
fn truncated(pos: usize) -> Stop {
    Stop { pos, missing: None }
}

/// Push the optional IEs starting at `pos`.
fn push_optional<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    offset: usize,
    mut pos: usize,
    ies: &MessageIes,
    ctx: &mut MessageContext,
    allow_n1_sm: bool,
) -> Result<(), Stop> {
    while pos < body.len() {
        let octet = body[pos];
        // TS 24.007, Section 11.2.4: "Bit 8 of the IEI octet is set to "1"
        // indicates a TV formatted type 1 standard IE or a T formatted type
        // 2 IEs. Hence, a 1 valued bit 8 indicates that the whole IE is one
        // octet long."
        if octet & 0x80 != 0 {
            let iei = octet >> 4;
            let known = ies
                .optional
                .iter()
                .find(|ie| matches!(ie.format, OptionalFormat::Tv1) && ie.iei == iei);
            let range = offset + pos..offset + pos + 1;
            let idx = begin_ie(
                buf,
                known.map_or("Unknown", |ie| ie.name),
                Some(iei),
                range.clone(),
            );
            let value = known.map_or(Value::Raw, |ie| ie.value);
            push_half_value(buf, value, octet & 0x0f, range, ctx);
            buf.end_container(idx);
            pos += 1;
            continue;
        }

        let known = ies
            .optional
            .iter()
            .find(|ie| !matches!(ie.format, OptionalFormat::Tv1) && ie.iei == octet);
        let (len_size, value_len) = match known.map(|ie| ie.format) {
            // A known type 3 IE has a fixed length and no length octet.
            Some(OptionalFormat::Tv(n)) => (0, n),
            // TS 24.007, Section 11.2.4, for 5GMM and 5GSM: IEIs 70 to 7F
            // (hexadecimal) are TLV-E, 00 to 6F are TLV. The known TLV and
            // TLV-E IEs of the message tables follow the same rule.
            _ => {
                let l = if octet & 0x70 == 0x70 { 2 } else { 1 };
                match body.get(pos + 1..pos + 1 + l) {
                    Some(&[a]) => (1, usize::from(a)),
                    Some(&[a, b]) => (2, usize::from(u16::from_be_bytes([a, b]))),
                    _ => return Err(truncated(pos)),
                }
            }
        };
        let end = pos + 1 + len_size + value_len;
        if end > body.len() {
            return Err(truncated(pos));
        }
        let idx = begin_ie(
            buf,
            known.map_or("Unknown", |ie| ie.name),
            Some(octet),
            offset + pos..offset + end,
        );
        push_length(buf, len_size, value_len, offset + pos + 1);
        let value_start = pos + 1 + len_size;
        push_value(
            buf,
            known.map_or(Value::Raw, |ie| ie.value),
            &body[value_start..end],
            offset + value_start,
            ctx,
            allow_n1_sm,
        );
        buf.end_container(idx);
        pos = end;
    }
    Ok(())
}

/// Begin an `ie` object and push its `name` and, if present, `iei`.
fn begin_ie<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    name: &'static str,
    iei: Option<u8>,
    range: core::ops::Range<usize>,
) -> u32 {
    let idx = buf.begin_container(&FD_IE, FieldValue::Object(0..0), range.clone());
    buf.push_field(&FD_IE_NAME, FieldValue::Str(name), range.clone());
    if let Some(iei) = iei {
        buf.push_field(
            &FD_IE_IEI,
            FieldValue::U8(iei),
            range.start..range.start + 1,
        );
    }
    idx
}

/// Push the length indicator of an LV/TLV (one octet) or LV-E/TLV-E (two
/// octets) IE.
fn push_length(buf: &mut DissectBuffer<'_>, len_size: usize, value_len: usize, at: usize) {
    match len_size {
        1 => buf.push_field(
            &FD_IE_LENGTH_U8,
            FieldValue::U8(value_len as u8),
            at..at + 1,
        ),
        2 => buf.push_field(
            &FD_IE_LENGTH_U16,
            FieldValue::U16(value_len as u16),
            at..at + 2,
        ),
        _ => {}
    }
}

/// Push the value of a half-octet (type 1) IE.
fn push_half_value(
    buf: &mut DissectBuffer<'_>,
    value: Value,
    nibble: u8,
    range: core::ops::Range<usize>,
    ctx: &mut MessageContext,
) {
    let u8_field = |buf: &mut DissectBuffer<'_>, d: &'static FieldDescriptor, v: u8| {
        buf.push_field(d, FieldValue::U8(v), range.clone());
    };
    match value {
        // TS 24.501, 9.11.3.32: TSC in bit 4, NAS key set identifier in
        // bits 1 to 3.
        Value::NasKeySetIdentifier => {
            u8_field(buf, &FD_TSC, (nibble >> 3) & 1);
            u8_field(buf, &FD_KSI, nibble & 0x07);
        }
        // TS 24.501, 9.11.3.7: FOR in bit 4, value in bits 1 to 3.
        Value::RegistrationType => {
            u8_field(buf, &FD_FOR, (nibble >> 3) & 1);
            u8_field(buf, &FD_REGISTRATION_TYPE, nibble & 0x07);
        }
        // TS 24.501, 9.11.3.40: value in bits 1 to 4.
        Value::PayloadContainerType => {
            ctx.payload_container_type = Some(nibble);
            u8_field(buf, &FD_PAYLOAD_CONTAINER_TYPE, nibble);
        }
        // TS 24.501, 9.11.3.47: value in bits 1 to 3.
        Value::RequestType => u8_field(buf, &FD_REQUEST_TYPE, nibble & 0x07),
        // TS 24.501, 9.11.3.3: type of identity in bits 1 to 3.
        Value::IdentityType => u8_field(buf, &FD_IDENTITY_TYPE, nibble & 0x07),
        // TS 24.501, 9.11.3.20: switch off in bit 4, re-registration
        // required in bit 3, access type in bits 1 and 2.
        Value::DeregistrationType => {
            u8_field(buf, &FD_SWITCH_OFF, (nibble >> 3) & 1);
            u8_field(buf, &FD_REREGISTRATION_REQUIRED, (nibble >> 2) & 1);
            u8_field(buf, &FD_ACCESS_TYPE, nibble & 0x03);
        }
        // TS 24.501, 9.11.3.50: value in bits 1 to 4.
        Value::ServiceType => u8_field(buf, &FD_SERVICE_TYPE, nibble),
        // TS 24.501, 9.11.4.11: value in bits 1 to 3.
        Value::PduSessionType => u8_field(buf, &FD_PDU_SESSION_TYPE, nibble & 0x07),
        // TS 24.501, 9.11.4.16: value in bits 1 to 3.
        Value::SscMode => u8_field(buf, &FD_SSC_MODE, nibble & 0x07),
        _ => u8_field(buf, &FD_IE_VALUE_U8, nibble),
    }
}

/// Push the value part of an octet-aligned IE.
///
/// A structured decoder that rejects the value leaves no fields behind;
/// the value is then pushed as raw `value` bytes.
fn push_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: Value,
    data: &'pkt [u8],
    offset: usize,
    ctx: &mut MessageContext,
    allow_n1_sm: bool,
) {
    let mark = buf.fields().len();
    let ok = match value {
        Value::MobileIdentity => push_mobile_identity(buf, data, offset),
        Value::RegistrationResult => push_registration_result(buf, data, offset),
        Value::MmCause => push_single(buf, &FD_MM_CAUSE, data, offset),
        Value::SmCause => push_single(buf, &FD_SM_CAUSE, data, offset),
        Value::Nssai => push_nssai(buf, data, offset),
        Value::SNssai => push_s_nssai_contents(buf, data, offset),
        Value::TrackingAreaIdentity => push_tai_contents(buf, data, offset),
        Value::TrackingAreaIdentityList => push_tai_list(buf, data, offset),
        Value::UeSecurityCapability => push_ue_security_capability(buf, data, offset),
        Value::NasSecurityAlgorithms => push_nas_security_algorithms(buf, data, offset),
        Value::PayloadContainer => push_payload_container(buf, data, offset, ctx, allow_n1_sm),
        Value::PduSessionIdentity2 => push_single(buf, &FD_PDU_SESSION_ID, data, offset),
        Value::Dnn => {
            buf.push_field(
                &FD_DNN,
                FieldValue::Bytes(data),
                offset..offset + data.len(),
            );
            true
        }
        Value::PduAddress => push_pdu_address(buf, data, offset),
        Value::QosRules => push_qos_rules(buf, data, offset),
        Value::QosFlowDescriptions => push_qos_flow_descriptions(buf, data, offset),
        Value::SessionAmbr => push_session_ambr(buf, data, offset),
        Value::IntegrityProtectionMaximumDataRate => {
            push_integrity_max_data_rate(buf, data, offset)
        }
        _ => false,
    };
    if !ok {
        buf.truncate_fields(mark);
        buf.push_field(
            &FD_IE_VALUE,
            FieldValue::Bytes(data),
            offset..offset + data.len(),
        );
    }
}

// ── Value decoders ─────────────────────────────────────────────────────

/// Push a one-octet value.
fn push_single<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    desc: &'static FieldDescriptor,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let &[v] = data else {
        return false;
    };
    buf.push_field(desc, FieldValue::U8(v), offset..offset + 1);
    true
}

/// Push the MCC and MNC of a 3-octet PLMN identity starting at `at`.
fn push_plmn<'pkt>(buf: &mut DissectBuffer<'pkt>, plmn: &'pkt [u8], at: usize) {
    buf.push_field(&FD_MCC, FieldValue::Bytes(plmn), at..at + 3);
    buf.push_field(&FD_MNC, FieldValue::Bytes(plmn), at..at + 3);
}

/// Read a 24-bit big-endian value.
fn be_u24(b: &[u8]) -> u32 {
    (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2])
}

/// Push the AMF Set ID, AMF Pointer and 5G-TMSI of a 5G-GUTI or 5G-S-TMSI
/// from the 6 octets starting with the AMF Set ID.
///
/// 3GPP TS 24.501, Section 9.11.3.4: "AMF Set ID (octet 9, octet 10 bits 7
/// to 8)", "AMF Pointer (octet 10 bits 1 to 6)", "5G-TMSI (octet 11 to 14)".
fn push_amf_set_pointer_tmsi(buf: &mut DissectBuffer<'_>, b: &[u8], at: usize) {
    let set_id = (u16::from(b[0]) << 2) | u16::from(b[1] >> 6);
    buf.push_field(&FD_AMF_SET_ID, FieldValue::U16(set_id), at..at + 2);
    buf.push_field(&FD_AMF_POINTER, FieldValue::U8(b[1] & 0x3f), at + 1..at + 2);
    let tmsi = u32::from_be_bytes([b[2], b[3], b[4], b[5]]);
    buf.push_field(&FD_TMSI, FieldValue::U32(tmsi), at + 2..at + 6);
}

/// 5GS mobile identity contents (octet 4 onwards).
///
/// 3GPP TS 24.501, Section 9.11.3.4.
fn push_mobile_identity<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let Some(&octet4) = data.first() else {
        return false;
    };
    let identity_type = octet4 & 0x07;
    let expected_ok = match identity_type {
        // 5G-GUTI: octets 4 to 14.
        2 => data.len() == 11,
        // 5G-S-TMSI: octets 4 to 10.
        4 => data.len() == 7,
        // MAC address: octets 4 to 10.
        6 => data.len() == 7,
        // EUI-64: octets 4 to 12.
        7 => data.len() == 9,
        // SUCI: IMSI format needs octets 4 to 11; the NAI formats at least
        // one NAI octet.
        1 => {
            if is_imsi_supi_format((octet4 >> 4) & 0x07) {
                data.len() >= 8
            } else {
                data.len() >= 2
            }
        }
        // No identity, IMEI, IMEISV.
        _ => true,
    };
    if !expected_ok {
        return false;
    }
    let first = offset..offset + 1;
    buf.push_field(
        &FD_TYPE_OF_IDENTITY,
        FieldValue::U8(identity_type),
        first.clone(),
    );
    match identity_type {
        1 => {
            let supi_format = (octet4 >> 4) & 0x07;
            buf.push_field(&FD_SUPI_FORMAT, FieldValue::U8(supi_format), first);
            if is_imsi_supi_format(supi_format) {
                // Figure 9.11.3.4.3.
                push_plmn(buf, &data[1..4], offset + 1);
                buf.push_field(
                    &FD_ROUTING_INDICATOR,
                    FieldValue::Bytes(&data[4..6]),
                    offset + 4..offset + 6,
                );
                let scheme = data[6] & 0x0f;
                buf.push_field(
                    &FD_PROTECTION_SCHEME,
                    FieldValue::U8(scheme),
                    offset + 6..offset + 7,
                );
                buf.push_field(&FD_HN_PKI, FieldValue::U8(data[7]), offset + 7..offset + 8);
                let output = &data[8..];
                if !output.is_empty() {
                    // "If Protection scheme identifier is set to "0000"
                    // (i.e. Null scheme), then the Scheme output consists of
                    // the MSIN and is coded using BCD coding".
                    let desc = if scheme == 0 {
                        &FD_MSIN
                    } else {
                        &FD_SCHEME_OUTPUT
                    };
                    buf.push_field(
                        desc,
                        FieldValue::Bytes(output),
                        offset + 8..offset + data.len(),
                    );
                }
            } else {
                // Figure 9.11.3.4.4: SUCI NAI encoded as UTF-8 string.
                buf.push_field(
                    &FD_SUCI_NAI,
                    FieldValue::Bytes(&data[1..]),
                    offset + 1..offset + data.len(),
                );
            }
        }
        2 => {
            // Figure 9.11.3.4.1.
            push_plmn(buf, &data[1..4], offset + 1);
            buf.push_field(
                &FD_AMF_REGION_ID,
                FieldValue::U8(data[4]),
                offset + 4..offset + 5,
            );
            push_amf_set_pointer_tmsi(buf, &data[5..11], offset + 5);
        }
        3 | 5 => {
            // Figure 9.11.3.4.2.
            buf.push_field(&FD_ODD_EVEN, FieldValue::U8((octet4 >> 3) & 1), first);
            buf.push_field(
                &FD_IDENTITY_DIGITS,
                FieldValue::Bytes(data),
                offset..offset + data.len(),
            );
        }
        4 => {
            // Figure 9.11.3.4.5.
            push_amf_set_pointer_tmsi(buf, &data[1..7], offset + 1);
        }
        6 => {
            // Figure 9.11.3.4.7.
            buf.push_field(&FD_MAURI, FieldValue::U8((octet4 >> 3) & 1), first);
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&data[1..7]);
            buf.push_field(
                &FD_MAC_ADDRESS,
                FieldValue::MacAddr(MacAddr(mac)),
                offset + 1..offset + 7,
            );
        }
        7 => {
            // Figure 9.11.3.4.8.
            buf.push_field(
                &FD_EUI64,
                FieldValue::Bytes(&data[1..9]),
                offset + 1..offset + 9,
            );
        }
        // No identity (Figure 9.11.3.4.6): nothing beyond the type.
        _ => {}
    }
    true
}

/// 5GS registration result value part (one octet).
///
/// 3GPP TS 24.501, Section 9.11.3.6, Figure 9.11.3.6.1.
fn push_registration_result(buf: &mut DissectBuffer<'_>, data: &[u8], offset: usize) -> bool {
    let &[v] = data else {
        return false;
    };
    let r = offset..offset + 1;
    buf.push_field(
        &FD_DISASTER_ROAMING_RESULT,
        FieldValue::U8((v >> 6) & 1),
        r.clone(),
    );
    buf.push_field(
        &FD_EMERGENCY_REGISTERED,
        FieldValue::U8((v >> 5) & 1),
        r.clone(),
    );
    buf.push_field(&FD_NSSAA, FieldValue::U8((v >> 4) & 1), r.clone());
    buf.push_field(&FD_SMS_ALLOWED, FieldValue::U8((v >> 3) & 1), r.clone());
    buf.push_field(&FD_REGISTRATION_RESULT, FieldValue::U8(v & 0x07), r);
    true
}

/// S-NSSAI contents (octet 3 onwards of Figure 9.11.2.8.1).
///
/// 3GPP TS 24.501, Section 9.11.2.8, Table 9.11.2.8.1: the length is 1
/// (SST), 2 (SST and mapped HPLMN SST), 4 (SST and SD), 5 (SST, SD and
/// mapped HPLMN SST) or 8 (all four). "All other values are reserved."
fn push_s_nssai_contents(buf: &mut DissectBuffer<'_>, data: &[u8], offset: usize) -> bool {
    let (sd, mapped_sst, mapped_sd) = match data.len() {
        1 => (None, None, None),
        2 => (None, Some(1), None),
        4 => (Some(1), None, None),
        5 => (Some(1), Some(4), None),
        8 => (Some(1), Some(4), Some(5)),
        _ => return false,
    };
    buf.push_field(&FD_SST, FieldValue::U8(data[0]), offset..offset + 1);
    if let Some(i) = sd {
        buf.push_field(
            &FD_SD,
            FieldValue::U32(be_u24(&data[i..i + 3])),
            offset + i..offset + i + 3,
        );
    }
    if let Some(i) = mapped_sst {
        buf.push_field(
            &FD_MAPPED_SST,
            FieldValue::U8(data[i]),
            offset + i..offset + i + 1,
        );
    }
    if let Some(i) = mapped_sd {
        buf.push_field(
            &FD_MAPPED_SD,
            FieldValue::U32(be_u24(&data[i..i + 3])),
            offset + i..offset + i + 3,
        );
    }
    true
}

/// NSSAI value part: a list of S-NSSAI values, each "coded as the length
/// and value part of S-NSSAI information element".
///
/// 3GPP TS 24.501, Section 9.11.3.37, Table 9.11.3.37.1.
fn push_nssai(buf: &mut DissectBuffer<'_>, data: &[u8], offset: usize) -> bool {
    let list = buf.begin_container(
        &FD_S_NSSAI_LIST,
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    let mut pos = 0;
    while pos < data.len() {
        let len = usize::from(data[pos]);
        let end = pos + 1 + len;
        if end > data.len() {
            return false;
        }
        let item = buf.begin_container(
            &FD_S_NSSAI,
            FieldValue::Object(0..0),
            offset + pos..offset + end,
        );
        buf.push_field(
            &FD_IE_LENGTH_U8,
            FieldValue::U8(data[pos]),
            offset + pos..offset + pos + 1,
        );
        if !push_s_nssai_contents(buf, &data[pos + 1..end], offset + pos + 1) {
            return false;
        }
        buf.end_container(item);
        pos = end;
    }
    buf.end_container(list);
    true
}

/// 5GS tracking area identity value part: PLMN identity and TAC.
///
/// 3GPP TS 24.501, Section 9.11.3.8, Figure 9.11.3.8.1.
fn push_tai_contents<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.len() != 6 {
        return false;
    }
    push_plmn(buf, &data[..3], offset);
    buf.push_field(
        &FD_TAC,
        FieldValue::U32(be_u24(&data[3..6])),
        offset + 3..offset + 6,
    );
    true
}

/// Push one `tai` object from a PLMN identity and a TAC.
fn push_tai<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    plmn: &'pkt [u8],
    plmn_at: usize,
    tac: &[u8],
    tac_at: usize,
) {
    let idx = buf.begin_container(&FD_TAI, FieldValue::Object(0..0), plmn_at..tac_at + 3);
    push_plmn(buf, plmn, plmn_at);
    buf.push_field(&FD_TAC, FieldValue::U32(be_u24(tac)), tac_at..tac_at + 3);
    buf.end_container(idx);
}

/// 5GS tracking area identity list value part.
///
/// 3GPP TS 24.501, Section 9.11.3.9, Figures 9.11.3.9.2 to 9.11.3.9.4 and
/// Table 9.11.3.9.1.
fn push_tai_list<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    let lists = buf.begin_container(
        &FD_PARTIAL_TAI_LISTS,
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    let mut pos = 0;
    while pos < data.len() {
        let octet1 = data[pos];
        let type_of_list = (octet1 >> 5) & 0x03;
        // "Number of elements" is coded as the count minus one.
        let k = usize::from(octet1 & 0x1f) + 1;
        let len = match type_of_list {
            0 => 1 + 3 + 3 * k,
            1 => 1 + 3 + 3,
            2 => 1 + 6 * k,
            // "All other values are reserved": the length cannot be
            // determined.
            _ => return false,
        };
        let end = pos + len;
        if end > data.len() {
            return false;
        }
        let at = offset + pos;
        let item = buf.begin_container(
            &FD_PARTIAL_TAI_LIST,
            FieldValue::Object(0..0),
            at..offset + end,
        );
        buf.push_field(&FD_TYPE_OF_LIST, FieldValue::U8(type_of_list), at..at + 1);
        buf.push_field(&FD_NUMBER_OF_ELEMENTS, FieldValue::U8(k as u8), at..at + 1);
        let tais = buf.begin_container(&FD_TAIS, FieldValue::Array(0..0), at + 1..offset + end);
        let p = pos + 1;
        match type_of_list {
            0 => {
                let plmn = &data[p..p + 3];
                for j in 0..k {
                    let t = p + 3 + 3 * j;
                    push_tai(buf, plmn, offset + p, &data[t..t + 3], offset + t);
                }
            }
            1 => {
                // "The TAC values of the other k-1 TAIs are TAC+1, TAC+2,
                // …, TAC+k-1": only the first TAI is carried.
                push_tai(
                    buf,
                    &data[p..p + 3],
                    offset + p,
                    &data[p + 3..p + 6],
                    offset + p + 3,
                );
            }
            _ => {
                for j in 0..k {
                    let t = p + 6 * j;
                    push_tai(
                        buf,
                        &data[t..t + 3],
                        offset + t,
                        &data[t + 3..t + 6],
                        offset + t + 3,
                    );
                }
            }
        }
        buf.end_container(tais);
        buf.end_container(item);
        pos = end;
    }
    buf.end_container(lists);
    true
}

/// UE security capability value part (octets 3 to 10).
///
/// 3GPP TS 24.501, Section 9.11.3.54, Figure 9.11.3.54.1. Each octet is a
/// bitmap with algorithm 0 in bit 8. Octets 7 to 10 are spare.
fn push_ue_security_capability(buf: &mut DissectBuffer<'_>, data: &[u8], offset: usize) -> bool {
    // "If octet 5 is included, then also octet 6 shall be included." and
    // "If the network includes octet 7, then it shall include also octet 8.
    // If the network includes octet 9, then it shall include also octet
    // 10." — so the contents are 2, 4, 6 or 8 octets long.
    if !matches!(data.len(), 2 | 4 | 6 | 8) {
        return false;
    }
    buf.push_field(&FD_EA_5G, FieldValue::U8(data[0]), offset..offset + 1);
    buf.push_field(&FD_IA_5G, FieldValue::U8(data[1]), offset + 1..offset + 2);
    if data.len() >= 4 {
        buf.push_field(&FD_EEA, FieldValue::U8(data[2]), offset + 2..offset + 3);
        buf.push_field(&FD_EIA, FieldValue::U8(data[3]), offset + 3..offset + 4);
    }
    true
}

/// NAS security algorithms value part (one octet).
///
/// 3GPP TS 24.501, Section 9.11.3.34, Figure 9.11.3.34.1: ciphering in
/// bits 5 to 8, integrity protection in bits 1 to 4.
fn push_nas_security_algorithms(buf: &mut DissectBuffer<'_>, data: &[u8], offset: usize) -> bool {
    let &[v] = data else {
        return false;
    };
    let r = offset..offset + 1;
    buf.push_field(&FD_CIPHERING_ALGORITHM, FieldValue::U8(v >> 4), r.clone());
    buf.push_field(&FD_INTEGRITY_ALGORITHM, FieldValue::U8(v & 0x0f), r);
    true
}

/// Payload container contents.
///
/// 3GPP TS 24.501, Section 9.11.3.39: when the payload container type is
/// "N1 SM information" the contents are a 5GSM message, which is decoded
/// as `n1_sm_message`. Other payload types are kept as raw bytes.
fn push_payload_container<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    ctx: &MessageContext,
    allow_n1_sm: bool,
) -> bool {
    // Only a container that starts with the 5GSM extended protocol
    // discriminator (TS 24.007, Table 11.2) is decoded as a 5GSM message.
    if !allow_n1_sm
        || ctx.payload_container_type != Some(PAYLOAD_CONTAINER_TYPE_N1_SM)
        || data.first() != Some(&crate::EPD_5GSM)
    {
        return false;
    }
    let idx = buf.begin_container(
        &FD_N1_SM_MESSAGE,
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    if !crate::push_5gsm(buf, data, offset) {
        return false;
    }
    buf.end_container(idx);
    true
}

/// PDU address value part.
///
/// 3GPP TS 24.501, Section 9.11.4.10, Figure 9.11.4.10.1 and Table
/// 9.11.4.10.1.
fn push_pdu_address<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    let Some(&octet3) = data.first() else {
        return false;
    };
    let session_type = octet3 & 0x07;
    let si6lla = (octet3 >> 3) & 1;
    let info_len = match session_type {
        1 => 4,
        2 => 8,
        3 => 12,
        // "All other values are reserved."
        _ => return false,
    };
    let lla_len = if si6lla == 1 { 16 } else { 0 };
    if data.len() != 1 + info_len + lla_len {
        return false;
    }
    let r = offset..offset + 1;
    buf.push_field(&FD_SI6LLA, FieldValue::U8(si6lla), r.clone());
    buf.push_field(&FD_PDU_SESSION_TYPE, FieldValue::U8(session_type), r);
    let mut p = 1;
    if session_type != 1 {
        // IPv6 or IPv4v6: interface identifier first.
        buf.push_field(
            &FD_IPV6_IID,
            FieldValue::Bytes(&data[p..p + 8]),
            offset + p..offset + p + 8,
        );
        p += 8;
    }
    if session_type != 2 {
        let v4 = [data[p], data[p + 1], data[p + 2], data[p + 3]];
        buf.push_field(
            &FD_IPV4_ADDRESS,
            FieldValue::Ipv4Addr(v4),
            offset + p..offset + p + 4,
        );
        p += 4;
    }
    if lla_len != 0 {
        let mut v6 = [0u8; 16];
        v6.copy_from_slice(&data[p..p + 16]);
        buf.push_field(
            &FD_SMF_IPV6_LLA,
            FieldValue::Ipv6Addr(v6),
            offset + p..offset + p + 16,
        );
    }
    true
}

/// QoS rules value part: a sequence of QoS rules.
///
/// 3GPP TS 24.501, Section 9.11.4.13, Figures 9.11.4.13.2 to 9.11.4.13.4
/// and Table 9.11.4.13.1. Packet filter contents are kept as raw bytes.
fn push_qos_rules<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    let list = buf.begin_container(
        &FD_QOS_RULES,
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    let mut pos = 0;
    while pos < data.len() {
        let Some(&[qri, l0, l1]) = data.get(pos..pos + 3) else {
            return false;
        };
        let len = usize::from(u16::from_be_bytes([l0, l1]));
        let end = pos + 3 + len;
        if len == 0 || end > data.len() {
            return false;
        }
        let at = offset + pos;
        let rule = buf.begin_container(&FD_QOS_RULE, FieldValue::Object(0..0), at..offset + end);
        buf.push_field(&FD_QOS_RULE_ID, FieldValue::U8(qri), at..at + 1);
        buf.push_field(
            &FD_IE_LENGTH_U16,
            FieldValue::U16(len as u16),
            at + 1..at + 3,
        );
        if !push_qos_rule_body(buf, &data[pos + 3..end], at + 3) {
            return false;
        }
        buf.end_container(rule);
        pos = end;
    }
    buf.end_container(list);
    true
}

/// Octet 7 onwards of one QoS rule (Figure 9.11.4.13.2).
fn push_qos_rule_body<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let octet7 = data[0];
    let op = octet7 >> 5;
    let count = usize::from(octet7 & 0x0f);
    let r = offset..offset + 1;
    buf.push_field(&FD_RULE_OPERATION_CODE, FieldValue::U8(op), r.clone());
    buf.push_field(&FD_DQR, FieldValue::U8((octet7 >> 4) & 1), r.clone());
    buf.push_field(&FD_NUMBER_OF_PACKET_FILTERS, FieldValue::U8(count as u8), r);

    let mut pos = 1;
    let filters = buf.begin_container(
        &FD_PACKET_FILTERS,
        FieldValue::Array(0..0),
        offset + 1..offset + 1,
    );
    for _ in 0..count {
        let Some(&octet) = data.get(pos) else {
            return false;
        };
        let at = offset + pos;
        if op == RULE_OP_DELETE_PACKET_FILTERS {
            // Figure 9.11.4.13.3: packet filter identifiers only.
            let pf = buf.begin_container(&FD_PACKET_FILTER, FieldValue::Object(0..0), at..at + 1);
            buf.push_field(&FD_PF_IDENTIFIER, FieldValue::U8(octet & 0x0f), at..at + 1);
            buf.end_container(pf);
            pos += 1;
        } else {
            // Figure 9.11.4.13.4: direction, identifier, length, contents.
            let Some(&len) = data.get(pos + 1) else {
                return false;
            };
            let end = pos + 2 + usize::from(len);
            if end > data.len() {
                return false;
            }
            let pf = buf.begin_container(
                &FD_PACKET_FILTER,
                FieldValue::Object(0..0),
                at..offset + end,
            );
            buf.push_field(
                &FD_PF_DIRECTION,
                FieldValue::U8((octet >> 4) & 0x03),
                at..at + 1,
            );
            buf.push_field(&FD_PF_IDENTIFIER, FieldValue::U8(octet & 0x0f), at..at + 1);
            buf.push_field(&FD_IE_LENGTH_U8, FieldValue::U8(len), at + 1..at + 2);
            push_bytes(buf, &FD_PF_CONTENTS, &data[pos + 2..end], at + 2);
            buf.end_container(pf);
            pos = end;
        }
    }
    if let Some(field) = buf.field_mut(filters as usize) {
        field.range = offset + 1..offset + pos;
    }
    buf.end_container(filters);

    // "QoS rule precedence (octet m+1)" and "Segregation / QFI (octet
    // m+2)"; "Octet m+2 shall not be included without octet m+1."
    let tail = data.len() - pos;
    if tail > 2 {
        return false;
    }
    if tail >= 1 {
        buf.push_field(
            &FD_QOS_RULE_PRECEDENCE,
            FieldValue::U8(data[pos]),
            offset + pos..offset + pos + 1,
        );
    }
    if tail == 2 {
        let o = data[pos + 1];
        let r = offset + pos + 1..offset + pos + 2;
        buf.push_field(&FD_SEGREGATION, FieldValue::U8((o >> 6) & 1), r.clone());
        buf.push_field(&FD_QFI, FieldValue::U8(o & 0x3f), r);
    }
    true
}

/// Push a byte slice field (helper keeping the lifetime explicit).
fn push_bytes<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    desc: &'static FieldDescriptor,
    data: &'pkt [u8],
    at: usize,
) {
    buf.push_field(desc, FieldValue::Bytes(data), at..at + data.len());
}

/// QoS flow descriptions value part.
///
/// 3GPP TS 24.501, Section 9.11.4.12, Figures 9.11.4.12.2 to 9.11.4.12.4
/// and Table 9.11.4.12.1. A description has no length field: it ends after
/// "number of parameters" parameters.
fn push_qos_flow_descriptions<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let list = buf.begin_container(
        &FD_QOS_FLOWS,
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    let mut pos = 0;
    while pos < data.len() {
        let Some(&[o4, o5, o6]) = data.get(pos..pos + 3) else {
            return false;
        };
        let at = offset + pos;
        let flow = buf.begin_container(&FD_QOS_FLOW, FieldValue::Object(0..0), at..at + 3);
        buf.push_field(&FD_QFI, FieldValue::U8(o4 & 0x3f), at..at + 1);
        buf.push_field(
            &FD_FLOW_OPERATION_CODE,
            FieldValue::U8(o5 >> 5),
            at + 1..at + 2,
        );
        buf.push_field(&FD_E_BIT, FieldValue::U8((o6 >> 6) & 1), at + 2..at + 3);
        let count = o6 & 0x3f;
        buf.push_field(
            &FD_NUMBER_OF_PARAMETERS,
            FieldValue::U8(count),
            at + 2..at + 3,
        );
        pos += 3;
        let params_start = offset + pos;
        let params = buf.begin_container(
            &FD_PARAMETERS,
            FieldValue::Array(0..0),
            params_start..params_start,
        );
        for _ in 0..count {
            let Some(&[id, len]) = data.get(pos..pos + 2) else {
                return false;
            };
            let end = pos + 2 + usize::from(len);
            if end > data.len() {
                return false;
            }
            let p_at = offset + pos;
            let param =
                buf.begin_container(&FD_PARAMETER, FieldValue::Object(0..0), p_at..offset + end);
            buf.push_field(&FD_PARAMETER_IDENTIFIER, FieldValue::U8(id), p_at..p_at + 1);
            buf.push_field(&FD_IE_LENGTH_U8, FieldValue::U8(len), p_at + 1..p_at + 2);
            push_flow_parameter(buf, id, &data[pos + 2..end], p_at + 2);
            buf.end_container(param);
            pos = end;
        }
        if let Some(field) = buf.field_mut(params as usize) {
            field.range = params_start..offset + pos;
        }
        buf.end_container(params);
        if let Some(field) = buf.field_mut(flow as usize) {
            field.range = at..offset + pos;
        }
        buf.end_container(flow);
    }
    buf.end_container(list);
    true
}

/// Contents of one QoS flow description parameter.
///
/// 3GPP TS 24.501, Section 9.11.4.12, Table 9.11.4.12.1. Contents that do
/// not have the specified length are kept as raw bytes.
fn push_flow_parameter<'pkt>(buf: &mut DissectBuffer<'pkt>, id: u8, c: &'pkt [u8], at: usize) {
    match (id, c) {
        // 5QI: one octet.
        (0x01, &[q]) => buf.push_field(&FD_FIVE_QI, FieldValue::U8(q), at..at + 1),
        // GFBR/MFBR uplink/downlink: unit octet and two value octets.
        (0x02..=0x05, &[unit, a, b]) => {
            buf.push_field(&FD_BIT_RATE_UNIT, FieldValue::U8(unit), at..at + 1);
            buf.push_field(
                &FD_BIT_RATE,
                FieldValue::U16(u16::from_be_bytes([a, b])),
                at + 1..at + 3,
            );
        }
        // Averaging window: two octets, in milliseconds.
        (0x06, &[a, b]) => buf.push_field(
            &FD_AVERAGING_WINDOW,
            FieldValue::U16(u16::from_be_bytes([a, b])),
            at..at + 2,
        ),
        // EPS bearer identity: bits 5 to 8.
        (0x07, &[e]) => buf.push_field(&FD_EPS_BEARER_IDENTITY, FieldValue::U8(e >> 4), at..at + 1),
        _ => push_bytes(buf, &FD_PARAMETER_CONTENTS, c, at),
    }
}

/// Session-AMBR value part (octets 3 to 8).
///
/// 3GPP TS 24.501, Section 9.11.4.14, Figure 9.11.4.14.1.
fn push_session_ambr(buf: &mut DissectBuffer<'_>, data: &[u8], offset: usize) -> bool {
    let &[dl_unit, d0, d1, ul_unit, u0, u1] = data else {
        return false;
    };
    buf.push_field(
        &FD_AMBR_DL_UNIT,
        FieldValue::U8(dl_unit),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_AMBR_DL,
        FieldValue::U16(u16::from_be_bytes([d0, d1])),
        offset + 1..offset + 3,
    );
    buf.push_field(
        &FD_AMBR_UL_UNIT,
        FieldValue::U8(ul_unit),
        offset + 3..offset + 4,
    );
    buf.push_field(
        &FD_AMBR_UL,
        FieldValue::U16(u16::from_be_bytes([u0, u1])),
        offset + 4..offset + 6,
    );
    true
}

/// Integrity protection maximum data rate value part (two octets).
///
/// 3GPP TS 24.501, Section 9.11.4.7, Figure 9.11.4.7.1.
fn push_integrity_max_data_rate(buf: &mut DissectBuffer<'_>, data: &[u8], offset: usize) -> bool {
    let &[ul, dl] = data else {
        return false;
    };
    buf.push_field(&FD_UPLINK_RATE, FieldValue::U8(ul), offset..offset + 1);
    buf.push_field(
        &FD_DOWNLINK_RATE,
        FieldValue::U8(dl),
        offset + 1..offset + 2,
    );
    true
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 24.501 IE Decoder Coverage
    //!
    //! | Spec Section | Description                               | Test                                 |
    //! |--------------|-------------------------------------------|--------------------------------------|
    //! | 9.11.3.2     | 5GMM cause table (all 256 values)         | mm_cause_table_matches_spec          |
    //! | 9.11.4.2     | 5GSM cause table (all 256 values)         | sm_cause_table_matches_spec          |
    //! | 9.11.x       | Other value name tables                   | value_name_tables                    |
    //! | 9.11.3.4     | BCD, identity digit, MCC/MNC formatting   | format_functions                     |
    //! | 9.11.3.4     | Mobile identity length checks             | mobile_identity_rejects_bad_lengths  |
    //! | 9.11.3.4     | SUCI without scheme output                | suci_without_scheme_output           |
    //! | 9.11.x       | Fixed-length values reject other lengths  | fixed_length_values_reject_bad_input |
    //! | 9.11.2.8     | S-NSSAI / NSSAI malformed                 | nssai_rejects_malformed_lists        |
    //! | 9.11.3.9     | TAI list reserved type / truncation       | tai_list_rejects_malformed_lists     |
    //! | 9.11.4.10    | PDU address malformed                     | pdu_address_rejects_bad_input        |
    //! | 9.11.4.13    | QoS rules malformed / precedence only     | qos_rules_edge_cases                 |
    //! | 9.11.4.12    | QoS flow parameters (all identifiers)     | qos_flow_parameters                  |
    //! | 9.11.4.12    | QoS flow descriptions malformed           | qos_flow_descriptions_reject_bad_input |
    //! | 9.11.3.39    | N1 SM container that is not 5GSM          | n1_sm_container_not_5gsm_kept_raw    |
    //! | 9.11.3.54    | UE security capability odd lengths        | fixed_length_values_reject_bad_input |

    use super::*;

    /// Decode `data` as `value` and return the top-level pushed fields.
    fn decode(value: Value, data: &[u8]) -> Vec<(&'static str, FieldValue<'_>)> {
        let mut buf = DissectBuffer::new();
        let mut ctx = MessageContext::default();
        push_value(&mut buf, value, data, 0, &mut ctx, true);
        top(&buf)
    }

    fn top<'pkt>(buf: &DissectBuffer<'pkt>) -> Vec<(&'static str, FieldValue<'pkt>)> {
        let fields = buf.fields();
        let mut out = Vec::new();
        let mut i = 0;
        while i < fields.len() {
            out.push((fields[i].name(), fields[i].value.clone()));
            i = match &fields[i].value {
                FieldValue::Array(r) | FieldValue::Object(r) => r.end as usize,
                _ => i + 1,
            };
        }
        out
    }

    /// Assert that `data` decoded as `value` falls back to raw bytes.
    fn assert_raw(value: Value, data: &[u8]) {
        assert_eq!(
            decode(value, data),
            [("value", FieldValue::Bytes(data))],
            "{data:02x?}"
        );
    }

    fn fmt(f: packet_dissector_core::field::FormatFn, v: FieldValue<'_>) -> String {
        let ctx = FormatContext {
            packet_data: &[],
            scratch: &[],
            layer_range: 0..0,
            field_range: 0..0,
        };
        let mut out = Vec::new();
        f(&v, &ctx, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// 3GPP TS 24.501 v19.8.0, Table 9.11.3.2.1.
    const MM_CAUSES: &[(u8, &str)] = &[
        (3, "Illegal UE"),
        (5, "PEI not accepted"),
        (6, "Illegal ME"),
        (7, "5GS services not allowed"),
        (9, "UE identity cannot be derived by the network"),
        (10, "Implicitly de-registered"),
        (11, "PLMN not allowed"),
        (12, "Tracking area not allowed"),
        (13, "Roaming not allowed in this tracking area"),
        (15, "No suitable cells in tracking area"),
        (20, "MAC failure"),
        (21, "Synch failure"),
        (22, "Congestion"),
        (23, "UE security capabilities mismatch"),
        (24, "Security mode rejected, unspecified"),
        (26, "Non-5G authentication unacceptable"),
        (27, "N1 mode not allowed"),
        (28, "Restricted service area"),
        (31, "Redirection to EPC required"),
        (36, "IAB-node operation not authorized"),
        (43, "LADN not available"),
        (62, "No network slices available"),
        (65, "Maximum number of PDU sessions reached"),
        (67, "Insufficient resources for specific slice and DNN"),
        (69, "Insufficient resources for specific slice"),
        (71, "ngKSI already in use"),
        (72, "Non-3GPP access to 5GCN not allowed"),
        (73, "Serving network not authorized"),
        (74, "Temporarily not authorized for this SNPN"),
        (75, "Permanently not authorized for this SNPN"),
        (
            76,
            "Not authorized for this CAG or authorized for CAG cells only",
        ),
        (77, "Wireline access area not allowed"),
        (78, "PLMN not allowed to operate at the present UE location"),
        (79, "UAS services not allowed"),
        (
            80,
            "Disaster roaming for the determined PLMN with disaster condition not allowed",
        ),
        (
            81,
            "Selected N3IWF is not compatible with the allowed NSSAI",
        ),
        (82, "Selected TNGF is not compatible with the allowed NSSAI"),
        (90, "Payload was not forwarded"),
        (91, "DNN not supported or not subscribed in the slice"),
        (92, "Insufficient user-plane resources for the PDU session"),
        (93, "Onboarding services terminated"),
        (94, "User plane positioning not authorized"),
        (95, "Semantically incorrect message"),
        (96, "Invalid mandatory information"),
        (97, "Message type non-existent or not implemented"),
        (98, "Message type not compatible with the protocol state"),
        (99, "Information element non-existent or not implemented"),
        (100, "Conditional IE error"),
        (101, "Message not compatible with the protocol state"),
        (111, "Protocol error, unspecified"),
    ];

    /// 3GPP TS 24.501 v19.8.0, Table 9.11.4.2.1.
    const SM_CAUSES: &[(u8, &str)] = &[
        (8, "Operator determined barring"),
        (26, "Insufficient resources"),
        (27, "Missing or unknown DNN"),
        (28, "Unknown PDU session type"),
        (29, "User authentication or authorization failed"),
        (31, "Request rejected, unspecified"),
        (32, "Service option not supported"),
        (33, "Requested service option not subscribed"),
        (35, "PTI already in use"),
        (36, "Regular deactivation"),
        (37, "5GS QoS not accepted"),
        (38, "Network failure"),
        (39, "Reactivation requested"),
        (41, "Semantic error in the TFT operation"),
        (42, "Syntactical error in the TFT operation"),
        (43, "Invalid PDU session identity"),
        (44, "Semantic errors in packet filter(s)"),
        (45, "Syntactical error in packet filter(s)"),
        (46, "Out of LADN service area"),
        (47, "PTI mismatch"),
        (50, "PDU session type IPv4 only allowed"),
        (51, "PDU session type IPv6 only allowed"),
        (54, "PDU session does not exist"),
        (57, "PDU session type IPv4v6 only allowed"),
        (58, "PDU session type Unstructured only allowed"),
        (59, "Unsupported 5QI value"),
        (61, "PDU session type Ethernet only allowed"),
        (67, "Insufficient resources for specific slice and DNN"),
        (68, "Not supported SSC mode"),
        (69, "Insufficient resources for specific slice"),
        (70, "Missing or unknown DNN in a slice"),
        (81, "Invalid PTI value"),
        (
            82,
            "Maximum data rate per UE for user-plane integrity protection is too low",
        ),
        (83, "Semantic error in the QoS operation"),
        (84, "Syntactical error in the QoS operation"),
        (85, "Invalid mapped EPS bearer identity"),
        (86, "UAS services not allowed"),
        (
            87,
            "QoS differentiation for non-3GPP device identifier(s) not available",
        ),
        (95, "Semantically incorrect message"),
        (96, "Invalid mandatory information"),
        (97, "Message type non-existent or not implemented"),
        (98, "Message type not compatible with the protocol state"),
        (99, "Information element non-existent or not implemented"),
        (100, "Conditional IE error"),
        (101, "Message not compatible with the protocol state"),
        (111, "Protocol error, unspecified"),
    ];

    fn assert_table(f: fn(u8) -> Option<&'static str>, spec: &[(u8, &str)]) {
        for v in 0..=255u8 {
            let expected = spec.iter().find(|(c, _)| *c == v).map(|(_, n)| *n);
            assert_eq!(f(v), expected, "value {v}");
        }
    }

    #[test]
    fn mm_cause_table_matches_spec() {
        assert_table(mm_cause_name, MM_CAUSES);
    }

    #[test]
    fn sm_cause_table_matches_spec() {
        assert_table(sm_cause_name, SM_CAUSES);
    }

    #[test]
    fn value_name_tables() {
        assert_table(
            type_of_identity_name,
            &[
                (0, "No identity"),
                (1, "SUCI"),
                (2, "5G-GUTI"),
                (3, "IMEI"),
                (4, "5G-S-TMSI"),
                (5, "IMEISV"),
                (6, "MAC address"),
                (7, "EUI-64"),
            ],
        );
        // TS 24.501, Table 9.11.3.3.1: "All other values are unused and
        // shall be interpreted as \"SUCI\", if received by the UE."
        assert_table(
            identity_type_name,
            &[
                (1, "SUCI"),
                (2, "5G-GUTI"),
                (3, "IMEI"),
                (4, "5G-S-TMSI"),
                (5, "IMEISV"),
                (6, "MAC address"),
                (7, "EUI-64"),
            ],
        );
        for (v, n) in [
            (0, "IMSI"),
            (1, "Network specific identifier"),
            (2, "GCI"),
            (3, "GLI"),
            (7, "IMSI"),
        ] {
            assert_eq!(supi_format_name(v), Some(n));
        }
        for (v, n) in [
            (0, "Null scheme"),
            (1, "ECIES scheme profile A"),
            (2, "ECIES scheme profile B"),
            (3, "Reserved"),
            (11, "Reserved"),
            (12, "Operator-specific protection scheme"),
            (15, "Operator-specific protection scheme"),
        ] {
            assert_eq!(protection_scheme_name(v), Some(n));
        }
        assert_table(
            registration_type_name,
            &[
                (1, "initial registration"),
                (2, "mobility registration updating"),
                (3, "periodic registration updating"),
                (4, "emergency registration"),
                (5, "SNPN onboarding registration"),
                (6, "disaster roaming mobility registration updating"),
                (7, "disaster roaming initial registration"),
            ],
        );
        assert_table(
            registration_result_name,
            &[
                (1, "3GPP access"),
                (2, "Non-3GPP access"),
                (3, "3GPP access and non-3GPP access"),
                (7, "reserved"),
            ],
        );
        assert_eq!(tsc_name(0), Some("native security context"));
        assert_eq!(tsc_name(1), Some("mapped security context"));
        assert_eq!(ksi_name(0), None);
        assert_eq!(
            ksi_name(7),
            Some("no key is available (UE to network); reserved (network to UE)")
        );
        assert_eq!(
            type_of_list_name(0),
            Some("list of TACs belonging to one PLMN or SNPN, with non-consecutive TAC values")
        );
        assert_eq!(
            type_of_list_name(1),
            Some("list of TACs belonging to one PLMN or SNPN, with consecutive TAC values")
        );
        assert_eq!(type_of_list_name(3), None);
        for a in 0..8u8 {
            assert!(
                ciphering_algorithm_name(a)
                    .unwrap()
                    .contains(&format!("EA{a}"))
            );
            assert!(
                integrity_algorithm_name(a)
                    .unwrap()
                    .contains(&format!("IA{a}"))
            );
        }
        assert_eq!(ciphering_algorithm_name(8), None);
        assert_eq!(integrity_algorithm_name(8), None);
        assert_table(
            payload_container_type_name,
            &[
                (1, "N1 SM information"),
                (2, "SMS"),
                (3, "LTE Positioning Protocol (LPP) message container"),
                (4, "SOR transparent container"),
                (5, "UE policy container"),
                (6, "UE parameters update transparent container"),
                (7, "Location services message container"),
                (8, "CIoT user data container"),
                (9, "Service-level-AA container"),
                (10, "Event notification"),
                (11, "UPP-CMI container"),
                (12, "SLPP message container"),
                (15, "Multiple payloads"),
            ],
        );
        assert_table(
            request_type_name,
            &[
                (1, "initial request"),
                (2, "existing PDU session"),
                (3, "initial emergency request"),
                (4, "existing emergency PDU session"),
                (5, "modification request"),
                (6, "MA PDU request"),
                (7, "reserved"),
            ],
        );
        assert_table(
            access_type_name,
            &[
                (1, "3GPP access"),
                (2, "Non-3GPP access"),
                (3, "3GPP access and non-3GPP access"),
            ],
        );
        for (v, n) in [
            (0, "signalling"),
            (2, "mobile terminated services"),
            (3, "emergency services"),
            (4, "emergency services fallback"),
            (5, "high priority access"),
            (6, "elevated signalling"),
        ] {
            assert_eq!(service_type_name(v), Some(n));
        }
        assert!(service_type_name(8).unwrap().contains("\"signalling\""));
        assert!(service_type_name(11).unwrap().contains("\"data\""));
        assert_eq!(service_type_name(12), None);
        assert_table(
            pdu_session_type_name,
            &[
                (1, "IPv4"),
                (2, "IPv6"),
                (3, "IPv4v6"),
                (4, "Unstructured"),
                (5, "Ethernet"),
                (7, "reserved"),
            ],
        );
        for (v, n) in [(2, "SSC mode 2"), (3, "SSC mode 3")] {
            assert_eq!(ssc_mode_name(v), Some(n));
        }
        for v in 4..=6u8 {
            assert!(ssc_mode_name(v).unwrap().starts_with("unused"));
        }
        assert_eq!(ssc_mode_name(0), None);
        assert_table(
            integrity_max_data_rate_name,
            &[(0, "64 kbps"), (1, "NULL"), (0xff, "Full data rate")],
        );
        assert_eq!(bit_rate_unit_name(0), Some("value is not used"));
        assert_eq!(bit_rate_unit_name(1), Some("1 Kbps"));
        assert_eq!(bit_rate_unit_name(11), Some("1 Gbps"));
        assert_eq!(bit_rate_unit_name(24), Some("64 Pbps"));
        assert_eq!(bit_rate_unit_name(25), Some("256 Pbps"));
        assert_eq!(bit_rate_unit_name(0xff), Some("256 Pbps"));
        for (v, n) in [
            (0, "Reserved"),
            (2, "Delete existing QoS rule"),
            (3, "Modify existing QoS rule and add packet filters"),
            (4, "Modify existing QoS rule and replace all packet filters"),
            (
                6,
                "Modify existing QoS rule without modifying packet filters",
            ),
            (7, "Reserved"),
        ] {
            assert_eq!(rule_operation_code_name(v), Some(n));
        }
        for (v, n) in [(0, "reserved"), (1, "downlink only"), (2, "uplink only")] {
            assert_eq!(packet_filter_direction_name(v), Some(n));
        }
        for (v, n) in [
            (0, "reserved"),
            (2, "Delete existing QoS flow description"),
            (3, "Modify existing QoS flow description"),
        ] {
            assert_eq!(flow_operation_code_name(v), Some(n));
        }
        assert_table(
            parameter_identifier_name,
            &[
                (1, "5QI"),
                (2, "GFBR uplink"),
                (3, "GFBR downlink"),
                (4, "MFBR uplink"),
                (5, "MFBR downlink"),
                (6, "Averaging window"),
                (7, "EPS bearer identity"),
            ],
        );
        // A display function given a value of the wrong type yields no name.
        let display = FD_MM_CAUSE.display_fn.unwrap();
        assert_eq!(display(&FieldValue::U16(3), &[]), None);
    }

    #[test]
    fn format_functions() {
        assert_eq!(fmt(format_bcd, FieldValue::Bytes(&[0x21, 0xf3])), "\"123\"");
        assert_eq!(fmt(format_bcd, FieldValue::Bytes(&[0xba])), "\"ab\"");
        assert_eq!(
            fmt(format_identity_digits, FieldValue::Bytes(&[0x1b, 0x32])),
            "\"123\""
        );
        assert_eq!(
            fmt(format_mcc, FieldValue::Bytes(&[0x21, 0xf3, 0x54])),
            "\"123\""
        );
        assert_eq!(
            fmt(format_mnc, FieldValue::Bytes(&[0x21, 0xf3, 0x54])),
            "\"45\""
        );
        assert_eq!(
            fmt(format_mnc, FieldValue::Bytes(&[0x21, 0x63, 0x54])),
            "\"456\""
        );
        // Values of an unexpected shape are written as empty strings.
        for f in [format_bcd, format_identity_digits, format_mcc, format_mnc] {
            assert_eq!(fmt(f, FieldValue::U8(1)), "\"\"");
        }
        assert_eq!(fmt(format_mcc, FieldValue::Bytes(&[0x21])), "\"\"");
        assert_eq!(fmt(format_mnc, FieldValue::Bytes(&[0x21])), "\"\"");
    }

    #[test]
    fn mobile_identity_rejects_bad_lengths() {
        for data in [
            &[][..],
            &[0xf2, 0x02][..],             // 5G-GUTI too short
            &[0xf4, 0x00][..],             // 5G-S-TMSI too short
            &[0x06, 0x00][..],             // MAC address too short
            &[0x07, 0x00][..],             // EUI-64 too short
            &[0x01, 0x00, 0xf1, 0x10][..], // SUCI (IMSI) too short
            &[0x11][..],                   // SUCI NAI without NAI
        ] {
            assert_raw(Value::MobileIdentity, data);
        }
    }

    #[test]
    fn suci_without_scheme_output() {
        let fields = decode(
            Value::MobileIdentity,
            &[0x01, 0x00, 0xf1, 0x10, 0xf0, 0xff, 0x00, 0x00],
        );
        let names: Vec<_> = fields.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            [
                "type_of_identity",
                "supi_format",
                "mcc",
                "mnc",
                "routing_indicator",
                "protection_scheme_id",
                "home_network_public_key_id",
            ]
        );
    }

    #[test]
    fn fixed_length_values_reject_bad_input() {
        for value in [
            Value::RegistrationResult,
            Value::MmCause,
            Value::SmCause,
            Value::PduSessionIdentity2,
            Value::NasSecurityAlgorithms,
            Value::TrackingAreaIdentity,
            Value::SessionAmbr,
            Value::IntegrityProtectionMaximumDataRate,
            Value::UeSecurityCapability,
        ] {
            assert_raw(value, &[]);
            assert_raw(value, &[0; 9]);
        }
        // "If octet 5 is included, then also octet 6 shall be included."
        for len in [1, 3, 5, 7] {
            assert_raw(Value::UeSecurityCapability, &[0; 8][..len]);
        }
        // Value kinds without an octet decoder keep the raw value.
        assert_raw(Value::Raw, &[1, 2]);
        assert_raw(Value::NasKeySetIdentifier, &[1]);
    }

    #[test]
    fn nssai_rejects_malformed_lists() {
        // S-NSSAI length beyond the IE.
        assert_raw(Value::Nssai, &[0x04, 0x01, 0x02]);
        // S-NSSAI with a reserved length.
        assert_raw(Value::SNssai, &[1, 2, 3]);
        assert_raw(Value::SNssai, &[]);
    }

    #[test]
    fn tai_list_rejects_malformed_lists() {
        // Type of list "11" is reserved.
        assert_raw(Value::TrackingAreaIdentityList, &[0x60, 0, 0, 0, 0, 0, 0]);
        // Two TACs announced, one present.
        assert_raw(
            Value::TrackingAreaIdentityList,
            &[0x01, 0x02, 0xf8, 0x39, 0, 0, 1],
        );
    }

    #[test]
    fn pdu_address_rejects_bad_input() {
        assert_raw(Value::PduAddress, &[]);
        // Reserved PDU session type.
        assert_raw(Value::PduAddress, &[0x04, 0, 0, 0, 0]);
        // IPv4 with a missing octet.
        assert_raw(Value::PduAddress, &[0x01, 10, 0, 0]);
        // SI6LLA set without the SMF address.
        assert_raw(Value::PduAddress, &[0x09, 10, 0, 0, 1]);
    }

    #[test]
    fn qos_rules_edge_cases() {
        // Rule header truncated.
        assert_raw(Value::QosRules, &[0x01, 0x00]);
        // Zero rule length.
        assert_raw(Value::QosRules, &[0x01, 0x00, 0x00]);
        // Rule length beyond the IE.
        assert_raw(Value::QosRules, &[0x01, 0x00, 0x05, 0x31]);
        // Packet filter announced but missing.
        assert_raw(Value::QosRules, &[0x01, 0x00, 0x01, 0x21]);
        // Packet filter length octet missing.
        assert_raw(Value::QosRules, &[0x01, 0x00, 0x02, 0x21, 0x31]);
        // Packet filter contents beyond the rule.
        assert_raw(Value::QosRules, &[0x01, 0x00, 0x04, 0x21, 0x31, 0x05, 0x01]);
        // Delete-packet-filters rule with a missing identifier.
        assert_raw(Value::QosRules, &[0x01, 0x00, 0x02, 0xa2, 0x01]);
        // More than two octets after the packet filter list.
        assert_raw(Value::QosRules, &[0x01, 0x00, 0x04, 0x40, 0x01, 0x02, 0x03]);

        // Delete existing QoS rule: no filters, no precedence.
        let mut buf = DissectBuffer::new();
        let mut ctx = MessageContext::default();
        push_value(
            &mut buf,
            Value::QosRules,
            &[0x01, 0x00, 0x01, 0x40],
            0,
            &mut ctx,
            true,
        );
        assert!(
            buf.fields()
                .iter()
                .all(|f| f.name() != "qos_rule_precedence")
        );

        // Precedence without QFI.
        let mut buf = DissectBuffer::new();
        push_value(
            &mut buf,
            Value::QosRules,
            &[0x01, 0x00, 0x02, 0xc0, 0x07],
            0,
            &mut ctx,
            true,
        );
        let precedence = buf
            .fields()
            .iter()
            .find(|f| f.name() == "qos_rule_precedence")
            .unwrap();
        assert_eq!(precedence.value, FieldValue::U8(7));
        assert!(buf.fields().iter().all(|f| f.name() != "qfi"));
    }

    #[test]
    fn qos_flow_parameters() {
        let data = [
            0x01, 0x20, 0x45, // QFI 1, create, E=1, 5 parameters
            0x02, 0x03, 0x06, 0x00, 0x0a, // GFBR uplink 10 Mbps
            0x05, 0x03, 0x06, 0x00, 0x14, // MFBR downlink 20 Mbps
            0x06, 0x02, 0x07, 0xd0, // averaging window 2000 ms
            0x07, 0x01, 0x50, // EPS bearer identity 5
            0x09, 0x01, 0xaa, // unknown parameter
        ];
        let mut buf = DissectBuffer::new();
        let mut ctx = MessageContext::default();
        push_value(
            &mut buf,
            Value::QosFlowDescriptions,
            &data,
            0,
            &mut ctx,
            true,
        );
        let get = |name: &str| -> Vec<FieldValue<'_>> {
            buf.fields()
                .iter()
                .filter(|f| f.name() == name)
                .map(|f| f.value.clone())
                .collect()
        };
        assert_eq!(get("unit"), [FieldValue::U8(6), FieldValue::U8(6)]);
        assert_eq!(get("bit_rate"), [FieldValue::U16(10), FieldValue::U16(20)]);
        assert_eq!(get("averaging_window"), [FieldValue::U16(2000)]);
        assert_eq!(get("eps_bearer_identity"), [FieldValue::U8(5)]);
        assert_eq!(get("contents"), [FieldValue::Bytes(&[0xaa])]);
        // A 5QI parameter of the wrong length keeps its contents.
        let mut buf = DissectBuffer::new();
        push_value(
            &mut buf,
            Value::QosFlowDescriptions,
            &[0x01, 0x20, 0x41, 0x01, 0x02, 0x09, 0x09],
            0,
            &mut ctx,
            true,
        );
        assert!(buf.fields().iter().any(|f| f.name() == "contents"));
    }

    #[test]
    fn qos_flow_descriptions_reject_bad_input() {
        // Description header truncated.
        assert_raw(Value::QosFlowDescriptions, &[0x01, 0x20]);
        // Parameter announced but missing.
        assert_raw(Value::QosFlowDescriptions, &[0x01, 0x20, 0x41, 0x01]);
        // Parameter contents beyond the IE.
        assert_raw(
            Value::QosFlowDescriptions,
            &[0x01, 0x20, 0x41, 0x01, 0x02, 0x09],
        );
    }

    #[test]
    fn n1_sm_schema_uses_pushed_header_descriptors() {
        // The schema must describe the descriptors push_5gsm actually
        // pushes, including their display functions.
        let names: Vec<_> = N1_SM_CHILDREN[..4].iter().map(|d| d.name).collect();
        assert_eq!(
            names,
            [
                "extended_protocol_discriminator",
                "pdu_session_id",
                "procedure_transaction_identity",
                "message_type",
            ]
        );
        let epd = N1_SM_CHILDREN[0].display_fn.unwrap();
        assert_eq!(
            epd(&FieldValue::U8(0x2e), &[]),
            Some("5GS session management")
        );
        let mt = N1_SM_CHILDREN[3].display_fn.unwrap();
        assert_eq!(
            mt(&FieldValue::U8(0xc1), &[]),
            Some("PDU session establishment request")
        );
    }

    #[test]
    fn n1_sm_container_not_5gsm_kept_raw() {
        let mut buf = DissectBuffer::new();
        let mut ctx = MessageContext {
            payload_container_type: Some(PAYLOAD_CONTAINER_TYPE_N1_SM),
        };
        push_value(
            &mut buf,
            Value::PayloadContainer,
            &[0x2e, 0x01],
            0,
            &mut ctx,
            true,
        );
        assert_eq!(top(&buf), [("value", FieldValue::Bytes(&[0x2e, 0x01]))]);
        // Not decoded when nesting is not allowed.
        let mut buf = DissectBuffer::new();
        let data = [0x2e, 0x01, 0x01, 0xd6, 0x24];
        push_value(&mut buf, Value::PayloadContainer, &data, 0, &mut ctx, false);
        assert_eq!(top(&buf), [("value", FieldValue::Bytes(&data))]);
    }
}
