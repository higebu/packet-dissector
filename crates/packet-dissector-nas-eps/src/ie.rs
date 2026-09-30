//! EPS NAS information element framing and value decoding.
//!
//! An EMM or ESM message body is an imperative part of mandatory IEs in a
//! fixed order (formats V, LV and LV-E, no IEI) followed by a non-imperative
//! part of optional IEs, each starting with an IEI (formats TV, TLV and
//! TLV-E). The per-message layouts are in [`crate::messages`].
//!
//! ## References
//! - 3GPP TS 24.301, Section 8 (message contents), 9.9 (IEs):
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.301/>
//! - 3GPP TS 24.007, Section 11.2.1.1.4 (IE categories), 11.2.4
//!   (non-imperative part, unknown IEIs):
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.007/>
//! - 3GPP TS 24.008, Section 10.5.1.3 (location area identification),
//!   10.5.1.4 (mobile identity), 10.5.5.9 (identity type 2), 10.5.6.17
//!   (request type), 10.5.7.3 (GPRS timer):
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.008/>

use std::io::{self, Write};

use packet_dissector_core::field::{
    FieldDescriptor, FieldType, FieldValue, FormatContext, format_fqdn_labels,
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
    /// Spare half octet (TS 24.301, 9.9.2.9); not emitted.
    Spare,
    /// NAS key set identifier (TS 24.301, 9.9.3.21).
    NasKeySetIdentifier,
    /// EPS attach type (TS 24.301, 9.9.3.11).
    EpsAttachType,
    /// EPS attach result (TS 24.301, 9.9.3.10).
    EpsAttachResult,
    /// EPS update type (TS 24.301, 9.9.3.14).
    EpsUpdateType,
    /// EPS update result (TS 24.301, 9.9.3.13).
    EpsUpdateResult,
    /// Detach type (TS 24.301, 9.9.3.7).
    DetachType,
    /// Service type (TS 24.301, 9.9.3.27).
    ServiceType,
    /// Identity type 2 (TS 24.301, 9.9.3.17; TS 24.008, 10.5.5.9).
    IdentityType2,
    /// PDN type (TS 24.301, 9.9.4.10).
    PdnType,
    /// Request type (TS 24.301, 9.9.4.14; TS 24.008, 10.5.6.17).
    RequestType,
    /// EPS bearer identity in a half octet (linked EPS bearer identity,
    /// TS 24.301, 9.9.4.6).
    EpsBearerIdentity,
    /// EPS mobile identity (TS 24.301, 9.9.3.12).
    EpsMobileIdentity,
    /// Mobile identity (TS 24.301, 9.9.2.3; TS 24.008, 10.5.1.4).
    MobileIdentity,
    /// EMM cause (TS 24.301, 9.9.3.9).
    EmmCause,
    /// ESM cause (TS 24.301, 9.9.4.4).
    EsmCause,
    /// Tracking area identity (TS 24.301, 9.9.3.32).
    TrackingAreaIdentity,
    /// Tracking area identity list (TS 24.301, 9.9.3.33).
    TrackingAreaIdentityList,
    /// Location area identification (TS 24.301, 9.9.2.2; TS 24.008,
    /// 10.5.1.3).
    LocationAreaIdentification,
    /// NAS security algorithms (TS 24.301, 9.9.3.23).
    NasSecurityAlgorithms,
    /// UE network capability (TS 24.301, 9.9.3.34).
    UeNetworkCapability,
    /// UE security capability (TS 24.301, 9.9.3.36).
    UeSecurityCapability,
    /// ESM message container (TS 24.301, 9.9.3.15).
    EsmMessageContainer,
    /// Access point name (TS 24.301, 9.9.4.1; TS 24.008, 10.5.6.1).
    AccessPointName,
    /// PDN address (TS 24.301, 9.9.4.9).
    PdnAddress,
    /// EPS quality of service (TS 24.301, 9.9.4.3).
    EpsQos,
    /// GPRS timer (TS 24.301, 9.9.3.16; TS 24.008, 10.5.7.3).
    GprsTimer,
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

/// EMM cause value name.
///
/// 3GPP TS 24.301, Section 9.9.3.9, Table 9.9.3.9.1.
pub(crate) fn emm_cause_name(cause: u8) -> Option<&'static str> {
    crate::names::emm_cause_name(cause)
}

/// ESM cause value name.
///
/// 3GPP TS 24.301, Section 9.9.4.4, Table 9.9.4.4.1.
pub(crate) fn esm_cause_name(cause: u8) -> Option<&'static str> {
    crate::names::esm_cause_name(cause)
}

/// Type of identity of an EPS mobile identity.
///
/// 3GPP TS 24.301, Section 9.9.3.12, Table 9.9.3.12.1.
fn eps_identity_type_name(t: u8) -> Option<&'static str> {
    match t {
        1 => Some("IMSI"),
        3 => Some("IMEI"),
        6 => Some("GUTI"),
        _ => None,
    }
}

/// Type of identity of a mobile identity.
///
/// 3GPP TS 24.008, Section 10.5.1.4, Table 10.5.4.
fn mobile_identity_type_name(t: u8) -> Option<&'static str> {
    match t {
        0 => Some("No Identity"),
        1 => Some("IMSI"),
        2 => Some("IMEI"),
        3 => Some("IMEISV"),
        4 => Some("TMSI/P-TMSI/M-TMSI"),
        5 => Some("TMGI and optional MBMS Session Identity"),
        _ => None,
    }
}

/// Type of security context flag.
///
/// 3GPP TS 24.301, Section 9.9.3.21, Table 9.9.3.21.1.
fn tsc_name(t: u8) -> Option<&'static str> {
    match t {
        0 => Some("native security context"),
        1 => Some("mapped security context"),
        _ => None,
    }
}

/// EPS attach type value. TS 24.301, Section 9.9.3.11, Table 9.9.3.11.1.
fn eps_attach_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("EPS attach"),
        2 => Some("combined EPS/IMSI attach"),
        3 => Some("EPS RLOS attach"),
        6 => Some("EPS emergency attach"),
        7 => Some("disaster roaming attach"),
        _ => None,
    }
}

/// EPS attach result value. TS 24.301, Section 9.9.3.10, Table 9.9.3.10.1.
fn eps_attach_result_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("EPS only"),
        2 => Some("combined EPS/IMSI attach"),
        _ => None,
    }
}

/// EPS update type value. TS 24.301, Section 9.9.3.14, Table 9.9.3.14.1.
fn eps_update_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("TA updating"),
        1 => Some("combined TA/LA updating"),
        2 => Some("combined TA/LA updating with IMSI attach"),
        3 => Some("periodic updating"),
        6 => Some("disaster roaming update"),
        _ => None,
    }
}

/// EPS update result value. TS 24.301, Section 9.9.3.13, Table 9.9.3.13.1.
fn eps_update_result_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("TA updated"),
        1 => Some("combined TA/LA updated"),
        4 => Some("TA updated and ISR activated"),
        5 => Some("combined TA/LA updated and ISR activated"),
        _ => None,
    }
}

/// Service type value. TS 24.301, Section 9.9.3.27, Table 9.9.3.27.1.
fn service_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("mobile originating CS fallback or 1xCS fallback"),
        1 => Some("mobile terminating CS fallback or 1xCS fallback"),
        2 => Some("mobile originating CS fallback emergency call or 1xCS fallback emergency call"),
        8 => Some("packet services via S1"),
        _ => None,
    }
}

/// Type of identity of the Identity type 2 IE.
///
/// 3GPP TS 24.008, Section 10.5.5.9, Table 10.5.140.
fn identity_type_2_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("IMSI"),
        2 => Some("IMEI"),
        3 => Some("IMEISV"),
        4 => Some("TMSI"),
        _ => None,
    }
}

/// PDN type value. TS 24.301, Sections 9.9.4.9 and 9.9.4.10.
fn pdn_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("IPv4"),
        2 => Some("IPv6"),
        3 => Some("IPv4v6"),
        5 => Some("non IP"),
        6 => Some("Ethernet"),
        _ => None,
    }
}

/// Request type value.
///
/// 3GPP TS 24.008, Section 10.5.6.17, Table 10.5.173.
fn request_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("initial request"),
        2 => Some("handover"),
        3 => Some("unused"),
        4 => Some("emergency"),
        6 => Some("handover of emergency bearer services"),
        _ => None,
    }
}

/// Type of list of a partial tracking area identity list.
///
/// 3GPP TS 24.301, Section 9.9.3.33, Table 9.9.3.33.1.
fn type_of_list_name(t: u8) -> Option<&'static str> {
    match t {
        0 => Some("list of TACs belonging to one PLMN, with non-consecutive TAC values"),
        1 => Some("list of TACs belonging to one PLMN, with consecutive TAC values"),
        2 => Some("list of TAIs belonging to different PLMNs"),
        _ => None,
    }
}

/// Type of ciphering algorithm. TS 24.301, Section 9.9.3.23.
fn ciphering_algorithm_name(a: u8) -> Option<&'static str> {
    match a {
        0 => Some("EEA0 (null ciphering algorithm)"),
        1 => Some("128-EEA1"),
        2 => Some("128-EEA2"),
        3 => Some("128-EEA3"),
        4 => Some("EEA4"),
        5 => Some("EEA5"),
        6 => Some("EEA6"),
        7 => Some("EEA7"),
        _ => None,
    }
}

/// Type of integrity protection algorithm. TS 24.301, Section 9.9.3.23.
fn integrity_algorithm_name(a: u8) -> Option<&'static str> {
    match a {
        0 => Some("EIA0 (null integrity protection algorithm)"),
        1 => Some("128-EIA1"),
        2 => Some("128-EIA2"),
        3 => Some("128-EIA3"),
        4 => Some("EIA4"),
        5 => Some("EIA5"),
        6 => Some("EIA6"),
        7 => Some("EIA7"),
        _ => None,
    }
}

/// GPRS timer unit.
///
/// 3GPP TS 24.008, Section 10.5.7.3, Table 10.5.172.
fn gprs_timer_unit_name(u: u8) -> Option<&'static str> {
    match u {
        0 => Some("2 seconds"),
        1 => Some("1 minute"),
        2 => Some("decihours"),
        7 => Some("deactivated"),
        _ => None,
    }
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

/// Format identity digits whose digit 1 is in bits 5 to 8 of the first
/// value octet, followed by two digits per octet.
///
/// 3GPP TS 24.301, Section 9.9.3.12, Figure 9.9.3.12.2; TS 24.008,
/// Section 10.5.1.4, Figure 10.5.4.
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

/// Format the MCC of a 3-octet PLMN identity (TS 24.008, Figure 10.5.154).
fn format_mcc(v: &FieldValue<'_>, _ctx: &FormatContext<'_>, w: &mut dyn Write) -> io::Result<()> {
    let &FieldValue::Bytes(&[b0, b1, _]) = v else {
        return w.write_all(b"\"\"");
    };
    write_digits(w, [b0 & 0x0f, b0 >> 4, b1 & 0x0f].into_iter())
}

/// Format the MNC of a 3-octet PLMN identity; MNC digit 3 is "1111" for a
/// two-digit MNC (TS 24.008, Figure 10.5.154).
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

// PLMN identity, tracking area and location area.
static FD_MCC: FieldDescriptor = FieldDescriptor::new("mcc", "MCC", FieldType::Bytes)
    .optional()
    .with_format_fn(format_mcc);
static FD_MNC: FieldDescriptor = FieldDescriptor::new("mnc", "MNC", FieldType::Bytes)
    .optional()
    .with_format_fn(format_mnc);
plain!(FD_TAC, "tac", "TAC", U16);
plain!(FD_LAC, "lac", "LAC", U16);

// EPS mobile identity (9.9.3.12) and mobile identity (TS 24.008 10.5.1.4).
named_u8!(
    FD_EPS_IDENTITY_TYPE,
    "type_of_identity",
    "Type of Identity",
    eps_identity_type_name
);
named_u8!(
    FD_MOBILE_IDENTITY_TYPE,
    "type_of_identity",
    "Type of Identity",
    mobile_identity_type_name
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
plain!(FD_MME_GROUP_ID, "mme_group_id", "MME Group ID", U16);
plain!(FD_MME_CODE, "mme_code", "MME Code", U8);
plain!(FD_M_TMSI, "m_tmsi", "M-TMSI", U32);
plain!(FD_TMSI, "tmsi", "TMSI/P-TMSI", U32);

// Half-octet IEs.
named_u8!(FD_TSC, "tsc", "Type of Security Context", tsc_name);
plain!(FD_KSI, "nas_key_set_identifier", "NAS Key Set Identifier", U8);
named_u8!(
    FD_EPS_ATTACH_TYPE,
    "eps_attach_type",
    "EPS Attach Type",
    eps_attach_type_name
);
named_u8!(
    FD_EPS_ATTACH_RESULT,
    "eps_attach_result",
    "EPS Attach Result",
    eps_attach_result_name
);
plain!(FD_ACTIVE_FLAG, "active_flag", "Active Flag", U8);
named_u8!(
    FD_EPS_UPDATE_TYPE,
    "eps_update_type",
    "EPS Update Type",
    eps_update_type_name
);
named_u8!(
    FD_EPS_UPDATE_RESULT,
    "eps_update_result",
    "EPS Update Result",
    eps_update_result_name
);
plain!(FD_SWITCH_OFF, "switch_off", "Switch Off", U8);
plain!(FD_TYPE_OF_DETACH, "type_of_detach", "Type of Detach", U8);
named_u8!(
    FD_SERVICE_TYPE,
    "service_type",
    "Service Type",
    service_type_name
);
named_u8!(
    FD_IDENTITY_TYPE_2,
    "identity_type",
    "Type of Identity",
    identity_type_2_name
);
named_u8!(FD_PDN_TYPE, "pdn_type", "PDN Type", pdn_type_name);
named_u8!(
    FD_REQUEST_TYPE,
    "request_type",
    "Request Type",
    request_type_name
);
plain!(
    FD_EPS_BEARER_IDENTITY,
    "eps_bearer_identity",
    "EPS Bearer Identity",
    U8
);

// Causes.
named_u8!(FD_EMM_CAUSE, "cause", "EMM Cause", emm_cause_name);
named_u8!(FD_ESM_CAUSE, "cause", "ESM Cause", esm_cause_name);

// Tracking area identity list (9.9.3.33).
static TAI_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("mcc", "MCC", FieldType::Bytes).with_format_fn(format_mcc),
    FieldDescriptor::new("mnc", "MNC", FieldType::Bytes).with_format_fn(format_mnc),
    FieldDescriptor::new("tac", "TAC", FieldType::U16),
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

// Security (9.9.3.23, 9.9.3.34, 9.9.3.36).
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
plain!(FD_EEA, "eea", "EPS Encryption Algorithms", U8);
plain!(FD_EIA, "eia", "EPS Integrity Algorithms", U8);
plain!(FD_UEA, "uea", "UMTS Encryption Algorithms", U8);
plain!(FD_UIA, "uia", "UMTS Integrity Algorithms", U8);
plain!(FD_GEA, "gea", "GPRS Encryption Algorithms", U8);
plain!(FD_ADDITIONAL_OCTETS, "additional_octets", "Additional Octets", Bytes);

// ESM message container (9.9.3.15): a nested plain ESM message.
static FD_ESM_MESSAGE: FieldDescriptor =
    FieldDescriptor::new("esm_message", "ESM Message", FieldType::Object).optional();

// ESM (9.9.4.1, 9.9.4.3, 9.9.4.9).
static FD_APN: FieldDescriptor = FieldDescriptor::new("apn", "Access Point Name", FieldType::Bytes)
    .optional()
    .with_format_fn(format_fqdn_labels);
plain!(FD_IPV4_ADDRESS, "ipv4_address", "IPv4 Address", Ipv4Addr);
plain!(
    FD_IPV6_IID,
    "ipv6_interface_identifier",
    "IPv6 Interface Identifier",
    Bytes
);
plain!(FD_QCI, "qci", "QCI", U8);
plain!(FD_BIT_RATES, "bit_rates", "Bit Rates", Bytes);

// GPRS timer (TS 24.008 10.5.7.3).
named_u8!(
    FD_TIMER_UNIT,
    "timer_unit",
    "Timer Unit",
    gprs_timer_unit_name
);
plain!(FD_TIMER_VALUE, "timer_value", "Timer Value", U8);

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
    FD_MCC,
    FD_MNC,
    FD_TAC,
    FD_LAC,
    FD_EPS_IDENTITY_TYPE,
    FD_ODD_EVEN,
    FD_IDENTITY_DIGITS,
    FD_MME_GROUP_ID,
    FD_MME_CODE,
    FD_M_TMSI,
    FD_TMSI,
    FD_TSC,
    FD_KSI,
    FD_EPS_ATTACH_TYPE,
    FD_EPS_ATTACH_RESULT,
    FD_ACTIVE_FLAG,
    FD_EPS_UPDATE_TYPE,
    FD_EPS_UPDATE_RESULT,
    FD_SWITCH_OFF,
    FD_TYPE_OF_DETACH,
    FD_SERVICE_TYPE,
    FD_IDENTITY_TYPE_2,
    FD_PDN_TYPE,
    FD_REQUEST_TYPE,
    FD_EPS_BEARER_IDENTITY,
    FD_EMM_CAUSE,
    FD_PARTIAL_TAI_LISTS,
    FD_CIPHERING_ALGORITHM,
    FD_INTEGRITY_ALGORITHM,
    FD_EEA,
    FD_EIA,
    FD_UEA,
    FD_UIA,
    FD_GEA,
    FD_ADDITIONAL_OCTETS,
    FD_ESM_MESSAGE,
    FD_APN,
    FD_IPV4_ADDRESS,
    FD_IPV6_IID,
    FD_QCI,
    FD_BIT_RATES,
    FD_TIMER_UNIT,
    FD_TIMER_VALUE,
];

/// One IE object in `information_elements`.
static FD_IE: FieldDescriptor =
    FieldDescriptor::new("ie", "Information Element", FieldType::Object).with_children(IE_CHILDREN);

/// The `information_elements` array of an EMM or ESM message.
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

/// Push the IEs of a message body (the octets after the message type) as
/// `information_elements`.
///
/// Mandatory IEs are framed with the message content table; optional IEs
/// with their table entry, or with the rules of TS 24.007, Section 11.2.4
/// when unknown. Octets that cannot be framed are pushed as
/// `undecoded_octets`.
///
/// `allow_esm` controls whether an ESM message container is decoded as a
/// nested ESM message. It is `false` inside an ESM message (which never
/// carries one) and for a partially ciphered message, where the container
/// value is ciphered (TS 24.301, Section 4.4.5).
pub(crate) fn push_message_ies<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    offset: usize,
    ies: &MessageIes,
    allow_esm: bool,
) {
    let list_idx = buf.begin_container(
        &FD_INFORMATION_ELEMENTS,
        FieldValue::Array(0..0),
        offset..offset + body.len(),
    );
    let result = push_mandatory(buf, body, offset, ies, allow_esm)
        .and_then(|pos| push_optional(buf, body, offset, pos, ies, allow_esm));
    let (framed_end, missing) = match result {
        Ok(()) => (body.len(), None),
        Err(stop) => (stop.pos, stop.missing),
    };
    // Shrink the array range to the octets actually framed as IEs.
    if let Some(field) = buf.field_mut(list_idx as usize) {
        field.range = offset..offset + framed_end;
    }
    buf.end_container(list_idx);
    if buf.fields().len() == list_idx as usize + 1 {
        // No IE was pushed: drop the empty array.
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

/// Push the mandatory IEs; returns the position after the last one, or the
/// position of the first IE that does not fit.
fn push_mandatory<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    offset: usize,
    ies: &MessageIes,
    allow_esm: bool,
) -> Result<usize, Stop> {
    let mut pos = 0;
    // TS 24.301, Section 8.1 (as TS 24.007, Section 11.2.1.1.4): of two
    // consecutive half-octet IEs, the first occupies bits 1 to 4 and the
    // second bits 5 to 8 of the same octet.
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
                    push_half_value(buf, ie.value, nibble, range);
                    buf.end_container(idx);
                }
                if high_nibble {
                    pos += 1;
                }
                high_nibble = !high_nibble;
                continue;
            }
            // Every half-octet IE in the message tables is paired (see the
            // `messages` tests), so an octet-aligned IE never starts in the
            // middle of an octet.
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
        let idx = begin_ie(buf, ie.name, None, offset + pos..offset + end);
        push_length(buf, len_size, value_len, offset + pos);
        let value_start = pos + len_size;
        push_value(
            buf,
            ie.value,
            &body[value_start..end],
            offset + value_start,
            allow_esm,
        );
        buf.end_container(idx);
        pos = end;
    }
    Ok(pos)
}

/// Push the optional IEs starting at `pos`.
fn push_optional<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    offset: usize,
    mut pos: usize,
    ies: &MessageIes,
    allow_esm: bool,
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
            push_half_value(buf, known.map_or(Value::Raw, |ie| ie.value), octet & 0x0f, range);
            buf.end_container(idx);
            pos += 1;
            continue;
        }

        let known = ies.optional.iter().find(|ie| {
            !matches!(ie.format, OptionalFormat::Tv1) && ie.iei == octet
        });
        let (len_size, value_len) = match known.map(|ie| ie.format) {
            // A known type 3 IE has a fixed length and no length octet.
            Some(OptionalFormat::Tv(n)) => (0, n),
            // TS 24.007, Section 11.2.4, for EMM and ESM: IEIs 78 to 7F
            // (hexadecimal) are TLV-E, 00 to 77 are TLV. The known TLV and
            // TLV-E IEs of the message tables follow the same rule.
            _ => {
                let l = if octet & 0x78 == 0x78 { 2 } else { 1 };
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
            allow_esm,
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
) {
    let mut u8_field = |d: &'static FieldDescriptor, v: u8| {
        buf.push_field(d, FieldValue::U8(v), range.clone());
    };
    match value {
        // 9.9.3.21: TSC in bit 4, NAS key set identifier in bits 1 to 3.
        Value::NasKeySetIdentifier => {
            u8_field(&FD_TSC, (nibble >> 3) & 1);
            u8_field(&FD_KSI, nibble & 0x07);
        }
        // 9.9.3.11: spare bit 4, value in bits 1 to 3.
        Value::EpsAttachType => u8_field(&FD_EPS_ATTACH_TYPE, nibble & 0x07),
        // 9.9.3.10: spare bit 4, value in bits 1 to 3.
        Value::EpsAttachResult => u8_field(&FD_EPS_ATTACH_RESULT, nibble & 0x07),
        // 9.9.3.14: "Active" flag in bit 4, value in bits 1 to 3.
        Value::EpsUpdateType => {
            u8_field(&FD_ACTIVE_FLAG, (nibble >> 3) & 1);
            u8_field(&FD_EPS_UPDATE_TYPE, nibble & 0x07);
        }
        // 9.9.3.13: spare bit 4, value in bits 1 to 3.
        Value::EpsUpdateResult => u8_field(&FD_EPS_UPDATE_RESULT, nibble & 0x07),
        // 9.9.3.7: switch off in bit 4, type of detach in bits 1 to 3.
        Value::DetachType => {
            u8_field(&FD_SWITCH_OFF, (nibble >> 3) & 1);
            u8_field(&FD_TYPE_OF_DETACH, nibble & 0x07);
        }
        // 9.9.3.27: value in bits 1 to 4.
        Value::ServiceType => u8_field(&FD_SERVICE_TYPE, nibble),
        // TS 24.008, 10.5.5.9: type of identity in bits 1 to 3.
        Value::IdentityType2 => u8_field(&FD_IDENTITY_TYPE_2, nibble & 0x07),
        // 9.9.4.10: spare bit 4, value in bits 1 to 3.
        Value::PdnType => u8_field(&FD_PDN_TYPE, nibble & 0x07),
        // TS 24.008, 10.5.6.17: spare bit 4, value in bits 1 to 3.
        Value::RequestType => u8_field(&FD_REQUEST_TYPE, nibble & 0x07),
        // 9.9.4.6: EPS bearer identity in bits 1 to 4.
        Value::EpsBearerIdentity => u8_field(&FD_EPS_BEARER_IDENTITY, nibble),
        _ => u8_field(&FD_IE_VALUE_U8, nibble),
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
    allow_esm: bool,
) {
    let mark = buf.fields().len();
    let ok = match value {
        Value::EpsMobileIdentity => push_eps_mobile_identity(buf, data, offset),
        Value::MobileIdentity => push_mobile_identity(buf, data, offset),
        Value::EmmCause => push_single(buf, &FD_EMM_CAUSE, data, offset),
        Value::EsmCause => push_single(buf, &FD_ESM_CAUSE, data, offset),
        Value::TrackingAreaIdentity => push_tai_contents(buf, data, offset),
        Value::TrackingAreaIdentityList => push_tai_list(buf, data, offset),
        Value::LocationAreaIdentification => push_lai(buf, data, offset),
        Value::NasSecurityAlgorithms => push_nas_security_algorithms(buf, data, offset),
        Value::UeNetworkCapability => push_security_capability(buf, data, offset, false),
        Value::UeSecurityCapability => push_security_capability(buf, data, offset, true),
        Value::EsmMessageContainer => allow_esm && push_esm_message_container(buf, data, offset),
        Value::AccessPointName => {
            buf.push_field(&FD_APN, FieldValue::Bytes(data), offset..offset + data.len());
            true
        }
        Value::PdnAddress => push_pdn_address(buf, data, offset),
        Value::EpsQos => push_eps_qos(buf, data, offset),
        Value::GprsTimer => push_gprs_timer(buf, data, offset),
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
fn push_single(
    buf: &mut DissectBuffer<'_>,
    desc: &'static FieldDescriptor,
    data: &[u8],
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

/// EPS mobile identity contents (octet 3 onwards).
///
/// 3GPP TS 24.301, Section 9.9.3.12: the IMSI or IMEI digits
/// (Figure 9.9.3.12.2), or a GUTI of exactly 11 octets
/// (Figure 9.9.3.12.1).
fn push_eps_mobile_identity<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let Some(&octet3) = data.first() else {
        return false;
    };
    let identity_type = octet3 & 0x07;
    let first = offset..offset + 1;
    match identity_type {
        // GUTI: octets 3 to 13.
        6 => {
            if data.len() != 11 {
                return false;
            }
            buf.push_field(&FD_EPS_IDENTITY_TYPE, FieldValue::U8(6), first);
            push_plmn(buf, &data[1..4], offset + 1);
            buf.push_field(
                &FD_MME_GROUP_ID,
                FieldValue::U16(u16::from_be_bytes([data[4], data[5]])),
                offset + 4..offset + 6,
            );
            buf.push_field(
                &FD_MME_CODE,
                FieldValue::U8(data[6]),
                offset + 6..offset + 7,
            );
            let m_tmsi = u32::from_be_bytes([data[7], data[8], data[9], data[10]]);
            buf.push_field(&FD_M_TMSI, FieldValue::U32(m_tmsi), offset + 7..offset + 11);
            true
        }
        // IMSI or IMEI.
        1 | 3 => {
            push_identity_digits(buf, &FD_EPS_IDENTITY_TYPE, identity_type, data, offset);
            true
        }
        // "All other values are reserved."
        _ => false,
    }
}

/// Mobile identity contents (octet 3 onwards).
///
/// 3GPP TS 24.008, Section 10.5.1.4: digits for IMSI, IMEI and IMEISV
/// (Figure 10.5.4), a 4-octet TMSI/P-TMSI/M-TMSI (Figure 10.5.4a), or no
/// identity. The TMGI form is kept as raw bytes.
fn push_mobile_identity<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let Some(&octet3) = data.first() else {
        return false;
    };
    let identity_type = octet3 & 0x07;
    match identity_type {
        1..=3 => {
            push_identity_digits(buf, &FD_MOBILE_IDENTITY_TYPE, identity_type, data, offset);
            true
        }
        4 => {
            let &[_, a, b, c, d] = data else {
                return false;
            };
            buf.push_field(
                &FD_MOBILE_IDENTITY_TYPE,
                FieldValue::U8(4),
                offset..offset + 1,
            );
            buf.push_field(
                &FD_TMSI,
                FieldValue::U32(u32::from_be_bytes([a, b, c, d])),
                offset + 1..offset + 5,
            );
            true
        }
        0 => {
            buf.push_field(
                &FD_MOBILE_IDENTITY_TYPE,
                FieldValue::U8(0),
                offset..offset + 1,
            );
            true
        }
        _ => false,
    }
}

/// Push the type of identity, odd/even indication and digits of an
/// identity coded as in TS 24.008, Figure 10.5.4.
fn push_identity_digits<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    type_desc: &'static FieldDescriptor,
    identity_type: u8,
    data: &'pkt [u8],
    offset: usize,
) {
    let first = offset..offset + 1;
    buf.push_field(type_desc, FieldValue::U8(identity_type), first.clone());
    buf.push_field(&FD_ODD_EVEN, FieldValue::U8((data[0] >> 3) & 1), first);
    buf.push_field(
        &FD_IDENTITY_DIGITS,
        FieldValue::Bytes(data),
        offset..offset + data.len(),
    );
}

/// Tracking area identity value part: PLMN identity and a 2-octet TAC.
///
/// 3GPP TS 24.301, Section 9.9.3.32.
fn push_tai_contents<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.len() != 5 {
        return false;
    }
    push_plmn(buf, &data[..3], offset);
    buf.push_field(
        &FD_TAC,
        FieldValue::U16(u16::from_be_bytes([data[3], data[4]])),
        offset + 3..offset + 5,
    );
    true
}

/// Location area identification value part: PLMN identity and LAC.
///
/// 3GPP TS 24.008, Section 10.5.1.3.
fn push_lai<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.len() != 5 {
        return false;
    }
    push_plmn(buf, &data[..3], offset);
    buf.push_field(
        &FD_LAC,
        FieldValue::U16(u16::from_be_bytes([data[3], data[4]])),
        offset + 3..offset + 5,
    );
    true
}

/// Push one TAI object.
fn push_tai<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    plmn: &'pkt [u8],
    plmn_at: usize,
    tac: &[u8],
    tac_at: usize,
) {
    let tai = buf.begin_container(&FD_TAI, FieldValue::Object(0..0), plmn_at..tac_at + 2);
    buf.push_field(&TAI_CHILDREN[0], FieldValue::Bytes(plmn), plmn_at..plmn_at + 3);
    buf.push_field(&TAI_CHILDREN[1], FieldValue::Bytes(plmn), plmn_at..plmn_at + 3);
    buf.push_field(
        &TAI_CHILDREN[2],
        FieldValue::U16(u16::from_be_bytes([tac[0], tac[1]])),
        tac_at..tac_at + 2,
    );
    buf.end_container(tai);
}

/// Tracking area identity list value part.
///
/// 3GPP TS 24.301, Section 9.9.3.33, Table 9.9.3.33.1.
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
            0 => 1 + 3 + 2 * k,
            1 => 1 + 3 + 2,
            2 => 1 + 5 * k,
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
                    let t = p + 3 + 2 * j;
                    push_tai(buf, plmn, offset + p, &data[t..t + 2], offset + t);
                }
            }
            1 => {
                // "The TAC values of the other k-1 TAIs are TAC+1, TAC+2,
                // …, TAC+k-1": only the first TAI is carried.
                push_tai(
                    buf,
                    &data[p..p + 3],
                    offset + p,
                    &data[p + 3..p + 5],
                    offset + p + 3,
                );
            }
            _ => {
                for j in 0..k {
                    let t = p + 5 * j;
                    push_tai(
                        buf,
                        &data[t..t + 3],
                        offset + t,
                        &data[t + 3..t + 5],
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

/// NAS security algorithms value part (octet 2).
///
/// 3GPP TS 24.301, Section 9.9.3.23: ciphering algorithm in bits 5 to 7,
/// integrity protection algorithm in bits 1 to 3.
fn push_nas_security_algorithms(buf: &mut DissectBuffer<'_>, data: &[u8], offset: usize) -> bool {
    let &[v] = data else {
        return false;
    };
    let r = offset..offset + 1;
    buf.push_field(
        &FD_CIPHERING_ALGORITHM,
        FieldValue::U8((v >> 4) & 0x07),
        r.clone(),
    );
    buf.push_field(&FD_INTEGRITY_ALGORITHM, FieldValue::U8(v & 0x07), r);
    true
}

/// UE network capability or UE security capability value part.
///
/// 3GPP TS 24.301, Sections 9.9.3.34 and 9.9.3.36: octet 3 is the EPS
/// encryption algorithms (EEA0 in bit 8 ... EEA7 in bit 1), octet 4 the EPS
/// integrity algorithms, and the optional octets 5 and 6 the UMTS
/// encryption and integrity algorithms (UIA1 to UIA7 in bits 7 to 1 of
/// octet 6). Octet 7 of the UE security capability carries the GPRS
/// encryption algorithms (bits 7 to 1); the remaining octets of the UE
/// network capability are feature flags, kept as `additional_octets`.
fn push_security_capability<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    ue_security_capability: bool,
) -> bool {
    if data.len() < 2 {
        return false;
    }
    let mut fields: [(&'static FieldDescriptor, u8); 5] = [
        (&FD_EEA, 0xff),
        (&FD_EIA, 0xff),
        (&FD_UEA, 0xff),
        (&FD_UIA, 0x7f),
        (&FD_GEA, 0x7f),
    ];
    let known = if ue_security_capability { 5 } else { 4 };
    for (i, (desc, mask)) in fields.iter_mut().enumerate().take(known.min(data.len())) {
        buf.push_field(
            *desc,
            FieldValue::U8(data[i] & *mask),
            offset + i..offset + i + 1,
        );
    }
    if data.len() > known {
        buf.push_field(
            &FD_ADDITIONAL_OCTETS,
            FieldValue::Bytes(&data[known..]),
            offset + known..offset + data.len(),
        );
    }
    true
}

/// ESM message container value: a plain ESM message.
///
/// 3GPP TS 24.301, Section 9.9.3.15: "The ESM message included in this IE
/// shall be coded as specified in clause 8.3, i.e. without NAS security
/// header." An ESM message never carries another container, so the
/// nesting depth is bounded.
fn push_esm_message_container<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if !crate::is_esm_message(data) {
        return false;
    }
    let obj = buf.begin_container(
        &FD_ESM_MESSAGE,
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    crate::push_esm(buf, data, offset);
    buf.end_container(obj);
    true
}

/// PDN address value part.
///
/// 3GPP TS 24.301, Section 9.9.4.9, Table 9.9.4.9.1: IPv4 address (4
/// octets), IPv6 interface identifier (8 octets), or both (IID first).
fn push_pdn_address<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    let Some(&octet3) = data.first() else {
        return false;
    };
    let pdn_type = octet3 & 0x07;
    let addr = &data[1..];
    let a = offset + 1;
    let (iid, v4) = match (pdn_type, addr.len()) {
        (1, 4) => (None, Some(0)),
        (2, 8) => (Some(0), None),
        (3, 12) => (Some(0), Some(8)),
        // Non IP and Ethernet: octets 4 to 7 are spare.
        (5 | 6, 4) => (None, None),
        _ => return false,
    };
    buf.push_field(&FD_PDN_TYPE, FieldValue::U8(pdn_type), offset..offset + 1);
    if let Some(i) = iid {
        buf.push_field(
            &FD_IPV6_IID,
            FieldValue::Bytes(&addr[i..i + 8]),
            a + i..a + i + 8,
        );
    }
    if let Some(i) = v4 {
        buf.push_field(
            &FD_IPV4_ADDRESS,
            FieldValue::Ipv4Addr([addr[i], addr[i + 1], addr[i + 2], addr[i + 3]]),
            a + i..a + i + 4,
        );
    }
    true
}

/// EPS quality of service value part.
///
/// 3GPP TS 24.301, Section 9.9.4.3: octet 3 is the QCI; the optional
/// octets 4 onwards carry the bit rates, kept as raw octets.
fn push_eps_qos<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    let Some((&qci, rates)) = data.split_first() else {
        return false;
    };
    buf.push_field(&FD_QCI, FieldValue::U8(qci), offset..offset + 1);
    if !rates.is_empty() {
        buf.push_field(
            &FD_BIT_RATES,
            FieldValue::Bytes(rates),
            offset + 1..offset + data.len(),
        );
    }
    true
}

/// GPRS timer value part.
///
/// 3GPP TS 24.008, Section 10.5.7.3: unit in bits 6 to 8, timer value in
/// bits 1 to 5.
fn push_gprs_timer(buf: &mut DissectBuffer<'_>, data: &[u8], offset: usize) -> bool {
    let &[v] = data else {
        return false;
    };
    let r = offset..offset + 1;
    buf.push_field(&FD_TIMER_UNIT, FieldValue::U8(v >> 5), r.clone());
    buf.push_field(&FD_TIMER_VALUE, FieldValue::U8(v & 0x1f), r);
    true
}
