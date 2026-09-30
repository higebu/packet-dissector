//! SGsAP information elements.
//!
//! Every IE is an IEI octet, a one-octet length indicator and a value
//! (3GPP TS 29.118, Sections 9.3 and 9.3a). The value is decoded by IE
//! type; a type without a decoder, or a value whose length does not match
//! its coding, is kept as raw `value` octets.
//!
//! ## References
//! - 3GPP TS 29.118, Section 9.4:
//!   <https://www.3gpp.org/ftp/Specs/archive/29_series/29.118/>
//! - 3GPP TS 29.018, Section 18.4:
//!   <https://www.3gpp.org/ftp/Specs/archive/29_series/29.018/>
//! - 3GPP TS 24.008, Sections 10.5.1.3, 10.5.1.4, 10.5.4.9, 10.5.5.31:
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.008/>

use core::ops::Range;
use std::io::{self, Write};

use packet_dissector_core::field::{
    FieldDescriptor, FieldType, FieldValue, FormatContext, format_fqdn_labels,
};
use packet_dissector_core::packet::DissectBuffer;

// 3GPP TS 29.118, Section 9.3, Table 9.3.1 — IE identifiers.
const IE_IMSI: u8 = 1;
const IE_VLR_NAME: u8 = 2;
const IE_TMSI: u8 = 3;
const IE_LAI: u8 = 4;
const IE_CHANNEL_NEEDED: u8 = 5;
const IE_EMLPP_PRIORITY: u8 = 6;
const IE_TMSI_STATUS: u8 = 7;
const IE_SGS_CAUSE: u8 = 8;
const IE_MME_NAME: u8 = 9;
const IE_EPS_LOCATION_UPDATE_TYPE: u8 = 10;
const IE_GLOBAL_CN_ID: u8 = 11;
const IE_MOBILE_IDENTITY: u8 = 14;
const IE_REJECT_CAUSE: u8 = 15;
const IE_IMSI_DETACH_FROM_EPS: u8 = 16;
const IE_IMSI_DETACH_FROM_NON_EPS: u8 = 17;
const IE_IMEISV: u8 = 21;
const IE_NAS_MESSAGE_CONTAINER: u8 = 22;
const IE_ERRONEOUS_MESSAGE: u8 = 27;
const IE_CLI: u8 = 28;
const IE_LCS_INDICATOR: u8 = 30;
const IE_SS_CODE: u8 = 31;
const IE_SERVICE_INDICATOR: u8 = 32;
const IE_UE_TIME_ZONE: u8 = 33;
const IE_TAI: u8 = 35;
const IE_ECGI: u8 = 36;
const IE_UE_EMM_MODE: u8 = 37;
const IE_ADDITIONAL_PAGING_INDICATORS: u8 = 38;
const IE_TMSI_BASED_NRI_CONTAINER: u8 = 39;
const IE_SELECTED_CS_DOMAIN_OPERATOR: u8 = 40;
const IE_MAXIMUM_UE_AVAILABILITY_TIME: u8 = 41;
const IE_SM_DELIVERY_TIMER: u8 = 42;
const IE_SM_DELIVERY_START_TIME: u8 = 43;
const IE_ADDITIONAL_UE_UNREACHABLE_INDICATORS: u8 = 44;
const IE_MAXIMUM_RETRANSMISSION_TIME: u8 = 45;
const IE_REQUESTED_RETRANSMISSION_TIME: u8 = 46;

/// Returns the name of an SGsAP information element identifier.
///
/// 3GPP TS 29.118, Section 9.3, Table 9.3.1.
pub fn ie_type_name(ie_type: u8) -> Option<&'static str> {
    Some(match ie_type {
        IE_IMSI => "IMSI",
        IE_VLR_NAME => "VLR name",
        IE_TMSI => "TMSI",
        IE_LAI => "Location area identifier",
        IE_CHANNEL_NEEDED => "Channel Needed",
        IE_EMLPP_PRIORITY => "eMLPP Priority",
        IE_TMSI_STATUS => "TMSI status",
        IE_SGS_CAUSE => "SGs cause",
        IE_MME_NAME => "MME name",
        IE_EPS_LOCATION_UPDATE_TYPE => "EPS location update type",
        IE_GLOBAL_CN_ID => "Global CN-Id",
        IE_MOBILE_IDENTITY => "Mobile identity",
        IE_REJECT_CAUSE => "Reject cause",
        IE_IMSI_DETACH_FROM_EPS => "IMSI detach from EPS service type",
        IE_IMSI_DETACH_FROM_NON_EPS => "IMSI detach from non-EPS service type",
        IE_IMEISV => "IMEISV",
        IE_NAS_MESSAGE_CONTAINER => "NAS message container",
        23 => "MM information",
        IE_ERRONEOUS_MESSAGE => "Erroneous message",
        IE_CLI => "CLI",
        29 => "LCS client identity",
        IE_LCS_INDICATOR => "LCS indicator",
        IE_SS_CODE => "SS code",
        IE_SERVICE_INDICATOR => "Service indicator",
        IE_UE_TIME_ZONE => "UE Time Zone",
        34 => "Mobile Station Classmark 2",
        IE_TAI => "Tracking Area Identity",
        IE_ECGI => "E-UTRAN Cell Global Identity",
        IE_UE_EMM_MODE => "UE EMM mode",
        IE_ADDITIONAL_PAGING_INDICATORS => "Additional paging indicators",
        IE_TMSI_BASED_NRI_CONTAINER => "TMSI based NRI container",
        IE_SELECTED_CS_DOMAIN_OPERATOR => "Selected CS domain operator",
        IE_MAXIMUM_UE_AVAILABILITY_TIME => "Maximum UE Availability Time",
        IE_SM_DELIVERY_TIMER => "SM Delivery Timer",
        IE_SM_DELIVERY_START_TIME => "SM Delivery Start Time",
        IE_ADDITIONAL_UE_UNREACHABLE_INDICATORS => "Additional UE Unreachable indicators",
        IE_MAXIMUM_RETRANSMISSION_TIME => "Maximum Retransmission Time",
        IE_REQUESTED_RETRANSMISSION_TIME => "Requested Retransmission Time",
        _ => return None,
    })
}

/// 3GPP TS 29.118, Section 9.4.2, Table 9.4.2.1.
pub(crate) fn eps_location_update_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("IMSI attach"),
        2 => Some("Normal location update"),
        _ => None,
    }
}

/// 3GPP TS 29.118, Section 9.4.7, Table 9.4.7.1.
pub(crate) fn imsi_detach_from_eps_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Network initiated IMSI detach from EPS services"),
        2 => Some("UE initiated IMSI detach from EPS services"),
        3 => Some("EPS services not allowed"),
        _ => None,
    }
}

/// 3GPP TS 29.118, Section 9.4.8, Table 9.4.8.1.
pub(crate) fn imsi_detach_from_non_eps_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Explicit UE initiated IMSI detach from non-EPS services"),
        2 => Some("Combined UE initiated IMSI detach from EPS and non-EPS services"),
        3 => Some("Implicit network initiated IMSI detach from EPS and non-EPS services"),
        _ => None,
    }
}

/// 3GPP TS 29.118, Section 9.4.10, Table 9.4.10.1.
pub(crate) fn lcs_indicator_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("MT-LR"),
        _ => None,
    }
}

/// 3GPP TS 29.118, Section 9.4.17, Table 9.4.17.1.
pub(crate) fn service_indicator_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("CS call indicator"),
        2 => Some("SMS indicator"),
        _ => None,
    }
}

/// 3GPP TS 29.118, Section 9.4.18, Table 9.4.18.1. Values 15 to 255 are
/// "Normal, unspecified" and left unnamed.
pub(crate) fn sgs_cause_name(v: u8) -> Option<&'static str> {
    Some(match v {
        0 => "Normal, unspecified",
        1 => "IMSI detached for EPS services",
        2 => "IMSI detached for EPS and non-EPS services",
        3 => "IMSI unknown",
        4 => "IMSI detached for non-EPS services",
        5 => "IMSI implicitly detached for non-EPS services",
        6 => "UE unreachable",
        7 => "Message not compatible with the protocol state",
        8 => "Missing mandatory information element",
        9 => "Invalid mandatory information",
        10 => "Conditional information element error",
        11 => "Semantically incorrect message",
        12 => "Message unknown",
        13 => "Mobile terminating CS fallback call rejected by the user",
        14 => "UE temporarily unreachable",
        _ => return None,
    })
}

/// 3GPP TS 29.118, Section 9.4.21c, Table 9.4.21c.1.
pub(crate) fn ue_emm_mode_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("EMM-IDLE"),
        1 => Some("EMM-CONNECTED"),
        _ => None,
    }
}

/// 3GPP TS 24.008, Section 10.5.1.4, Table 10.5.4 — type of identity.
pub(crate) fn type_of_identity_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("No Identity"),
        1 => Some("IMSI"),
        2 => Some("IMEI"),
        3 => Some("IMEISV"),
        4 => Some("TMSI/P-TMSI/M-TMSI"),
        5 => Some("TMGI and optional MBMS Session Identity"),
        _ => None,
    }
}

/// Writes BCD digits as a JSON string, stopping at the "1111" end mark.
fn write_digits(w: &mut dyn Write, digits: impl Iterator<Item = u8>) -> io::Result<()> {
    w.write_all(b"\"")?;
    for d in digits {
        if d == 0x0F {
            break;
        }
        // Digits above 9 are not BCD; show them as hexadecimal so that they
        // stay visible.
        let c = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        w.write_all(&[c])?;
    }
    w.write_all(b"\"")
}

/// Low nibble first, as in TS 29.018, Section 18.4.9 and TS 24.008,
/// Section 10.5.4.9.
fn nibbles(data: &[u8]) -> impl Iterator<Item = u8> + '_ {
    data.iter().flat_map(|b| [b & 0x0F, b >> 4])
}

/// Formats BCD digits packed two per octet, the earlier digit in the low
/// nibble.
fn format_bcd(v: &FieldValue<'_>, _ctx: &FormatContext<'_>, w: &mut dyn Write) -> io::Result<()> {
    match v {
        FieldValue::Bytes(b) => write_digits(w, nibbles(b)),
        _ => w.write_all(b"\"\""),
    }
}

/// Formats an identity coded as the value part of the TS 24.008 Mobile
/// identity (Section 10.5.1.4) or the TS 29.018 IMSI (Section 18.4.10):
/// digit 1 in the high nibble of the first octet, whose low nibble holds
/// the odd/even indicator and the type of identity.
fn format_identity(
    v: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn Write,
) -> io::Result<()> {
    match v {
        FieldValue::Bytes([first, rest @ ..]) => {
            write_digits(w, core::iter::once(first >> 4).chain(nibbles(rest)))
        }
        _ => w.write_all(b"\"\""),
    }
}

/// Formats the MCC of a PLMN identity (TS 24.008, Section 10.5.1.3).
fn format_mcc(v: &FieldValue<'_>, _ctx: &FormatContext<'_>, w: &mut dyn Write) -> io::Result<()> {
    match v {
        FieldValue::Bytes([b0, b1, _]) => {
            write_digits(w, [b0 & 0x0F, b0 >> 4, b1 & 0x0F].into_iter())
        }
        _ => w.write_all(b"\"\""),
    }
}

/// Formats the MNC of a PLMN identity; MNC digit 3 is "1111" for a
/// two-digit MNC (TS 24.008, Section 10.5.1.3).
fn format_mnc(v: &FieldValue<'_>, _ctx: &FormatContext<'_>, w: &mut dyn Write) -> io::Result<()> {
    match v {
        FieldValue::Bytes([_, b1, b2]) => {
            write_digits(w, [b2 & 0x0F, b2 >> 4, b1 >> 4].into_iter())
        }
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

macro_rules! named {
    ($name:literal, $display:literal, $f:expr) => {
        FieldDescriptor::new($name, $display, FieldType::U8)
            .optional()
            .with_display_fn(|v, _| match v {
                FieldValue::U8(x) => $f(*x),
                _ => None,
            })
    };
}

macro_rules! plain {
    ($name:literal, $display:literal, $ty:ident) => {
        FieldDescriptor::new($name, $display, FieldType::$ty).optional()
    };
}

const FD_TYPE: usize = 0;
const FD_LENGTH: usize = 1;
const FD_VALUE: usize = 2;
const FD_IMSI: usize = 3;
const FD_NAME: usize = 4;
const FD_TMSI: usize = 5;
const FD_MCC: usize = 6;
const FD_MNC: usize = 7;
const FD_LAC: usize = 8;
const FD_TAC: usize = 9;
const FD_ECI: usize = 10;
const FD_CN_ID: usize = 11;
const FD_TMSI_FLAG: usize = 12;
const FD_SGS_CAUSE: usize = 13;
const FD_EPS_LOCATION_UPDATE_TYPE: usize = 14;
const FD_TYPE_OF_IDENTITY: usize = 15;
const FD_IDENTITY_DIGITS: usize = 16;
const FD_REJECT_CAUSE: usize = 17;
const FD_IMSI_DETACH_FROM_EPS: usize = 18;
const FD_IMSI_DETACH_FROM_NON_EPS: usize = 19;
const FD_IMEISV: usize = 20;
const FD_NAS_MESSAGE_CONTAINER: usize = 21;
const FD_SERVICE_INDICATOR: usize = 22;
const FD_UE_EMM_MODE: usize = 23;
const FD_LCS_INDICATOR: usize = 24;
const FD_CSRI: usize = 25;
const FD_SMBRI: usize = 26;
const FD_NRI_CONTAINER: usize = 27;
const FD_TYPE_OF_NUMBER: usize = 28;
const FD_NUMBERING_PLAN: usize = 29;
const FD_PRESENTATION_INDICATOR: usize = 30;
const FD_SCREENING_INDICATOR: usize = 31;
const FD_DIGITS: usize = 32;
const FD_ERRONEOUS_MESSAGE_TYPE: usize = 33;
const FD_CHANNEL_NEEDED: usize = 34;
const FD_EMLPP_PRIORITY: usize = 35;
const FD_SS_CODE: usize = 36;
const FD_UE_TIME_ZONE: usize = 37;
const FD_TIME: usize = 38;
const FD_SM_DELIVERY_TIMER: usize = 39;

/// Child fields of an IE object (the union over all decoded IE types).
pub(crate) static IE_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => ie_type_name(*t),
        _ => None,
    }),
    plain!("length", "Length", U8),
    plain!("value", "Value", Bytes),
    plain!("imsi", "IMSI", Bytes).with_format_fn(format_identity),
    plain!("name", "Name", Bytes).with_format_fn(format_fqdn_labels),
    plain!("tmsi", "TMSI", U32),
    plain!("mcc", "MCC", Bytes).with_format_fn(format_mcc),
    plain!("mnc", "MNC", Bytes).with_format_fn(format_mnc),
    plain!("lac", "LAC", U16),
    plain!("tac", "TAC", U16),
    plain!("eci", "E-UTRAN Cell Identifier", U32),
    plain!("cn_id", "CN-Id", U16),
    plain!("tmsi_flag", "TMSI Flag", U8),
    named!("sgs_cause", "SGs Cause", sgs_cause_name),
    named!(
        "eps_location_update_type",
        "EPS Location Update Type",
        eps_location_update_type_name
    ),
    named!(
        "type_of_identity",
        "Type of Identity",
        type_of_identity_name
    ),
    plain!("identity_digits", "Identity Digits", Bytes).with_format_fn(format_identity),
    plain!("reject_cause", "Reject Cause", U8),
    named!(
        "imsi_detach_from_eps_service_type",
        "IMSI Detach from EPS Service Type",
        imsi_detach_from_eps_name
    ),
    named!(
        "imsi_detach_from_non_eps_service_type",
        "IMSI Detach from non-EPS Service Type",
        imsi_detach_from_non_eps_name
    ),
    plain!("imeisv", "IMEISV", Bytes).with_format_fn(format_bcd),
    plain!("nas_message_container", "NAS Message Container", Bytes),
    named!(
        "service_indicator",
        "Service Indicator",
        service_indicator_name
    ),
    named!("ue_emm_mode", "UE EMM Mode", ue_emm_mode_name),
    named!("lcs_indicator", "LCS Indicator", lcs_indicator_name),
    plain!("csri", "CS Restoration Indicator", U8),
    plain!("smbri", "SM Buffer Request Indicator", U8),
    plain!("nri_container", "NRI Container Value", U16),
    plain!("type_of_number", "Type of Number", U8),
    plain!("numbering_plan", "Numbering Plan Identification", U8),
    plain!("presentation_indicator", "Presentation Indicator", U8),
    plain!("screening_indicator", "Screening Indicator", U8),
    plain!("digits", "Number Digits", Bytes).with_format_fn(format_bcd),
    named!(
        "erroneous_message_type",
        "Erroneous Message Type",
        crate::message_type_name
    ),
    plain!("channel_needed", "Channel Needed", U8),
    plain!("emlpp_priority", "eMLPP Priority", U8),
    plain!("ss_code", "SS Code", U8),
    plain!("ue_time_zone", "UE Time Zone", U8),
    plain!("time", "Time", U32),
    plain!("sm_delivery_timer", "SM Delivery Timer", U16),
];

/// Walks the IEs in `data` (the message after its message type); `base` is
/// the absolute offset of `data`.
///
/// An IE whose length indicator is missing or runs past the message ends
/// the walk; the octets after its identifier are kept as its raw `value`
/// (3GPP TS 29.118, Section 7.2).
pub(crate) fn parse_ies<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], base: usize) {
    let mut pos = 0;
    while pos < data.len() {
        let ie_type = data[pos];
        let start = base + pos;
        let obj = buf.begin_container(&FD_IE, FieldValue::Object(0..0), start..start);
        push(buf, FD_TYPE, FieldValue::U8(ie_type), start..start + 1);

        // Section 9.3a — one-octet length of the value part.
        let len = data.get(pos + 1).map(|&l| usize::from(l));
        let Some(len) = len.filter(|len| pos + 2 + len <= data.len()) else {
            if pos + 1 < data.len() {
                push_raw(buf, &data[pos + 1..], start + 1);
            }
            close(buf, obj, start..base + data.len());
            break;
        };
        push(
            buf,
            FD_LENGTH,
            FieldValue::U8(len as u8),
            start + 1..start + 2,
        );
        let end = pos + 2 + len;
        push_ie_value(buf, ie_type, &data[pos + 2..end], start + 2);
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

fn push_bytes<'pkt>(buf: &mut DissectBuffer<'pkt>, fd: usize, v: &'pkt [u8], off: usize) -> bool {
    push(buf, fd, FieldValue::Bytes(v), off..off + v.len());
    true
}

/// Pushes a one-octet value, masked with `mask`.
fn push_u8(buf: &mut DissectBuffer<'_>, fd: usize, v: &[u8], off: usize, mask: u8) -> bool {
    let &[x] = v else { return false };
    push(buf, fd, FieldValue::U8(x & mask), off..off + 1);
    true
}

fn push_u16(buf: &mut DissectBuffer<'_>, fd: usize, v: &[u8], off: usize) -> bool {
    let &[a, b] = v else { return false };
    push(
        buf,
        fd,
        FieldValue::U16(u16::from_be_bytes([a, b])),
        off..off + 2,
    );
    true
}

fn push_u32(buf: &mut DissectBuffer<'_>, fd: usize, v: &[u8], off: usize) -> bool {
    let &[a, b, c, d] = v else { return false };
    push(
        buf,
        fd,
        FieldValue::U32(u32::from_be_bytes([a, b, c, d])),
        off..off + 4,
    );
    true
}

/// Pushes the MCC and MNC of a three-octet PLMN identity at `v[..3]`.
fn push_plmn<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], off: usize) {
    push(buf, FD_MCC, FieldValue::Bytes(&v[..3]), off..off + 3);
    push(buf, FD_MNC, FieldValue::Bytes(&v[..3]), off..off + 3);
}

/// Pushes the decoded value of one IE, or its raw octets when the IE has
/// no decoder or the value does not match its coding.
fn push_ie_value<'pkt>(buf: &mut DissectBuffer<'pkt>, ie_type: u8, v: &'pkt [u8], off: usize) {
    let decoded = match ie_type {
        // TS 29.018, Section 18.4.10.
        IE_IMSI => !v.is_empty() && push_bytes(buf, FD_IMSI, v, off),
        // TS 29.118, Sections 9.4.13 and 9.4.22 — FQDN labels.
        IE_VLR_NAME | IE_MME_NAME => push_bytes(buf, FD_NAME, v, off),
        // TS 29.018, Section 18.4.23.
        IE_TMSI => push_u32(buf, FD_TMSI, v, off),
        IE_LAI => push_lai(buf, v, off),
        // TS 29.018, Sections 18.4.2 and 18.4.4 — carried as in TS 44.018
        // and TS 48.008.
        IE_CHANNEL_NEEDED => push_u8(buf, FD_CHANNEL_NEEDED, v, off, 0xFF),
        IE_EMLPP_PRIORITY => push_u8(buf, FD_EMLPP_PRIORITY, v, off, 0xFF),
        // TS 29.018, Section 18.4.24 — the TMSI flag is bit 1.
        IE_TMSI_STATUS => push_u8(buf, FD_TMSI_FLAG, v, off, 0x01),
        IE_SGS_CAUSE => push_u8(buf, FD_SGS_CAUSE, v, off, 0xFF),
        IE_EPS_LOCATION_UPDATE_TYPE => push_u8(buf, FD_EPS_LOCATION_UPDATE_TYPE, v, off, 0xFF),
        IE_GLOBAL_CN_ID => push_global_cn_id(buf, v, off),
        IE_MOBILE_IDENTITY => push_mobile_identity(buf, v, off),
        // TS 29.018, Section 18.4.21 — the TS 24.008 reject cause value.
        IE_REJECT_CAUSE => push_u8(buf, FD_REJECT_CAUSE, v, off, 0xFF),
        IE_IMSI_DETACH_FROM_EPS => push_u8(buf, FD_IMSI_DETACH_FROM_EPS, v, off, 0xFF),
        IE_IMSI_DETACH_FROM_NON_EPS => push_u8(buf, FD_IMSI_DETACH_FROM_NON_EPS, v, off, 0xFF),
        // TS 29.018, Section 18.4.9 — 16 BCD digits.
        IE_IMEISV => v.len() == 8 && push_bytes(buf, FD_IMEISV, v, off),
        // TS 29.118, Section 9.4.15 — an SMS CP message (CP-DATA, CP-ACK
        // or CP-ERROR, TS 24.011, Section 7.2), not an EPS NAS message.
        IE_NAS_MESSAGE_CONTAINER => push_bytes(buf, FD_NAS_MESSAGE_CONTAINER, v, off),
        IE_ERRONEOUS_MESSAGE => push_erroneous_message(buf, v, off),
        IE_CLI => push_cli(buf, v, off),
        IE_LCS_INDICATOR => push_u8(buf, FD_LCS_INDICATOR, v, off, 0xFF),
        // TS 29.118, Section 9.4.19 — SS-Code of TS 29.002.
        IE_SS_CODE => push_u8(buf, FD_SS_CODE, v, off, 0xFF),
        IE_SERVICE_INDICATOR => push_u8(buf, FD_SERVICE_INDICATOR, v, off, 0xFF),
        // TS 29.118, Section 9.4.21b — Time Zone of TS 24.008, Section
        // 10.5.3.8.
        IE_UE_TIME_ZONE => push_u8(buf, FD_UE_TIME_ZONE, v, off, 0xFF),
        // TS 29.118, Section 9.4.21a — the TS 24.301 TAI value part.
        IE_TAI => push_tai(buf, v, off),
        IE_ECGI => push_ecgi(buf, v, off),
        IE_UE_EMM_MODE => push_u8(buf, FD_UE_EMM_MODE, v, off, 0xFF),
        // TS 29.118, Sections 9.4.25 and 9.4.31 — the flag is bit 1.
        IE_ADDITIONAL_PAGING_INDICATORS => push_u8(buf, FD_CSRI, v, off, 0x01),
        IE_ADDITIONAL_UE_UNREACHABLE_INDICATORS => push_u8(buf, FD_SMBRI, v, off, 0x01),
        IE_TMSI_BASED_NRI_CONTAINER => push_nri_container(buf, v, off),
        // TS 29.118, Section 9.4.27 — octets 2 to 4 of the TS 24.008 LAI.
        IE_SELECTED_CS_DOMAIN_OPERATOR => {
            v.len() == 3 && {
                push_plmn(buf, v, off);
                true
            }
        }
        // TS 29.118, Sections 9.4.28, 9.4.30, 9.4.32, 9.4.33 — four-octet
        // times of TS 29.002.
        IE_MAXIMUM_UE_AVAILABILITY_TIME
        | IE_SM_DELIVERY_START_TIME
        | IE_MAXIMUM_RETRANSMISSION_TIME
        | IE_REQUESTED_RETRANSMISSION_TIME => push_u32(buf, FD_TIME, v, off),
        // TS 29.118, Section 9.4.29 — two octets.
        IE_SM_DELIVERY_TIMER => push_u16(buf, FD_SM_DELIVERY_TIMER, v, off),
        _ => false,
    };
    if !decoded {
        push_raw(buf, v, off);
    }
}

/// TS 29.118, Section 9.4.11 — the TS 24.008 Location area identification
/// value part (Section 10.5.1.3): PLMN identity and a two-octet LAC.
fn push_lai<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], off: usize) -> bool {
    let &[_, _, _, a, b] = v else { return false };
    push_plmn(buf, v, off);
    push(
        buf,
        FD_LAC,
        FieldValue::U16(u16::from_be_bytes([a, b])),
        off + 3..off + 5,
    );
    true
}

/// TS 24.301, Section 9.9.3.32 — PLMN identity and a two-octet TAC.
fn push_tai<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], off: usize) -> bool {
    let &[_, _, _, a, b] = v else { return false };
    push_plmn(buf, v, off);
    push(
        buf,
        FD_TAC,
        FieldValue::U16(u16::from_be_bytes([a, b])),
        off + 3..off + 5,
    );
    true
}

/// TS 29.118, Section 9.4.3a — the ECGI of TS 29.274, Section 8.21.5: PLMN
/// identity, four spare bits and a 28-bit E-UTRAN Cell Identifier.
fn push_ecgi<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], off: usize) -> bool {
    let &[_, _, _, a, b, c, d] = v else {
        return false;
    };
    push_plmn(buf, v, off);
    let eci = u32::from_be_bytes([a, b, c, d]) & 0x0FFF_FFFF;
    push(buf, FD_ECI, FieldValue::U32(eci), off + 3..off + 7);
    true
}

/// TS 29.018, Section 18.4.27 — PLMN identity and a CN-Id (0..4095) in
/// octets 6 and 7.
fn push_global_cn_id<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], off: usize) -> bool {
    let &[_, _, _, a, b] = v else { return false };
    push_plmn(buf, v, off);
    let cn_id = u16::from_be_bytes([a, b]) & 0x0FFF;
    push(buf, FD_CN_ID, FieldValue::U16(cn_id), off + 3..off + 5);
    true
}

/// TS 29.018, Section 18.4.28 — the TS 24.008 Network resource identifier
/// container value (Section 10.5.5.31): ten bits, octet 3 then bits 8-7 of
/// octet 4.
fn push_nri_container(buf: &mut DissectBuffer<'_>, v: &[u8], off: usize) -> bool {
    let &[a, b] = v else { return false };
    let nri = (u16::from(a) << 2) | u16::from(b >> 6);
    push(buf, FD_NRI_CONTAINER, FieldValue::U16(nri), off..off + 2);
    true
}

/// TS 29.018, Section 18.4.17 — the TS 24.008 Mobile identity value part
/// (Section 10.5.1.4): type of identity in bits 3-1 of the first octet,
/// then BCD digits (IMSI, IMEI, IMEISV) or a four-octet TMSI.
fn push_mobile_identity<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], off: usize) -> bool {
    let Some(&first) = v.first() else {
        return false;
    };
    let identity_type = first & 0x07;
    match (identity_type, v) {
        (1..=3, _) => {
            push(
                buf,
                FD_TYPE_OF_IDENTITY,
                FieldValue::U8(identity_type),
                off..off + 1,
            );
            push_bytes(buf, FD_IDENTITY_DIGITS, v, off)
        }
        (4, &[_, a, b, c, d]) => {
            push(
                buf,
                FD_TYPE_OF_IDENTITY,
                FieldValue::U8(identity_type),
                off..off + 1,
            );
            let tmsi = u32::from_be_bytes([a, b, c, d]);
            push(buf, FD_TMSI, FieldValue::U32(tmsi), off + 1..off + 5);
            true
        }
        (4, _) => false,
        _ => {
            push(
                buf,
                FD_TYPE_OF_IDENTITY,
                FieldValue::U8(identity_type),
                off..off + 1,
            );
            if v.len() > 1 {
                push_raw(buf, &v[1..], off + 1);
            }
            true
        }
    }
}

/// TS 29.018, Section 18.4.5 — the erroneous message, starting with its
/// message type; kept whole as `value`.
fn push_erroneous_message<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], off: usize) -> bool {
    let Some(&message_type) = v.first() else {
        return false;
    };
    push(
        buf,
        FD_ERRONEOUS_MESSAGE_TYPE,
        FieldValue::U8(message_type),
        off..off + 1,
    );
    push_raw(buf, v, off);
    true
}

/// TS 29.118, Section 9.4.1 — the value part of the TS 24.008 Calling
/// party BCD number (Section 10.5.4.9): octet 3 (extension bit, type of
/// number, numbering plan), octet 3a when the extension bit is 0
/// (presentation and screening indicators), then the digits.
fn push_cli<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], off: usize) -> bool {
    let Some(&octet3) = v.first() else {
        return false;
    };
    push(
        buf,
        FD_TYPE_OF_NUMBER,
        FieldValue::U8((octet3 >> 4) & 0x07),
        off..off + 1,
    );
    push(
        buf,
        FD_NUMBERING_PLAN,
        FieldValue::U8(octet3 & 0x0F),
        off..off + 1,
    );
    let mut pos = 1;
    if octet3 & 0x80 == 0 {
        if let Some(&octet3a) = v.get(1) {
            push(
                buf,
                FD_PRESENTATION_INDICATOR,
                FieldValue::U8((octet3a >> 5) & 0x03),
                off + 1..off + 2,
            );
            push(
                buf,
                FD_SCREENING_INDICATOR,
                FieldValue::U8(octet3a & 0x03),
                off + 1..off + 2,
            );
            pos = 2;
        }
    }
    if pos < v.len() {
        push_bytes(buf, FD_DIGITS, &v[pos..], off + pos);
    }
    true
}
