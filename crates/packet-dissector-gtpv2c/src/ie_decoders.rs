//! Additional GTPv2-C IE value decoders.
//!
//! ## References
//! - 3GPP TS 29.274 v19.6.0, Section 8: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.274/>
//! - 3GPP TS 24.008, Section 10.5.1.13 (PLMN identity), 10.5.6.13 (TMGI):
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.008/>

use core::ops::Range;

use crate::ie_parsers;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, MacAddr};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{
    read_be_u16, read_be_u24, read_be_u32, read_be_u64, read_ipv4_addr, read_ipv6_addr,
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Push the whole value as raw bytes (used when a value is malformed).
fn push_raw<'pkt>(
    data: &'pkt [u8],
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    buf.push_field(value_desc, FieldValue::Bytes(data), value_range.clone());
}

/// Open the value Object container.
fn begin(
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'_>,
) -> u32 {
    buf.begin_container(value_desc, FieldValue::Object(0..0), value_range.clone())
}

fn u8f(buf: &mut DissectBuffer<'_>, fd: &'static FieldDescriptor, v: u8, at: usize) {
    buf.push_field(fd, FieldValue::U8(v), at..at + 1);
}

fn u16f(buf: &mut DissectBuffer<'_>, fd: &'static FieldDescriptor, v: u16, r: Range<usize>) {
    buf.push_field(fd, FieldValue::U16(v), r);
}

fn u32f(buf: &mut DissectBuffer<'_>, fd: &'static FieldDescriptor, v: u32, r: Range<usize>) {
    buf.push_field(fd, FieldValue::U32(v), r);
}

fn bytes<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: &'static FieldDescriptor,
    v: &'pkt [u8],
    at: usize,
) {
    buf.push_field(fd, FieldValue::Bytes(v), at..at + v.len());
}

/// PLMN identity coded as in 3GPP TS 24.008, Figure 10.5.13.
fn push_plmn(buf: &mut DissectBuffer<'_>, p: &[u8], at: usize) {
    ie_parsers::push_plmn_fields(p, at, 3, buf);
}

/// PLMN ID coded as in 3GPP TS 29.274, Figures 8.50-2 / 8.50-3 (the
/// TS 36.413 order): with a 3-digit MNC octet 2 carries MNC digit 1 in its
/// high nibble and octet 3 carries MNC digit 3 | MNC digit 2; with a 2-digit
/// MNC octet 2's high nibble is "1111" and octet 3 is MNC digit 2 | digit 1.
fn push_plmn_s1ap(buf: &mut DissectBuffer<'_>, p: &[u8], at: usize) {
    let mcc = [p[0] & 0x0F, p[0] >> 4, p[1] & 0x0F];
    let mnc = if p[1] >> 4 == 0x0F {
        [p[2] & 0x0F, p[2] >> 4, 0x0F]
    } else {
        [p[1] >> 4, p[2] & 0x0F, p[2] >> 4]
    };
    ie_parsers::push_mcc_mnc(buf, mcc, mnc, at..at + 3);
}

/// One bit flag of a flags IE: octet index within the value, bit mask.
struct Flag {
    octet: usize,
    mask: u8,
    fd: FieldDescriptor,
}

const fn flag(octet: usize, bit: u8, name: &'static str, display: &'static str) -> Flag {
    Flag {
        octet,
        mask: 1 << (bit - 1),
        fd: FieldDescriptor::new(name, display, FieldType::U8),
    }
}

static FD_ADDITIONAL_OCTETS: FieldDescriptor =
    FieldDescriptor::new("additional_octets", "Additional Octets", FieldType::Bytes);

/// Push every flag whose octet is present, then any octets past the last
/// defined one ("These octet(s) is/are present only if explicitly
/// specified") as raw bytes.
fn push_flags<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    flags: &'static [Flag],
    defined_octets: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.is_empty() {
        push_raw(data, value_desc, value_range, buf);
        return;
    }
    let obj = begin(value_desc, value_range, buf);
    for f in flags.iter().filter(|f| f.octet < data.len()) {
        u8f(
            buf,
            &f.fd,
            u8::from(data[f.octet] & f.mask != 0),
            offset + f.octet,
        );
    }
    if data.len() > defined_octets {
        bytes(
            buf,
            &FD_ADDITIONAL_OCTETS,
            &data[defined_octets..],
            offset + defined_octets,
        );
    }
    buf.end_container(obj);
}

// ---------------------------------------------------------------------------
// 8.12 Indication, 8.83 Node Features
// ---------------------------------------------------------------------------

/// 3GPP TS 29.274, Section 8.12, Figure 8.12-1 — octets 5 to 14.
static INDICATION_FLAGS: &[Flag] = &[
    flag(0, 8, "daf", "DAF (Dual Address Bearer Flag)"),
    flag(0, 7, "dtf", "DTF (Direct Tunnel Flag)"),
    flag(0, 6, "hi", "HI (Handover Indication)"),
    flag(0, 5, "dfi", "DFI (Direct Forwarding Indication)"),
    flag(0, 4, "oi", "OI (Operation Indication)"),
    flag(
        0,
        3,
        "isrsi",
        "ISRSI (Idle mode Signalling Reduction Supported Indication)",
    ),
    flag(
        0,
        2,
        "israi",
        "ISRAI (Idle mode Signalling Reduction Activation Indication)",
    ),
    flag(0, 1, "sgwci", "SGWCI (SGW Change Indication)"),
    flag(1, 8, "sqci", "SQCI (Subscribed QoS Change Indication)"),
    flag(1, 7, "uimsi", "UIMSI (Unauthenticated IMSI)"),
    flag(1, 6, "cfsi", "CFSI (Change F-TEID support indication)"),
    flag(1, 5, "crsi", "CRSI (Change Reporting support indication)"),
    flag(1, 4, "ps", "P (Piggybacking Supported)"),
    flag(1, 3, "pt", "PT (S5/S8 Protocol Type)"),
    flag(1, 2, "si", "SI (Scope Indication)"),
    flag(1, 1, "msv", "MSV (MS Validated)"),
    flag(2, 8, "retloc", "RetLoc (Retrieve Location Indication Flag)"),
    flag(2, 7, "pbic", "PBIC (Propagate BBAI Information Change)"),
    flag(2, 6, "srni", "SRNI (SGW Restoration Needed Indication)"),
    flag(2, 5, "s6af", "S6AF (Static IPv6 Address Flag)"),
    flag(2, 4, "s4af", "S4AF (Static IPv4 Address Flag)"),
    flag(2, 3, "mbmdt", "MBMDT (Management Based MDT allowed flag)"),
    flag(2, 2, "israu", "ISRAU (ISR is activated for the UE)"),
    flag(
        2,
        1,
        "ccrsi",
        "CCRSI (CSG Change Reporting support indication)",
    ),
    flag(3, 8, "cprai", "CPRAI"),
    flag(3, 7, "arrl", "ARRL"),
    flag(3, 6, "ppof", "PPOF"),
    flag(3, 5, "ppon_ppei", "PPON/PPEI"),
    flag(3, 4, "ppsi", "PPSI"),
    flag(3, 3, "csfbi", "CSFBI"),
    flag(3, 2, "clii", "CLII"),
    flag(3, 1, "cpsr", "CPSR"),
    flag(4, 8, "nsi", "NSI"),
    flag(4, 7, "uasi", "UASI"),
    flag(4, 6, "dtci", "DTCI"),
    flag(4, 5, "bdwi", "BDWI"),
    flag(4, 4, "psci", "PSCI"),
    flag(4, 3, "pcri", "PCRI"),
    flag(4, 2, "aosi", "AOSI"),
    flag(4, 1, "aopi", "AOPI"),
    flag(5, 8, "roaai", "ROAAI"),
    flag(5, 7, "epcosi", "EPCOSI"),
    flag(5, 6, "cpopci", "CPOPCI"),
    flag(5, 5, "pmtsmi", "PMTSMI"),
    flag(5, 4, "s11tf", "S11TF"),
    flag(5, 3, "pnsi", "PNSI"),
    flag(5, 2, "unaccsi", "UNACCSI"),
    flag(5, 1, "wpmsi", "WPMSI"),
    flag(6, 8, "n5gsnn26", "5GSNN26"),
    flag(6, 7, "reprefi", "REPREFI"),
    flag(6, 6, "n5gsiwk", "5GSIWK"),
    flag(6, 5, "eevrsi", "EEVRSI"),
    flag(6, 4, "ltemui", "LTEMUI"),
    flag(6, 3, "ltempi", "LTEMPI"),
    flag(6, 2, "enbcrsi", "ENBCRSI"),
    flag(6, 1, "tspcmi", "TSPCMI"),
    flag(7, 8, "csrmfi", "CSRMFI"),
    flag(7, 7, "mtedtn", "MTEDTN"),
    flag(7, 6, "mtedta", "MTEDTA"),
    flag(7, 5, "n5gnmi", "N5GNMI"),
    flag(7, 4, "n5gcnrs", "5GCNRS"),
    flag(7, 3, "n5gcnri", "5GCNRI"),
    flag(7, 2, "n5srhoi", "5SRHOI"),
    flag(7, 1, "ethpdn", "ETHPDN"),
    flag(8, 8, "nspusi", "NSPUSI"),
    flag(8, 7, "pgwrnsi", "PGWRNSI"),
    flag(8, 6, "rppcsi", "RPPCSI"),
    flag(8, 5, "pgwchi", "PGWCHI"),
    flag(8, 4, "sissme", "SISSME"),
    flag(8, 3, "nsenbi", "NSENBI"),
    flag(8, 2, "idfupf", "IDFUPF"),
    flag(8, 1, "emci", "EMCI"),
    // Octet 14: bits 8 and 7 are spare.
    flag(9, 6, "disrei", "DISREI"),
    flag(9, 5, "ppri", "PPRI"),
    flag(9, 4, "lapcosi", "LAPCOSI"),
    flag(9, 3, "ltemsai", "LTEMSAI"),
    flag(9, 2, "srtpi", "SRTPI"),
    flag(9, 1, "upipsi", "UPIPSI"),
];

/// 3GPP TS 29.274, Section 8.83, Table 8.83-1 — Supported-Features octet 5.
static NODE_FEATURES_FLAGS: &[Flag] = &[
    flag(0, 1, "prn", "PRN (PGW Restart Notification)"),
    flag(0, 2, "mabr", "MABR (Modify Access Bearers Request)"),
    flag(0, 3, "ntsr", "NTSR (Network Triggered Service Restoration)"),
    flag(0, 4, "ciot", "CIOT (Cellular Internet Of Things)"),
    flag(0, 5, "s1un", "S1UN (S1-U path failure notification)"),
    flag(0, 6, "eth", "ETH (Ethernet PDN type)"),
    flag(0, 7, "mtedt", "MTEDT (Support of MT-EDT)"),
    flag(0, 8, "psset", "PSSET (Support of PGW-C/SMF Set)"),
];

/// 3GPP TS 29.274, Section 8.12 — Indication.
pub(crate) fn push_indication<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    push_flags(
        data,
        offset,
        INDICATION_FLAGS,
        10,
        value_desc,
        value_range,
        buf,
    );
}

/// 3GPP TS 29.274, Section 8.83 — Node Features.
pub(crate) fn push_node_features<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    push_flags(
        data,
        offset,
        NODE_FEATURES_FLAGS,
        1,
        value_desc,
        value_range,
        buf,
    );
}

// ---------------------------------------------------------------------------
// Enumerated single-octet IEs
// ---------------------------------------------------------------------------

/// 3GPP TS 29.274, Table 8.61-1 — Action values.
fn change_reporting_action_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Stop Reporting"),
        1 => Some("Start Reporting CGI/SAI"),
        2 => Some("Start Reporting RAI"),
        3 => Some("Start Reporting TAI"),
        4 => Some("Start Reporting ECGI"),
        5 => Some("Start Reporting CGI/SAI and RAI"),
        6 => Some("Start Reporting TAI and ECGI"),
        7 => Some("Start Reporting Macro eNodeB ID and Extended Macro eNodeB ID"),
        8 => Some("Start Reporting TAI, Macro eNodeB ID and Extended Macro eNodeB ID"),
        _ => None,
    }
}

/// 3GPP TS 29.274, Table 8.81-1 — Detach Type values.
fn detach_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("PS Detach"),
        2 => Some("Combined PS/CS Detach"),
        _ => None,
    }
}

static FD_ACTION: FieldDescriptor = FieldDescriptor::new("action", "Action", FieldType::U8)
    .with_display_fn(|v, _| match v {
        FieldValue::U8(a) => change_reporting_action_name(*a),
        _ => None,
    });
static FD_DETACH_TYPE: FieldDescriptor =
    FieldDescriptor::new("detach_type", "Detach Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => detach_type_name(*t),
            _ => None,
        },
    );

/// 3GPP TS 29.274, Section 8.61 — Change Reporting Action.
pub(crate) fn push_change_reporting_action<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    ie_parsers::push_single_u8(data, offset, &FD_ACTION, 0xFF, value_desc, value_range, buf);
}

/// 3GPP TS 29.274, Section 8.81 — Detach Type.
pub(crate) fn push_detach_type<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    ie_parsers::push_single_u8(
        data,
        offset,
        &FD_DETACH_TYPE,
        0xFF,
        value_desc,
        value_range,
        buf,
    );
}

// ---------------------------------------------------------------------------
// 8.23 TMSI, 8.41 P-TMSI, 8.42 P-TMSI Signature
// ---------------------------------------------------------------------------

static FD_TMSI: FieldDescriptor = FieldDescriptor::new("tmsi", "TMSI", FieldType::U32);
static FD_P_TMSI: FieldDescriptor = FieldDescriptor::new("p_tmsi", "P-TMSI", FieldType::U32);
static FD_P_TMSI_SIGNATURE: FieldDescriptor =
    FieldDescriptor::new("p_tmsi_signature", "P-TMSI Signature", FieldType::U32);

/// Push a TMSI-like identity as a U32 when it has the expected size.
///
/// The TMSI and P-TMSI are 4 octets (3GPP TS 23.003, Sections 2.4 and
/// 2.6); the P-TMSI signature is 3 octets (3GPP TS 24.008, Section
/// 10.5.5.8).
pub(crate) fn push_tmsi<'pkt>(
    ie_type: u8,
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    let (fd, v) = match (ie_type, data.len()) {
        (88, 4) => (&FD_TMSI, read_be_u32(data, 0)),
        (111, 4) => (&FD_P_TMSI, read_be_u32(data, 0)),
        (112, 3) => (&FD_P_TMSI_SIGNATURE, read_be_u24(data, 0)),
        _ => {
            push_raw(data, value_desc, value_range, buf);
            return;
        }
    };
    let obj = begin(value_desc, value_range, buf);
    if let Ok(v) = v {
        u32f(buf, fd, v, offset..offset + data.len());
    }
    buf.end_container(obj);
}

// ---------------------------------------------------------------------------
// 8.46 Complete Request Message, 8.48 F-Container, 8.49 F-Cause
// ---------------------------------------------------------------------------

/// 3GPP TS 29.274, Table 8.46-1.
fn complete_request_message_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Complete Attach Request Message"),
        1 => Some("Complete TAU Request Message"),
        _ => None,
    }
}

/// 3GPP TS 29.274, Table 8.48-2 — Container Type values.
fn container_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("UTRAN Transparent Container"),
        2 => Some("BSS Container"),
        3 => Some("E-UTRAN Transparent Container"),
        4 => Some("NBIFOM Container"),
        5 => Some("EN-DC Container"),
        6 => Some("Inter-System SON Container"),
        _ => None,
    }
}

/// 3GPP TS 29.274, Tables 8.49-1 and 8.103-1 — Cause Type values.
fn ran_cause_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Radio Network Layer"),
        1 => Some("Transport Layer"),
        2 => Some("NAS"),
        3 => Some("Protocol"),
        4 => Some("Miscellaneous"),
        _ => None,
    }
}

static FD_CRM_TYPE: FieldDescriptor = FieldDescriptor::new(
    "message_type",
    "Complete Request Message Type",
    FieldType::U8,
)
.with_display_fn(|v, _| match v {
    FieldValue::U8(t) => complete_request_message_type_name(*t),
    _ => None,
});
static FD_CRM_MESSAGE: FieldDescriptor =
    FieldDescriptor::new("message", "Complete Request Message", FieldType::Bytes);
static FD_CONTAINER_TYPE: FieldDescriptor =
    FieldDescriptor::new("container_type", "Container Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => container_type_name(*t),
            _ => None,
        },
    );
static FD_CONTAINER: FieldDescriptor =
    FieldDescriptor::new("container", "F-Container", FieldType::Bytes);
static FD_CAUSE_TYPE: FieldDescriptor =
    FieldDescriptor::new("cause_type", "Cause Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => ran_cause_type_name(*t),
            _ => None,
        },
    );
/// F-Cause Cause Type: only meaningful for S1-AP causes, which the IE
/// instance selects (3GPP TS 29.274, Section 8.49), so no name is resolved.
static FD_F_CAUSE_TYPE: FieldDescriptor =
    FieldDescriptor::new("cause_type", "Cause Type", FieldType::U8);
static FD_CAUSE_VALUE: FieldDescriptor =
    FieldDescriptor::new("cause_value", "Cause Value", FieldType::U16);
static FD_F_CAUSE: FieldDescriptor = FieldDescriptor::new("f_cause", "F-Cause", FieldType::Bytes);
static FD_CAUSE_VALUE_RAW: FieldDescriptor =
    FieldDescriptor::new("cause_value_raw", "Cause Value", FieldType::Bytes);

/// Push "octet 5 = type, octets 6.. = payload" IEs.
fn push_typed_payload<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    (type_fd, type_mask): (&'static FieldDescriptor, u8),
    payload_fd: &'static FieldDescriptor,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    let Some(&t) = data.first() else {
        push_raw(data, value_desc, value_range, buf);
        return;
    };
    let obj = begin(value_desc, value_range, buf);
    u8f(buf, type_fd, t & type_mask, offset);
    bytes(buf, payload_fd, &data[1..], offset + 1);
    buf.end_container(obj);
}

/// 3GPP TS 29.274, Section 8.46 — Complete Request Message. The EPS NAS
/// message is kept as raw bytes.
pub(crate) fn push_complete_request_message<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    push_typed_payload(
        data,
        offset,
        (&FD_CRM_TYPE, 0xFF),
        &FD_CRM_MESSAGE,
        value_desc,
        value_range,
        buf,
    );
}

/// 3GPP TS 29.274, Section 8.48 — F-Container: octet 5 bits 4-1 carry the
/// Container Type.
pub(crate) fn push_f_container<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    push_typed_payload(
        data,
        offset,
        (&FD_CONTAINER_TYPE, 0x0F),
        &FD_CONTAINER,
        value_desc,
        value_range,
        buf,
    );
}

/// 3GPP TS 29.274, Section 8.49 — F-Cause. The F-Cause field is one octet
/// (BSSGP, S1-AP) or two octets (RANAP) as a binary integer.
pub(crate) fn push_f_cause<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    let Some(&t) = data.first() else {
        push_raw(data, value_desc, value_range, buf);
        return;
    };
    let obj = begin(value_desc, value_range, buf);
    u8f(buf, &FD_F_CAUSE_TYPE, t & 0x0F, offset);
    push_cause_value(&data[1..], offset + 1, &FD_F_CAUSE, buf);
    buf.end_container(obj);
}

/// Push a 1- or 2-octet binary cause value; other lengths stay raw.
fn push_cause_value<'pkt>(
    v: &'pkt [u8],
    at: usize,
    raw_fd: &'static FieldDescriptor,
    buf: &mut DissectBuffer<'pkt>,
) {
    match v {
        [b] => u16f(buf, &FD_CAUSE_VALUE, u16::from(*b), at..at + 1),
        [a, b] => u16f(
            buf,
            &FD_CAUSE_VALUE,
            u16::from_be_bytes([*a, *b]),
            at..at + 2,
        ),
        _ => bytes(buf, raw_fd, v, at),
    }
}

// ---------------------------------------------------------------------------
// 8.103 RAN/NAS Cause
// ---------------------------------------------------------------------------

/// 3GPP TS 29.274, Table 8.103-0 — Protocol Type values.
fn ran_nas_protocol_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("S1AP Cause"),
        2 => Some("EMM Cause"),
        3 => Some("ESM Cause"),
        4 => Some("Diameter Cause"),
        5 => Some("IKEv2 Cause"),
        _ => None,
    }
}

static FD_PROTOCOL_TYPE: FieldDescriptor =
    FieldDescriptor::new("protocol_type", "Protocol Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => ran_nas_protocol_type_name(*t),
            _ => None,
        },
    );

/// 3GPP TS 29.274, Section 8.103 — RAN/NAS Cause. S1AP, EMM and ESM causes
/// are one octet; Diameter and IKEv2 causes are two octets. Octets after the
/// cause value are kept as `additional_octets`.
pub(crate) fn push_ran_nas_cause<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    let Some(&o5) = data.first() else {
        push_raw(data, value_desc, value_range, buf);
        return;
    };
    let protocol_type = o5 >> 4;
    let rest = &data[1..];
    let obj = begin(value_desc, value_range, buf);
    u8f(buf, &FD_PROTOCOL_TYPE, protocol_type, offset);
    // "The Cause Type field shall be ignored by the receiver" for all but
    // S1-AP causes.
    if protocol_type == 1 {
        u8f(buf, &FD_CAUSE_TYPE, o5 & 0x0F, offset);
    }
    let width = match protocol_type {
        1..=3 => 1,
        4 | 5 => 2,
        _ => 0,
    };
    if width > 0 && rest.len() >= width {
        push_cause_value(&rest[..width], offset + 1, &FD_CAUSE_VALUE_RAW, buf);
        if rest.len() > width {
            bytes(
                buf,
                &FD_ADDITIONAL_OCTETS,
                &rest[width..],
                offset + 1 + width,
            );
        }
    } else {
        bytes(buf, &FD_CAUSE_VALUE_RAW, rest, offset + 1);
    }
    buf.end_container(obj);
}

// ---------------------------------------------------------------------------
// 8.47 GUTI, 8.50 PLMN ID, 8.89 TMGI
// ---------------------------------------------------------------------------

static FD_MME_GROUP_ID: FieldDescriptor =
    FieldDescriptor::new("mme_group_id", "MME Group ID", FieldType::U16);
static FD_MME_CODE: FieldDescriptor = FieldDescriptor::new("mme_code", "MME Code", FieldType::U8);
static FD_M_TMSI: FieldDescriptor = FieldDescriptor::new("m_tmsi", "M-TMSI", FieldType::U32);
static FD_MBMS_SERVICE_ID: FieldDescriptor =
    FieldDescriptor::new("mbms_service_id", "MBMS Service ID", FieldType::U32);

/// 3GPP TS 29.274, Section 8.47 — GUTI: PLMN (octets 5-7), MME Group ID
/// (8-9), MME Code (10), M-TMSI (11-14).
pub(crate) fn push_guti<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    let (Ok(group), Ok(m_tmsi)) = (read_be_u16(data, 3), read_be_u32(data, 6)) else {
        push_raw(data, value_desc, value_range, buf);
        return;
    };
    let obj = begin(value_desc, value_range, buf);
    push_plmn(buf, data, offset);
    u16f(buf, &FD_MME_GROUP_ID, group, offset + 3..offset + 5);
    u8f(buf, &FD_MME_CODE, data[5], offset + 5);
    u32f(buf, &FD_M_TMSI, m_tmsi, offset + 6..offset + 10);
    buf.end_container(obj);
}

/// 3GPP TS 29.274, Section 8.50 — PLMN ID.
pub(crate) fn push_plmn_id<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    if data.len() < 3 {
        push_raw(data, value_desc, value_range, buf);
        return;
    }
    let obj = begin(value_desc, value_range, buf);
    push_plmn_s1ap(buf, data, offset);
    buf.end_container(obj);
}

/// 3GPP TS 29.274, Section 8.89 — TMGI: "Octets 5 to 10 shall be encoded as
/// octets 3 to octet 8 in the figure 10.5.154 of TS 24.008", i.e. MBMS
/// Service ID (3 octets) followed by MCC/MNC.
pub(crate) fn push_tmgi<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    let (Ok(service_id), true) = (read_be_u24(data, 0), data.len() >= 6) else {
        push_raw(data, value_desc, value_range, buf);
        return;
    };
    let obj = begin(value_desc, value_range, buf);
    u32f(buf, &FD_MBMS_SERVICE_ID, service_id, offset..offset + 3);
    push_plmn(buf, &data[3..6], offset + 3);
    buf.end_container(obj);
}

// ---------------------------------------------------------------------------
// 8.51 Target Identification
// ---------------------------------------------------------------------------

/// 3GPP TS 29.274, Table 8.51-1 — Target Type values.
fn target_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("RNC ID"),
        1 => Some("Macro eNodeB ID"),
        2 => Some("Cell Identifier"),
        3 => Some("Home eNodeB ID"),
        4 => Some("Extended Macro eNodeB ID"),
        5 => Some("gNodeB ID"),
        6 => Some("Macro ng-eNodeB ID"),
        7 => Some("Extended ng-eNodeB ID"),
        8 => Some("en-gNB ID"),
        _ => None,
    }
}

static FD_TARGET_TYPE: FieldDescriptor =
    FieldDescriptor::new("target_type", "Target Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => target_type_name(*t),
            _ => None,
        },
    );
static FD_TARGET_ID: FieldDescriptor =
    FieldDescriptor::new("target_id", "Target ID", FieldType::Bytes);
static FD_LAC: FieldDescriptor = FieldDescriptor::new("lac", "LAC", FieldType::U16);
static FD_RAC: FieldDescriptor = FieldDescriptor::new("rac", "RAC", FieldType::U8);
static FD_RNC_ID: FieldDescriptor = FieldDescriptor::new("rnc_id", "RNC-ID", FieldType::U16);
static FD_EXTENDED_RNC_ID: FieldDescriptor =
    FieldDescriptor::new("extended_rnc_id", "Extended RNC-ID", FieldType::U16);
static FD_MACRO_ENB_ID: FieldDescriptor =
    FieldDescriptor::new("macro_enodeb_id", "Macro eNodeB ID", FieldType::U32);
static FD_HOME_ENB_ID: FieldDescriptor =
    FieldDescriptor::new("home_enodeb_id", "Home eNodeB ID", FieldType::U32);
static FD_SMENB: FieldDescriptor = FieldDescriptor::new("smenb", "SMeNB", FieldType::U8);
static FD_EXT_MACRO_ENB_ID: FieldDescriptor = FieldDescriptor::new(
    "extended_macro_enodeb_id",
    "Extended Macro eNodeB ID",
    FieldType::U32,
);
static FD_TAC: FieldDescriptor =
    FieldDescriptor::new("tac", "Tracking Area Code (TAC)", FieldType::U32);
static FD_TAC_5GS: FieldDescriptor =
    FieldDescriptor::new("tac_5gs", "5GS Tracking Area Code (TAC)", FieldType::U32);
static FD_GNB_ID_LENGTH: FieldDescriptor =
    FieldDescriptor::new("gnodeb_id_length", "gNodeB ID Length", FieldType::U8);
static FD_GNB_ID: FieldDescriptor = FieldDescriptor::new("gnodeb_id", "gNodeB ID", FieldType::U32);
static FD_FIVE_TAC: FieldDescriptor = FieldDescriptor::new("five_tac", "5TAC", FieldType::U8);
static FD_ETAC: FieldDescriptor = FieldDescriptor::new("etac", "ETAC", FieldType::U8);
static FD_EN_GNB_ID_LENGTH: FieldDescriptor =
    FieldDescriptor::new("en_gnb_id_length", "en-gNB ID Length", FieldType::U8);
static FD_EN_GNB_ID: FieldDescriptor =
    FieldDescriptor::new("en_gnb_id", "en-gNB ID", FieldType::U32);

/// Keep the `bits` least significant bits of `v` (`bits` capped at 32).
fn low_bits(v: u32, bits: u8) -> u32 {
    match bits {
        0 => 0,
        b if b >= 32 => v,
        b => v & ((1u32 << b) - 1),
    }
}

/// Length of the Target ID needed by `target_type`, or `None` when the
/// Target ID is not decoded (Cell Identifier and spare types).
///
/// `id` is the Target ID field (octets 6 to n+4).
fn target_id_len(target_type: u8, id: &[u8]) -> Option<usize> {
    match target_type {
        // 8.51.2: PLMN, LAC, RAC, RNC-ID
        0 => Some(8),
        // 8.51.3 / 8.51.5: PLMN, eNodeB ID (3), TAC (2)
        1 | 4 => Some(8),
        // 8.51.4: PLMN, Home eNodeB ID (4), TAC (2)
        3 => Some(9),
        // 8.51.7: PLMN, length, gNodeB ID (4), 5GS TAC (3)
        5 => Some(11),
        // 8.51.8 / 8.51.9: PLMN, eNodeB ID (3), 5GS TAC (3)
        6 | 7 => Some(9),
        // 8.51.10: PLMN, flags/length, en-gNB ID (4), [TAC (2)], [5GS TAC (3)]
        8 => id
            .get(3)
            .map(|f| 8 + usize::from(f & 0x40 != 0) * 2 + usize::from(f & 0x80 != 0) * 3),
        _ => None,
    }
}

/// 3GPP TS 29.274, Section 8.51 — Target Identification.
pub(crate) fn push_target_identification<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    let Some(&target_type) = data.first() else {
        push_raw(data, value_desc, value_range, buf);
        return;
    };
    let id = &data[1..];
    let at = offset + 1;
    let obj = begin(value_desc, value_range, buf);
    u8f(buf, &FD_TARGET_TYPE, target_type, offset);
    match target_id_len(target_type, id) {
        Some(len) if id.len() >= len => push_target_id(buf, target_type, id, at),
        _ => bytes(buf, &FD_TARGET_ID, id, at),
    }
    buf.end_container(obj);
}

/// Push the decoded Target ID; `id` is long enough for `target_type`.
fn push_target_id(buf: &mut DissectBuffer<'_>, target_type: u8, id: &[u8], at: usize) {
    let u16_at = |i: usize| u16::from_be_bytes([id[i], id[i + 1]]);
    let u24_at = |i: usize| u32::from_be_bytes([0, id[i], id[i + 1], id[i + 2]]);
    let u32_at = |i: usize| u32::from_be_bytes([id[i], id[i + 1], id[i + 2], id[i + 3]]);
    push_plmn(buf, id, at);
    match target_type {
        0 => {
            // Figure 8.51-1a
            u16f(buf, &FD_LAC, u16_at(3), at + 3..at + 5);
            u8f(buf, &FD_RAC, id[5], at + 5);
            // "Bit 4 of octet 12 is the most significant bit"
            u16f(buf, &FD_RNC_ID, u16_at(6) & 0x0FFF, at + 6..at + 8);
            if id.len() >= 10 {
                u16f(buf, &FD_EXTENDED_RNC_ID, u16_at(8), at + 8..at + 10);
            }
        }
        1 | 6 => {
            // Figures 8.51-2 / 8.51.8-1: 20-bit Macro eNodeB ID
            u32f(buf, &FD_MACRO_ENB_ID, u24_at(3) & 0x0F_FFFF, at + 3..at + 6);
            push_target_tac(buf, target_type == 6, id, 6, at);
        }
        3 => {
            // Figure 8.51-3: 28-bit Home eNodeB ID
            u32f(
                buf,
                &FD_HOME_ENB_ID,
                u32_at(3) & 0x0FFF_FFFF,
                at + 3..at + 7,
            );
            u32f(buf, &FD_TAC, u32::from(u16_at(7)), at + 7..at + 9);
        }
        4 | 7 => {
            // Figures 8.51-4 / 8.51.9-1: SMeNB selects an 18- or 21-bit ID
            let smenb = id[3] >> 7;
            let mask = if smenb == 1 { 0x3_FFFF } else { 0x1F_FFFF };
            u8f(buf, &FD_SMENB, smenb, at + 3);
            u32f(buf, &FD_EXT_MACRO_ENB_ID, u24_at(3) & mask, at + 3..at + 6);
            push_target_tac(buf, target_type == 7, id, 6, at);
        }
        5 => {
            // Figure 8.51.7-1
            let len = id[3] & 0x3F;
            u8f(buf, &FD_GNB_ID_LENGTH, len, at + 3);
            u32f(buf, &FD_GNB_ID, low_bits(u32_at(4), len), at + 4..at + 8);
            u32f(buf, &FD_TAC_5GS, u24_at(8), at + 8..at + 11);
        }
        8 => {
            // Figure 8.51.10-1
            let flags = id[3];
            let len = flags & 0x3F;
            u8f(buf, &FD_FIVE_TAC, flags >> 7, at + 3);
            u8f(buf, &FD_ETAC, (flags >> 6) & 1, at + 3);
            u8f(buf, &FD_EN_GNB_ID_LENGTH, len, at + 3);
            u32f(buf, &FD_EN_GNB_ID, low_bits(u32_at(4), len), at + 4..at + 8);
            let mut pos = 8;
            if flags & 0x40 != 0 {
                u32f(buf, &FD_TAC, u32::from(u16_at(pos)), at + pos..at + pos + 2);
                pos += 2;
            }
            if flags & 0x80 != 0 {
                u32f(buf, &FD_TAC_5GS, u24_at(pos), at + pos..at + pos + 3);
            }
        }
        _ => {}
    }
}

/// Push a 2-octet TAC, or a 3-octet 5GS TAC when `five_gs` is set.
fn push_target_tac(buf: &mut DissectBuffer<'_>, five_gs: bool, id: &[u8], i: usize, at: usize) {
    if five_gs {
        let v = u32::from_be_bytes([0, id[i], id[i + 1], id[i + 2]]);
        u32f(buf, &FD_TAC_5GS, v, at + i..at + i + 3);
    } else {
        let v = u32::from(u16::from_be_bytes([id[i], id[i + 1]]));
        u32f(buf, &FD_TAC, v, at + i..at + i + 2);
    }
}

// ---------------------------------------------------------------------------
// 8.62 FQ-CSID
// ---------------------------------------------------------------------------

/// 3GPP TS 29.274, Section 8.62 — Node-ID Type values.
fn node_id_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("IPv4"),
        1 => Some("IPv6"),
        2 => Some("MCC/MNC-based"),
        _ => None,
    }
}

static FD_NODE_ID_TYPE: FieldDescriptor =
    FieldDescriptor::new("node_id_type", "Node-ID Type", FieldType::U8).with_display_fn(|v, _| {
        match v {
            FieldValue::U8(t) => node_id_type_name(*t),
            _ => None,
        }
    });
static FD_NUMBER_OF_CSIDS: FieldDescriptor =
    FieldDescriptor::new("number_of_csids", "Number of CSIDs", FieldType::U8);
static FD_NODE_ID: FieldDescriptor = FieldDescriptor::new("node_id", "Node-ID", FieldType::Any);
static FD_MCC_MNC: FieldDescriptor =
    FieldDescriptor::new("mcc_mnc", "MCC * 1000 + MNC", FieldType::U32);
static FD_NODE_LOCAL_ID: FieldDescriptor =
    FieldDescriptor::new("node_local_id", "Node Local ID", FieldType::U16);
static FD_CSIDS: FieldDescriptor = FieldDescriptor::new("csids", "CSIDs", FieldType::Array);
static FD_CSID: FieldDescriptor = FieldDescriptor::new(
    "csid",
    "PDN Connection Set Identifier (CSID)",
    FieldType::U16,
);

/// 3GPP TS 29.274, Section 8.62 — FQ-CSID.
pub(crate) fn push_fq_csid<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    let Some(&o5) = data.first() else {
        push_raw(data, value_desc, value_range, buf);
        return;
    };
    let node_id_type = o5 >> 4;
    let count = usize::from(o5 & 0x0F);
    // "0 ... p = 9", "1 ... p = 21", "2 ... p = 9"
    let node_id_len = match node_id_type {
        0 | 2 => 4,
        1 => 16,
        _ => {
            push_raw(data, value_desc, value_range, buf);
            return;
        }
    };
    let csid_start = 1 + node_id_len;
    if data.len() < csid_start + count * 2 {
        push_raw(data, value_desc, value_range, buf);
        return;
    }
    let obj = begin(value_desc, value_range, buf);
    u8f(buf, &FD_NODE_ID_TYPE, node_id_type, offset);
    u8f(buf, &FD_NUMBER_OF_CSIDS, o5 & 0x0F, offset);
    let id_range = offset + 1..offset + csid_start;
    match node_id_type {
        0 => {
            if let Ok(a) = read_ipv4_addr(data, 1) {
                buf.push_field(&FD_NODE_ID, FieldValue::Ipv4Addr(a), id_range);
            }
        }
        1 => {
            if let Ok(a) = read_ipv6_addr(data, 1) {
                buf.push_field(&FD_NODE_ID, FieldValue::Ipv6Addr(a), id_range);
            }
        }
        _ => {
            if let Ok(v) = read_be_u32(data, 1) {
                buf.push_field(&FD_NODE_ID, FieldValue::U32(v), id_range.clone());
                // "Most significant 20 bits are the binary encoded value of
                // (MCC * 1000 + MNC)"; the least significant 12 bits are
                // assigned by the operator.
                u32f(buf, &FD_MCC_MNC, v >> 12, id_range.clone());
                u16f(buf, &FD_NODE_LOCAL_ID, (v & 0x0FFF) as u16, id_range);
            }
        }
    }
    let arr_range = offset + csid_start..offset + csid_start + count * 2;
    let arr = buf.begin_container(&FD_CSIDS, FieldValue::Array(0..0), arr_range);
    for i in 0..count {
        let p = csid_start + i * 2;
        if let Ok(v) = read_be_u16(data, p) {
            u16f(buf, &FD_CSID, v, offset + p..offset + p + 2);
        }
    }
    buf.end_container(arr);
    // "(q+2) to (n+4): These octet(s) is/are present only if explicitly
    // specified"
    let end = csid_start + count * 2;
    if data.len() > end {
        bytes(buf, &FD_ADDITIONAL_OCTETS, &data[end..], offset + end);
    }
    buf.end_container(obj);
}

// ---------------------------------------------------------------------------
// 8.85 Throttling
// ---------------------------------------------------------------------------

/// 3GPP TS 29.274, Table 8.85.1 — Throttling Delay unit (bits 8-6).
/// "Other values shall be interpreted as multiples of 1 minute."
fn throttling_unit_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("2 seconds"),
        2 => Some("10 minutes"),
        3 => Some("1 hour"),
        4 => Some("10 hours"),
        7 => Some("deactivated"),
        _ => Some("1 minute"),
    }
}

static FD_THROTTLING_UNIT: FieldDescriptor = FieldDescriptor::new(
    "throttling_delay_unit",
    "Throttling Delay Unit",
    FieldType::U8,
)
.with_display_fn(|v, _| match v {
    FieldValue::U8(u) => throttling_unit_name(*u),
    _ => None,
});
static FD_THROTTLING_VALUE: FieldDescriptor = FieldDescriptor::new(
    "throttling_delay_value",
    "Throttling Delay Value",
    FieldType::U8,
);
static FD_THROTTLING_FACTOR: FieldDescriptor =
    FieldDescriptor::new("throttling_factor", "Throttling Factor", FieldType::U8);

/// 3GPP TS 29.274, Section 8.85 — Throttling.
pub(crate) fn push_throttling<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    let [delay, factor, ..] = *data else {
        push_raw(data, value_desc, value_range, buf);
        return;
    };
    let obj = begin(value_desc, value_range, buf);
    u8f(buf, &FD_THROTTLING_UNIT, delay >> 5, offset);
    u8f(buf, &FD_THROTTLING_VALUE, delay & 0x1F, offset);
    u8f(buf, &FD_THROTTLING_FACTOR, factor, offset + 1);
    buf.end_container(obj);
}

// ---------------------------------------------------------------------------
// 8.100 TWAN Identifier
// ---------------------------------------------------------------------------

static TWAN_FLAGS: &[Flag] = &[
    flag(0, 5, "laii", "LAII"),
    flag(0, 4, "opnai", "OPNAI"),
    flag(0, 3, "plmni", "PLMNI"),
    flag(0, 2, "civai", "CIVAI"),
    flag(0, 1, "bssidi", "BSSIDI"),
];
static FD_SSID: FieldDescriptor = FieldDescriptor::new("ssid", "SSID", FieldType::Bytes);
static FD_BSSID: FieldDescriptor = FieldDescriptor::new("bssid", "BSSID", FieldType::MacAddr);
static FD_CIVIC_ADDRESS: FieldDescriptor = FieldDescriptor::new(
    "civic_address",
    "Civic Address Information",
    FieldType::Bytes,
);
static FD_TWAN_OPERATOR_NAME: FieldDescriptor =
    FieldDescriptor::new("twan_operator_name", "TWAN Operator Name", FieldType::Bytes);
static FD_RELAY_IDENTITY_TYPE: FieldDescriptor =
    FieldDescriptor::new("relay_identity_type", "Relay Identity Type", FieldType::U8);
static FD_RELAY_IDENTITY: FieldDescriptor =
    FieldDescriptor::new("relay_identity", "Relay Identity", FieldType::Any);
static FD_CIRCUIT_ID: FieldDescriptor =
    FieldDescriptor::new("circuit_id", "Circuit-ID", FieldType::Bytes);

/// Length-prefixed field cursor used by the TWAN Identifier walk.
struct Cursor<'pkt> {
    data: &'pkt [u8],
    pos: usize,
}

impl<'pkt> Cursor<'pkt> {
    /// Take `n` octets, or `None` if fewer remain.
    fn take(&mut self, n: usize) -> Option<Span<'pkt>> {
        let start = self.pos;
        let v = self.data.get(start..start + n)?;
        self.pos += n;
        Some((start, v))
    }

    /// Take a one-octet length followed by that many octets.
    fn take_lv(&mut self) -> Option<Span<'pkt>> {
        let (_, l) = self.take(1)?;
        self.take(usize::from(l[0]))
    }
}

/// A field of the TWAN Identifier: offset within the value, and its octets.
type Span<'pkt> = (usize, &'pkt [u8]);

/// Logical Access ID: Relay Identity Type (offset, value), Relay Identity,
/// Circuit-ID.
struct Relay<'pkt> {
    type_at: usize,
    relay_type: u8,
    identity: Span<'pkt>,
    circuit_id: Span<'pkt>,
}

/// Parsed TWAN Identifier fields.
struct Twan<'pkt> {
    ssid: Span<'pkt>,
    bssid: Option<Span<'pkt>>,
    civic: Option<Span<'pkt>>,
    plmn: Option<Span<'pkt>>,
    operator: Option<Span<'pkt>>,
    relay: Option<Relay<'pkt>>,
}

/// Walk the TWAN Identifier (Figure 8.100-1); `None` if a flagged field is
/// missing or a length runs past the value.
fn parse_twan(data: &[u8]) -> Option<Twan<'_>> {
    let flags = *data.first()?;
    let mut c = Cursor { data, pos: 1 };
    let ssid = c.take_lv()?;
    let bssid = if flags & 0x01 != 0 {
        Some(c.take(6)?)
    } else {
        None
    };
    let civic = if flags & 0x02 != 0 {
        Some(c.take_lv()?)
    } else {
        None
    };
    let plmn = if flags & 0x04 != 0 {
        Some(c.take(3)?)
    } else {
        None
    };
    let operator = if flags & 0x08 != 0 {
        Some(c.take_lv()?)
    } else {
        None
    };
    let relay = if flags & 0x10 != 0 {
        let (type_at, t) = c.take(1)?;
        let identity = c.take_lv()?;
        let circuit_id = c.take_lv()?;
        Some(Relay {
            type_at,
            relay_type: t[0],
            identity,
            circuit_id,
        })
    } else {
        None
    };
    Some(Twan {
        ssid,
        bssid,
        civic,
        plmn,
        operator,
        relay,
    })
}

/// 3GPP TS 29.274, Section 8.100 — TWAN Identifier.
pub(crate) fn push_twan_identifier<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    let Some(t) = parse_twan(data) else {
        push_raw(data, value_desc, value_range, buf);
        return;
    };
    let obj = begin(value_desc, value_range, buf);
    for f in TWAN_FLAGS {
        u8f(buf, &f.fd, u8::from(data[0] & f.mask != 0), offset);
    }
    bytes(buf, &FD_SSID, t.ssid.1, offset + t.ssid.0);
    if let Some((at, b)) = t.bssid {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(b);
        buf.push_field(
            &FD_BSSID,
            FieldValue::MacAddr(MacAddr(mac)),
            offset + at..offset + at + 6,
        );
    }
    if let Some((at, b)) = t.civic {
        bytes(buf, &FD_CIVIC_ADDRESS, b, offset + at);
    }
    if let Some((at, p)) = t.plmn {
        // "encoded as octets 5 to 7 of the Serving Network IE"
        push_plmn(buf, p, offset + at);
    }
    if let Some((at, b)) = t.operator {
        bytes(buf, &FD_TWAN_OPERATOR_NAME, b, offset + at);
    }
    if let Some(Relay {
        type_at,
        relay_type,
        identity: (id_at, id),
        circuit_id: (cid_at, cid),
    }) = t.relay
    {
        u8f(buf, &FD_RELAY_IDENTITY_TYPE, relay_type, offset + type_at);
        // Table 8.100-1: 0 = IPv4 or IPv6 address (by length), 1 = FQDN
        let r = offset + id_at..offset + id_at + id.len();
        let v = match (relay_type, id.len()) {
            (0, 4) => read_ipv4_addr(id, 0).map_or(FieldValue::Bytes(id), FieldValue::Ipv4Addr),
            (0, 16) => read_ipv6_addr(id, 0).map_or(FieldValue::Bytes(id), FieldValue::Ipv6Addr),
            _ => FieldValue::Bytes(id),
        };
        buf.push_field(&FD_RELAY_IDENTITY, v, r);
        bytes(buf, &FD_CIRCUIT_ID, cid, offset + cid_at);
    }
    buf.end_container(obj);
}

// ---------------------------------------------------------------------------
// 8.132 Secondary RAT Usage Data Report
// ---------------------------------------------------------------------------

/// 3GPP TS 29.274, Table 8.132-1 — Secondary RAT Type values.
fn secondary_rat_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("NR"),
        1 => Some("Unlicensed Spectrum"),
        _ => None,
    }
}

static SRUDR_FLAGS: &[Flag] = &[
    flag(0, 3, "srudn", "SRUDN"),
    flag(0, 2, "irsgw", "IRSGW (Intended Receiver SGW)"),
    flag(0, 1, "irpgw", "IRPGW (Intended Receiver PGW)"),
];
static FD_SECONDARY_RAT_TYPE: FieldDescriptor =
    FieldDescriptor::new("secondary_rat_type", "Secondary RAT Type", FieldType::U8)
        .with_display_fn(|v, _| match v {
            FieldValue::U8(t) => secondary_rat_type_name(*t),
            _ => None,
        });
static FD_EBI: FieldDescriptor = FieldDescriptor::new("ebi", "EPS Bearer ID", FieldType::U8);
static FD_START_TIMESTAMP: FieldDescriptor =
    FieldDescriptor::new("start_timestamp", "Start timestamp", FieldType::U32);
static FD_END_TIMESTAMP: FieldDescriptor =
    FieldDescriptor::new("end_timestamp", "End timestamp", FieldType::U32);
static FD_USAGE_DATA_DL: FieldDescriptor =
    FieldDescriptor::new("usage_data_dl", "Usage Data DL", FieldType::U64);
static FD_USAGE_DATA_UL: FieldDescriptor =
    FieldDescriptor::new("usage_data_ul", "Usage Data UL", FieldType::U64);
static FD_SRUDR_TRANSFER: FieldDescriptor = FieldDescriptor::new(
    "secondary_rat_data_usage_report_transfer",
    "Secondary RAT Data Usage Report Transfer",
    FieldType::Bytes,
);

/// 3GPP TS 29.274, Section 8.132 — Secondary RAT Usage Data Report.
pub(crate) fn push_secondary_rat_usage_data_report<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    value_desc: &'static FieldDescriptor,
    value_range: &Range<usize>,
    buf: &mut DissectBuffer<'pkt>,
) {
    // Octets 5 to 31 are fixed (27 octets).
    let (Ok(start), Ok(end), Ok(dl), Ok(ul)) = (
        read_be_u32(data, 3),
        read_be_u32(data, 7),
        read_be_u64(data, 11),
        read_be_u64(data, 19),
    ) else {
        push_raw(data, value_desc, value_range, buf);
        return;
    };
    // SRUDN: "the Length of Secondary RAT Data Usage Report Transfer and
    // Secondary RAT Data Usage Report Transfer field shall be present".
    let transfer = if data[0] & 0x04 != 0 {
        data.get(27)
            .and_then(|l| data.get(28..28 + usize::from(*l)))
    } else {
        None
    };
    let decoded_end = transfer.map_or(27, |t| 28 + t.len());
    let obj = begin(value_desc, value_range, buf);
    for f in SRUDR_FLAGS {
        u8f(buf, &f.fd, u8::from(data[0] & f.mask != 0), offset);
    }
    u8f(buf, &FD_SECONDARY_RAT_TYPE, data[1], offset + 1);
    u8f(buf, &FD_EBI, data[2] & 0x0F, offset + 2);
    u32f(buf, &FD_START_TIMESTAMP, start, offset + 3..offset + 7);
    u32f(buf, &FD_END_TIMESTAMP, end, offset + 7..offset + 11);
    buf.push_field(
        &FD_USAGE_DATA_DL,
        FieldValue::U64(dl),
        offset + 11..offset + 19,
    );
    buf.push_field(
        &FD_USAGE_DATA_UL,
        FieldValue::U64(ul),
        offset + 19..offset + 27,
    );
    if let Some(t) = transfer {
        bytes(buf, &FD_SRUDR_TRANSFER, t, offset + 28);
    }
    // Octets past the decoded fields: a transfer that runs past the value,
    // or octets "present only if explicitly specified".
    if data.len() > decoded_end {
        bytes(
            buf,
            &FD_ADDITIONAL_OCTETS,
            &data[decoded_end..],
            offset + decoded_end,
        );
    }
    buf.end_container(obj);
}

#[cfg(test)]
mod tests {
    use crate::ie_parsers::push_ie_value;
    use packet_dissector_core::field::{Field, FieldDescriptor, FieldType, FieldValue, MacAddr};
    use packet_dissector_core::packet::DissectBuffer;

    // # 3GPP TS 29.274 v19.6.0 Coverage (IE value decoders)
    //
    // | Section         | Description                          | Test                                   |
    // |-----------------|--------------------------------------|----------------------------------------|
    // | 8.12            | Indication flags (DAF, PT)           | indication_daf_and_pt                  |
    // | 8.12            | Indication octets 7-14, extra octets | indication_all_octets                  |
    // | 8.19            | Bearer TFT                           | tft_* (see tft.rs)                     |
    // | 8.23            | TMSI                                 | tmsi_ptmsi_and_signature               |
    // | 8.41            | P-TMSI                               | tmsi_ptmsi_and_signature               |
    // | 8.42            | P-TMSI Signature                     | tmsi_ptmsi_and_signature               |
    // | 8.46            | Complete Request Message             | complete_request_message               |
    // | 8.47            | GUTI                                 | guti                                   |
    // | 8.48            | F-Container                          | f_container                            |
    // | 8.49            | F-Cause                              | f_cause                                |
    // | 8.50            | PLMN ID (3- and 2-digit MNC)         | plmn_id_three_and_two_digit_mnc        |
    // | 8.51.2          | Target Identification: RNC ID        | target_identification_rnc_id           |
    // | 8.51.3 / 8.51.8 | Macro eNodeB / Macro ng-eNodeB ID    | target_identification_macro_enb        |
    // | 8.51.4          | Home eNodeB ID                       | target_identification_home_enb         |
    // | 8.51.5 / 8.51.9 | Extended Macro (ng-)eNodeB ID        | target_identification_extended_macro   |
    // | 8.51.7          | gNodeB ID                            | target_identification_gnb              |
    // | 8.51.10         | en-gNB ID                            | target_identification_en_gnb           |
    // | 8.51            | Cell Identifier / short / unknown    | target_identification_raw_cases        |
    // | 8.61            | Change Reporting Action              | change_reporting_action                |
    // | 8.62            | FQ-CSID (IPv4 / IPv6 / MCC-MNC)      | fq_csid_node_id_types                  |
    // | 8.62            | FQ-CSID malformed                    | fq_csid_malformed_is_raw               |
    // | 8.81            | Detach Type                          | detach_type                            |
    // | 8.83            | Node Features                        | node_features                          |
    // | 8.85            | Throttling                           | throttling                             |
    // | 8.89            | TMGI                                 | tmgi                                   |
    // | 8.100           | TWAN Identifier                      | twan_identifier_all_fields             |
    // | 8.100           | TWAN Identifier malformed            | twan_identifier_malformed_is_raw       |
    // | 8.103           | RAN/NAS Cause                        | ran_nas_cause                          |
    // | 8.132           | Secondary RAT Usage Data Report      | secondary_rat_usage_data_report        |
    // | 8.x             | Short values fall back to raw        | short_values_fall_back_to_raw          |
    // | 8.50            | BCD nibble above 9 shown as hex      | plmn_nibble_above_nine_is_visible      |
    // | 8.x             | Value name tables                    | name_tables_and_display_fns            |
    // | 8.100 / 8.51.7  | Relay IPv6, gNodeB ID length 0       | twan_relay_ipv6_and_gnb_zero_length    |

    static FD_VALUE: FieldDescriptor = FieldDescriptor::new("value", "Value", FieldType::Bytes);

    fn push(ie_type: u8, data: &[u8]) -> DissectBuffer<'_> {
        let mut buf = DissectBuffer::new();
        let range = 100..100 + data.len();
        push_ie_value(ie_type, data, 100, &FD_VALUE, &range, &mut buf);
        buf
    }

    /// Direct children of the value Object.
    fn children<'a>(buf: &'a DissectBuffer<'a>) -> &'a [Field<'a>] {
        let FieldValue::Object(ref r) = buf.fields()[0].value else {
            panic!("expected Object, got {:?}", buf.fields()[0].value)
        };
        buf.nested_fields(r)
    }

    fn field<'a>(buf: &'a DissectBuffer<'a>, name: &str) -> &'a Field<'a> {
        children(buf)
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("field {name} missing"))
    }

    fn val<'a>(buf: &'a DissectBuffer<'a>, name: &str) -> &'a FieldValue<'a> {
        &field(buf, name).value
    }

    fn has(buf: &DissectBuffer<'_>, name: &str) -> bool {
        children(buf).iter().any(|f| f.name() == name)
    }

    fn text<'a>(buf: &'a DissectBuffer<'a>, name: &str) -> &'a [u8] {
        match val(buf, name) {
            FieldValue::Scratch(r) => &buf.scratch()[r.start as usize..r.end as usize],
            FieldValue::Bytes(b) => b,
            v => panic!("{name} is not text: {v:?}"),
        }
    }

    fn display(buf: &DissectBuffer<'_>, name: &str) -> Option<&'static str> {
        let FieldValue::Object(ref r) = buf.fields()[0].value else {
            return None;
        };
        buf.resolve_nested_display_name(r, &format!("{name}_name"))
    }

    fn is_raw(buf: &DissectBuffer<'_>, data: &[u8]) -> bool {
        buf.fields()[0].value == FieldValue::Bytes(data) && buf.fields().len() == 1
    }

    #[test]
    fn indication_daf_and_pt() {
        // Issue reproduction: octet 5 = DAF, octet 6 = PT.
        let buf = push(77, &[0x80, 0x04]);
        assert_eq!(*val(&buf, "daf"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "pt"), FieldValue::U8(1));
        for name in ["dtf", "hi", "sgwci", "sqci", "ps", "si", "msv"] {
            assert_eq!(*val(&buf, name), FieldValue::U8(0), "{name}");
        }
        assert_eq!(field(&buf, "daf").range, 100..101);
        assert_eq!(field(&buf, "pt").range, 101..102);
        // Octet 7 is absent.
        assert!(!has(&buf, "retloc"));
    }

    #[test]
    fn indication_all_octets() {
        let data = [
            0x00, 0x00, 0x80, 0x01, 0x80, 0x01, 0x80, 0x01, 0x80, 0x3F, 0xAA,
        ];
        let buf = push(77, &data);
        assert_eq!(*val(&buf, "retloc"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "cpsr"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "nsi"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "wpmsi"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "n5gsnn26"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "ethpdn"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "nspusi"), FieldValue::U8(1));
        // Octet 14: bits 6-1 are DISREI, PPRI, LAPCOSI, LTEMSAI, SRTPI, UPIPSI
        for name in ["disrei", "ppri", "lapcosi", "ltemsai", "srtpi", "upipsi"] {
            assert_eq!(*val(&buf, name), FieldValue::U8(1), "{name}");
        }
        assert_eq!(field(&buf, "upipsi").range, 109..110);
        assert_eq!(*val(&buf, "additional_octets"), FieldValue::Bytes(&[0xAA]));
    }

    #[test]
    fn node_features() {
        let buf = push(152, &[0b1010_0101]);
        assert_eq!(*val(&buf, "prn"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "mabr"), FieldValue::U8(0));
        assert_eq!(*val(&buf, "ntsr"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "ciot"), FieldValue::U8(0));
        assert_eq!(*val(&buf, "s1un"), FieldValue::U8(0));
        assert_eq!(*val(&buf, "eth"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "mtedt"), FieldValue::U8(0));
        assert_eq!(*val(&buf, "psset"), FieldValue::U8(1));
    }

    #[test]
    fn change_reporting_action() {
        let buf = push(131, &[6]);
        assert_eq!(*val(&buf, "action"), FieldValue::U8(6));
        assert_eq!(
            display(&buf, "action"),
            Some("Start Reporting TAI and ECGI")
        );
        let buf = push(131, &[9]);
        assert_eq!(display(&buf, "action"), None);
    }

    #[test]
    fn fq_csid_node_id_types() {
        // Node-ID type 0 (IPv4), 2 CSIDs
        let buf = push(132, &[0x02, 10, 0, 0, 1, 0x00, 0x01, 0xFF, 0xFE]);
        assert_eq!(*val(&buf, "node_id_type"), FieldValue::U8(0));
        assert_eq!(*val(&buf, "number_of_csids"), FieldValue::U8(2));
        assert_eq!(*val(&buf, "node_id"), FieldValue::Ipv4Addr([10, 0, 0, 1]));
        let FieldValue::Array(ref r) = *val(&buf, "csids") else {
            panic!("csids")
        };
        let csids: Vec<_> = buf
            .nested_fields(r)
            .iter()
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(csids, vec![FieldValue::U16(1), FieldValue::U16(0xFFFE)]);

        // Node-ID type 1 (IPv6), 1 CSID
        let mut data = vec![0x11];
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data.extend_from_slice(&[0x12, 0x34]);
        let buf = push(132, &data);
        assert!(matches!(val(&buf, "node_id"), FieldValue::Ipv6Addr(_)));

        // Node-ID type 2: (MCC*1000+MNC) << 12 | 0x123 with MCC 440, MNC 10
        let v: u32 = ((440 * 1000 + 10) << 12) | 0x123;
        let mut data = vec![0x21];
        data.extend_from_slice(&v.to_be_bytes());
        data.extend_from_slice(&[0x00, 0x07, 0xEE]);
        let buf = push(132, &data);
        assert_eq!(*val(&buf, "additional_octets"), FieldValue::Bytes(&[0xEE]));
        assert_eq!(*val(&buf, "node_id"), FieldValue::U32(v));
        assert_eq!(*val(&buf, "mcc_mnc"), FieldValue::U32(440_010));
        assert_eq!(*val(&buf, "node_local_id"), FieldValue::U16(0x123));
        assert_eq!(display(&buf, "node_id_type"), Some("MCC/MNC-based"));
    }

    #[test]
    fn fq_csid_malformed_is_raw() {
        // Reserved Node-ID type 3
        let data = [0x31, 1, 2, 3, 4, 0, 1];
        assert!(is_raw(&push(132, &data), &data));
        // CSID list shorter than announced
        let data = [0x02, 10, 0, 0, 1, 0x00, 0x01];
        assert!(is_raw(&push(132, &data), &data));
        assert!(is_raw(&push(132, &[]), &[]));
    }

    #[test]
    fn guti() {
        // MCC 440, MNC 10 (2-digit), MME Group ID 0x8001, MME Code 0x01,
        // M-TMSI 0xC0000001
        let data = [0x44, 0xF0, 0x01, 0x80, 0x01, 0x01, 0xC0, 0x00, 0x00, 0x01];
        let buf = push(117, &data);
        assert_eq!(text(&buf, "mcc"), b"440");
        assert_eq!(text(&buf, "mnc"), b"10");
        assert_eq!(*val(&buf, "mme_group_id"), FieldValue::U16(0x8001));
        assert_eq!(*val(&buf, "mme_code"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "m_tmsi"), FieldValue::U32(0xC000_0001));
        assert_eq!(field(&buf, "m_tmsi").range, 106..110);
    }

    #[test]
    fn complete_request_message() {
        let buf = push(116, &[1, 0x07, 0x48]);
        assert_eq!(*val(&buf, "message_type"), FieldValue::U8(1));
        assert_eq!(
            display(&buf, "message_type"),
            Some("Complete TAU Request Message")
        );
        assert_eq!(*val(&buf, "message"), FieldValue::Bytes(&[0x07, 0x48]));
    }

    #[test]
    fn f_container() {
        let buf = push(118, &[0x03, 0xAA, 0xBB]);
        assert_eq!(*val(&buf, "container_type"), FieldValue::U8(3));
        assert_eq!(
            display(&buf, "container_type"),
            Some("E-UTRAN Transparent Container")
        );
        assert_eq!(*val(&buf, "container"), FieldValue::Bytes(&[0xAA, 0xBB]));
    }

    #[test]
    fn f_cause() {
        // S1-AP cause: Cause Type 2 (NAS), one-octet value
        let buf = push(119, &[0x02, 0x03]);
        assert_eq!(*val(&buf, "cause_type"), FieldValue::U8(2));
        // The meaning of Cause Type depends on the IE instance (S1-AP only),
        // which the value decoder does not see, so no name is given.
        assert_eq!(display(&buf, "cause_type"), None);
        assert_eq!(*val(&buf, "cause_value"), FieldValue::U16(3));
        // RANAP cause: two-octet value
        let buf = push(119, &[0x00, 0x01, 0x02]);
        assert_eq!(*val(&buf, "cause_value"), FieldValue::U16(0x0102));
        // Unexpected length: raw F-Cause field
        let buf = push(119, &[0x00, 1, 2, 3]);
        assert_eq!(*val(&buf, "f_cause"), FieldValue::Bytes(&[1, 2, 3]));
    }

    #[test]
    fn plmn_id_three_and_two_digit_mnc() {
        // Figure 8.50-2: MCC 310, MNC 410 → 13 00 14
        let buf = push(120, &[0x13, 0x40, 0x01]);
        assert_eq!(text(&buf, "mcc"), b"310");
        assert_eq!(text(&buf, "mnc"), b"410");
        // Figure 8.50-3: MCC 440, MNC 10 → 44 F0 01
        let buf = push(120, &[0x44, 0xF0, 0x01]);
        assert_eq!(text(&buf, "mcc"), b"440");
        assert_eq!(text(&buf, "mnc"), b"10");
    }

    #[test]
    fn target_identification_rnc_id() {
        // PLMN 440/10, LAC 0x1234, RAC 0x56, RNC-ID 0x0ABC, Extended RNC-ID 5000
        let data = [
            0x00, 0x44, 0xF0, 0x01, 0x12, 0x34, 0x56, 0x0A, 0xBC, 0x13, 0x88,
        ];
        let buf = push(121, &data);
        assert_eq!(*val(&buf, "target_type"), FieldValue::U8(0));
        assert_eq!(display(&buf, "target_type"), Some("RNC ID"));
        assert_eq!(text(&buf, "mcc"), b"440");
        assert_eq!(*val(&buf, "lac"), FieldValue::U16(0x1234));
        assert_eq!(*val(&buf, "rac"), FieldValue::U8(0x56));
        assert_eq!(*val(&buf, "rnc_id"), FieldValue::U16(0x0ABC));
        assert_eq!(*val(&buf, "extended_rnc_id"), FieldValue::U16(5000));
        // Without the Extended RNC-ID
        let buf = push(121, &data[..9]);
        assert!(!has(&buf, "extended_rnc_id"));
    }

    #[test]
    fn target_identification_macro_enb() {
        // Macro eNodeB ID 0xABCDE, TAC 0x0102
        let buf = push(121, &[1, 0x44, 0xF0, 0x01, 0xFA, 0xBC, 0xDE, 0x01, 0x02]);
        assert_eq!(*val(&buf, "macro_enodeb_id"), FieldValue::U32(0xABCDE));
        assert_eq!(*val(&buf, "tac"), FieldValue::U32(0x0102));
        // Macro ng-eNodeB ID with 3-octet 5GS TAC
        let buf = push(
            121,
            &[6, 0x44, 0xF0, 0x01, 0x0A, 0xBC, 0xDE, 0x01, 0x02, 0x03],
        );
        assert_eq!(*val(&buf, "macro_enodeb_id"), FieldValue::U32(0xABCDE));
        assert_eq!(*val(&buf, "tac_5gs"), FieldValue::U32(0x010203));
    }

    #[test]
    fn target_identification_home_enb() {
        let buf = push(
            121,
            &[3, 0x44, 0xF0, 0x01, 0xF1, 0x23, 0x45, 0x67, 0x00, 0x09],
        );
        assert_eq!(*val(&buf, "home_enodeb_id"), FieldValue::U32(0x123_4567));
        assert_eq!(*val(&buf, "tac"), FieldValue::U32(9));
    }

    #[test]
    fn target_identification_extended_macro() {
        // Long Macro eNodeB ID (SMeNB = 0): 21 bits
        let buf = push(121, &[4, 0x44, 0xF0, 0x01, 0x1F, 0xFF, 0xFF, 0x00, 0x01]);
        assert_eq!(*val(&buf, "smenb"), FieldValue::U8(0));
        assert_eq!(
            *val(&buf, "extended_macro_enodeb_id"),
            FieldValue::U32(0x1F_FFFF)
        );
        assert_eq!(*val(&buf, "tac"), FieldValue::U32(1));
        // Short Macro eNodeB ID (SMeNB = 1): 18 bits
        let buf = push(121, &[4, 0x44, 0xF0, 0x01, 0x9F, 0xFF, 0xFF, 0x00, 0x01]);
        assert_eq!(*val(&buf, "smenb"), FieldValue::U8(1));
        assert_eq!(
            *val(&buf, "extended_macro_enodeb_id"),
            FieldValue::U32(0x3_FFFF)
        );
        // Extended Macro ng-eNodeB ID with 5GS TAC
        let buf = push(
            121,
            &[7, 0x44, 0xF0, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x05],
        );
        assert_eq!(*val(&buf, "extended_macro_enodeb_id"), FieldValue::U32(2));
        assert_eq!(*val(&buf, "tac_5gs"), FieldValue::U32(5));
    }

    #[test]
    fn target_identification_gnb() {
        // gNodeB ID length 24: ID in octets 11-13
        let buf = push(
            121,
            &[
                5, 0x44, 0xF0, 0x01, 24, 0xFF, 0x12, 0x34, 0x56, 0x00, 0x00, 0x07,
            ],
        );
        assert_eq!(*val(&buf, "gnodeb_id_length"), FieldValue::U8(24));
        assert_eq!(*val(&buf, "gnodeb_id"), FieldValue::U32(0x12_3456));
        assert_eq!(*val(&buf, "tac_5gs"), FieldValue::U32(7));
        // Length 32
        let buf = push(
            121,
            &[
                5, 0x44, 0xF0, 0x01, 32, 0xFF, 0x12, 0x34, 0x56, 0x00, 0x00, 0x07,
            ],
        );
        assert_eq!(*val(&buf, "gnodeb_id"), FieldValue::U32(0xFF12_3456));
    }

    #[test]
    fn target_identification_en_gnb() {
        // 5TAC=1, ETAC=1, length 22; TAC 0x0102; 5GS TAC 0x030405
        let buf = push(
            121,
            &[
                8,
                0x44,
                0xF0,
                0x01,
                0xC0 | 22,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
            ],
        );
        assert_eq!(*val(&buf, "five_tac"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "etac"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "en_gnb_id_length"), FieldValue::U8(22));
        assert_eq!(*val(&buf, "en_gnb_id"), FieldValue::U32(0x3F_FFFF));
        assert_eq!(*val(&buf, "tac"), FieldValue::U32(0x0102));
        assert_eq!(*val(&buf, "tac_5gs"), FieldValue::U32(0x030405));
        // No TACs
        let buf = push(121, &[8, 0x44, 0xF0, 0x01, 22, 0, 0, 0, 1]);
        assert!(!has(&buf, "tac") && !has(&buf, "tac_5gs"));
    }

    #[test]
    fn target_identification_raw_cases() {
        // Cell Identifier (TS 48.018 coding) is kept raw.
        let buf = push(121, &[2, 1, 2, 3]);
        assert_eq!(*val(&buf, "target_type"), FieldValue::U8(2));
        assert_eq!(display(&buf, "target_type"), Some("Cell Identifier"));
        assert_eq!(*val(&buf, "target_id"), FieldValue::Bytes(&[1, 2, 3]));
        // Too short for a Macro eNodeB ID
        let buf = push(121, &[1, 0x44, 0xF0]);
        assert_eq!(*val(&buf, "target_id"), FieldValue::Bytes(&[0x44, 0xF0]));
        assert!(!has(&buf, "mcc"));
        // Spare target type
        let buf = push(121, &[200, 9]);
        assert_eq!(*val(&buf, "target_id"), FieldValue::Bytes(&[9]));
        // en-gNB with ETAC set but no TAC octets
        let buf = push(121, &[8, 0x44, 0xF0, 0x01, 0x40 | 22, 0, 0, 0, 1]);
        assert!(has(&buf, "target_id"));
        assert!(is_raw(&push(121, &[]), &[]));
    }

    #[test]
    fn tmsi_ptmsi_and_signature() {
        let buf = push(88, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(*val(&buf, "tmsi"), FieldValue::U32(0x0102_0304));
        let buf = push(111, &[0xC0, 0x00, 0x00, 0x01]);
        assert_eq!(*val(&buf, "p_tmsi"), FieldValue::U32(0xC000_0001));
        let buf = push(112, &[0xAB, 0xCD, 0xEF]);
        assert_eq!(*val(&buf, "p_tmsi_signature"), FieldValue::U32(0xAB_CDEF));
    }

    #[test]
    fn detach_type() {
        let buf = push(150, &[2]);
        assert_eq!(*val(&buf, "detach_type"), FieldValue::U8(2));
        assert_eq!(display(&buf, "detach_type"), Some("Combined PS/CS Detach"));
    }

    #[test]
    fn throttling() {
        // Unit 001 (1 minute), value 5; factor 50
        let buf = push(154, &[0x25, 50]);
        assert_eq!(*val(&buf, "throttling_delay_unit"), FieldValue::U8(1));
        assert_eq!(display(&buf, "throttling_delay_unit"), Some("1 minute"));
        assert_eq!(*val(&buf, "throttling_delay_value"), FieldValue::U8(5));
        assert_eq!(*val(&buf, "throttling_factor"), FieldValue::U8(50));
        let buf = push(154, &[0xE0, 0]);
        assert_eq!(display(&buf, "throttling_delay_unit"), Some("deactivated"));
    }

    #[test]
    fn ran_nas_cause() {
        // S1AP cause, Cause Type Transport (1), value 0
        let buf = push(172, &[0x11, 0x00]);
        assert_eq!(*val(&buf, "protocol_type"), FieldValue::U8(1));
        assert_eq!(display(&buf, "protocol_type"), Some("S1AP Cause"));
        assert_eq!(*val(&buf, "cause_type"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "cause_value"), FieldValue::U16(0));
        assert_eq!(display(&buf, "cause_type"), Some("Transport Layer"));
        // Diameter cause: two-octet value; Cause Type is not shown
        let buf = push(172, &[0x40, 0x00, 0x01]);
        assert_eq!(*val(&buf, "cause_value"), FieldValue::U16(1));
        assert!(!has(&buf, "cause_type"));
        // EMM cause is one octet; later octets are "present only if
        // explicitly specified"
        let buf = push(172, &[0x20, 0x07, 0x00]);
        assert_eq!(*val(&buf, "cause_value"), FieldValue::U16(7));
        assert_eq!(*val(&buf, "additional_octets"), FieldValue::Bytes(&[0x00]));
        // IKEv2 cause cut short, and a spare protocol type, stay raw
        let buf = push(172, &[0x50, 0x01]);
        assert_eq!(*val(&buf, "cause_value_raw"), FieldValue::Bytes(&[0x01]));
        let buf = push(172, &[0x60, 1, 2, 3]);
        assert_eq!(*val(&buf, "cause_value_raw"), FieldValue::Bytes(&[1, 2, 3]));
    }

    #[test]
    fn twan_identifier_all_fields() {
        let mut data = vec![0x1F, 3];
        data.extend_from_slice(b"ssi");
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // BSSID
        data.extend_from_slice(&[2, 0xCA, 0xFE]); // civic address
        data.extend_from_slice(&[0x44, 0xF0, 0x01]); // TWAN PLMN-ID
        data.extend_from_slice(&[2, b'o', b'p']); // operator name
        data.extend_from_slice(&[0, 4, 10, 0, 0, 9]); // relay IPv4
        data.extend_from_slice(&[1, 0x77]); // circuit-ID
        let buf = push(169, &data);
        for flag in ["laii", "opnai", "plmni", "civai", "bssidi"] {
            assert_eq!(*val(&buf, flag), FieldValue::U8(1), "{flag}");
        }
        assert_eq!(*val(&buf, "ssid"), FieldValue::Bytes(b"ssi"));
        assert_eq!(
            *val(&buf, "bssid"),
            FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
        assert_eq!(
            *val(&buf, "civic_address"),
            FieldValue::Bytes(&[0xCA, 0xFE])
        );
        assert_eq!(text(&buf, "mcc"), b"440");
        assert_eq!(*val(&buf, "twan_operator_name"), FieldValue::Bytes(b"op"));
        assert_eq!(*val(&buf, "relay_identity_type"), FieldValue::U8(0));
        assert_eq!(
            *val(&buf, "relay_identity"),
            FieldValue::Ipv4Addr([10, 0, 0, 9])
        );
        assert_eq!(*val(&buf, "circuit_id"), FieldValue::Bytes(&[0x77]));

        // Only the SSID; FQDN relay identity kept as bytes
        let mut data = vec![0x10, 1, b'x', 1, 3];
        data.extend_from_slice(b"a.b");
        data.push(0);
        let buf = push(169, &data);
        assert!(!has(&buf, "bssid"));
        assert_eq!(*val(&buf, "relay_identity"), FieldValue::Bytes(b"a.b"));
        assert_eq!(*val(&buf, "circuit_id"), FieldValue::Bytes(&[]));
    }

    #[test]
    fn twan_identifier_malformed_is_raw() {
        // BSSIDI set but no BSSID
        let data = [0x01, 1, b'x'];
        assert!(is_raw(&push(169, &data), &data));
        // SSID length past the end
        let data = [0x00, 5, b'x'];
        assert!(is_raw(&push(169, &data), &data));
    }

    #[test]
    fn secondary_rat_usage_data_report() {
        let mut data = vec![0x07, 0x00, 0x05];
        data.extend_from_slice(&0xE000_0000u32.to_be_bytes());
        data.extend_from_slice(&0xE000_0010u32.to_be_bytes());
        data.extend_from_slice(&1000u64.to_be_bytes());
        data.extend_from_slice(&2000u64.to_be_bytes());
        data.extend_from_slice(&[2, 0xAB, 0xCD]); // SRUDN transfer
        let buf = push(201, &data);
        assert_eq!(*val(&buf, "srudn"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "irsgw"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "irpgw"), FieldValue::U8(1));
        assert_eq!(*val(&buf, "secondary_rat_type"), FieldValue::U8(0));
        assert_eq!(display(&buf, "secondary_rat_type"), Some("NR"));
        assert_eq!(*val(&buf, "ebi"), FieldValue::U8(5));
        assert_eq!(*val(&buf, "start_timestamp"), FieldValue::U32(0xE000_0000));
        assert_eq!(*val(&buf, "end_timestamp"), FieldValue::U32(0xE000_0010));
        assert_eq!(*val(&buf, "usage_data_dl"), FieldValue::U64(1000));
        assert_eq!(*val(&buf, "usage_data_ul"), FieldValue::U64(2000));
        assert_eq!(
            *val(&buf, "secondary_rat_data_usage_report_transfer"),
            FieldValue::Bytes(&[0xAB, 0xCD])
        );
        // SRUDN = 0: no transfer field
        let mut no_transfer = data[..27].to_vec();
        no_transfer[0] = 0x03;
        let buf = push(201, &no_transfer);
        assert!(!has(&buf, "secondary_rat_data_usage_report_transfer"));
        // SRUDN set but the transfer runs past the value: the fixed part is
        // decoded and the rest is kept raw.
        let mut short = data[..28].to_vec();
        short[27] = 0x10;
        let buf = push(201, &short);
        assert_eq!(*val(&buf, "ebi"), FieldValue::U8(5));
        assert_eq!(*val(&buf, "additional_octets"), FieldValue::Bytes(&[0x10]));
        assert!(!has(&buf, "secondary_rat_data_usage_report_transfer"));
    }

    #[test]
    fn plmn_nibble_above_nine_is_visible() {
        let buf = push(120, &[0xF2, 0xF0, 0x01]);
        assert_eq!(text(&buf, "mcc"), b"2F0");
    }

    #[test]
    fn tmgi() {
        // MBMS Service ID 0x123456, MCC 440, MNC 10
        let buf = push(158, &[0x12, 0x34, 0x56, 0x44, 0xF0, 0x01]);
        assert_eq!(*val(&buf, "mbms_service_id"), FieldValue::U32(0x12_3456));
        assert_eq!(text(&buf, "mcc"), b"440");
        assert_eq!(text(&buf, "mnc"), b"10");
    }

    #[test]
    fn short_values_fall_back_to_raw() {
        for (ie_type, data) in [
            (77u8, &[][..]),
            (152, &[][..]),
            (131, &[][..]),
            (117, &[0x44, 0xF0, 0x01, 0x80][..]),
            (116, &[][..]),
            (118, &[][..]),
            (119, &[][..]),
            (120, &[0x44, 0xF0][..]),
            (88, &[1, 2, 3][..]),
            (111, &[1, 2][..]),
            (112, &[1, 2][..]),
            (150, &[][..]),
            (154, &[0x25][..]),
            (172, &[][..]),
            (169, &[0x00][..]),
            (201, &[0x07; 26][..]),
            (158, &[1, 2, 3, 4, 5][..]),
        ] {
            let buf = push(ie_type, data);
            assert!(is_raw(&buf, data), "IE {ie_type} should be raw");
        }
    }

    #[test]
    fn name_tables_and_display_fns() {
        use super::*;
        // Table 8.61-1
        let actions: Vec<_> = (0..=9).map(change_reporting_action_name).collect();
        assert!(actions[..9].iter().all(Option::is_some));
        assert_eq!(actions[9], None);
        // Table 8.81-1
        assert_eq!(detach_type_name(1), Some("PS Detach"));
        assert_eq!(detach_type_name(0), None);
        // Table 8.46-1
        assert_eq!(
            complete_request_message_type_name(0),
            Some("Complete Attach Request Message")
        );
        assert_eq!(complete_request_message_type_name(2), None);
        // Table 8.48-2
        assert!((1..=6).all(|v| container_type_name(v).is_some()));
        assert_eq!(container_type_name(0), None);
        // Tables 8.49-1 / 8.103-1
        assert!((0..=4).all(|v| ran_cause_type_name(v).is_some()));
        assert_eq!(ran_cause_type_name(5), None);
        // Table 8.103-0
        assert!((1..=5).all(|v| ran_nas_protocol_type_name(v).is_some()));
        assert_eq!(ran_nas_protocol_type_name(0), None);
        // Table 8.51-1
        assert!((0..=8).all(|v| target_type_name(v).is_some()));
        assert_eq!(target_type_name(9), None);
        // Section 8.62
        assert!((0..=2).all(|v| node_id_type_name(v).is_some()));
        assert_eq!(node_id_type_name(3), None);
        // Table 8.85.1
        for (v, name) in [
            (0, "2 seconds"),
            (1, "1 minute"),
            (2, "10 minutes"),
            (3, "1 hour"),
            (4, "10 hours"),
            (5, "1 minute"),
            (7, "deactivated"),
        ] {
            assert_eq!(throttling_unit_name(v), Some(name));
        }
        // Table 8.132-1
        assert_eq!(secondary_rat_type_name(1), Some("Unlicensed Spectrum"));
        assert_eq!(secondary_rat_type_name(2), None);
        assert_eq!(low_bits(0xFFFF_FFFF, 0), 0);

        // Display functions ignore values of another type.
        for fd in [
            &FD_ACTION,
            &FD_DETACH_TYPE,
            &FD_CRM_TYPE,
            &FD_CONTAINER_TYPE,
            &FD_CAUSE_TYPE,
            &FD_PROTOCOL_TYPE,
            &FD_TARGET_TYPE,
            &FD_NODE_ID_TYPE,
            &FD_THROTTLING_UNIT,
            &FD_SECONDARY_RAT_TYPE,
        ] {
            assert_eq!((fd.display_fn.unwrap())(&FieldValue::U16(0), &[]), None);
        }
    }

    #[test]
    fn twan_relay_ipv6_and_gnb_zero_length() {
        let mut data = vec![0x10, 0];
        data.extend_from_slice(&[0, 16]);
        data.extend_from_slice(&[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data.push(0);
        let buf = push(169, &data);
        assert!(matches!(
            val(&buf, "relay_identity"),
            FieldValue::Ipv6Addr(_)
        ));

        // gNodeB ID Length 0 yields an empty ID.
        let buf = push(
            121,
            &[5, 0x44, 0xF0, 0x01, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 1],
        );
        assert_eq!(*val(&buf, "gnodeb_id"), FieldValue::U32(0));
    }
}
