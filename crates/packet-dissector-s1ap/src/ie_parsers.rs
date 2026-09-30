//! S1AP IE value decoders.
//!
//! Each IE value is the complete APER encoding of its ASN.1 type (an open
//! type, ITU-T Rec. X.691, Section 11.2). Values with a decoder are pushed
//! as named fields of the IE object; any other value, or one that does not
//! decode completely, is kept as raw `value` octets.
//!
//! ## References
//! - 3GPP TS 36.413 v19.2.0, Sections 9.3.3 (PDU definitions) and 9.3.4
//!   (IE definitions): <https://www.3gpp.org/ftp/Specs/archive/36_series/36.413/>
//! - ITU-T Rec. X.691 (APER): <https://www.itu.int/rec/T-REC-X.691>
//! - 3GPP TS 24.301 (NAS-PDU contents):
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.301/>

use core::ops::Range;
use std::io::{self, Write};

use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{
    FieldDescriptor, FieldType, FieldValue, FormatContext, format_utf8_lossy,
};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_per::AperReader;
use packet_dissector_per::ap::{
    ensure_consumed, read_aligned_octets, read_bit_string_field, read_sequence_preamble,
    skip_protocol_ie_single_container, skip_sequence_tail,
};

use crate::container::{self, IeContext};

// ── IE identifiers (3GPP TS 36.413, Section 9.3.6) ─────────────────────

const ID_MME_UE_S1AP_ID: u16 = 0;
const ID_CAUSE: u16 = 2;
const ID_ENB_UE_S1AP_ID: u16 = 8;
const ID_E_RAB_TO_BE_SETUP_LIST_BEARER_SU_REQ: u16 = 16;
const ID_E_RAB_TO_BE_SETUP_ITEM_BEARER_SU_REQ: u16 = 17;
const ID_E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ: u16 = 24;
const ID_NAS_PDU: u16 = 26;
const ID_E_RAB_SETUP_ITEM_CTXT_SU_RES: u16 = 50;
const ID_E_RAB_SETUP_LIST_CTXT_SU_RES: u16 = 51;
const ID_E_RAB_TO_BE_SETUP_ITEM_CTXT_SU_REQ: u16 = 52;
const ID_GLOBAL_ENB_ID: u16 = 59;
const ID_ENB_NAME: u16 = 60;
const ID_MME_NAME: u16 = 61;
const ID_UE_AGGREGATE_MAXIMUM_BITRATE: u16 = 66;
const ID_TAI: u16 = 67;
const ID_S_TMSI: u16 = 96;
const ID_EUTRAN_CGI: u16 = 100;
const ID_UE_SECURITY_CAPABILITIES: u16 = 107;
const ID_RRC_ESTABLISHMENT_CAUSE: u16 = 134;
const ID_DEFAULT_PAGING_DRX: u16 = 137;

/// `maxnoofE-RABs` (3GPP TS 36.413, Section 9.3.6).
const MAX_NO_OF_E_RABS: u64 = 256;

/// `BitRate ::= INTEGER (0..10000000000)` (3GPP TS 36.413, Section 9.3.4).
const BIT_RATE_MAX: u64 = 10_000_000_000;

// ── Enumerations ───────────────────────────────────────────────────────

/// An ENUMERATED type: `root` root values followed by extension additions.
struct Enum {
    root: usize,
    names: &'static [&'static str],
}

impl Enum {
    /// Decodes an index (ITU-T Rec. X.691, Section 14) of this extensible
    /// enumeration.
    fn read(&self, r: &mut AperReader<'_>) -> Result<u8, PacketError> {
        let v = r.read_enumerated(self.root as u64, true)?;
        u8::try_from(v).map_err(|_| PacketError::InvalidHeader("APER enumerated index too large"))
    }

    fn name(&self, index: u8) -> Option<&'static str> {
        self.names.get(usize::from(index)).copied()
    }
}

/// `CauseRadioNetwork` values: 36 root values, then the extension additions
/// (3GPP TS 36.413, Section 9.3.4).
const CAUSE_RADIO_NETWORK: Enum = Enum {
    root: 36,
    names: &[
        "unspecified",
        "tx2relocoverall-expiry",
        "successful-handover",
        "release-due-to-eutran-generated-reason",
        "handover-cancelled",
        "partial-handover",
        "ho-failure-in-target-EPC-eNB-or-target-system",
        "ho-target-not-allowed",
        "tS1relocoverall-expiry",
        "tS1relocprep-expiry",
        "cell-not-available",
        "unknown-targetID",
        "no-radio-resources-available-in-target-cell",
        "unknown-mme-ue-s1ap-id",
        "unknown-enb-ue-s1ap-id",
        "unknown-pair-ue-s1ap-id",
        "handover-desirable-for-radio-reason",
        "time-critical-handover",
        "resource-optimisation-handover",
        "reduce-load-in-serving-cell",
        "user-inactivity",
        "radio-connection-with-ue-lost",
        "load-balancing-tau-required",
        "cs-fallback-triggered",
        "ue-not-available-for-ps-service",
        "radio-resources-not-available",
        "failure-in-radio-interface-procedure",
        "invalid-qos-combination",
        "interrat-redirection",
        "interaction-with-other-procedure",
        "unknown-E-RAB-ID",
        "multiple-E-RAB-ID-instances",
        "encryption-and-or-integrity-protection-algorithms-not-supported",
        "s1-intra-system-handover-triggered",
        "s1-inter-system-handover-triggered",
        "x2-handover-triggered",
        "redirection-towards-1xRTT",
        "not-supported-QCI-value",
        "invalid-CSG-Id",
        "release-due-to-pre-emption",
        "n26-interface-not-available",
        "insufficient-ue-capabilities",
        "maximum-bearer-pre-emption-rate-exceeded",
        "up-integrity-protection-not-possible",
        "release-due-to-discontinuous-coverage",
    ],
};

/// `CauseTransport` values: 2 root values, then the extension additions
/// (3GPP TS 36.413, Section 9.3.4).
const CAUSE_TRANSPORT: Enum = Enum {
    root: 2,
    names: &["transport-resource-unavailable", "unspecified"],
};

/// `CauseNas` values: 4 root values, then the extension additions
/// (3GPP TS 36.413, Section 9.3.4).
const CAUSE_NAS: Enum = Enum {
    root: 4,
    names: &[
        "normal-release",
        "authentication-failure",
        "detach",
        "unspecified",
        "csg-subscription-expiry",
        "uE-not-in-PLMN-serving-area",
        "iab-not-authorized",
    ],
};

/// `CauseProtocol` values: 7 root values, then the extension additions
/// (3GPP TS 36.413, Section 9.3.4).
const CAUSE_PROTOCOL: Enum = Enum {
    root: 7,
    names: &[
        "transfer-syntax-error",
        "abstract-syntax-error-reject",
        "abstract-syntax-error-ignore-and-notify",
        "message-not-compatible-with-receiver-state",
        "semantic-error",
        "abstract-syntax-error-falsely-constructed-message",
        "unspecified",
    ],
};

/// `CauseMisc` values: 6 root values, then the extension additions
/// (3GPP TS 36.413, Section 9.3.4).
const CAUSE_MISC: Enum = Enum {
    root: 6,
    names: &[
        "control-processing-overload",
        "not-enough-user-plane-processing-resources",
        "hardware-failure",
        "om-intervention",
        "unspecified",
        "unknown-PLMN",
    ],
};

/// `RRC-Establishment-Cause` values: 5 root values, then the extension additions
/// (3GPP TS 36.413, Section 9.3.4).
const RRC_ESTABLISHMENT_CAUSE: Enum = Enum {
    root: 5,
    names: &[
        "emergency",
        "highPriorityAccess",
        "mt-Access",
        "mo-Signalling",
        "mo-Data",
        "delay-TolerantAccess",
        "mo-VoiceCall",
        "mo-ExceptionData",
    ],
};

/// `PagingDRX` values: 4 root values, then the extension additions
/// (3GPP TS 36.413, Section 9.3.4).
const PAGING_DRX: Enum = Enum {
    root: 4,
    names: &["v32", "v64", "v128", "v256"],
};

/// `Cause` CHOICE groups (3GPP TS 36.413, Section 9.3.4): five root
/// alternatives and an extension marker.
const CAUSE_GROUPS: [(&str, &Enum); 5] = [
    ("radioNetwork", &CAUSE_RADIO_NETWORK),
    ("transport", &CAUSE_TRANSPORT),
    ("nas", &CAUSE_NAS),
    ("protocol", &CAUSE_PROTOCOL),
    ("misc", &CAUSE_MISC),
];

/// `ENB-ID` CHOICE alternatives and their BIT STRING sizes (3GPP TS
/// 36.413, Section 9.3.4): two root alternatives, then two extension
/// additions.
const ENB_ID_TYPES: [(&str, u32); 4] = [
    ("macroENB-ID", 20),
    ("homeENB-ID", 28),
    ("short-macroENB-ID", 18),
    ("long-macroENB-ID", 21),
];

fn cause_group_name(g: u8) -> Option<&'static str> {
    CAUSE_GROUPS.get(usize::from(g)).map(|(n, _)| *n)
}

fn enb_id_type_name(t: u8) -> Option<&'static str> {
    ENB_ID_TYPES.get(usize::from(t)).map(|(n, _)| *n)
}

/// Pre-emptionCapability names (3GPP TS 36.413, Section 9.3.4).
fn pre_emption_capability_name(v: u8) -> Option<&'static str> {
    ["shall-not-trigger-pre-emption", "may-trigger-pre-emption"]
        .get(usize::from(v))
        .copied()
}

/// Pre-emptionVulnerability names (3GPP TS 36.413, Section 9.3.4).
fn pre_emption_vulnerability_name(v: u8) -> Option<&'static str> {
    ["not-pre-emptable", "pre-emptable"]
        .get(usize::from(v))
        .copied()
}

// ── Format functions ───────────────────────────────────────────────────

/// Write BCD digits as a JSON string, stopping at a "1111" filler.
fn write_digits(w: &mut dyn Write, digits: &[u8]) -> io::Result<()> {
    w.write_all(b"\"")?;
    for &d in digits {
        if d == 0x0f {
            break;
        }
        let c = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        w.write_all(&[c])?;
    }
    w.write_all(b"\"")
}

/// Format the MCC of a `PLMNidentity` (3GPP TS 36.413, Section 9.3.4:
/// "digits 0 to 9, encoded 0000 to 1001, 1111 used as filler digit", MCC
/// digit 1 in bits 4 to 1 of octet 1, as in TS 24.008 Figure 10.5.154).
fn format_mcc(v: &FieldValue<'_>, _ctx: &FormatContext<'_>, w: &mut dyn Write) -> io::Result<()> {
    let &FieldValue::Bytes(&[b0, b1, _]) = v else {
        return w.write_all(b"\"\"");
    };
    write_digits(w, &[b0 & 0x0f, b0 >> 4, b1 & 0x0f])
}

/// Format the MNC of a `PLMNidentity`; MNC digit 3 is the filler "1111"
/// for a two-digit MNC.
fn format_mnc(v: &FieldValue<'_>, _ctx: &FormatContext<'_>, w: &mut dyn Write) -> io::Result<()> {
    let &FieldValue::Bytes(&[_, b1, b2]) = v else {
        return w.write_all(b"\"\"");
    };
    write_digits(w, &[b2 & 0x0f, b2 >> 4, b1 >> 4])
}

// ── Field descriptors ──────────────────────────────────────────────────

macro_rules! plain {
    ($name:literal, $display:literal, $ty:ident) => {
        FieldDescriptor::new($name, $display, FieldType::$ty).optional()
    };
}

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

const FD_MME_UE_S1AP_ID: usize = 0;
const FD_ENB_UE_S1AP_ID: usize = 1;
const FD_CAUSE_GROUP: usize = 2;
const FD_CAUSE: usize = 3;
const FD_MCC: usize = 4;
const FD_MNC: usize = 5;
const FD_TAC: usize = 6;
const FD_CELL_IDENTITY: usize = 7;
const FD_ENB_ID_TYPE: usize = 8;
const FD_ENB_ID: usize = 9;
const FD_NAS_PDU: usize = 10;
const FD_ITEMS: usize = 11;
const FD_E_RAB_ID: usize = 12;
const FD_QCI: usize = 13;
const FD_PRIORITY_LEVEL: usize = 14;
const FD_PRE_EMPTION_CAPABILITY: usize = 15;
const FD_PRE_EMPTION_VULNERABILITY: usize = 16;
const FD_MBR_DL: usize = 17;
const FD_MBR_UL: usize = 18;
const FD_GBR_DL: usize = 19;
const FD_GBR_UL: usize = 20;
const FD_TRANSPORT_LAYER_ADDRESS: usize = 21;
const FD_GTP_TEID: usize = 22;
const FD_ENCRYPTION_ALGORITHMS: usize = 23;
const FD_INTEGRITY_ALGORITHMS: usize = 24;
const FD_MME_CODE: usize = 25;
const FD_M_TMSI: usize = 26;
const FD_NAME: usize = 27;
const FD_RRC_ESTABLISHMENT_CAUSE: usize = 28;
const FD_DEFAULT_PAGING_DRX: usize = 29;
const FD_UE_AMBR_DL: usize = 30;
const FD_UE_AMBR_UL: usize = 31;
const FD_NAS_RAW: usize = 32;

/// Fields of decoded IE values, pushed inside the IE object after `id`,
/// `criticality` and `length`.
pub(crate) static VALUE_FIELDS: &[FieldDescriptor] = &[
    plain!("mme_ue_s1ap_id", "MME UE S1AP ID", U32),
    plain!("enb_ue_s1ap_id", "eNB UE S1AP ID", U32),
    named!("cause_group", "Cause Group", cause_group_name),
    FieldDescriptor::new("cause", "Cause", FieldType::U8)
        .optional()
        .with_display_fn(|v, siblings| {
            let group = siblings
                .iter()
                .find(|f| f.name() == "cause_group")
                .and_then(|f| f.value.as_u8())?;
            let (_, e) = CAUSE_GROUPS.get(usize::from(group))?;
            match v {
                FieldValue::U8(c) => e.name(*c),
                _ => None,
            }
        }),
    FieldDescriptor::new("mcc", "MCC", FieldType::Bytes)
        .optional()
        .with_format_fn(format_mcc),
    FieldDescriptor::new("mnc", "MNC", FieldType::Bytes)
        .optional()
        .with_format_fn(format_mnc),
    plain!("tac", "TAC", U16),
    plain!("cell_identity", "Cell Identity", U32),
    named!("enb_id_type", "eNB ID Type", enb_id_type_name),
    plain!("enb_id", "eNB ID", U32),
    plain!("nas_pdu", "NAS-PDU", Object),
    plain!("items", "Items", Array),
    plain!("e_rab_id", "E-RAB ID", U8),
    plain!("qci", "QCI", U8),
    plain!("priority_level", "Priority Level", U8),
    named!(
        "pre_emption_capability",
        "Pre-emption Capability",
        pre_emption_capability_name
    ),
    named!(
        "pre_emption_vulnerability",
        "Pre-emption Vulnerability",
        pre_emption_vulnerability_name
    ),
    plain!("e_rab_maximum_bitrate_dl", "E-RAB Maximum Bitrate DL", U64),
    plain!("e_rab_maximum_bitrate_ul", "E-RAB Maximum Bitrate UL", U64),
    plain!(
        "e_rab_guaranteed_bitrate_dl",
        "E-RAB Guaranteed Bitrate DL",
        U64
    ),
    plain!(
        "e_rab_guaranteed_bitrate_ul",
        "E-RAB Guaranteed Bitrate UL",
        U64
    ),
    plain!("transport_layer_address", "Transport Layer Address", Any),
    plain!("gtp_teid", "GTP-TEID", U32),
    plain!("encryption_algorithms", "Encryption Algorithms", U16),
    plain!(
        "integrity_protection_algorithms",
        "Integrity Protection Algorithms",
        U16
    ),
    plain!("mme_code", "MME Code", U8),
    plain!("m_tmsi", "M-TMSI", U32),
    plain!("name", "Name", Bytes).with_format_fn(format_utf8_lossy),
    named!("rrc_establishment_cause", "RRC Establishment Cause", |v| {
        RRC_ESTABLISHMENT_CAUSE.name(v)
    }),
    named!("default_paging_drx", "Default Paging DRX", |v| PAGING_DRX
        .name(v)),
    plain!(
        "ue_aggregate_maximum_bitrate_dl",
        "UE Aggregate Maximum Bitrate DL",
        U64
    ),
    plain!(
        "ue_aggregate_maximum_bitrate_ul",
        "UE Aggregate Maximum Bitrate UL",
        U64
    ),
    plain!("raw", "Raw NAS-PDU", Bytes),
];

// ── Dispatch ───────────────────────────────────────────────────────────

/// Pushes the decoded value of IE `id`, or its raw octets.
///
/// `data` is the open type contents of the IE value and `offset` its
/// absolute packet offset. E-RAB lists are decoded only in the IE
/// container of a message, so the nesting depth is bounded.
pub(crate) fn push_ie_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    id: u16,
    data: &'pkt [u8],
    offset: usize,
    ctx: IeContext,
) {
    let mark = buf.fields().len();
    let mut out = Out { buf, offset };
    let result = match id {
        ID_MME_UE_S1AP_ID => whole(&mut out, data, FD_MME_UE_S1AP_ID, 0, u64::from(u32::MAX)),
        ID_ENB_UE_S1AP_ID => whole(&mut out, data, FD_ENB_UE_S1AP_ID, 0, 16_777_215),
        ID_CAUSE => read_all(&mut out, data, push_cause),
        ID_TAI => read_all(&mut out, data, push_tai),
        ID_EUTRAN_CGI => read_all(&mut out, data, push_eutran_cgi),
        ID_GLOBAL_ENB_ID => read_all(&mut out, data, push_global_enb_id),
        ID_S_TMSI => read_all(&mut out, data, push_s_tmsi),
        ID_UE_SECURITY_CAPABILITIES => read_all(&mut out, data, push_ue_security_capabilities),
        ID_UE_AGGREGATE_MAXIMUM_BITRATE => read_all(&mut out, data, push_ue_ambr),
        ID_ENB_NAME | ID_MME_NAME => read_all(&mut out, data, push_name),
        ID_RRC_ESTABLISHMENT_CAUSE => read_all(&mut out, data, |o, r| {
            push_enum(o, r, FD_RRC_ESTABLISHMENT_CAUSE, &RRC_ESTABLISHMENT_CAUSE)
        }),
        ID_DEFAULT_PAGING_DRX => read_all(&mut out, data, |o, r| {
            push_enum(o, r, FD_DEFAULT_PAGING_DRX, &PAGING_DRX)
        }),
        ID_NAS_PDU => read_all(&mut out, data, |o, r| push_nas_pdu(o, r, FD_NAS_PDU)),
        ID_E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ
        | ID_E_RAB_TO_BE_SETUP_LIST_BEARER_SU_REQ
        | ID_E_RAB_SETUP_LIST_CTXT_SU_RES
            if ctx == IeContext::Message =>
        {
            read_all(&mut out, data, |o, r| push_e_rab_list(o, r, data))
        }
        ID_E_RAB_TO_BE_SETUP_ITEM_CTXT_SU_REQ => read_all(&mut out, data, |o, r| {
            push_e_rab_to_be_setup_item(o, r, true)
        }),
        ID_E_RAB_TO_BE_SETUP_ITEM_BEARER_SU_REQ => read_all(&mut out, data, |o, r| {
            push_e_rab_to_be_setup_item(o, r, false)
        }),
        ID_E_RAB_SETUP_ITEM_CTXT_SU_RES => read_all(&mut out, data, push_e_rab_setup_item),
        _ => Err(PacketError::InvalidHeader("no decoder")),
    };
    if result.is_err() {
        buf.truncate_fields(mark);
        container::push_raw_value(buf, data, offset);
    }
}

/// Destination of decoded fields: the buffer and the absolute offset of
/// the IE value, to which reader-relative byte ranges are shifted.
struct Out<'b, 'pkt> {
    buf: &'b mut DissectBuffer<'pkt>,
    offset: usize,
}

impl<'pkt> Out<'_, 'pkt> {
    fn push(&mut self, fd: usize, value: FieldValue<'pkt>, range: Range<usize>) {
        let r = self.offset + range.start..self.offset + range.end;
        self.buf.push_field(&VALUE_FIELDS[fd], value, r);
    }
}

/// Runs `decode` over the whole value and checks that it was consumed.
fn read_all<'pkt>(
    out: &mut Out<'_, 'pkt>,
    data: &'pkt [u8],
    decode: impl FnOnce(&mut Out<'_, 'pkt>, &mut AperReader<'pkt>) -> Result<(), PacketError>,
) -> Result<(), PacketError> {
    let mut r = AperReader::new(data);
    decode(out, &mut r)?;
    ensure_consumed(&r, data)
}

/// A constrained INTEGER value (ITU-T Rec. X.691, Section 13.2.2 and
/// 11.5.7).
fn whole<'pkt>(
    out: &mut Out<'_, 'pkt>,
    data: &'pkt [u8],
    fd: usize,
    lb: u64,
    ub: u64,
) -> Result<(), PacketError> {
    read_all(out, data, |o, r| {
        let v = r.read_constrained_whole_number(lb, ub)?;
        o.push(
            fd,
            FieldValue::U32(v as u32),
            0..r.bit_position().div_ceil(8),
        );
        Ok(())
    })
}

// ── Decoders ───────────────────────────────────────────────────────────

/// Pushes an extensible ENUMERATED value.
fn push_enum(
    out: &mut Out<'_, '_>,
    r: &mut AperReader<'_>,
    fd: usize,
    e: &Enum,
) -> Result<(), PacketError> {
    let start = r.bit_position();
    let v = e.read(r)?;
    let range = r.byte_range_since(start);
    out.push(fd, FieldValue::U8(v), range);
    Ok(())
}

/// `Cause ::= CHOICE { radioNetwork, transport, nas, protocol, misc, ... }`
/// (3GPP TS 36.413, Section 9.3.4).
fn push_cause(out: &mut Out<'_, '_>, r: &mut AperReader<'_>) -> Result<(), PacketError> {
    let start = r.bit_position();
    let group = r.read_choice_index(CAUSE_GROUPS.len() as u64, true)?;
    // An extension alternative is an open type of unknown contents.
    let (_, e) = CAUSE_GROUPS
        .get(group as usize)
        .ok_or(PacketError::InvalidHeader("unknown Cause alternative"))?;
    let cause = e.read(r)?;
    let range = r.byte_range_since(start);
    out.push(FD_CAUSE_GROUP, FieldValue::U8(group as u8), range.clone());
    out.push(FD_CAUSE, FieldValue::U8(cause), range);
    Ok(())
}

/// Pushes a `PLMNidentity` (TBCD-STRING, OCTET STRING (SIZE (3))).
fn push_plmn<'pkt>(out: &mut Out<'_, 'pkt>, r: &mut AperReader<'pkt>) -> Result<(), PacketError> {
    let (plmn, range) = read_aligned_octets(r, 3)?;
    out.push(FD_MCC, FieldValue::Bytes(plmn), range.clone());
    out.push(FD_MNC, FieldValue::Bytes(plmn), range);
    Ok(())
}

/// `TAI ::= SEQUENCE { pLMNidentity, tAC OCTET STRING (SIZE (2)),
/// iE-Extensions OPTIONAL, ... }` (3GPP TS 36.413, Section 9.3.4). A
/// two-octet fixed OCTET STRING is not octet-aligned (ITU-T Rec. X.691,
/// Section 17.6), but follows the aligned PLMN identity here.
fn push_tai<'pkt>(out: &mut Out<'_, 'pkt>, r: &mut AperReader<'pkt>) -> Result<(), PacketError> {
    let (extended, opt) = read_sequence_preamble(r, 1)?;
    push_plmn(out, r)?;
    let start = r.bit_position();
    let tac = r.read_bits(16)? as u16;
    out.push(FD_TAC, FieldValue::U16(tac), r.byte_range_since(start));
    skip_sequence_tail(r, extended, opt == 1)
}

/// `EUTRAN-CGI ::= SEQUENCE { pLMNidentity, cell-ID BIT STRING (SIZE
/// (28)), iE-Extensions OPTIONAL, ... }` (3GPP TS 36.413, Section 9.3.4).
fn push_eutran_cgi<'pkt>(
    out: &mut Out<'_, 'pkt>,
    r: &mut AperReader<'pkt>,
) -> Result<(), PacketError> {
    let (extended, opt) = read_sequence_preamble(r, 1)?;
    push_plmn(out, r)?;
    let (cell, range) = read_bit_string_field(r, 28)?;
    out.push(FD_CELL_IDENTITY, FieldValue::U32(cell as u32), range);
    skip_sequence_tail(r, extended, opt == 1)
}

/// `Global-ENB-ID ::= SEQUENCE { pLMNidentity, eNB-ID, iE-Extensions
/// OPTIONAL, ... }` with `ENB-ID ::= CHOICE { macroENB-ID BIT STRING
/// (SIZE(20)), homeENB-ID BIT STRING (SIZE(28)), ..., short-macroENB-ID
/// BIT STRING (SIZE(18)), long-macroENB-ID BIT STRING (SIZE(21)) }`
/// (3GPP TS 36.413, Section 9.3.4).
fn push_global_enb_id<'pkt>(
    out: &mut Out<'_, 'pkt>,
    r: &mut AperReader<'pkt>,
) -> Result<(), PacketError> {
    let (extended, opt) = read_sequence_preamble(r, 1)?;
    push_plmn(out, r)?;
    let start = r.bit_position();
    let choice = r.read_choice_index(2, true)?;
    let &(_, bits) = ENB_ID_TYPES
        .get(choice as usize)
        .ok_or(PacketError::InvalidHeader("unknown ENB-ID alternative"))?;
    let id = if choice < 2 {
        let (id, _) = read_bit_string_field(r, bits)?;
        id
    } else {
        // ITU-T Rec. X.691, Section 23.8: an extension alternative is
        // encoded as an open type.
        let len = r.read_length(0, None)?;
        let inner = r.read_octets(len as usize)?;
        let mut ir = AperReader::new(inner);
        let (id, _) = read_bit_string_field(&mut ir, bits)?;
        ensure_consumed(&ir, inner)?;
        id
    };
    let range = r.byte_range_since(start);
    out.push(FD_ENB_ID_TYPE, FieldValue::U8(choice as u8), range.clone());
    out.push(FD_ENB_ID, FieldValue::U32(id as u32), range);
    skip_sequence_tail(r, extended, opt == 1)
}

/// `S-TMSI ::= SEQUENCE { mMEC MME-Code, m-TMSI M-TMSI, iE-Extensions
/// OPTIONAL, ... }` with `MME-Code ::= OCTET STRING (SIZE (1))` and
/// `M-TMSI ::= OCTET STRING (SIZE (4))` (3GPP TS 36.413, Section 9.3.4).
fn push_s_tmsi<'pkt>(out: &mut Out<'_, 'pkt>, r: &mut AperReader<'pkt>) -> Result<(), PacketError> {
    let (extended, opt) = read_sequence_preamble(r, 1)?;
    let start = r.bit_position();
    let mmec = r.read_bits(8)? as u8;
    out.push(FD_MME_CODE, FieldValue::U8(mmec), r.byte_range_since(start));
    let (tmsi, range) = read_aligned_octets(r, 4)?;
    let tmsi = u32::from_be_bytes([tmsi[0], tmsi[1], tmsi[2], tmsi[3]]);
    out.push(FD_M_TMSI, FieldValue::U32(tmsi), range);
    skip_sequence_tail(r, extended, opt == 1)
}

/// Reads a `BIT STRING (SIZE (16,...))` (ITU-T Rec. X.691, Section 16.6
/// and 16.9): an extension bit, then 16 bits; an extended size is not
/// decoded.
fn read_algorithms(r: &mut AperReader<'_>) -> Result<u16, PacketError> {
    if r.read_bit()? {
        return Err(PacketError::InvalidHeader(
            "extended algorithm bit string not decoded",
        ));
    }
    Ok(r.read_bits(16)? as u16)
}

/// `UESecurityCapabilities ::= SEQUENCE { encryptionAlgorithms,
/// integrityProtectionAlgorithms, iE-Extensions OPTIONAL, ... }` (3GPP TS
/// 36.413, Section 9.3.4).
fn push_ue_security_capabilities(
    out: &mut Out<'_, '_>,
    r: &mut AperReader<'_>,
) -> Result<(), PacketError> {
    let (extended, opt) = read_sequence_preamble(r, 1)?;
    let start = r.bit_position();
    let eea = read_algorithms(r)?;
    out.push(
        FD_ENCRYPTION_ALGORITHMS,
        FieldValue::U16(eea),
        r.byte_range_since(start),
    );
    let start = r.bit_position();
    let eia = read_algorithms(r)?;
    out.push(
        FD_INTEGRITY_ALGORITHMS,
        FieldValue::U16(eia),
        r.byte_range_since(start),
    );
    skip_sequence_tail(r, extended, opt == 1)
}

/// Pushes a `BitRate ::= INTEGER (0..10000000000)`.
fn push_bit_rate(
    out: &mut Out<'_, '_>,
    r: &mut AperReader<'_>,
    fd: usize,
) -> Result<(), PacketError> {
    let start = r.bit_position();
    let v = r.read_constrained_whole_number(0, BIT_RATE_MAX)?;
    out.push(fd, FieldValue::U64(v), r.byte_range_since(start));
    Ok(())
}

/// `UEAggregateMaximumBitrate ::= SEQUENCE { uEaggregateMaximumBitRateDL,
/// uEaggregateMaximumBitRateUL, iE-Extensions OPTIONAL, ... }` (3GPP TS
/// 36.413, Section 9.3.4).
fn push_ue_ambr(out: &mut Out<'_, '_>, r: &mut AperReader<'_>) -> Result<(), PacketError> {
    let (extended, opt) = read_sequence_preamble(r, 1)?;
    push_bit_rate(out, r, FD_UE_AMBR_DL)?;
    push_bit_rate(out, r, FD_UE_AMBR_UL)?;
    skip_sequence_tail(r, extended, opt == 1)
}

/// `ENBname` / `MMEname ::= PrintableString (SIZE (1..150,...))` (3GPP TS
/// 36.413, Section 9.3.4): an extension bit, the length as a constrained
/// whole number, then one octet-aligned octet per character (ITU-T Rec.
/// X.691, Section 30.5.7, ALIGNED variant with 8-bit characters).
fn push_name<'pkt>(out: &mut Out<'_, 'pkt>, r: &mut AperReader<'pkt>) -> Result<(), PacketError> {
    let len = if r.read_bit()? {
        r.read_length(0, None)?
    } else {
        r.read_length(1, Some(150))?
    };
    let (name, range) = read_aligned_octets(r, len as usize)?;
    out.push(FD_NAME, FieldValue::Bytes(name), range);
    Ok(())
}

/// `NAS-PDU ::= OCTET STRING` (3GPP TS 36.413, Section 9.3.4): a length
/// determinant then the octets, decoded as an EPS NAS message (TS 24.301)
/// in a `nas_pdu` object.
fn push_nas_pdu<'pkt>(
    out: &mut Out<'_, 'pkt>,
    r: &mut AperReader<'pkt>,
    fd: usize,
) -> Result<(), PacketError> {
    let len = r.read_length(0, None)?;
    let (nas, range) = read_aligned_octets(r, len as usize)?;
    let at = out.offset + range.start;
    let abs = at..out.offset + range.end;
    let obj = out
        .buf
        .begin_container(&VALUE_FIELDS[fd], FieldValue::Object(0..0), abs.clone());
    if !packet_dissector_nas_eps::push_nas_pdu(out.buf, nas, at) {
        out.buf
            .push_field(&VALUE_FIELDS[FD_NAS_RAW], FieldValue::Bytes(nas), abs);
    }
    out.buf.end_container(obj);
    Ok(())
}

/// An E-RAB list: `SEQUENCE (SIZE(1..maxnoofE-RABs)) OF
/// ProtocolIE-SingleContainer` (3GPP TS 36.413, Section 9.3.3,
/// `E-RAB-IE-ContainerList`). Each item is pushed as an IE object in an
/// `items` array.
fn push_e_rab_list<'pkt>(
    out: &mut Out<'_, 'pkt>,
    r: &mut AperReader<'pkt>,
    value: &'pkt [u8],
) -> Result<(), PacketError> {
    // The count is a constrained whole number with a range of 256: one
    // octet-aligned octet (ITU-T Rec. X.691, Section 11.5.7.2), so the
    // items start on an octet boundary.
    let count = r.read_length(1, Some(MAX_NO_OF_E_RABS))?;
    let start = r.bit_position() / 8;
    let data = &value[start..];
    let arr = out.buf.begin_container(
        &VALUE_FIELDS[FD_ITEMS],
        FieldValue::Array(0..0),
        out.offset + start..out.offset + start + data.len(),
    );
    let mut pos = 0;
    for _ in 0..count {
        pos = container::push_ie(out.buf, data, pos, out.offset + start, IeContext::Item)
            .map_err(PacketError::InvalidHeader)?;
    }
    if let Some(f) = out.buf.field_mut(arr as usize) {
        f.range = out.offset + start..out.offset + start + pos;
    }
    out.buf.end_container(arr);
    // Advance the reader past the items with the same framing.
    for _ in 0..count {
        skip_protocol_ie_single_container(r)?;
    }
    Ok(())
}

/// `E-RABLevelQoSParameters ::= SEQUENCE { qCI QCI,
/// allocationRetentionPriority, gbrQosInformation OPTIONAL, iE-Extensions
/// OPTIONAL, ... }` (3GPP TS 36.413, Section 9.3.4).
fn push_e_rab_qos(out: &mut Out<'_, '_>, r: &mut AperReader<'_>) -> Result<(), PacketError> {
    let (extended, opt) = read_sequence_preamble(r, 2)?;
    // QCI ::= INTEGER (0..255): one octet-aligned octet.
    let start = r.bit_position();
    let qci = r.read_constrained_whole_number(0, 255)? as u8;
    out.push(FD_QCI, FieldValue::U8(qci), r.byte_range_since(start));
    // AllocationAndRetentionPriority ::= SEQUENCE { priorityLevel INTEGER
    // (0..15), pre-emptionCapability, pre-emptionVulnerability,
    // iE-Extensions OPTIONAL, ... }
    let (arp_ext, arp_opt) = read_sequence_preamble(r, 1)?;
    let start = r.bit_position();
    let level = r.read_constrained_whole_number(0, 15)? as u8;
    let cap = r.read_enumerated(2, false)? as u8;
    let vul = r.read_enumerated(2, false)? as u8;
    let range = r.byte_range_since(start);
    out.push(FD_PRIORITY_LEVEL, FieldValue::U8(level), range.clone());
    out.push(
        FD_PRE_EMPTION_CAPABILITY,
        FieldValue::U8(cap),
        range.clone(),
    );
    out.push(FD_PRE_EMPTION_VULNERABILITY, FieldValue::U8(vul), range);
    skip_sequence_tail(r, arp_ext, arp_opt == 1)?;
    if opt & 0b10 != 0 {
        // GBR-QosInformation ::= SEQUENCE { four BitRates, iE-Extensions
        // OPTIONAL, ... }
        let (gbr_ext, gbr_opt) = read_sequence_preamble(r, 1)?;
        for fd in [FD_MBR_DL, FD_MBR_UL, FD_GBR_DL, FD_GBR_UL] {
            push_bit_rate(out, r, fd)?;
        }
        skip_sequence_tail(r, gbr_ext, gbr_opt == 1)?;
    }
    skip_sequence_tail(r, extended, opt & 0b01 != 0)
}

/// Pushes the E-RAB ID, `INTEGER (0..15, ...)`.
fn push_e_rab_id(out: &mut Out<'_, '_>, r: &mut AperReader<'_>) -> Result<(), PacketError> {
    let start = r.bit_position();
    // ITU-T Rec. X.691, Section 13.1: an extension bit, then the value.
    if r.read_bit()? {
        return Err(PacketError::InvalidHeader("extended E-RAB-ID not decoded"));
    }
    let id = r.read_bits(4)? as u8;
    out.push(FD_E_RAB_ID, FieldValue::U8(id), r.byte_range_since(start));
    Ok(())
}

/// Pushes a `TransportLayerAddress ::= BIT STRING (SIZE(1..160, ...))`
/// and a `GTP-TEID ::= OCTET STRING (SIZE (4))` (3GPP TS 36.413, Section
/// 9.3.4). A 32-bit address is shown as IPv4 and a 128-bit one as IPv6;
/// other sizes (such as the 160-bit IPv4 and IPv6 pair) are kept as octets.
fn push_tla_teid<'pkt>(
    out: &mut Out<'_, 'pkt>,
    r: &mut AperReader<'pkt>,
) -> Result<(), PacketError> {
    if r.read_bit()? {
        return Err(PacketError::InvalidHeader(
            "extended TransportLayerAddress not decoded",
        ));
    }
    let bits = r.read_length(1, Some(160))? as usize;
    // ITU-T Rec. X.691, Section 16.11: more than 16 bits are octet-aligned;
    // the contents occupy whole octets with trailing padding bits.
    if bits <= 16 {
        return Err(PacketError::InvalidHeader(
            "TransportLayerAddress shorter than an IP address",
        ));
    }
    let (addr, range) = read_aligned_octets(r, bits.div_ceil(8))?;
    let value = match (bits, addr) {
        (32, &[a, b, c, d]) => FieldValue::Ipv4Addr([a, b, c, d]),
        (128, _) => {
            let mut v6 = [0u8; 16];
            v6.copy_from_slice(addr);
            FieldValue::Ipv6Addr(v6)
        }
        _ => FieldValue::Bytes(addr),
    };
    out.push(FD_TRANSPORT_LAYER_ADDRESS, value, range);
    let (teid, range) = read_aligned_octets(r, 4)?;
    let teid = u32::from_be_bytes([teid[0], teid[1], teid[2], teid[3]]);
    out.push(FD_GTP_TEID, FieldValue::U32(teid), range);
    Ok(())
}

/// `E-RABToBeSetupItemCtxtSUReq` (nAS-PDU OPTIONAL) and
/// `E-RABToBeSetupItemBearerSUReq` (nAS-PDU mandatory) ::= SEQUENCE {
/// e-RAB-ID, e-RABlevelQoSParameters, transportLayerAddress, gTP-TEID,
/// nAS-PDU, iE-Extensions OPTIONAL, ... } (3GPP TS 36.413, Section 9.3.3).
fn push_e_rab_to_be_setup_item<'pkt>(
    out: &mut Out<'_, 'pkt>,
    r: &mut AperReader<'pkt>,
    nas_optional: bool,
) -> Result<(), PacketError> {
    let (extended, opt, has_nas) = if nas_optional {
        let (e, o) = read_sequence_preamble(r, 2)?;
        (e, o & 0b01, o & 0b10 != 0)
    } else {
        let (e, o) = read_sequence_preamble(r, 1)?;
        (e, o, true)
    };
    push_e_rab_id(out, r)?;
    push_e_rab_qos(out, r)?;
    push_tla_teid(out, r)?;
    if has_nas {
        push_nas_pdu(out, r, FD_NAS_PDU)?;
    }
    skip_sequence_tail(r, extended, opt == 1)
}

/// `E-RABSetupItemCtxtSURes ::= SEQUENCE { e-RAB-ID,
/// transportLayerAddress, gTP-TEID, iE-Extensions OPTIONAL, ... }` (3GPP
/// TS 36.413, Section 9.3.3).
fn push_e_rab_setup_item<'pkt>(
    out: &mut Out<'_, 'pkt>,
    r: &mut AperReader<'pkt>,
) -> Result<(), PacketError> {
    let (extended, opt) = read_sequence_preamble(r, 1)?;
    push_e_rab_id(out, r)?;
    push_tla_teid(out, r)?;
    skip_sequence_tail(r, extended, opt == 1)
}
