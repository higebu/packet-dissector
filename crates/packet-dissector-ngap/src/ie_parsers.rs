//! Per-IE-type value parsers for NGAP.
//!
//! Parses APER-encoded IE values into structured fields pushed directly
//! into a [`DissectBuffer`]. Unknown IE types, and values that cannot be
//! decoded, fall back to raw bytes.
//!
//! ## References
//! - 3GPP TS 38.413: <https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/>
//! - ITU-T Rec. X.691 (APER): <https://www.itu.int/rec/T-REC-X.691>

use core::ops::Range;

use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;

use crate::aper::AperReader;

// ── Field descriptors ──────────────────────────────────────────────────

static FD_AMF_UE_NGAP_ID: FieldDescriptor =
    FieldDescriptor::new("amf_ue_ngap_id", "AMF-UE-NGAP-ID", FieldType::U64);

static FD_RAN_UE_NGAP_ID: FieldDescriptor =
    FieldDescriptor::new("ran_ue_ngap_id", "RAN-UE-NGAP-ID", FieldType::U32);

static FD_RELATIVE_AMF_CAPACITY: FieldDescriptor = FieldDescriptor::new(
    "relative_amf_capacity",
    "Relative AMF Capacity",
    FieldType::U8,
);

static FD_CAUSE_GROUP: FieldDescriptor = FieldDescriptor {
    name: "cause_group",
    display_name: "Cause Group",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(g) => Some(cause_group_name(*g)),
        _ => None,
    }),
    format_fn: None,
};

static FD_CAUSE_VALUE: FieldDescriptor =
    FieldDescriptor::new("cause_value", "Cause Value", FieldType::U8);

static FD_RRC_ESTABLISHMENT_CAUSE: FieldDescriptor = FieldDescriptor {
    name: "rrc_establishment_cause",
    display_name: "RRC Establishment Cause",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(c) => Some(rrc_establishment_cause_name(*c)),
        _ => None,
    }),
    format_fn: None,
};

static FD_UE_CONTEXT_REQUEST: FieldDescriptor = FieldDescriptor {
    name: "ue_context_request",
    display_name: "UE Context Request",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(c) => Some(ue_context_request_name(*c)),
        _ => None,
    }),
    format_fn: None,
};

static FD_DEFAULT_PAGING_DRX: FieldDescriptor = FieldDescriptor {
    name: "default_paging_drx",
    display_name: "Default Paging DRX",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(c) => Some(paging_drx_name(*c)),
        _ => None,
    }),
    format_fn: None,
};

static FD_NAME_STRING: FieldDescriptor =
    FieldDescriptor::new("name", "Name", FieldType::Bytes).with_format_fn(format_utf8_lossy);

static FD_SST: FieldDescriptor = FieldDescriptor::new("sst", "SST", FieldType::U8);

static FD_SD: FieldDescriptor = FieldDescriptor::new("sd", "SD", FieldType::U32).optional();

static FD_PLMN_IDENTITY: FieldDescriptor =
    FieldDescriptor::new("plmn_identity", "PLMN Identity", FieldType::Bytes);

static FD_AMF_REGION_ID: FieldDescriptor =
    FieldDescriptor::new("amf_region_id", "AMF Region ID", FieldType::U8);

static FD_AMF_SET_ID: FieldDescriptor =
    FieldDescriptor::new("amf_set_id", "AMF Set ID", FieldType::U16);

static FD_AMF_POINTER: FieldDescriptor =
    FieldDescriptor::new("amf_pointer", "AMF Pointer", FieldType::U8);

static FD_GNB_ID_CHOICE: FieldDescriptor = FieldDescriptor {
    name: "choice",
    display_name: "Choice",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(c) => Some(global_ran_node_id_choice_name(*c)),
        _ => None,
    }),
    format_fn: None,
};

static FD_GNB_ID: FieldDescriptor =
    FieldDescriptor::new("gnb_id", "gNB ID", FieldType::U32).optional();

static FD_GNB_ID_LENGTH: FieldDescriptor =
    FieldDescriptor::new("gnb_id_length", "gNB ID Length", FieldType::U8).optional();

static FD_ULI_CHOICE: FieldDescriptor = FieldDescriptor {
    name: "choice",
    display_name: "Choice",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(c) => Some(uli_choice_name(*c)),
        _ => None,
    }),
    format_fn: None,
};

static FD_NR_CELL_IDENTITY: FieldDescriptor =
    FieldDescriptor::new("nr_cell_identity", "NR Cell Identity", FieldType::U64).optional();

static FD_EUTRA_CELL_IDENTITY: FieldDescriptor = FieldDescriptor::new(
    "eutra_cell_identity",
    "E-UTRA Cell Identity",
    FieldType::U32,
)
.optional();

static FD_TAC: FieldDescriptor = FieldDescriptor::new("tac", "TAC", FieldType::U32).optional();

static FD_TIME_STAMP: FieldDescriptor =
    FieldDescriptor::new("time_stamp", "Time Stamp", FieldType::U32).optional();

static FD_NAS_PDU: FieldDescriptor = FieldDescriptor::new("nas_pdu", "NAS-PDU", FieldType::Object);

static FD_HANDOVER_TYPE: FieldDescriptor = FieldDescriptor {
    name: "handover_type",
    display_name: "Handover Type",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(c) => Some(handover_type_name(*c)),
        _ => None,
    }),
    format_fn: None,
};

static FD_TIME_TO_WAIT: FieldDescriptor = FieldDescriptor {
    name: "time_to_wait",
    display_name: "Time to Wait",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(c) => Some(time_to_wait_name(*c)),
        _ => None,
    }),
    format_fn: None,
};

/// Descriptor used for the IE value fallback field.
static FD_IE_VALUE_FALLBACK: FieldDescriptor =
    FieldDescriptor::new("value", "Value", FieldType::Bytes);

// ── Public API ─────────────────────────────────────────────────────────

/// Push an NGAP IE value's structured fields into the buffer based on
/// the IE ID. For unknown IE types, or values that cannot be decoded,
/// pushes a raw bytes field.
///
/// Each IE value is an open type, so it starts on an octet boundary and
/// is decoded with ALIGNED PER from its first bit.
///
/// 3GPP TS 38.413, Section 9.3 — NGAP Information Elements.
/// 3GPP TS 38.413, Section 9.5 — Message Transfer Syntax (APER).
pub fn push_ie_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    ie_id: u16,
    data: &'pkt [u8],
    offset: usize,
) {
    let pushed = match ie_id {
        1 => push_printable_name(buf, data, offset),  // AMFName
        10 => push_amf_ue_ngap_id(buf, data, offset), // AMF-UE-NGAP-ID
        15 => push_cause(buf, data, offset),          // Cause
        21 => push_enumerated(
            buf,
            &FD_DEFAULT_PAGING_DRX,
            PAGING_DRX_ROOT_COUNT,
            data,
            offset,
        ), // DefaultPagingDRX
        25 => push_eutra_cgi(buf, data, offset),      // EUTRA-CGI
        27 => push_global_ran_node_id(buf, data, offset), // GlobalRANNodeID
        28 => push_guami(buf, data, offset),          // GUAMI
        29 => push_enumerated(
            buf,
            &FD_HANDOVER_TYPE,
            HANDOVER_TYPE_ROOT_COUNT,
            data,
            offset,
        ), // HandoverType
        38 => push_nas_pdu(buf, data, offset),        // NAS-PDU
        45 => push_nr_cgi(buf, data, offset),         // NR-CGI
        82 => push_printable_name(buf, data, offset), // RANNodeName
        85 => push_ran_ue_ngap_id(buf, data, offset), // RAN-UE-NGAP-ID
        86 => push_relative_amf_capacity(buf, data, offset), // RelativeAMFCapacity
        90 => push_enumerated(
            buf,
            &FD_RRC_ESTABLISHMENT_CAUSE,
            RRC_ESTABLISHMENT_CAUSE_ROOT_COUNT,
            data,
            offset,
        ), // RRCEstablishmentCause
        107 => push_enumerated(buf, &FD_TIME_TO_WAIT, TIME_TO_WAIT_ROOT_COUNT, data, offset), // TimeToWait
        112 => push_enumerated(
            buf,
            &FD_UE_CONTEXT_REQUEST,
            UE_CONTEXT_REQUEST_ROOT_COUNT,
            data,
            offset,
        ), // UEContextRequest
        121 => push_user_location_information(buf, data, offset), // UserLocationInformation
        148 => push_s_nssai(buf, data, offset),                   // S-NSSAI
        _ => false,
    };

    if !pushed {
        // Fallback: raw bytes for unknown or unparseable IE values.
        buf.push_field(
            &FD_IE_VALUE_FALLBACK,
            FieldValue::Bytes(data),
            offset..offset + data.len(),
        );
    }
}

// ── ASN.1 constants ────────────────────────────────────────────────────

/// `AMF-UE-NGAP-ID ::= INTEGER (0..1099511627775)`.
///
/// 3GPP TS 38.413, Section 9.4.5.
const AMF_UE_NGAP_ID_MAX: u64 = 1_099_511_627_775;

/// `RAN-UE-NGAP-ID ::= INTEGER (0..4294967295)`.
///
/// 3GPP TS 38.413, Section 9.4.5.
const RAN_UE_NGAP_ID_MAX: u64 = 4_294_967_295;

/// Number of root values of `RRCEstablishmentCause` (extensible).
///
/// 3GPP TS 38.413, Section 9.4.5.
const RRC_ESTABLISHMENT_CAUSE_ROOT_COUNT: u64 = 10;

/// Number of root values of `UEContextRequest` (extensible).
///
/// 3GPP TS 38.413, Section 9.4.5.
const UE_CONTEXT_REQUEST_ROOT_COUNT: u64 = 1;

/// Number of root values of `PagingDRX` (extensible).
///
/// 3GPP TS 38.413, Section 9.4.5.
const PAGING_DRX_ROOT_COUNT: u64 = 4;

/// Number of root values of `HandoverType` (extensible).
///
/// 3GPP TS 38.413, Section 9.4.5.
const HANDOVER_TYPE_ROOT_COUNT: u64 = 3;

/// Number of root values of `TimeToWait` (extensible).
///
/// 3GPP TS 38.413, Section 9.4.5.
const TIME_TO_WAIT_ROOT_COUNT: u64 = 6;

/// Number of alternatives of `Cause` (no extension marker; the last
/// alternative is `choice-Extensions`).
///
/// 3GPP TS 38.413, Section 9.4.5.
const CAUSE_CHOICE_COUNT: u64 = 6;

/// Number of alternatives of `GlobalRANNodeID` and
/// `UserLocationInformation` (no extension marker; the last alternative
/// is `choice-Extensions`).
///
/// 3GPP TS 38.413, Section 9.4.5.
const RAN_NODE_AND_ULI_CHOICE_COUNT: u64 = 4;

/// Number of alternatives of `GNB-ID` (`gNB-ID`, `choice-Extensions`).
///
/// 3GPP TS 38.413, Section 9.4.5.
const GNB_ID_CHOICE_COUNT: u64 = 2;

/// `maxProtocolExtensions`.
///
/// 3GPP TS 38.413, Section 9.4.7.
const MAX_PROTOCOL_EXTENSIONS: u64 = 65535;

/// Returns the number of root values of the ENUMERATED type carried by
/// Cause alternative `group`, or `None` for `choice-Extensions`.
///
/// 3GPP TS 38.413, Section 9.4.5 — CauseRadioNetwork, CauseTransport,
/// CauseNas, CauseProtocol and CauseMisc are all extensible.
fn cause_root_count(group: u64) -> Option<u64> {
    match group {
        0 => Some(45), // CauseRadioNetwork
        1 => Some(2),  // CauseTransport
        2 => Some(4),  // CauseNas
        3 => Some(7),  // CauseProtocol
        4 => Some(6),  // CauseMisc
        _ => None,     // choice-Extensions
    }
}

// ── Shared APER decoding helpers ───────────────────────────────────────

/// Shifts a byte range relative to the IE value by `offset`.
fn shift(range: Range<usize>, offset: usize) -> Range<usize> {
    range.start + offset..range.end + offset
}

/// Reads an octet-aligned fixed-size OCTET STRING of `n` (> 2) octets and
/// returns it with its byte range relative to the IE value.
///
/// ITU-T Rec. X.691, Section 17.7.
fn read_aligned_octets<'a>(
    r: &mut AperReader<'a>,
    n: usize,
) -> Result<(&'a [u8], Range<usize>), PacketError> {
    let octets = r.read_octets(n)?;
    let end = r.bit_position() / 8;
    Ok((octets, end - n..end))
}

/// Reads a fixed-size BIT STRING of `n` bits and returns the value with
/// its byte range relative to the IE value.
///
/// ITU-T Rec. X.691, Section 16.9–16.10.
fn read_bit_string_field(
    r: &mut AperReader<'_>,
    n: u32,
) -> Result<(u64, Range<usize>), PacketError> {
    if n > 16 {
        r.align();
    }
    let start = r.bit_position();
    let value = r.read_fixed_bit_string(n)?;
    Ok((value, r.byte_range_since(start)))
}

/// Skips a `ProtocolExtensionContainer`.
///
/// 3GPP TS 38.413, Section 9.4.8 — `SEQUENCE (SIZE (1..maxProtocolExtensions))
/// OF ProtocolExtensionField`, each field being `id` (INTEGER
/// (0..65535)), `criticality` (ENUMERATED {reject, ignore, notify}) and
/// `extensionValue` (open type, ITU-T Rec. X.691, Section 11.2).
fn skip_protocol_extension_container(r: &mut AperReader<'_>) -> Result<(), PacketError> {
    let count = r.read_length(1, Some(MAX_PROTOCOL_EXTENSIONS))?;
    for _ in 0..count {
        r.read_constrained_whole_number(0, 65535)?;
        r.read_enumerated(3, false)?;
        let len = r.read_length(0, None)?;
        r.read_octets(len as usize)?;
    }
    Ok(())
}

/// Skips the extension additions of an extensible SEQUENCE whose
/// extension bit was set.
///
/// ITU-T Rec. X.691, Section 19.8–19.9: a normally small length giving
/// the size of the presence bitmap, the bitmap, then each present
/// addition as an open type.
fn skip_sequence_extension_additions(r: &mut AperReader<'_>) -> Result<(), PacketError> {
    let count = r.read_normally_small()?.saturating_add(1);
    let mut present = 0u64;
    for _ in 0..count {
        if r.read_bit()? {
            present += 1;
        }
    }
    for _ in 0..present {
        let len = r.read_length(0, None)?;
        r.read_octets(len as usize)?;
    }
    Ok(())
}

/// Reads the preamble of an extensible SEQUENCE with a single OPTIONAL
/// `iE-Extensions` component. Returns `(extended, has_ie_extensions)`.
///
/// ITU-T Rec. X.691, Section 19.1 (extension bit) and 19.2 (bitmap of
/// OPTIONAL components).
fn read_sequence_preamble(r: &mut AperReader<'_>) -> Result<(bool, bool), PacketError> {
    let extended = r.read_bit()?;
    let has_ie_extensions = r.read_bit()?;
    Ok((extended, has_ie_extensions))
}

/// Skips what follows the root components of an extensible SEQUENCE:
/// the `iE-Extensions` container and the extension additions.
fn skip_sequence_tail(
    r: &mut AperReader<'_>,
    extended: bool,
    has_ie_extensions: bool,
) -> Result<(), PacketError> {
    if has_ie_extensions {
        skip_protocol_extension_container(r)?;
    }
    if extended {
        skip_sequence_extension_additions(r)?;
    }
    Ok(())
}

/// A decoded NR-CGI or E-UTRA CGI.
struct Cgi<'a> {
    plmn: &'a [u8],
    plmn_range: Range<usize>,
    cell_identity: u64,
    cell_identity_range: Range<usize>,
}

/// Reads an NR-CGI (36-bit cell identity) or E-UTRA CGI (28-bit cell
/// identity).
///
/// 3GPP TS 38.413, Section 9.4.5 — `NR-CGI ::= SEQUENCE { pLMNIdentity,
/// nRCellIdentity BIT STRING (SIZE(36)), iE-Extensions OPTIONAL, ... }`
/// and `EUTRA-CGI` with `eUTRACellIdentity BIT STRING (SIZE(28))`.
fn read_cgi<'a>(r: &mut AperReader<'a>, cell_identity_bits: u32) -> Result<Cgi<'a>, PacketError> {
    let (extended, has_ie_extensions) = read_sequence_preamble(r)?;
    let (plmn, plmn_range) = read_aligned_octets(r, 3)?;
    let (cell_identity, cell_identity_range) = read_bit_string_field(r, cell_identity_bits)?;
    skip_sequence_tail(r, extended, has_ie_extensions)?;
    Ok(Cgi {
        plmn,
        plmn_range,
        cell_identity,
        cell_identity_range,
    })
}

/// A decoded TAI.
struct Tai<'a> {
    plmn: &'a [u8],
    plmn_range: Range<usize>,
    tac: u32,
    tac_range: Range<usize>,
}

/// Reads a TAI.
///
/// 3GPP TS 38.413, Section 9.4.5 — `TAI ::= SEQUENCE { pLMNIdentity,
/// tAC OCTET STRING (SIZE(3)), iE-Extensions OPTIONAL, ... }`.
fn read_tai<'a>(r: &mut AperReader<'a>) -> Result<Tai<'a>, PacketError> {
    let (extended, has_ie_extensions) = read_sequence_preamble(r)?;
    let (plmn, plmn_range) = read_aligned_octets(r, 3)?;
    let (tac, tac_range) = read_aligned_octets(r, 3)?;
    skip_sequence_tail(r, extended, has_ie_extensions)?;
    Ok(Tai {
        plmn,
        plmn_range,
        tac: (u32::from(tac[0]) << 16) | (u32::from(tac[1]) << 8) | u32::from(tac[2]),
        tac_range,
    })
}

// ── Individual IE parsers ──────────────────────────────────────────────

/// AMF-UE-NGAP-ID (IE 10) — INTEGER (0..1099511627775).
///
/// The range exceeds 64K, so the value is encoded with the indefinite
/// length case: a 3-bit length (1..5 octets), padding, then the value in
/// the minimum number of octets.
///
/// 3GPP TS 38.413, Section 9.3.3.1; ITU-T Rec. X.691, Section 11.5.7.4.
fn push_amf_ue_ngap_id<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let mut r = AperReader::new(data);
    let Ok(value) = r.read_constrained_whole_number(0, AMF_UE_NGAP_ID_MAX) else {
        return false;
    };
    buf.push_field(
        &FD_AMF_UE_NGAP_ID,
        FieldValue::U64(value),
        shift(r.byte_range_since(0), offset),
    );
    true
}

/// RAN-UE-NGAP-ID (IE 85) — INTEGER (0..4294967295).
///
/// Encoded like AMF-UE-NGAP-ID with a 2-bit length (1..4 octets).
///
/// 3GPP TS 38.413, Section 9.3.3.2; ITU-T Rec. X.691, Section 11.5.7.4.
fn push_ran_ue_ngap_id<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let mut r = AperReader::new(data);
    let Some(value) = r
        .read_constrained_whole_number(0, RAN_UE_NGAP_ID_MAX)
        .ok()
        .and_then(|v| u32::try_from(v).ok())
    else {
        return false;
    };
    buf.push_field(
        &FD_RAN_UE_NGAP_ID,
        FieldValue::U32(value),
        shift(r.byte_range_since(0), offset),
    );
    true
}

/// Cause (IE 15) — CHOICE { radioNetwork, transport, nas, protocol, misc,
/// choice-Extensions }.
///
/// APER encoding: a 3-bit choice index (6 alternatives, no extension
/// marker) immediately followed by the extensible ENUMERATED value of the
/// chosen group. `choice-Extensions` reports only the group.
///
/// 3GPP TS 38.413, Section 9.3.1.2; ITU-T Rec. X.691, Sections 14, 23.
fn push_cause<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    let mut r = AperReader::new(data);
    let Ok(group) = r.read_choice_index(CAUSE_CHOICE_COUNT, false) else {
        return false;
    };
    let group_range = r.byte_range_since(0);

    let value = match cause_root_count(group) {
        Some(root_count) => {
            let start = r.bit_position();
            let Some(value) = r
                .read_enumerated(root_count, true)
                .ok()
                .and_then(|v| u8::try_from(v).ok())
            else {
                return false;
            };
            Some((value, r.byte_range_since(start)))
        }
        None => None,
    };

    // `group` is at most 5 (3-bit constrained whole number 0..5).
    buf.push_field(
        &FD_CAUSE_GROUP,
        FieldValue::U8(group as u8),
        shift(group_range, offset),
    );
    if let Some((value, range)) = value {
        buf.push_field(&FD_CAUSE_VALUE, FieldValue::U8(value), shift(range, offset));
    }
    true
}

/// RelativeAMFCapacity (IE 86) — INTEGER (0..255).
///
/// A range of 256 is the one-octet case.
///
/// 3GPP TS 38.413, Section 9.3.1.32; ITU-T Rec. X.691, Section 11.5.7.2.
fn push_relative_amf_capacity<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let mut r = AperReader::new(data);
    let Ok(value) = r.read_constrained_whole_number(0, 255) else {
        return false;
    };
    // The constraint guarantees `value <= 255`.
    buf.push_field(
        &FD_RELATIVE_AMF_CAPACITY,
        FieldValue::U8(value as u8),
        shift(r.byte_range_since(0), offset),
    );
    true
}

/// Extensible ENUMERATED IEs with `root_count` root values:
///
/// - RRCEstablishmentCause (IE 90) — 3GPP TS 38.413, Section 9.3.1.111
/// - UEContextRequest (IE 112) — 3GPP TS 38.413, Section 9.2.5.1
/// - DefaultPagingDRX (IE 21) — PagingDRX, 3GPP TS 38.413, Section 9.3.1.90
/// - HandoverType (IE 29) — 3GPP TS 38.413, Section 9.3.1.22
/// - TimeToWait (IE 107) — 3GPP TS 38.413, Section 9.3.1.56
///
/// APER encoding: an extension bit, then the root index as a minimal
/// bit-field, or a normally small number for an extension value. The
/// pushed value is the position in the full enumeration list (extension
/// values follow the root values).
///
/// ITU-T Rec. X.691, Section 14.
fn push_enumerated<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    descriptor: &'static FieldDescriptor,
    root_count: u64,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let mut r = AperReader::new(data);
    let Some(value) = r
        .read_enumerated(root_count, true)
        .ok()
        .and_then(|v| u8::try_from(v).ok())
    else {
        return false;
    };
    buf.push_field(
        descriptor,
        FieldValue::U8(value),
        shift(r.byte_range_since(0), offset),
    );
    true
}

/// AMFName (IE 1) / RANNodeName (IE 82) — PrintableString (SIZE(1..150, ...)).
///
/// APER encoding: an extension bit for the size constraint, the length
/// (an 8-bit constrained whole number 1..150 in the root, or an
/// unconstrained length determinant otherwise), then the characters as
/// octet-aligned 8-bit values.
///
/// 3GPP TS 38.413, Sections 9.3.3.21 (AMF Name) and 9.2.6.1 (RAN Node
/// Name); ITU-T Rec. X.691, Section 30.5.
fn push_printable_name<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let decode = || -> Result<(&'pkt [u8], Range<usize>), PacketError> {
        let mut r = AperReader::new(data);
        let len = if r.read_bit()? {
            r.read_length(0, None)?
        } else {
            r.read_length(1, Some(150))?
        };
        read_aligned_octets(&mut r, len as usize)
    };
    let Ok((name, range)) = decode() else {
        return false;
    };

    // Store the raw string bytes (zero-copy).
    buf.push_field(
        &FD_NAME_STRING,
        FieldValue::Bytes(name),
        shift(range, offset),
    );
    true
}

/// S-NSSAI (IE 148) — SEQUENCE { sST, sD OPTIONAL, iE-Extensions OPTIONAL, ... }.
///
/// APER encoding: an extension bit and two presence bits, then `sST`
/// (`OCTET STRING (SIZE(1))`, a bit-field with no alignment) and the
/// octet-aligned `sD` (`OCTET STRING (SIZE(3))`).
///
/// 3GPP TS 38.413, Section 9.3.1.24; ITU-T Rec. X.691, Sections 17.6, 17.7, 19.
fn push_s_nssai<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    type SNssai = ((u8, Range<usize>), Option<(u32, Range<usize>)>);
    let decode = || -> Result<SNssai, PacketError> {
        let mut r = AperReader::new(data);
        // Extension additions (if any) follow the root components and do
        // not affect them — ITU-T Rec. X.691, Section 19.7.
        r.read_bit()?;
        let sd_present = r.read_bit()?;
        r.read_bit()?; // iE-Extensions
        let start = r.bit_position();
        // Eight bits read from a u64 always fit in a u8.
        let sst = r.read_bits(8)? as u8;
        let sst_range = r.byte_range_since(start);
        let sd = if sd_present {
            let (sd, range) = read_aligned_octets(&mut r, 3)?;
            let sd = (u32::from(sd[0]) << 16) | (u32::from(sd[1]) << 8) | u32::from(sd[2]);
            Some((sd, range))
        } else {
            None
        };
        Ok(((sst, sst_range), sd))
    };
    let Ok(((sst, sst_range), sd)) = decode() else {
        return false;
    };

    buf.push_field(&FD_SST, FieldValue::U8(sst), shift(sst_range, offset));
    if let Some((sd, range)) = sd {
        buf.push_field(&FD_SD, FieldValue::U32(sd), shift(range, offset));
    }
    true
}

/// GUAMI (IE 28) — SEQUENCE { pLMNIdentity, aMFRegionID, aMFSetID,
/// aMFPointer, iE-Extensions OPTIONAL, ... }.
///
/// `aMFRegionID`, `aMFSetID` and `aMFPointer` are BIT STRINGs of 8, 10
/// and 6 bits: bit-fields with no alignment.
///
/// 3GPP TS 38.413, Section 9.3.3.3; ITU-T Rec. X.691, Section 16.9.
fn push_guami<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    type Guami<'a> = (
        (&'a [u8], Range<usize>),
        (u64, Range<usize>),
        (u64, Range<usize>),
        (u64, Range<usize>),
    );
    let decode = || -> Result<Guami<'pkt>, PacketError> {
        let mut r = AperReader::new(data);
        read_sequence_preamble(&mut r)?;
        let plmn = read_aligned_octets(&mut r, 3)?;
        let region = read_bit_string_field(&mut r, 8)?;
        let set = read_bit_string_field(&mut r, 10)?;
        let pointer = read_bit_string_field(&mut r, 6)?;
        Ok((plmn, region, set, pointer))
    };
    let Ok((
        (plmn, plmn_range),
        (region, region_range),
        (set, set_range),
        (pointer, pointer_range),
    )) = decode()
    else {
        return false;
    };

    // Store raw PLMN bytes (3 bytes).
    buf.push_field(
        &FD_PLMN_IDENTITY,
        FieldValue::Bytes(plmn),
        shift(plmn_range, offset),
    );
    // Bit widths 8, 10 and 6 guarantee the narrowing casts are lossless.
    buf.push_field(
        &FD_AMF_REGION_ID,
        FieldValue::U8(region as u8),
        shift(region_range, offset),
    );
    buf.push_field(
        &FD_AMF_SET_ID,
        FieldValue::U16(set as u16),
        shift(set_range, offset),
    );
    buf.push_field(
        &FD_AMF_POINTER,
        FieldValue::U8(pointer as u8),
        shift(pointer_range, offset),
    );
    true
}

/// GlobalRANNodeID (IE 27) — CHOICE { globalGNB-ID, globalNgENB-ID,
/// globalN3IWF-ID, choice-Extensions }.
///
/// APER encoding: a 2-bit choice index (4 alternatives, no extension
/// marker). For `globalGNB-ID`, the SEQUENCE preamble follows, then the
/// octet-aligned PLMN identity, the 1-bit `GNB-ID` choice, the 4-bit
/// length of `gNB-ID` (`BIT STRING (SIZE(22..32))`) and the octet-aligned
/// identifier. Other alternatives report only the choice.
///
/// 3GPP TS 38.413, Sections 9.3.1.5, 9.3.1.6; ITU-T Rec. X.691, Sections
/// 16.11, 19, 23.
fn push_global_ran_node_id<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    struct GlobalGnbId<'a> {
        plmn: &'a [u8],
        plmn_range: Range<usize>,
        /// `(bit length, length range, identifier, identifier range)`.
        gnb_id: Option<(u8, Range<usize>, u32, Range<usize>)>,
    }

    let decode = || -> Result<(u64, Range<usize>, Option<GlobalGnbId<'pkt>>), PacketError> {
        let mut r = AperReader::new(data);
        let choice = r.read_choice_index(RAN_NODE_AND_ULI_CHOICE_COUNT, false)?;
        let choice_range = r.byte_range_since(0);
        if choice != 0 {
            return Ok((choice, choice_range, None));
        }
        read_sequence_preamble(&mut r)?;
        let (plmn, plmn_range) = read_aligned_octets(&mut r, 3)?;
        let gnb_id = if r.read_choice_index(GNB_ID_CHOICE_COUNT, false)? == 0 {
            let len_start = r.bit_position();
            let len = r.read_length(22, Some(32))?;
            let len_range = r.byte_range_since(len_start);
            r.align();
            let id_start = r.bit_position();
            // `len` is at most 32, so both narrowing conversions are lossless.
            let id = r.read_bits(len as u32)? as u32;
            Some((len as u8, len_range, id, r.byte_range_since(id_start)))
        } else {
            None
        };
        Ok((
            choice,
            choice_range,
            Some(GlobalGnbId {
                plmn,
                plmn_range,
                gnb_id,
            }),
        ))
    };
    let Ok((choice, choice_range, gnb)) = decode() else {
        return false;
    };

    // `choice` is at most 3 (2-bit constrained whole number).
    buf.push_field(
        &FD_GNB_ID_CHOICE,
        FieldValue::U8(choice as u8),
        shift(choice_range, offset),
    );
    if let Some(gnb) = gnb {
        buf.push_field(
            &FD_PLMN_IDENTITY,
            FieldValue::Bytes(gnb.plmn),
            shift(gnb.plmn_range, offset),
        );
        if let Some((len, len_range, id, id_range)) = gnb.gnb_id {
            buf.push_field(
                &FD_GNB_ID_LENGTH,
                FieldValue::U8(len),
                shift(len_range, offset),
            );
            buf.push_field(&FD_GNB_ID, FieldValue::U32(id), shift(id_range, offset));
        }
    }
    true
}

/// UserLocationInformation (IE 121) — CHOICE { userLocationInformationEUTRA,
/// userLocationInformationNR, userLocationInformationN3IWF-with-PortNumber,
/// choice-Extensions }.
///
/// APER encoding: a 2-bit choice index (4 alternatives, no extension
/// marker). The E-UTRA and NR alternatives are `SEQUENCE { CGI, tAI,
/// timeStamp OPTIONAL, iE-Extensions OPTIONAL, ... }`; their CGI, TAI
/// and time stamp are decoded. Other alternatives report only the choice.
///
/// 3GPP TS 38.413, Section 9.3.1.16; ITU-T Rec. X.691, Sections 19, 23.
fn push_user_location_information<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    struct Uli<'a> {
        cgi: Cgi<'a>,
        tai: Tai<'a>,
        time_stamp: Option<(u32, Range<usize>)>,
    }

    let decode = || -> Result<(u64, Range<usize>, Option<Uli<'pkt>>), PacketError> {
        let mut r = AperReader::new(data);
        let choice = r.read_choice_index(RAN_NODE_AND_ULI_CHOICE_COUNT, false)?;
        let choice_range = r.byte_range_since(0);
        let cell_identity_bits = match choice {
            0 => 28, // EUTRA-CGI.eUTRACellIdentity
            1 => 36, // NR-CGI.nRCellIdentity
            _ => return Ok((choice, choice_range, None)),
        };
        r.read_bit()?; // extension bit — additions follow the fields decoded here.
        let time_stamp_present = r.read_bit()?;
        r.read_bit()?; // iE-Extensions
        let cgi = read_cgi(&mut r, cell_identity_bits)?;
        let tai = read_tai(&mut r)?;
        // TimeStamp ::= OCTET STRING (SIZE(4)) — 3GPP TS 38.413, Section 9.3.1.75.
        let time_stamp = if time_stamp_present {
            let (ts, range) = read_aligned_octets(&mut r, 4)?;
            Some((u32::from_be_bytes([ts[0], ts[1], ts[2], ts[3]]), range))
        } else {
            None
        };
        Ok((
            choice,
            choice_range,
            Some(Uli {
                cgi,
                tai,
                time_stamp,
            }),
        ))
    };
    let Ok((choice, choice_range, uli)) = decode() else {
        return false;
    };

    // `choice` is at most 3 (2-bit constrained whole number).
    buf.push_field(
        &FD_ULI_CHOICE,
        FieldValue::U8(choice as u8),
        shift(choice_range, offset),
    );
    if let Some(uli) = uli {
        buf.push_field(
            &FD_PLMN_IDENTITY,
            FieldValue::Bytes(uli.cgi.plmn),
            shift(uli.cgi.plmn_range, offset),
        );
        let cell_range = shift(uli.cgi.cell_identity_range, offset);
        if choice == 0 {
            // A 28-bit identity always fits in a u32.
            buf.push_field(
                &FD_EUTRA_CELL_IDENTITY,
                FieldValue::U32(uli.cgi.cell_identity as u32),
                cell_range,
            );
        } else {
            buf.push_field(
                &FD_NR_CELL_IDENTITY,
                FieldValue::U64(uli.cgi.cell_identity),
                cell_range,
            );
        }
        buf.push_field(
            &FD_PLMN_IDENTITY,
            FieldValue::Bytes(uli.tai.plmn),
            shift(uli.tai.plmn_range, offset),
        );
        buf.push_field(
            &FD_TAC,
            FieldValue::U32(uli.tai.tac),
            shift(uli.tai.tac_range, offset),
        );
        if let Some((ts, range)) = uli.time_stamp {
            buf.push_field(&FD_TIME_STAMP, FieldValue::U32(ts), shift(range, offset));
        }
    }
    true
}

/// NR-CGI (IE 45) — SEQUENCE { pLMNIdentity, nRCellIdentity, iE-Extensions
/// OPTIONAL, ... }.
///
/// 3GPP TS 38.413, Section 9.3.1.7; ITU-T Rec. X.691, Section 16.10.
fn push_nr_cgi<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    let Ok(cgi) = read_cgi(&mut AperReader::new(data), 36) else {
        return false;
    };
    buf.push_field(
        &FD_PLMN_IDENTITY,
        FieldValue::Bytes(cgi.plmn),
        shift(cgi.plmn_range, offset),
    );
    buf.push_field(
        &FD_NR_CELL_IDENTITY,
        FieldValue::U64(cgi.cell_identity),
        shift(cgi.cell_identity_range, offset),
    );
    true
}

/// EUTRA-CGI (IE 25) — SEQUENCE { pLMNIdentity, eUTRACellIdentity,
/// iE-Extensions OPTIONAL, ... }.
///
/// 3GPP TS 38.413, Section 9.3.1.9; ITU-T Rec. X.691, Section 16.10.
fn push_eutra_cgi<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    let Ok(cgi) = read_cgi(&mut AperReader::new(data), 28) else {
        return false;
    };
    buf.push_field(
        &FD_PLMN_IDENTITY,
        FieldValue::Bytes(cgi.plmn),
        shift(cgi.plmn_range, offset),
    );
    // A 28-bit identity always fits in a u32.
    buf.push_field(
        &FD_EUTRA_CELL_IDENTITY,
        FieldValue::U32(cgi.cell_identity as u32),
        shift(cgi.cell_identity_range, offset),
    );
    true
}

/// NAS-PDU (IE 38) — OCTET STRING.
///
/// Contains a 5G NAS message. An unconstrained OCTET STRING is encoded
/// as an octet-aligned length determinant followed by the octets.
///
/// 3GPP TS 38.413, Section 9.3.3.4; ITU-T Rec. X.691, Sections 11.9, 17.8.
fn push_nas_pdu<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    let decode = || -> Result<(&'pkt [u8], Range<usize>), PacketError> {
        let mut r = AperReader::new(data);
        let len = r.read_length(0, None)?;
        read_aligned_octets(&mut r, len as usize)
    };
    let Ok((nas_data, range)) = decode() else {
        return false;
    };
    if nas_data.is_empty() {
        return false;
    }
    let range = shift(range, offset);
    let nas_offset = range.start;

    let obj_idx = buf.begin_container(&FD_NAS_PDU, FieldValue::Object(0..0), range.clone());
    let ok = packet_dissector_nas5g::push_nas_pdu(buf, nas_data, nas_offset);
    if !ok {
        // Could not parse — store raw bytes.
        buf.push_field(&FD_IE_VALUE_FALLBACK, FieldValue::Bytes(nas_data), range);
    }
    buf.end_container(obj_idx);
    true
}

// ── Helper functions ───────────────────────────────────────────────────

/// Decode a 3-byte PLMN Identity (MCC + MNC) in BCD format.
///
/// Returns a string like "001/01" (MCC/MNC).
///
/// 3GPP TS 38.413, Section 9.3.3.5 / 3GPP TS 23.003, Section 2.2.
#[cfg(test)]
fn decode_plmn(data: &[u8]) -> String {
    if data.len() < 3 {
        return String::new();
    }

    let mcc1 = data[0] & 0x0F;
    let mcc2 = (data[0] >> 4) & 0x0F;
    let mcc3 = data[1] & 0x0F;
    let mnc3 = (data[1] >> 4) & 0x0F;
    let mnc1 = data[2] & 0x0F;
    let mnc2 = (data[2] >> 4) & 0x0F;

    if mnc3 == 0x0F {
        // 2-digit MNC
        format!("{mcc1}{mcc2}{mcc3}/{mnc1}{mnc2}")
    } else {
        // 3-digit MNC
        format!("{mcc1}{mcc2}{mcc3}/{mnc1}{mnc2}{mnc3}")
    }
}

/// Returns a human-readable name for the NGAP Cause group.
///
/// 3GPP TS 38.413, Section 9.3.1.2.
fn cause_group_name(group: u8) -> &'static str {
    match group {
        0 => "radioNetwork",
        1 => "transport",
        2 => "nas",
        3 => "protocol",
        4 => "misc",
        5 => "choice-Extensions",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for the RRC Establishment Cause.
///
/// 3GPP TS 38.413, Section 9.3.1.111 (ASN.1 in Section 9.4.5).
fn rrc_establishment_cause_name(cause: u8) -> &'static str {
    match cause {
        0 => "emergency",
        1 => "highPriorityAccess",
        2 => "mt-Access",
        3 => "mo-Signalling",
        4 => "mo-Data",
        5 => "mo-VoiceCall",
        6 => "mo-VideoCall",
        7 => "mo-SMS",
        8 => "mps-PriorityAccess",
        9 => "mcs-PriorityAccess",
        // Extension values.
        10 => "notAvailable",
        11 => "mo-ExceptionData",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for the UE Context Request.
///
/// 3GPP TS 38.413, Section 9.2.5.1 (ASN.1 in Section 9.4.5).
fn ue_context_request_name(value: u8) -> &'static str {
    match value {
        0 => "requested",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for the Default Paging DRX.
///
/// 3GPP TS 38.413, Section 9.3.1.90 (ASN.1 in Section 9.4.5).
fn paging_drx_name(value: u8) -> &'static str {
    match value {
        0 => "v32",
        1 => "v64",
        2 => "v128",
        3 => "v256",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for the GlobalRANNodeID CHOICE.
///
/// 3GPP TS 38.413, Section 9.3.1.5.
fn global_ran_node_id_choice_name(choice: u8) -> &'static str {
    match choice {
        0 => "globalGNB-ID",
        1 => "globalNgENB-ID",
        2 => "globalN3IWF-ID",
        3 => "choice-Extensions",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for the UserLocationInformation CHOICE.
///
/// 3GPP TS 38.413, Section 9.3.1.16 (ASN.1 in Section 9.4.5).
fn uli_choice_name(choice: u8) -> &'static str {
    match choice {
        0 => "userLocationInformationEUTRA",
        1 => "userLocationInformationNR",
        2 => "userLocationInformationN3IWF-with-PortNumber",
        3 => "choice-Extensions",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for HandoverType.
///
/// 3GPP TS 38.413, Section 9.3.1.22 (ASN.1 in Section 9.4.5).
fn handover_type_name(value: u8) -> &'static str {
    match value {
        0 => "intra5gs",
        1 => "fivegs-to-eps",
        2 => "eps-to-5gs",
        // Extension value.
        3 => "fivegs-to-utran",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for TimeToWait.
///
/// 3GPP TS 38.413, Section 9.3.1.56 (ASN.1 in Section 9.4.5).
fn time_to_wait_name(value: u8) -> &'static str {
    match value {
        0 => "v1s",
        1 => "v2s",
        2 => "v5s",
        3 => "v10s",
        4 => "v20s",
        5 => "v60s",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 38.413 IE Parser Coverage
    //!
    //! IE values are encoded with ALIGNED PER (TS 38.413, Section 9.5;
    //! ITU-T X.691). Test vectors were cross-checked with an independent
    //! APER encoder (pycrate `NGAP_IEs`).
    //!
    //! | IE ID | TS 38.413 | Description                         | Test                                   |
    //! |-------|-----------|-------------------------------------|----------------------------------------|
    //! | 10    | 9.3.3.1   | AMF-UE-NGAP-ID, 1-octet value       | parse_amf_ue_ngap_id                   |
    //! | 10    | 9.3.3.1   | AMF-UE-NGAP-ID, 5-octet value       | parse_amf_ue_ngap_id_max               |
    //! | 10    | 9.3.3.1   | AMF-UE-NGAP-ID, truncated           | parse_amf_ue_ngap_id_truncated         |
    //! | 85    | 9.3.3.2   | RAN-UE-NGAP-ID, 1-octet value       | parse_ran_ue_ngap_id                   |
    //! | 85    | 9.3.3.2   | RAN-UE-NGAP-ID, 4-octet value       | parse_ran_ue_ngap_id_four_octets       |
    //! | 15    | 9.3.1.2   | Cause radioNetwork                  | parse_cause                            |
    //! | 15    | 9.3.1.2   | Cause nas (single octet)            | parse_cause_nas_group                  |
    //! | 15    | 9.3.1.2   | Cause misc                          | parse_cause_misc_group                 |
    //! | 15    | 9.3.1.2   | Cause extension value               | parse_cause_extension_value            |
    //! | 15    | 9.3.1.2   | Cause choice-Extensions             | parse_cause_choice_extensions          |
    //! | 15    | 9.3.1.2   | Cause truncated                     | parse_cause_truncated                  |
    //! | 86    | 9.3.1.32  | RelativeAMFCapacity                 | parse_relative_amf_capacity            |
    //! | 90    | 9.3.1.111 | RRCEstablishmentCause (root)        | parse_rrc_establishment_cause          |
    //! | 90    | 9.3.1.111 | RRCEstablishmentCause (extension)   | parse_rrc_establishment_cause_extension|
    //! | 112   | 9.2.5.1   | UEContextRequest                    | parse_ue_context_request               |
    //! | 21    | 9.3.1.90  | DefaultPagingDRX                    | parse_default_paging_drx               |
    //! | 21    | 9.3.1.90  | DefaultPagingDRX, unknown extension | parse_default_paging_drx_unknown_ext   |
    //! | 1     | 9.3.3.21  | AMFName                             | parse_amf_name                         |
    //! | 1     | 9.3.3.21  | AMFName, size extension             | parse_amf_name_size_extension          |
    //! | 1     | 9.3.3.21  | AMFName, truncated                  | parse_amf_name_truncated               |
    //! | 82    | 9.2.6.1   | RANNodeName                         | parse_ran_node_name                    |
    //! | 148   | 9.3.1.24  | S-NSSAI                             | parse_s_nssai_with_sd                  |
    //! | 148   | 9.3.1.24  | S-NSSAI (no SD)                     | parse_s_nssai_without_sd               |
    //! | 148   | 9.3.1.24  | S-NSSAI truncated                   | parse_s_nssai_truncated                |
    //! | 28    | 9.3.3.3   | GUAMI                               | parse_guami                            |
    //! | 38    | 9.3.3.4   | NAS-PDU                             | parse_nas_pdu                          |
    //! | 38    | 9.3.3.4   | NAS-PDU truncated                   | parse_nas_pdu_truncated                |
    //! | 45    | 9.3.1.7   | NR-CGI                              | parse_nr_cgi                           |
    //! | 25    | 9.3.1.9   | EUTRA-CGI                           | parse_eutra_cgi                        |
    //! | 27    | 9.3.1.5   | GlobalRANNodeID gNB, 32-bit ID      | parse_global_ran_node_id               |
    //! | 27    | 9.3.1.5   | GlobalRANNodeID gNB, 22-bit ID      | parse_global_ran_node_id_22_bit        |
    //! | 27    | 9.3.1.5   | GlobalRANNodeID ng-eNB              | parse_global_ran_node_id_ng_enb        |
    //! | 27    | 9.3.1.5   | GlobalRANNodeID truncated           | parse_global_ran_node_id_truncated     |
    //! | 121   | 9.3.1.16  | UserLocationInformation NR          | parse_uli_nr                           |
    //! | 121   | 9.3.1.16  | ULI NR with timeStamp               | parse_uli_nr_with_time_stamp           |
    //! | 121   | 9.3.1.16  | ULI NR, NR-CGI iE-Extensions        | parse_uli_nr_with_cgi_extensions       |
    //! | 121   | 9.3.1.16  | ULI NR, NR-CGI extension additions  | parse_uli_nr_with_cgi_ext_additions    |
    //! | 121   | 9.3.1.16  | UserLocationInformation E-UTRA      | parse_uli_eutra                        |
    //! | 121   | 9.3.1.16  | ULI N3IWF (choice only)             | parse_uli_n3iwf                        |
    //! | 121   | 9.3.1.16  | ULI truncated                       | parse_uli_truncated                    |
    //! | 29    | 9.3.1.22  | HandoverType                        | parse_handover_type                    |
    //! | 29    | 9.3.1.22  | HandoverType (extension)            | parse_handover_type_extension          |
    //! | 107   | 9.3.1.56  | TimeToWait                          | parse_time_to_wait                     |
    //! | _     | —         | Unknown IE                          | parse_unknown_ie                       |

    use super::*;

    /// Helper to push an IE value into the buffer.
    fn push_and_get_fields<'pkt>(
        buf: &mut DissectBuffer<'pkt>,
        ie_id: u16,
        data: &'pkt [u8],
        offset: usize,
    ) {
        push_ie_value(buf, ie_id, data, offset);
    }

    /// Returns the display string of field `idx`.
    fn display(buf: &DissectBuffer<'_>, idx: usize) -> Option<&'static str> {
        let field = &buf.fields()[idx];
        (field.descriptor.display_fn.unwrap())(&field.value, buf.fields())
    }

    /// Asserts that the IE value fell back to a single raw bytes field.
    fn assert_fallback(buf: &DissectBuffer<'_>, data: &[u8]) {
        assert_eq!(buf.fields().len(), 1);
        assert_eq!(buf.fields()[0].name(), "value");
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(data));
    }

    #[test]
    fn parse_amf_ue_ngap_id() {
        // INTEGER (0..1099511627775): 3-bit length (0 → 1 octet), pad, 0x01.
        let data = [0x00, 0x01];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 10, &data, 100);
        assert_eq!(buf.fields().len(), 1);
        assert_eq!(buf.fields()[0].name(), "amf_ue_ngap_id");
        assert_eq!(buf.fields()[0].value, FieldValue::U64(1));
        assert_eq!(buf.fields()[0].range, 100..102);
    }

    #[test]
    fn parse_amf_ue_ngap_id_max() {
        // Length 5 (bits 100), pad, 5 octets.
        let data = [0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 10, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U64(0xFF_FFFF_FFFF));
        assert_eq!(buf.fields()[0].range, 0..6);
    }

    #[test]
    fn parse_amf_ue_ngap_id_truncated() {
        // Length says 3 octets, only 2 present.
        let data = [0x40, 0x01, 0x02];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 10, &data, 0);
        assert_fallback(&buf, &data);
    }

    #[test]
    fn parse_ran_ue_ngap_id() {
        // INTEGER (0..4294967295): 2-bit length (0 → 1 octet), pad, 0x2a.
        let data = [0x00, 0x2A];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 85, &data, 0);
        assert_eq!(buf.fields()[0].name(), "ran_ue_ngap_id");
        assert_eq!(buf.fields()[0].value, FieldValue::U32(42));
        assert_eq!(buf.fields()[0].range, 0..2);
    }

    #[test]
    fn parse_ran_ue_ngap_id_four_octets() {
        let data = [0xC0, 0x12, 0x34, 0x56, 0x78];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 85, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U32(0x1234_5678));
        assert_eq!(buf.fields()[0].range, 0..5);
    }

    #[test]
    fn parse_cause() {
        // radioNetwork (000) | ext 0 | user-inactivity (010100) | pad.
        let data = [0x05, 0x00];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 15, &data, 10);
        assert_eq!(buf.fields().len(), 2);
        assert_eq!(buf.fields()[0].name(), "cause_group");
        assert_eq!(buf.fields()[0].value, FieldValue::U8(0));
        assert_eq!(display(&buf, 0), Some("radioNetwork"));
        assert_eq!(buf.fields()[0].range, 10..11);
        assert_eq!(buf.fields()[1].name(), "cause_value");
        assert_eq!(buf.fields()[1].value, FieldValue::U8(20));
        assert_eq!(buf.fields()[1].range, 10..12);
    }

    #[test]
    fn parse_cause_nas_group() {
        // nas (010) | ext 0 | deregister (10) | pad.
        let data = [0x48];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 15, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(2));
        assert_eq!(display(&buf, 0), Some("nas"));
        assert_eq!(buf.fields()[1].value, FieldValue::U8(2));
        assert_eq!(buf.fields()[1].range, 0..1);
    }

    #[test]
    fn parse_cause_misc_group() {
        // misc (100) | ext 0 | unspecified (101).
        let data = [0x8A];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 15, &data, 0);
        assert_eq!(display(&buf, 0), Some("misc"));
        assert_eq!(buf.fields()[1].value, FieldValue::U8(5));
    }

    #[test]
    fn parse_cause_extension_value() {
        // radioNetwork (000) | ext 1 | normally small 1 → index 45 + 1.
        let data = [0x10, 0x20];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 15, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(0));
        assert_eq!(buf.fields()[1].value, FieldValue::U8(46));
    }

    #[test]
    fn parse_cause_choice_extensions() {
        // choice-Extensions (101): the group is reported, the value is not.
        let data = [0xA0, 0x00];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 15, &data, 0);
        assert_eq!(buf.fields().len(), 1);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(5));
        assert_eq!(display(&buf, 0), Some("choice-Extensions"));
    }

    #[test]
    fn parse_cause_truncated() {
        let data = [0x04];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 15, &data, 0);
        assert_fallback(&buf, &data);
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 15, &[], 0);
        assert_fallback(&buf, &[]);
    }

    #[test]
    fn parse_relative_amf_capacity() {
        let data = [0xFF];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 86, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(255));
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 86, &[], 0);
        assert_fallback(&buf, &[]);
    }

    #[test]
    fn parse_rrc_establishment_cause() {
        // ext 0 | 0011 | pad.
        let data = [0x18];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 90, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(3));
        assert_eq!(display(&buf, 0), Some("mo-Signalling"));
    }

    #[test]
    fn parse_rrc_establishment_cause_extension() {
        let cases: [(u8, u8, &str); 2] =
            [(0x80, 10, "notAvailable"), (0x81, 11, "mo-ExceptionData")];
        for (octet, value, name) in cases {
            let data = [octet];
            let mut buf = DissectBuffer::new();
            push_and_get_fields(&mut buf, 90, &data, 0);
            assert_eq!(buf.fields()[0].value, FieldValue::U8(value));
            assert_eq!(display(&buf, 0), Some(name));
        }
    }

    #[test]
    fn parse_ue_context_request() {
        let data = [0x00];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 112, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(0));
        assert_eq!(display(&buf, 0), Some("requested"));
    }

    #[test]
    fn parse_default_paging_drx() {
        // ext 0 | 10 (v128) | pad.
        let data = [0x40];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 21, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(2));
        assert_eq!(display(&buf, 0), Some("v128"));
    }

    #[test]
    fn parse_default_paging_drx_unknown_ext() {
        // An extension value not known to this release is still decoded.
        let data = [0x80];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 21, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(4));
        assert_eq!(display(&buf, 0), Some("Unknown"));
    }

    #[test]
    fn parse_amf_name() {
        // ext 0 | length-1 = 11 (8 bits) | pad | "open5gs-amf0".
        let data = [
            0x05, 0x80, b'o', b'p', b'e', b'n', b'5', b'g', b's', b'-', b'a', b'm', b'f', b'0',
        ];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 1, &data, 0);
        assert_eq!(buf.fields().len(), 1);
        assert_eq!(buf.fields()[0].name(), "name");
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(b"open5gs-amf0"));
        assert_eq!(buf.fields()[0].range, 2..14);
    }

    #[test]
    fn parse_amf_name_size_extension() {
        // ext 1 | pad | unconstrained length 3 | "amf".
        let data = [0x80, 0x03, b'a', b'm', b'f'];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 1, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(b"amf"));
        assert_eq!(buf.fields()[0].range, 2..5);
    }

    #[test]
    fn parse_amf_name_truncated() {
        let data = [0x05, 0x80, b'o', b'p'];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 1, &data, 0);
        assert_fallback(&buf, &data);
    }

    #[test]
    fn parse_ran_node_name() {
        let data = [0x01, 0x00, b'g', b'N', b'B'];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 82, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(b"gNB"));
    }

    #[test]
    fn parse_s_nssai_with_sd() {
        // ext 0 | sD 1 | iE-Ext 0 | SST 0x01 (8 bits) | pad | SD.
        let data = [0x40, 0x20, 0x01, 0x02, 0x03];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 148, &data, 0);
        assert_eq!(buf.fields()[0].name(), "sst");
        assert_eq!(buf.fields()[0].value, FieldValue::U8(1));
        assert_eq!(buf.fields()[0].range, 0..2);
        assert_eq!(buf.fields()[1].name(), "sd");
        assert_eq!(buf.fields()[1].value, FieldValue::U32(0x010203));
        assert_eq!(buf.fields()[1].range, 2..5);
    }

    #[test]
    fn parse_s_nssai_without_sd() {
        let data = [0x00, 0x20];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 148, &data, 0);
        assert_eq!(buf.fields().len(), 1);
        assert_eq!(buf.fields()[0].name(), "sst");
        assert_eq!(buf.fields()[0].value, FieldValue::U8(1));
    }

    #[test]
    fn parse_s_nssai_truncated() {
        let data = [0x40, 0x20, 0x01];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 148, &data, 0);
        assert_fallback(&buf, &data);
    }

    #[test]
    fn parse_guami() {
        let data = [0x00, 0x00, 0xF1, 0x10, 0x01, 0x00, 0x42];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 28, &data, 0);
        assert_eq!(buf.fields()[0].name(), "plmn_identity");
        assert_eq!(
            buf.fields()[0].value,
            FieldValue::Bytes(&[0x00, 0xF1, 0x10])
        );
        assert_eq!(buf.fields()[0].range, 1..4);
        assert_eq!(buf.fields()[1].name(), "amf_region_id");
        assert_eq!(buf.fields()[1].value, FieldValue::U8(0x01));
        assert_eq!(buf.fields()[2].name(), "amf_set_id");
        assert_eq!(buf.fields()[2].value, FieldValue::U16(1));
        assert_eq!(buf.fields()[2].range, 5..7);
        assert_eq!(buf.fields()[3].name(), "amf_pointer");
        assert_eq!(buf.fields()[3].value, FieldValue::U8(2));
        assert_eq!(buf.fields()[3].range, 6..7);

        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 28, &data[..6], 0);
        assert_fallback(&buf, &data[..6]);
    }

    #[test]
    fn parse_nr_cgi() {
        let data = [0x00, 0x00, 0xF1, 0x10, 0x12, 0x34, 0x56, 0x78, 0x90];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 45, &data, 0);
        assert_eq!(buf.fields()[0].name(), "plmn_identity");
        assert_eq!(
            buf.fields()[0].value,
            FieldValue::Bytes(&[0x00, 0xF1, 0x10])
        );
        assert_eq!(buf.fields()[1].name(), "nr_cell_identity");
        assert_eq!(buf.fields()[1].value, FieldValue::U64(0x1_2345_6789));
        assert_eq!(buf.fields()[1].range, 4..9);

        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 45, &data[..8], 0);
        assert_fallback(&buf, &data[..8]);
    }

    #[test]
    fn parse_eutra_cgi() {
        let data = [0x00, 0x00, 0xF1, 0x10, 0x12, 0x34, 0x56, 0x70];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 25, &data, 0);
        assert_eq!(
            buf.fields()[0].value,
            FieldValue::Bytes(&[0x00, 0xF1, 0x10])
        );
        assert_eq!(buf.fields()[1].name(), "eutra_cell_identity");
        assert_eq!(buf.fields()[1].value, FieldValue::U32(0x123_4567));
        assert_eq!(buf.fields()[1].range, 4..8);

        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 25, &data[..7], 0);
        assert_fallback(&buf, &data[..7]);
    }

    #[test]
    fn parse_global_ran_node_id() {
        // choice 00 | ext 0 | opt 0 | pad | PLMN | gNB-ID choice 0 |
        // length 32-22 = 1010 | pad | 4 octets.
        let data = [0x00, 0x00, 0xF1, 0x10, 0x50, 0x00, 0x00, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 27, &data, 0);
        assert_eq!(buf.fields().len(), 4);
        assert_eq!(buf.fields()[0].name(), "choice");
        assert_eq!(buf.fields()[0].value, FieldValue::U8(0));
        assert_eq!(display(&buf, 0), Some("globalGNB-ID"));
        assert_eq!(buf.fields()[1].name(), "plmn_identity");
        assert_eq!(
            buf.fields()[1].value,
            FieldValue::Bytes(&[0x00, 0xF1, 0x10])
        );
        assert_eq!(buf.fields()[1].range, 1..4);
        assert_eq!(buf.fields()[2].name(), "gnb_id_length");
        assert_eq!(buf.fields()[2].value, FieldValue::U8(32));
        assert_eq!(buf.fields()[2].range, 4..5);
        assert_eq!(buf.fields()[3].name(), "gnb_id");
        assert_eq!(buf.fields()[3].value, FieldValue::U32(1));
        assert_eq!(buf.fields()[3].range, 5..9);
    }

    #[test]
    fn parse_global_ran_node_id_22_bit() {
        let data = [0x00, 0x00, 0xF1, 0x10, 0x00, 0x00, 0x48, 0xD0];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 27, &data, 0);
        assert_eq!(buf.fields()[2].value, FieldValue::U8(22));
        assert_eq!(buf.fields()[3].value, FieldValue::U32(0x1234));
        assert_eq!(buf.fields()[3].range, 5..8);
    }

    #[test]
    fn parse_global_ran_node_id_ng_enb() {
        // choice 01 (globalNgENB-ID): only the choice is decoded.
        let data = [0x40, 0x00, 0xF1, 0x10, 0x00, 0x12, 0x34, 0x50];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 27, &data, 0);
        assert_eq!(buf.fields().len(), 1);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(1));
        assert_eq!(display(&buf, 0), Some("globalNgENB-ID"));
    }

    #[test]
    fn parse_global_ran_node_id_truncated() {
        let data = [0x00, 0x00, 0xF1, 0x10, 0x50, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 27, &data, 0);
        assert_fallback(&buf, &data);
    }

    #[test]
    fn parse_uli_nr() {
        // choice 01 | ULI-NR ext 0, opts 00 | NR-CGI ext 0, opt 0 | pad |
        // PLMN | NCI (36 bits) | TAI ext 0, opt 0 | pad | PLMN | TAC.
        let data = [
            0x40, 0x00, 0xF1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0xF1, 0x10, 0x00, 0x01,
            0x02,
        ];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 121, &data, 0);
        assert_eq!(buf.fields().len(), 5);
        assert_eq!(buf.fields()[0].name(), "choice");
        assert_eq!(buf.fields()[0].value, FieldValue::U8(1));
        assert_eq!(display(&buf, 0), Some("userLocationInformationNR"));
        assert_eq!(buf.fields()[1].name(), "plmn_identity");
        assert_eq!(buf.fields()[1].range, 1..4);
        assert_eq!(buf.fields()[2].name(), "nr_cell_identity");
        assert_eq!(buf.fields()[2].value, FieldValue::U64(1));
        assert_eq!(buf.fields()[2].range, 4..9);
        assert_eq!(buf.fields()[3].name(), "plmn_identity");
        assert_eq!(buf.fields()[3].range, 9..12);
        assert_eq!(buf.fields()[4].name(), "tac");
        assert_eq!(buf.fields()[4].value, FieldValue::U32(0x000102));
        assert_eq!(buf.fields()[4].range, 12..15);
    }

    #[test]
    fn parse_uli_nr_with_time_stamp() {
        let data = [
            0x50, 0x00, 0xF1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0xF1, 0x10, 0x00, 0x01,
            0x02, 0xE1, 0x2B, 0x3C, 0x4D,
        ];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 121, &data, 0);
        assert_eq!(buf.fields().len(), 6);
        assert_eq!(buf.fields()[4].value, FieldValue::U32(0x000102));
        assert_eq!(buf.fields()[5].name(), "time_stamp");
        assert_eq!(buf.fields()[5].value, FieldValue::U32(0xE12B_3C4D));
        assert_eq!(buf.fields()[5].range, 15..19);
    }

    #[test]
    fn parse_uli_nr_with_cgi_extensions() {
        // NR-CGI carries an iE-Extensions container with one field
        // (id 0x1234, criticality ignore, 1-octet open type value) that
        // must be skipped before TAI.
        let data = [
            0x42, 0x00, 0xF1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, // NR-CGI
            0x00, 0x00, // SEQUENCE OF length - 1 = 0 (two-octet case)
            0x12, 0x34, // id
            0x40, // criticality ignore | pad
            0x01, 0xAB, // open type
            0x00, 0x00, 0xF1, 0x10, 0x00, 0x01, 0x02, // TAI
        ];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 121, &data, 0);
        assert_eq!(buf.fields().len(), 5);
        assert_eq!(buf.fields()[2].value, FieldValue::U64(1));
        assert_eq!(buf.fields()[3].range, 17..20);
        assert_eq!(buf.fields()[4].value, FieldValue::U32(0x000102));
        assert_eq!(buf.fields()[4].range, 20..23);
    }

    #[test]
    fn parse_uli_nr_with_cgi_ext_additions() {
        // NR-CGI extension bit set: a normally small bitmap length (0 → one
        // bit), bitmap `1`, then one open-type addition that must be
        // skipped before TAI.
        let data = [
            0x44, 0x00, 0xF1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, // NR-CGI root
            0x10, // bitmap length (cont.) | bitmap 1 | pad
            0x01, 0xAB, // open type
            0x00, 0x00, 0xF1, 0x10, 0x00, 0x01, 0x02, // TAI
        ];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 121, &data, 0);
        assert_eq!(buf.fields().len(), 5);
        assert_eq!(buf.fields()[2].value, FieldValue::U64(1));
        assert_eq!(buf.fields()[3].range, 13..16);
        assert_eq!(buf.fields()[4].value, FieldValue::U32(0x000102));
    }

    #[test]
    fn parse_uli_eutra() {
        // The TAI preamble shares the last octet of the 28-bit ECI.
        let data = [
            0x00, 0x00, 0xF1, 0x10, 0x12, 0x34, 0x56, 0x70, 0x00, 0xF1, 0x10, 0x00, 0x01, 0x02,
        ];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 121, &data, 0);
        assert_eq!(buf.fields().len(), 5);
        assert_eq!(display(&buf, 0), Some("userLocationInformationEUTRA"));
        assert_eq!(buf.fields()[2].name(), "eutra_cell_identity");
        assert_eq!(buf.fields()[2].value, FieldValue::U32(0x123_4567));
        assert_eq!(buf.fields()[2].range, 4..8);
        assert_eq!(buf.fields()[3].range, 8..11);
        assert_eq!(buf.fields()[4].value, FieldValue::U32(0x000102));
    }

    #[test]
    fn parse_uli_n3iwf() {
        let data = [0x80, 0x00];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 121, &data, 0);
        assert_eq!(buf.fields().len(), 1);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(2));
        assert_eq!(
            display(&buf, 0),
            Some("userLocationInformationN3IWF-with-PortNumber")
        );
    }

    #[test]
    fn parse_uli_truncated() {
        let data = [
            0x40, 0x00, 0xF1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0xF1, 0x10, 0x00, 0x01,
        ];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 121, &data, 0);
        assert_fallback(&buf, &data);
    }

    #[test]
    fn parse_nas_pdu() {
        let nas_bytes = [0x7E, 0x00, 0x41];
        let mut data = vec![nas_bytes.len() as u8];
        data.extend_from_slice(&nas_bytes);

        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 38, &data, 0);
        assert_eq!(buf.fields()[0].name(), "nas_pdu");
        assert_eq!(buf.fields()[0].range, 1..4);
        if let FieldValue::Object(ref range) = buf.fields()[0].value {
            let inner = buf.nested_fields(range);
            let mt = inner.iter().find(|f| f.name() == "message_type").unwrap();
            assert_eq!(mt.value, FieldValue::U8(0x41));
        } else {
            panic!("expected Object");
        }
    }

    #[test]
    fn parse_nas_pdu_truncated() {
        let data = [0x05, 0x7E, 0x00];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 38, &data, 0);
        assert_fallback(&buf, &data);
    }

    #[test]
    fn parse_handover_type() {
        // ext 0 | 01 | pad.
        let data = [0x20];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 29, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(1));
        assert_eq!(display(&buf, 0), Some("fivegs-to-eps"));
    }

    #[test]
    fn parse_handover_type_extension() {
        let data = [0x80];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 29, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(3));
        assert_eq!(display(&buf, 0), Some("fivegs-to-utran"));
    }

    #[test]
    fn parse_time_to_wait() {
        // ext 0 | 011 | pad.
        let data = [0x30];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 107, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(3));
        assert_eq!(display(&buf, 0), Some("v10s"));
    }

    #[test]
    fn parse_unknown_ie() {
        let data = [0x01, 0x02, 0x03];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 9999, &data, 0);
        assert_fallback(&buf, &data);
    }

    #[test]
    fn decode_plmn_2digit_mnc() {
        let data = [0x00, 0xF1, 0x10];
        assert_eq!(decode_plmn(&data), "001/01");
    }

    #[test]
    fn decode_plmn_3digit_mnc() {
        let data = [0x13, 0x00, 0x14];
        assert_eq!(decode_plmn(&data), "310/410");
    }

    #[test]
    fn decode_plmn_short() {
        let data = [0x00, 0x01];
        assert_eq!(decode_plmn(&data), "");
    }
}
