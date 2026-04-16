//! Per-IE-type value parsers for NGAP.
//!
//! Parses APER-encoded IE values into structured fields pushed directly
//! into a [`DissectBuffer`]. Unknown IE types fall back to raw bytes.
//!
//! ## References
//! - 3GPP TS 38.413: <https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/>
//! - ITU-T Rec. X.691 (APER): <https://www.itu.int/rec/T-REC-X.691>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;

use crate::read_aper_length;

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
/// the IE ID. For unknown IE types, pushes a raw bytes field.
///
/// 3GPP TS 38.413, Section 9.3 — NGAP Information Elements.
pub fn push_ie_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    ie_id: u16,
    data: &'pkt [u8],
    offset: usize,
) {
    let pushed = match ie_id {
        1 => push_visible_string(buf, data, offset),  // AMFName
        10 => push_amf_ue_ngap_id(buf, data, offset), // AMF-UE-NGAP-ID
        15 => push_cause(buf, data, offset),          // Cause
        21 => push_default_paging_drx(buf, data, offset), // DefaultPagingDRX
        25 => push_eutra_cgi(buf, data, offset),      // EUTRA-CGI
        27 => push_global_ran_node_id(buf, data, offset), // GlobalRANNodeID
        28 => push_guami(buf, data, offset),          // GUAMI
        29 => push_handover_type(buf, data, offset),  // HandoverType
        38 => push_nas_pdu(buf, data, offset),        // NAS-PDU
        45 => push_nr_cgi(buf, data, offset),         // NR-CGI
        82 => push_visible_string(buf, data, offset), // RANNodeName
        85 => push_ran_ue_ngap_id(buf, data, offset), // RAN-UE-NGAP-ID
        86 => push_relative_amf_capacity(buf, data, offset), // RelativeAMFCapacity
        90 => push_rrc_establishment_cause(buf, data, offset), // RRCEstablishmentCause
        107 => push_time_to_wait(buf, data, offset),  // TimeToWait
        112 => push_ue_context_request(buf, data, offset), // UEContextRequest
        121 => push_user_location_information(buf, data, offset), // UserLocationInformation
        148 => push_s_nssai(buf, data, offset),       // S-NSSAI
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

// ── Individual IE parsers ──────────────────────────────────────────────

/// AMF-UE-NGAP-ID (IE 10) — INTEGER (0..1099511627775).
///
/// APER constrained whole number for range 0..2^40-1 requires 5 bytes.
///
/// 3GPP TS 38.413, Section 9.3.3.1.
fn push_amf_ue_ngap_id<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.len() < 5 {
        return false;
    }
    let value = (u64::from(data[0]) << 32)
        | (u64::from(data[1]) << 24)
        | (u64::from(data[2]) << 16)
        | (u64::from(data[3]) << 8)
        | u64::from(data[4]);

    buf.push_field(
        &FD_AMF_UE_NGAP_ID,
        FieldValue::U64(value),
        offset..offset + 5,
    );
    true
}

/// RAN-UE-NGAP-ID (IE 85) — INTEGER (0..4294967295).
///
/// APER constrained whole number for range 0..2^32-1 requires 4 bytes.
///
/// 3GPP TS 38.413, Section 9.3.3.2.
fn push_ran_ue_ngap_id<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.len() < 4 {
        return false;
    }
    let value = packet_dissector_core::util::read_be_u32(data, 0).unwrap_or_default();

    buf.push_field(
        &FD_RAN_UE_NGAP_ID,
        FieldValue::U32(value),
        offset..offset + 4,
    );
    true
}

/// Cause (IE 15) — CHOICE.
///
/// APER encoding: choice index (1 byte preamble with extension bit +
/// choice bits) followed by the cause value (constrained whole number).
///
/// 3GPP TS 38.413, Section 9.3.1.2.
fn push_cause<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.is_empty() {
        return false;
    }

    let ext = (data[0] >> 7) & 0x01;
    let choice_index = (data[0] >> 4) & 0x07;

    if ext != 0 || data.len() < 2 {
        return false;
    }

    let cause_ext = (data[1] >> 7) & 0x01;
    let cause_value = data[1] & 0x7F;

    if cause_ext != 0 {
        return false;
    }

    buf.push_field(
        &FD_CAUSE_GROUP,
        FieldValue::U8(choice_index),
        offset..offset + 1,
    );
    buf.push_field(
        &FD_CAUSE_VALUE,
        FieldValue::U8(cause_value),
        offset + 1..offset + 2,
    );
    true
}

/// RelativeAMFCapacity (IE 86) — INTEGER (0..255).
///
/// 3GPP TS 38.413, Section 9.3.3.8.
fn push_relative_amf_capacity<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.is_empty() {
        return false;
    }

    buf.push_field(
        &FD_RELATIVE_AMF_CAPACITY,
        FieldValue::U8(data[0]),
        offset..offset + 1,
    );
    true
}

/// RRCEstablishmentCause (IE 90) — ENUMERATED.
///
/// 3GPP TS 38.413, Section 9.3.1.70.
fn push_rrc_establishment_cause<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.is_empty() {
        return false;
    }

    let ext = (data[0] >> 7) & 0x01;
    if ext != 0 {
        return false;
    }
    let value = data[0] & 0x7F;

    buf.push_field(
        &FD_RRC_ESTABLISHMENT_CAUSE,
        FieldValue::U8(value),
        offset..offset + 1,
    );
    true
}

/// UEContextRequest (IE 112) — ENUMERATED { requested, ... }.
///
/// 3GPP TS 38.413, Section 9.3.1.96.
fn push_ue_context_request<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.is_empty() {
        return false;
    }

    let ext = (data[0] >> 7) & 0x01;
    if ext != 0 {
        return false;
    }
    let value = data[0] & 0x7F;

    buf.push_field(
        &FD_UE_CONTEXT_REQUEST,
        FieldValue::U8(value),
        offset..offset + 1,
    );
    true
}

/// DefaultPagingDRX (IE 21) — ENUMERATED { v32, v64, v128, v256, ... }.
///
/// 3GPP TS 38.413, Section 9.3.1.14.
fn push_default_paging_drx<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.is_empty() {
        return false;
    }

    let ext = (data[0] >> 7) & 0x01;
    if ext != 0 {
        return false;
    }
    let value = data[0] & 0x7F;

    buf.push_field(
        &FD_DEFAULT_PAGING_DRX,
        FieldValue::U8(value),
        offset..offset + 1,
    );
    true
}

/// HandoverType (IE 29) — ENUMERATED { intra5gs, fivegs_to_eps, eps_to_5gs, ... }.
///
/// 3GPP TS 38.413, Section 9.3.1.22.
fn push_handover_type<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.is_empty() {
        return false;
    }
    let ext = (data[0] >> 7) & 0x01;
    if ext != 0 {
        return false;
    }
    let value = data[0] & 0x7F;

    buf.push_field(&FD_HANDOVER_TYPE, FieldValue::U8(value), offset..offset + 1);
    true
}

/// TimeToWait (IE 107) — ENUMERATED { v1s, v2s, v5s, v10s, v20s, v60s, ... }.
///
/// 3GPP TS 38.413, Section 9.3.1.63.
fn push_time_to_wait<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.is_empty() {
        return false;
    }
    let ext = (data[0] >> 7) & 0x01;
    if ext != 0 {
        return false;
    }
    let value = data[0] & 0x7F;

    buf.push_field(&FD_TIME_TO_WAIT, FieldValue::U8(value), offset..offset + 1);
    true
}

/// AMFName / RANNodeName (IEs 1, 82) — VisibleString (1..150, ...).
///
/// APER encoding: APER length determinant followed by UTF-8 characters.
///
/// 3GPP TS 38.413, Sections 9.3.3.6, 9.3.3.10.
fn push_visible_string<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.is_empty() {
        return false;
    }

    let ext = (data[0] >> 7) & 0x01;
    if ext != 0 {
        return false;
    }

    let str_len = data[0] as usize + 1;
    let str_start = 1;

    if str_start + str_len > data.len() {
        return false;
    }

    // Store the raw string bytes (zero-copy).
    buf.push_field(
        &FD_NAME_STRING,
        FieldValue::Bytes(&data[str_start..str_start + str_len]),
        offset + str_start..offset + str_start + str_len,
    );
    true
}

/// S-NSSAI (IE 148) — SEQUENCE { sST, sD OPTIONAL }.
///
/// APER encoding: 1-byte preamble (extension + optional bitmap) +
/// 1-byte SST + optional 3-byte SD.
///
/// 3GPP TS 38.413, Section 9.3.1.24.
fn push_s_nssai<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.is_empty() {
        return false;
    }

    let ext = (data[0] >> 7) & 0x01;
    if ext != 0 {
        return false;
    }

    let sd_present = (data[0] >> 6) & 0x01;

    if data.len() < 2 {
        return false;
    }

    let sst = data[1];
    buf.push_field(&FD_SST, FieldValue::U8(sst), offset + 1..offset + 2);

    if sd_present != 0 {
        if data.len() < 5 {
            return false;
        }
        let sd = (u32::from(data[2]) << 16) | (u32::from(data[3]) << 8) | u32::from(data[4]);
        buf.push_field(&FD_SD, FieldValue::U32(sd), offset + 2..offset + 5);
    }

    true
}

/// GUAMI (IE 28) — SEQUENCE { pLMNIdentity, aMFRegionID, aMFSetID, aMFPointer }.
///
/// 3GPP TS 38.413, Section 9.3.1.23.
fn push_guami<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.is_empty() {
        return false;
    }

    let ext = (data[0] >> 7) & 0x01;
    if ext != 0 {
        return false;
    }

    if data.len() < 7 {
        return false;
    }

    // Store raw PLMN bytes (3 bytes).
    buf.push_field(
        &FD_PLMN_IDENTITY,
        FieldValue::Bytes(&data[1..4]),
        offset + 1..offset + 4,
    );
    let amf_region_id = data[4];
    let amf_set_id = (u16::from(data[5]) << 2) | (u16::from(data[6]) >> 6);
    let amf_pointer = data[6] & 0x3F;

    buf.push_field(
        &FD_AMF_REGION_ID,
        FieldValue::U8(amf_region_id),
        offset + 4..offset + 5,
    );
    buf.push_field(
        &FD_AMF_SET_ID,
        FieldValue::U16(amf_set_id),
        offset + 5..offset + 7,
    );
    buf.push_field(
        &FD_AMF_POINTER,
        FieldValue::U8(amf_pointer),
        offset + 6..offset + 7,
    );
    true
}

/// GlobalRANNodeID (IE 27) — CHOICE { globalGNB-ID, globalNgENB-ID, ... }.
///
/// 3GPP TS 38.413, Section 9.3.1.5.
fn push_global_ran_node_id<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.is_empty() {
        return false;
    }

    let ext = (data[0] >> 7) & 0x01;
    if ext != 0 {
        return false;
    }

    let choice_index = (data[0] >> 5) & 0x03;

    buf.push_field(
        &FD_GNB_ID_CHOICE,
        FieldValue::U8(choice_index),
        offset..offset + 1,
    );

    // For globalGNB-ID (choice 0):
    if choice_index == 0 && data.len() >= 9 {
        // Store raw PLMN bytes.
        buf.push_field(
            &FD_PLMN_IDENTITY,
            FieldValue::Bytes(&data[2..5]),
            offset + 2..offset + 5,
        );

        let gnb_id_bit_len = (data[6] & 0x0F) + 22;
        let gnb_id_byte_len = (gnb_id_bit_len as usize).div_ceil(8);

        buf.push_field(
            &FD_GNB_ID_LENGTH,
            FieldValue::U8(gnb_id_bit_len),
            offset + 6..offset + 7,
        );

        if data.len() >= 7 + gnb_id_byte_len {
            let gnb_id_bytes = &data[7..7 + gnb_id_byte_len];
            let mut gnb_id: u32 = 0;
            for &b in gnb_id_bytes {
                gnb_id = (gnb_id << 8) | u32::from(b);
            }
            let shift = (gnb_id_byte_len * 8) as u32 - u32::from(gnb_id_bit_len);
            gnb_id >>= shift;

            buf.push_field(
                &FD_GNB_ID,
                FieldValue::U32(gnb_id),
                offset + 7..offset + 7 + gnb_id_byte_len,
            );
        }
    }

    true
}

/// UserLocationInformation (IE 121) — CHOICE { userLocationInformationEUTRA,
/// userLocationInformationNR, ... }.
///
/// 3GPP TS 38.413, Section 9.3.1.16.
fn push_user_location_information<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.is_empty() {
        return false;
    }

    let ext = (data[0] >> 7) & 0x01;
    if ext != 0 {
        return false;
    }

    let choice_index = (data[0] >> 5) & 0x03;

    buf.push_field(
        &FD_ULI_CHOICE,
        FieldValue::U8(choice_index),
        offset..offset + 1,
    );

    match choice_index {
        // userLocationInformationEUTRA
        0 if data.len() >= 17 => {
            let eutra_cgi_offset = offset + 2;
            buf.push_field(
                &FD_PLMN_IDENTITY,
                FieldValue::Bytes(&data[3..6]),
                eutra_cgi_offset + 1..eutra_cgi_offset + 4,
            );
            let eci = packet_dissector_core::util::read_be_u32(data, 6).unwrap_or_default() >> 4;
            buf.push_field(
                &FD_EUTRA_CELL_IDENTITY,
                FieldValue::U32(eci),
                offset + 6..offset + 10,
            );
            if data.len() >= 17 {
                let tac =
                    (u32::from(data[14]) << 16) | (u32::from(data[15]) << 8) | u32::from(data[16]);
                buf.push_field(&FD_TAC, FieldValue::U32(tac), offset + 14..offset + 17);
            }
        }
        // userLocationInformationNR
        1 if data.len() >= 18 => {
            let nr_cgi_offset = offset + 2;
            buf.push_field(
                &FD_PLMN_IDENTITY,
                FieldValue::Bytes(&data[3..6]),
                nr_cgi_offset + 1..nr_cgi_offset + 4,
            );
            let nci = ((u64::from(data[6]) << 32)
                | u64::from(packet_dissector_core::util::read_be_u32(data, 7).unwrap_or_default()))
                >> 4;
            buf.push_field(
                &FD_NR_CELL_IDENTITY,
                FieldValue::U64(nci),
                offset + 6..offset + 11,
            );
            if data.len() >= 18 {
                let tac =
                    (u32::from(data[15]) << 16) | (u32::from(data[16]) << 8) | u32::from(data[17]);
                buf.push_field(&FD_TAC, FieldValue::U32(tac), offset + 15..offset + 18);
            }
        }
        _ => {
            // userLocationInformationN3IWF or unknown — no extra fields.
        }
    }

    true
}

/// NR-CGI (IE 45) — SEQUENCE { pLMNIdentity, nRCellIdentity }.
///
/// 3GPP TS 38.413, Section 9.3.1.7.
fn push_nr_cgi<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.len() < 9 {
        return false;
    }

    let ext = (data[0] >> 7) & 0x01;
    if ext != 0 {
        return false;
    }

    buf.push_field(
        &FD_PLMN_IDENTITY,
        FieldValue::Bytes(&data[1..4]),
        offset + 1..offset + 4,
    );
    let nci = ((u64::from(data[4]) << 32)
        | u64::from(packet_dissector_core::util::read_be_u32(data, 5).unwrap_or_default()))
        >> 4;

    buf.push_field(
        &FD_NR_CELL_IDENTITY,
        FieldValue::U64(nci),
        offset + 4..offset + 9,
    );
    true
}

/// EUTRA-CGI (IE 25) — SEQUENCE { pLMNIdentity, eUTRACellIdentity }.
///
/// 3GPP TS 38.413, Section 9.3.1.8.
fn push_eutra_cgi<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.len() < 8 {
        return false;
    }

    let ext = (data[0] >> 7) & 0x01;
    if ext != 0 {
        return false;
    }

    buf.push_field(
        &FD_PLMN_IDENTITY,
        FieldValue::Bytes(&data[1..4]),
        offset + 1..offset + 4,
    );
    let eci = packet_dissector_core::util::read_be_u32(data, 4).unwrap_or_default() >> 4;

    buf.push_field(
        &FD_EUTRA_CELL_IDENTITY,
        FieldValue::U32(eci),
        offset + 4..offset + 8,
    );
    true
}

/// NAS-PDU (IE 38) — OCTET STRING.
///
/// Contains a 5G NAS message. The APER encoding wraps it in a length
/// determinant, but the IE value we receive here is already the raw
/// OCTET STRING content (length determinant was consumed by the IE
/// container parser).
///
/// 3GPP TS 38.413, Section 9.3.3.4.
fn push_nas_pdu<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.is_empty() {
        return false;
    }

    let Ok((nas_len, len_bytes)) = read_aper_length(data, 0) else {
        return false;
    };
    let nas_len = nas_len as usize;

    if len_bytes + nas_len > data.len() {
        return false;
    }

    let nas_data = &data[len_bytes..len_bytes + nas_len];
    let nas_offset = offset + len_bytes;

    let obj_idx = buf.begin_container(
        &FD_NAS_PDU,
        FieldValue::Object(0..0),
        nas_offset..nas_offset + nas_len,
    );
    let ok = packet_dissector_nas5g::push_nas_pdu(buf, nas_data, nas_offset);
    if !ok {
        // Could not parse — store raw bytes.
        buf.push_field(
            &FD_IE_VALUE_FALLBACK,
            FieldValue::Bytes(nas_data),
            nas_offset..nas_offset + nas_len,
        );
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
        _ => "Unknown",
    }
}

/// Returns a human-readable name for the RRC Establishment Cause.
///
/// 3GPP TS 38.413, Section 9.3.1.70.
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
        _ => "Unknown",
    }
}

/// Returns a human-readable name for the UE Context Request.
///
/// 3GPP TS 38.413, Section 9.3.1.96.
fn ue_context_request_name(value: u8) -> &'static str {
    match value {
        0 => "requested",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for the Default Paging DRX.
///
/// 3GPP TS 38.413, Section 9.3.1.14.
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
/// 3GPP TS 38.413, Section 9.3.1.16.
fn uli_choice_name(choice: u8) -> &'static str {
    match choice {
        0 => "userLocationInformationEUTRA",
        1 => "userLocationInformationNR",
        2 => "userLocationInformationN3IWF",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for HandoverType.
///
/// 3GPP TS 38.413, Section 9.3.1.22.
fn handover_type_name(value: u8) -> &'static str {
    match value {
        0 => "intra5gs",
        1 => "fivegs_to_eps",
        2 => "eps_to_5gs",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for TimeToWait.
///
/// 3GPP TS 38.413, Section 9.3.1.63.
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
    //! | IE ID | Description              | Test                                |
    //! |-------|--------------------------|-------------------------------------|
    //! | 10    | AMF-UE-NGAP-ID           | parse_amf_ue_ngap_id                |
    //! | 85    | RAN-UE-NGAP-ID           | parse_ran_ue_ngap_id                |
    //! | 15    | Cause                    | parse_cause                         |
    //! | 86    | RelativeAMFCapacity      | parse_relative_amf_capacity         |
    //! | 90    | RRCEstablishmentCause    | parse_rrc_establishment_cause       |
    //! | 112   | UEContextRequest         | parse_ue_context_request            |
    //! | 21    | DefaultPagingDRX         | parse_default_paging_drx            |
    //! | 1     | AMFName                  | parse_amf_name                      |
    //! | 148   | S-NSSAI                  | parse_s_nssai_with_sd               |
    //! | 148   | S-NSSAI (no SD)          | parse_s_nssai_without_sd            |
    //! | 28    | GUAMI                    | parse_guami                         |
    //! | 38    | NAS-PDU                  | parse_nas_pdu                       |
    //! | 45    | NR-CGI                   | parse_nr_cgi                        |
    //! | 25    | EUTRA-CGI                | parse_eutra_cgi                     |
    //! | 27    | GlobalRANNodeID          | parse_global_ran_node_id            |
    //! | 121   | UserLocationInformation  | parse_uli_nr                        |
    //! | 29    | HandoverType             | parse_handover_type                 |
    //! | 107   | TimeToWait               | parse_time_to_wait                  |
    //! | _     | Unknown IE               | parse_unknown_ie                    |

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

    #[test]
    fn parse_amf_ue_ngap_id() {
        let data = [0x00, 0x00, 0x00, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 10, &data, 100);
        assert_eq!(buf.fields()[0].name(), "amf_ue_ngap_id");
        assert_eq!(buf.fields()[0].value, FieldValue::U64(1));
        assert_eq!(buf.fields()[0].range, 100..105);
    }

    #[test]
    fn parse_amf_ue_ngap_id_truncated() {
        let data = [0x00, 0x01, 0x02];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 10, &data, 0);
        // Should fallback to raw bytes
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(&data[..]));
    }

    #[test]
    fn parse_ran_ue_ngap_id() {
        let data = [0x00, 0x00, 0x00, 0x2A]; // 42
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 85, &data, 0);
        assert_eq!(buf.fields()[0].name(), "ran_ue_ngap_id");
        assert_eq!(buf.fields()[0].value, FieldValue::U32(42));
    }

    #[test]
    fn parse_cause() {
        let data = [0x00, 0x00];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 15, &data, 0);
        assert_eq!(buf.fields()[0].name(), "cause_group");
        assert_eq!(buf.fields()[0].value, FieldValue::U8(0));
        let display_fn = buf.fields()[0].descriptor.display_fn.unwrap();
        assert_eq!(
            display_fn(&buf.fields()[0].value, buf.fields()),
            Some("radioNetwork")
        );
        assert_eq!(buf.fields()[1].name(), "cause_value");
        assert_eq!(buf.fields()[1].value, FieldValue::U8(0));
    }

    #[test]
    fn parse_cause_nas_group() {
        let data = [0x20, 0x00];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 15, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(2));
        let display_fn = buf.fields()[0].descriptor.display_fn.unwrap();
        assert_eq!(
            display_fn(&buf.fields()[0].value, buf.fields()),
            Some("nas")
        );
    }

    #[test]
    fn parse_relative_amf_capacity() {
        let data = [0xFF];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 86, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(255));
    }

    #[test]
    fn parse_rrc_establishment_cause() {
        let data = [0x03];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 90, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(3));
        let display_fn = buf.fields()[0].descriptor.display_fn.unwrap();
        assert_eq!(
            display_fn(&buf.fields()[0].value, buf.fields()),
            Some("mo-Signalling")
        );
    }

    #[test]
    fn parse_ue_context_request() {
        let data = [0x00];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 112, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(0));
        let display_fn = buf.fields()[0].descriptor.display_fn.unwrap();
        assert_eq!(
            display_fn(&buf.fields()[0].value, buf.fields()),
            Some("requested")
        );
    }

    #[test]
    fn parse_default_paging_drx() {
        let data = [0x02];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 21, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(2));
        let display_fn = buf.fields()[0].descriptor.display_fn.unwrap();
        assert_eq!(
            display_fn(&buf.fields()[0].value, buf.fields()),
            Some("v128")
        );
    }

    #[test]
    fn parse_amf_name() {
        let data = [0x03, b'a', b'm', b'f', b'1'];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 1, &data, 0);
        assert_eq!(buf.fields()[0].name(), "name");
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(b"amf1"));
    }

    #[test]
    fn parse_ran_node_name() {
        let data = [0x02, b'g', b'N', b'B'];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 82, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(b"gNB"));
    }

    #[test]
    fn parse_s_nssai_with_sd() {
        let data = [0x40, 0x01, 0x01, 0x02, 0x03];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 148, &data, 0);
        assert_eq!(buf.fields()[0].name(), "sst");
        assert_eq!(buf.fields()[0].value, FieldValue::U8(1));
        assert_eq!(buf.fields()[1].name(), "sd");
        assert_eq!(buf.fields()[1].value, FieldValue::U32(0x010203));
    }

    #[test]
    fn parse_s_nssai_without_sd() {
        let data = [0x00, 0x01];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 148, &data, 0);
        assert_eq!(buf.fields().len(), 1);
        assert_eq!(buf.fields()[0].name(), "sst");
        assert_eq!(buf.fields()[0].value, FieldValue::U8(1));
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
        assert_eq!(buf.fields()[1].name(), "amf_region_id");
        assert_eq!(buf.fields()[1].value, FieldValue::U8(0x01));
        assert_eq!(buf.fields()[2].name(), "amf_set_id");
        assert_eq!(buf.fields()[2].value, FieldValue::U16(1));
        assert_eq!(buf.fields()[3].name(), "amf_pointer");
        assert_eq!(buf.fields()[3].value, FieldValue::U8(2));
    }

    #[test]
    fn parse_nr_cgi() {
        let nci: u64 = 0x123456789;
        let nci_shifted = nci << 4;
        let nci_bytes = [
            ((nci_shifted >> 32) & 0xFF) as u8,
            ((nci_shifted >> 24) & 0xFF) as u8,
            ((nci_shifted >> 16) & 0xFF) as u8,
            ((nci_shifted >> 8) & 0xFF) as u8,
            (nci_shifted & 0xFF) as u8,
        ];
        let mut data = vec![0x00, 0x00, 0xF1, 0x10];
        data.extend_from_slice(&nci_bytes);

        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 45, &data, 0);
        assert_eq!(buf.fields()[0].name(), "plmn_identity");
        assert_eq!(
            buf.fields()[0].value,
            FieldValue::Bytes(&[0x00, 0xF1, 0x10])
        );
        assert_eq!(buf.fields()[1].name(), "nr_cell_identity");
        assert_eq!(buf.fields()[1].value, FieldValue::U64(nci));
    }

    #[test]
    fn parse_eutra_cgi() {
        let eci: u32 = 0x1234567;
        let eci_shifted = eci << 4;
        let eci_bytes = eci_shifted.to_be_bytes();
        let mut data = vec![0x00, 0x00, 0xF1, 0x10];
        data.extend_from_slice(&eci_bytes);

        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 25, &data, 0);
        assert_eq!(
            buf.fields()[0].value,
            FieldValue::Bytes(&[0x00, 0xF1, 0x10])
        );
        assert_eq!(buf.fields()[1].name(), "eutra_cell_identity");
        assert_eq!(buf.fields()[1].value, FieldValue::U32(eci));
    }

    #[test]
    fn parse_global_ran_node_id() {
        let data = [
            0x00, // CHOICE preamble
            0x00, // SEQUENCE preamble
            0x00, 0xF1, 0x10, // PLMN
            0x00, // gNB-ID CHOICE preamble
            0x0A, // gNB-ID length = 10 + 22 = 32
            0x00, 0x00, 0x00, 0x01, // gNB-ID = 1
        ];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 27, &data, 0);
        assert_eq!(buf.fields()[0].name(), "choice");
        assert_eq!(buf.fields()[0].value, FieldValue::U8(0));
        let display_fn = buf.fields()[0].descriptor.display_fn.unwrap();
        assert_eq!(
            display_fn(&buf.fields()[0].value, buf.fields()),
            Some("globalGNB-ID")
        );
        assert_eq!(buf.fields()[1].name(), "plmn_identity");
        assert_eq!(buf.fields()[2].name(), "gnb_id_length");
        assert_eq!(buf.fields()[2].value, FieldValue::U8(32));
        assert_eq!(buf.fields()[3].name(), "gnb_id");
        assert_eq!(buf.fields()[3].value, FieldValue::U32(1));
    }

    #[test]
    fn parse_uli_nr() {
        let nci: u64 = 0x000000001;
        let nci_shifted = nci << 4;
        let mut data = vec![
            0x20, // CHOICE: NR
            0x00, // SEQUENCE preamble
            0x00, // NR-CGI preamble
            0x00, 0xF1, 0x10, // NR-CGI PLMN
        ];
        data.push(((nci_shifted >> 32) & 0xFF) as u8);
        data.push(((nci_shifted >> 24) & 0xFF) as u8);
        data.push(((nci_shifted >> 16) & 0xFF) as u8);
        data.push(((nci_shifted >> 8) & 0xFF) as u8);
        data.push((nci_shifted & 0xFF) as u8);
        data.extend_from_slice(&[0x00, 0x00, 0xF1, 0x10, 0x00, 0x01, 0x02]);

        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 121, &data, 0);
        assert_eq!(buf.fields()[0].name(), "choice");
        assert_eq!(buf.fields()[0].value, FieldValue::U8(1));
        assert_eq!(buf.fields()[1].name(), "plmn_identity");
        assert_eq!(buf.fields()[2].name(), "nr_cell_identity");
        assert_eq!(buf.fields()[2].value, FieldValue::U64(nci));
        assert_eq!(buf.fields()[3].name(), "tac");
        assert_eq!(buf.fields()[3].value, FieldValue::U32(258));
    }

    #[test]
    fn parse_nas_pdu() {
        let nas_bytes = [0x7E, 0x00, 0x41];
        let mut data = vec![nas_bytes.len() as u8];
        data.extend_from_slice(&nas_bytes);

        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 38, &data, 0);
        assert_eq!(buf.fields()[0].name(), "nas_pdu");
        if let FieldValue::Object(ref range) = buf.fields()[0].value {
            let inner = buf.nested_fields(range);
            let mt = inner.iter().find(|f| f.name() == "message_type").unwrap();
            assert_eq!(mt.value, FieldValue::U8(0x41));
        } else {
            panic!("expected Object");
        }
    }

    #[test]
    fn parse_handover_type() {
        let data = [0x01];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 29, &data, 0);
        let display_fn = buf.fields()[0].descriptor.display_fn.unwrap();
        assert_eq!(
            display_fn(&buf.fields()[0].value, buf.fields()),
            Some("fivegs_to_eps")
        );
    }

    #[test]
    fn parse_time_to_wait() {
        let data = [0x03];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 107, &data, 0);
        let display_fn = buf.fields()[0].descriptor.display_fn.unwrap();
        assert_eq!(
            display_fn(&buf.fields()[0].value, buf.fields()),
            Some("v10s")
        );
    }

    #[test]
    fn parse_unknown_ie() {
        let data = [0x01, 0x02, 0x03];
        let mut buf = DissectBuffer::new();
        push_and_get_fields(&mut buf, 9999, &data, 0);
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(&data[..]));
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
