//! E1AP IE value decoders.
//!
//! Decodes the UE E1AP IDs, the gNB-CU-UP identity, names and capacity,
//! CN Support, Cause, Time To Wait, the Serving PLMN, and the
//! `System-BearerContext...` CHOICEs whose E-UTRAN / NG-RAN IE containers
//! carry the DRB and PDU session resource setup lists with their UP
//! transport layer information (GTP tunnel endpoints). Other IEs are kept
//! raw.
//!
//! ## References
//! - 3GPP TS 37.483 v19.4.0, Sections 9.3 (IE semantics), 9.4.4 (PDU
//!   contents) and 9.4.5 (IE ASN.1):
//!   <https://www.3gpp.org/ftp/Specs/archive/37_series/37.483/>
//! - ITU-T Rec. X.691 (APER): <https://www.itu.int/rec/T-REC-X.691>

use packet_dissector_aper::AperReader;
use packet_dissector_aper::ap::{self, MAX_DEPTH};
use packet_dissector_aper::helpers::{read_sequence_preamble, skip_sequence_tail};
use packet_dissector_aper::ies;
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

use crate::SPEC;

// ── Field descriptors ──────────────────────────────────────────────────

static FD_GNB_CU_CP_UE_E1AP_ID: FieldDescriptor = FieldDescriptor::new(
    "gnb_cu_cp_ue_e1ap_id",
    "gNB-CU-CP UE E1AP ID",
    FieldType::U32,
);

static FD_GNB_CU_UP_UE_E1AP_ID: FieldDescriptor = FieldDescriptor::new(
    "gnb_cu_up_ue_e1ap_id",
    "gNB-CU-UP UE E1AP ID",
    FieldType::U32,
);

static FD_TRANSACTION_ID: FieldDescriptor =
    FieldDescriptor::new("transaction_id", "Transaction ID", FieldType::U8);

static FD_GNB_CU_UP_ID: FieldDescriptor =
    FieldDescriptor::new("gnb_cu_up_id", "gNB-CU-UP ID", FieldType::U64);

static FD_GNB_CU_UP_NAME: FieldDescriptor =
    FieldDescriptor::new("gnb_cu_up_name", "gNB-CU-UP Name", FieldType::Str);

static FD_GNB_CU_CP_NAME: FieldDescriptor =
    FieldDescriptor::new("gnb_cu_cp_name", "gNB-CU-CP Name", FieldType::Str);

static FD_CN_SUPPORT: FieldDescriptor =
    FieldDescriptor::new("cn_support", "CN Support", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(0) => Some("c-epc"),
            FieldValue::U8(1) => Some("c-5gc"),
            FieldValue::U8(2) => Some("both"),
            _ => None,
        },
    );

static FD_GNB_CU_UP_CAPACITY: FieldDescriptor =
    FieldDescriptor::new("gnb_cu_up_capacity", "gNB-CU-UP Capacity", FieldType::U8);

static FD_TIME_TO_WAIT: FieldDescriptor =
    FieldDescriptor::new("time_to_wait", "Time To Wait", FieldType::U8).with_display_fn(|v, _| {
        match v {
            FieldValue::U8(t) => time_to_wait_name(*t),
            _ => None,
        }
    });

static FD_SYSTEM_CHOICE: FieldDescriptor =
    FieldDescriptor::new("system_choice", "System", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(0) => Some("e-UTRAN"),
            FieldValue::U8(1) => Some("nG-RAN"),
            FieldValue::U8(2) => Some("choice-extension"),
            _ => None,
        },
    );

static FD_NESTED_IES: FieldDescriptor = FieldDescriptor::new(
    "nested_ies",
    "Nested Information Elements",
    FieldType::Array,
);

static FD_ITEMS: FieldDescriptor = FieldDescriptor::new("items", "Items", FieldType::Array);

static FD_DRB_SETUP_ITEM: FieldDescriptor =
    FieldDescriptor::new("drb_setup_item", "DRB Setup Item", FieldType::Object);

static FD_PDU_SESSION_RESOURCE_SETUP_ITEM: FieldDescriptor = FieldDescriptor::new(
    "pdu_session_resource_setup_item",
    "PDU Session Resource Setup Item",
    FieldType::Object,
);

static FD_DRB_ID: FieldDescriptor = FieldDescriptor::new("drb_id", "DRB ID", FieldType::U8);

static FD_PDU_SESSION_ID: FieldDescriptor =
    FieldDescriptor::new("pdu_session_id", "PDU Session ID", FieldType::U8);

static FD_INTEGRITY_PROTECTION_RESULT: FieldDescriptor = FieldDescriptor::new(
    "integrity_protection_result",
    "Integrity Protection Result",
    FieldType::U8,
)
.optional()
.with_display_fn(|v, _| protection_result_name(v));

static FD_CONFIDENTIALITY_PROTECTION_RESULT: FieldDescriptor = FieldDescriptor::new(
    "confidentiality_protection_result",
    "Confidentiality Protection Result",
    FieldType::U8,
)
.optional()
.with_display_fn(|v, _| protection_result_name(v));

static FD_S1_DL_UP_TNL_INFORMATION: FieldDescriptor = FieldDescriptor::new(
    "s1_dl_up_tnl_information",
    "S1 DL UP TNL Information",
    FieldType::Object,
);

static FD_NG_DL_UP_TNL_INFORMATION: FieldDescriptor = FieldDescriptor::new(
    "ng_dl_up_tnl_information",
    "NG DL UP TNL Information",
    FieldType::Object,
);

static FD_DATA_FORWARDING_INFORMATION: FieldDescriptor = FieldDescriptor::new(
    "data_forwarding_information",
    "Data Forwarding Information",
    FieldType::Object,
)
.optional();

static FD_UL_DATA_FORWARDING: FieldDescriptor = FieldDescriptor::new(
    "ul_data_forwarding",
    "UL Data Forwarding",
    FieldType::Object,
)
.optional();

static FD_DL_DATA_FORWARDING: FieldDescriptor = FieldDescriptor::new(
    "dl_data_forwarding",
    "DL Data Forwarding",
    FieldType::Object,
)
.optional();

static FD_UL_UP_TRANSPORT_PARAMETERS: FieldDescriptor = FieldDescriptor::new(
    "ul_up_transport_parameters",
    "UL UP Transport Parameters",
    FieldType::Array,
);

static FD_UP_PARAMETERS_ITEM: FieldDescriptor = FieldDescriptor::new(
    "up_parameters_item",
    "UP Parameters Item",
    FieldType::Object,
);

static FD_CELL_GROUP_ID: FieldDescriptor =
    FieldDescriptor::new("cell_group_id", "Cell Group ID", FieldType::U8);

static FD_DL_UP_UNCHANGED: FieldDescriptor =
    FieldDescriptor::new("dl_up_unchanged", "DL UP Unchanged", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(0) => Some("true"),
            _ => None,
        });

static FD_DRB_SETUP_LIST: FieldDescriptor =
    FieldDescriptor::new("drb_setup_list", "DRB Setup List", FieldType::Array);

static FD_DRB_FAILED_LIST: FieldDescriptor =
    FieldDescriptor::new("drb_failed_list", "DRB Failed List", FieldType::Array).optional();

static FD_DRB_FAILED_ITEM: FieldDescriptor =
    FieldDescriptor::new("drb_failed_item", "DRB Failed Item", FieldType::Object);

static FD_QOS_FLOW_SETUP_LIST: FieldDescriptor = FieldDescriptor::new(
    "qos_flow_setup_list",
    "QoS Flow Setup List",
    FieldType::Array,
);

static FD_QOS_FLOW_FAILED_LIST: FieldDescriptor = FieldDescriptor::new(
    "qos_flow_failed_list",
    "QoS Flow Failed List",
    FieldType::Array,
)
.optional();

static FD_QOS_FLOW_FAILED_ITEM: FieldDescriptor = FieldDescriptor::new(
    "qos_flow_failed_item",
    "QoS Flow Failed Item",
    FieldType::Object,
);

static FD_QOS_FLOW_IDENTIFIER: FieldDescriptor =
    FieldDescriptor::new("qos_flow_identifier", "QoS Flow Identifier", FieldType::U8);

// ── ASN.1 constants ────────────────────────────────────────────────────

/// `GNB-CU-CP-UE-E1AP-ID` / `GNB-CU-UP-UE-E1AP-ID ::= INTEGER
/// (0..4294967295)`.
///
/// 3GPP TS 37.483, Section 9.4.5.
const UE_E1AP_ID_MAX: u64 = 4_294_967_295;

/// `GNB-CU-UP-ID ::= INTEGER (0..68719476735)`.
///
/// 3GPP TS 37.483, Section 9.4.5.
const GNB_CU_UP_ID_MAX: u64 = 68_719_476_735;

/// `TransactionID ::= INTEGER (0..255, ...)`.
///
/// 3GPP TS 37.483, Section 9.4.5.
const TRANSACTION_ID_MAX: u64 = 255;

/// `GNB-CU-UP-Capacity ::= INTEGER (0..255)`.
///
/// 3GPP TS 37.483, Section 9.4.5.
const GNB_CU_UP_CAPACITY_MAX: u64 = 255;

/// `PrintableString (SIZE(1..150, ...))` of `GNB-CU-UP-Name` /
/// `GNB-CU-CP-Name`.
///
/// 3GPP TS 37.483, Section 9.4.5.
const NAME_MAX: u64 = 150;

/// `CNSupport ::= ENUMERATED { c-epc, c-5gc, both, ... }`.
///
/// 3GPP TS 37.483, Section 9.4.5.
const CN_SUPPORT_ROOT_COUNT: u64 = 3;

/// `TimeToWait ::= ENUMERATED {v1s, v2s, v5s, v10s, v20s, v60s, ...}`.
///
/// 3GPP TS 37.483, Section 9.4.5.
const TIME_TO_WAIT_ROOT_COUNT: u64 = 6;

/// Root sizes of `CauseRadioNetwork`, `CauseTransport`, `CauseProtocol`
/// and `CauseMisc`.
///
/// 3GPP TS 37.483 v19.4.0, Section 9.4.5.
const CAUSE_ROOT_COUNTS: [u64; 4] = [25, 2, 7, 5];

/// `DRB-ID ::= INTEGER (1..32, ...)`.
///
/// 3GPP TS 37.483, Section 9.4.5.
const DRB_ID_MAX: u64 = 32;

/// `PDU-Session-ID ::= INTEGER (0..255)`.
///
/// 3GPP TS 37.483, Section 9.4.5.
const PDU_SESSION_ID_MAX: u64 = 255;

/// `QoS-Flow-Identifier ::= INTEGER (0..63)`.
///
/// 3GPP TS 37.483, Section 9.4.5.
const QOS_FLOW_IDENTIFIER_MAX: u64 = 63;

/// `Cell-Group-ID ::= INTEGER (0..3, ...)`.
///
/// 3GPP TS 37.483, Section 9.4.5.
const CELL_GROUP_ID_MAX: u64 = 3;

/// `maxnoofDRBs`.
///
/// 3GPP TS 37.483, Section 9.4.7.
const MAX_NO_OF_DRBS: u64 = 32;

/// `maxnoofPDUSessionResource`.
///
/// 3GPP TS 37.483, Section 9.4.7.
const MAX_NO_OF_PDU_SESSION_RESOURCE: u64 = 256;

/// `maxnoofQoSFlows`.
///
/// 3GPP TS 37.483, Section 9.4.7.
const MAX_NO_OF_QOS_FLOWS: u64 = 64;

/// `maxnoofUPParameters`.
///
/// 3GPP TS 37.483, Section 9.4.7.
const MAX_NO_OF_UP_PARAMETERS: u64 = 8;

/// `IntegrityProtectionResult` / `ConfidentialityProtectionResult ::=
/// ENUMERATED { performed, not-performed, ... }`.
///
/// 3GPP TS 37.483, Section 9.4.5.
const PROTECTION_RESULT_ROOT_COUNT: u64 = 2;

// ── Dispatch ───────────────────────────────────────────────────────────

/// Decodes the value of IE `id` (see [`packet_dissector_aper::ap::PushValueFn`]).
///
/// IE IDs are the `id-` constants of 3GPP TS 37.483, Section 9.4.7.
pub(crate) fn push_ie_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    id: u16,
    data: &'pkt [u8],
    offset: usize,
    depth: u8,
) -> bool {
    match id {
        // Cause — TS 37.483, Section 9.3.1.2.
        0 => ies::push_cause(buf, &CAUSE_ROOT_COUNTS, data, offset),
        // gNB-CU-CP-UE-E1AP-ID — Section 9.3.1.4.
        2 => ies::push_unsigned(buf, &FD_GNB_CU_CP_UE_E1AP_ID, UE_E1AP_ID_MAX, data, offset),
        // gNB-CU-UP-UE-E1AP-ID — Section 9.3.1.5.
        3 => ies::push_unsigned(buf, &FD_GNB_CU_UP_UE_E1AP_ID, UE_E1AP_ID_MAX, data, offset),
        // gNB-CU-UP-ID — Section 9.3.1.15.
        7 => ies::push_unsigned(buf, &FD_GNB_CU_UP_ID, GNB_CU_UP_ID_MAX, data, offset),
        // gNB-CU-UP-Name — Section 9.3.1.16.
        8 => ies::push_printable_string(buf, &FD_GNB_CU_UP_NAME, 1, NAME_MAX, data, offset),
        // gNB-CU-CP-Name — Section 9.3.1.17.
        9 => ies::push_printable_string(buf, &FD_GNB_CU_CP_NAME, 1, NAME_MAX, data, offset),
        // CNSupport — Section 9.3.1.20.
        10 => ies::push_enumerated(
            buf,
            &FD_CN_SUPPORT,
            CN_SUPPORT_ROOT_COUNT,
            true,
            data,
            offset,
        ),
        // TimeToWait — Section 9.3.1.18.
        12 => ies::push_enumerated(
            buf,
            &FD_TIME_TO_WAIT,
            TIME_TO_WAIT_ROOT_COUNT,
            true,
            data,
            offset,
        ),
        // System-BearerContextSetupRequest / -SetupResponse /
        // -ModificationRequest / -ModificationResponse /
        // -ModificationConfirm / -ModificationRequired — Section 9.4.4.
        15 | 16 | 18 | 19 | 20 | 21 if depth < MAX_DEPTH => {
            push_system_bearer_context(buf, data, offset, depth)
        }
        // DRB-Setup-List-EUTRAN — Section 9.4.5.
        37 => push_drb_setup_list_eutran(buf, data, offset),
        // PDU-Session-Resource-Setup-List — Section 9.4.5.
        46 => push_pdu_session_resource_setup_list(buf, data, offset),
        // TransactionID — Section 9.3.1.53.
        57 => {
            ies::push_extensible_unsigned(buf, &FD_TRANSACTION_ID, TRANSACTION_ID_MAX, data, offset)
        }
        // Serving-PLMN — PLMN-Identity, Section 9.3.1.7.
        58 => push_plmn_identity(buf, data, offset),
        // gNB-CU-UP-Capacity — Section 9.3.1.30.
        64 => ies::push_unsigned(
            buf,
            &FD_GNB_CU_UP_CAPACITY,
            GNB_CU_UP_CAPACITY_MAX,
            data,
            offset,
        ),
        _ => false,
    }
}

// ── Individual decoders ────────────────────────────────────────────────

/// `PLMN-Identity ::= OCTET STRING (SIZE(3))`: octet-aligned with no
/// length (ITU-T Rec. X.691, Section 17.7), so the value is exactly the
/// three octets.
///
/// 3GPP TS 37.483, Section 9.3.1.7.
fn push_plmn_identity<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.len() != 3 {
        return false;
    }
    buf.push_field(
        &ies::FD_PLMN_IDENTITY,
        FieldValue::Bytes(data),
        offset..offset + 3,
    );
    true
}

/// `System-BearerContext... ::= CHOICE { e-UTRAN-... ProtocolIE-Container,
/// nG-RAN-... ProtocolIE-Container, choice-extension
/// ProtocolIE-SingleContainer }`: a 2-bit index (three alternatives, no
/// extension marker), then the octet-aligned IE container, whose IEs are
/// decoded like those of the message.
///
/// 3GPP TS 37.483, Section 9.4.4; ITU-T Rec. X.691, Sections 11.5.7.3
/// (the two-octet IE count is octet-aligned) and 23.
fn push_system_bearer_context<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    depth: u8,
) -> bool {
    let Some((&first, container)) = data.split_first() else {
        return false;
    };
    let choice = first >> 6;
    if choice > 1 {
        // choice-extension (2) is not decoded; 3 is out of range.
        return false;
    }
    buf.push_field(
        &FD_SYSTEM_CHOICE,
        FieldValue::U8(choice),
        offset..offset + 1,
    );
    ap::push_ie_container(
        buf,
        &SPEC,
        &FD_NESTED_IES,
        container,
        offset + 1,
        depth + 1,
        false,
    );
    true
}

/// `DRB-Setup-List-EUTRAN ::= SEQUENCE (SIZE(1..maxnoofDRBs)) OF
/// DRB-Setup-Item-EUTRAN`, each `SEQUENCE { dRB-ID,
/// s1-DL-UP-TNL-Information UP-TNL-Information,
/// data-Forwarding-Information-Response Data-Forwarding-Information
/// OPTIONAL, uL-UP-Transport-Parameters UP-Parameters, s1-DL-UP-Unchanged
/// ENUMERATED {true, ...} OPTIONAL, iE-Extensions OPTIONAL, ... }`.
///
/// 3GPP TS 37.483, Sections 9.3.3.x and 9.4.5; ITU-T Rec. X.691, Sections
/// 19, 20.
fn push_drb_setup_list_eutran<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    ies::push_value_with(buf, data, |buf, r| {
        ies::push_sequence_of(buf, &FD_ITEMS, r, offset, 1, MAX_NO_OF_DRBS, |buf, r| {
            ies::push_object(buf, &FD_DRB_SETUP_ITEM, r, offset, |buf, r| {
                let extended = r.read_bit()?;
                let forwarding = r.read_bit()?;
                let unchanged = r.read_bit()?;
                let ie_extensions = r.read_bit()?;
                ies::push_small_integer(buf, &FD_DRB_ID, r, offset, 1, DRB_ID_MAX)?;
                ies::push_up_tnl_object(buf, &FD_S1_DL_UP_TNL_INFORMATION, r, offset)?;
                if forwarding {
                    push_data_forwarding_information(buf, r, offset)?;
                }
                push_up_parameters(buf, r, offset)?;
                if unchanged {
                    ies::push_enumerated_field(buf, &FD_DL_UP_UNCHANGED, r, offset, 1, true)?;
                }
                skip_sequence_tail(r, extended, ie_extensions)
            })
        })
    })
}

/// `PDU-Session-Resource-Setup-List ::= SEQUENCE (SIZE(1..
/// maxnoofPDUSessionResource)) OF PDU-Session-Resource-Setup-Item`, each
/// `SEQUENCE { pDU-Session-ID, securityResult SecurityResult OPTIONAL,
/// nG-DL-UP-TNL-Information UP-TNL-Information,
/// pDU-Session-Data-Forwarding-Information-Response
/// Data-Forwarding-Information OPTIONAL, nG-DL-UP-Unchanged ENUMERATED
/// {true, ...} OPTIONAL, dRB-Setup-List-NG-RAN, dRB-Failed-List-NG-RAN
/// OPTIONAL, iE-Extensions OPTIONAL, ... }`.
///
/// 3GPP TS 37.483, Sections 9.3.3.x and 9.4.5; ITU-T Rec. X.691, Sections
/// 19, 20.
fn push_pdu_session_resource_setup_list<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    ies::push_value_with(buf, data, |buf, r| {
        ies::push_sequence_of(
            buf,
            &FD_ITEMS,
            r,
            offset,
            1,
            MAX_NO_OF_PDU_SESSION_RESOURCE,
            |buf, r| {
                ies::push_object(
                    buf,
                    &FD_PDU_SESSION_RESOURCE_SETUP_ITEM,
                    r,
                    offset,
                    |buf, r| push_pdu_session_resource_setup_item(buf, r, offset),
                )
            },
        )
    })
}

fn push_pdu_session_resource_setup_item<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    r: &mut AperReader<'pkt>,
    offset: usize,
) -> Result<(), PacketError> {
    let extended = r.read_bit()?;
    let security = r.read_bit()?;
    let forwarding = r.read_bit()?;
    let unchanged = r.read_bit()?;
    let failed = r.read_bit()?;
    let ie_extensions = r.read_bit()?;
    ies::push_constrained_u8(buf, &FD_PDU_SESSION_ID, r, offset, 0, PDU_SESSION_ID_MAX)?;
    if security {
        // SecurityResult ::= SEQUENCE { integrityProtectionResult,
        // confidentialityProtectionResult, iE-Extensions OPTIONAL, ... }.
        let (sec_extended, sec_ie_extensions) = read_sequence_preamble(r)?;
        ies::push_enumerated_field(
            buf,
            &FD_INTEGRITY_PROTECTION_RESULT,
            r,
            offset,
            PROTECTION_RESULT_ROOT_COUNT,
            true,
        )?;
        ies::push_enumerated_field(
            buf,
            &FD_CONFIDENTIALITY_PROTECTION_RESULT,
            r,
            offset,
            PROTECTION_RESULT_ROOT_COUNT,
            true,
        )?;
        skip_sequence_tail(r, sec_extended, sec_ie_extensions)?;
    }
    ies::push_up_tnl_object(buf, &FD_NG_DL_UP_TNL_INFORMATION, r, offset)?;
    if forwarding {
        push_data_forwarding_information(buf, r, offset)?;
    }
    if unchanged {
        ies::push_enumerated_field(buf, &FD_DL_UP_UNCHANGED, r, offset, 1, true)?;
    }
    ies::push_sequence_of(
        buf,
        &FD_DRB_SETUP_LIST,
        r,
        offset,
        1,
        MAX_NO_OF_DRBS,
        |buf, r| {
            ies::push_object(buf, &FD_DRB_SETUP_ITEM, r, offset, |buf, r| {
                push_drb_setup_item_ng_ran(buf, r, offset)
            })
        },
    )?;
    if failed {
        ies::push_sequence_of(
            buf,
            &FD_DRB_FAILED_LIST,
            r,
            offset,
            1,
            MAX_NO_OF_DRBS,
            |buf, r| {
                // DRB-Failed-Item-NG-RAN ::= SEQUENCE { dRB-ID, cause,
                // iE-Extensions OPTIONAL, ... }.
                ies::push_object(buf, &FD_DRB_FAILED_ITEM, r, offset, |buf, r| {
                    let (item_extended, item_ie_extensions) = read_sequence_preamble(r)?;
                    ies::push_small_integer(buf, &FD_DRB_ID, r, offset, 1, DRB_ID_MAX)?;
                    let cause = ies::read_cause(r, &CAUSE_ROOT_COUNTS)?;
                    ies::push_cause_fields(buf, &cause, offset);
                    skip_sequence_tail(r, item_extended, item_ie_extensions)
                })
            },
        )?;
    }
    skip_sequence_tail(r, extended, ie_extensions)
}

/// `DRB-Setup-Item-NG-RAN ::= SEQUENCE { dRB-ID,
/// dRB-data-Forwarding-Information-Response Data-Forwarding-Information
/// OPTIONAL, uL-UP-Transport-Parameters UP-Parameters, flow-Setup-List
/// QoS-Flow-List, flow-Failed-List QoS-Flow-Failed-List OPTIONAL,
/// iE-Extensions OPTIONAL, ... }`.
///
/// 3GPP TS 37.483, Section 9.4.5.
fn push_drb_setup_item_ng_ran<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    r: &mut AperReader<'pkt>,
    offset: usize,
) -> Result<(), PacketError> {
    let extended = r.read_bit()?;
    let forwarding = r.read_bit()?;
    let failed = r.read_bit()?;
    let ie_extensions = r.read_bit()?;
    ies::push_small_integer(buf, &FD_DRB_ID, r, offset, 1, DRB_ID_MAX)?;
    if forwarding {
        push_data_forwarding_information(buf, r, offset)?;
    }
    push_up_parameters(buf, r, offset)?;
    // QoS-Flow-List ::= SEQUENCE (SIZE(1..maxnoofQoSFlows)) OF QoS-Flow-Item
    // { qoS-Flow-Identifier, iE-Extensions OPTIONAL, ... }.
    ies::push_sequence_of(
        buf,
        &FD_QOS_FLOW_SETUP_LIST,
        r,
        offset,
        1,
        MAX_NO_OF_QOS_FLOWS,
        |buf, r| {
            let (item_extended, item_ie_extensions) = read_sequence_preamble(r)?;
            ies::push_constrained_u8(
                buf,
                &FD_QOS_FLOW_IDENTIFIER,
                r,
                offset,
                0,
                QOS_FLOW_IDENTIFIER_MAX,
            )?;
            skip_sequence_tail(r, item_extended, item_ie_extensions)
        },
    )?;
    if failed {
        // QoS-Flow-Failed-List ::= SEQUENCE (SIZE(1..maxnoofQoSFlows)) OF
        // QoS-Flow-Failed-Item { qoS-Flow-Identifier, cause, iE-Extensions
        // OPTIONAL, ... }.
        ies::push_sequence_of(
            buf,
            &FD_QOS_FLOW_FAILED_LIST,
            r,
            offset,
            1,
            MAX_NO_OF_QOS_FLOWS,
            |buf, r| {
                ies::push_object(buf, &FD_QOS_FLOW_FAILED_ITEM, r, offset, |buf, r| {
                    let (item_extended, item_ie_extensions) = read_sequence_preamble(r)?;
                    ies::push_constrained_u8(
                        buf,
                        &FD_QOS_FLOW_IDENTIFIER,
                        r,
                        offset,
                        0,
                        QOS_FLOW_IDENTIFIER_MAX,
                    )?;
                    let cause = ies::read_cause(r, &CAUSE_ROOT_COUNTS)?;
                    ies::push_cause_fields(buf, &cause, offset);
                    skip_sequence_tail(r, item_extended, item_ie_extensions)
                })
            },
        )?;
    }
    skip_sequence_tail(r, extended, ie_extensions)
}

/// `Data-Forwarding-Information ::= SEQUENCE { uL-Data-Forwarding
/// UP-TNL-Information OPTIONAL, dL-Data-Forwarding UP-TNL-Information
/// OPTIONAL, iE-Extensions OPTIONAL, ... }`.
///
/// 3GPP TS 37.483, Section 9.4.5.
fn push_data_forwarding_information<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    r: &mut AperReader<'pkt>,
    offset: usize,
) -> Result<(), PacketError> {
    ies::push_object(buf, &FD_DATA_FORWARDING_INFORMATION, r, offset, |buf, r| {
        let extended = r.read_bit()?;
        let ul = r.read_bit()?;
        let dl = r.read_bit()?;
        let ie_extensions = r.read_bit()?;
        if ul {
            ies::push_up_tnl_object(buf, &FD_UL_DATA_FORWARDING, r, offset)?;
        }
        if dl {
            ies::push_up_tnl_object(buf, &FD_DL_DATA_FORWARDING, r, offset)?;
        }
        skip_sequence_tail(r, extended, ie_extensions)
    })
}

/// `UP-Parameters ::= SEQUENCE (SIZE(1..maxnoofUPParameters)) OF
/// UP-Parameters-Item { uP-TNL-Information UP-TNL-Information,
/// cell-Group-ID Cell-Group-ID, iE-Extensions OPTIONAL, ... }`.
///
/// 3GPP TS 37.483, Section 9.4.5.
fn push_up_parameters<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    r: &mut AperReader<'pkt>,
    offset: usize,
) -> Result<(), PacketError> {
    ies::push_sequence_of(
        buf,
        &FD_UL_UP_TRANSPORT_PARAMETERS,
        r,
        offset,
        1,
        MAX_NO_OF_UP_PARAMETERS,
        |buf, r| {
            ies::push_object(buf, &FD_UP_PARAMETERS_ITEM, r, offset, |buf, r| {
                let (extended, ie_extensions) = read_sequence_preamble(r)?;
                let tnl = ies::read_up_tnl(r)?;
                ies::push_up_tnl_fields(buf, &tnl, offset);
                ies::push_small_integer(buf, &FD_CELL_GROUP_ID, r, offset, 0, CELL_GROUP_ID_MAX)?;
                skip_sequence_tail(r, extended, ie_extensions)
            })
        },
    )
}

/// Returns the name of an Integrity / Confidentiality Protection Result.
///
/// 3GPP TS 37.483, Section 9.4.5.
fn protection_result_name(v: &FieldValue<'_>) -> Option<&'static str> {
    match v {
        FieldValue::U8(0) => Some("performed"),
        FieldValue::U8(1) => Some("not-performed"),
        _ => None,
    }
}

/// Returns the name of a TimeToWait value.
///
/// 3GPP TS 37.483, Section 9.4.5.
fn time_to_wait_name(value: u8) -> Option<&'static str> {
    Some(match value {
        0 => "v1s",
        1 => "v2s",
        2 => "v5s",
        3 => "v10s",
        4 => "v20s",
        5 => "v60s",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 37.483 IE Decoder Coverage
    //!
    //! | Spec Section | Description                             | Test                            |
    //! |--------------|-----------------------------------------|---------------------------------|
    //! | 9.3.1.7      | PLMN identity of the wrong size         | plmn_identity_wrong_size        |
    //! | 9.4.4        | System CHOICE: choice-extension / empty | system_choice_not_decoded       |
    //! | 9.4.4        | Nested container beyond the depth limit | system_beyond_depth_kept_raw    |
    //! | 9.4.5        | Names                                   | names                           |

    use super::*;

    #[test]
    fn plmn_identity_wrong_size() {
        let mut buf = DissectBuffer::new();
        assert!(!push_plmn_identity(&mut buf, &[0x00], 0));
        assert!(push_ie_value(&mut buf, 58, &[0x00, 0xf1, 0x10], 0, 0));
    }

    #[test]
    fn system_choice_not_decoded() {
        let mut buf = DissectBuffer::new();
        assert!(!push_system_bearer_context(&mut buf, &[], 0, 0));
        assert!(!push_system_bearer_context(&mut buf, &[0x80, 0x00], 0, 0));
        assert!(!push_system_bearer_context(&mut buf, &[0xc0, 0x00], 0, 0));
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn system_beyond_depth_kept_raw() {
        let mut buf = DissectBuffer::new();
        assert!(!push_ie_value(
            &mut buf,
            16,
            &[0x40, 0x00, 0x00],
            0,
            MAX_DEPTH
        ));
        assert!(push_ie_value(&mut buf, 16, &[0x40, 0x00, 0x00], 0, 0));
        assert!(!push_ie_value(&mut buf, 9999, &[0x00], 0, 0));
    }

    #[test]
    fn names() {
        assert_eq!(time_to_wait_name(0), Some("v1s"));
        assert_eq!(time_to_wait_name(3), Some("v10s"));
        assert_eq!(time_to_wait_name(6), None);
        assert_eq!(
            protection_result_name(&FieldValue::U8(1)),
            Some("not-performed")
        );
        assert_eq!(protection_result_name(&FieldValue::U8(2)), None);
        let f = |d: &FieldDescriptor, v: FieldValue<'_>| (d.display_fn.unwrap())(&v, &[]);
        assert_eq!(f(&FD_CN_SUPPORT, FieldValue::U8(2)), Some("both"));
        assert_eq!(f(&FD_CN_SUPPORT, FieldValue::U8(3)), None);
        assert_eq!(f(&FD_SYSTEM_CHOICE, FieldValue::U8(1)), Some("nG-RAN"));
        assert_eq!(
            f(&FD_SYSTEM_CHOICE, FieldValue::U8(2)),
            Some("choice-extension")
        );
        assert_eq!(f(&FD_SYSTEM_CHOICE, FieldValue::U8(3)), None);
        assert_eq!(f(&FD_DL_UP_UNCHANGED, FieldValue::U8(0)), Some("true"));
        assert_eq!(f(&FD_DL_UP_UNCHANGED, FieldValue::U8(1)), None);
        assert_eq!(f(&FD_TIME_TO_WAIT, FieldValue::U8(5)), Some("v60s"));
        assert_eq!(f(&FD_TIME_TO_WAIT, FieldValue::U16(5)), None);
        assert_eq!(
            f(&FD_INTEGRITY_PROTECTION_RESULT, FieldValue::U8(0)),
            Some("performed")
        );
        assert_eq!(
            f(&FD_CONFIDENTIALITY_PROTECTION_RESULT, FieldValue::U8(0)),
            Some("performed")
        );
    }
}
