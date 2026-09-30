//! XnAP IE value decoders.
//!
//! Decodes the NG-RAN node UE XnAP IDs, Cause, Global NG-RAN Node ID,
//! Target Cell Global ID, Time To Wait, Interface Instance Indication, the
//! selected PLMN, the transparent containers (kept as raw octets) and the
//! PDU Session Resources Admitted List of the Handover Request Acknowledge
//! with its data forwarding UP transport layer information (GTP tunnel
//! endpoints). Other IEs are kept raw.
//!
//! ## References
//! - 3GPP TS 38.423 v19.4.0, Sections 9.2 (IE semantics) and 9.3.5 (IE
//!   ASN.1): <https://www.3gpp.org/ftp/Specs/archive/38_series/38.423/>
//! - ITU-T Rec. X.691 (APER): <https://www.itu.int/rec/T-REC-X.691>

use core::ops::Range;

use packet_dissector_aper::AperReader;
use packet_dissector_aper::helpers::{
    ensure_consumed, read_aligned_octets, read_bit_string_field, read_sequence_preamble, shift,
    skip_protocol_ie_single_container, skip_sequence_tail,
};
use packet_dissector_aper::ies;
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

// ── Field descriptors ──────────────────────────────────────────────────

static FD_NG_RAN_NODE_UE_XNAP_ID: FieldDescriptor = FieldDescriptor::new(
    "ng_ran_node_ue_xnap_id",
    "NG-RAN node UE XnAP ID",
    FieldType::U32,
);

static FD_NODE_CHOICE: FieldDescriptor =
    FieldDescriptor::new("node_choice", "NG-RAN Node Choice", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(0) => Some("gNB"),
            FieldValue::U8(1) => Some("ng-eNB"),
            FieldValue::U8(2) => Some("choice-extension"),
            _ => None,
        },
    );

static FD_GNB_ID: FieldDescriptor =
    FieldDescriptor::new("gnb_id", "gNB ID", FieldType::U32).optional();

static FD_GNB_ID_LENGTH: FieldDescriptor =
    FieldDescriptor::new("gnb_id_length", "gNB ID Length", FieldType::U8).optional();

static FD_ENB_ID_CHOICE: FieldDescriptor =
    FieldDescriptor::new("enb_id_choice", "eNB ID Choice", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(0) => Some("enb-ID-macro"),
            FieldValue::U8(1) => Some("enb-ID-shortmacro"),
            FieldValue::U8(2) => Some("enb-ID-longmacro"),
            FieldValue::U8(3) => Some("choice-extension"),
            _ => None,
        });

static FD_ENB_ID: FieldDescriptor =
    FieldDescriptor::new("enb_id", "eNB ID", FieldType::U32).optional();

static FD_CGI_CHOICE: FieldDescriptor =
    FieldDescriptor::new("cgi_choice", "CGI Choice", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(0) => Some("nr"),
            FieldValue::U8(1) => Some("e-utra"),
            FieldValue::U8(2) => Some("choice-extension"),
            _ => None,
        },
    );

static FD_EUTRA_CELL_IDENTITY: FieldDescriptor = FieldDescriptor::new(
    "eutra_cell_identity",
    "E-UTRA Cell Identity",
    FieldType::U32,
)
.optional();

static FD_INTERFACE_INSTANCE_INDICATION: FieldDescriptor = FieldDescriptor::new(
    "interface_instance_indication",
    "Interface Instance Indication",
    FieldType::U8,
);

static FD_TARGET_TO_SOURCE_CONTAINER: FieldDescriptor = FieldDescriptor::new(
    "target_to_source_container",
    "Target NG-RAN node To Source NG-RAN node Transparent Container",
    FieldType::Bytes,
);

static FD_MN_TO_SN_CONTAINER: FieldDescriptor =
    FieldDescriptor::new("mn_to_sn_container", "MN to SN Container", FieldType::Bytes);

static FD_SN_TO_MN_CONTAINER: FieldDescriptor =
    FieldDescriptor::new("sn_to_mn_container", "SN to MN Container", FieldType::Bytes);

static FD_ITEMS: FieldDescriptor = FieldDescriptor::new("items", "Items", FieldType::Array);

static FD_PDU_SESSION_RESOURCES_ADMITTED_ITEM: FieldDescriptor = FieldDescriptor::new(
    "pdu_session_resources_admitted_item",
    "PDU Session Resources Admitted Item",
    FieldType::Object,
);

static FD_PDU_SESSION_ID: FieldDescriptor =
    FieldDescriptor::new("pdu_session_id", "PDU Session ID", FieldType::U8);

static FD_DL_NG_U_TNL_INFORMATION_UNCHANGED: FieldDescriptor = FieldDescriptor::new(
    "dl_ng_u_tnl_information_unchanged",
    "DL NG-U TNL Information Unchanged",
    FieldType::U8,
)
.optional()
.with_display_fn(|v, _| match v {
    FieldValue::U8(0) => Some("true"),
    _ => None,
});

static FD_QOS_FLOWS_ADMITTED_LIST: FieldDescriptor = FieldDescriptor::new(
    "qos_flows_admitted_list",
    "QoS Flows Admitted List",
    FieldType::Array,
);

static FD_QOS_FLOWS_NOT_ADMITTED_LIST: FieldDescriptor = FieldDescriptor::new(
    "qos_flows_not_admitted_list",
    "QoS Flows Not Admitted List",
    FieldType::Array,
)
.optional();

static FD_QOS_FLOW_WITH_CAUSE_ITEM: FieldDescriptor = FieldDescriptor::new(
    "qos_flow_with_cause_item",
    "QoS Flow with Cause Item",
    FieldType::Object,
);

static FD_QOS_FLOW_IDENTIFIER: FieldDescriptor =
    FieldDescriptor::new("qos_flow_identifier", "QoS Flow Identifier", FieldType::U8);

static FD_DATA_FORWARDING_INFO_FROM_TARGET: FieldDescriptor = FieldDescriptor::new(
    "data_forwarding_info_from_target",
    "Data Forwarding Info from Target NG-RAN node",
    FieldType::Object,
)
.optional();

static FD_QOS_FLOWS_ACCEPTED_FOR_DATA_FORWARDING: FieldDescriptor = FieldDescriptor::new(
    "qos_flows_accepted_for_data_forwarding",
    "QoS Flows Accepted for Data Forwarding",
    FieldType::Array,
);

static FD_DL_DATA_FORWARDING: FieldDescriptor = FieldDescriptor::new(
    "dl_data_forwarding",
    "PDU Session Level DL Data Forwarding",
    FieldType::Object,
)
.optional();

static FD_UL_DATA_FORWARDING: FieldDescriptor = FieldDescriptor::new(
    "ul_data_forwarding",
    "PDU Session Level UL Data Forwarding",
    FieldType::Object,
)
.optional();

static FD_DATA_FORWARDING_RESPONSE_DRB_LIST: FieldDescriptor = FieldDescriptor::new(
    "data_forwarding_response_drb_list",
    "Data Forwarding Response DRB List",
    FieldType::Array,
)
.optional();

static FD_DATA_FORWARDING_RESPONSE_DRB_ITEM: FieldDescriptor = FieldDescriptor::new(
    "data_forwarding_response_drb_item",
    "Data Forwarding Response DRB Item",
    FieldType::Object,
);

static FD_DRB_ID: FieldDescriptor = FieldDescriptor::new("drb_id", "DRB ID", FieldType::U8);

static FD_DL_FORWARDING_UP_TNL: FieldDescriptor = FieldDescriptor::new(
    "dl_forwarding_up_tnl",
    "DL Forwarding UP TNL Information",
    FieldType::Object,
)
.optional();

static FD_UL_FORWARDING_UP_TNL: FieldDescriptor = FieldDescriptor::new(
    "ul_forwarding_up_tnl",
    "UL Forwarding UP TNL Information",
    FieldType::Object,
)
.optional();

// ── ASN.1 constants ────────────────────────────────────────────────────

/// `NG-RANnodeUEXnAPID ::= INTEGER (0.. 4294967295)`.
///
/// 3GPP TS 38.423, Section 9.3.5.
const UE_XNAP_ID_MAX: u64 = 4_294_967_295;

/// `InterfaceInstanceIndication ::= INTEGER (0..255, ...)`.
///
/// 3GPP TS 38.423, Section 9.3.5.
const INTERFACE_INSTANCE_INDICATION_MAX: u64 = 255;

/// Root sizes of `CauseRadioNetworkLayer`, `CauseTransportLayer`,
/// `CauseProtocol` and `CauseMisc`.
///
/// 3GPP TS 38.423 v19.4.0, Section 9.3.5.
const CAUSE_ROOT_COUNTS: [u64; 4] = [53, 2, 7, 5];

/// `PDUSession-ID ::= INTEGER (0..255)`.
///
/// 3GPP TS 38.423, Section 9.3.5.
const PDU_SESSION_ID_MAX: u64 = 255;

/// `QoSFlowIdentifier ::= INTEGER (0..63, ...)`.
///
/// 3GPP TS 38.423, Section 9.3.5.
const QOS_FLOW_IDENTIFIER_MAX: u64 = 63;

/// `DRB-ID ::= INTEGER (1..32, ...)`.
///
/// 3GPP TS 38.423, Section 9.3.5.
const DRB_ID_MAX: u64 = 32;

/// `maxnoofPDUSessions`.
///
/// 3GPP TS 38.423, Section 9.3.7.
const MAX_NO_OF_PDU_SESSIONS: u64 = 256;

/// `maxnoofQoSFlows`.
///
/// 3GPP TS 38.423, Section 9.3.7.
const MAX_NO_OF_QOS_FLOWS: u64 = 64;

/// `maxnoofDRBs`.
///
/// 3GPP TS 38.423, Section 9.3.7.
const MAX_NO_OF_DRBS: u64 = 32;

// ── Dispatch ───────────────────────────────────────────────────────────

/// Decodes the value of IE `id` (see [`packet_dissector_aper::ap::PushValueFn`]).
///
/// IE IDs are the `id-` constants of 3GPP TS 38.423, Section 9.3.7.
pub(crate) fn push_ie_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    id: u16,
    data: &'pkt [u8],
    offset: usize,
    _depth: u8,
) -> bool {
    match id {
        // Cause — TS 38.423, Section 9.2.3.2.
        7 => ies::push_cause(buf, &CAUSE_ROOT_COUNTS, data, offset),
        // GlobalNG-RAN-node-ID / SourceNG-RAN-node-ID /
        // Source-M-NG-RANnodeID — GlobalNG-RANNode-ID, Section 9.2.2.3.
        14 | 254 | 457 => push_global_ng_ran_node_id(buf, data, offset),
        // M-NG-RANnodeUEXnAPID / newNG-RANnodeUEXnAPID /
        // oldNG-RANnodeUEXnAPID / S-NG-RANnodeUEXnAPID /
        // sourceNG-RANnodeUEXnAPID / targetNG-RANnodeUEXnAPID /
        // nonF1-Terminating-IAB-DonorUEXnAPID /
        // F1-Terminating-IAB-DonorUEXnAPID — NG-RANnodeUEXnAPID, Section
        // 9.2.3.16.
        23 | 27 | 29 | 71 | 73 | 79 | 313 | 314 => ies::push_unsigned(
            buf,
            &FD_NG_RAN_NODE_UE_XNAP_ID,
            UE_XNAP_ID_MAX,
            data,
            offset,
        ),
        // MN-to-SN-Container — OCTET STRING, Section 9.1.2.1.
        24 => ies::push_octet_string(buf, &FD_MN_TO_SN_CONTAINER, data, offset),
        // PDUSessionResourcesAdmitted-List — Section 9.2.1.2.
        42 => push_pdu_session_resources_admitted_list(buf, data, offset),
        // selectedPLMN — PLMN-Identity, Section 9.2.2.4.
        64 => ies::push_plmn_identity(buf, data, offset),
        // SN-to-MN-Container — OCTET STRING, Section 9.1.2.2.
        72 => ies::push_octet_string(buf, &FD_SN_TO_MN_CONTAINER, data, offset),
        // TimeToWait — Section 9.2.3.28.
        76 => ies::push_time_to_wait(buf, data, offset),
        // Target2SourceNG-RANnodeTranspContainer — OCTET STRING, Section
        // 9.1.1.2.
        77 => ies::push_octet_string(buf, &FD_TARGET_TO_SOURCE_CONTAINER, data, offset),
        // targetCellGlobalID / requestedTargetCellGlobalID — Target-CGI,
        // Section 9.2.3.25.
        78 | 161 => push_target_cgi(buf, data, offset),
        // InterfaceInstanceIndication — Section 9.2.3.x.
        130 => ies::push_extensible_unsigned(
            buf,
            &FD_INTERFACE_INSTANCE_INDICATION,
            INTERFACE_INSTANCE_INDICATION_MAX,
            data,
            offset,
        ),
        _ => false,
    }
}

// ── Individual decoders ────────────────────────────────────────────────

/// A decoded node or cell identity: `(descriptor, value, byte range)`.
type IdField = (&'static FieldDescriptor, FieldValue<'static>, Range<usize>);

/// `GlobalNG-RANNode-ID ::= CHOICE { gNB GlobalgNB-ID, ng-eNB
/// GlobalngeNB-ID, choice-extension }`, with `GlobalgNB-ID ::= SEQUENCE {
/// plmn-id, gnb-id GNB-ID-Choice, iE-Extensions OPTIONAL, ... }`,
/// `GNB-ID-Choice ::= CHOICE { gnb-ID BIT STRING (SIZE(22..32)),
/// choice-extension }`, `GlobalngeNB-ID ::= SEQUENCE { plmn-id, enb-id
/// ENB-ID-Choice, iE-Extensions OPTIONAL, ... }` and `ENB-ID-Choice ::=
/// CHOICE { enb-ID-macro BIT STRING (SIZE(20)), enb-ID-shortmacro BIT
/// STRING (SIZE(18)), enb-ID-longmacro BIT STRING (SIZE(21)),
/// choice-extension }`.
///
/// 3GPP TS 38.423, Sections 9.2.2.1–9.2.2.3 and 9.3.5; ITU-T Rec. X.691,
/// Sections 16.10–16.11 (the identifiers exceed 16 bits, so they are
/// octet-aligned), 19 and 23.
fn push_global_ng_ran_node_id<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    struct Node<'a> {
        choice: u8,
        choice_range: Range<usize>,
        plmn: Option<(&'a [u8], Range<usize>)>,
        ids: [Option<IdField>; 2],
    }
    let decode = || -> Result<Node<'pkt>, PacketError> {
        let mut r = AperReader::new(data);
        let choice = r.read_choice_index(3, false)? as u8;
        let choice_range = r.byte_range_since(0);
        let mut node = Node {
            choice,
            choice_range,
            plmn: None,
            ids: [None, None],
        };
        if choice == 2 {
            skip_protocol_ie_single_container(&mut r)?;
        } else {
            let (extended, has_ie_extensions) = read_sequence_preamble(&mut r)?;
            node.plmn = Some(read_aligned_octets(&mut r, 3)?);
            if choice == 0 {
                if r.read_choice_index(2, false)? == 0 {
                    let len_start = r.bit_position();
                    let len = r.read_length(22, Some(32))?;
                    let len_range = r.byte_range_since(len_start);
                    let (id, id_range) = read_bit_string_field(&mut r, len as u32)?;
                    // `len` is at most 32, so both conversions are lossless.
                    node.ids = [
                        Some((&FD_GNB_ID_LENGTH, FieldValue::U8(len as u8), len_range)),
                        Some((&FD_GNB_ID, FieldValue::U32(id as u32), id_range)),
                    ];
                } else {
                    skip_protocol_ie_single_container(&mut r)?;
                }
            } else {
                let enb_start = r.bit_position();
                let enb_choice = r.read_choice_index(4, false)? as u8;
                let enb_range = r.byte_range_since(enb_start);
                let bits = match enb_choice {
                    0 => Some(20),
                    1 => Some(18),
                    2 => Some(21),
                    _ => None,
                };
                let id = match bits {
                    Some(bits) => {
                        let (id, id_range) = read_bit_string_field(&mut r, bits)?;
                        // At most 21 bits.
                        Some((&FD_ENB_ID, FieldValue::U32(id as u32), id_range))
                    }
                    None => {
                        skip_protocol_ie_single_container(&mut r)?;
                        None
                    }
                };
                node.ids = [
                    Some((&FD_ENB_ID_CHOICE, FieldValue::U8(enb_choice), enb_range)),
                    id,
                ];
            }
            skip_sequence_tail(&mut r, extended, has_ie_extensions)?;
        }
        ensure_consumed(&r, data)?;
        Ok(node)
    };
    let Ok(node) = decode() else {
        return false;
    };
    buf.push_field(
        &FD_NODE_CHOICE,
        FieldValue::U8(node.choice),
        shift(node.choice_range, offset),
    );
    if let Some((plmn, range)) = node.plmn {
        buf.push_field(
            &ies::FD_PLMN_IDENTITY,
            FieldValue::Bytes(plmn),
            shift(range, offset),
        );
    }
    for (desc, value, range) in node.ids.into_iter().flatten() {
        buf.push_field(desc, value, shift(range, offset));
    }
    true
}

/// `Target-CGI ::= CHOICE { nr NR-CGI, e-utra E-UTRA-CGI,
/// choice-extension }`, with `E-UTRA-CGI ::= SEQUENCE { plmn-id,
/// e-utra-CI BIT STRING (SIZE(28)), iE-Extension OPTIONAL, ... }`.
///
/// 3GPP TS 38.423, Sections 9.2.2.9, 9.2.2.11 and 9.3.5; ITU-T Rec. X.691,
/// Sections 16.10, 19 and 23.
fn push_target_cgi<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    ies::push_value_with(buf, data, |buf, r| {
        let choice = r.read_choice_index(3, false)? as u8;
        buf.push_field(
            &FD_CGI_CHOICE,
            FieldValue::U8(choice),
            shift(r.byte_range_since(0), offset),
        );
        match choice {
            0 => {
                let cgi = ies::read_nr_cgi(r)?;
                ies::push_nr_cgi_fields(buf, &cgi, offset);
            }
            1 => {
                let (extended, has_ie_extensions) = read_sequence_preamble(r)?;
                let (plmn, plmn_range) = read_aligned_octets(r, 3)?;
                let (cell, cell_range) = read_bit_string_field(r, 28)?;
                skip_sequence_tail(r, extended, has_ie_extensions)?;
                buf.push_field(
                    &ies::FD_PLMN_IDENTITY,
                    FieldValue::Bytes(plmn),
                    shift(plmn_range, offset),
                );
                // 28 bits always fit in a u32.
                buf.push_field(
                    &FD_EUTRA_CELL_IDENTITY,
                    FieldValue::U32(cell as u32),
                    shift(cell_range, offset),
                );
            }
            _ => skip_protocol_ie_single_container(r)?,
        }
        Ok(())
    })
}

/// `PDUSessionResourcesAdmitted-List ::= SEQUENCE (SIZE(1..
/// maxnoofPDUSessions)) OF PDUSessionResourcesAdmitted-Item`, each
/// `SEQUENCE { pduSessionId, pduSessionResourceAdmittedInfo,
/// iE-Extensions OPTIONAL, ... }`, with `PDUSessionResourceAdmittedInfo
/// ::= SEQUENCE { dL-NG-U-TNL-Information-Unchanged ENUMERATED {true, ...}
/// OPTIONAL, qosFlowsAdmitted-List, qosFlowsNotAdmitted-List
/// QoSFlows-List-withCause OPTIONAL, dataForwardingInfoFromTarget
/// DataForwardingInfoFromTargetNGRANnode OPTIONAL, iE-Extensions
/// OPTIONAL, ... }`.
///
/// 3GPP TS 38.423, Sections 9.2.1.2, 9.2.1.3 and 9.3.5; ITU-T Rec. X.691,
/// Sections 19, 20.
fn push_pdu_session_resources_admitted_list<'pkt>(
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
            MAX_NO_OF_PDU_SESSIONS,
            |buf, r| {
                ies::push_object(
                    buf,
                    &FD_PDU_SESSION_RESOURCES_ADMITTED_ITEM,
                    r,
                    offset,
                    |buf, r| {
                        let (extended, has_ie_extensions) = read_sequence_preamble(r)?;
                        ies::push_constrained_u8(
                            buf,
                            &FD_PDU_SESSION_ID,
                            r,
                            offset,
                            0,
                            PDU_SESSION_ID_MAX,
                        )?;
                        push_pdu_session_resource_admitted_info(buf, r, offset)?;
                        skip_sequence_tail(r, extended, has_ie_extensions)
                    },
                )
            },
        )
    })
}

fn push_pdu_session_resource_admitted_info<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    r: &mut AperReader<'pkt>,
    offset: usize,
) -> Result<(), PacketError> {
    let extended = r.read_bit()?;
    let unchanged = r.read_bit()?;
    let not_admitted = r.read_bit()?;
    let forwarding = r.read_bit()?;
    let has_ie_extensions = r.read_bit()?;
    if unchanged {
        ies::push_enumerated_field(
            buf,
            &FD_DL_NG_U_TNL_INFORMATION_UNCHANGED,
            r,
            offset,
            1,
            true,
        )?;
    }
    // QoSFlowsAdmitted-List ::= SEQUENCE (SIZE(1..maxnoofQoSFlows)) OF
    // QoSFlowsAdmitted-Item { qfi, iE-Extension OPTIONAL, ... }.
    push_qos_flow_list(buf, r, offset, &FD_QOS_FLOWS_ADMITTED_LIST)?;
    if not_admitted {
        // QoSFlows-List-withCause ::= SEQUENCE (SIZE(1..maxnoofQoSFlows)) OF
        // QoSFlowwithCause-Item { qfi, cause Cause OPTIONAL, iE-Extension
        // OPTIONAL, ... }.
        ies::push_sequence_of(
            buf,
            &FD_QOS_FLOWS_NOT_ADMITTED_LIST,
            r,
            offset,
            1,
            MAX_NO_OF_QOS_FLOWS,
            |buf, r| {
                ies::push_object(buf, &FD_QOS_FLOW_WITH_CAUSE_ITEM, r, offset, |buf, r| {
                    let extended = r.read_bit()?;
                    let has_cause = r.read_bit()?;
                    let has_ie_extensions = r.read_bit()?;
                    ies::push_small_integer(
                        buf,
                        &FD_QOS_FLOW_IDENTIFIER,
                        r,
                        offset,
                        0,
                        QOS_FLOW_IDENTIFIER_MAX,
                    )?;
                    if has_cause {
                        let cause = ies::read_cause(r, &CAUSE_ROOT_COUNTS)?;
                        ies::push_cause_fields(buf, &cause, offset);
                    }
                    skip_sequence_tail(r, extended, has_ie_extensions)
                })
            },
        )?;
    }
    if forwarding {
        push_data_forwarding_info_from_target(buf, r, offset)?;
    }
    skip_sequence_tail(r, extended, has_ie_extensions)
}

/// A list of `SEQUENCE { QoSFlowIdentifier, iE-Extension OPTIONAL, ... }`
/// (QoSFlowsAdmitted-List, QoSFLowsAcceptedToBeForwarded-List).
///
/// 3GPP TS 38.423, Section 9.3.5.
fn push_qos_flow_list<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    r: &mut AperReader<'pkt>,
    offset: usize,
    desc: &'static FieldDescriptor,
) -> Result<(), PacketError> {
    ies::push_sequence_of(buf, desc, r, offset, 1, MAX_NO_OF_QOS_FLOWS, |buf, r| {
        let (extended, has_ie_extensions) = read_sequence_preamble(r)?;
        ies::push_small_integer(
            buf,
            &FD_QOS_FLOW_IDENTIFIER,
            r,
            offset,
            0,
            QOS_FLOW_IDENTIFIER_MAX,
        )?;
        skip_sequence_tail(r, extended, has_ie_extensions)
    })
}

/// `DataForwardingInfoFromTargetNGRANnode ::= SEQUENCE {
/// qosFlowsAcceptedForDataForwarding-List,
/// pduSessionLevelDLDataForwardingInfo UPTransportLayerInformation
/// OPTIONAL, pduSessionLevelULDataForwardingInfo
/// UPTransportLayerInformation OPTIONAL, dataForwardingResponseDRBItemList
/// OPTIONAL, iE-Extension OPTIONAL, ... }`, the DRB list being
/// `SEQUENCE (SIZE(1..maxnoofDRBs)) OF SEQUENCE { drb-ID,
/// dlForwardingUPTNL OPTIONAL, ulForwardingUPTNL OPTIONAL, iE-Extension
/// OPTIONAL, ... }`.
///
/// 3GPP TS 38.423, Sections 9.2.1.16 and 9.3.5.
fn push_data_forwarding_info_from_target<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    r: &mut AperReader<'pkt>,
    offset: usize,
) -> Result<(), PacketError> {
    ies::push_object(
        buf,
        &FD_DATA_FORWARDING_INFO_FROM_TARGET,
        r,
        offset,
        |buf, r| {
            let extended = r.read_bit()?;
            let dl = r.read_bit()?;
            let ul = r.read_bit()?;
            let drbs = r.read_bit()?;
            let has_ie_extensions = r.read_bit()?;
            push_qos_flow_list(buf, r, offset, &FD_QOS_FLOWS_ACCEPTED_FOR_DATA_FORWARDING)?;
            if dl {
                ies::push_up_tnl_object(buf, &FD_DL_DATA_FORWARDING, r, offset)?;
            }
            if ul {
                ies::push_up_tnl_object(buf, &FD_UL_DATA_FORWARDING, r, offset)?;
            }
            if drbs {
                ies::push_sequence_of(
                    buf,
                    &FD_DATA_FORWARDING_RESPONSE_DRB_LIST,
                    r,
                    offset,
                    1,
                    MAX_NO_OF_DRBS,
                    |buf, r| {
                        ies::push_object(
                            buf,
                            &FD_DATA_FORWARDING_RESPONSE_DRB_ITEM,
                            r,
                            offset,
                            |buf, r| {
                                let extended = r.read_bit()?;
                                let dl = r.read_bit()?;
                                let ul = r.read_bit()?;
                                let has_ie_extensions = r.read_bit()?;
                                ies::push_small_integer(buf, &FD_DRB_ID, r, offset, 1, DRB_ID_MAX)?;
                                if dl {
                                    ies::push_up_tnl_object(
                                        buf,
                                        &FD_DL_FORWARDING_UP_TNL,
                                        r,
                                        offset,
                                    )?;
                                }
                                if ul {
                                    ies::push_up_tnl_object(
                                        buf,
                                        &FD_UL_FORWARDING_UP_TNL,
                                        r,
                                        offset,
                                    )?;
                                }
                                skip_sequence_tail(r, extended, has_ie_extensions)
                            },
                        )
                    },
                )?;
            }
            skip_sequence_tail(r, extended, has_ie_extensions)
        },
    )
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 38.423 IE Decoder Coverage
    //!
    //! Vectors were produced with pycrate `XnAP_IEs` (APER), except the
    //! `choice-extension` ones, which are hand-built.
    //!
    //! | Spec Section | Description                               | Test                              |
    //! |--------------|-------------------------------------------|-----------------------------------|
    //! | 9.2.2.3      | Global NG-RAN Node ID, macro / short macro| global_node_id_enb_variants       |
    //! | 9.2.2.3      | Global NG-RAN Node ID, choice-extension   | global_node_id_choice_extension   |
    //! | 9.2.2.3      | Global NG-RAN Node ID, malformed          | global_node_id_malformed          |
    //! | 9.2.3.25     | Target CGI, NR                            | target_cgi_nr                     |
    //! | 9.2.3.25     | Target CGI, choice-extension / malformed  | target_cgi_other                  |
    //! | 9.2.2.4      | PLMN identity                             | plmn_identity                     |
    //! | 9.3.5        | Names                                     | names                             |

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s = s.replace(' ', "");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Test vector with a `'static` lifetime, so that a buffer can be
    /// reused across several values.
    fn hex_static(s: &str) -> &'static [u8] {
        hex(s).leak()
    }

    fn pushed<'a>(buf: &'a DissectBuffer<'a>) -> Vec<(&'static str, FieldValue<'a>)> {
        buf.fields()
            .iter()
            .map(|f| (f.name(), f.value.clone()))
            .collect()
    }

    #[test]
    fn global_node_id_enb_variants() {
        // ng-eNB, enb-ID-macro 0xABCDE.
        let data = hex("4000f11000abcde0");
        let mut buf = DissectBuffer::new();
        assert!(push_global_ng_ran_node_id(&mut buf, &data, 0));
        assert_eq!(pushed(&buf)[2], ("enb_id_choice", FieldValue::U8(0)));
        assert_eq!(pushed(&buf)[3], ("enb_id", FieldValue::U32(0xABCDE)));
        // ng-eNB, enb-ID-shortmacro 0x2ABCD.
        let data = hex("4000f11040aaf340");
        let mut buf = DissectBuffer::new();
        assert!(push_global_ng_ran_node_id(&mut buf, &data, 0));
        assert_eq!(pushed(&buf)[3], ("enb_id", FieldValue::U32(0x2ABCD)));
        // gNB with a 32-bit gNB ID.
        let data = hex("0000f11050ffffffff");
        let mut buf = DissectBuffer::new();
        assert!(push_global_ng_ran_node_id(&mut buf, &data, 0));
        assert_eq!(pushed(&buf)[2], ("gnb_id_length", FieldValue::U8(32)));
        assert_eq!(pushed(&buf)[3], ("gnb_id", FieldValue::U32(0xFFFF_FFFF)));
        assert_eq!(buf.fields()[3].range, 5..9);
    }

    #[test]
    fn global_node_id_choice_extension() {
        // gNB-ID choice-extension, then the node choice-extension.
        let mut buf = DissectBuffer::new();
        assert!(push_global_ng_ran_node_id(
            &mut buf,
            hex_static("0000f1108000014000"),
            0
        ));
        assert_eq!(
            pushed(&buf).iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            ["node_choice", "plmn_identity"]
        );
        let mut buf = DissectBuffer::new();
        assert!(push_global_ng_ran_node_id(
            &mut buf,
            hex_static("8000014001 00"),
            0
        ));
        assert_eq!(pushed(&buf), [("node_choice", FieldValue::U8(2))]);
        // ng-eNB with ENB-ID-Choice choice-extension.
        let mut buf = DissectBuffer::new();
        assert!(push_global_ng_ran_node_id(
            &mut buf,
            hex_static("4000f110c000014001 00"),
            0
        ));
        assert_eq!(pushed(&buf).len(), 3);
    }

    #[test]
    fn global_node_id_malformed() {
        let mut buf = DissectBuffer::new();
        assert!(!push_global_ng_ran_node_id(
            &mut buf,
            hex_static("0000f1"),
            0
        ));
        assert!(!push_global_ng_ran_node_id(&mut buf, hex_static("c0"), 0));
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn target_cgi_nr() {
        let data = hex("0000f1101234567890");
        let mut buf = DissectBuffer::new();
        assert!(push_target_cgi(&mut buf, &data, 0));
        assert_eq!(
            pushed(&buf),
            [
                ("cgi_choice", FieldValue::U8(0)),
                ("plmn_identity", FieldValue::Bytes(&[0x00, 0xf1, 0x10])),
                ("nr_cell_identity", FieldValue::U64(0x1_2345_6789))
            ]
        );
    }

    #[test]
    fn target_cgi_other() {
        let mut buf = DissectBuffer::new();
        assert!(push_target_cgi(&mut buf, hex_static("800001400100"), 0));
        assert_eq!(pushed(&buf), [("cgi_choice", FieldValue::U8(2))]);
        let mut buf = DissectBuffer::new();
        assert!(!push_target_cgi(&mut buf, hex_static("c0"), 0));
        assert!(!push_target_cgi(&mut buf, hex_static("0000f110"), 0));
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn plmn_identity() {
        let mut buf = DissectBuffer::new();
        assert!(!push_ie_value(&mut buf, 64, &[0x00], 0, 0));
        assert!(push_ie_value(&mut buf, 64, &[0x00, 0xf1, 0x10], 0, 0));
        assert!(push_ie_value(&mut buf, 24, &[0x01, 0xaa], 0, 0));
        assert!(push_ie_value(&mut buf, 72, &[0x01, 0xbb], 0, 0));
        assert!(!push_ie_value(&mut buf, 9999, &[0x00], 0, 0));
        assert_eq!(buf.fields().len(), 3);
    }

    #[test]
    fn names() {
        let f = |d: &FieldDescriptor, v: FieldValue<'_>| (d.display_fn.unwrap())(&v, &[]);
        assert_eq!(
            f(&FD_NODE_CHOICE, FieldValue::U8(2)),
            Some("choice-extension")
        );
        assert_eq!(f(&FD_NODE_CHOICE, FieldValue::U8(3)), None);
        assert_eq!(
            f(&FD_ENB_ID_CHOICE, FieldValue::U8(0)),
            Some("enb-ID-macro")
        );
        assert_eq!(
            f(&FD_ENB_ID_CHOICE, FieldValue::U8(1)),
            Some("enb-ID-shortmacro")
        );
        assert_eq!(
            f(&FD_ENB_ID_CHOICE, FieldValue::U8(3)),
            Some("choice-extension")
        );
        assert_eq!(f(&FD_ENB_ID_CHOICE, FieldValue::U8(4)), None);
        assert_eq!(f(&FD_CGI_CHOICE, FieldValue::U8(0)), Some("nr"));
        assert_eq!(
            f(&FD_CGI_CHOICE, FieldValue::U8(2)),
            Some("choice-extension")
        );
        assert_eq!(f(&FD_CGI_CHOICE, FieldValue::U8(3)), None);
        assert_eq!(
            f(&FD_DL_NG_U_TNL_INFORMATION_UNCHANGED, FieldValue::U8(0)),
            Some("true")
        );
        assert_eq!(
            f(&FD_DL_NG_U_TNL_INFORMATION_UNCHANGED, FieldValue::U8(1)),
            None
        );
    }
}
