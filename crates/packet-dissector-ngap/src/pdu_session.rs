//! PDU session resource lists, their `...Transfer` OCTET STRINGs and the
//! user plane transport layer information they carry.
//!
//! ## References
//! - 3GPP TS 38.413 v19.3.0, Section 9.4.5 (Information Element
//!   Definitions): <https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/>
//! - ITU-T Rec. X.691 (APER): <https://www.itu.int/rec/T-REC-X.691>

use core::ops::Range;

use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

use crate::aper::AperReader;
use crate::container::{self, IeContext};
use crate::ie_parsers::{
    FD_SD, FD_SST, ensure_consumed, push_cause_fields, push_nas_pdu_octets, read_aligned_octets,
    read_cause, read_s_nssai, read_sequence_preamble, shift, skip_protocol_ie_single_container,
    skip_sequence_tail,
};

// ── Field descriptors ──────────────────────────────────────────────────

static FD_PDU_SESSION_ID: FieldDescriptor =
    FieldDescriptor::new("pdu_session_id", "PDU Session ID", FieldType::U8);

static FD_S_NSSAI: FieldDescriptor =
    FieldDescriptor::new("s_nssai", "S-NSSAI", FieldType::Object).optional();

static FD_TRANSFER: FieldDescriptor =
    FieldDescriptor::new("transfer", "Transfer", FieldType::Object);

static FD_TRANSFER_IES: FieldDescriptor =
    FieldDescriptor::new("ies", "Information Elements", FieldType::Array)
        .optional()
        .with_children(container::IE_CHILD_FIELDS);

static FD_TRANSFER_VALUE: FieldDescriptor =
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional();

/// The rest of a SEQUENCE transfer after its last decoded component.
static FD_TRANSFER_UNDECODED: FieldDescriptor = FieldDescriptor::new(
    "transfer_undecoded_octets",
    "Transfer Undecoded Octets",
    FieldType::Bytes,
)
.optional();

static ITEM_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("pdu_session_id", "PDU Session ID", FieldType::U8),
    FieldDescriptor::new("nas_pdu", "NAS-PDU", FieldType::Object).optional(),
    FieldDescriptor::new("s_nssai", "S-NSSAI", FieldType::Object).optional(),
    FieldDescriptor::new("transfer", "Transfer", FieldType::Object),
];

static FD_ITEM: FieldDescriptor =
    FieldDescriptor::new("item", "Item", FieldType::Object).with_children(ITEM_CHILDREN);

static FD_ITEMS: FieldDescriptor = FieldDescriptor::new("items", "Items", FieldType::Array)
    .optional()
    .with_children(ITEM_CHILDREN);

static FD_UP_TNL_CHOICE: FieldDescriptor = FieldDescriptor::new(
    "up_tnl_choice",
    "UP Transport Layer Information Choice",
    FieldType::U8,
)
.optional()
.with_display_fn(|v, _| match v {
    FieldValue::U8(0) => Some("gTPTunnel"),
    FieldValue::U8(1) => Some("choice-Extensions"),
    _ => None,
});

static FD_IPV4_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv4_address", "IPv4 Address", FieldType::Ipv4Addr).optional();

static FD_IPV6_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv6_address", "IPv6 Address", FieldType::Ipv6Addr).optional();

static FD_TRANSPORT_LAYER_ADDRESS: FieldDescriptor = FieldDescriptor::new(
    "transport_layer_address",
    "Transport Layer Address",
    FieldType::Bytes,
)
.optional();

static FD_GTP_TEID: FieldDescriptor =
    FieldDescriptor::new("gtp_teid", "GTP-TEID", FieldType::U32).optional();

static FD_DL_QOS_FLOW_PER_TNL: FieldDescriptor = FieldDescriptor::new(
    "dl_qos_flow_per_tnl_information",
    "DL QoS Flow per TNL Information",
    FieldType::Object,
)
.optional();

static FD_DL_NGU_UP_TNL: FieldDescriptor = FieldDescriptor::new(
    "dl_ngu_up_tnl_information",
    "DL NG-U UP TNL Information",
    FieldType::Object,
)
.optional();

static FD_UL_NGU_UP_TNL: FieldDescriptor = FieldDescriptor::new(
    "ul_ngu_up_tnl_information",
    "UL NG-U UP TNL Information",
    FieldType::Object,
)
.optional();

static FD_ASSOCIATED_QOS_FLOWS: FieldDescriptor = FieldDescriptor::new(
    "associated_qos_flows",
    "Associated QoS Flow List",
    FieldType::Array,
)
.optional();

static FD_ASSOCIATED_QOS_FLOW: FieldDescriptor = FieldDescriptor::new(
    "associated_qos_flow",
    "Associated QoS Flow",
    FieldType::Object,
);

static FD_QFI: FieldDescriptor =
    FieldDescriptor::new("qos_flow_identifier", "QoS Flow Identifier", FieldType::U8);

static FD_QOS_FLOW_MAPPING_INDICATION: FieldDescriptor = FieldDescriptor::new(
    "qos_flow_mapping_indication",
    "QoS Flow Mapping Indication",
    FieldType::U8,
)
.optional()
.with_display_fn(|v, _| match v {
    FieldValue::U8(0) => Some("ul"),
    FieldValue::U8(1) => Some("dl"),
    _ => None,
});

// ── ASN.1 constants ────────────────────────────────────────────────────

/// `maxnoofPDUSessions` — 3GPP TS 38.413, Section 9.4.7.
const MAX_NO_OF_PDU_SESSIONS: u64 = 256;

/// `maxnoofQosFlows` — 3GPP TS 38.413, Section 9.4.7.
const MAX_NO_OF_QOS_FLOWS: u64 = 64;

/// `QosFlowIdentifier ::= INTEGER (0..63, ...)` — 3GPP TS 38.413, Section
/// 9.4.5.
const QOS_FLOW_IDENTIFIER_MAX: u64 = 63;

/// Upper bound of `TransportLayerAddress ::= BIT STRING (SIZE(1..160,
/// ...))` — 3GPP TS 38.413, Section 9.4.5.
const TRANSPORT_LAYER_ADDRESS_MAX_BITS: u64 = 160;

// ── Lists ──────────────────────────────────────────────────────────────

/// The `...Transfer` carried by the items of a list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TransferKind {
    /// `SEQUENCE { protocolIEs ProtocolIE-Container, ... }` (Setup and
    /// Modify request transfers).
    IeContainer,
    /// A transfer that is a plain SEQUENCE of components.
    Sequence(SequenceTransfer),
}

/// Transfers that are plain SEQUENCEs of components.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SequenceTransfer {
    /// PDUSessionResourceSetupResponseTransfer.
    SetupResponse,
    /// PDUSessionResourceSetupUnsuccessfulTransfer and
    /// PDUSessionResourceModifyUnsuccessfulTransfer: a Cause first.
    Unsuccessful,
    /// PDUSessionResourceModifyResponseTransfer.
    ModifyResponse,
    /// PDUSessionResourceReleaseCommandTransfer.
    ReleaseCommand,
    /// PDUSessionResourceReleaseResponseTransfer.
    ReleaseResponse,
}

/// Layout of the items of a PDU session resource list.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ItemLayout {
    /// The item has an optional `NAS-PDU` after the PDU session ID.
    nas_pdu: bool,
    /// The item has an `S-NSSAI` after the NAS-PDU.
    s_nssai: bool,
    /// The OCTET STRING transfer after those.
    transfer: TransferKind,
}

/// Item layout of the PDU session resource list IE `ie_id`, or `None`.
///
/// 3GPP TS 38.413, Section 9.4.5 — each list is `SEQUENCE
/// (SIZE(1..maxnoofPDUSessions)) OF` its item type; the item types are
/// `SEQUENCE { pDUSessionID, [NAS-PDU OPTIONAL,] [s-NSSAI,] transfer
/// OCTET STRING (CONTAINING ...), iE-Extensions OPTIONAL, ... }`.
pub(crate) fn item_layout(ie_id: u16) -> Option<ItemLayout> {
    use SequenceTransfer::{
        ModifyResponse, ReleaseCommand, ReleaseResponse, SetupResponse, Unsuccessful,
    };
    use TransferKind::{IeContainer, Sequence};
    let (nas_pdu, s_nssai, transfer) = match ie_id {
        // PDUSessionResourceSetupListSUReq, PDUSessionResourceSetupListCxtReq.
        74 | 71 => (true, true, IeContainer),
        // PDUSessionResourceModifyListModReq.
        64 => (true, false, IeContainer),
        // PDUSessionResourceSetupListSURes, PDUSessionResourceSetupListCxtRes.
        75 | 72 => (false, false, Sequence(SetupResponse)),
        // PDUSessionResourceFailedToSetupListSURes / ...CxtRes,
        // PDUSessionResourceFailedToModifyListModRes.
        58 | 55 | 54 => (false, false, Sequence(Unsuccessful)),
        // PDUSessionResourceModifyListModRes.
        65 => (false, false, Sequence(ModifyResponse)),
        // PDUSessionResourceToReleaseListRelCmd.
        79 => (false, false, Sequence(ReleaseCommand)),
        // PDUSessionResourceReleasedListRelRes.
        70 => (false, false, Sequence(ReleaseResponse)),
        _ => return None,
    };
    Some(ItemLayout {
        nas_pdu,
        s_nssai,
        transfer,
    })
}

/// Decodes a PDU session resource list IE value with item layout `layout`
/// into an `items` array.
///
/// Returns `false`, leaving no fields behind, when the value is not a
/// valid encoding of the list.
pub(crate) fn push_pdu_session_resource_list<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    layout: ItemLayout,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let mark = buf.fields().len();
    let ok = decode_list(buf, layout, data, offset).is_ok();
    if !ok {
        buf.truncate_fields(mark);
    }
    ok
}

fn decode_list<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    layout: ItemLayout,
    data: &'pkt [u8],
    offset: usize,
) -> Result<(), PacketError> {
    let mut r = AperReader::new(data);
    // SIZE(1..256): a constrained length, one octet-aligned octet
    // (ITU-T Rec. X.691, Sections 11.9.4.1 and 11.5.7.2).
    let count = r.read_length(1, Some(MAX_NO_OF_PDU_SESSIONS))?;
    let list = buf.begin_container(
        &FD_ITEMS,
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    for _ in 0..count {
        decode_item(buf, &mut r, layout, offset)?;
    }
    ensure_consumed(&r, data)?;
    buf.end_container(list);
    Ok(())
}

/// Decodes one list item.
fn decode_item<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    r: &mut AperReader<'pkt>,
    layout: ItemLayout,
    offset: usize,
) -> Result<(), PacketError> {
    let start = r.bit_position();
    let item = buf.begin_container(&FD_ITEM, FieldValue::Object(0..0), offset..offset);
    // ITU-T Rec. X.691, Section 19: extension bit, then one bit per
    // OPTIONAL component (NAS-PDU if present in the type, iE-Extensions).
    let extended = r.read_bit()?;
    let nas_present = layout.nas_pdu && r.read_bit()?;
    let ie_extensions = r.read_bit()?;

    // PDUSessionID ::= INTEGER (0..255): one octet-aligned octet
    // (ITU-T Rec. X.691, Section 11.5.7.2).
    r.align();
    let id_start = r.bit_position();
    let id = r.read_constrained_whole_number(0, 255)?;
    buf.push_field(
        &FD_PDU_SESSION_ID,
        FieldValue::U8(id as u8),
        shift(r.byte_range_since(id_start), offset),
    );

    if nas_present {
        // NAS-PDU ::= OCTET STRING: octet-aligned length, then the octets.
        let len = r.read_length(0, None)?;
        let (nas, range) = read_aligned_octets(r, len as usize)?;
        push_nas_pdu_octets(buf, nas, shift(range, offset));
    }

    if layout.s_nssai {
        let s_start = r.bit_position();
        let obj = buf.begin_container(&FD_S_NSSAI, FieldValue::Object(0..0), offset..offset);
        let ((sst, sst_range), sd) = read_s_nssai(r)?;
        buf.push_field(&FD_SST, FieldValue::U8(sst), shift(sst_range, offset));
        if let Some((sd, sd_range)) = sd {
            buf.push_field(&FD_SD, FieldValue::U32(sd), shift(sd_range, offset));
        }
        if let Some(field) = buf.field_mut(obj as usize) {
            field.range = shift(r.byte_range_since(s_start), offset);
        }
        buf.end_container(obj);
    }

    // The transfer: OCTET STRING (CONTAINING ...), unconstrained.
    let len = r.read_length(0, None)?;
    let (transfer, range) = read_aligned_octets(r, len as usize)?;
    push_transfer(buf, layout.transfer, transfer, range.start + offset);

    skip_sequence_tail(r, extended, ie_extensions)?;
    if let Some(field) = buf.field_mut(item as usize) {
        field.range = shift(r.byte_range_since(start), offset);
    }
    buf.end_container(item);
    Ok(())
}

// ── Transfers ──────────────────────────────────────────────────────────

/// Pushes a `transfer` object for the OCTET STRING `data`.
///
/// A transfer that cannot be decoded at all keeps its octets as `value`.
/// A transfer whose leading components are decoded but whose remaining
/// OPTIONAL components or extension additions are not supported here
/// carries the rest as `undecoded_octets`.
fn push_transfer<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    kind: TransferKind,
    data: &'pkt [u8],
    offset: usize,
) {
    let obj = buf.begin_container(
        &FD_TRANSFER,
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    let mark = buf.fields().len();
    let ok = match kind {
        TransferKind::IeContainer => push_ie_container_transfer(buf, data, offset),
        TransferKind::Sequence(kind) => {
            let mut r = AperReader::new(data);
            match decode_sequence_transfer(buf, kind, &mut r, offset) {
                Ok(Tail::Done) => ensure_consumed(&r, data).is_ok(),
                Ok(Tail::Undecoded) => {
                    // Keep everything from the octet where decoding stopped.
                    let at = r.bit_position() / 8;
                    buf.push_field(
                        &FD_TRANSFER_UNDECODED,
                        FieldValue::Bytes(&data[at..]),
                        offset + at..offset + data.len(),
                    );
                    true
                }
                Err(_) => false,
            }
        }
    };
    if !ok {
        buf.truncate_fields(mark);
        buf.push_field(
            &FD_TRANSFER_VALUE,
            FieldValue::Bytes(data),
            offset..offset + data.len(),
        );
    }
    buf.end_container(obj);
}

/// `SEQUENCE { protocolIEs ProtocolIE-Container, ... }`: one octet with the
/// extension bit and padding, then the IE container.
///
/// 3GPP TS 38.413, Section 9.4.5 — PDUSessionResourceSetupRequestTransfer
/// and PDUSessionResourceModifyRequestTransfer.
fn push_ie_container_transfer<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let (Some(&preamble), Some(ies)) = (data.first(), data.get(1..)) else {
        return false;
    };
    // ITU-T Rec. X.691, Section 19.1: the first bit is the extension bit.
    container::push_ie_container(
        buf,
        &FD_TRANSFER_IES,
        ies,
        offset + 1,
        IeContext::Transfer,
        preamble & 0x80 != 0,
    )
}

/// What remains after decoding the supported part of a SEQUENCE transfer.
enum Tail {
    /// Everything was decoded.
    Done,
    /// Components that are not decoded here follow.
    Undecoded,
}

/// Decodes a SEQUENCE-type transfer.
fn decode_sequence_transfer<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    kind: SequenceTransfer,
    r: &mut AperReader<'pkt>,
    offset: usize,
) -> Result<Tail, PacketError> {
    let extended = r.read_bit()?;
    match kind {
        // PDUSessionResourceSetupResponseTransfer ::= SEQUENCE {
        //   dLQosFlowPerTNLInformation, additionalDLQosFlowPerTNLInformation
        //   OPTIONAL, securityResult OPTIONAL, qosFlowFailedToSetupList
        //   OPTIONAL, iE-Extensions OPTIONAL, ... }
        SequenceTransfer::SetupResponse => {
            let additional = r.read_bit()?;
            let security_result = r.read_bit()?;
            let failed = r.read_bit()?;
            let ie_extensions = r.read_bit()?;
            push_qos_flow_per_tnl_information(buf, r, offset, &FD_DL_QOS_FLOW_PER_TNL)?;
            if additional || security_result || failed {
                return Ok(Tail::Undecoded);
            }
            finish(r, extended, ie_extensions)
        }
        // PDUSessionResourceSetupUnsuccessfulTransfer ::= SEQUENCE { cause,
        //   criticalityDiagnostics OPTIONAL, iE-Extensions OPTIONAL, ... },
        // and PDUSessionResourceModifyUnsuccessfulTransfer likewise.
        SequenceTransfer::Unsuccessful => {
            let diagnostics = r.read_bit()?;
            let ie_extensions = r.read_bit()?;
            let cause = read_cause(r)?;
            push_cause_fields(buf, &cause, offset);
            if diagnostics {
                return Ok(Tail::Undecoded);
            }
            finish(r, extended, ie_extensions)
        }
        // PDUSessionResourceModifyResponseTransfer ::= SEQUENCE {
        //   dL-NGU-UP-TNLInformation OPTIONAL, uL-NGU-UP-TNLInformation
        //   OPTIONAL, qosFlowAddOrModifyResponseList OPTIONAL,
        //   additionalDLQosFlowPerTNLInformation OPTIONAL,
        //   qosFlowFailedToAddOrModifyList OPTIONAL, iE-Extensions OPTIONAL,
        //   ... }
        SequenceTransfer::ModifyResponse => {
            let dl = r.read_bit()?;
            let ul = r.read_bit()?;
            let add_or_modify = r.read_bit()?;
            let additional = r.read_bit()?;
            let failed = r.read_bit()?;
            let ie_extensions = r.read_bit()?;
            if dl {
                push_up_tnl_object(buf, r, offset, &FD_DL_NGU_UP_TNL)?;
            }
            if ul {
                push_up_tnl_object(buf, r, offset, &FD_UL_NGU_UP_TNL)?;
            }
            if add_or_modify || additional || failed {
                return Ok(Tail::Undecoded);
            }
            finish(r, extended, ie_extensions)
        }
        // PDUSessionResourceReleaseCommandTransfer ::= SEQUENCE { cause,
        //   iE-Extensions OPTIONAL, ... }
        SequenceTransfer::ReleaseCommand => {
            let ie_extensions = r.read_bit()?;
            let cause = read_cause(r)?;
            push_cause_fields(buf, &cause, offset);
            finish(r, extended, ie_extensions)
        }
        // PDUSessionResourceReleaseResponseTransfer ::= SEQUENCE {
        //   iE-Extensions OPTIONAL, ... }
        SequenceTransfer::ReleaseResponse => {
            let ie_extensions = r.read_bit()?;
            finish(r, extended, ie_extensions)
        }
    }
}

/// Skips the iE-Extensions container and the extension additions that end
/// a SEQUENCE.
fn finish(
    r: &mut AperReader<'_>,
    extended: bool,
    ie_extensions: bool,
) -> Result<Tail, PacketError> {
    skip_sequence_tail(r, extended, ie_extensions)?;
    Ok(Tail::Done)
}

/// QosFlowPerTNLInformation ::= SEQUENCE { uPTransportLayerInformation,
/// associatedQosFlowList, iE-Extensions OPTIONAL, ... }, pushed as the
/// object `desc`.
///
/// 3GPP TS 38.413, Section 9.4.5.
fn push_qos_flow_per_tnl_information<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    r: &mut AperReader<'pkt>,
    offset: usize,
    desc: &'static FieldDescriptor,
) -> Result<(), PacketError> {
    let start = r.bit_position();
    let obj = buf.begin_container(desc, FieldValue::Object(0..0), offset..offset);
    let (extended, ie_extensions) = read_sequence_preamble(r)?;
    let tnl = read_up_tnl(r)?;
    push_up_tnl_fields(buf, &tnl, offset);

    // AssociatedQosFlowList ::= SEQUENCE (SIZE(1..maxnoofQosFlows)) OF
    // AssociatedQosFlowItem.
    let list_start = r.bit_position();
    let count = r.read_length(1, Some(MAX_NO_OF_QOS_FLOWS))?;
    let list = buf.begin_container(
        &FD_ASSOCIATED_QOS_FLOWS,
        FieldValue::Array(0..0),
        offset..offset,
    );
    for _ in 0..count {
        push_associated_qos_flow(buf, r, offset)?;
    }
    if let Some(field) = buf.field_mut(list as usize) {
        field.range = shift(r.byte_range_since(list_start), offset);
    }
    buf.end_container(list);

    finish(r, extended, ie_extensions)?;
    if let Some(field) = buf.field_mut(obj as usize) {
        field.range = shift(r.byte_range_since(start), offset);
    }
    buf.end_container(obj);
    Ok(())
}

/// AssociatedQosFlowItem ::= SEQUENCE { qosFlowIdentifier,
/// qosFlowMappingIndication ENUMERATED {ul, dl, ...} OPTIONAL,
/// iE-Extensions OPTIONAL, ... }.
///
/// 3GPP TS 38.413, Section 9.4.5.
fn push_associated_qos_flow<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    r: &mut AperReader<'pkt>,
    offset: usize,
) -> Result<(), PacketError> {
    let start = r.bit_position();
    let obj = buf.begin_container(
        &FD_ASSOCIATED_QOS_FLOW,
        FieldValue::Object(0..0),
        offset..offset,
    );
    let extended = r.read_bit()?;
    let mapping_present = r.read_bit()?;
    let ie_extensions = r.read_bit()?;
    let qfi_start = r.bit_position();
    let qfi = read_qfi(r)?;
    buf.push_field(
        &FD_QFI,
        FieldValue::U8(qfi),
        shift(r.byte_range_since(qfi_start), offset),
    );
    if mapping_present {
        let m_start = r.bit_position();
        let mapping = r.read_enumerated(2, true)?;
        // Extension values of the ENUMERATED are not named; keep them
        // saturated in the U8.
        buf.push_field(
            &FD_QOS_FLOW_MAPPING_INDICATION,
            FieldValue::U8(u8::try_from(mapping).unwrap_or(u8::MAX)),
            shift(r.byte_range_since(m_start), offset),
        );
    }
    finish(r, extended, ie_extensions)?;
    if let Some(field) = buf.field_mut(obj as usize) {
        field.range = shift(r.byte_range_since(start), offset);
    }
    buf.end_container(obj);
    Ok(())
}

/// QosFlowIdentifier ::= INTEGER (0..63, ...): an extension bit, then a
/// 6-bit value, or a semi-constrained number for an extension value.
///
/// ITU-T Rec. X.691, Section 13.1 / 11.5.
fn read_qfi(r: &mut AperReader<'_>) -> Result<u8, PacketError> {
    if r.read_bit()? {
        return Err(PacketError::InvalidHeader(
            "QosFlowIdentifier extension value",
        ));
    }
    // At most 63.
    Ok(r.read_constrained_whole_number(0, QOS_FLOW_IDENTIFIER_MAX)? as u8)
}

// ── UP transport layer information ─────────────────────────────────────

/// A decoded UPTransportLayerInformation.
pub(crate) struct UpTnl<'a> {
    choice: u8,
    choice_range: Range<usize>,
    /// Transport layer address: bit length, octets and range.
    address: Option<(u64, &'a [u8], Range<usize>)>,
    teid: Option<(u32, Range<usize>)>,
}

/// UPTransportLayerInformation ::= CHOICE { gTPTunnel GTPTunnel,
/// choice-Extensions ProtocolIE-SingleContainer }.
///
/// GTPTunnel ::= SEQUENCE { transportLayerAddress TransportLayerAddress,
/// gTP-TEID GTP-TEID, iE-Extensions OPTIONAL, ... }, with
/// `TransportLayerAddress ::= BIT STRING (SIZE(1..160, ...))` and
/// `GTP-TEID ::= OCTET STRING (SIZE(4))`.
///
/// 3GPP TS 38.413, Sections 9.3.2.2 and 9.4.5; ITU-T Rec. X.691, Sections
/// 16.11 (variable-size BIT STRING: a constrained length, then the
/// octet-aligned bits, since the upper bound exceeds 16) and 17.7 (fixed-size OCTET STRING above two
/// octets, octet-aligned).
pub(crate) fn read_up_tnl<'a>(r: &mut AperReader<'a>) -> Result<UpTnl<'a>, PacketError> {
    let choice_start = r.bit_position();
    // Two alternatives, no extension marker: one bit.
    let choice = r.read_choice_index(2, false)? as u8;
    let choice_range = r.byte_range_since(choice_start);
    if choice != 0 {
        skip_protocol_ie_single_container(r)?;
        return Ok(UpTnl {
            choice,
            choice_range,
            address: None,
            teid: None,
        });
    }
    let (extended, ie_extensions) = read_sequence_preamble(r)?;
    if r.read_bit()? {
        return Err(PacketError::InvalidHeader(
            "TransportLayerAddress size extension",
        ));
    }
    let bits = r.read_length(1, Some(TRANSPORT_LAYER_ADDRESS_MAX_BITS))?;
    // The upper bound (160 bits) exceeds 16 bits, so the contents are
    // octet-aligned whatever the actual length (X.691, Section 16.11).
    let (address, address_range) = read_aligned_octets(r, bits.div_ceil(8) as usize)?;
    let (teid, teid_range) = read_aligned_octets(r, 4)?;
    let teid = u32::from_be_bytes([teid[0], teid[1], teid[2], teid[3]]);
    skip_sequence_tail(r, extended, ie_extensions)?;
    Ok(UpTnl {
        choice,
        choice_range,
        address: Some((bits, address, address_range)),
        teid: Some((teid, teid_range)),
    })
}

/// Pushes the fields of a decoded UPTransportLayerInformation.
///
/// The transport layer address is an IPv4 address (32 bits), an IPv6
/// address (128 bits) or both, IPv4 first (160 bits) — 3GPP TS 38.414,
/// Section 5.1 — and raw bytes otherwise.
pub(crate) fn push_up_tnl_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    tnl: &UpTnl<'pkt>,
    offset: usize,
) {
    buf.push_field(
        &FD_UP_TNL_CHOICE,
        FieldValue::U8(tnl.choice),
        shift(tnl.choice_range.clone(), offset),
    );
    if let Some((bits, address, ref range)) = tnl.address {
        let range = shift(range.clone(), offset);
        let v4 = |a: &[u8]| FieldValue::Ipv4Addr([a[0], a[1], a[2], a[3]]);
        let v6 = |a: &[u8]| {
            let mut v = [0u8; 16];
            v.copy_from_slice(a);
            FieldValue::Ipv6Addr(v)
        };
        match bits {
            32 => buf.push_field(&FD_IPV4_ADDRESS, v4(address), range),
            128 => buf.push_field(&FD_IPV6_ADDRESS, v6(address), range),
            160 => {
                let s = range.start;
                buf.push_field(&FD_IPV4_ADDRESS, v4(&address[..4]), s..s + 4);
                buf.push_field(&FD_IPV6_ADDRESS, v6(&address[4..]), s + 4..s + 20);
            }
            _ => buf.push_field(
                &FD_TRANSPORT_LAYER_ADDRESS,
                FieldValue::Bytes(address),
                range,
            ),
        }
    }
    if let Some((teid, ref range)) = tnl.teid {
        buf.push_field(
            &FD_GTP_TEID,
            FieldValue::U32(teid),
            shift(range.clone(), offset),
        );
    }
}

/// Pushes a UPTransportLayerInformation as the object `desc`.
fn push_up_tnl_object<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    r: &mut AperReader<'pkt>,
    offset: usize,
    desc: &'static FieldDescriptor,
) -> Result<(), PacketError> {
    let start = r.bit_position();
    let obj = buf.begin_container(desc, FieldValue::Object(0..0), offset..offset);
    let tnl = read_up_tnl(r)?;
    push_up_tnl_fields(buf, &tnl, offset);
    if let Some(field) = buf.field_mut(obj as usize) {
        field.range = shift(r.byte_range_since(start), offset);
    }
    buf.end_container(obj);
    Ok(())
}

/// UPTransportLayerInformation IE value (e.g. UL-NGU-UP-TNLInformation, IE
/// 139, and RedundantUL-NGU-UP-TNLInformation, IE 195).
///
/// 3GPP TS 38.413, Section 9.3.2.2.
pub(crate) fn push_up_transport_layer_information<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let decode = || -> Result<UpTnl<'pkt>, PacketError> {
        let mut r = AperReader::new(data);
        let tnl = read_up_tnl(&mut r)?;
        ensure_consumed(&r, data)?;
        Ok(tnl)
    };
    let Ok(tnl) = decode() else {
        return false;
    };
    push_up_tnl_fields(buf, &tnl, offset);
    true
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 38.413 PDU Session Resource Coverage
    //!
    //! Test vectors were produced by an independent APER encoder (pycrate
    //! `NGAP_IEs`).
    //!
    //! | IE ID      | TS 38.413 | Description                                  | Test                                  |
    //! |------------|-----------|----------------------------------------------|---------------------------------------|
    //! | 139        | 9.3.2.2   | GTPTunnel, IPv4 address                      | up_tnl_ipv4                           |
    //! | 139        | 9.3.2.2   | GTPTunnel, IPv6 address                      | up_tnl_ipv6                           |
    //! | 139        | 9.3.2.2   | GTPTunnel, IPv4 and IPv6 (160 bits)          | up_tnl_ipv4_and_ipv6                  |
    //! | 139        | 9.3.2.2   | Other address length kept as bytes           | up_tnl_other_length                   |
    //! | 139        | 9.3.2.2   | choice-Extensions / malformed                | up_tnl_choice_extensions_and_errors   |
    //! | 74         | 9.3.1.x   | SetupListSUReq: NAS-PDU, S-NSSAI, transfer   | setup_list_su_req                     |
    //! | 71         | 9.4.5     | SetupListCxtReq                              | setup_list_cxt_req                    |
    //! | 75         | 9.4.5     | SetupListSURes: SetupResponseTransfer        | setup_list_su_res                     |
    //! | 72         | 9.4.5     | SetupResponseTransfer, partially decoded     | setup_response_transfer_partial       |
    //! | 58, 55, 54 | 9.4.5     | Failed lists: unsuccessful transfers (Cause) | failed_lists                          |
    //! | 64         | 9.4.5     | ModifyListModReq: ModifyRequestTransfer      | modify_list_mod_req                   |
    //! | 65         | 9.4.5     | ModifyListModRes: ModifyResponseTransfer     | modify_list_mod_res                   |
    //! | 79, 70     | 9.4.5     | Release command / response transfers         | release_lists                         |
    //! | 74         | 9.4.5     | Malformed list / transfer                    | malformed_list_and_transfer           |
    //! | 74         | 9.4.5     | List inside a transfer is kept raw           | list_in_transfer_not_decoded          |
    //! | 79         | 9.4.5     | Item and transfer iE-Extensions / additions  | extensions_are_skipped                |
    //! | 58, 65     | 9.4.5     | Unsupported optional components kept raw     | unsupported_components_kept_raw       |
    //! | 64, 71     | 9.4.5     | Undecodable NAS-PDU / empty transfer         | undecodable_nas_pdu_and_empty_transfer|
    //! | —          | 9.4.5     | Display names                                | display_names                         |
    //! | 79, 58     | 9.3.1.2   | Cause choice-Extensions in a transfer        | transfer_cause_choice_extensions      |
    //! | 74         | 9.4.5     | Transfer SEQUENCE extension additions        | transfer_container_extension_additions|

    use super::*;
    use crate::ie_parsers::{push_ie_value, push_ie_value_in};
    use packet_dissector_core::field::Field;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// All fields named `name`, in order.
    fn all<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> Vec<&'a Field<'pkt>> {
        buf.fields().iter().filter(|f| f.name() == name).collect()
    }

    fn one<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> &'a Field<'pkt> {
        let v = all(buf, name);
        assert_eq!(v.len(), 1, "{name}: {:?}", names(buf));
        v[0]
    }

    fn names<'a>(buf: &'a DissectBuffer<'_>) -> Vec<&'a str> {
        buf.fields().iter().map(|f| f.name()).collect()
    }

    fn decode(ie_id: u16, value: &str) -> (Vec<u8>, DissectBuffer<'static>) {
        let data: &'static [u8] = hex(value).leak();
        let mut buf = DissectBuffer::new();
        push_ie_value(&mut buf, ie_id, data, 0);
        (data.to_vec(), buf)
    }

    const UPTNL4: &str = "01f00a00000100000001";
    const SETUP_REQUEST_TRANSFER: &str = "0000040082000a0c3b9aca00301dcd6500008b000a01f00a0000010000000100860001000088000700090000091c00";

    #[test]
    fn up_tnl_ipv4() {
        let (_, buf) = decode(139, UPTNL4);
        assert_eq!(names(&buf), ["up_tnl_choice", "ipv4_address", "gtp_teid"]);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(0));
        let display = buf.fields()[0].descriptor.display_fn.unwrap();
        assert_eq!(display(&buf.fields()[0].value, &[]), Some("gTPTunnel"));
        assert_eq!(buf.fields()[1].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
        assert_eq!(buf.fields()[1].range, 2..6);
        assert_eq!(buf.fields()[2].value, FieldValue::U32(1));
        assert_eq!(buf.fields()[2].range, 6..10);
    }

    #[test]
    fn up_tnl_ipv6() {
        let (_, buf) = decode(139, "07f020010db800000000000000000000000112345678");
        let mut v6 = [0u8; 16];
        v6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        v6[15] = 1;
        assert_eq!(one(&buf, "ipv6_address").value, FieldValue::Ipv6Addr(v6));
        assert_eq!(one(&buf, "gtp_teid").value, FieldValue::U32(0x1234_5678));
    }

    #[test]
    fn up_tnl_ipv4_and_ipv6() {
        let (_, buf) = decode(195, "09f00a00000220010db8000000000000000000000002aabbccdd");
        assert_eq!(
            one(&buf, "ipv4_address").value,
            FieldValue::Ipv4Addr([10, 0, 0, 2])
        );
        assert_eq!(one(&buf, "ipv4_address").range, 2..6);
        assert_eq!(one(&buf, "ipv6_address").range, 6..22);
        assert_eq!(one(&buf, "gtp_teid").value, FieldValue::U32(0xaabb_ccdd));
    }

    #[test]
    fn up_tnl_other_length() {
        // 24-bit address: length 23 (0 | 00010111), aligned octets, TEID.
        let (_, buf) = decode(139, "0170010203000000ff");
        assert_eq!(
            one(&buf, "transport_layer_address").value,
            FieldValue::Bytes(&[1, 2, 3])
        );
        assert_eq!(one(&buf, "gtp_teid").value, FieldValue::U32(0xff));
        // 8-bit address: still octet-aligned (pycrate).
        let (_, buf) = decode(139, "0070ab00000007");
        let address = one(&buf, "transport_layer_address");
        assert_eq!(address.value, FieldValue::Bytes(&[0xab]));
        assert_eq!(address.range, 2..3);
        assert_eq!(one(&buf, "gtp_teid").value, FieldValue::U32(7));
    }

    #[test]
    fn up_tnl_choice_extensions_and_errors() {
        // choice-Extensions: id 1, criticality reject, 1-octet open type.
        let (_, buf) = decode(139, "8000010001ff");
        assert_eq!(names(&buf), ["up_tnl_choice"]);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(1));
        for value in [
            "01f00a000001",           // TEID missing
            "10",                     // size extension bit set
            "01f00a0000010000000100", // trailing octet
        ] {
            let (data, buf) = decode(139, value);
            assert_eq!(names(&buf), ["value"], "{value}");
            assert_eq!(buf.fields()[0].value, FieldValue::Bytes(&data));
        }
    }

    #[test]
    fn setup_list_su_req() {
        let (_, buf) = decode(
            74,
            &format!(
                "0140010c7e00680100062e0501c2120040200000022f{t}000200402f{t}",
                t = SETUP_REQUEST_TRANSFER
            ),
        );
        assert_eq!(one(&buf, "items").name(), "items");
        let ids: Vec<_> = all(&buf, "pdu_session_id")
            .iter()
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(ids, [FieldValue::U8(1), FieldValue::U8(2)]);
        assert_eq!(all(&buf, "pdu_session_id")[0].range, 2..3);

        // The NAS-PDU of item 1 is decoded as 5G NAS (DL NAS transport).
        let nas = one(&buf, "nas_pdu");
        assert_eq!(nas.range, 4..16);
        let mts: Vec<_> = all(&buf, "message_type")
            .iter()
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(mts[0], FieldValue::U8(0x68));

        let sst: Vec<_> = all(&buf, "sst").iter().map(|f| f.value.clone()).collect();
        assert_eq!(sst, [FieldValue::U8(1), FieldValue::U8(2)]);
        assert_eq!(one(&buf, "sd").value, FieldValue::U32(2));

        // Both transfers: IE containers with IEs 130, 139, 134, 136.
        assert_eq!(all(&buf, "transfer").len(), 2);
        let ie_ids: Vec<_> = all(&buf, "id").iter().map(|f| f.value.clone()).collect();
        assert_eq!(
            ie_ids,
            [130, 139, 134, 136, 130, 139, 134, 136].map(FieldValue::U16)
        );
        assert_eq!(
            all(&buf, "ipv4_address")[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert_eq!(all(&buf, "gtp_teid")[1].value, FieldValue::U32(1));
        assert_eq!(
            all(&buf, "pdu_session_ambr_dl")[0].value,
            FieldValue::U64(1_000_000_000)
        );
        assert_eq!(all(&buf, "pdu_session_type")[0].value, FieldValue::U8(0));
        assert!(
            names(&buf)
                .iter()
                .all(|n| *n != "transfer_ie_container_error")
        );
    }

    #[test]
    fn setup_list_cxt_req() {
        let (_, buf) = decode(71, &format!("00000500202f{SETUP_REQUEST_TRANSFER}"));
        assert_eq!(one(&buf, "pdu_session_id").value, FieldValue::U8(5));
        assert!(names(&buf).iter().all(|n| *n != "nas_pdu"));
        assert_eq!(one(&buf, "sst").value, FieldValue::U8(1));
        assert_eq!(all(&buf, "ie").len(), 4);
    }

    #[test]
    fn setup_list_su_res() {
        let (_, buf) = decode(75, "0000010f0003e00a0000010000000104094150");
        assert_eq!(one(&buf, "pdu_session_id").value, FieldValue::U8(1));
        let info = one(&buf, "dl_qos_flow_per_tnl_information");
        assert_eq!(info.range, 4..19);
        assert_eq!(
            one(&buf, "ipv4_address").value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert_eq!(one(&buf, "gtp_teid").value, FieldValue::U32(1));
        let qfis: Vec<_> = all(&buf, "qos_flow_identifier")
            .iter()
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(qfis, [FieldValue::U8(9), FieldValue::U8(5)]);
        let mapping = one(&buf, "qos_flow_mapping_indication");
        assert_eq!(mapping.value, FieldValue::U8(1));
        let display = mapping.descriptor.display_fn.unwrap();
        assert_eq!(display(&mapping.value, &[]), Some("dl"));
    }

    #[test]
    fn setup_response_transfer_partial() {
        // securityResult present: decoded up to it, then kept raw.
        let (_, buf) = decode(72, "0000050e2003e00a00000100000001000904");
        assert_eq!(one(&buf, "qos_flow_identifier").value, FieldValue::U8(9));
        let rest = one(&buf, "transfer_undecoded_octets");
        assert_eq!(rest.value, FieldValue::Bytes(&[0x04]));
        assert_eq!(rest.range, 17..18);
    }

    #[test]
    fn failed_lists() {
        for (id, value, group, cause) in [
            (58, "000003020000", 0, 0),
            (55, "000006020000", 0, 0),
            (54, "000001021140", 4, 5),
        ] {
            let (_, buf) = decode(id, value);
            assert_eq!(
                one(&buf, "cause_group").value,
                FieldValue::U8(group),
                "{id}"
            );
            assert_eq!(
                one(&buf, "cause_value").value,
                FieldValue::U8(cause),
                "{id}"
            );
        }
    }

    #[test]
    fn modify_list_mod_req() {
        let (_, buf) = decode(
            64,
            "0040010c7e00680100062e0501c212000d000001008200060407d01003e8",
        );
        assert_eq!(one(&buf, "pdu_session_id").value, FieldValue::U8(1));
        assert_eq!(all(&buf, "message_type")[0].value, FieldValue::U8(0x68));
        assert_eq!(
            one(&buf, "pdu_session_ambr_dl").value,
            FieldValue::U64(2000)
        );
        assert_eq!(
            one(&buf, "pdu_session_ambr_ul").value,
            FieldValue::U64(1000)
        );
    }

    #[test]
    fn modify_list_mod_res() {
        let (_, buf) = decode(
            65,
            "000001216003e00a0000010000000107f020010db800000000000000000000000112345678",
        );
        assert_eq!(
            one(&buf, "dl_ngu_up_tnl_information").name(),
            "dl_ngu_up_tnl_information"
        );
        assert_eq!(
            one(&buf, "ipv4_address").value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert!(matches!(
            one(&buf, "ipv6_address").value,
            FieldValue::Ipv6Addr(_)
        ));
        let teids: Vec<_> = all(&buf, "gtp_teid")
            .iter()
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(teids, [FieldValue::U32(1), FieldValue::U32(0x1234_5678)]);
    }

    #[test]
    fn release_lists() {
        let (_, buf) = decode(79, "0000070110");
        assert_eq!(one(&buf, "pdu_session_id").value, FieldValue::U8(7));
        assert_eq!(one(&buf, "cause_group").value, FieldValue::U8(2));
        assert_eq!(one(&buf, "cause_value").value, FieldValue::U8(0));

        let (_, buf) = decode(70, "0000070100");
        assert_eq!(one(&buf, "pdu_session_id").value, FieldValue::U8(7));
        let transfer = one(&buf, "transfer");
        assert_eq!(transfer.value, FieldValue::Object(4..4));
    }

    #[test]
    fn malformed_list_and_transfer() {
        // Truncated list: raw fallback of the whole IE value.
        let (data, buf) = decode(74, "0140010c7e00");
        assert_eq!(names(&buf), ["value"]);
        assert_eq!(buf.fields()[0].value, FieldValue::Bytes(&data));

        // A release command transfer that is not a valid Cause: kept as
        // the transfer's raw value.
        let (_, buf) = decode(79, "000007017f");
        let values: Vec<_> = all(&buf, "value").iter().map(|f| f.value.clone()).collect();
        assert_eq!(values, [FieldValue::Bytes(&[0x7f])]);

        // Setup request transfer without an IE count: raw value.
        let (_, buf) = decode(71, "00000500200100");
        assert_eq!(one(&buf, "value").value, FieldValue::Bytes(&[0x00]));
    }

    #[test]
    fn list_in_transfer_not_decoded() {
        let data = hex("0000070110");
        let mut buf = DissectBuffer::new();
        push_ie_value_in(&mut buf, 79, &data, 0, IeContext::Transfer);
        assert_eq!(names(&buf), ["value"]);
    }

    /// An iE-Extensions container with one extension (id 1, reject, one
    /// octet 0xff) followed by one extension addition (one octet 0xaa).
    const EXTENSIONS: &str = "000000010001ff";
    const ADDITIONS: &str = "0101aa";

    #[test]
    fn extensions_are_skipped() {
        // Item: extension and iE-Extensions bits set; transfer (release
        // command, cause nas/normal-release) with both set too.
        let transfer = format!("d0{EXTENSIONS}{ADDITIONS}");
        let value = format!(
            "00c007{:02x}{transfer}{EXTENSIONS}{ADDITIONS}",
            transfer.len() / 2
        );
        let (data, buf) = decode(79, &value);
        assert_eq!(one(&buf, "cause_group").value, FieldValue::U8(2));
        assert_eq!(one(&buf, "cause_value").value, FieldValue::U8(0));
        assert_eq!(one(&buf, "item").range, 1..data.len());

        // GTPTunnel with iE-Extensions and an extension addition.
        let (_, buf) = decode(139, &format!("61f00a00000100000001{EXTENSIONS}{ADDITIONS}"));
        assert_eq!(one(&buf, "gtp_teid").value, FieldValue::U32(1));
    }

    #[test]
    fn unsupported_components_kept_raw() {
        // Unsuccessful transfer with criticalityDiagnostics present. The
        // cause ends in the middle of the second octet, so that octet is
        // part of the undecoded rest.
        let (_, buf) = decode(58, "00000303400000");
        assert_eq!(one(&buf, "cause_value").value, FieldValue::U8(0));
        assert_eq!(
            one(&buf, "transfer_undecoded_octets").value,
            FieldValue::Bytes(&[0x00, 0x00])
        );

        // Modify response transfer with only the UL TNL information and a
        // qosFlowAddOrModifyResponseList.
        let (_, buf) = decode(65, "0000010d3003e00a000001000000010099");
        assert_eq!(
            one(&buf, "ul_ngu_up_tnl_information").name(),
            "ul_ngu_up_tnl_information"
        );
        assert!(
            names(&buf)
                .iter()
                .all(|n| *n != "dl_ngu_up_tnl_information")
        );
        assert_eq!(
            one(&buf, "transfer_undecoded_octets").value,
            FieldValue::Bytes(&[0x00, 0x99])
        );
    }

    #[test]
    fn undecodable_nas_pdu_and_empty_transfer() {
        let (_, buf) = decode(64, "00400101990100");
        let nas = one(&buf, "nas_pdu");
        assert_eq!(nas.range, 4..5);
        let values: Vec<_> = all(&buf, "value").iter().map(|f| f.value.clone()).collect();
        assert_eq!(
            values,
            [FieldValue::Bytes(&[0x99]), FieldValue::Bytes(&[0x00])]
        );

        let (_, buf) = decode(71, "000005002000");
        assert_eq!(one(&buf, "value").value, FieldValue::Bytes(&[]));
    }

    #[test]
    fn display_names() {
        let d = FD_UP_TNL_CHOICE.display_fn.unwrap();
        assert_eq!(d(&FieldValue::U8(1), &[]), Some("choice-Extensions"));
        assert_eq!(d(&FieldValue::U8(2), &[]), None);
        let d = FD_QOS_FLOW_MAPPING_INDICATION.display_fn.unwrap();
        assert_eq!(d(&FieldValue::U8(0), &[]), Some("ul"));
        assert_eq!(d(&FieldValue::U8(2), &[]), None);
    }

    #[test]
    fn transfer_cause_choice_extensions() {
        // Release command transfer: cause choice-Extensions with a
        // ProtocolIE-SingleContainer (id 1, reject, one octet 0xff).
        let (_, buf) = decode(79, "000007062800010001ff");
        assert_eq!(one(&buf, "cause_group").value, FieldValue::U8(5));
        assert!(names(&buf).iter().all(|n| *n != "cause_value"));
    }

    #[test]
    fn transfer_container_extension_additions() {
        // Setup request transfer with the extension bit set: one IE (PDU
        // session type ipv4) and one extension addition after the
        // container.
        let (_, buf) = decode(
            71,
            "00000500200b800001008600010001 01aa"
                .replace(' ', "")
                .as_str(),
        );
        assert_eq!(one(&buf, "pdu_session_type").value, FieldValue::U8(0));
        assert!(
            names(&buf)
                .iter()
                .all(|n| *n != "transfer_ie_container_error")
        );
    }
}
