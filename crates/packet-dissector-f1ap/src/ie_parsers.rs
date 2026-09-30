//! F1AP IE value decoders.
//!
//! Decodes the UE F1AP IDs, the node identity and names, Cause, NR CGI,
//! C-RNTI, SRB ID, Time To Wait, the RRC containers (kept as raw octets,
//! NR RRC decoding is out of scope), PLMN identities, and the DRB lists of
//! the UE context responses with their DL UP transport layer information
//! (GTP tunnel endpoints). Other IEs are kept raw.
//!
//! ## References
//! - 3GPP TS 38.473 v19.4.0, Sections 9.3 (IE semantics) and 9.4.5 (IE
//!   ASN.1): <https://www.3gpp.org/ftp/Specs/archive/38_series/38.473/>
//! - ITU-T Rec. X.691 (APER): <https://www.itu.int/rec/T-REC-X.691>

use packet_dissector_aper::ap::{self, MAX_DEPTH};
use packet_dissector_aper::helpers::{read_sequence_preamble, skip_sequence_tail};
use packet_dissector_aper::ies;
use packet_dissector_core::field::{FieldDescriptor, FieldType};
use packet_dissector_core::packet::DissectBuffer;

use crate::SPEC;

// ── Field descriptors ──────────────────────────────────────────────────

static FD_GNB_CU_UE_F1AP_ID: FieldDescriptor =
    FieldDescriptor::new("gnb_cu_ue_f1ap_id", "gNB-CU UE F1AP ID", FieldType::U32);

static FD_GNB_DU_UE_F1AP_ID: FieldDescriptor =
    FieldDescriptor::new("gnb_du_ue_f1ap_id", "gNB-DU UE F1AP ID", FieldType::U32);

static FD_TRANSACTION_ID: FieldDescriptor =
    FieldDescriptor::new("transaction_id", "Transaction ID", FieldType::U8);

static FD_GNB_DU_ID: FieldDescriptor =
    FieldDescriptor::new("gnb_du_id", "gNB-DU ID", FieldType::U64);

static FD_GNB_DU_NAME: FieldDescriptor =
    FieldDescriptor::new("gnb_du_name", "gNB-DU Name", FieldType::Str);

static FD_GNB_CU_NAME: FieldDescriptor =
    FieldDescriptor::new("gnb_cu_name", "gNB-CU Name", FieldType::Str);

static FD_C_RNTI: FieldDescriptor = FieldDescriptor::new("c_rnti", "C-RNTI", FieldType::U16);

static FD_SRB_ID: FieldDescriptor = FieldDescriptor::new("srb_id", "SRB ID", FieldType::U8);

static FD_RRC_CONTAINER: FieldDescriptor =
    FieldDescriptor::new("rrc_container", "RRC-Container", FieldType::Bytes);

static FD_DU_TO_CU_RRC_CONTAINER: FieldDescriptor = FieldDescriptor::new(
    "du_to_cu_rrc_container",
    "DU to CU RRC Container",
    FieldType::Bytes,
);

static FD_RRC_SETUP_COMPLETE: FieldDescriptor = FieldDescriptor::new(
    "rrc_container_rrc_setup_complete",
    "RRC-Container-RRCSetupComplete",
    FieldType::Bytes,
);

static FD_REDIRECTED_RRC_MESSAGE: FieldDescriptor = FieldDescriptor::new(
    "redirected_rrc_message",
    "Redirected RRC Message",
    FieldType::Bytes,
);

static FD_ITEMS: FieldDescriptor = FieldDescriptor::new("items", "Items", FieldType::Array);

static FD_DRB_ID: FieldDescriptor = FieldDescriptor::new("drb_id", "DRB ID", FieldType::U8);

static FD_LCID: FieldDescriptor = FieldDescriptor::new("lcid", "LCID", FieldType::U8).optional();

static FD_DL_UP_TNL_INFORMATION_LIST: FieldDescriptor = FieldDescriptor::new(
    "dl_up_tnl_information",
    "DL UP TNL Information",
    FieldType::Array,
);

static FD_UP_TNL_INFORMATION: FieldDescriptor = FieldDescriptor::new(
    "up_tnl_information",
    "UP Transport Layer Information",
    FieldType::Object,
);

// ── ASN.1 constants ────────────────────────────────────────────────────

/// `GNB-CU-UE-F1AP-ID` / `GNB-DU-UE-F1AP-ID ::= INTEGER (0..4294967295)`.
///
/// 3GPP TS 38.473, Section 9.4.5.
const UE_F1AP_ID_MAX: u64 = 4_294_967_295;

/// `GNB-DU-ID ::= INTEGER (0..68719476735)`.
///
/// 3GPP TS 38.473, Section 9.4.5.
const GNB_DU_ID_MAX: u64 = 68_719_476_735;

/// `TransactionID ::= INTEGER (0..255, ...)`.
///
/// 3GPP TS 38.473, Section 9.4.5.
const TRANSACTION_ID_MAX: u64 = 255;

/// `C-RNTI ::= INTEGER (0..65535, ...)`.
///
/// 3GPP TS 38.473, Section 9.4.5.
const C_RNTI_MAX: u64 = 65535;

/// `SRBID ::= INTEGER (0..3, ..., 4 | 5 | 6)`.
///
/// 3GPP TS 38.473, Section 9.4.5.
const SRB_ID_MAX: u64 = 3;

/// `DRBID ::= INTEGER (1..32, ...)` and `LCID ::= INTEGER (1..32, ...)`.
///
/// 3GPP TS 38.473, Section 9.4.5.
const DRB_ID_AND_LCID_MAX: u64 = 32;

/// `PrintableString (SIZE(1..150, ...))` of `GNB-DU-Name` / `GNB-CU-Name`.
///
/// 3GPP TS 38.473, Section 9.4.5.
const NAME_MAX: u64 = 150;

/// Root sizes of `CauseRadioNetwork`, `CauseTransport`, `CauseProtocol`
/// and `CauseMisc`.
///
/// 3GPP TS 38.473 v19.4.0, Section 9.4.5.
const CAUSE_ROOT_COUNTS: [u64; 4] = [11, 2, 7, 5];

/// `maxnoofDRBs`, the size bound of the DRB lists.
///
/// 3GPP TS 38.473, Section 9.4.7.
const MAX_NO_OF_DRBS: u64 = 64;

/// `maxnoofDLUPTNLInformation`.
///
/// 3GPP TS 38.473, Section 9.4.7.
const MAX_NO_OF_DL_UP_TNL_INFORMATION: u64 = 2;

/// `maxCellingNBDU`, the size bound of GNB-DU-Served-Cells-List.
///
/// 3GPP TS 38.473, Section 9.4.7.
const MAX_CELL_IN_GNB_DU: u64 = 512;

// ── Dispatch ───────────────────────────────────────────────────────────

/// Decodes the value of IE `id` (see [`packet_dissector_aper::ap::PushValueFn`]).
///
/// IE IDs are the `id-` constants of 3GPP TS 38.473, Section 9.4.7.
pub(crate) fn push_ie_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    id: u16,
    data: &'pkt [u8],
    offset: usize,
    depth: u8,
) -> bool {
    match id {
        // Cause — TS 38.473, Section 9.3.1.2.
        0 => ies::push_cause(buf, &CAUSE_ROOT_COUNTS, data, offset),
        // DRBs-Modified-List / DRBs-Setup-List / DRBs-SetupMod-List —
        // SEQUENCE (SIZE(1..maxnoofDRBs)) OF ProtocolIE-SingleContainer
        // (TS 38.473, Section 9.4.4).
        21 | 27 | 29 if depth < MAX_DEPTH => ap::push_single_container_list(
            buf,
            &SPEC,
            &FD_ITEMS,
            data,
            offset,
            depth + 1,
            MAX_NO_OF_DRBS,
        ),
        // DRBs-Modified-Item / DRBs-Setup-Item / DRBs-SetupMod-Item.
        20 | 26 | 28 => push_drb_item(buf, data, offset),
        // gNB-CU-UE-F1AP-ID / new-gNB-CU-UE-F1AP-ID — Section 9.3.1.4.
        40 | 217 => ies::push_unsigned(buf, &FD_GNB_CU_UE_F1AP_ID, UE_F1AP_ID_MAX, data, offset),
        // gNB-DU-UE-F1AP-ID / oldgNB-DU-UE-F1AP-ID / new-gNB-DU-UE-F1AP-ID
        // — Section 9.3.1.5.
        41 | 47 | 219 => {
            ies::push_unsigned(buf, &FD_GNB_DU_UE_F1AP_ID, UE_F1AP_ID_MAX, data, offset)
        }
        // gNB-DU-ID — Section 9.3.1.9.
        42 => ies::push_unsigned(buf, &FD_GNB_DU_ID, GNB_DU_ID_MAX, data, offset),
        // gNB-DU-Served-Cells-List — SEQUENCE (SIZE(1..maxCellingNBDU)) OF
        // ProtocolIE-SingleContainer; the items are kept raw.
        44 if depth < MAX_DEPTH => ap::push_single_container_list(
            buf,
            &SPEC,
            &FD_ITEMS,
            data,
            offset,
            depth + 1,
            MAX_CELL_IN_GNB_DU,
        ),
        // gNB-DU-Name — Section 9.3.1.12a.
        45 => ies::push_printable_string(buf, &FD_GNB_DU_NAME, 1, NAME_MAX, data, offset),
        // RRCContainer — Section 9.3.1.6.
        50 => ies::push_octet_string(buf, &FD_RRC_CONTAINER, data, offset),
        // SpCell-ID / NRCGI / requestedTargetCellGlobalID — NRCGI, Section
        // 9.3.1.12.
        63 | 111 | 376 => ies::push_nr_cgi(buf, data, offset),
        // SRBID — Section 9.3.1.7.
        64 => ies::push_extensible_unsigned(buf, &FD_SRB_ID, SRB_ID_MAX, data, offset),
        // TimeToWait — Section 9.3.1.13.
        77 => ies::push_time_to_wait(buf, data, offset),
        // TransactionID — Section 9.3.1.23.
        78 => {
            ies::push_extensible_unsigned(buf, &FD_TRANSACTION_ID, TRANSACTION_ID_MAX, data, offset)
        }
        // gNB-CU-Name — Section 9.3.1.41.
        82 => ies::push_printable_string(buf, &FD_GNB_CU_NAME, 1, NAME_MAX, data, offset),
        // C-RNTI — Section 9.3.1.32.
        95 => ies::push_extensible_unsigned(buf, &FD_C_RNTI, C_RNTI_MAX, data, offset),
        // DUtoCURRCContainer — Section 9.3.1.26.
        128 => ies::push_octet_string(buf, &FD_DU_TO_CU_RRC_CONTAINER, data, offset),
        // ServingPLMN / PLMNAssistanceInfoForNetShar / SelectedPLMNID —
        // PLMN-Identity, Section 9.3.1.14.
        165 | 221 | 224 => ies::push_plmn_identity(buf, data, offset),
        // RedirectedRRCmessage — OCTET STRING, Section 9.2.3.2.
        218 => ies::push_octet_string(buf, &FD_REDIRECTED_RRC_MESSAGE, data, offset),
        // RRCContainer-RRCSetupComplete — Section 9.3.1.6.
        241 => ies::push_octet_string(buf, &FD_RRC_SETUP_COMPLETE, data, offset),
        _ => false,
    }
}

// ── Individual decoders ────────────────────────────────────────────────

/// DRBs-Setup-Item / DRBs-SetupMod-Item / DRBs-Modified-Item —
/// `SEQUENCE { dRBID DRBID, lCID LCID OPTIONAL,
/// dLUPTNLInformation-ToBeSetup-List, iE-Extensions OPTIONAL, ... }`, the
/// list being `SEQUENCE (SIZE(1..maxnoofDLUPTNLInformation)) OF SEQUENCE {
/// dLUPTNLInformation UPTransportLayerInformation, iE-Extensions OPTIONAL,
/// ... }`.
///
/// 3GPP TS 38.473, Sections 9.3.1.8 (DRB ID), 9.3.2.1 (UP Transport Layer
/// Information) and 9.4.5; ITU-T Rec. X.691, Sections 13.2.6, 19, 20.
fn push_drb_item<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    ies::push_value_with(buf, data, |buf, r| {
        let extended = r.read_bit()?;
        let lcid_present = r.read_bit()?;
        let has_ie_extensions = r.read_bit()?;
        ies::push_small_integer(buf, &FD_DRB_ID, r, offset, 1, DRB_ID_AND_LCID_MAX)?;
        if lcid_present {
            ies::push_small_integer(buf, &FD_LCID, r, offset, 1, DRB_ID_AND_LCID_MAX)?;
        }
        ies::push_sequence_of(
            buf,
            &FD_DL_UP_TNL_INFORMATION_LIST,
            r,
            offset,
            1,
            MAX_NO_OF_DL_UP_TNL_INFORMATION,
            |buf, r| {
                let (item_extended, item_ie_extensions) = read_sequence_preamble(r)?;
                ies::push_up_tnl_object(buf, &FD_UP_TNL_INFORMATION, r, offset)?;
                skip_sequence_tail(r, item_extended, item_ie_extensions)
            },
        )?;
        skip_sequence_tail(r, extended, has_ie_extensions)
    })
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 38.473 IE Decoder Coverage
    //!
    //! | Spec Section | Description                           | Test                          |
    //! |--------------|---------------------------------------|-------------------------------|
    //! | 9.4.5        | DRB item with extended DRB ID / LCID  | drb_item_extended_drb_id      |
    //! | 9.4.5        | DRB item, malformed                   | drb_item_malformed            |
    //! | —            | Lists beyond the nesting limit        | lists_beyond_depth_kept_raw   |

    use super::*;
    use packet_dissector_core::field::FieldValue;

    #[test]
    fn drb_item_extended_drb_id() {
        // DRB ID 33 and LCID 40, both extension values (pycrate
        // `F1AP_IEs.DRBs_Setup_Item`), then one GTP tunnel.
        let data = [
            0x50, 0x01, 0x21, 0x80, 0x01, 0x28, 0x00, 0x3e, 0x0a, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x10, 0x01,
        ];
        let mut buf = DissectBuffer::new();
        assert!(push_drb_item(&mut buf, &data, 0));
        let values: Vec<_> = buf
            .fields()
            .iter()
            .map(|f| (f.name(), f.value.clone()))
            .collect();
        assert_eq!(values[0], ("drb_id", FieldValue::U8(33)));
        assert_eq!(values[1], ("lcid", FieldValue::U8(40)));
        assert_eq!(buf.fields()[0].range, 0..3);
        assert_eq!(
            values.last().unwrap(),
            &("gtp_teid", FieldValue::U32(0x1001))
        );
    }

    #[test]
    fn drb_item_malformed() {
        // Valid DRBs-Setup-Item (pycrate) with a trailing octet, then
        // truncated.
        let valid = [
            0x40, 0x06, 0x00, 0x7c, 0x0a, 0x00, 0x00, 0x02, 0x00, 0x00, 0x10, 0x01,
        ];
        let mut buf = DissectBuffer::new();
        assert!(push_drb_item(&mut buf, &valid, 0));
        let mut trailing = valid.to_vec();
        trailing.push(0);
        let mut buf = DissectBuffer::new();
        assert!(!push_drb_item(&mut buf, &trailing, 0));
        assert!(buf.fields().is_empty());
        assert!(!push_drb_item(&mut buf, &valid[..8], 0));
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn lists_beyond_depth_kept_raw() {
        let mut buf = DissectBuffer::new();
        assert!(!push_ie_value(&mut buf, 27, &[0x00], 0, MAX_DEPTH));
        assert!(!push_ie_value(&mut buf, 44, &[0x00], 0, MAX_DEPTH));
        assert!(!push_ie_value(&mut buf, 9999, &[0x00], 0, 0));
    }
}
