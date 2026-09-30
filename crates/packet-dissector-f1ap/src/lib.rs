//! F1AP (F1 Application Protocol) dissector.
//!
//! F1AP is the control-plane protocol of the F1-C (between gNB-CU and gNB-DU)
//! interface. It runs over SCTP (IANA port 38472 `f1-control`,
//! payload protocol identifier 62) and uses ASN.1 ALIGNED PER
//! (APER) encoding.
//!
//! ## References
//! - 3GPP TS 38.473 v19.4.0: <https://www.3gpp.org/ftp/Specs/archive/38_series/38.473/>
//! - 3GPP TS 38.472 (signalling transport), Section 7:
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.472/>
//! - IANA SCTP Payload Protocol Identifiers:
//!   <https://www.iana.org/assignments/sctp-parameters/>
//! - IANA Service Name and Transport Protocol Port Number Registry:
//!   <https://www.iana.org/assignments/service-names-port-numbers/>
//! - ITU-T Rec. X.691 (APER): <https://www.itu.int/rec/T-REC-X.691>

#![deny(missing_docs)]

pub mod ie_id;
mod ie_parsers;
pub mod procedure_code;

use packet_dissector_aper::ap::{self, ApSpec, PduChoice};
use packet_dissector_core::dissector::{DissectResult, Dissector, ProtocolLayer, SpecReference};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

/// IANA-assigned SCTP port (`f1-control`).
pub const SCTP_PORT: u16 = 38472;

/// IANA-assigned SCTP Payload Protocol Identifier.
pub const SCTP_PPID: u32 = 62;

/// Procedure code of the Private Message procedure.
///
/// 3GPP TS 38.473, Section 9.4.7.
const PRIVATE_MESSAGE_CODE: u8 = 14;

/// Child descriptors of each IE element of an `ies` array.
///
/// 3GPP TS 38.473, Section 9.4.8 — ProtocolIE-Field. `value` is the
/// raw fallback; decoded IEs carry their own fields instead.
pub(crate) static IE_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("id", "ID", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(id) => Some(ie_id::ie_id_name(*id)),
        _ => None,
    }),
    ap::IE_CRITICALITY,
    ap::IE_LENGTH,
    ap::IE_VALUE,
    ap::IE_FRAGMENTED_VALUE,
];

/// Descriptor of one ProtocolIE-Field object; its label is the IE name.
static FD_IE: FieldDescriptor = FieldDescriptor::new(ap::IE_OBJECT_NAME, "IE", FieldType::Object)
    .with_children(IE_CHILD_FIELDS)
    .with_display_fn(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("id", FieldValue::U16(id)) => Some(ie_id::ie_id_name(*id)),
            _ => None,
        }),
        _ => None,
    });

// Indices into [`FIELD_DESCRIPTORS`].
const FD_PROCEDURE_CODE: usize = 1;
const FD_IES: usize = 4;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    ap::PDU_TYPE,
    FieldDescriptor::new("procedure_code", "Procedure Code", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(c) => Some(procedure_code::procedure_code_name(*c)),
            _ => None,
        },
    ),
    ap::CRITICALITY,
    ap::VALUE_LENGTH,
    FieldDescriptor::new("ies", "Information Elements", FieldType::Array)
        .optional()
        .with_children(IE_CHILD_FIELDS),
    ap::IE_CONTAINER_ERROR,
    ap::UNDECODED_IES,
    ap::PRIVATE_IES,
];

/// The F1AP parts of the shared PDU decoder.
pub(crate) static SPEC: ApSpec = ApSpec {
    short_name: "F1AP",
    field_descriptors: FIELD_DESCRIPTORS,
    pdu_choice: PduChoice::ChoiceExtension,
    private_message_code: PRIVATE_MESSAGE_CODE,
    procedure_code: &FIELD_DESCRIPTORS[FD_PROCEDURE_CODE],
    ies: &FIELD_DESCRIPTORS[FD_IES],
    ie: &FD_IE,
    ie_id: &IE_CHILD_FIELDS[0],
    push_value: ie_parsers::push_ie_value,
};

/// F1AP (F1 Application Protocol) dissector.
///
/// Decodes the F1AP-PDU CHOICE, the procedure code, the criticality and
/// the ProtocolIE-Container of the message, with structured values for
/// the common IEs (3GPP TS 38.473, Section 9.4.3).
pub struct F1apDissector;

static REFERENCES: &[SpecReference] = &[SpecReference::new(
    "3GPP TS 38.473",
    "NG-RAN; F1 Application Protocol (F1AP)",
    "https://www.3gpp.org/ftp/Specs/archive/38_series/38.473/",
)];

impl Dissector for F1apDissector {
    fn name(&self) -> &'static str {
        "F1 Application Protocol"
    }

    fn short_name(&self) -> &'static str {
        "F1AP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        ap::dissect_pdu(&SPEC, data, buf, offset)
    }
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 38.473 (F1AP) Coverage
    //!
    //! Test messages were produced by an independent APER encoder (pycrate
    //! `F1AP_PDU_Descriptions`).
    //!
    //! | Spec Section | Description                                        | Test                              |
    //! |--------------|----------------------------------------------------|-----------------------------------|
    //! | 9.4.3        | F1AP-PDU initiatingMessage, F1 Setup Request       | f1_setup_request                  |
    //! | 9.2.1.4      | F1 Setup Request IEs (Transaction ID, DU ID, name) | f1_setup_request                  |
    //! | 9.4.4        | GNB-DU-Served-Cells-List (SingleContainer list)    | f1_setup_request                  |
    //! | 9.4.3        | unsuccessfulOutcome, F1 Setup Failure              | f1_setup_failure                  |
    //! | 9.3.1.2      | Cause                                              | f1_setup_failure                  |
    //! | 9.3.1.13     | Time To Wait                                       | f1_setup_failure                  |
    //! | 9.2.3.1      | Initial UL RRC Message Transfer                    | initial_ul_rrc_message_transfer   |
    //! | 9.3.1.12     | NR CGI                                             | initial_ul_rrc_message_transfer   |
    //! | 9.3.1.32     | C-RNTI                                             | initial_ul_rrc_message_transfer   |
    //! | 9.3.1.6      | RRC-Container (raw)                                | initial_ul_rrc_message_transfer   |
    //! | 9.2.3.1      | DU to CU RRC Container (raw)                       | initial_ul_rrc_message_transfer   |
    //! | 9.2.3.3      | UL RRC Message Transfer, SRB ID, PLMN identity     | ul_rrc_message_transfer           |
    //! | 9.2.2.2      | UE Context Setup Response, DRBs Setup List         | ue_context_setup_response         |
    //! | 9.3.2.1      | UP Transport Layer Information (GTP-TEID)          | ue_context_setup_response         |
    //! | 9.2.2.8      | UE Context Modification Response, DRB lists        | ue_context_modification_response  |
    //! | 9.3.1.4, 9.3.1.7 | Malformed IE values kept raw                       | malformed_values_kept_raw         |
    //! | 9.4.3        | choice-extension PDU rejected                      | choice_extension_rejected         |
    //! | —            | Dissector metadata                                 | dissector_metadata                |

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Values of every field named `name`, in order.
    fn values<'a>(buf: &'a DissectBuffer<'a>, name: &str) -> Vec<FieldValue<'a>> {
        buf.fields()
            .iter()
            .filter(|f| f.name() == name)
            .map(|f| f.value.clone())
            .collect()
    }

    fn dissect(data: &[u8]) -> DissectBuffer<'_> {
        let mut buf = DissectBuffer::new();
        let r = F1apDissector.dissect(data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, data.len());
        buf
    }

    fn assert_no_errors(buf: &DissectBuffer<'_>) {
        for name in [
            "ie_container_error",
            "nested_ie_container_error",
            "value",
            "undecoded_ies",
        ] {
            assert!(values(buf, name).is_empty(), "unexpected {name}");
        }
    }

    const F1_SETUP_REQUEST: &str = "00010047000005004e00020001002a0003200123002d4006018064752d31002c00240000002b001e000000f110000000010000010000f110410009c40000004d00270002102000ab000100";

    #[test]
    fn f1_setup_request() {
        let data = hex(F1_SETUP_REQUEST);
        let buf = dissect(&data);
        let layer = buf.layer_by_name("F1AP").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "procedure_code_name"),
            Some("F1Setup")
        );
        assert_eq!(values(&buf, "transaction_id"), [FieldValue::U8(1)]);
        assert_eq!(values(&buf, "gnb_du_id"), [FieldValue::U64(0x123)]);
        assert_eq!(values(&buf, "gnb_du_name"), [FieldValue::Str("du-1")]);
        // The served cell item is carried as a ProtocolIE-Field (id 43).
        let ids: Vec<_> = [78u16, 42, 45, 44, 43, 171]
            .iter()
            .map(|&i| FieldValue::U16(i))
            .collect();
        assert_eq!(values(&buf, "id"), ids);
        // Served-Cell-Information and RRC-Version are kept raw.
        assert_eq!(values(&buf, "value").len(), 2);
        assert!(values(&buf, "ie_container_error").is_empty());
        assert!(values(&buf, "nested_ie_container_error").is_empty());
    }

    #[test]
    fn f1_setup_failure() {
        let data = hex("80010013000003004e000200010000400166004d400130");
        let buf = dissect(&data);
        assert_eq!(values(&buf, "pdu_type"), [FieldValue::U8(2)]);
        assert_eq!(values(&buf, "cause_group"), [FieldValue::U8(3)]);
        assert_eq!(values(&buf, "cause_value"), [FieldValue::U8(3)]);
        assert_eq!(values(&buf, "time_to_wait"), [FieldValue::U8(3)]);
        let f = buf
            .fields()
            .iter()
            .find(|f| f.name() == "time_to_wait")
            .unwrap();
        assert_eq!(
            (f.descriptor.display_fn.unwrap())(&f.value, &[]),
            Some("v10s")
        );
        assert_no_errors(&buf);
    }

    #[test]
    fn initial_ul_rrc_message_transfer() {
        let data = hex(
            "000b4032000006002900020007006f00090000f1101234567890005f000300460100320004031dec8900800003025c00004e40020000",
        );
        let buf = dissect(&data);
        assert_eq!(values(&buf, "gnb_du_ue_f1ap_id"), [FieldValue::U32(7)]);
        assert_eq!(
            values(&buf, "plmn_identity"),
            [FieldValue::Bytes(&[0x00, 0xf1, 0x10])]
        );
        assert_eq!(
            values(&buf, "nr_cell_identity"),
            [FieldValue::U64(0x1_2345_6789)]
        );
        assert_eq!(values(&buf, "c_rnti"), [FieldValue::U16(0x4601)]);
        assert_eq!(
            values(&buf, "rrc_container"),
            [FieldValue::Bytes(&[0x1d, 0xec, 0x89])]
        );
        assert_eq!(
            values(&buf, "du_to_cu_rrc_container"),
            [FieldValue::Bytes(&[0x5c, 0x00])]
        );
        assert_eq!(values(&buf, "transaction_id"), [FieldValue::U8(0)]);
        // The RRC container range covers only its contents.
        let rrc = buf
            .fields()
            .iter()
            .find(|f| f.name() == "rrc_container")
            .unwrap();
        assert_eq!(&data[rrc.range.clone()], &[0x1d, 0xec, 0x89]);
        assert_no_errors(&buf);
    }

    #[test]
    fn ul_rrc_message_transfer() {
        let data =
            hex("000d40230000050028000200010029000200070040000120003200040300010200e0000300f110");
        let buf = dissect(&data);
        assert_eq!(values(&buf, "gnb_cu_ue_f1ap_id"), [FieldValue::U32(1)]);
        assert_eq!(values(&buf, "gnb_du_ue_f1ap_id"), [FieldValue::U32(7)]);
        assert_eq!(values(&buf, "srb_id"), [FieldValue::U8(1)]);
        assert_eq!(
            values(&buf, "plmn_identity"),
            [FieldValue::Bytes(&[0x00, 0xf1, 0x10])]
        );
        assert_no_errors(&buf);
    }

    #[test]
    fn ue_context_setup_response() {
        let data = hex(
            "400500450000040028000200010029000200070027000400025c00001b402a04001a400c4006007c0a00000200001001001a401500c01f0a00000200001002007c0a00000300001003",
        );
        let buf = dissect(&data);
        assert_eq!(values(&buf, "pdu_type"), [FieldValue::U8(1)]);
        assert_eq!(
            values(&buf, "drb_id"),
            [FieldValue::U8(1), FieldValue::U8(2)]
        );
        assert_eq!(values(&buf, "lcid"), [FieldValue::U8(4)]);
        assert_eq!(
            values(&buf, "ipv4_address"),
            [
                FieldValue::Ipv4Addr([10, 0, 0, 2]),
                FieldValue::Ipv4Addr([10, 0, 0, 2]),
                FieldValue::Ipv4Addr([10, 0, 0, 3])
            ]
        );
        assert_eq!(
            values(&buf, "gtp_teid"),
            [
                FieldValue::U32(0x1001),
                FieldValue::U32(0x1002),
                FieldValue::U32(0x1003)
            ]
        );
        let teid = buf
            .fields()
            .iter()
            .find(|f| f.name() == "gtp_teid")
            .unwrap();
        assert_eq!(&data[teid.range.clone()], &[0x00, 0x00, 0x10, 0x01]);
        // DUtoCURRCInformation is kept raw; nothing else is.
        assert_eq!(values(&buf, "value").len(), 1);
        assert!(values(&buf, "nested_ie_container_error").is_empty());
    }

    #[test]
    fn ue_context_modification_response() {
        let data = hex(
            "40070037000004002800020001002900020007001d401000001c400b01001f0a0000040000200100154010000014400b00001f0a00000500002002",
        );
        let buf = dissect(&data);
        assert_eq!(
            values(&buf, "drb_id"),
            [FieldValue::U8(3), FieldValue::U8(1)]
        );
        assert_eq!(
            values(&buf, "gtp_teid"),
            [FieldValue::U32(0x2001), FieldValue::U32(0x2002)]
        );
        assert_no_errors(&buf);
    }

    #[test]
    fn malformed_values_kept_raw() {
        // UL RRC Message Transfer whose gNB-CU-UE-F1AP-ID value has a
        // trailing octet and whose SRB ID is truncated.
        let data = hex("000d400e0000020028000300010000400000");
        let mut buf = DissectBuffer::new();
        F1apDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(values(&buf, "gnb_cu_ue_f1ap_id").is_empty());
        assert_eq!(values(&buf, "value").len(), 2);
    }

    #[test]
    fn choice_extension_rejected() {
        let data = hex("c00000020000");
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            F1apDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn dissector_metadata() {
        assert_eq!(F1apDissector.name(), "F1 Application Protocol");
        assert_eq!(F1apDissector.short_name(), "F1AP");
        assert_eq!(F1apDissector.layer(), Some(ProtocolLayer::Application));
        assert_eq!(F1apDissector.references()[0].id, "3GPP TS 38.473");
        let names: Vec<_> = F1apDissector
            .field_descriptors()
            .iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(
            names,
            [
                "pdu_type",
                "procedure_code",
                "criticality",
                "value_length",
                "ies",
                "ie_container_error",
                "undecoded_ies",
                "private_ies"
            ]
        );
        assert_eq!(SCTP_PORT, 38472);
        assert_eq!(SCTP_PPID, 62);
    }
}
