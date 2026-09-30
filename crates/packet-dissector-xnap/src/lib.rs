//! XnAP (Xn Application Protocol) dissector.
//!
//! XnAP is the control-plane protocol of the Xn-C (between NG-RAN nodes)
//! interface. It runs over SCTP (IANA port 38422 `xn-control`,
//! payload protocol identifier 61) and uses ASN.1 ALIGNED PER
//! (APER) encoding.
//!
//! ## References
//! - 3GPP TS 38.423 v19.4.0: <https://www.3gpp.org/ftp/Specs/archive/38_series/38.423/>
//! - 3GPP TS 38.422 (signalling transport), Section 7:
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.422/>
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

/// IANA-assigned SCTP port (`xn-control`).
pub const SCTP_PORT: u16 = 38422;

/// IANA-assigned SCTP Payload Protocol Identifier.
pub const SCTP_PPID: u32 = 61;

/// Procedure code of the Private Message procedure.
///
/// 3GPP TS 38.423, Section 9.3.7.
const PRIVATE_MESSAGE_CODE: u8 = 22;

/// Child descriptors of each IE element of an `ies` array.
///
/// 3GPP TS 38.423, Section 9.3.8 — ProtocolIE-Field. `value` is the
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

/// The XnAP parts of the shared PDU decoder.
pub(crate) static SPEC: ApSpec = ApSpec {
    short_name: "XnAP",
    field_descriptors: FIELD_DESCRIPTORS,
    pdu_choice: PduChoice::Extensible,
    private_message_code: PRIVATE_MESSAGE_CODE,
    procedure_code: &FIELD_DESCRIPTORS[FD_PROCEDURE_CODE],
    ies: &FIELD_DESCRIPTORS[FD_IES],
    ie: &FD_IE,
    ie_id: &IE_CHILD_FIELDS[0],
    push_value: ie_parsers::push_ie_value,
};

/// XnAP (Xn Application Protocol) dissector.
///
/// Decodes the XnAP-PDU CHOICE, the procedure code, the criticality and
/// the ProtocolIE-Container of the message, with structured values for
/// the common IEs (3GPP TS 38.423, Section 9.3.3).
pub struct XnapDissector;

static REFERENCES: &[SpecReference] = &[SpecReference::new(
    "3GPP TS 38.423",
    "NG-RAN; Xn Application Protocol (XnAP)",
    "https://www.3gpp.org/ftp/Specs/archive/38_series/38.423/",
)];

impl Dissector for XnapDissector {
    fn name(&self) -> &'static str {
        "Xn Application Protocol"
    }

    fn short_name(&self) -> &'static str {
        "XnAP"
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
    //! # 3GPP TS 38.423 (XnAP) Coverage
    //!
    //! Test messages were produced by an independent APER encoder (pycrate
    //! `XnAP_PDU_Descriptions`).
    //!
    //! | Spec Section | Description                                          | Test                              |
    //! |--------------|------------------------------------------------------|-----------------------------------|
    //! | 9.3.3        | XnAP-PDU initiatingMessage, Xn Setup Request         | xn_setup_request                  |
    //! | 9.2.2.1, 9.2.2.39 | Global NG-RAN Node ID (gNB), Interface Instance Ind. | xn_setup_request                  |
    //! | 9.3.3        | successfulOutcome, Xn Setup Response                 | xn_setup_response_ng_enb          |
    //! | 9.2.2.2      | Global NG-RAN Node ID (ng-eNB, long macro eNB ID)    | xn_setup_response_ng_enb          |
    //! | 9.3.3        | unsuccessfulOutcome, Xn Setup Failure                | xn_setup_failure                  |
    //! | 9.2.3.2, 9.2.3.56 | Cause (extension value), Time To Wait                | xn_setup_failure                  |
    //! | 9.1.1.2      | Handover Request Acknowledge                         | handover_request_acknowledge      |
    //! | 9.2.3.16     | NG-RAN node UE XnAP ID                               | handover_request_acknowledge      |
    //! | 9.2.1.2      | PDU Session Resources Admitted List                  | handover_request_acknowledge      |
    //! | 9.2.1.16     | Data Forwarding Info from target (GTP-TEID)          | handover_request_acknowledge      |
    //! | 9.1.1.3, 9.2.3.25 | Handover Preparation Failure, Target Cell Global ID  | handover_preparation_failure      |
    //! | 9.1.1.5      | UE Context Release                                   | ue_context_release                |
    //! | 9.3.4        | Malformed admitted list kept raw                     | malformed_admitted_list_kept_raw  |
    //! | 9.3.3        | PDU extension rejected                               | pdu_extension_rejected            |
    //! | —            | Dissector metadata                                   | dissector_metadata                |

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

    fn u8s(v: &[u8]) -> Vec<FieldValue<'static>> {
        v.iter().map(|&x| FieldValue::U8(x)).collect()
    }

    fn display(buf: &DissectBuffer<'_>, name: &str) -> Option<&'static str> {
        let f = buf.fields().iter().find(|f| f.name() == name)?;
        (f.descriptor.display_fn?)(&f.value, &[])
    }

    fn dissect(data: &[u8]) -> DissectBuffer<'_> {
        let mut buf = DissectBuffer::new();
        let r = XnapDissector.dissect(data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, data.len());
        buf
    }

    fn assert_fully_decoded(buf: &DissectBuffer<'_>) {
        for name in [
            "ie_container_error",
            "nested_ie_container_error",
            "value",
            "undecoded_ies",
        ] {
            assert!(values(buf, name).is_empty(), "unexpected {name}");
        }
    }

    const HANDOVER_REQUEST_ACKNOWLEDGE: &str = "20000058000004004940020064004f400200c8002a403d01000170100808140d8808e000203e0a0a00010000500101f00a0a0002000050020a0003e00a0a00030000500320407c0a0a0004000050040002000050004d4004030a0b0c";

    #[test]
    fn xn_setup_request() {
        let data = hex(
            "0011002f000004000e00080000f1100000066c004b000d00000000010000f11000000020000400050000f11080008200020007",
        );
        let buf = dissect(&data);
        let layer = buf.layer_by_name("XnAP").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "procedure_code_name"),
            Some("xnSetup")
        );
        assert_eq!(values(&buf, "node_choice"), u8s(&[0]));
        assert_eq!(display(&buf, "node_choice"), Some("gNB"));
        assert_eq!(
            values(&buf, "plmn_identity"),
            [FieldValue::Bytes(&[0x00, 0xf1, 0x10])]
        );
        assert_eq!(values(&buf, "gnb_id_length"), u8s(&[22]));
        assert_eq!(values(&buf, "gnb_id"), [FieldValue::U32(0x19b)]);
        assert_eq!(values(&buf, "interface_instance_indication"), u8s(&[7]));
        // TAISupport-List and AMF-Region-Information are kept raw.
        assert_eq!(values(&buf, "value").len(), 2);
        assert!(values(&buf, "ie_container_error").is_empty());
    }

    #[test]
    fn xn_setup_response_ng_enb() {
        let data = hex("20110020000002000e00084000f11080091a28004b000d00000000010000f11000000020");
        let buf = dissect(&data);
        assert_eq!(values(&buf, "pdu_type"), u8s(&[1]));
        assert_eq!(values(&buf, "node_choice"), u8s(&[1]));
        assert_eq!(display(&buf, "node_choice"), Some("ng-eNB"));
        assert_eq!(values(&buf, "enb_id_choice"), u8s(&[2]));
        assert_eq!(display(&buf, "enb_id_choice"), Some("enb-ID-longmacro"));
        assert_eq!(values(&buf, "enb_id"), [FieldValue::U32(0x12345)]);
    }

    #[test]
    fn xn_setup_failure() {
        let data = hex("4011000e000002000740021000004c400110");
        let buf = dissect(&data);
        assert_fully_decoded(&buf);
        assert_eq!(values(&buf, "pdu_type"), u8s(&[2]));
        assert_eq!(values(&buf, "cause_group"), u8s(&[0]));
        // ue-context-id-not-known, the first extension value.
        assert_eq!(values(&buf, "cause_value"), u8s(&[53]));
        assert_eq!(values(&buf, "time_to_wait"), u8s(&[1]));
        assert_eq!(display(&buf, "time_to_wait"), Some("v2s"));
    }

    #[test]
    fn handover_request_acknowledge() {
        let data = hex(HANDOVER_REQUEST_ACKNOWLEDGE);
        let buf = dissect(&data);
        assert_fully_decoded(&buf);
        assert_eq!(
            values(&buf, "ng_ran_node_ue_xnap_id"),
            [FieldValue::U32(100), FieldValue::U32(200)]
        );
        assert_eq!(values(&buf, "pdu_session_id"), u8s(&[1, 2]));
        assert_eq!(values(&buf, "dl_ng_u_tnl_information_unchanged"), u8s(&[0]));
        assert_eq!(
            values(&buf, "qos_flow_identifier"),
            u8s(&[1, 2, 3, 4, 1, 5])
        );
        assert_eq!(values(&buf, "cause_group"), u8s(&[3]));
        assert_eq!(values(&buf, "cause_value"), u8s(&[1]));
        assert_eq!(values(&buf, "drb_id"), u8s(&[1, 2]));
        let teids: Vec<_> = (1..=4).map(|i| FieldValue::U32(0x5000 + i)).collect();
        assert_eq!(values(&buf, "gtp_teid"), teids);
        let addrs: Vec<_> = (1..=4)
            .map(|i| FieldValue::Ipv4Addr([10, 10, 0, i]))
            .collect();
        assert_eq!(values(&buf, "ipv4_address"), addrs);
        assert_eq!(
            values(&buf, "target_to_source_container"),
            [FieldValue::Bytes(&[0x0a, 0x0b, 0x0c])]
        );
        let teid = buf
            .fields()
            .iter()
            .find(|f| f.name() == "gtp_teid")
            .unwrap();
        assert_eq!(&data[teid.range.clone()], &[0x00, 0x00, 0x50, 0x01]);
    }

    #[test]
    fn handover_preparation_failure() {
        let data = hex("4000001a000003004940020064000740012800a100084000f11012345670");
        let buf = dissect(&data);
        assert_fully_decoded(&buf);
        assert_eq!(values(&buf, "cause_group"), u8s(&[1]));
        assert_eq!(values(&buf, "cause_value"), u8s(&[1]));
        assert_eq!(values(&buf, "cgi_choice"), u8s(&[1]));
        assert_eq!(display(&buf, "cgi_choice"), Some("e-utra"));
        assert_eq!(
            values(&buf, "eutra_cell_identity"),
            [FieldValue::U32(0x123_4567)]
        );
    }

    #[test]
    fn ue_context_release() {
        let data = hex("0006400f000002004900020064004f000200c8");
        let buf = dissect(&data);
        assert_fully_decoded(&buf);
        assert_eq!(
            values(&buf, "ng_ran_node_ue_xnap_id"),
            [FieldValue::U32(100), FieldValue::U32(200)]
        );
    }

    #[test]
    fn malformed_admitted_list_kept_raw() {
        // Change the admitted list's first octet so that its count (one
        // octet-aligned octet, 1..256) announces more items than present.
        let mut data = hex(HANDOVER_REQUEST_ACKNOWLEDGE);
        let list = data
            .windows(3)
            .position(|w| w == [0x00, 0x2a, 0x40])
            .unwrap();
        data[list + 4] = 0x05;
        let buf = dissect(&data);
        assert!(values(&buf, "pdu_session_id").is_empty());
        assert_eq!(values(&buf, "value").len(), 1);
        assert!(values(&buf, "ie_container_error").is_empty());
    }

    #[test]
    fn pdu_extension_rejected() {
        let data = hex("800000020000");
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            XnapDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn dissector_metadata() {
        assert_eq!(XnapDissector.name(), "Xn Application Protocol");
        assert_eq!(XnapDissector.short_name(), "XnAP");
        assert_eq!(XnapDissector.layer(), Some(ProtocolLayer::Application));
        assert_eq!(XnapDissector.references()[0].id, "3GPP TS 38.423");
        assert_eq!(XnapDissector.field_descriptors().len(), 8);
        assert_eq!(SCTP_PORT, 38422);
        assert_eq!(SCTP_PPID, 61);
    }
}
