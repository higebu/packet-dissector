//! E1AP (E1 Application Protocol) dissector.
//!
//! E1AP is the control-plane protocol of the E1 (between gNB-CU-CP and gNB-CU-UP)
//! interface. It runs over SCTP (IANA port 38462 `e1-interface`,
//! payload protocol identifier 64) and uses ASN.1 ALIGNED PER
//! (APER) encoding.
//!
//! ## References
//! - 3GPP TS 37.483 v19.4.0: <https://www.3gpp.org/ftp/Specs/archive/37_series/37.483/>
//! - 3GPP TS 37.482 (signalling transport), Section 7:
//!   <https://www.3gpp.org/ftp/Specs/archive/37_series/37.482/>
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

/// IANA-assigned SCTP port (`e1-interface`).
pub const SCTP_PORT: u16 = 38462;

/// IANA-assigned SCTP Payload Protocol Identifier.
pub const SCTP_PPID: u32 = 64;

/// Procedure code of the Private Message procedure.
///
/// 3GPP TS 37.483, Section 9.4.7.
const PRIVATE_MESSAGE_CODE: u8 = 2;

/// Child descriptors of each IE element of an `ies` array.
///
/// 3GPP TS 37.483, Section 9.4.8 — ProtocolIE-Field. `value` is the
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

/// The E1AP parts of the shared PDU decoder.
pub(crate) static SPEC: ApSpec = ApSpec {
    short_name: "E1AP",
    field_descriptors: FIELD_DESCRIPTORS,
    pdu_choice: PduChoice::Extensible,
    private_message_code: PRIVATE_MESSAGE_CODE,
    procedure_code: &FIELD_DESCRIPTORS[FD_PROCEDURE_CODE],
    ies: &FIELD_DESCRIPTORS[FD_IES],
    ie: &FD_IE,
    ie_id: &IE_CHILD_FIELDS[0],
    push_value: ie_parsers::push_ie_value,
};

/// E1AP (E1 Application Protocol) dissector.
///
/// Decodes the E1AP-PDU CHOICE, the procedure code, the criticality and
/// the ProtocolIE-Container of the message, with structured values for
/// the common IEs (3GPP TS 37.483, Section 9.4.3).
pub struct E1apDissector;

static REFERENCES: &[SpecReference] = &[SpecReference::new(
    "3GPP TS 37.483",
    "E1 Application Protocol (E1AP)",
    "https://www.3gpp.org/ftp/Specs/archive/37_series/37.483/",
)];

impl Dissector for E1apDissector {
    fn name(&self) -> &'static str {
        "E1 Application Protocol"
    }

    fn short_name(&self) -> &'static str {
        "E1AP"
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
    //! # 3GPP TS 37.483 (E1AP) Coverage
    //!
    //! Test messages were produced by an independent APER encoder (pycrate
    //! `E1AP_PDU_Descriptions`).
    //!
    //! | Spec Section | Description                                          | Test                              |
    //! |--------------|------------------------------------------------------|-----------------------------------|
    //! | 9.4.3        | E1AP-PDU initiatingMessage                           | gnb_cu_up_e1_setup_request        |
    //! | 9.2.1.4      | gNB-CU-UP E1 Setup Request IEs                       | gnb_cu_up_e1_setup_request        |
    //! | 9.3.1.15     | gNB-CU-UP ID                                         | gnb_cu_up_e1_setup_request        |
    //! | 9.2.1.4      | CN Support                                           | gnb_cu_up_e1_setup_request        |
    //! | 9.4.3        | unsuccessfulOutcome, E1 Setup Failure                | gnb_cu_up_e1_setup_failure        |
    //! | 9.3.1.2, 9.3.1.6 | Cause, Time To Wait                                  | gnb_cu_up_e1_setup_failure        |
    //! | 9.2.2.2      | Bearer Context Setup Response (NG-RAN)               | bearer_context_setup_response_ng_ran |
    //! | 9.3.3.5      | PDU Session Resource Setup List, DRB / QoS lists     | bearer_context_setup_response_ng_ran |
    //! | 9.3.2.1      | UP TNL Information (GTP-TEID)                        | bearer_context_setup_response_ng_ran |
    //! | 9.2.2.2      | Bearer Context Setup Response (E-UTRAN)              | bearer_context_setup_response_eutran |
    //! | 9.3.3.3, 9.3.1.13 | DRB Setup List E-UTRAN, UP Parameters                | bearer_context_setup_response_eutran |
    //! | 9.2.2.9      | Bearer Context Release Command                       | bearer_context_release_command    |
    //! | 9.4.4        | Malformed nested list kept raw                       | malformed_nested_list_kept_raw    |
    //! | 9.4.3        | PDU extension rejected                               | pdu_extension_rejected            |
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

    fn dissect(data: &[u8]) -> DissectBuffer<'_> {
        let mut buf = DissectBuffer::new();
        let r = E1apDissector.dissect(data, &mut buf, 0).unwrap();
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

    const BEARER_CONTEXT_SETUP_RESPONSE_NG_RAN: &str = "2008007c00000300020002000a00030002001400104069400001002e40620178011007c0c0a80001abcd0001201fc0a80002abcd00020480000f80c0a80003abcd0003008081000a0f405007c0c0a80004abcd0004000f80c0a80005abcd000520048009a0000201f0c0a80006abcd00060006001fc0a80007abcd0007000180";

    #[test]
    fn gnb_cu_up_e1_setup_request() {
        let data = hex(
            "0003002f00000600390002000300070002000100084009030063752d75702d31000a000120000b0005000000f11000404001c8",
        );
        let buf = dissect(&data);
        let layer = buf.layer_by_name("E1AP").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "procedure_code_name"),
            Some("gNB-CU-UP-E1Setup")
        );
        assert_eq!(values(&buf, "transaction_id"), u8s(&[3]));
        assert_eq!(values(&buf, "gnb_cu_up_id"), [FieldValue::U64(1)]);
        assert_eq!(values(&buf, "gnb_cu_up_name"), [FieldValue::Str("cu-up-1")]);
        assert_eq!(values(&buf, "cn_support"), u8s(&[1]));
        assert_eq!(values(&buf, "gnb_cu_up_capacity"), u8s(&[200]));
        let f = buf
            .fields()
            .iter()
            .find(|f| f.name() == "cn_support")
            .unwrap();
        assert_eq!(
            (f.descriptor.display_fn.unwrap())(&f.value, &[]),
            Some("c-5gc")
        );
        // SupportedPLMNs-List is kept raw.
        assert_eq!(values(&buf, "value").len(), 1);
        assert!(values(&buf, "ie_container_error").is_empty());
    }

    #[test]
    fn gnb_cu_up_e1_setup_failure() {
        let data = hex("400300130000030039000200030000400148000c400150");
        let buf = dissect(&data);
        assert_eq!(values(&buf, "pdu_type"), u8s(&[2]));
        assert_eq!(values(&buf, "cause_group"), u8s(&[2]));
        assert_eq!(values(&buf, "cause_value"), u8s(&[4]));
        assert_eq!(values(&buf, "time_to_wait"), u8s(&[5]));
        assert_fully_decoded(&buf);
    }

    #[test]
    fn bearer_context_setup_response_ng_ran() {
        let data = hex(BEARER_CONTEXT_SETUP_RESPONSE_NG_RAN);
        let buf = dissect(&data);
        assert_fully_decoded(&buf);
        assert_eq!(values(&buf, "gnb_cu_cp_ue_e1ap_id"), [FieldValue::U32(10)]);
        assert_eq!(values(&buf, "gnb_cu_up_ue_e1ap_id"), [FieldValue::U32(20)]);
        assert_eq!(values(&buf, "system_choice"), u8s(&[1]));
        assert_eq!(values(&buf, "pdu_session_id"), u8s(&[1, 2]));
        assert_eq!(values(&buf, "integrity_protection_result"), u8s(&[1]));
        assert_eq!(values(&buf, "confidentiality_protection_result"), u8s(&[0]));
        assert_eq!(values(&buf, "dl_up_unchanged"), u8s(&[0]));
        assert_eq!(values(&buf, "drb_id"), u8s(&[1, 2, 3, 4]));
        assert_eq!(values(&buf, "cell_group_id"), u8s(&[0, 1, 0]));
        assert_eq!(values(&buf, "qos_flow_identifier"), u8s(&[1, 2, 5, 9, 3]));
        // QoS flow 5 and DRB 3 failed.
        assert_eq!(values(&buf, "cause_group"), u8s(&[0, 3]));
        assert_eq!(values(&buf, "cause_value"), u8s(&[15, 4]));
        let teids: Vec<_> = (1..=7).map(|i| FieldValue::U32(0xabcd_0000 + i)).collect();
        assert_eq!(values(&buf, "gtp_teid"), teids);
        let addrs: Vec<_> = (1..=7)
            .map(|i| FieldValue::Ipv4Addr([192, 168, 0, i]))
            .collect();
        assert_eq!(values(&buf, "ipv4_address"), addrs);
        // The TEID range points at the TEID octets.
        let teid = buf
            .fields()
            .iter()
            .find(|f| f.name() == "gtp_teid")
            .unwrap();
        assert_eq!(&data[teid.range.clone()], &[0xab, 0xcd, 0x00, 0x01]);
    }

    #[test]
    fn bearer_context_setup_response_eutran() {
        let data = hex(
            "2008006800000300020002000a000300020014001040550000010025404e080803e00a00000100000011000f800a000002000000220c280f800a00000300000033601f0a0000040000004401f00a00000500000055200f800a00000600000066200f800a0000070000007740",
        );
        let buf = dissect(&data);
        assert_fully_decoded(&buf);
        assert_eq!(values(&buf, "system_choice"), u8s(&[0]));
        assert_eq!(values(&buf, "drb_id"), u8s(&[5, 6]));
        assert_eq!(values(&buf, "cell_group_id"), u8s(&[0, 1, 2]));
        // Each UP-Parameters item nests its tunnel as an object.
        assert_eq!(values(&buf, "up_tnl_information").len(), 3);
        assert_eq!(values(&buf, "dl_up_unchanged"), u8s(&[0]));
        let teids: Vec<_> = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
            .iter()
            .map(|&t| FieldValue::U32(t))
            .collect();
        assert_eq!(values(&buf, "gtp_teid"), teids);
    }

    #[test]
    fn bearer_context_release_command() {
        let data = hex("000b001500000300020002000a000300020014000040020a00");
        let buf = dissect(&data);
        assert_fully_decoded(&buf);
        assert_eq!(values(&buf, "cause_group"), u8s(&[0]));
        assert_eq!(values(&buf, "cause_value"), u8s(&[20]));
    }

    #[test]
    fn malformed_nested_list_kept_raw() {
        // Truncate the PDU Session Resource Setup List by one octet and fix
        // up the three enclosing lengths.
        let mut data = hex(BEARER_CONTEXT_SETUP_RESPONSE_NG_RAN);
        // Remove the last octet of the list value (the final
        // iE-Extensions / padding octet).
        data.pop();
        data[3] -= 1; // message value length
        let sys = data
            .windows(3)
            .position(|w| w == [0x00, 0x10, 0x40])
            .unwrap();
        data[sys + 3] -= 1; // System-BearerContextSetupResponse length
        let list = data
            .windows(3)
            .position(|w| w == [0x00, 0x2e, 0x40])
            .unwrap();
        data[list + 3] -= 1; // PDU-Session-Resource-Setup-List length
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
            E1apDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn dissector_metadata() {
        assert_eq!(E1apDissector.name(), "E1 Application Protocol");
        assert_eq!(E1apDissector.short_name(), "E1AP");
        assert_eq!(E1apDissector.layer(), Some(ProtocolLayer::Application));
        assert_eq!(E1apDissector.references()[0].id, "3GPP TS 37.483");
        assert_eq!(E1apDissector.field_descriptors().len(), 8);
        assert_eq!(SCTP_PORT, 38462);
        assert_eq!(SCTP_PPID, 64);
    }
}
