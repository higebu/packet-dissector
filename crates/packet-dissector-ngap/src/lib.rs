//! NGAP (NG Application Protocol) dissector.
//!
//! NGAP is the control-plane protocol between the gNB and the AMF in
//! 5G networks. It runs over SCTP port 38412 and uses ASN.1 Aligned PER
//! (APER) encoding.
//!
//! ## References
//! - 3GPP TS 38.413: <https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/>
//! - ITU-T Rec. X.691 (APER): <https://www.itu.int/rec/T-REC-X.691>

#![deny(missing_docs)]

// The APER reader is shared with the other 3GPP application protocols.
mod container;
pub mod ie_id;
pub mod ie_parsers;
mod pdu_session;
pub mod procedure_code;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_per::{Extent, read_extent};

/// Minimum NGAP-PDU header size: PDU type (1) + procedure code (1) +
/// criticality (1) = 3 bytes, before the value length determinant.
///
/// 3GPP TS 38.413, Section 9.4.2.
const MIN_HEADER_SIZE: usize = 3;

// Field descriptor indices.
const FD_PDU_TYPE: usize = 0;
const FD_PROCEDURE_CODE: usize = 1;
const FD_CRITICALITY: usize = 2;
const FD_VALUE_LENGTH: usize = 3;
const FD_IES: usize = 4;

// IE child field descriptor indices (used in tests to verify schema).
#[cfg(test)]
const CFD_ID: usize = 0;
#[cfg(test)]
const CFD_CRITICALITY: usize = 1;
#[cfg(test)]
const CFD_LENGTH: usize = 2;
#[cfg(test)]
const CFD_VALUE: usize = 3;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "pdu_type",
        display_name: "PDU Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => Some(pdu_type_name(*t)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "procedure_code",
        display_name: "Procedure Code",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(c) => Some(procedure_code::procedure_code_name(*c)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "criticality",
        display_name: "Criticality",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(c) => Some(criticality_name(*c)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("value_length", "Value Length", FieldType::U32),
    FieldDescriptor::new("ies", "Information Elements", FieldType::Array)
        .optional()
        .with_children(container::IE_CHILD_FIELDS),
    container::FD_IE_CONTAINER_ERROR,
    container::FD_UNDECODED_IES,
];

/// Returns a human-readable name for the NGAP-PDU CHOICE index.
///
/// 3GPP TS 38.413, Section 9.4.2.
fn pdu_type_name(pdu_type: u8) -> &'static str {
    match pdu_type {
        0 => "initiatingMessage",
        1 => "successfulOutcome",
        2 => "unsuccessfulOutcome",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for the NGAP criticality value.
///
/// 3GPP TS 38.413, Section 9.4 — Criticality ENUMERATED.
pub(crate) fn criticality_name(criticality: u8) -> &'static str {
    match criticality {
        0 => "reject",
        1 => "ignore",
        2 => "notify",
        _ => "Unknown",
    }
}

/// Reads an APER length determinant from `data` starting at `pos`.
///
/// Returns `(length, bytes_consumed)`.
///
/// ITU-T Rec. X.691, Section 11.9.
pub fn read_aper_length(data: &[u8], pos: usize) -> Result<(u32, usize), PacketError> {
    match read_extent(data, pos)? {
        // At most 16383 octets: always fits in a u32.
        Extent::Contiguous { len_octets, len } => Ok((len as u32, len_octets)),
        // ITU-T Rec. X.691, Section 11.9.3.8: a fragmented length has no
        // single (length, determinant size) pair.
        Extent::Fragmented { .. } => Err(PacketError::InvalidHeader(
            "APER fragmented length determinant not supported",
        )),
    }
}

/// NGAP (NG Application Protocol) dissector.
///
/// Parses NGAP-PDUs encoded with ASN.1 Aligned PER (APER) as specified
/// in 3GPP TS 38.413. Extracts the PDU type, procedure code, criticality,
/// and all top-level Information Elements.
///
/// 3GPP TS 38.413: <https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/>
pub struct NgapDissector;

/// Specification references for the NGAP dissector.
static REFERENCES: &[SpecReference] = &[SpecReference::new(
    "3GPP TS 38.413",
    "NG-RAN; NG Application Protocol (NGAP)",
    "https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/",
)];

impl Dissector for NgapDissector {
    fn name(&self) -> &'static str {
        "NG Application Protocol"
    }

    fn short_name(&self) -> &'static str {
        "NGAP"
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
        if data.len() < MIN_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // Byte 0: NGAP-PDU CHOICE (APER)
        // 3GPP TS 38.413, Section 9.4.2 — NGAP-PDU ::= CHOICE
        //   Bit 7: extension marker (0 = root)
        //   Bits 6-5: choice index (0-2)
        //   Bits 4-0: padding
        let pdu_byte = data[0];
        let extension = (pdu_byte >> 7) & 0x01;
        let pdu_type = (pdu_byte >> 5) & 0x03;

        if extension != 0 {
            return Err(PacketError::InvalidHeader(
                "NGAP-PDU extension not supported",
            ));
        }
        if pdu_type > 2 {
            return Err(PacketError::InvalidFieldValue {
                field: "pdu_type",
                value: u32::from(pdu_type),
            });
        }

        // Byte 1: procedureCode (INTEGER 0..255)
        // 3GPP TS 38.413, Section 9.4 — InitiatingMessage / SuccessfulOutcome /
        // UnsuccessfulOutcome common fields.
        let proc_code = data[1];

        // Byte 2: criticality (ENUMERATED {reject, ignore, notify})
        // 2 bits + 6 bits padding (APER octet-aligned)
        let crit = (data[2] >> 6) & 0x03;

        // Value field: APER OPEN TYPE with length determinant.
        // ITU-T Rec. X.691, Sections 11.2 and 11.9.
        let pos: usize = 3;
        let (value_length, value_start, total_consumed) = match read_extent(data, pos)? {
            Extent::Contiguous { len_octets, len } => {
                (len, pos + len_octets, pos + len_octets + len)
            }
            Extent::Fragmented { total, end } => (total, pos, end),
        };
        if total_consumed > data.len() {
            return Err(PacketError::Truncated {
                expected: total_consumed,
                actual: data.len(),
            });
        }
        let fragmented = value_start == pos;
        let len_bytes = if fragmented { 1 } else { value_start - pos };
        let value_length = value_length as u32;
        let value_length_usize = total_consumed - value_start;

        // Parse ProtocolIE-Container from the value field.
        let value_data = &data[value_start..value_start + value_length_usize];
        let ie_base_offset = offset + value_start;

        buf.begin_layer(
            "NGAP",
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_consumed,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PDU_TYPE],
            FieldValue::U8(pdu_type),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PROCEDURE_CODE],
            FieldValue::U8(proc_code),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CRITICALITY],
            FieldValue::U8(crit),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VALUE_LENGTH],
            FieldValue::U32(value_length),
            offset + 3..offset + 3 + len_bytes,
        );

        // The value OPEN TYPE contains an APER-encoded SEQUENCE
        // (e.g. NGSetupRequest) with a 1-byte preamble: extension bit (1)
        // + padding (7). All NGAP message types follow the pattern
        // `SEQUENCE { protocolIEs ProtocolIE-Container, ... }` with zero
        // optional fields, so the preamble is always exactly 1 byte.
        //
        // 3GPP TS 38.413, Section 9.4 — message SEQUENCE definitions.
        // ITU-T Rec. X.691, Section 18.1 — SEQUENCE preamble encoding.
        const SEQUENCE_PREAMBLE_SIZE: usize = 1;

        if fragmented {
            // ITU-T Rec. X.691, Section 11.9.3.8: the message value is split
            // into fragments separated by length determinants, so the IE
            // container is not contiguous in the packet and is not decoded.
            buf.push_field(
                &container::FD_IE_CONTAINER_ERROR,
                FieldValue::Str("fragmented message value not decoded"),
                offset + pos..offset + total_consumed,
            );
            buf.push_field(
                &container::FD_UNDECODED_IES,
                FieldValue::Bytes(value_data),
                offset + pos..offset + total_consumed,
            );
        } else if value_data.len() > SEQUENCE_PREAMBLE_SIZE {
            let ie_data = &value_data[SEQUENCE_PREAMBLE_SIZE..];
            let ie_offset = ie_base_offset + SEQUENCE_PREAMBLE_SIZE;
            // ITU-T Rec. X.691, Section 19.1: the first bit of the message
            // SEQUENCE is its extension bit.
            let extended = value_data[0] & 0x80 != 0;
            if !container::push_ie_container(
                buf,
                &FIELD_DESCRIPTORS[FD_IES],
                ie_data,
                ie_offset,
                container::IeContext::Message,
                extended,
            ) {
                buf.push_field(
                    &container::FD_IE_CONTAINER_ERROR,
                    FieldValue::Str("IE count truncated"),
                    ie_offset..ie_offset + ie_data.len(),
                );
                buf.push_field(
                    &container::FD_UNDECODED_IES,
                    FieldValue::Bytes(ie_data),
                    ie_offset..ie_offset + ie_data.len(),
                );
            }
        }

        buf.end_layer();

        Ok(DissectResult::new(total_consumed, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 38.413 Coverage
    //!
    //! | Spec Section | Description                  | Test                              |
    //! |--------------|------------------------------|-----------------------------------|
    //! | 9.4.2        | NGAP-PDU CHOICE              | parse_ngap_initiating_message     |
    //! | 9.4.2        | successfulOutcome             | parse_ngap_successful_outcome     |
    //! | 9.4.2        | unsuccessfulOutcome           | parse_ngap_unsuccessful_outcome   |
    //! | 9.4.2        | Invalid PDU type              | parse_ngap_invalid_pdu_type       |
    //! | 9.4.2        | Truncated header              | parse_ngap_truncated              |
    //! | 9.4          | Empty IE container            | parse_ngap_empty_ie_container     |
    //! | 9.4          | ProtocolIE-Container          | parse_ngap_with_ies               |
    //! | 9.5          | APER IE values (InitialUEMessage) | parse_aper_initial_ue_message |
    //! | 9.5          | APER IE values (NGSetupRequest)   | parse_aper_ng_setup_request   |
    //! | 9.5          | APER IE values (UEContextReleaseRequest) | parse_aper_ue_context_release_request |
    //! | 9.4.5        | PDUSessionResourceSetupRequest: N3 TEID | parse_aper_pdu_session_resource_setup_request |
    //! | 9.4.4        | IE count missing                 | parse_ngap_ie_count_truncated     |
    //! | X.691 11.9.3.8 | Fragmented message value       | parse_ngap_fragmented_value       |
    //! | X.691 11.9   | Public length determinant reader | read_aper_length_forms            |

    use super::*;

    /// Build a minimal NGAP-PDU (initiatingMessage, NGSetup, reject)
    /// with the given value payload.
    fn build_ngap_pdu(pdu_type: u8, proc_code: u8, crit: u8, value: &[u8]) -> Vec<u8> {
        let mut pdu = Vec::new();
        // Byte 0: extension(0) | pdu_type(2 bits) | padding(5 bits)
        pdu.push(pdu_type << 5);
        // Byte 1: procedure code
        pdu.push(proc_code);
        // Byte 2: criticality(2 bits) | padding(6 bits)
        pdu.push(crit << 6);
        // Value length determinant
        if value.len() < 128 {
            pdu.push(value.len() as u8);
        } else {
            let len = value.len() as u16;
            pdu.push(0x80 | ((len >> 8) as u8 & 0x3F));
            pdu.push((len & 0xFF) as u8);
        }
        pdu.extend_from_slice(value);
        pdu
    }

    /// Build an APER-encoded message value containing a ProtocolIE-Container.
    /// Includes the 1-byte SEQUENCE preamble (extension bit + padding).
    /// Each IE is (id, criticality, value_bytes).
    fn build_ie_container(ies: &[(u16, u8, &[u8])]) -> Vec<u8> {
        let mut container = Vec::new();
        // SEQUENCE preamble: extension bit (0) + 7 bits padding
        container.push(0x00);
        // IE count: 2 bytes
        container.push((ies.len() >> 8) as u8);
        container.push((ies.len() & 0xFF) as u8);
        for (id, crit, value) in ies {
            // IE id: 2 bytes
            container.push((*id >> 8) as u8);
            container.push((*id & 0xFF) as u8);
            // IE criticality: 1 byte (2 bits + 6 padding)
            container.push(*crit << 6);
            // IE value length determinant
            if value.len() < 128 {
                container.push(value.len() as u8);
            } else {
                let len = value.len() as u16;
                container.push(0x80 | ((len >> 8) as u8 & 0x3F));
                container.push((len & 0xFF) as u8);
            }
            container.extend_from_slice(value);
        }
        container
    }

    #[test]
    fn parse_ngap_initiating_message() {
        // initiatingMessage, NGSetup (21), reject (0), empty container
        let container = build_ie_container(&[]);
        let data = build_ngap_pdu(0, 21, 0, &container);

        let mut buf = DissectBuffer::new();
        let result = NgapDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, data.len());

        let layer = buf.layer_by_name("NGAP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "pdu_type").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "pdu_type_name"),
            Some("initiatingMessage")
        );
        assert_eq!(
            buf.field_by_name(layer, "procedure_code").unwrap().value,
            FieldValue::U8(21)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "procedure_code_name"),
            Some("NGSetup")
        );
        assert_eq!(
            buf.field_by_name(layer, "criticality").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "criticality_name"),
            Some("reject")
        );
    }

    #[test]
    fn parse_ngap_successful_outcome() {
        let container = build_ie_container(&[]);
        let data = build_ngap_pdu(1, 21, 0, &container);

        let mut buf = DissectBuffer::new();
        NgapDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("NGAP").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "pdu_type_name"),
            Some("successfulOutcome")
        );
    }

    #[test]
    fn parse_ngap_unsuccessful_outcome() {
        let container = build_ie_container(&[]);
        let data = build_ngap_pdu(2, 14, 0, &container);

        let mut buf = DissectBuffer::new();
        NgapDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("NGAP").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "pdu_type_name"),
            Some("unsuccessfulOutcome")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "procedure_code_name"),
            Some("InitialContextSetup")
        );
    }

    #[test]
    fn parse_ngap_invalid_pdu_type() {
        // pdu_type = 3 is invalid
        let data = [0x60, 0x15, 0x00, 0x02, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        let result = NgapDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_ngap_truncated() {
        let data = [0x00, 0x15];
        let mut buf = DissectBuffer::new();
        let result = NgapDissector.dissect(&data, &mut buf, 0);
        assert!(matches!(result, Err(PacketError::Truncated { .. })));
    }

    #[test]
    fn parse_ngap_empty_ie_container() {
        let container = build_ie_container(&[]);
        let data = build_ngap_pdu(0, 21, 0, &container);

        let mut buf = DissectBuffer::new();
        NgapDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("NGAP").unwrap();
        let fields = buf.layer_fields(layer);
        // 4 header fields + 1 empty Array container
        assert_eq!(fields.len(), 5);
        // The Array container should have no children.
        if let FieldValue::Array(ref range) = fields[4].value {
            assert!(range.is_empty());
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn parse_ngap_with_ies() {
        // APER: 3-bit (AMF) / 2-bit (RAN) octet count - 1, padding, value.
        let ie_value_1 = [0x00, 0x01]; // AMF-UE-NGAP-ID = 1
        let ie_value_2 = [0x00, 0x2A]; // RAN-UE-NGAP-ID = 42
        let container = build_ie_container(&[
            (10, 0, &ie_value_1), // AMF-UE-NGAP-ID, reject
            (85, 0, &ie_value_2), // RAN-UE-NGAP-ID, reject
        ]);
        let data = build_ngap_pdu(0, 15, 0, &container); // InitialUEMessage

        let mut buf = DissectBuffer::new();
        NgapDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("NGAP").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "procedure_code_name"),
            Some("InitialUEMessage")
        );

        // Find Object containers (IEs) in the layer fields.
        let fields = buf.layer_fields(layer);
        let ie_objects: Vec<_> = fields
            .iter()
            .filter(|f| matches!(f.value, FieldValue::Object(_)))
            .collect();
        assert_eq!(ie_objects.len(), 2);

        // First IE: AMF-UE-NGAP-ID
        if let FieldValue::Object(ref range) = ie_objects[0].value {
            let ie_fields = buf.nested_fields(range);
            let id_field = ie_fields.iter().find(|f| f.name() == "id").unwrap();
            assert_eq!(id_field.value, FieldValue::U16(10));
            let display_fn = id_field.descriptor.display_fn.unwrap();
            assert_eq!(
                display_fn(&id_field.value, ie_fields),
                Some("AMF-UE-NGAP-ID")
            );
            let val_field = ie_fields
                .iter()
                .find(|f| f.name() == "amf_ue_ngap_id")
                .unwrap();
            assert_eq!(val_field.value, FieldValue::U64(1));
        } else {
            panic!("expected Object");
        }

        // Second IE: RAN-UE-NGAP-ID
        if let FieldValue::Object(ref range) = ie_objects[1].value {
            let ie_fields = buf.nested_fields(range);
            let id_field = ie_fields.iter().find(|f| f.name() == "id").unwrap();
            assert_eq!(id_field.value, FieldValue::U16(85));
            let display_fn = id_field.descriptor.display_fn.unwrap();
            assert_eq!(
                display_fn(&id_field.value, ie_fields),
                Some("RAN-UE-NGAP-ID")
            );
            let val_field = ie_fields
                .iter()
                .find(|f| f.name() == "ran_ue_ngap_id")
                .unwrap();
            assert_eq!(val_field.value, FieldValue::U32(42));
        } else {
            panic!("expected Object");
        }
    }

    #[test]
    fn ie_container_resolves_to_ie_name() {
        let ie_value = [0x01, 0x02, 0x03];
        let container = build_ie_container(&[(10, 0, &ie_value)]); // AMF-UE-NGAP-ID
        let data = build_ngap_pdu(0, 15, 0, &container);

        let mut buf = DissectBuffer::new();
        NgapDissector.dissect(&data, &mut buf, 0).unwrap();

        // Find the IE Object container and verify its outer label resolves
        // to the IE name rather than duplicating "ID".
        let (ie_idx, ie_field) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| matches!(f.value, FieldValue::Object(_)))
            .expect("IE container not found");
        assert_eq!(ie_field.name(), "ie");
        assert_eq!(ie_field.display_name(), "IE");
        assert_eq!(
            buf.resolve_container_display_name(ie_idx as u32),
            Some("AMF-UE-NGAP-ID")
        );
    }

    #[test]
    fn parse_ngap_with_offset() {
        let container = build_ie_container(&[(10, 0, &[0x01])]);
        let data = build_ngap_pdu(0, 21, 0, &container);

        let mut buf = DissectBuffer::new();
        let base_offset = 100;
        NgapDissector.dissect(&data, &mut buf, base_offset).unwrap();

        let layer = buf.layer_by_name("NGAP").unwrap();
        assert_eq!(layer.range.start, base_offset);
        assert_eq!(layer.range.end, base_offset + data.len());
    }

    #[test]
    fn parse_ngap_long_length_determinant() {
        // Build a value payload > 127 bytes to trigger the 2-byte length form.
        let ie_value = vec![0xAA; 200];
        let container = build_ie_container(&[(38, 0, &ie_value)]); // NAS-PDU
        let data = build_ngap_pdu(0, 4, 1, &container); // DownlinkNASTransport, ignore

        let mut buf = DissectBuffer::new();
        NgapDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("NGAP").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "procedure_code_name"),
            Some("DownlinkNASTransport")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "criticality_name"),
            Some("ignore")
        );

        // Find IE Object containers.
        let fields = buf.layer_fields(layer);
        let ie_objects: Vec<_> = fields
            .iter()
            .filter(|f| matches!(f.value, FieldValue::Object(_)))
            .collect();
        assert_eq!(ie_objects.len(), 1);
        if let FieldValue::Object(ref range) = ie_objects[0].value {
            let ie_fields = buf.nested_fields(range);
            let val_field = ie_fields.iter().find(|f| f.name() == "value").unwrap();
            if let FieldValue::Bytes(bytes) = &val_field.value {
                assert_eq!(bytes.len(), 200);
            } else {
                panic!("expected Bytes");
            }
        }
    }

    #[test]
    fn field_descriptors_accessible() {
        let d = NgapDissector;
        assert_eq!(d.field_descriptors().len(), 7);
        assert_eq!(
            d.field_descriptors()[FD_IES].children,
            Some(container::IE_CHILD_FIELDS)
        );
    }

    #[test]
    #[allow(unused_variables)]
    fn unused_child_field_indices_compile() {
        // Ensure all CFD_* constants are used and valid.
        let _ = container::IE_CHILD_FIELDS[CFD_ID];
        let _ = container::IE_CHILD_FIELDS[CFD_CRITICALITY];
        let _ = container::IE_CHILD_FIELDS[CFD_LENGTH];
        let _ = container::IE_CHILD_FIELDS[CFD_VALUE];
    }

    #[test]
    fn references_and_layer_are_populated() {
        let dissector = NgapDissector;
        let references = dissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Application));
    }

    /// Returns `(name, value)` of every field of the IE with `ie_id`,
    /// excluding the IE header fields.
    fn ie_value_fields<'a>(
        buf: &'a DissectBuffer<'a>,
        ie_id: u16,
    ) -> Vec<(&'static str, FieldValue<'a>)> {
        for field in buf.fields() {
            if field.name() != "ie" {
                continue;
            }
            let FieldValue::Object(ref range) = field.value else {
                continue;
            };
            let fields = buf.nested_fields(range);
            if fields
                .iter()
                .any(|f| f.name() == "id" && f.value == FieldValue::U16(ie_id))
            {
                return fields
                    .iter()
                    .filter(|f| !matches!(f.name(), "id" | "criticality" | "length"))
                    .map(|f| (f.name(), f.value.clone()))
                    .collect();
            }
        }
        panic!("IE {ie_id} not found");
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // The PDUs below were produced by an independent ALIGNED PER encoder
    // (pycrate `NGAP_PDU_Descriptions.NGAP_PDU.to_aper()`), so they
    // exercise the bit-packed IE value layout of 3GPP TS 38.413,
    // Section 9.5 rather than a hand-written approximation.

    #[test]
    fn parse_aper_initial_ue_message() {
        // RAN-UE-NGAP-ID 1, NAS-PDU (Registration Request), ULI NR
        // (PLMN 001/01, NCI 0x10, TAC 1, timeStamp), RRCEstablishmentCause
        // mo-Signalling, UEContextRequest requested.
        let data = decode_hex(concat!(
            "000f404200000500550002000100260014137e004179000d0100f11000000000",
            "0000000001007900135000f110000000010000f110000001e84f5c11005a4001",
            "180070400100",
        ));
        let mut buf = DissectBuffer::new();
        NgapDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(
            ie_value_fields(&buf, 85),
            vec![("ran_ue_ngap_id", FieldValue::U32(1))]
        );
        assert_eq!(ie_value_fields(&buf, 38)[0].0, "nas_pdu");
        let plmn: &[u8] = &[0x00, 0xF1, 0x10];
        assert_eq!(
            ie_value_fields(&buf, 121),
            vec![
                ("choice", FieldValue::U8(1)),
                ("plmn_identity", FieldValue::Bytes(plmn)),
                ("nr_cell_identity", FieldValue::U64(0x10)),
                ("plmn_identity", FieldValue::Bytes(plmn)),
                ("tac", FieldValue::U32(1)),
                ("time_stamp", FieldValue::U32(0xE84F_5C11)),
            ]
        );
        assert_eq!(
            ie_value_fields(&buf, 90),
            vec![("rrc_establishment_cause", FieldValue::U8(3))]
        );
        assert_eq!(
            ie_value_fields(&buf, 112),
            vec![("ue_context_request", FieldValue::U8(0))]
        );
    }

    #[test]
    fn parse_aper_ng_setup_request() {
        // GlobalRANNodeID gNB (PLMN 001/01, 32-bit gNB-ID 1), RANNodeName
        // "UERANSIM-gnb-1-1-1", SupportedTAList, DefaultPagingDRX v128.
        let data = decode_hex(concat!(
            "0015003e000004001b00090000f1105000000001005240140880554552414e53",
            "494d2d676e622d312d312d310066000d00000000010000f11000000008001540",
            "0140",
        ));
        let mut buf = DissectBuffer::new();
        NgapDissector.dissect(&data, &mut buf, 0).unwrap();

        let plmn: &[u8] = &[0x00, 0xF1, 0x10];
        assert_eq!(
            ie_value_fields(&buf, 27),
            vec![
                ("choice", FieldValue::U8(0)),
                ("plmn_identity", FieldValue::Bytes(plmn)),
                ("gnb_id_length", FieldValue::U8(32)),
                ("gnb_id", FieldValue::U32(1)),
            ]
        );
        assert_eq!(
            ie_value_fields(&buf, 82),
            vec![("name", FieldValue::Bytes(b"UERANSIM-gnb-1-1-1"))]
        );
        assert_eq!(
            ie_value_fields(&buf, 21),
            vec![("default_paging_drx", FieldValue::U8(2))]
        );
    }

    #[test]
    fn parse_aper_ue_context_release_request() {
        // AMF-UE-NGAP-ID 0x1234567890, RAN-UE-NGAP-ID 0xdeadbeef,
        // Cause nas/deregister.
        let data = decode_hex("002a401b000003000a000680123456789000550005c0deadbeef000f400148");
        let mut buf = DissectBuffer::new();
        NgapDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(
            ie_value_fields(&buf, 10),
            vec![("amf_ue_ngap_id", FieldValue::U64(0x12_3456_7890))]
        );
        assert_eq!(
            ie_value_fields(&buf, 85),
            vec![("ran_ue_ngap_id", FieldValue::U32(0xDEAD_BEEF))]
        );
        assert_eq!(
            ie_value_fields(&buf, 15),
            vec![
                ("cause_group", FieldValue::U8(2)),
                ("cause_value", FieldValue::U8(2)),
            ]
        );
    }

    #[test]
    fn parse_aper_pdu_session_resource_setup_request() {
        // AMF-UE-NGAP-ID 1, RAN-UE-NGAP-ID 1, PDUSessionResourceSetupListSUReq
        // with one item: PDU session 1, NAS-PDU (DL NAS transport), SST 1
        // and a PDUSessionResourceSetupRequestTransfer carrying
        // UL-NGU-UP-TNLInformation 10.0.0.1 / TEID 1 (pycrate).
        let data = decode_hex(concat!(
            "001d0055000003000a00020001005500020001004a00420040010c7e00680100",
            "062e0501c2120000202f0000040082000a0c3b9aca00301dcd6500008b000a01",
            "f00a0000010000000100860001000088000700090000091c00",
        ));
        let mut buf = DissectBuffer::new();
        let result = NgapDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        let find = |name: &str| {
            buf.fields()
                .iter()
                .find(|f| f.name() == name)
                .unwrap_or_else(|| panic!("no {name}"))
        };
        assert_eq!(find("pdu_session_id").value, FieldValue::U8(1));
        let addr = find("ipv4_address");
        assert_eq!(addr.value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
        assert_eq!(&data[addr.range.clone()], &[10, 0, 0, 1]);
        let teid = find("gtp_teid");
        assert_eq!(teid.value, FieldValue::U32(1));
        assert_eq!(&data[teid.range.clone()], &[0, 0, 0, 1]);
        assert!(
            buf.fields()
                .iter()
                .all(|f| f.name() != "ie_container_error")
        );
    }

    #[test]
    fn parse_ngap_ie_count_truncated() {
        // Value: SEQUENCE preamble and a single octet of the IE count.
        let data = build_ngap_pdu(0, 15, 0, &[0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        NgapDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("NGAP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "ie_container_error")
                .unwrap()
                .value,
            FieldValue::Str("IE count truncated")
        );
        assert_eq!(
            buf.field_by_name(layer, "undecoded_ies").unwrap().value,
            FieldValue::Bytes(&[0x00])
        );
    }

    #[test]
    fn parse_ngap_fragmented_value() {
        // Value of one 16K fragment followed by a final 3-octet part.
        let mut data = vec![0x00, 0x15, 0x00, 0xc1];
        data.extend(std::iter::repeat_n(0u8, 16384));
        data.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        let result = NgapDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        let layer = buf.layer_by_name("NGAP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "value_length").unwrap().value,
            FieldValue::U32(16387)
        );
        assert_eq!(
            buf.field_by_name(layer, "ie_container_error")
                .unwrap()
                .value,
            FieldValue::Str("fragmented message value not decoded")
        );
        assert!(buf.field_by_name(layer, "ies").is_none());

        // A fragmented value that runs past the data is truncated.
        let mut buf = DissectBuffer::new();
        let result = NgapDissector.dissect(&data[..100], &mut buf, 0);
        assert!(matches!(result, Err(PacketError::Truncated { .. })));
    }

    #[test]
    fn read_aper_length_forms() {
        assert_eq!(read_aper_length(&[0x05], 0).unwrap(), (5, 1));
        assert_eq!(read_aper_length(&[0x00, 0x81, 0x00], 1).unwrap(), (256, 2));
        assert!(matches!(
            read_aper_length(&[0x81], 0),
            Err(PacketError::Truncated { .. })
        ));
        let mut data = vec![0xc1];
        data.extend(std::iter::repeat_n(0u8, 16384));
        data.push(0x00);
        assert!(matches!(
            read_aper_length(&data, 0),
            Err(PacketError::InvalidHeader(_))
        ));
    }
}
