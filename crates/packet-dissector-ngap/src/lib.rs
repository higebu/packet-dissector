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

pub mod ie_id;
pub mod ie_parsers;
pub mod procedure_code;

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

static FD_INLINE_CRITICALITY: FieldDescriptor = FieldDescriptor {
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
};

static FD_INLINE_ID: FieldDescriptor = FieldDescriptor {
    name: "id",
    display_name: "ID",
    field_type: FieldType::U16,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U16(id) => Some(ie_id::ie_id_name(*id)),
        _ => None,
    }),
    format_fn: None,
};

/// Descriptor for the ProtocolIE-Field Object container itself.
///
/// `display_fn` is invoked by
/// [`DissectBuffer::resolve_container_display_name`] with the container's
/// children, so the outer label resolves to the IE name instead of
/// colliding with the inner `ID` field.
static FD_IE: FieldDescriptor = FieldDescriptor {
    name: "ie",
    display_name: "IE",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("id", FieldValue::U16(id)) => Some(ie_id::ie_id_name(*id)),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

static FD_INLINE_LENGTH: FieldDescriptor = FieldDescriptor::new("length", "Length", FieldType::U32);

// Note: FD_INLINE_VALUE was removed — IE values are now pushed by
// ie_parsers::push_ie_value using their own descriptors or a fallback.

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

/// Child field descriptors for each IE element in the `ies` array.
///
/// 3GPP TS 38.413, Section 9.4 — ProtocolIE-Field structure.
static IE_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "id",
        display_name: "ID",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(id) => Some(ie_id::ie_id_name(*id)),
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
    FieldDescriptor::new("length", "Length", FieldType::U32),
    FieldDescriptor::new("value", "Value", FieldType::Bytes),
];

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
        .with_children(IE_CHILD_FIELDS),
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
fn criticality_name(criticality: u8) -> &'static str {
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
    if pos >= data.len() {
        return Err(PacketError::Truncated {
            expected: pos + 1,
            actual: data.len(),
        });
    }
    let first = data[pos];
    if first & 0x80 == 0 {
        // Short form: 0..127, encoded in 1 byte.
        Ok((u32::from(first), 1))
    } else if first & 0xC0 == 0x80 {
        // Long form: 128..16383, encoded in 2 bytes.
        if pos + 2 > data.len() {
            return Err(PacketError::Truncated {
                expected: pos + 2,
                actual: data.len(),
            });
        }
        let len = u32::from(first & 0x3F) << 8 | u32::from(data[pos + 1]);
        Ok((len, 2))
    } else {
        // Fragmented form (>=16384) — not expected in typical NGAP messages.
        Err(PacketError::InvalidHeader(
            "APER fragmented length determinant not supported",
        ))
    }
}

/// Parses NGAP ProtocolIE-Container from `data` starting at `pos`,
/// pushing fields directly into the [`DissectBuffer`].
///
/// Returns `bytes_consumed`.
///
/// 3GPP TS 38.413, Section 9.4 — ProtocolIE-Container.
fn parse_ies<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
) -> Result<usize, PacketError> {
    // IE count: constrained whole number 0..65535 → 2 bytes.
    if data.len() < 2 {
        return Err(PacketError::Truncated {
            expected: 2,
            actual: data.len(),
        });
    }
    let ie_count = read_be_u16(data, 0)? as usize;
    let mut pos: usize = 2;

    for _ in 0..ie_count {
        // Each IE: id (2 bytes) + criticality (1 byte) + value (length + data).
        if pos + 3 > data.len() {
            break;
        }

        let ie_id = read_be_u16(data, pos)?;
        let ie_criticality = (data[pos + 2] >> 6) & 0x03;
        let ie_start = base_offset + pos;
        pos += 3;

        // IE value: APER length determinant + raw bytes.
        let (ie_value_len, len_bytes) = read_aper_length(data, pos)?;
        pos += len_bytes;

        let ie_value_len_usize = ie_value_len as usize;
        if pos + ie_value_len_usize > data.len() {
            break;
        }

        let ie_value_data = &data[pos..pos + ie_value_len_usize];
        let ie_end = base_offset + pos + ie_value_len_usize;
        let ie_value_offset = base_offset + pos;

        // Begin Object container for this IE element.
        let obj_idx = buf.begin_container(&FD_IE, FieldValue::Object(0..0), ie_start..ie_end);

        buf.push_field(
            &FD_INLINE_ID,
            FieldValue::U16(ie_id),
            ie_start..ie_start + 2,
        );
        buf.push_field(
            &FD_INLINE_CRITICALITY,
            FieldValue::U8(ie_criticality),
            ie_start + 2..ie_start + 3,
        );
        buf.push_field(
            &FD_INLINE_LENGTH,
            FieldValue::U32(ie_value_len),
            base_offset + pos - len_bytes..base_offset + pos,
        );

        // Parse the IE value into structured fields if possible.
        ie_parsers::push_ie_value(buf, ie_id, ie_value_data, ie_value_offset);

        buf.end_container(obj_idx);

        pos += ie_value_len_usize;
    }

    Ok(pos)
}

/// NGAP (NG Application Protocol) dissector.
///
/// Parses NGAP-PDUs encoded with ASN.1 Aligned PER (APER) as specified
/// in 3GPP TS 38.413. Extracts the PDU type, procedure code, criticality,
/// and all top-level Information Elements.
///
/// 3GPP TS 38.413: <https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/>
pub struct NgapDissector;

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
        let mut pos: usize = 3;
        let (value_length, len_bytes) = read_aper_length(data, pos)?;
        pos += len_bytes;

        let value_length_usize = value_length as usize;
        if pos + value_length_usize > data.len() {
            return Err(PacketError::Truncated {
                expected: pos + value_length_usize,
                actual: data.len(),
            });
        }

        let total_consumed = pos + value_length_usize;

        // Parse ProtocolIE-Container from the value field.
        let value_data = &data[pos..pos + value_length_usize];
        let ie_base_offset = offset + pos;

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

        // Attempt to parse IEs; if the container is present.
        if value_data.len() > SEQUENCE_PREAMBLE_SIZE {
            let ie_data = &value_data[SEQUENCE_PREAMBLE_SIZE..];
            let ie_offset = ie_base_offset + SEQUENCE_PREAMBLE_SIZE;

            let arr_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_IES],
                FieldValue::Array(0..0),
                ie_offset..ie_offset + ie_data.len(),
            );
            match parse_ies(buf, ie_data, ie_offset) {
                Ok(_) => {}
                Err(_) => {
                    // Gracefully handle IE parse failures by exposing the
                    // header fields without IEs, rather than failing the
                    // entire dissection.
                }
            }
            buf.end_container(arr_idx);
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
        let ie_value_1 = [0x01, 0x02, 0x03]; // dummy AMF-UE-NGAP-ID value
        let ie_value_2 = [0x04, 0x05]; // dummy RAN-UE-NGAP-ID value
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
            let val_field = ie_fields.iter().find(|f| f.name() == "value").unwrap();
            assert_eq!(val_field.value, FieldValue::Bytes(&[0x01, 0x02, 0x03]));
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
        assert_eq!(d.field_descriptors().len(), 5);
        assert_eq!(
            d.field_descriptors()[FD_IES].children,
            Some(IE_CHILD_FIELDS)
        );
    }

    #[test]
    #[allow(unused_variables)]
    fn unused_child_field_indices_compile() {
        // Ensure all CFD_* constants are used and valid.
        let _ = IE_CHILD_FIELDS[CFD_ID];
        let _ = IE_CHILD_FIELDS[CFD_CRITICALITY];
        let _ = IE_CHILD_FIELDS[CFD_LENGTH];
        let _ = IE_CHILD_FIELDS[CFD_VALUE];
    }
}
