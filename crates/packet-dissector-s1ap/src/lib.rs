//! S1AP (S1 Application Protocol) dissector.
//!
//! S1AP is the control-plane protocol between the eNB and the MME in LTE
//! networks (S1-MME). It runs over SCTP (port 36412, payload protocol
//! identifier 18) and uses ASN.1 ALIGNED PER (APER) encoding. The NAS-PDU
//! IE is decoded as an EPS NAS message (3GPP TS 24.301).
//!
//! ## References
//! - 3GPP TS 36.413: <https://www.3gpp.org/ftp/Specs/archive/36_series/36.413/>
//! - 3GPP TS 36.412, Section 7 (SCTP transport):
//!   <https://www.3gpp.org/ftp/Specs/archive/36_series/36.412/>
//! - ITU-T Rec. X.691 (APER): <https://www.itu.int/rec/T-REC-X.691>

#![deny(missing_docs)]

mod container;
pub mod ie_id;
mod ie_parsers;
pub mod procedure_code;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_per::{Extent, read_extent};

/// S1AP-PDU header: CHOICE index (1), procedure code (1) and criticality
/// (1), before the value length determinant.
///
/// 3GPP TS 36.413, Section 9.3.2.
const MIN_HEADER_SIZE: usize = 3;

/// Size of the message SEQUENCE preamble: the extension bit padded to an
/// octet, since every S1AP message is `SEQUENCE { protocolIEs
/// ProtocolIE-Container, ... }` with no OPTIONAL component and the
/// container count is octet-aligned.
///
/// 3GPP TS 36.413, Section 9.3.3; ITU-T Rec. X.691, Section 19.1.
const SEQUENCE_PREAMBLE_SIZE: usize = 1;

const FD_PDU_TYPE: usize = 0;
const FD_PROCEDURE_CODE: usize = 1;
const FD_CRITICALITY: usize = 2;
const FD_VALUE_LENGTH: usize = 3;
const FD_IES: usize = 4;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("pdu_type", "PDU Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => pdu_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("procedure_code", "Procedure Code", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(c) => Some(procedure_code::procedure_code_name(*c)),
            _ => None,
        },
    ),
    FieldDescriptor::new("criticality", "Criticality", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(c) => criticality_name(*c),
            _ => None,
        },
    ),
    FieldDescriptor::new("value_length", "Value Length", FieldType::U32),
    FieldDescriptor::new("ies", "Information Elements", FieldType::Array)
        .optional()
        .with_children(container::IE_CHILD_FIELDS),
    container::FD_IE_CONTAINER_ERROR,
    container::FD_UNDECODED_IES,
];

/// Returns the name of an S1AP-PDU CHOICE alternative.
///
/// 3GPP TS 36.413, Section 9.3.2 — `S1AP-PDU ::= CHOICE {
/// initiatingMessage, successfulOutcome, unsuccessfulOutcome, ... }`.
fn pdu_type_name(pdu_type: u8) -> Option<&'static str> {
    match pdu_type {
        0 => Some("initiatingMessage"),
        1 => Some("successfulOutcome"),
        2 => Some("unsuccessfulOutcome"),
        _ => None,
    }
}

/// Returns the name of a Criticality value.
///
/// 3GPP TS 36.413, Section 9.3.5 — `Criticality ::= ENUMERATED { reject,
/// ignore, notify }`.
pub(crate) fn criticality_name(criticality: u8) -> Option<&'static str> {
    match criticality {
        0 => Some("reject"),
        1 => Some("ignore"),
        2 => Some("notify"),
        _ => None,
    }
}

/// S1AP (S1 Application Protocol) dissector.
///
/// Parses S1AP-PDUs encoded with ASN.1 ALIGNED PER as specified in 3GPP TS
/// 36.413: the PDU type, procedure code, criticality and the IEs of the
/// message, with value decoders for the common IEs.
pub struct S1apDissector;

/// Specification references for the S1AP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "3GPP TS 36.413",
        "Evolved Universal Terrestrial Radio Access Network (E-UTRAN); S1 Application Protocol \
         (S1AP)",
        "https://www.3gpp.org/ftp/Specs/archive/36_series/36.413/",
    ),
    SpecReference::new(
        "3GPP TS 36.412",
        "Evolved Universal Terrestrial Radio Access Network (E-UTRAN); S1 signalling transport",
        "https://www.3gpp.org/ftp/Specs/archive/36_series/36.412/",
    ),
];

impl Dissector for S1apDissector {
    fn name(&self) -> &'static str {
        "S1 Application Protocol"
    }

    fn short_name(&self) -> &'static str {
        "S1AP"
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

        // 3GPP TS 36.413, Section 9.3.2 — S1AP-PDU is an extensible CHOICE
        // of three alternatives: an extension bit, a 2-bit index, padding.
        if data[0] & 0x80 != 0 {
            return Err(PacketError::InvalidHeader(
                "S1AP-PDU extension not supported",
            ));
        }
        let pdu_type = (data[0] >> 5) & 0x03;
        if pdu_type > 2 {
            return Err(PacketError::InvalidFieldValue {
                field: "pdu_type",
                value: u32::from(pdu_type),
            });
        }
        // procedureCode INTEGER (0..255): one octet (ITU-T Rec. X.691,
        // Section 11.5.7.2); criticality: 2 bits and padding.
        let procedure_code = data[1];
        let criticality = data[2] >> 6;

        // The value is an open type (ITU-T Rec. X.691, Sections 11.2, 11.9).
        let pos = MIN_HEADER_SIZE;
        let (value_length, value_start, total) = match read_extent(data, pos)? {
            Extent::Contiguous { len_octets, len } => {
                (len, pos + len_octets, pos + len_octets + len)
            }
            Extent::Fragmented { total, end } => (total, pos, end),
        };
        if total > data.len() {
            return Err(PacketError::Truncated {
                expected: total,
                actual: data.len(),
            });
        }
        let fragmented = value_start == pos;

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total,
        );
        let push = |buf: &mut DissectBuffer<'pkt>, fd: usize, v, r: core::ops::Range<usize>| {
            buf.push_field(&FIELD_DESCRIPTORS[fd], v, offset + r.start..offset + r.end);
        };
        push(buf, FD_PDU_TYPE, FieldValue::U8(pdu_type), 0..1);
        push(buf, FD_PROCEDURE_CODE, FieldValue::U8(procedure_code), 1..2);
        push(buf, FD_CRITICALITY, FieldValue::U8(criticality), 2..3);
        let len_end = if fragmented { pos + 1 } else { value_start };
        push(
            buf,
            FD_VALUE_LENGTH,
            FieldValue::U32(value_length as u32),
            pos..len_end,
        );

        if fragmented {
            // ITU-T Rec. X.691, Section 11.9.3.8: the message value is split
            // into fragments, so the IE container is not contiguous.
            let r = offset + pos..offset + total;
            buf.push_field(
                &container::FD_IE_CONTAINER_ERROR,
                FieldValue::Str("fragmented message value not decoded"),
                r.clone(),
            );
            buf.push_field(
                &container::FD_UNDECODED_IES,
                FieldValue::Bytes(&data[pos..total]),
                r,
            );
        } else if total - value_start > SEQUENCE_PREAMBLE_SIZE {
            let value = &data[value_start..total];
            let ie_data = &value[SEQUENCE_PREAMBLE_SIZE..];
            let ie_offset = offset + value_start + SEQUENCE_PREAMBLE_SIZE;
            // ITU-T Rec. X.691, Section 19.1: the first bit of the message
            // SEQUENCE is its extension bit.
            let extended = value[0] & 0x80 != 0;
            if !container::push_ie_container(
                buf,
                &FIELD_DESCRIPTORS[FD_IES],
                ie_data,
                ie_offset,
                extended,
            ) {
                let r = ie_offset..ie_offset + ie_data.len();
                buf.push_field(
                    &container::FD_IE_CONTAINER_ERROR,
                    FieldValue::Str("IE count truncated"),
                    r.clone(),
                );
                buf.push_field(&container::FD_UNDECODED_IES, FieldValue::Bytes(ie_data), r);
            }
        }

        buf.end_layer();
        Ok(DissectResult::new(total, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests;
