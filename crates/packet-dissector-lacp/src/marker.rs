//! Link Aggregation Marker protocol dissector.
//!
//! Parses Marker PDUs and Marker Response PDUs carried inside IEEE 802.3
//! Slow Protocols frames (EtherType 0x8809, subtype 0x02).
//!
//! ## References
//! - IEEE 802.1AX-2020, Section 6.5.3 (Marker and Marker Response PDU
//!   structure and encoding): <https://standards.ieee.org/ieee/802.1AX/6734/>

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, MacAddr};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Specification references for the Marker protocol dissector.
static REFERENCES: &[SpecReference] = &[SpecReference::new(
    "IEEE 802.1AX",
    "IEEE Standard for Local and Metropolitan Area Networks - Link Aggregation \
     (IEEE 802.1AX-2020), Section 6.5 (Marker protocol)",
    "https://standards.ieee.org/ieee/802.1AX/6734/",
)];

/// Slow Protocols subtype for the Marker protocol.
/// IEEE 802.1AX-2020, Section 6.5.3.3 a).
pub(crate) const SUBTYPE_MARKER: u8 = 0x02;

/// Octets from Subtype through the Terminator TLV: the part of a Marker PDU
/// that carries information (IEEE 802.1AX-2020, Section 6.5.3.3, Figure 6-19).
const MARKER_INFO_SIZE: usize = 20;

/// Total size of a Marker PDU including the 90-octet Reserved field
/// (IEEE 802.1AX-2020, Section 6.5.3.3, Figure 6-19).
const MARKER_PDU_SIZE: usize = 110;

/// TLV_type value for Marker Information.
/// IEEE 802.1AX-2020, Section 6.5.3.3 c).
const TLV_TYPE_MARKER_INFORMATION: u8 = 0x01;

/// TLV_type value for Marker Response Information.
/// IEEE 802.1AX-2020, Section 6.5.3.3 c).
const TLV_TYPE_MARKER_RESPONSE_INFORMATION: u8 = 0x02;

/// TLV_type value for the Terminator TLV.
/// IEEE 802.1AX-2020, Section 6.5.3.3, Figure 6-19.
const TLV_TYPE_TERMINATOR: u8 = 0x00;

/// Returns a human-readable name for a Marker PDU TLV_type value.
///
/// IEEE 802.1AX-2020, Section 6.5.3.3 c).
fn tlv_type_name(v: u8) -> Option<&'static str> {
    match v {
        TLV_TYPE_TERMINATOR => Some("Terminator"),
        TLV_TYPE_MARKER_INFORMATION => Some("Marker Information"),
        TLV_TYPE_MARKER_RESPONSE_INFORMATION => Some("Marker Response Information"),
        _ => None,
    }
}

const FD_SUBTYPE: usize = 0;
const FD_VERSION: usize = 1;
const FD_TLV_TYPE: usize = 2;
const FD_TLV_LENGTH: usize = 3;
const FD_REQUESTER_PORT: usize = 4;
const FD_REQUESTER_SYSTEM: usize = 5;
const FD_REQUESTER_TRANSACTION_ID: usize = 6;
const FD_PAD: usize = 7;
const FD_TERMINATOR_TLV_TYPE: usize = 8;
const FD_TERMINATOR_TLV_LENGTH: usize = 9;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("subtype", "Subtype", FieldType::U8),
    FieldDescriptor::new("version", "Version Number", FieldType::U8),
    FieldDescriptor::new("tlv_type", "TLV Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => tlv_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("tlv_length", "Information Length", FieldType::U8),
    FieldDescriptor::new("requester_port", "Requester Port", FieldType::U16),
    FieldDescriptor::new("requester_system", "Requester System", FieldType::MacAddr),
    FieldDescriptor::new(
        "requester_transaction_id",
        "Requester Transaction ID",
        FieldType::U32,
    ),
    FieldDescriptor::new("pad", "Pad", FieldType::U16),
    FieldDescriptor::new("terminator_tlv_type", "Terminator TLV Type", FieldType::U8)
        .with_display_fn(|v, _| match v {
            FieldValue::U8(t) => tlv_type_name(*t),
            _ => None,
        }),
    FieldDescriptor::new("terminator_tlv_length", "Terminator Length", FieldType::U8),
];

/// Link Aggregation Marker protocol dissector (Slow Protocols subtype 0x02).
pub struct MarkerDissector;

impl Dissector for MarkerDissector {
    fn name(&self) -> &'static str {
        "Link Aggregation Marker Protocol"
    }

    fn short_name(&self) -> &'static str {
        "Marker"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Link)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < MARKER_INFO_SIZE {
            return Err(PacketError::Truncated {
                expected: MARKER_INFO_SIZE,
                actual: data.len(),
            });
        }

        // IEEE 802.1AX-2020, Section 6.5.3.3 a) — Subtype
        if data[0] != SUBTYPE_MARKER {
            return Err(PacketError::InvalidHeader(
                "Slow Protocol subtype is not Marker",
            ));
        }

        // The Reserved field pads the PDU to 110 octets. Consume it when it
        // was captured, but do not require it: only the first 20 octets carry
        // information.
        let consumed = data.len().min(MARKER_PDU_SIZE);

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + consumed,
        );

        // IEEE 802.1AX-2020, Section 6.5.3.3 a)-b) — Subtype, Version number
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SUBTYPE],
            FieldValue::U8(data[0]),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(data[1]),
            offset + 1..offset + 2,
        );
        // IEEE 802.1AX-2020, Section 6.5.3.3 c)-d) — TLV_Type, Length
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TLV_TYPE],
            FieldValue::U8(data[2]),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TLV_LENGTH],
            FieldValue::U8(data[3]),
            offset + 3..offset + 4,
        );
        // IEEE 802.1AX-2020, Section 6.5.3.3 e) — Requester_Port
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_REQUESTER_PORT],
            FieldValue::U16(read_be_u16(data, 4)?),
            offset + 4..offset + 6,
        );
        // IEEE 802.1AX-2020, Section 6.5.3.3 f) — Requester_System
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_REQUESTER_SYSTEM],
            FieldValue::MacAddr(MacAddr([
                data[6], data[7], data[8], data[9], data[10], data[11],
            ])),
            offset + 6..offset + 12,
        );
        // IEEE 802.1AX-2020, Section 6.5.3.3, Figure 6-19 — Requester_Transaction_ID
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_REQUESTER_TRANSACTION_ID],
            FieldValue::U32(read_be_u32(data, 12)?),
            offset + 12..offset + 16,
        );
        // IEEE 802.1AX-2020, Section 6.5.3.3, Figure 6-19 — Pad = 0
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PAD],
            FieldValue::U16(read_be_u16(data, 16)?),
            offset + 16..offset + 18,
        );
        // IEEE 802.1AX-2020, Section 6.5.3.3, Figure 6-19 — Terminator TLV
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TERMINATOR_TLV_TYPE],
            FieldValue::U8(data[18]),
            offset + 18..offset + 19,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TERMINATOR_TLV_LENGTH],
            FieldValue::U8(data[19]),
            offset + 19..offset + 20,
        );

        buf.end_layer();

        Ok(DissectResult::new(consumed, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    //! # IEEE 802.1AX-2020 Marker Protocol Coverage
    //!
    //! | Section | Description                         | Test                           |
    //! |---------|-------------------------------------|--------------------------------|
    //! | 6.5.3.3 | Marker PDU structure                | parse_marker_pdu               |
    //! | 6.5.3.3 | Marker Response PDU (TLV_type 0x02) | parse_marker_response_pdu      |
    //! | 6.5.3.3 | Reserved field not captured         | parse_marker_without_reserved  |
    //! | 6.5.3.3 | Truncated before Terminator         | parse_marker_truncated         |
    //! | 6.5.3.3 | Subtype other than Marker           | parse_marker_invalid_subtype   |

    use super::*;

    /// Build a Marker PDU (IEEE 802.1AX-2020, Section 6.5.3.3, Figure 6-19).
    fn build_marker(tlv_type: u8) -> Vec<u8> {
        let mut pdu = vec![0u8; MARKER_PDU_SIZE];
        pdu[0] = SUBTYPE_MARKER;
        pdu[1] = 0x01;
        pdu[2] = tlv_type;
        pdu[3] = 0x10;
        pdu[4..6].copy_from_slice(&[0x00, 0x07]);
        pdu[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pdu[12..16].copy_from_slice(&[0x00, 0x00, 0x01, 0x02]);
        pdu
    }

    fn field<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> &'a FieldValue<'a> {
        let layer = buf.layer_by_name("Marker").expect("Marker layer");
        &buf.field_by_name(layer, name).expect(name).value
    }

    #[test]
    fn parse_marker_pdu() {
        let data = build_marker(TLV_TYPE_MARKER_INFORMATION);
        let mut buf = DissectBuffer::new();
        let r = MarkerDissector.dissect(&data, &mut buf, 14).unwrap();

        assert_eq!(r.bytes_consumed, MARKER_PDU_SIZE);
        assert_eq!(r.next, DispatchHint::End);
        let layer = buf.layer_by_name("Marker").unwrap();
        assert_eq!(layer.range, 14..14 + MARKER_PDU_SIZE);
        assert_eq!(*field(&buf, "subtype"), FieldValue::U8(2));
        assert_eq!(*field(&buf, "version"), FieldValue::U8(1));
        assert_eq!(*field(&buf, "tlv_type"), FieldValue::U8(1));
        assert_eq!(
            buf.resolve_display_name(layer, "tlv_type_name"),
            Some("Marker Information")
        );
        assert_eq!(*field(&buf, "tlv_length"), FieldValue::U8(16));
        assert_eq!(*field(&buf, "requester_port"), FieldValue::U16(7));
        assert_eq!(
            *field(&buf, "requester_system"),
            FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
        assert_eq!(
            *field(&buf, "requester_transaction_id"),
            FieldValue::U32(0x0102)
        );
        assert_eq!(*field(&buf, "pad"), FieldValue::U16(0));
        assert_eq!(*field(&buf, "terminator_tlv_type"), FieldValue::U8(0));
        assert_eq!(*field(&buf, "terminator_tlv_length"), FieldValue::U8(0));
        assert_eq!(
            buf.field_by_name(layer, "requester_transaction_id")
                .unwrap()
                .range,
            26..30
        );
    }

    #[test]
    fn parse_marker_response_pdu() {
        let data = build_marker(TLV_TYPE_MARKER_RESPONSE_INFORMATION);
        let mut buf = DissectBuffer::new();
        MarkerDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("Marker").unwrap();
        assert_eq!(*field(&buf, "tlv_type"), FieldValue::U8(2));
        assert_eq!(
            buf.resolve_display_name(layer, "tlv_type_name"),
            Some("Marker Response Information")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "terminator_tlv_type_name"),
            Some("Terminator")
        );
        assert_eq!(tlv_type_name(0x7F), None);
    }

    #[test]
    fn parse_marker_without_reserved() {
        let data = build_marker(TLV_TYPE_MARKER_INFORMATION);
        let mut buf = DissectBuffer::new();
        let r = MarkerDissector
            .dissect(&data[..MARKER_INFO_SIZE], &mut buf, 0)
            .unwrap();
        assert_eq!(r.bytes_consumed, MARKER_INFO_SIZE);
    }

    #[test]
    fn parse_marker_truncated() {
        let data = build_marker(TLV_TYPE_MARKER_INFORMATION);
        let mut buf = DissectBuffer::new();
        let err = MarkerDissector
            .dissect(&data[..MARKER_INFO_SIZE - 1], &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: MARKER_INFO_SIZE,
                actual: MARKER_INFO_SIZE - 1
            }
        );
    }

    #[test]
    fn parse_marker_invalid_subtype() {
        let mut data = build_marker(TLV_TYPE_MARKER_INFORMATION);
        data[0] = 0x01;
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            MarkerDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn marker_metadata() {
        assert_eq!(MarkerDissector.short_name(), "Marker");
        assert!(!MarkerDissector.name().is_empty());
        assert_eq!(MarkerDissector.field_descriptors().len(), 10);
        assert!(!MarkerDissector.references().is_empty());
        assert_eq!(MarkerDissector.layer(), Some(ProtocolLayer::Link));
    }
}
