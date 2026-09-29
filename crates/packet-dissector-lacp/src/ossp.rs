//! Organization Specific Slow Protocol (OSSP) and ESMC dissectors.
//!
//! OSSP frames are IEEE 802.3 Slow Protocols frames (EtherType 0x8809) with
//! subtype 0x0A; the first three octets after the subtype are an OUI that
//! identifies the organization defining the rest of the PDU. The ITU-T OUI
//! 00-19-A7 carries the Ethernet Synchronization Messaging Channel (ESMC)
//! used by Synchronous Ethernet.
//!
//! ## References
//! - IEEE 802.3-2022, Annex 57B (Organization Specific Slow Protocol):
//!   <https://standards.ieee.org/ieee/802.3/10422/>
//! - ITU-T G.8264 (11/2025), Section 11.3.1 (ESMC format):
//!   <https://www.itu.int/rec/T-REC-G.8264>
//! - ITU-T G.781 (01/2026), Section 6.5.1.1 (QL TLV) and 6.5.1.2 (Extended
//!   QL TLV): <https://www.itu.int/rec/T-REC-G.781>

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

use crate::tlv;

/// Slow Protocols subtype for OSSP (IEEE 802.3-2022, Annex 57B;
/// ITU-T G.8264, Table 11-2).
pub(crate) const SUBTYPE_OSSP: u8 = 0x0A;

/// ITU-T OUI assigned for ESMC (ITU-T G.8264, Table 11-2).
pub(crate) const OUI_ITU_T: [u8; 3] = [0x00, 0x19, 0xA7];

/// Subtype (1) + OUI (3) — IEEE 802.3-2022, Annex 57B.
const OSSP_HEADER_SIZE: usize = 4;

/// ESMC header: subtype (1), ITU-OUI (3), ITU subtype (2),
/// version/event flag (1), reserved (3) — ITU-T G.8264, Table 11-3.
pub(crate) const ESMC_HEADER_SIZE: usize = 10;

/// ITU subtype for all usage defined in ITU-T G.8264 (Section 11.3.1.1 f).
const ITU_SUBTYPE_ESMC: u16 = 0x0001;

/// TLV header: type (1) + length (2) — ITU-T G.8264, Table 11-4.
const TLV_HEADER_SIZE: usize = 3;

/// QL TLV type and length (ITU-T G.781, Section 6.5.1.1, Table 6-4).
const TLV_TYPE_QL: u8 = 0x01;
const QL_TLV_LENGTH: usize = 4;

/// Extended QL TLV type and length (ITU-T G.781, Section 6.5.1.2, Table 6-5).
const TLV_TYPE_EXTENDED_QL: u8 = 0x02;
const EXTENDED_QL_TLV_LENGTH: usize = 20;

/// Returns the name of an ESMC TLV type.
fn tlv_type_name(v: u8) -> Option<&'static str> {
    match v {
        TLV_TYPE_QL => Some("QL TLV"),
        TLV_TYPE_EXTENDED_QL => Some("Extended QL TLV"),
        _ => None,
    }
}

/// Returns the quality level of an Enhanced SSM code
/// (ITU-T G.781, Section 6.5.1.2, Table 6-6).
fn enhanced_ssm_code_name(v: u8) -> Option<&'static str> {
    match v {
        0xFF => Some("QL message (refer to the QL TLV)"),
        0x20 => Some("QL-PRTC"),
        0x21 => Some("QL-ePRTC"),
        0x22 => Some("QL-eSEC"),
        0x23 => Some("QL-ePRC"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// OSSP (any OUI other than ITU-T)
// ---------------------------------------------------------------------------

static OSSP_REFERENCES: &[SpecReference] = &[SpecReference::new(
    "IEEE 802.3",
    "IEEE Standard for Ethernet, Annex 57B (Organization Specific Slow \
     Protocol) (IEEE 802.3-2022)",
    "https://standards.ieee.org/ieee/802.3/10422/",
)];

const FD_OSSP_SUBTYPE: usize = 0;
const FD_OSSP_OUI: usize = 1;
const FD_OSSP_DATA: usize = 2;

static OSSP_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("subtype", "Subtype", FieldType::U8),
    FieldDescriptor::new("oui", "OUI", FieldType::Bytes),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
];

/// Organization Specific Slow Protocol dissector (Slow Protocols subtype
/// 0x0A) for OUIs without a dedicated decoder.
pub struct OsspDissector;

impl Dissector for OsspDissector {
    fn name(&self) -> &'static str {
        "Organization Specific Slow Protocol"
    }

    fn short_name(&self) -> &'static str {
        "OSSP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        OSSP_FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        OSSP_REFERENCES
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
        check_ossp_header(data, OSSP_HEADER_SIZE)?;

        buf.begin_layer(
            self.short_name(),
            None,
            OSSP_FIELD_DESCRIPTORS,
            offset..offset + data.len(),
        );
        buf.push_field(
            &OSSP_FIELD_DESCRIPTORS[FD_OSSP_SUBTYPE],
            FieldValue::U8(data[0]),
            offset..offset + 1,
        );
        // IEEE 802.3-2022, Annex 57B — OUI
        buf.push_field(
            &OSSP_FIELD_DESCRIPTORS[FD_OSSP_OUI],
            FieldValue::Bytes(&data[1..4]),
            offset + 1..offset + 4,
        );
        if data.len() > OSSP_HEADER_SIZE {
            buf.push_field(
                &OSSP_FIELD_DESCRIPTORS[FD_OSSP_DATA],
                FieldValue::Bytes(&data[OSSP_HEADER_SIZE..]),
                offset + OSSP_HEADER_SIZE..offset + data.len(),
            );
        }
        buf.end_layer();

        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

/// Validate the length and subtype of an OSSP PDU.
fn check_ossp_header(data: &[u8], min: usize) -> Result<(), PacketError> {
    if data.len() < min {
        return Err(PacketError::Truncated {
            expected: min,
            actual: data.len(),
        });
    }
    if data[0] != SUBTYPE_OSSP {
        return Err(PacketError::InvalidHeader(
            "Slow Protocol subtype is not OSSP",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ESMC (ITU-T OUI 00-19-A7)
// ---------------------------------------------------------------------------

static ESMC_REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "ITU-T G.8264",
        "Distribution of timing information through packet networks, \
         Section 11.3.1 (ESMC format)",
        "https://www.itu.int/rec/T-REC-G.8264",
    ),
    SpecReference::new(
        "ITU-T G.781",
        "Synchronization layer functions for frequency synchronization based \
         on the physical layer, Section 6.5.1 (QL TLV formats)",
        "https://www.itu.int/rec/T-REC-G.781",
    ),
];

const FD_ESMC_SUBTYPE: usize = 0;
const FD_ESMC_OUI: usize = 1;
const FD_ESMC_ITU_SUBTYPE: usize = 2;
const FD_ESMC_VERSION: usize = 3;
const FD_ESMC_EVENT_FLAG: usize = 4;
const FD_ESMC_TLVS: usize = 5;
const FD_ESMC_DATA: usize = 6;

static ESMC_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("subtype", "Subtype", FieldType::U8),
    FieldDescriptor::new("oui", "ITU-OUI", FieldType::Bytes),
    FieldDescriptor::new("itu_subtype", "ITU Subtype", FieldType::U16),
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("event_flag", "Event Flag", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(0) => Some("Information PDU"),
            FieldValue::U8(1) => Some("Event PDU"),
            _ => None,
        },
    ),
    FieldDescriptor::new("tlvs", "TLVs", FieldType::Array)
        .optional()
        .with_children(ESMC_TLV_CHILD_FIELDS),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
];

const FD_TLV_TYPE: usize = 0;
const FD_TLV_LENGTH: usize = 1;
const FD_TLV_SSM_CODE: usize = 2;
const FD_TLV_ENHANCED_SSM_CODE: usize = 3;
const FD_TLV_CLOCK_IDENTITY: usize = 4;
const FD_TLV_FLAGS: usize = 5;
const FD_TLV_MIXED_EEC: usize = 6;
const FD_TLV_PARTIAL_CHAIN: usize = 7;
const FD_TLV_CASCADED_EEECS: usize = 8;
const FD_TLV_CASCADED_EECS: usize = 9;
const FD_TLV_VALUE: usize = 10;

/// Container descriptor for one ESMC TLV; labelled by its type.
static FD_ESMC_TLV: FieldDescriptor = FieldDescriptor {
    name: "tlv",
    display_name: "TLV",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => tlv_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

static ESMC_TLV_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => tlv_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U16).optional(),
    FieldDescriptor::new("ssm_code", "SSM Code", FieldType::U8).optional(),
    FieldDescriptor::new("enhanced_ssm_code", "Enhanced SSM Code", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(c) => enhanced_ssm_code_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("clock_identity", "clockIdentity", FieldType::Bytes).optional(),
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("mixed_eec", "Mixed EEC/eEEC", FieldType::U8).optional(),
    FieldDescriptor::new("partial_chain", "Partial Chain", FieldType::U8).optional(),
    FieldDescriptor::new("cascaded_eeecs", "Number of Cascaded eEECs", FieldType::U8).optional(),
    FieldDescriptor::new("cascaded_eecs", "Number of Cascaded EECs", FieldType::U8).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// ESMC (Synchronous Ethernet SSM) dissector: OSSP with ITU-T OUI 00-19-A7.
pub struct EsmcDissector;

impl Dissector for EsmcDissector {
    fn name(&self) -> &'static str {
        "Ethernet Synchronization Messaging Channel"
    }

    fn short_name(&self) -> &'static str {
        "ESMC"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        ESMC_FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        ESMC_REFERENCES
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
        check_ossp_header(data, ESMC_HEADER_SIZE)?;
        if data[1..4] != OUI_ITU_T {
            return Err(PacketError::InvalidHeader("OSSP OUI is not ITU-T"));
        }

        let itu_subtype = read_be_u16(data, 4)?;

        buf.begin_layer(
            self.short_name(),
            None,
            ESMC_FIELD_DESCRIPTORS,
            offset..offset + data.len(),
        );
        // ITU-T G.8264, Section 11.3.1.1 d)-f), Table 11-3
        buf.push_field(
            &ESMC_FIELD_DESCRIPTORS[FD_ESMC_SUBTYPE],
            FieldValue::U8(data[0]),
            offset..offset + 1,
        );
        buf.push_field(
            &ESMC_FIELD_DESCRIPTORS[FD_ESMC_OUI],
            FieldValue::Bytes(&data[1..4]),
            offset + 1..offset + 4,
        );
        buf.push_field(
            &ESMC_FIELD_DESCRIPTORS[FD_ESMC_ITU_SUBTYPE],
            FieldValue::U16(itu_subtype),
            offset + 4..offset + 6,
        );
        // ITU-T G.8264, Table 11-3 — bits 7:4 Version, bit 3 Event flag,
        // bits 2:0 and the next 3 octets reserved.
        buf.push_field(
            &ESMC_FIELD_DESCRIPTORS[FD_ESMC_VERSION],
            FieldValue::U8(data[6] >> 4),
            offset + 6..offset + 7,
        );
        buf.push_field(
            &ESMC_FIELD_DESCRIPTORS[FD_ESMC_EVENT_FLAG],
            FieldValue::U8((data[6] >> 3) & 1),
            offset + 6..offset + 7,
        );

        let body = &data[ESMC_HEADER_SIZE..];
        let body_offset = offset + ESMC_HEADER_SIZE;
        if itu_subtype == ITU_SUBTYPE_ESMC {
            push_esmc_tlvs(buf, body, body_offset);
        } else if !body.is_empty() {
            // Only ITU subtype 00-01 is defined (ITU-T G.8264, 11.3.1.1 f).
            buf.push_field(
                &ESMC_FIELD_DESCRIPTORS[FD_ESMC_DATA],
                FieldValue::Bytes(body),
                body_offset..body_offset + body.len(),
            );
        }
        buf.end_layer();

        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

/// Decode the TLVs in the ESMC Data and padding field.
///
/// ITU-T G.781, Section 6.5.1.1 — "All additional TLVs (e.g., the extended
/// QL TLV) must occur after the QL TLV and with no padding between TLVs.
/// Any padding must occur after the last TLV." Padding is all-zero
/// (ITU-T G.8264, 11.3.1.1 j), so a zero type octet ends the walk. The length
/// covers the whole TLV including type and length (ITU-T G.8264, Table 11-4).
fn push_esmc_tlvs<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], offset: usize) {
    let array_idx = buf.begin_container(
        &ESMC_FIELD_DESCRIPTORS[FD_ESMC_TLVS],
        FieldValue::Array(0..0),
        offset..offset,
    );
    let mut pos = 0;
    while pos < body.len() && body[pos] != 0 {
        let rest = &body[pos..];
        let declared = rest
            .get(1..TLV_HEADER_SIZE)
            .map(|l| u16::from_be_bytes([l[0], l[1]]) as usize);
        let split = tlv::split_tlv(rest, TLV_HEADER_SIZE, declared);
        let tlv = &rest[..split.len];
        let base = offset + pos;

        let obj_idx = buf.begin_container(
            &FD_ESMC_TLV,
            FieldValue::Object(0..0),
            base..base + split.len,
        );
        buf.push_field(
            &ESMC_TLV_CHILD_FIELDS[FD_TLV_TYPE],
            FieldValue::U8(tlv[0]),
            base..base + 1,
        );
        if let Some(l) = split.declared {
            buf.push_field(
                &ESMC_TLV_CHILD_FIELDS[FD_TLV_LENGTH],
                FieldValue::U16(l as u16),
                base + 1..base + 3,
            );
        }

        let fits = |expected: usize| split.well_formed && split.len == expected;
        match tlv[0] {
            // ITU-T G.781, Table 6-4 — bits 3:0 of octet 4 carry the SSM code.
            TLV_TYPE_QL if fits(QL_TLV_LENGTH) => {
                buf.push_field(
                    &ESMC_TLV_CHILD_FIELDS[FD_TLV_SSM_CODE],
                    FieldValue::U8(tlv[3] & 0x0F),
                    base + 3..base + 4,
                );
            }
            // ITU-T G.781, Table 6-5 — Extended QL TLV.
            TLV_TYPE_EXTENDED_QL if fits(EXTENDED_QL_TLV_LENGTH) => {
                push_extended_ql(buf, tlv, base);
            }
            _ => tlv::push_raw_value(
                buf,
                &ESMC_TLV_CHILD_FIELDS[FD_TLV_VALUE],
                tlv,
                TLV_HEADER_SIZE,
                base,
            ),
        }
        buf.end_container(obj_idx);

        pos += split.len;
        if !split.well_formed {
            break;
        }
    }
    tlv::end_tlv_array(buf, array_idx, offset..offset + pos);
}

/// Decode an Extended QL TLV (ITU-T G.781, Section 6.5.1.2, Table 6-5).
fn push_extended_ql<'pkt>(buf: &mut DissectBuffer<'pkt>, tlv: &'pkt [u8], base: usize) {
    let flags = tlv[12];
    buf.push_field(
        &ESMC_TLV_CHILD_FIELDS[FD_TLV_ENHANCED_SSM_CODE],
        FieldValue::U8(tlv[3]),
        base + 3..base + 4,
    );
    buf.push_field(
        &ESMC_TLV_CHILD_FIELDS[FD_TLV_CLOCK_IDENTITY],
        FieldValue::Bytes(&tlv[4..12]),
        base + 4..base + 12,
    );
    // Table 6-5, Note 2 — bit 0 mixed SEC/eSEC, bit 1 partial chain.
    buf.push_field(
        &ESMC_TLV_CHILD_FIELDS[FD_TLV_FLAGS],
        FieldValue::U8(flags),
        base + 12..base + 13,
    );
    buf.push_field(
        &ESMC_TLV_CHILD_FIELDS[FD_TLV_MIXED_EEC],
        FieldValue::U8(flags & 1),
        base + 12..base + 13,
    );
    buf.push_field(
        &ESMC_TLV_CHILD_FIELDS[FD_TLV_PARTIAL_CHAIN],
        FieldValue::U8((flags >> 1) & 1),
        base + 12..base + 13,
    );
    buf.push_field(
        &ESMC_TLV_CHILD_FIELDS[FD_TLV_CASCADED_EEECS],
        FieldValue::U8(tlv[13]),
        base + 13..base + 14,
    );
    buf.push_field(
        &ESMC_TLV_CHILD_FIELDS[FD_TLV_CASCADED_EECS],
        FieldValue::U8(tlv[14]),
        base + 14..base + 15,
    );
}

#[cfg(test)]
mod tests {
    //! # OSSP / ESMC Coverage
    //!
    //! | Spec section                  | Description                        | Test                         |
    //! |-------------------------------|------------------------------------|------------------------------|
    //! | IEEE 802.3 Annex 57B          | OSSP subtype + OUI + data          | parse_ossp_other_oui         |
    //! | IEEE 802.3 Annex 57B          | OSSP truncated / wrong subtype     | parse_ossp_errors            |
    //! | G.8264 11.3.1.1, Table 11-3   | ESMC header, version, event flag   | parse_esmc_information_pdu   |
    //! | G.781 6.5.1.1, Table 6-4      | QL TLV                             | parse_esmc_information_pdu   |
    //! | G.781 6.5.1.2, Table 6-5      | Extended QL TLV                    | parse_esmc_extended_ql       |
    //! | G.8264 Table 11-4             | Unknown / malformed TLV            | parse_esmc_unknown_and_malformed_tlv |
    //! | G.8264 11.3.1.1 f)            | ITU subtype other than 00-01       | parse_esmc_other_itu_subtype |
    //! | G.8264 Table 11-2             | Non-ITU OUI / truncated header     | parse_esmc_errors            |

    use super::*;
    use packet_dissector_core::field::Field;

    fn esmc_header(event: bool) -> Vec<u8> {
        vec![
            SUBTYPE_OSSP,
            0x00,
            0x19,
            0xA7,
            0x00,
            0x01,
            0x10 | if event { 0x08 } else { 0 },
            0x00,
            0x00,
            0x00,
        ]
    }

    fn layer_field<'a>(buf: &'a DissectBuffer<'_>, layer: &str, name: &str) -> &'a FieldValue<'a> {
        let l = buf.layer_by_name(layer).expect(layer);
        &buf.field_by_name(l, name).expect(name).value
    }

    fn tlvs<'a>(buf: &'a DissectBuffer<'_>) -> Vec<&'a [Field<'a>]> {
        let FieldValue::Array(r) = layer_field(buf, "ESMC", "tlvs") else {
            panic!("tlvs")
        };
        buf.nested_fields(r)
            .iter()
            .filter_map(|f| match &f.value {
                FieldValue::Object(o) => Some(buf.nested_fields(o)),
                _ => None,
            })
            .collect()
    }

    fn child<'a>(fields: &'a [Field<'a>], name: &str) -> &'a FieldValue<'a> {
        &fields.iter().find(|f| f.name() == name).expect(name).value
    }

    #[test]
    fn parse_esmc_information_pdu() {
        let mut data = esmc_header(false);
        data.extend_from_slice(&[0x01, 0x00, 0x04, 0x0B]); // QL TLV, QL-SEC
        data.resize(ESMC_HEADER_SIZE + 36, 0);
        let mut buf = DissectBuffer::new();
        let r = EsmcDissector.dissect(&data, &mut buf, 14).unwrap();
        assert_eq!(r.bytes_consumed, data.len());
        assert_eq!(r.next, DispatchHint::End);

        let layer = buf.layer_by_name("ESMC").unwrap();
        assert_eq!(layer.range, 14..14 + data.len());
        assert_eq!(*layer_field(&buf, "ESMC", "subtype"), FieldValue::U8(0x0A));
        assert_eq!(
            *layer_field(&buf, "ESMC", "oui"),
            FieldValue::Bytes(&[0x00, 0x19, 0xA7])
        );
        assert_eq!(
            *layer_field(&buf, "ESMC", "itu_subtype"),
            FieldValue::U16(1)
        );
        assert_eq!(*layer_field(&buf, "ESMC", "version"), FieldValue::U8(1));
        assert_eq!(*layer_field(&buf, "ESMC", "event_flag"), FieldValue::U8(0));
        assert_eq!(
            buf.resolve_display_name(layer, "event_flag_name"),
            Some("Information PDU")
        );

        let t = tlvs(&buf);
        assert_eq!(t.len(), 1);
        assert_eq!(*child(t[0], "type"), FieldValue::U8(1));
        assert_eq!(*child(t[0], "length"), FieldValue::U16(4));
        assert_eq!(*child(t[0], "ssm_code"), FieldValue::U8(0x0B));
        let FieldValue::Array(r) = layer_field(&buf, "ESMC", "tlvs") else {
            unreachable!()
        };
        assert_eq!(buf.resolve_container_display_name(r.start), Some("QL TLV"));
        let arr = buf.field_by_name(layer, "tlvs").unwrap();
        assert_eq!(arr.range, 24..28);
    }

    #[test]
    fn parse_esmc_extended_ql() {
        let mut data = esmc_header(true);
        data.extend_from_slice(&[0x01, 0x00, 0x04, 0x0F]);
        data.extend_from_slice(&[
            0x02, 0x00, 0x14, // Extended QL TLV, length 20
            0x22, // QL-eSEC
            0x00, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55, // clockIdentity
            0x03, // mixed + partial chain
            0x05, 0x02, // cascaded eEECs / EECs
            0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        let mut buf = DissectBuffer::new();
        EsmcDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ESMC").unwrap();
        assert_eq!(*layer_field(&buf, "ESMC", "event_flag"), FieldValue::U8(1));
        assert_eq!(
            buf.resolve_display_name(layer, "event_flag_name"),
            Some("Event PDU")
        );
        let t = tlvs(&buf);
        assert_eq!(t.len(), 2);
        assert_eq!(*child(t[1], "type"), FieldValue::U8(2));
        assert_eq!(*child(t[1], "length"), FieldValue::U16(20));
        assert_eq!(*child(t[1], "enhanced_ssm_code"), FieldValue::U8(0x22));
        assert_eq!(
            *child(t[1], "clock_identity"),
            FieldValue::Bytes(&[0x00, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55])
        );
        assert_eq!(*child(t[1], "flags"), FieldValue::U8(3));
        assert_eq!(*child(t[1], "mixed_eec"), FieldValue::U8(1));
        assert_eq!(*child(t[1], "partial_chain"), FieldValue::U8(1));
        assert_eq!(*child(t[1], "cascaded_eeecs"), FieldValue::U8(5));
        assert_eq!(*child(t[1], "cascaded_eecs"), FieldValue::U8(2));
        let FieldValue::Array(r) = layer_field(&buf, "ESMC", "tlvs") else {
            unreachable!()
        };
        let ext_idx = buf
            .nested_fields(r)
            .iter()
            .enumerate()
            .filter(|(_, f)| f.value.is_object())
            .nth(1)
            .map(|(i, _)| r.start + i as u32)
            .unwrap();
        assert_eq!(
            buf.resolve_container_display_name(ext_idx),
            Some("Extended QL TLV")
        );
        assert_eq!(enhanced_ssm_code_name(0x22), Some("QL-eSEC"));
        for (c, n) in [
            (0xFF, "QL message (refer to the QL TLV)"),
            (0x20, "QL-PRTC"),
            (0x21, "QL-ePRTC"),
            (0x23, "QL-ePRC"),
        ] {
            assert_eq!(enhanced_ssm_code_name(c), Some(n));
        }
        assert_eq!(enhanced_ssm_code_name(0x24), None);
    }

    #[test]
    fn parse_esmc_unknown_and_malformed_tlv() {
        let mut data = esmc_header(false);
        data.extend_from_slice(&[0x01, 0x00, 0x04, 0x0B]);
        data.extend_from_slice(&[0x7E, 0x00, 0x05, 0xAA, 0xBB]); // unknown
        data.extend_from_slice(&[0x01, 0x00, 0x05, 0x0B, 0x00]); // QL, bad length
        data.extend_from_slice(&[0x7F, 0x00, 0x03]); // header-only unknown
        data.extend_from_slice(&[0x02, 0x00, 0x30, 0x01]); // runs past the PDU
        let mut buf = DissectBuffer::new();
        EsmcDissector.dissect(&data, &mut buf, 0).unwrap();
        let t = tlvs(&buf);
        assert_eq!(t.len(), 5);
        assert_eq!(*child(t[1], "value"), FieldValue::Bytes(&[0xAA, 0xBB]));
        assert_eq!(*child(t[2], "value"), FieldValue::Bytes(&[0x0B, 0x00]));
        assert!(t[2].iter().all(|f| f.name() != "ssm_code"));
        assert!(t[3].iter().all(|f| f.name() != "value"));
        assert_eq!(*child(t[4], "length"), FieldValue::U16(0x30));
        assert_eq!(*child(t[4], "value"), FieldValue::Bytes(&[0x01]));
        assert_eq!(tlv_type_name(0x7E), None);

        // Trailing octets too short for a TLV header.
        let mut data = esmc_header(false);
        data.extend_from_slice(&[0x01, 0x00]);
        let mut buf = DissectBuffer::new();
        EsmcDissector.dissect(&data, &mut buf, 0).unwrap();
        let t = tlvs(&buf);
        assert_eq!(t.len(), 1);
        assert!(t[0].iter().all(|f| f.name() != "length"));
        assert!(t[0].iter().all(|f| f.name() != "value"));

        // Header-only ESMC PDU: no TLV list.
        let data = esmc_header(false);
        let mut buf = DissectBuffer::new();
        EsmcDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ESMC").unwrap();
        assert!(buf.field_by_name(layer, "tlvs").is_none());
    }

    #[test]
    fn parse_esmc_other_itu_subtype() {
        let mut data = esmc_header(false);
        data[5] = 0x02;
        data.extend_from_slice(&[0x01, 0x00, 0x04, 0x0B]);
        let mut buf = DissectBuffer::new();
        EsmcDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ESMC").unwrap();
        assert!(buf.field_by_name(layer, "tlvs").is_none());
        assert_eq!(
            *layer_field(&buf, "ESMC", "data"),
            FieldValue::Bytes(&[0x01, 0x00, 0x04, 0x0B])
        );

        let mut data = esmc_header(false);
        data[5] = 0x02;
        let mut buf = DissectBuffer::new();
        EsmcDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ESMC").unwrap();
        assert!(buf.field_by_name(layer, "data").is_none());
    }

    #[test]
    fn parse_esmc_errors() {
        let mut buf = DissectBuffer::new();
        let data = esmc_header(false);
        assert_eq!(
            EsmcDissector.dissect(&data[..9], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 10,
                actual: 9
            })
        );
        let mut other = data.clone();
        other[3] = 0x00;
        assert!(matches!(
            EsmcDissector.dissect(&other, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
        let mut wrong_subtype = data.clone();
        wrong_subtype[0] = 0x03;
        assert!(matches!(
            EsmcDissector.dissect(&wrong_subtype, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn parse_ossp_other_oui() {
        let data = [SUBTYPE_OSSP, 0x00, 0x00, 0x0C, 0x01, 0x02, 0x03];
        let mut buf = DissectBuffer::new();
        let r = OsspDissector.dissect(&data, &mut buf, 14).unwrap();
        assert_eq!(r.bytes_consumed, data.len());
        let layer = buf.layer_by_name("OSSP").unwrap();
        assert_eq!(layer.range, 14..21);
        assert_eq!(
            *layer_field(&buf, "OSSP", "oui"),
            FieldValue::Bytes(&[0x00, 0x00, 0x0C])
        );
        let f = buf.field_by_name(layer, "data").unwrap();
        assert_eq!(f.value, FieldValue::Bytes(&[0x01, 0x02, 0x03]));
        assert_eq!(f.range, 18..21);

        let mut buf = DissectBuffer::new();
        OsspDissector.dissect(&data[..4], &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("OSSP").unwrap();
        assert!(buf.field_by_name(layer, "data").is_none());
    }

    #[test]
    fn parse_ossp_errors() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            OsspDissector.dissect(&[SUBTYPE_OSSP, 0, 0], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 4,
                actual: 3
            })
        );
        assert!(matches!(
            OsspDissector.dissect(&[0x01, 0, 0, 0], &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn metadata() {
        for d in [&OsspDissector as &dyn Dissector, &EsmcDissector] {
            assert!(!d.name().is_empty());
            assert!(!d.field_descriptors().is_empty());
            assert!(!d.references().is_empty());
            assert_eq!(d.layer(), Some(ProtocolLayer::Link));
        }
        assert_eq!(OsspDissector.short_name(), "OSSP");
        assert_eq!(EsmcDissector.short_name(), "ESMC");
    }
}
