//! Ethernet OAM (IEEE 802.3 Clause 57) OAMPDU dissector.
//!
//! Parses OAMPDUs carried inside IEEE 802.3 Slow Protocols frames
//! (EtherType 0x8809, subtype 0x03). The common header (flags and code) is
//! decoded for every OAMPDU; the Information TLVs of Information OAMPDUs
//! (code 0x00) are decoded, and the data of the other codes is kept raw.
//!
//! ## References
//! - IEEE 802.3-2022, Clause 57.4.2 (OAMPDU structure) and 57.5.2
//!   (Information OAMPDU TLVs): <https://standards.ieee.org/ieee/802.3/10422/>
//! - ITU-T G.781 (01/2026), Section 6.5.1.1 — restates the Clause 57.5.2.1
//!   TLV length convention: <https://www.itu.int/rec/T-REC-G.781>

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

use crate::tlv;

/// Specification references for the OAM dissector.
static REFERENCES: &[SpecReference] = &[SpecReference::new(
    "IEEE 802.3",
    "IEEE Standard for Ethernet, Clause 57 (Operations, Administration, and \
     Maintenance) (IEEE 802.3-2022)",
    "https://standards.ieee.org/ieee/802.3/10422/",
)];

/// Slow Protocols subtype for OAM (IEEE 802.3-2022, Clause 57.4.2).
pub(crate) const SUBTYPE_OAM: u8 = 0x03;

/// Subtype (1) + Flags (2) + Code (1) — IEEE 802.3-2022, Clause 57.4.2.
const OAMPDU_HEADER_SIZE: usize = 4;

/// Information OAMPDU code (IEEE 802.3-2022, Clause 57.4.2.2, Table 57-4).
const CODE_INFORMATION: u8 = 0x00;

/// End of TLV marker (IEEE 802.3-2022, Clause 57.5.2, Table 57-6).
const INFO_TYPE_END: u8 = 0x00;
/// Local Information TLV (IEEE 802.3-2022, Clause 57.5.2.1, Table 57-6).
const INFO_TYPE_LOCAL: u8 = 0x01;
/// Remote Information TLV (IEEE 802.3-2022, Clause 57.5.2.2, Table 57-6).
const INFO_TYPE_REMOTE: u8 = 0x02;
/// Organization Specific Information TLV (IEEE 802.3-2022, Clause 57.5.2.3).
const INFO_TYPE_ORG: u8 = 0xFE;

/// Info Length of the Local/Remote Information TLVs (IEEE 802.3-2022,
/// Clause 57.5.2.1). The length covers the whole TLV, including the type and
/// length octets (ITU-T G.781, Section 6.5.1.1).
const LOCAL_INFO_LENGTH: usize = 16;

/// Minimum TLV length: the type and length octets themselves.
const TLV_HEADER_SIZE: usize = 2;

/// Organization Specific Information TLV: type, length, and 3-octet OUI.
const ORG_TLV_MIN_LENGTH: usize = 5;

/// Returns the name of an OAMPDU code (IEEE 802.3-2022, Clause 57.4.2.2,
/// Table 57-4).
fn code_name(v: u8) -> Option<&'static str> {
    match v {
        0x00 => Some("Information"),
        0x01 => Some("Event Notification"),
        0x02 => Some("Variable Request"),
        0x03 => Some("Variable Response"),
        0x04 => Some("Loopback Control"),
        0xFE => Some("Organization Specific"),
        _ => None,
    }
}

/// Returns the name of an Information TLV type (IEEE 802.3-2022,
/// Clause 57.5.2, Table 57-6).
fn info_type_name(v: u8) -> Option<&'static str> {
    match v {
        INFO_TYPE_END => Some("End of TLV Marker"),
        INFO_TYPE_LOCAL => Some("Local Information"),
        INFO_TYPE_REMOTE => Some("Remote Information"),
        INFO_TYPE_ORG => Some("Organization Specific Information"),
        _ => None,
    }
}

/// Returns the name of the Parser Action (State field bits 1:0,
/// IEEE 802.3-2022, Clause 57.5.2.1).
fn parser_action_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Forward non-OAMPDUs to higher sublayer"),
        1 => Some("Loop back non-OAMPDUs to lower sublayer"),
        2 => Some("Discard non-OAMPDUs"),
        _ => None,
    }
}

/// Returns the name of the Multiplexer Action (State field bit 2,
/// IEEE 802.3-2022, Clause 57.5.2.1).
fn multiplexer_action_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Forward non-OAMPDUs to lower sublayer"),
        1 => Some("Discard non-OAMPDUs"),
        _ => None,
    }
}

const FD_SUBTYPE: usize = 0;
const FD_FLAGS: usize = 1;
/// Base index of the 7 flag bit descriptors (indices 2..=8).
const FD_FLAGS_BASE: usize = 2;
const FD_CODE: usize = 9;
const FD_TLVS: usize = 10;
const FD_DATA: usize = 11;

/// Number of defined bits in the OAMPDU Flags field
/// (IEEE 802.3-2022, Clause 57.4.2.1, Table 57-3); bits 15:7 are reserved.
const FLAG_BITS: usize = 7;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("subtype", "Subtype", FieldType::U8),
    FieldDescriptor::new("flags", "Flags", FieldType::U16),
    FieldDescriptor::new("flags_link_fault", "Link Fault", FieldType::U8),
    FieldDescriptor::new("flags_dying_gasp", "Dying Gasp", FieldType::U8),
    FieldDescriptor::new("flags_critical_event", "Critical Event", FieldType::U8),
    FieldDescriptor::new("flags_local_evaluating", "Local Evaluating", FieldType::U8),
    FieldDescriptor::new("flags_local_stable", "Local Stable", FieldType::U8),
    FieldDescriptor::new(
        "flags_remote_evaluating",
        "Remote Evaluating",
        FieldType::U8,
    ),
    FieldDescriptor::new("flags_remote_stable", "Remote Stable", FieldType::U8),
    FieldDescriptor::new("code", "Code", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(c) => code_name(*c),
        _ => None,
    }),
    FieldDescriptor::new("tlvs", "Information TLVs", FieldType::Array)
        .optional()
        .with_children(TLV_CHILD_FIELDS),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
];

const FD_TLV_TYPE: usize = 0;
const FD_TLV_LENGTH: usize = 1;
const FD_TLV_OAM_VERSION: usize = 2;
const FD_TLV_REVISION: usize = 3;
const FD_TLV_STATE: usize = 4;
const FD_TLV_PARSER_ACTION: usize = 5;
const FD_TLV_MULTIPLEXER_ACTION: usize = 6;
const FD_TLV_OAM_CONFIGURATION: usize = 7;
/// Base index of the 5 OAM Configuration bit descriptors (indices 8..=12).
const FD_TLV_OAM_CONFIGURATION_BASE: usize = 8;
const FD_TLV_OAMPDU_CONFIGURATION: usize = 13;
const FD_TLV_MAX_OAMPDU_SIZE: usize = 14;
const FD_TLV_OUI: usize = 15;
const FD_TLV_VENDOR_SPECIFIC_INFO: usize = 16;
const FD_TLV_VALUE: usize = 17;

/// Maximum OAMPDU Size occupies bits 10:0 of the OAMPDU Configuration
/// field; bits 15:11 are reserved (IEEE 802.3-2022, Clause 57.5.2.1).
const MAX_OAMPDU_SIZE_MASK: u16 = 0x07FF;

/// Number of defined bits in the OAM Configuration field
/// (IEEE 802.3-2022, Clause 57.5.2.1); bits 7:5 are reserved.
const OAM_CONFIGURATION_BITS: usize = 5;

/// Container descriptor for one Information TLV; labelled by its type.
static FD_TLV: FieldDescriptor = FieldDescriptor {
    name: "tlv",
    display_name: "Information TLV",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => info_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

static TLV_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Information Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => info_type_name(*t),
            _ => None,
        },
    ),
    FieldDescriptor::new("length", "Information Length", FieldType::U8).optional(),
    FieldDescriptor::new("oam_version", "OAM Version", FieldType::U8).optional(),
    FieldDescriptor::new("revision", "Revision", FieldType::U16).optional(),
    FieldDescriptor::new("state", "State", FieldType::U8).optional(),
    FieldDescriptor::new("parser_action", "Parser Action", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(a) => parser_action_name(*a),
            _ => None,
        }),
    FieldDescriptor::new("multiplexer_action", "Multiplexer Action", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(a) => multiplexer_action_name(*a),
            _ => None,
        }),
    FieldDescriptor::new("oam_configuration", "OAM Configuration", FieldType::U8).optional(),
    FieldDescriptor::new("oam_mode", "OAM Mode (Active)", FieldType::U8).optional(),
    FieldDescriptor::new(
        "unidirectional_support",
        "Unidirectional Support",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "remote_loopback_support",
        "OAM Remote Loopback Support",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "link_events",
        "Link Events Interpretation Support",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "variable_retrieval",
        "Variable Retrieval Support",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "oampdu_configuration",
        "OAMPDU Configuration",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("max_oampdu_size", "Maximum OAMPDU Size", FieldType::U16).optional(),
    FieldDescriptor::new("oui", "OUI", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "vendor_specific_info",
        "Vendor Specific Information",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// Ethernet OAM dissector (Slow Protocols subtype 0x03).
pub struct OamDissector;

impl Dissector for OamDissector {
    fn name(&self) -> &'static str {
        "Ethernet OAM Protocol"
    }

    fn short_name(&self) -> &'static str {
        "OAM"
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
        if data.len() < OAMPDU_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: OAMPDU_HEADER_SIZE,
                actual: data.len(),
            });
        }
        if data[0] != SUBTYPE_OAM {
            return Err(PacketError::InvalidHeader(
                "Slow Protocol subtype is not OAM",
            ));
        }

        let flags = read_be_u16(data, 1)?;
        let code = data[3];

        // The OAMPDU occupies the whole MAC client data field; the Data/Pad
        // field runs to its end (IEEE 802.3-2022, Clause 57.4.2).
        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + data.len(),
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SUBTYPE],
            FieldValue::U8(data[0]),
            offset..offset + 1,
        );
        // IEEE 802.3-2022, Clause 57.4.2.1 — Flags field
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAGS],
            FieldValue::U16(flags),
            offset + 1..offset + 3,
        );
        for bit in 0..FLAG_BITS {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FLAGS_BASE + bit],
                FieldValue::U8(((flags >> bit) & 1) as u8),
                offset + 1..offset + 3,
            );
        }
        // IEEE 802.3-2022, Clause 57.4.2.2 — Code field
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CODE],
            FieldValue::U8(code),
            offset + 3..offset + 4,
        );

        let body = &data[OAMPDU_HEADER_SIZE..];
        let body_offset = offset + OAMPDU_HEADER_SIZE;
        if code == CODE_INFORMATION {
            push_information_tlvs(buf, body, body_offset);
        } else if !body.is_empty() {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_DATA],
                FieldValue::Bytes(body),
                body_offset..body_offset + body.len(),
            );
        }

        buf.end_layer();

        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

/// Decode the Information TLVs of an Information OAMPDU.
///
/// IEEE 802.3-2022, Clause 57.5.2 — TLVs follow the header until an End of
/// TLV marker (type 0x00); the octets after it are padding. A TLV whose
/// length is shorter than its header or runs past the PDU ends the walk and
/// is reported with its remaining octets as `value`.
fn push_information_tlvs<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], offset: usize) {
    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_TLVS],
        FieldValue::Array(0..0),
        offset..offset,
    );
    let mut pos = 0;
    while pos < body.len() && body[pos] != INFO_TYPE_END {
        let info_type = body[pos];
        let rest = &body[pos..];
        let split = tlv::split_tlv(rest, TLV_HEADER_SIZE, rest.get(1).map(|&l| l as usize));
        let tlv = &rest[..split.len];
        let base = offset + pos;

        let obj_idx =
            buf.begin_container(&FD_TLV, FieldValue::Object(0..0), base..base + split.len);
        buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_TYPE],
            FieldValue::U8(info_type),
            base..base + 1,
        );
        if let Some(l) = split.declared {
            buf.push_field(
                &TLV_CHILD_FIELDS[FD_TLV_LENGTH],
                FieldValue::U8(l as u8),
                base + 1..base + 2,
            );
        }

        match info_type {
            INFO_TYPE_LOCAL | INFO_TYPE_REMOTE
                if split.well_formed && split.len == LOCAL_INFO_LENGTH =>
            {
                push_local_information(buf, tlv, base);
            }
            INFO_TYPE_ORG if split.well_formed && split.len >= ORG_TLV_MIN_LENGTH => {
                // IEEE 802.3-2022, Clause 57.5.2.3 — OUI, then
                // organization specific value.
                buf.push_field(
                    &TLV_CHILD_FIELDS[FD_TLV_OUI],
                    FieldValue::Bytes(&tlv[2..5]),
                    base + 2..base + 5,
                );
                tlv::push_raw_value(
                    buf,
                    &TLV_CHILD_FIELDS[FD_TLV_VALUE],
                    tlv,
                    ORG_TLV_MIN_LENGTH,
                    base,
                );
            }
            _ => tlv::push_raw_value(
                buf,
                &TLV_CHILD_FIELDS[FD_TLV_VALUE],
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

/// Decode a Local or Remote Information TLV (16 octets).
///
/// IEEE 802.3-2022, Clause 57.5.2.1 / 57.5.2.2 — Info Type, Info Length,
/// OAM Version, Revision (2), State, OAM Configuration, OAMPDU
/// Configuration (2), OUI (3), Vendor Specific Information (4).
fn push_local_information<'pkt>(buf: &mut DissectBuffer<'pkt>, tlv: &'pkt [u8], base: usize) {
    let state = tlv[5];
    let config = tlv[6];
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_OAM_VERSION],
        FieldValue::U8(tlv[2]),
        base + 2..base + 3,
    );
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_REVISION],
        FieldValue::U16(u16::from_be_bytes([tlv[3], tlv[4]])),
        base + 3..base + 5,
    );
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_STATE],
        FieldValue::U8(state),
        base + 5..base + 6,
    );
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_PARSER_ACTION],
        FieldValue::U8(state & 0x03),
        base + 5..base + 6,
    );
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_MULTIPLEXER_ACTION],
        FieldValue::U8((state >> 2) & 0x01),
        base + 5..base + 6,
    );
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_OAM_CONFIGURATION],
        FieldValue::U8(config),
        base + 6..base + 7,
    );
    for bit in 0..OAM_CONFIGURATION_BITS {
        buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_OAM_CONFIGURATION_BASE + bit],
            FieldValue::U8((config >> bit) & 1),
            base + 6..base + 7,
        );
    }
    let oampdu_config = u16::from_be_bytes([tlv[7], tlv[8]]);
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_OAMPDU_CONFIGURATION],
        FieldValue::U16(oampdu_config),
        base + 7..base + 9,
    );
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_MAX_OAMPDU_SIZE],
        FieldValue::U16(oampdu_config & MAX_OAMPDU_SIZE_MASK),
        base + 7..base + 9,
    );
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_OUI],
        FieldValue::Bytes(&tlv[9..12]),
        base + 9..base + 12,
    );
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_VENDOR_SPECIFIC_INFO],
        FieldValue::Bytes(&tlv[12..16]),
        base + 12..base + 16,
    );
}

#[cfg(test)]
mod tests {
    //! # IEEE 802.3-2022 Clause 57 (OAM) Coverage
    //!
    //! | Clause   | Description                              | Test                              |
    //! |----------|------------------------------------------|-----------------------------------|
    //! | 57.4.2   | OAMPDU header (subtype, flags, code)     | parse_oam_information_pdu         |
    //! | 57.4.2.1 | Flags bits                               | parse_oam_flags                   |
    //! | 57.4.2.2 | Non-Information code keeps raw data      | parse_oam_event_notification_raw  |
    //! | 57.5.2.1 | Local Information TLV                    | parse_oam_information_pdu         |
    //! | 57.5.2.2 | Remote Information TLV                   | parse_oam_information_pdu         |
    //! | 57.5.2.3 | Organization Specific Information TLV    | parse_oam_org_specific_tlv        |
    //! | 57.5.2   | Unknown TLV type kept raw                | parse_oam_unknown_tlv             |
    //! | 57.5.2   | Malformed TLV length ends the walk       | parse_oam_malformed_tlv_length    |
    //! | 57.5.2.1 | Max OAMPDU Size (bits 10:0)              | parse_oam_max_oampdu_size_ignores_reserved_bits |
    //! | 57.5.2   | End marker first: no TLV list            | parse_oam_information_without_tlvs |
    //! | 57.4.2   | Truncated header                         | parse_oam_truncated               |
    //! | 57.4.2   | Subtype other than OAM                   | parse_oam_invalid_subtype         |

    use super::*;

    fn local_info(info_type: u8) -> [u8; 16] {
        [
            info_type, 0x10, // Info Type, Info Length
            0x01, // OAM Version
            0x00, 0x05, // Revision
            0x06, // State: parser discard (2), mux discard (1)
            0x15, // OAM Config: mode, loopback, variable retrieval
            0x05, 0xEE, // OAMPDU Configuration: 1518
            0x00, 0x10, 0x00, // OUI
            0xDE, 0xAD, 0xBE, 0xEF, // Vendor Specific Information
        ]
    }

    /// Information OAMPDU with Local and Remote Information TLVs, padded to
    /// 42 octets of data.
    fn build_information() -> Vec<u8> {
        let mut pdu = vec![SUBTYPE_OAM, 0x00, 0x50, CODE_INFORMATION];
        pdu.extend_from_slice(&local_info(INFO_TYPE_LOCAL));
        pdu.extend_from_slice(&local_info(INFO_TYPE_REMOTE));
        pdu.resize(OAMPDU_HEADER_SIZE + 42, 0);
        pdu
    }

    fn top<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> &'a FieldValue<'a> {
        let layer = buf.layer_by_name("OAM").expect("OAM layer");
        &buf.field_by_name(layer, name).expect(name).value
    }

    fn tlv_objects<'a>(
        buf: &'a DissectBuffer<'_>,
    ) -> Vec<&'a [packet_dissector_core::field::Field<'a>]> {
        let FieldValue::Array(r) = top(buf, "tlvs") else {
            panic!("tlvs is not an array")
        };
        buf.nested_fields(r)
            .iter()
            .filter_map(|f| match &f.value {
                FieldValue::Object(o) => Some(buf.nested_fields(o)),
                _ => None,
            })
            .collect()
    }

    fn child<'a>(
        fields: &'a [packet_dissector_core::field::Field<'a>],
        name: &str,
    ) -> &'a FieldValue<'a> {
        &fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("{name}"))
            .value
    }

    #[test]
    fn parse_oam_information_pdu() {
        let data = build_information();
        let mut buf = DissectBuffer::new();
        let r = OamDissector.dissect(&data, &mut buf, 14).unwrap();
        assert_eq!(r.bytes_consumed, data.len());
        assert_eq!(r.next, DispatchHint::End);

        let layer = buf.layer_by_name("OAM").unwrap();
        assert_eq!(layer.range, 14..14 + data.len());
        assert_eq!(*top(&buf, "subtype"), FieldValue::U8(3));
        assert_eq!(*top(&buf, "code"), FieldValue::U8(0));
        assert_eq!(
            buf.resolve_display_name(layer, "code_name"),
            Some("Information")
        );
        assert!(buf.field_by_name(layer, "data").is_none());

        let tlvs = tlv_objects(&buf);
        assert_eq!(tlvs.len(), 2);
        for (fields, t) in tlvs.iter().zip([INFO_TYPE_LOCAL, INFO_TYPE_REMOTE]) {
            assert_eq!(*child(fields, "type"), FieldValue::U8(t));
            assert_eq!(*child(fields, "length"), FieldValue::U8(16));
            assert_eq!(*child(fields, "oam_version"), FieldValue::U8(1));
            assert_eq!(*child(fields, "revision"), FieldValue::U16(5));
            assert_eq!(*child(fields, "state"), FieldValue::U8(0x06));
            assert_eq!(*child(fields, "parser_action"), FieldValue::U8(2));
            assert_eq!(*child(fields, "multiplexer_action"), FieldValue::U8(1));
            assert_eq!(*child(fields, "oam_configuration"), FieldValue::U8(0x15));
            assert_eq!(*child(fields, "oam_mode"), FieldValue::U8(1));
            assert_eq!(*child(fields, "unidirectional_support"), FieldValue::U8(0));
            assert_eq!(*child(fields, "remote_loopback_support"), FieldValue::U8(1));
            assert_eq!(*child(fields, "link_events"), FieldValue::U8(0));
            assert_eq!(*child(fields, "variable_retrieval"), FieldValue::U8(1));
            assert_eq!(
                *child(fields, "oampdu_configuration"),
                FieldValue::U16(1518)
            );
            assert_eq!(
                *child(fields, "oui"),
                FieldValue::Bytes(&[0x00, 0x10, 0x00])
            );
            assert_eq!(
                *child(fields, "vendor_specific_info"),
                FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
            );
        }
        // Local Information TLV occupies octets 4..20 of the PDU.
        let FieldValue::Array(r) = top(&buf, "tlvs") else {
            unreachable!()
        };
        let obj = &buf.nested_fields(r)[0];
        assert_eq!(obj.range, 18..34);
        assert_eq!(
            buf.resolve_container_display_name(r.start),
            Some("Local Information")
        );
        let fields = tlvs[0];
        let state_ranges: Vec<_> = fields
            .iter()
            .filter(|f| f.name() == "parser_action")
            .map(|f| f.range.clone())
            .collect();
        assert_eq!(state_ranges, vec![23..24]);
        assert_eq!(parser_action_name(2), Some("Discard non-OAMPDUs"));
        assert_eq!(parser_action_name(3), None);
        assert_eq!(multiplexer_action_name(1), Some("Discard non-OAMPDUs"));
        assert_eq!(
            multiplexer_action_name(0),
            Some("Forward non-OAMPDUs to lower sublayer")
        );
        assert_eq!(multiplexer_action_name(2), None);
        assert_eq!(
            parser_action_name(0),
            Some("Forward non-OAMPDUs to higher sublayer")
        );
        assert_eq!(
            parser_action_name(1),
            Some("Loop back non-OAMPDUs to lower sublayer")
        );
    }

    #[test]
    fn parse_oam_max_oampdu_size_ignores_reserved_bits() {
        let mut data = build_information();
        data[11] = 0xF8; // reserved bits 15:11 set
        data[12] = 0x05;
        let mut buf = DissectBuffer::new();
        OamDissector.dissect(&data, &mut buf, 0).unwrap();
        let tlvs = tlv_objects(&buf);
        assert_eq!(
            *child(tlvs[0], "oampdu_configuration"),
            FieldValue::U16(0xF805)
        );
        assert_eq!(*child(tlvs[0], "max_oampdu_size"), FieldValue::U16(5));
    }

    #[test]
    fn parse_oam_information_without_tlvs() {
        let mut buf = DissectBuffer::new();
        let data = [SUBTYPE_OAM, 0x00, 0x00, CODE_INFORMATION, 0x00, 0x00];
        OamDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("OAM").unwrap();
        assert!(buf.field_by_name(layer, "tlvs").is_none());
    }

    #[test]
    fn parse_oam_flags() {
        let mut data = build_information();
        data[1] = 0xFF;
        data[2] = 0xFF;
        let mut buf = DissectBuffer::new();
        OamDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(*top(&buf, "flags"), FieldValue::U16(0xFFFF));
        for name in [
            "flags_link_fault",
            "flags_dying_gasp",
            "flags_critical_event",
            "flags_local_evaluating",
            "flags_local_stable",
            "flags_remote_evaluating",
            "flags_remote_stable",
        ] {
            assert_eq!(*top(&buf, name), FieldValue::U8(1), "{name}");
        }

        data[1] = 0x00;
        data[2] = 0x02; // Dying Gasp only
        let mut buf = DissectBuffer::new();
        OamDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(*top(&buf, "flags_link_fault"), FieldValue::U8(0));
        assert_eq!(*top(&buf, "flags_dying_gasp"), FieldValue::U8(1));
        assert_eq!(*top(&buf, "flags_remote_stable"), FieldValue::U8(0));
    }

    #[test]
    fn parse_oam_event_notification_raw() {
        let mut data = vec![SUBTYPE_OAM, 0x00, 0x50, 0x01, 0x00, 0x01];
        data.resize(46, 0);
        let mut buf = DissectBuffer::new();
        OamDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("OAM").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "code_name"),
            Some("Event Notification")
        );
        assert!(buf.field_by_name(layer, "tlvs").is_none());
        let f = buf.field_by_name(layer, "data").unwrap();
        assert_eq!(f.value, FieldValue::Bytes(&data[4..]));
        assert_eq!(f.range, 4..46);

        for (c, n) in [
            (0x02, "Variable Request"),
            (0x03, "Variable Response"),
            (0x04, "Loopback Control"),
            (0xFE, "Organization Specific"),
        ] {
            assert_eq!(code_name(c), Some(n));
        }
        assert_eq!(code_name(0x05), None);

        // A header-only OAMPDU of another code has no data field.
        let mut buf = DissectBuffer::new();
        OamDissector.dissect(&data[..4], &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("OAM").unwrap();
        assert!(buf.field_by_name(layer, "data").is_none());
    }

    #[test]
    fn parse_oam_org_specific_tlv() {
        let mut data = vec![SUBTYPE_OAM, 0x00, 0x50, CODE_INFORMATION];
        data.extend_from_slice(&[INFO_TYPE_ORG, 0x07, 0x00, 0x10, 0x00, 0xAB, 0xCD]);
        // Organization Specific TLV with no value after the OUI.
        data.extend_from_slice(&[INFO_TYPE_ORG, 0x05, 0x00, 0x10, 0x00]);
        data.resize(46, 0);
        let mut buf = DissectBuffer::new();
        OamDissector.dissect(&data, &mut buf, 0).unwrap();
        let tlvs = tlv_objects(&buf);
        assert_eq!(tlvs.len(), 2);
        assert_eq!(*child(tlvs[0], "type"), FieldValue::U8(0xFE));
        assert_eq!(
            *child(tlvs[0], "oui"),
            FieldValue::Bytes(&[0x00, 0x10, 0x00])
        );
        assert_eq!(*child(tlvs[0], "value"), FieldValue::Bytes(&[0xAB, 0xCD]));
        assert!(tlvs[1].iter().all(|f| f.name() != "value"));
        assert_eq!(
            info_type_name(INFO_TYPE_ORG),
            Some("Organization Specific Information")
        );
        assert_eq!(info_type_name(INFO_TYPE_END), Some("End of TLV Marker"));
        assert_eq!(info_type_name(0x10), None);
    }

    #[test]
    fn parse_oam_unknown_tlv() {
        let mut data = vec![SUBTYPE_OAM, 0x00, 0x00, CODE_INFORMATION];
        data.extend_from_slice(&[0x10, 0x04, 0x01, 0x02]);
        // Local Information TLV with an unexpected length is kept raw.
        data.extend_from_slice(&[INFO_TYPE_LOCAL, 0x03, 0x09]);
        // Header-only unknown TLV.
        data.extend_from_slice(&[0x11, 0x02]);
        let mut buf = DissectBuffer::new();
        OamDissector.dissect(&data, &mut buf, 0).unwrap();
        let tlvs = tlv_objects(&buf);
        assert_eq!(tlvs.len(), 3);
        assert_eq!(*child(tlvs[0], "value"), FieldValue::Bytes(&[0x01, 0x02]));
        assert_eq!(*child(tlvs[1], "value"), FieldValue::Bytes(&[0x09]));
        assert!(tlvs[1].iter().all(|f| f.name() != "oam_version"));
        assert!(tlvs[2].iter().all(|f| f.name() != "value"));
    }

    #[test]
    fn parse_oam_malformed_tlv_length() {
        // Length 1 is shorter than the TLV header: report and stop.
        let mut data = vec![SUBTYPE_OAM, 0x00, 0x00, CODE_INFORMATION];
        data.extend_from_slice(&[0x10, 0x01, 0xAA, 0xBB]);
        let mut buf = DissectBuffer::new();
        OamDissector.dissect(&data, &mut buf, 0).unwrap();
        let tlvs = tlv_objects(&buf);
        assert_eq!(tlvs.len(), 1);
        assert_eq!(*child(tlvs[0], "length"), FieldValue::U8(1));
        assert_eq!(*child(tlvs[0], "value"), FieldValue::Bytes(&[0xAA, 0xBB]));

        // Length runs past the PDU.
        let mut data = vec![SUBTYPE_OAM, 0x00, 0x00, CODE_INFORMATION];
        data.extend_from_slice(&[INFO_TYPE_LOCAL, 0x10, 0x01]);
        let mut buf = DissectBuffer::new();
        OamDissector.dissect(&data, &mut buf, 0).unwrap();
        let tlvs = tlv_objects(&buf);
        assert_eq!(tlvs.len(), 1);
        assert_eq!(*child(tlvs[0], "value"), FieldValue::Bytes(&[0x01]));

        // Type octet without a length octet.
        let data = [SUBTYPE_OAM, 0x00, 0x00, CODE_INFORMATION, 0x10];
        let mut buf = DissectBuffer::new();
        OamDissector.dissect(&data, &mut buf, 0).unwrap();
        let tlvs = tlv_objects(&buf);
        assert_eq!(tlvs.len(), 1);
        assert!(tlvs[0].iter().all(|f| f.name() != "length"));
    }

    #[test]
    fn parse_oam_truncated() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            OamDissector.dissect(&[SUBTYPE_OAM, 0, 0], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 4,
                actual: 3
            })
        );
    }

    #[test]
    fn parse_oam_invalid_subtype() {
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            OamDissector.dissect(&[0x01, 0, 0, 0], &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn oam_metadata() {
        assert_eq!(OamDissector.short_name(), "OAM");
        assert!(!OamDissector.name().is_empty());
        assert!(!OamDissector.field_descriptors().is_empty());
        assert!(!OamDissector.references().is_empty());
        assert_eq!(OamDissector.layer(), Some(ProtocolLayer::Link));
    }
}
