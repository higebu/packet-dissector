//! Standalone IEEE 802.1Q / IEEE 802.1ad VLAN tag dissector.
//!
//! [`EthernetDissector`](crate::EthernetDissector) parses VLAN tags that
//! directly follow the MAC addresses itself. This dissector handles a tag
//! reached through an EtherType dispatch instead — for example a Linux
//! cooked capture (SLL / SLL2) whose protocol type is 0x8100, or a tunnel
//! whose protocol field is 0x8100 / 0x88A8. The TPID has already been read
//! by the previous layer as its EtherType, so the input starts at the Tag
//! Control Information (TCI), followed by the inner Length/Type field.
//! Stacked tags (QinQ) produce one layer per tag.
//!
//! An inner value ≤ 1500 is decoded as an IEEE 802.3 Length (IEEE 802.3-2022,
//! clause 3.2.6). Note that behind a Linux cooked header libpcap inserts the
//! tag in front of the original `sll_protocol`, so there the inner value is a
//! Linux protocol number (e.g. 0x0004 for IEEE 802.2 LLC), which this
//! dissector cannot tell apart from a Length.
//!
//! ## References
//! - IEEE 802.1Q-2022, clause 9.6 (VLAN tag format, incorporates IEEE
//!   802.1ad): <https://standards.ieee.org/ieee/802.1Q/10323/>
//! - IEEE 802.3-2022, clause 3.2.6 (Length/Type):
//!   <https://standards.ieee.org/ieee/802.3/10422/>
//! - IANA EtherType registry (0x8100 C-Tag, 0x88A8 S-Tag):
//!   <https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml>

use packet_dissector_core::dissector::{DissectResult, Dissector, ProtocolLayer, SpecReference};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

use crate::{TAG_SIZE, TypeLengthFields, dissect_type_or_length, ethertype_name, llc, split_tci};

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_VLAN_PCP: usize = 0;
const FD_VLAN_DEI: usize = 1;
const FD_VLAN_ID: usize = 2;
const FD_ETHERTYPE: usize = 3;
const FD_LENGTH: usize = 4;
const FD_LLC_DSAP: usize = 5;
const FD_LLC_SSAP: usize = 6;
const FD_LLC_CONTROL: usize = 7;
const FD_LLC_CONTROL_EXT: usize = 8;
const FD_NOVELL_RAW: usize = 9;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // Same names as the tag fields of the Ethernet layer.
    FieldDescriptor::new("vlan_pcp", "VLAN PCP", FieldType::U8),
    FieldDescriptor::new("vlan_dei", "VLAN DEI", FieldType::U8),
    FieldDescriptor::new("vlan_id", "VLAN ID", FieldType::U16),
    FieldDescriptor::new("ethertype", "EtherType", FieldType::U16)
        .optional()
        .with_display_fn(|v, _siblings| match v {
            FieldValue::U16(v) => ethertype_name(*v),
            _ => None,
        }),
    FieldDescriptor::new("length", "Length", FieldType::U16).optional(),
    llc::DSAP_FIELD,
    llc::SSAP_FIELD,
    llc::CONTROL_FIELD,
    llc::CONTROL_EXT_FIELD,
    FieldDescriptor::new("novell_raw", "Novell raw IEEE 802.3 (IPX)", FieldType::U8).optional(),
];

static TYPE_LENGTH_FIELDS: TypeLengthFields = TypeLengthFields {
    ethertype: &FIELD_DESCRIPTORS[FD_ETHERTYPE],
    length: &FIELD_DESCRIPTORS[FD_LENGTH],
    llc: [
        &FIELD_DESCRIPTORS[FD_LLC_DSAP],
        &FIELD_DESCRIPTORS[FD_LLC_SSAP],
        &FIELD_DESCRIPTORS[FD_LLC_CONTROL],
        &FIELD_DESCRIPTORS[FD_LLC_CONTROL_EXT],
    ],
    novell_raw: &FIELD_DESCRIPTORS[FD_NOVELL_RAW],
};

static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "IEEE 802.1Q-2022",
        "IEEE Standard for Local and Metropolitan Area Networks—Bridges and Bridged Networks",
        "https://standards.ieee.org/ieee/802.1Q/10323/",
    ),
    SpecReference::new(
        "IEEE 802.3-2022",
        "IEEE Standard for Ethernet",
        "https://standards.ieee.org/ieee/802.3/10422/",
    ),
];

/// Standalone IEEE 802.1Q (C-Tag) / IEEE 802.1ad (S-Tag) VLAN tag dissector,
/// registered for EtherTypes 0x8100 and 0x88A8.
pub struct VlanDissector;

impl Dissector for VlanDissector {
    fn name(&self) -> &'static str {
        "IEEE 802.1Q Virtual LAN"
    }

    fn short_name(&self) -> &'static str {
        "VLAN"
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
        // IEEE 802.1Q-2022, clause 9.6: TCI (2 octets) followed by the
        // Length/Type of the tagged frame (2 octets).
        if data.len() < TAG_SIZE {
            return Err(PacketError::Truncated {
                expected: TAG_SIZE,
                actual: data.len(),
            });
        }
        let (pcp, dei, vlan_id) = split_tci(read_be_u16(data, 0)?);
        let inner_type = read_be_u16(data, 2)?;

        let field_start = buf.field_count();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VLAN_PCP],
            FieldValue::U8(pcp),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VLAN_DEI],
            FieldValue::U8(dei),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VLAN_ID],
            FieldValue::U16(vlan_id),
            offset..offset + 2,
        );

        let (header_len, next, payload_len) = match dissect_type_or_length(
            data,
            buf,
            offset,
            TAG_SIZE,
            inner_type,
            &TYPE_LENGTH_FIELDS,
        ) {
            Ok(parts) => parts,
            Err(e) => {
                buf.truncate_fields(field_start as usize);
                return Err(e);
            }
        };

        let field_end = buf.field_count();
        buf.push_layer(packet_dissector_core::packet::Layer {
            name: self.short_name(),
            display_name: None,
            field_descriptors: FIELD_DESCRIPTORS,
            range: offset..offset + header_len,
            field_range: field_start..field_end,
        });

        let mut result = DissectResult::new(header_len, next);
        result.payload_len = payload_len;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    //! # IEEE 802.1Q (standalone VLAN tag) Coverage
    //!
    //! | Spec section                     | Description                            | Test                               |
    //! |----------------------------------|----------------------------------------|------------------------------------|
    //! | IEEE 802.1Q-2022 clause 9.6      | TCI: PCP / DEI / VID                   | vlan_tag_fields                    |
    //! | IEEE 802.1Q-2022 clause 9.6      | Inner EtherType dispatch               | vlan_tag_fields                    |
    //! | IEEE 802.1Q-2022 clause 9.6      | Stacked tag: inner TPID dispatched     | vlan_tag_inner_tpid_dispatches     |
    //! | IEEE 802.1Q-2022 clause 9.6      | Truncated tag                          | vlan_tag_truncated                 |
    //! | IEEE 802.3-2022 clause 3.2.6     | Inner Length → LLC, payload bounded    | vlan_tag_inner_length_llc          |
    //! | IEEE 802.3-2022 clause 3.2.6     | Reserved Length/Type 1501–1535         | vlan_tag_reserved_type_length      |

    use super::*;
    use packet_dissector_core::dissector::DispatchHint;

    fn vlan_field<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> Option<&'a FieldValue<'a>> {
        let layer = buf.layer_by_name("VLAN")?;
        buf.field_by_name(layer, name).map(|f| &f.value)
    }

    #[test]
    fn vlan_tag_fields() {
        // TCI: PCP=5, DEI=1, VID=0x123; inner EtherType IPv4.
        let data = [0xB1, 0x23, 0x08, 0x00, 0x45];
        let mut buf = DissectBuffer::new();
        let r = VlanDissector.dissect(&data, &mut buf, 14).unwrap();
        assert_eq!(r.bytes_consumed, 4);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x0800));
        assert_eq!(r.payload_len, None);
        assert_eq!(vlan_field(&buf, "vlan_pcp"), Some(&FieldValue::U8(5)));
        assert_eq!(vlan_field(&buf, "vlan_dei"), Some(&FieldValue::U8(1)));
        assert_eq!(vlan_field(&buf, "vlan_id"), Some(&FieldValue::U16(0x123)));
        assert_eq!(
            vlan_field(&buf, "ethertype"),
            Some(&FieldValue::U16(0x0800))
        );
        let layer = buf.layer_by_name("VLAN").unwrap();
        assert_eq!(layer.range, 14..18);
        assert_eq!(buf.field_by_name(layer, "vlan_id").unwrap().range, 14..16);
        assert_eq!(buf.field_by_name(layer, "ethertype").unwrap().range, 16..18);
        assert_eq!(
            buf.resolve_display_name(layer, "ethertype_name"),
            Some("IPv4")
        );
    }

    #[test]
    fn vlan_tag_inner_tpid_dispatches() {
        // S-Tag whose inner type is a C-Tag TPID: the next tag is its own layer.
        let data = [0x00, 0x0A, 0x81, 0x00];
        let mut buf = DissectBuffer::new();
        let r = VlanDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.next, DispatchHint::ByEtherType(0x8100));
        assert_eq!(vlan_field(&buf, "vlan_id"), Some(&FieldValue::U16(10)));
    }

    #[test]
    fn vlan_tag_truncated() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            VlanDissector.dissect(&[0x00, 0x01, 0x08], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 4,
                actual: 3
            })
        );
        assert!(buf.layers().is_empty());
        assert_eq!(buf.field_count(), 0);
    }

    #[test]
    fn vlan_tag_inner_length_llc() {
        // Inner Length 5: LLC UI frame to SAP 0x42 with 2 octets of data,
        // followed by pad.
        let data = [
            0x00, 0x01, 0x00, 0x05, 0x42, 0x42, 0x03, 0x00, 0x00, 0xEE, 0xEE,
        ];
        let mut buf = DissectBuffer::new();
        let r = VlanDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 7);
        assert_eq!(r.next, DispatchHint::ByLlcSap(0x42));
        assert_eq!(r.payload_len, Some(2));
        assert_eq!(vlan_field(&buf, "length"), Some(&FieldValue::U16(5)));
        assert_eq!(vlan_field(&buf, "llc_dsap"), Some(&FieldValue::U8(0x42)));
        assert!(vlan_field(&buf, "ethertype").is_none());
        assert_eq!(buf.layer_by_name("VLAN").unwrap().range, 0..7);
    }

    #[test]
    fn vlan_tag_reserved_type_length() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            VlanDissector.dissect(&[0x00, 0x01, 0x05, 0xDD], &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "type_length",
                value: 0x05DD
            })
        );
        assert!(buf.layers().is_empty());
        assert_eq!(buf.field_count(), 0);
    }
}
