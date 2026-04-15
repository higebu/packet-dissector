//! Ethernet II frame dissector.
//!
//! Parses classic Ethernet II frames (DIX v2) as well as IEEE 802.3 frames
//! with IEEE 802.2 LLC encapsulation. IEEE 802.1Q (C-Tag) and IEEE 802.1ad
//! (S-Tag / QinQ) VLAN tags stacked in any number are accepted; each tag
//! is parsed in a loop until a non-VLAN EtherType or a length value is
//! reached.
//!
//! ## References
//! - IEEE 802.3-2022 (Ethernet): <https://standards.ieee.org/ieee/802.3/10422/>
//! - IEEE 802.1Q-2022 (VLAN tagging, incorporates IEEE 802.1ad QinQ):
//!   <https://standards.ieee.org/ieee/802.1Q/10323/>
//! - IEEE 802.2-1998 (LLC): <https://standards.ieee.org/ieee/802.2/1048/>
//! - IANA EtherType registry: <https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, MacAddr};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

/// Minimum Ethernet II header size (dst MAC + src MAC + EtherType).
/// IEEE 802.3-2022, clause 3.2.3.
const HEADER_SIZE: usize = 14;

/// 802.1Q Customer VLAN TPID value (C-Tag).
/// IEEE 802.1Q-2022, clause 9.6 (VLAN Tag Protocol Identifier).
const TPID_8021Q: u16 = 0x8100;

/// 802.1ad Service VLAN TPID value (S-Tag / QinQ outer tag).
/// IEEE 802.1Q-2022, clause 9.6 (originally introduced by IEEE 802.1ad-2005
/// and rolled into IEEE 802.1Q-2011 and later).
const TPID_8021AD: u16 = 0x88A8;

/// Minimum value of a valid EtherType field in an Ethernet II frame.
/// IEEE 802.3-2022, clause 3.2.6: values less than 0x0600 indicate a length field
/// (IEEE 802.3 LLC frame), not an EtherType.
const ETHERTYPE_MIN: u16 = 0x0600;

/// Maximum valid IEEE 802.3 length field value (1500 octets).
/// IEEE 802.3-2022, clause 3.2.6.
const LENGTH_MAX: u16 = 0x05DC;

/// Minimum size of an IEEE 802.2 LLC header (DSAP + SSAP + Control for UI frames).
/// IEEE 802.2-1998, Section 3.
const LLC_HEADER_SIZE: usize = 3;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_DST: usize = 0;
const FD_SRC: usize = 1;
const FD_VLAN_TPID: usize = 2;
const FD_VLAN_PCP: usize = 3;
const FD_VLAN_DEI: usize = 4;
const FD_VLAN_ID: usize = 5;
const FD_ETHERTYPE: usize = 6;
const FD_LENGTH: usize = 7;
const FD_LLC_DSAP: usize = 8;
const FD_LLC_SSAP: usize = 9;
const FD_LLC_CONTROL: usize = 10;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("dst", "Destination", FieldType::MacAddr),
    FieldDescriptor::new("src", "Source", FieldType::MacAddr),
    FieldDescriptor::new("vlan_tpid", "VLAN TPID", FieldType::U16).optional(),
    FieldDescriptor::new("vlan_pcp", "VLAN PCP", FieldType::U8).optional(),
    FieldDescriptor::new("vlan_dei", "VLAN DEI", FieldType::U8).optional(),
    FieldDescriptor::new("vlan_id", "VLAN ID", FieldType::U16).optional(),
    FieldDescriptor {
        name: "ethertype",
        display_name: "EtherType",
        field_type: FieldType::U16,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(v) => ethertype_name(*v),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U16).optional(),
    FieldDescriptor::new("llc_dsap", "LLC DSAP", FieldType::U8).optional(),
    FieldDescriptor::new("llc_ssap", "LLC SSAP", FieldType::U8).optional(),
    FieldDescriptor::new("llc_control", "LLC Control", FieldType::U8).optional(),
];

/// Returns a human-readable name for well-known EtherType values.
fn ethertype_name(v: u16) -> Option<&'static str> {
    match v {
        0x0800 => Some("IPv4"),
        0x0806 => Some("ARP"),
        0x8100 => Some("802.1Q"),
        0x88A8 => Some("802.1ad"),
        0x86DD => Some("IPv6"),
        0x8847 => Some("MPLS"),
        0x8848 => Some("MPLS_MC"),
        0x8809 => Some("Slow Protocols"),
        0x88CC => Some("LLDP"),
        _ => None,
    }
}

/// Ethernet II frame dissector.
pub struct EthernetDissector;

impl Dissector for EthernetDissector {
    fn name(&self) -> &'static str {
        "Ethernet II"
    }

    fn short_name(&self) -> &'static str {
        "Ethernet"
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
        // IEEE 802.3-2022, clause 3.2.3: minimum frame header is dst (6) + src (6) + type/length (2).
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        // IEEE 802.3-2022, clause 3.2.3: Destination Address (6 octets).
        let dst = MacAddr([data[0], data[1], data[2], data[3], data[4], data[5]]);
        // IEEE 802.3-2022, clause 3.2.3: Source Address (6 octets).
        let src = MacAddr([data[6], data[7], data[8], data[9], data[10], data[11]]);
        // IEEE 802.3-2022, clause 3.2.6: Length/Type field (2 octets, big-endian).
        let ethertype_or_tpid = read_be_u16(data, 12)?;

        // We defer begin_layer until we know the header length (VLAN tags vary).
        // Push MAC fields first; they're always present.
        let layer_field_start = buf.field_count();

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DST],
            FieldValue::MacAddr(dst),
            offset..offset + 6,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SRC],
            FieldValue::MacAddr(src),
            offset + 6..offset + 12,
        );

        let mut header_len = HEADER_SIZE;
        let mut current_type = ethertype_or_tpid;

        // IEEE 802.1Q-2022, clause 9.6: stacked VLAN tags may appear back-to-back
        // (e.g. QinQ S-Tag + C-Tag). Parse tags until `current_type` is no longer
        // a VLAN TPID. If a VLAN TPID is present but the remaining data cannot
        // hold the required 4-byte tag, the frame is truncated.
        while current_type == TPID_8021Q || current_type == TPID_8021AD {
            let vlan_end = header_len + 4;
            if data.len() < vlan_end {
                return Err(PacketError::Truncated {
                    expected: vlan_end,
                    actual: data.len(),
                });
            }

            // IEEE 802.1Q-2022, clause 9.6: Tag Control Information (TCI), 2 octets.
            // Bit layout (MSB first): PCP[3] | DEI[1] | VID[12].
            let tci = read_be_u16(data, header_len)?;
            let pcp = (tci >> 13) & 0x07;
            let dei = (tci >> 12) & 0x01;
            let vlan_id = tci & 0x0FFF;
            let inner_type = read_be_u16(data, header_len + 2)?;

            buf.push_field(
                &FIELD_DESCRIPTORS[FD_VLAN_TPID],
                FieldValue::U16(current_type),
                offset + header_len - 2..offset + header_len,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_VLAN_PCP],
                FieldValue::U8(pcp as u8),
                offset + header_len..offset + header_len + 2,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_VLAN_DEI],
                FieldValue::U8(dei as u8),
                offset + header_len..offset + header_len + 2,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_VLAN_ID],
                FieldValue::U16(vlan_id),
                offset + header_len..offset + header_len + 2,
            );

            header_len = vlan_end;
            current_type = inner_type;
        }

        let dispatch_hint = if current_type <= LENGTH_MAX {
            // IEEE 802.3-2022, clause 3.2.6: values ≤ 1500 indicate a length field
            // (IEEE 802.3 frame with LLC encapsulation).
            let llc_start = header_len;
            let llc_end = llc_start + LLC_HEADER_SIZE;
            if data.len() < llc_end {
                return Err(PacketError::Truncated {
                    expected: llc_end,
                    actual: data.len(),
                });
            }

            let dsap = data[llc_start];
            let ssap = data[llc_start + 1];
            let control = data[llc_start + 2];

            buf.push_field(
                &FIELD_DESCRIPTORS[FD_LENGTH],
                FieldValue::U16(current_type),
                offset + header_len - 2..offset + header_len,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_LLC_DSAP],
                FieldValue::U8(dsap),
                offset + llc_start..offset + llc_start + 1,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_LLC_SSAP],
                FieldValue::U8(ssap),
                offset + llc_start + 1..offset + llc_start + 2,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_LLC_CONTROL],
                FieldValue::U8(control),
                offset + llc_start + 2..offset + llc_end,
            );

            header_len = llc_end;
            DispatchHint::ByLlcSap(dsap)
        } else if current_type < ETHERTYPE_MIN {
            // IEEE 802.3-2022, clause 3.2.6: values 1501–1535 are undefined/reserved.
            return Err(PacketError::InvalidFieldValue {
                field: "type_length",
                value: current_type as u32,
            });
        } else {
            // Valid Ethernet II EtherType (≥ 0x0600).
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_ETHERTYPE],
                FieldValue::U16(current_type),
                offset + header_len - 2..offset + header_len,
            );

            DispatchHint::ByEtherType(current_type)
        };

        // Now that we know the header length, add the layer with the correct field range.
        let layer_field_end = buf.field_count();
        buf.push_layer(packet_dissector_core::packet::Layer {
            name: self.short_name(),
            display_name: None,
            field_descriptors: FIELD_DESCRIPTORS,
            range: offset..offset + header_len,
            field_range: layer_field_start..layer_field_end,
        });

        Ok(DissectResult::new(header_len, dispatch_hint))
    }
}
