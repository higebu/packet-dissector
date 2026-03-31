//! ARP (Address Resolution Protocol) dissector.
//!
//! ## References
//! - RFC 826: <https://www.rfc-editor.org/rfc/rfc826>
//! - RFC 5227 (IPv4 Address Conflict Detection): <https://www.rfc-editor.org/rfc/rfc5227>
//! - RFC 5494 (IANA Allocation Guidelines for ARP): <https://www.rfc-editor.org/rfc/rfc5494>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, MacAddr};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

/// Returns a human-readable name for ARP operation codes.
///
/// RFC 826, Section — Operation field values; RFC 5494 for IANA registry.
fn arp_oper_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("REQUEST"),
        2 => Some("REPLY"),
        _ => None,
    }
}

/// Minimum ARP header size (fixed fields only, before addresses).
const FIXED_HEADER_SIZE: usize = 8;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_HTYPE: usize = 0;
const FD_PTYPE: usize = 1;
const FD_HLEN: usize = 2;
const FD_PLEN: usize = 3;
const FD_OPER: usize = 4;
const FD_SHA: usize = 5;
const FD_SPA: usize = 6;
const FD_THA: usize = 7;
const FD_TPA: usize = 8;

// ARP address field types depend on htype/ptype at runtime.
// For the common case (Ethernet/IPv4), sha/tha are MacAddr and spa/tpa are Ipv4Addr.
// We advertise MacAddr/Ipv4Addr as the canonical types since Bytes is also possible.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("htype", "Hardware Type", FieldType::U16),
    FieldDescriptor::new("ptype", "Protocol Type", FieldType::U16),
    FieldDescriptor::new("hlen", "Hardware Address Length", FieldType::U8),
    FieldDescriptor::new("plen", "Protocol Address Length", FieldType::U8),
    FieldDescriptor {
        name: "oper",
        display_name: "Operation",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(v) => arp_oper_name(*v),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("sha", "Sender Hardware Address", FieldType::MacAddr),
    FieldDescriptor::new("spa", "Sender Protocol Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("tha", "Target Hardware Address", FieldType::MacAddr),
    FieldDescriptor::new("tpa", "Target Protocol Address", FieldType::Ipv4Addr),
];

/// ARP dissector.
pub struct ArpDissector;

impl Dissector for ArpDissector {
    fn name(&self) -> &'static str {
        "Address Resolution Protocol"
    }

    fn short_name(&self) -> &'static str {
        "ARP"
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
        if data.len() < FIXED_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: FIXED_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 826 — ARP packet format
        let htype = read_be_u16(data, 0)?;
        let ptype = read_be_u16(data, 2)?;
        let hlen = data[4] as usize;
        let plen = data[5] as usize;
        let oper = read_be_u16(data, 6)?;

        // Total size: 8 (fixed) + 2*hlen + 2*plen
        let total_len = FIXED_HEADER_SIZE + 2 * hlen + 2 * plen;
        if data.len() < total_len {
            return Err(PacketError::Truncated {
                expected: total_len,
                actual: data.len(),
            });
        }

        let sha_start = FIXED_HEADER_SIZE;
        let spa_start = sha_start + hlen;
        let tha_start = spa_start + plen;
        let tpa_start = tha_start + hlen;

        // Use MacAddr for 6-byte hardware addresses (Ethernet), Bytes otherwise
        let sha_value = if hlen == 6 {
            FieldValue::MacAddr(MacAddr([
                data[sha_start],
                data[sha_start + 1],
                data[sha_start + 2],
                data[sha_start + 3],
                data[sha_start + 4],
                data[sha_start + 5],
            ]))
        } else {
            FieldValue::Bytes(&data[sha_start..sha_start + hlen])
        };
        let tha_value = if hlen == 6 {
            FieldValue::MacAddr(MacAddr([
                data[tha_start],
                data[tha_start + 1],
                data[tha_start + 2],
                data[tha_start + 3],
                data[tha_start + 4],
                data[tha_start + 5],
            ]))
        } else {
            FieldValue::Bytes(&data[tha_start..tha_start + hlen])
        };

        // Use Ipv4Addr for 4-byte protocol addresses, Bytes otherwise
        let spa_value = if plen == 4 {
            FieldValue::Ipv4Addr([
                data[spa_start],
                data[spa_start + 1],
                data[spa_start + 2],
                data[spa_start + 3],
            ])
        } else {
            FieldValue::Bytes(&data[spa_start..spa_start + plen])
        };
        let tpa_value = if plen == 4 {
            FieldValue::Ipv4Addr([
                data[tpa_start],
                data[tpa_start + 1],
                data[tpa_start + 2],
                data[tpa_start + 3],
            ])
        } else {
            FieldValue::Bytes(&data[tpa_start..tpa_start + plen])
        };

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_len,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HTYPE],
            FieldValue::U16(htype),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PTYPE],
            FieldValue::U16(ptype),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HLEN],
            FieldValue::U8(hlen as u8),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PLEN],
            FieldValue::U8(plen as u8),
            offset + 5..offset + 6,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_OPER],
            FieldValue::U16(oper),
            offset + 6..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SHA],
            sha_value,
            offset + sha_start..offset + sha_start + hlen,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SPA],
            spa_value,
            offset + spa_start..offset + spa_start + plen,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_THA],
            tha_value,
            offset + tha_start..offset + tha_start + hlen,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TPA],
            tpa_value,
            offset + tpa_start..offset + tpa_start + plen,
        );
        buf.end_layer();

        Ok(DissectResult::new(total_len, DispatchHint::End))
    }
}
