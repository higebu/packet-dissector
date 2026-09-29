//! SNAP (Subnetwork Access Protocol) dissector.
//!
//! SNAP follows an IEEE 802.2 LLC header whose DSAP and SSAP are 0xAA. It is
//! 5 octets long: a 3-octet Organization Code (OUI) and a 2-octet Protocol
//! Identifier (PID). With OUI 00-00-00 (RFC 1042) or 00-00-F8 (IEEE 802.1H
//! bridge tunnel encapsulation) the PID is an EtherType.
//!
//! ## References
//! - RFC 1042 (IP over IEEE 802 networks, SNAP header format):
//!   <https://www.rfc-editor.org/rfc/rfc1042>
//! - IEEE Std 802-2014, Clause 10 (SNAP): <https://standards.ieee.org/standard/802-2014.html>
//! - IEEE 802.1H-1997 (bridge tunnel encapsulation, OUI 00-00-F8):
//!   <https://standards.ieee.org/standard/11802-5-1997.html>

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

use crate::ethertype_name;

/// SNAP header size: Organization Code (3) + Protocol Identifier (2).
/// RFC 1042, "Header Format" — <https://www.rfc-editor.org/rfc/rfc1042>
const SNAP_HEADER_SIZE: usize = 5;

/// Organization Code whose PID is an EtherType — RFC 1042
/// (<https://www.rfc-editor.org/rfc/rfc1042>): "The 24-bit
/// Organization Code in the SNAP is zero, and the remaining 16 bits are the
/// EtherType from Assigned Numbers".
const OUI_ETHERTYPE: u32 = 0x00_0000;

/// IEEE 802.1H bridge tunnel Organization Code; the PID is an EtherType.
const OUI_BRIDGE_TUNNEL: u32 = 0x00_00F8;

const FD_OUI: usize = 0;
const FD_PID: usize = 1;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("oui", "Organization Code", FieldType::U32),
    FieldDescriptor::new("pid", "Protocol ID", FieldType::U16).with_display_fn(|v, siblings| {
        let oui = siblings.iter().find_map(|f| match (f.name(), &f.value) {
            ("oui", FieldValue::U32(o)) => Some(*o),
            _ => None,
        })?;
        match v {
            FieldValue::U16(pid) if pid_is_ethertype(oui) => ethertype_name(*pid),
            _ => None,
        }
    }),
];

static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 1042",
        "A Standard for the Transmission of IP Datagrams over IEEE 802 Networks",
        "https://www.rfc-editor.org/rfc/rfc1042",
    ),
    SpecReference::new(
        "IEEE 802-2014",
        "IEEE Standard for Local and Metropolitan Area Networks: Overview and \
         Architecture, Clause 10 (SNAP)",
        "https://standards.ieee.org/standard/802-2014.html",
    ),
];

/// Whether the PID of a SNAP header with this OUI is an EtherType.
fn pid_is_ethertype(oui: u32) -> bool {
    oui == OUI_ETHERTYPE || oui == OUI_BRIDGE_TUNNEL
}

/// SNAP dissector, reached through LLC SAP 0xAA.
pub struct SnapDissector;

impl Dissector for SnapDissector {
    fn name(&self) -> &'static str {
        "Subnetwork Access Protocol"
    }

    fn short_name(&self) -> &'static str {
        "SNAP"
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
        if data.len() < SNAP_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: SNAP_HEADER_SIZE,
                actual: data.len(),
            });
        }
        let oui = u32::from_be_bytes([0, data[0], data[1], data[2]]);
        let pid = u16::from_be_bytes([data[3], data[4]]);

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + SNAP_HEADER_SIZE,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_OUI],
            FieldValue::U32(oui),
            offset..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PID],
            FieldValue::U16(pid),
            offset + 3..offset + 5,
        );
        buf.end_layer();

        // Protocol identifiers of other organizations (e.g. Cisco CDP/PVST+
        // under 00-00-0C) have no dissector yet.
        let next = if pid_is_ethertype(oui) {
            DispatchHint::ByEtherType(pid)
        } else {
            DispatchHint::End
        };
        Ok(DissectResult::new(SNAP_HEADER_SIZE, next))
    }
}

#[cfg(test)]
mod tests {
    //! # SNAP Coverage
    //!
    //! | Spec section              | Description                         | Test                       |
    //! |---------------------------|-------------------------------------|----------------------------|
    //! | RFC 1042 Header Format    | OUI 0, PID = EtherType              | snap_rfc1042_ipv4          |
    //! | IEEE 802.1H               | OUI 00-00-F8, PID = EtherType       | snap_bridge_tunnel         |
    //! | IEEE 802 clause 10        | Other OUI ends the chain            | snap_other_oui_ends_chain  |
    //! | RFC 1042 Header Format    | Truncated header                    | snap_truncated             |

    use super::*;

    #[test]
    fn snap_rfc1042_ipv4() {
        let data = [0x00, 0x00, 0x00, 0x08, 0x00, 0x45];
        let mut buf = DissectBuffer::new();
        let r = SnapDissector.dissect(&data, &mut buf, 17).unwrap();
        assert_eq!(r.bytes_consumed, 5);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x0800));
        let layer = buf.layer_by_name("SNAP").unwrap();
        assert_eq!(layer.range, 17..22);
        assert_eq!(
            buf.field_by_name(layer, "oui").unwrap().value,
            FieldValue::U32(0)
        );
        assert_eq!(buf.field_by_name(layer, "pid").unwrap().range, 20..22);
        assert_eq!(buf.resolve_display_name(layer, "pid_name"), Some("IPv4"));
    }

    #[test]
    fn snap_bridge_tunnel() {
        let data = [0x00, 0x00, 0xF8, 0x80, 0xF3];
        let mut buf = DissectBuffer::new();
        let r = SnapDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.next, DispatchHint::ByEtherType(0x80F3));
    }

    #[test]
    fn snap_other_oui_ends_chain() {
        // Cisco OUI 00-00-0C, PID 0x2000 (CDP).
        let data = [0x00, 0x00, 0x0C, 0x20, 0x00];
        let mut buf = DissectBuffer::new();
        let r = SnapDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.next, DispatchHint::End);
        let layer = buf.layer_by_name("SNAP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "oui").unwrap().value,
            FieldValue::U32(0x0C)
        );
        assert_eq!(buf.resolve_display_name(layer, "pid_name"), None);
    }

    #[test]
    fn snap_truncated() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            SnapDissector.dissect(&[0, 0, 0, 8], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 5,
                actual: 4
            })
        );
    }

    #[test]
    fn snap_metadata() {
        assert_eq!(SnapDissector.short_name(), "SNAP");
        assert!(!SnapDissector.name().is_empty());
        assert_eq!(SnapDissector.field_descriptors().len(), 2);
        assert!(!SnapDissector.references().is_empty());
        assert_eq!(SnapDissector.layer(), Some(ProtocolLayer::Link));
    }
}
