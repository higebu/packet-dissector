//! Linux cooked capture v2 (SLL2) dissector.
//!
//! Parses the 20-byte pseudo-header prepended by the Linux kernel when
//! capturing on the "any" device (or any cooked-mode capture using
//! `LINKTYPE_LINUX_SLL2 = 276`).
//!
//! ## References
//! - LINKTYPE_LINUX_SLL2: <https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html>
//! - Linux `sll.h`: <https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/sll.h>
//! - IEEE 802.2 LLC (protocol type 0x0004): <https://standards.ieee.org/ieee/802.2/1048/>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};
use packet_dissector_ethernet::llc::{self, LlcHeader};

/// SLL2 header size in bytes.
///
/// Layout (20 bytes total):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Protocol Type         |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Interface Index                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          ARPHRD Type          |  Packet Type  | LL Addr Len   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                    Link-layer Address (8)                     +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
const HEADER_SIZE: usize = 20;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_PROTOCOL_TYPE: usize = 0;
const FD_RESERVED: usize = 1;
const FD_INTERFACE_INDEX: usize = 2;
const FD_ARPHRD_TYPE: usize = 3;
const FD_PACKET_TYPE: usize = 4;
const FD_LL_ADDR_LEN: usize = 5;
const FD_LL_ADDR: usize = 6;
const FD_LLC_DSAP: usize = 7;
const FD_LLC_SSAP: usize = 8;
const FD_LLC_CONTROL: usize = 9;
const FD_LLC_CONTROL_EXT: usize = 10;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("protocol_type", "Protocol Type", FieldType::U16),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U16),
    FieldDescriptor::new("interface_index", "Interface Index", FieldType::U32),
    FieldDescriptor::new("arphrd_type", "ARPHRD Type", FieldType::U16),
    FieldDescriptor::new("packet_type", "Packet Type", FieldType::U8),
    FieldDescriptor::new("ll_addr_len", "Link-layer Address Length", FieldType::U8),
    FieldDescriptor::new("ll_addr", "Link-layer Address", FieldType::Bytes),
    llc::DSAP_FIELD,
    llc::SSAP_FIELD,
    llc::CONTROL_FIELD,
    llc::CONTROL_EXT_FIELD,
];

/// Specification references for the Linux cooked capture v2 (SLL2) dissector.
static REFERENCES: &[SpecReference] = &[SpecReference::new(
    "LINKTYPE_LINUX_SLL2",
    "LINKTYPE_LINUX_SLL2",
    "https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html",
)];

/// ARPHRD_NETLINK: the payload is a LINKTYPE_NETLINK packet and the protocol
/// type is the Netlink protocol type (LINKTYPE_LINUX_SLL2, Description).
const ARPHRD_NETLINK: u16 = 824;
/// ARPHRD_IEEE80211_RADIOTAP: the protocol type is ignored; Radiotap and an
/// 802.11 header follow (LINKTYPE_LINUX_SLL2, Description).
const ARPHRD_IEEE80211_RADIOTAP: u16 = 803;
/// ARPHRD_FRAD: the protocol type is ignored; a Frame Relay LAPF frame
/// follows (LINKTYPE_LINUX_SLL2, Description).
const ARPHRD_FRAD: u16 = 770;

/// Protocol type: "if the payload begins with an 802.2 LLC header"
/// (LINKTYPE_LINUX_SLL2, Description).
const PROTOCOL_LLC: u16 = 0x0004;

/// Smallest protocol type value that is an EtherType. The special values
/// defined by LINKTYPE_LINUX_SLL2 (0x0001, 0x0003, 0x0004, 0x000C, 0x000D,
/// 0x000E, 0x00F8) and the other Linux `ETH_P_*` pseudo protocol numbers
/// are below it (IEEE 802.3-2022, clause 3.2.6: EtherTypes are ≥ 0x0600).
const ETHERTYPE_MIN: u16 = 0x0600;

/// What the payload of the frame is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CookedPayload {
    /// The protocol type is an EtherType (or, for ARPHRD_IPGRE and
    /// ARPHRD_IP6GRE, a GRE protocol type, which uses EtherType values).
    EtherType(u16),
    /// The payload begins with this IEEE 802.2 LLC header (protocol type
    /// 0x0004).
    Llc(LlcHeader),
    /// A payload without a dissector reachable from the protocol type:
    /// Netlink, Radiotap, Frame Relay, Novell raw 802.3, CAN, DSA, ….
    Opaque,
}

/// Classify the payload that follows the 20-octet header in `data`.
///
/// LINKTYPE_LINUX_SLL2, Description: the ARPHRD_ type is checked first
/// (NETLINK, IEEE80211_RADIOTAP and FRAD give the protocol type another
/// meaning), then the protocol type special values, then the EtherType.
fn classify_payload(
    data: &[u8],
    arphrd_type: u16,
    protocol_type: u16,
) -> Result<CookedPayload, PacketError> {
    Ok(match arphrd_type {
        ARPHRD_NETLINK | ARPHRD_IEEE80211_RADIOTAP | ARPHRD_FRAD => CookedPayload::Opaque,
        _ if protocol_type == PROTOCOL_LLC => {
            CookedPayload::Llc(LlcHeader::parse_at(data, HEADER_SIZE, data.len())?)
        }
        _ if protocol_type < ETHERTYPE_MIN => CookedPayload::Opaque,
        _ => CookedPayload::EtherType(protocol_type),
    })
}

/// Linux cooked capture v2 (SLL2) dissector.
///
/// Handles `LINKTYPE_LINUX_SLL2` (276) frames.
pub struct LinuxSll2Dissector;

impl Dissector for LinuxSll2Dissector {
    fn name(&self) -> &'static str {
        "Linux cooked capture v2"
    }

    fn short_name(&self) -> &'static str {
        "SLL2"
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
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        // Parse fields (all big-endian / network byte order)
        let protocol_type = read_be_u16(data, 0)?;
        let reserved = read_be_u16(data, 2)?;
        let interface_index = read_be_u32(data, 4)?;
        let arphrd_type = read_be_u16(data, 8)?;
        let pkt_type = data[10];
        let ll_addr_len = data[11];
        // Link-layer address is 8 bytes on the wire, but only ll_addr_len bytes are meaningful.
        let meaningful_len = (ll_addr_len as usize).min(8);
        let ll_addr = &data[12..12 + meaningful_len];

        // LINKTYPE_LINUX_SLL2, Description — ARPHRD_ type first, then the
        // protocol type special values, then the EtherType.
        let payload = classify_payload(data, arphrd_type, protocol_type)?;
        let llc = match payload {
            CookedPayload::Llc(llc) => Some(llc),
            _ => None,
        };
        let header_len = HEADER_SIZE + llc.map_or(0, |l| l.header_len());

        buf.begin_layer("SLL2", None, FIELD_DESCRIPTORS, offset..offset + header_len);
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PROTOCOL_TYPE],
            FieldValue::U16(protocol_type),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_RESERVED],
            FieldValue::U16(reserved),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_INTERFACE_INDEX],
            FieldValue::U32(interface_index),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ARPHRD_TYPE],
            FieldValue::U16(arphrd_type),
            offset + 8..offset + 10,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PACKET_TYPE],
            FieldValue::U8(pkt_type),
            offset + 10..offset + 11,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LL_ADDR_LEN],
            FieldValue::U8(ll_addr_len),
            offset + 11..offset + 12,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LL_ADDR],
            FieldValue::Bytes(ll_addr),
            offset + 12..offset + 12 + meaningful_len,
        );
        if let Some(llc) = &llc {
            llc.push_fields(
                buf,
                [
                    &FIELD_DESCRIPTORS[FD_LLC_DSAP],
                    &FIELD_DESCRIPTORS[FD_LLC_SSAP],
                    &FIELD_DESCRIPTORS[FD_LLC_CONTROL],
                    &FIELD_DESCRIPTORS[FD_LLC_CONTROL_EXT],
                ],
                offset + HEADER_SIZE,
            );
        }
        buf.end_layer();

        let next = match payload {
            CookedPayload::EtherType(t) => DispatchHint::ByEtherType(t),
            CookedPayload::Llc(llc) => llc.next_hint(),
            CookedPayload::Opaque => DispatchHint::End,
        };

        Ok(DissectResult::new(header_len, next))
    }
}

#[cfg(test)]
mod tests {
    //! # LINKTYPE_LINUX_SLL2 Coverage
    //!
    //! Spec: <https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html>
    //!
    //! | Spec Section           | Description              | Test                              |
    //! |------------------------|--------------------------|-----------------------------------|
    //! | Header format          | 20-byte header parsing   | parse_sll2_ipv4                   |
    //! | Header format          | Offset handling          | parse_sll2_with_offset            |
    //! | Header format          | Truncated input          | parse_sll2_truncated              |
    //! | Header format          | Empty input              | parse_sll2_empty_data             |
    //! | Packet type field      | All packet types         | parse_sll2_multicast_packet, parse_sll2_otherhost_packet, parse_sll2_unknown_packet_type |
    //! | ARPHRD type field      | Various ARPHRD values    | parse_sll2_unknown_arphrd, parse_sll2_loopback_interface |
    //! | Interface index field  | Interface index parsing  | parse_sll2_ipv4, parse_sll2_with_offset |
    //! | Protocol type field    | EtherType dispatch       | parse_sll2_ipv4, parse_sll2_ipv6, parse_sll2_arp |
    //! | Protocol type field    | Zero ends chain          | parse_sll2_protocol_type_zero_ends_chain |
    //! | Protocol type field    | Unknown EtherType        | parse_sll2_unknown_protocol_type  |
    //! | Protocol type 0x0004   | 802.2 LLC header follows | parse_sll2_llc_snap, parse_sll2_llc_truncated |
    //! | Protocol type values   | 0x0001/0x0003/CAN/DSA end the chain | parse_sll2_special_values_and_arphrd |
    //! | ARPHRD_NETLINK/RADIOTAP/FRAD | Protocol type is not an EtherType | parse_sll2_special_values_and_arphrd |
    //! | Link-layer address     | Range covers meaningful octets only | parse_sll2_ll_addr_range |

    use super::*;

    /// Build a minimal SLL2 header.
    fn build_sll2_header(
        protocol_type: u16,
        interface_index: u32,
        arphrd_type: u16,
        packet_type: u8,
        ll_addr: &[u8; 6],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE);
        buf.extend_from_slice(&protocol_type.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // reserved
        buf.extend_from_slice(&interface_index.to_be_bytes());
        buf.extend_from_slice(&arphrd_type.to_be_bytes());
        buf.push(packet_type);
        buf.push(6); // ll_addr_len = 6 (Ethernet)
        buf.extend_from_slice(ll_addr);
        buf.extend_from_slice(&[0u8; 2]); // pad to 8 bytes
        assert_eq!(buf.len(), HEADER_SIZE);
        buf
    }

    #[test]
    fn parse_sll2_ipv4() {
        let data = build_sll2_header(0x0800, 1, 1, 0, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let dissector = LinuxSll2Dissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
        assert_eq!(buf.layers().len(), 1);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "SLL2");
        assert_eq!(layer.range, 0..20);

        // Check protocol_type field
        let pt = buf.field_by_name(layer, "protocol_type").unwrap();
        assert_eq!(pt.value, FieldValue::U16(0x0800));

        // Check interface_index
        let iface = buf.field_by_name(layer, "interface_index").unwrap();
        assert_eq!(iface.value, FieldValue::U32(1));

        // Check arphrd_type
        let arphrd = buf.field_by_name(layer, "arphrd_type").unwrap();
        assert_eq!(arphrd.value, FieldValue::U16(1));

        // Check packet_type
        let ptype = buf.field_by_name(layer, "packet_type").unwrap();
        assert_eq!(ptype.value, FieldValue::U8(0));

        // Check ll_addr_len
        let ll_len = buf.field_by_name(layer, "ll_addr_len").unwrap();
        assert_eq!(ll_len.value, FieldValue::U8(6));

        // Check ll_addr
        let ll = buf.field_by_name(layer, "ll_addr").unwrap();
        assert_eq!(
            ll.value,
            FieldValue::Bytes(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn parse_sll2_ipv6() {
        let data = build_sll2_header(0x86DD, 2, 1, 4, &[0x00; 6]);
        let dissector = LinuxSll2Dissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "protocol_type").unwrap().value,
            FieldValue::U16(0x86DD)
        );
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U8(4)
        );
    }

    #[test]
    fn parse_sll2_arp() {
        let data = build_sll2_header(0x0806, 0, 1, 1, &[0xff; 6]);
        let dissector = LinuxSll2Dissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::ByEtherType(0x0806));
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_sll2_with_offset() {
        let mut data = vec![0u8; 10]; // prefix padding
        data.extend_from_slice(&build_sll2_header(0x0800, 3, 772, 2, &[0x01; 6]));
        let dissector = LinuxSll2Dissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data[10..], &mut buf, 10).unwrap();

        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(buf.layers()[0].range, 10..30);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "protocol_type").unwrap().range,
            10..12
        );
    }

    #[test]
    fn parse_sll2_truncated() {
        let data = [0u8; 19]; // 1 byte short
        let dissector = LinuxSll2Dissector;
        let mut buf = DissectBuffer::new();
        let err = dissector.dissect(&data, &mut buf, 0).unwrap_err();

        match err {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, HEADER_SIZE);
                assert_eq!(actual, 19);
            }
            _ => panic!("expected Truncated error, got {err:?}"),
        }
    }

    #[test]
    fn parse_sll2_empty_data() {
        let data = [];
        let dissector = LinuxSll2Dissector;
        let mut buf = DissectBuffer::new();
        let err = dissector.dissect(&data, &mut buf, 0).unwrap_err();

        match err {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, HEADER_SIZE);
                assert_eq!(actual, 0);
            }
            _ => panic!("expected Truncated error, got {err:?}"),
        }
    }

    #[test]
    fn parse_sll2_protocol_type_zero_ends_chain() {
        let data = build_sll2_header(0x0000, 0, 1, 0, &[0; 6]);
        let dissector = LinuxSll2Dissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn parse_sll2_unknown_arphrd() {
        let data = build_sll2_header(0x0800, 0, 9999, 0, &[0; 6]);
        let dissector = LinuxSll2Dissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "arphrd_type").unwrap().value,
            FieldValue::U16(9999)
        );
    }

    #[test]
    fn parse_sll2_unknown_packet_type() {
        let data = build_sll2_header(0x0800, 0, 1, 255, &[0; 6]);
        let dissector = LinuxSll2Dissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U8(255)
        );
    }

    #[test]
    fn parse_sll2_loopback_interface() {
        let data = build_sll2_header(0x0800, 1, 772, 0, &[0; 6]);
        let dissector = LinuxSll2Dissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "arphrd_type").unwrap().value,
            FieldValue::U16(772)
        );
    }

    #[test]
    fn parse_sll2_llc_snap() {
        let mut data = build_sll2_header(0x0004, 3, 1, 0, &[0; 6]);
        data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
        let mut buf = DissectBuffer::new();
        let r = LinuxSll2Dissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, HEADER_SIZE + 3);
        assert_eq!(r.next, DispatchHint::ByLlcSap(0xAA));
        let layer = buf.layer_by_name("SLL2").unwrap();
        assert_eq!(layer.range, 0..23);
        assert_eq!(buf.field_u8(layer, "llc_dsap"), Some(0xAA));
        assert_eq!(buf.field_u8(layer, "llc_control"), Some(0x03));
        assert_eq!(buf.field_by_name(layer, "llc_dsap").unwrap().range, 20..21);

        let mut data = build_sll2_header(0x0004, 3, 1, 0, &[0; 6]);
        data.extend_from_slice(&[0xF0, 0xF0, 0x01, 0x03]);
        let mut buf = DissectBuffer::new();
        let r = LinuxSll2Dissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, HEADER_SIZE + 4);
        assert_eq!(r.next, DispatchHint::End);
        let layer = buf.layer_by_name("SLL2").unwrap();
        assert_eq!(buf.field_u8(layer, "llc_control_ext"), Some(0x03));
    }

    #[test]
    fn parse_sll2_llc_truncated() {
        let mut data = build_sll2_header(0x0004, 3, 1, 0, &[0; 6]);
        data.push(0x42);
        let mut buf = DissectBuffer::new();
        assert_eq!(
            LinuxSll2Dissector.dissect(&data, &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 23,
                actual: 21
            })
        );
    }

    #[test]
    fn parse_sll2_special_values_and_arphrd() {
        for proto in [0x0001, 0x0003, 0x000C, 0x000D, 0x000E, 0x00F8] {
            let data = build_sll2_header(proto, 0, 1, 0, &[0; 6]);
            let mut buf = DissectBuffer::new();
            let r = LinuxSll2Dissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(r.next, DispatchHint::End, "protocol {proto:#06x}");
        }
        for arphrd in [824, 803, 770] {
            let data = build_sll2_header(0x0800, 0, arphrd, 0, &[0; 6]);
            let mut buf = DissectBuffer::new();
            let r = LinuxSll2Dissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(r.next, DispatchHint::End, "arphrd {arphrd}");
        }
        let data = build_sll2_header(0x86DD, 0, 823, 0, &[0; 6]);
        let mut buf = DissectBuffer::new();
        let r = LinuxSll2Dissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn parse_sll2_ll_addr_range() {
        let mut data = build_sll2_header(0x0800, 0, 1, 0, &[1, 2, 3, 4, 5, 6]);
        let mut buf = DissectBuffer::new();
        LinuxSll2Dissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("SLL2").unwrap();
        assert_eq!(buf.field_by_name(layer, "ll_addr").unwrap().range, 12..18);

        data[11] = 0;
        let mut buf = DissectBuffer::new();
        LinuxSll2Dissector.dissect(&data, &mut buf, 4).unwrap();
        let layer = buf.layer_by_name("SLL2").unwrap();
        assert_eq!(buf.field_by_name(layer, "ll_addr").unwrap().range, 16..16);
    }

    #[test]
    fn dissector_metadata() {
        let d = LinuxSll2Dissector;
        assert_eq!(d.name(), "Linux cooked capture v2");
        assert_eq!(d.short_name(), "SLL2");
        assert_eq!(d.field_descriptors().len(), 11);
    }

    #[test]
    fn parse_sll2_multicast_packet() {
        let data = build_sll2_header(0x0800, 5, 1, 2, &[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
        let dissector = LinuxSll2Dissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U8(2)
        );
    }

    #[test]
    fn parse_sll2_otherhost_packet() {
        let data = build_sll2_header(0x0800, 0, 1, 3, &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        let dissector = LinuxSll2Dissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
    }

    #[test]
    fn parse_sll2_unknown_protocol_type() {
        let data = build_sll2_header(0x1234, 0, 1, 0, &[0; 6]);
        let dissector = LinuxSll2Dissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::ByEtherType(0x1234));
    }

    #[test]
    fn references_and_layer_are_populated() {
        let dissector = LinuxSll2Dissector;
        let references = dissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Link));
    }
}
