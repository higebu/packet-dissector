//! Linux cooked capture v1 (SLL) dissector.
//!
//! Parses the 16-byte pseudo-header prepended by the Linux kernel when
//! capturing on the "any" device (or any cooked-mode capture using
//! `LINKTYPE_LINUX_SLL = 113`).
//!
//! ## References
//! - LINKTYPE_LINUX_SLL: <https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html>
//! - Linux `sll.h`: <https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/sll.h>
//! - IEEE 802.2 LLC (protocol type 0x0004): <https://standards.ieee.org/ieee/802.2/1048/>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;
use packet_dissector_ethernet::llc::{self, LlcHeader};

/// SLL header size in bytes.
///
/// Layout (16 bytes total):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Packet Type           |          ARPHRD Type          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Link-layer Address Length  |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
/// |                    Link-layer Address (8)                     |
/// +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                               |        Protocol Type          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
const HEADER_SIZE: usize = 16;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_PACKET_TYPE: usize = 0;
const FD_ARPHRD_TYPE: usize = 1;
const FD_LL_ADDR_LEN: usize = 2;
const FD_LL_ADDR: usize = 3;
const FD_PROTOCOL_TYPE: usize = 4;
const FD_LLC_DSAP: usize = 5;
const FD_LLC_SSAP: usize = 6;
const FD_LLC_CONTROL: usize = 7;
const FD_LLC_CONTROL_EXT: usize = 8;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("packet_type", "Packet Type", FieldType::U16),
    FieldDescriptor::new("arphrd_type", "ARPHRD Type", FieldType::U16),
    FieldDescriptor::new("ll_addr_len", "Link-layer Address Length", FieldType::U16),
    FieldDescriptor::new("ll_addr", "Link-layer Address", FieldType::Bytes),
    FieldDescriptor::new("protocol_type", "Protocol Type", FieldType::U16),
    llc::DSAP_FIELD,
    llc::SSAP_FIELD,
    llc::CONTROL_FIELD,
    llc::CONTROL_EXT_FIELD,
];

/// ARPHRD_NETLINK: the payload is a LINKTYPE_NETLINK packet and the protocol
/// type is the Netlink protocol type (LINKTYPE_LINUX_SLL, Description).
const ARPHRD_NETLINK: u16 = 824;
/// ARPHRD_IEEE80211_RADIOTAP: the protocol type is ignored; Radiotap and an
/// 802.11 header follow (LINKTYPE_LINUX_SLL, Description).
const ARPHRD_IEEE80211_RADIOTAP: u16 = 803;
/// ARPHRD_FRAD: the protocol type is ignored; a Frame Relay LAPF frame
/// follows (LINKTYPE_LINUX_SLL, Description).
const ARPHRD_FRAD: u16 = 770;

/// Protocol type: "if the payload begins with an 802.2 LLC header"
/// (LINKTYPE_LINUX_SLL, Description).
const PROTOCOL_LLC: u16 = 0x0004;

/// Smallest protocol type value that is an EtherType. The special values
/// defined by LINKTYPE_LINUX_SLL (0x0001, 0x0003, 0x0004, 0x000C, 0x000D,
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

/// Classify the payload that follows the 16-octet header in `data`.
///
/// LINKTYPE_LINUX_SLL, Description: the ARPHRD_ type is checked first
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

/// Specification references for the Linux cooked capture v1 (SLL) dissector.
static REFERENCES: &[SpecReference] = &[SpecReference::new(
    "LINKTYPE_LINUX_SLL",
    "LINKTYPE_LINUX_SLL",
    "https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html",
)];

/// Linux cooked capture v1 (SLL) dissector.
///
/// Handles `LINKTYPE_LINUX_SLL` (113) frames.
pub struct LinuxSllDissector;

impl Dissector for LinuxSllDissector {
    fn name(&self) -> &'static str {
        "Linux cooked capture v1"
    }

    fn short_name(&self) -> &'static str {
        "SLL"
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
        let pkt_type = read_be_u16(data, 0)?;
        let arphrd_type = read_be_u16(data, 2)?;
        let ll_addr_len = read_be_u16(data, 4)?;
        // Link-layer address is 8 bytes on the wire, but only ll_addr_len bytes are meaningful.
        let meaningful_len = (ll_addr_len as usize).min(8);
        let ll_addr = &data[6..6 + meaningful_len];
        let protocol_type = read_be_u16(data, 14)?;

        let payload = classify_payload(data, arphrd_type, protocol_type)?;
        let llc = match payload {
            CookedPayload::Llc(llc) => Some(llc),
            _ => None,
        };
        let header_len = HEADER_SIZE + llc.map_or(0, |l| l.header_len());

        buf.begin_layer("SLL", None, FIELD_DESCRIPTORS, offset..offset + header_len);
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PACKET_TYPE],
            FieldValue::U16(pkt_type),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ARPHRD_TYPE],
            FieldValue::U16(arphrd_type),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LL_ADDR_LEN],
            FieldValue::U16(ll_addr_len),
            offset + 4..offset + 6,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LL_ADDR],
            FieldValue::Bytes(ll_addr),
            offset + 6..offset + 6 + meaningful_len,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PROTOCOL_TYPE],
            FieldValue::U16(protocol_type),
            offset + 14..offset + 16,
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
    //! # LINKTYPE_LINUX_SLL Coverage
    //!
    //! Spec: <https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html>
    //!
    //! | Spec Section           | Description              | Test                              |
    //! |------------------------|--------------------------|-----------------------------------|
    //! | Header format          | 16-byte header parsing   | parse_sll_ipv4                    |
    //! | Header format          | Offset handling          | parse_sll_with_offset             |
    //! | Header format          | Truncated input          | parse_sll_truncated               |
    //! | Header format          | Empty input              | parse_sll_empty_data              |
    //! | Packet type field      | All packet types         | parse_sll_multicast, parse_sll_otherhost, parse_sll_unknown_packet_type |
    //! | ARPHRD type field      | Various ARPHRD values    | parse_sll_unknown_arphrd, parse_sll_loopback |
    //! | Protocol type field    | EtherType dispatch       | parse_sll_ipv4, parse_sll_ipv6, parse_sll_arp |
    //! | Protocol type field    | Zero ends chain          | parse_sll_protocol_type_zero_ends_chain |
    //! | Protocol type field    | Unknown EtherType        | parse_sll_unknown_protocol_type   |
    //! | Protocol type 0x0004   | 802.2 LLC header follows | parse_sll_llc_stp, parse_sll_llc_i_frame, parse_sll_llc_truncated |
    //! | Protocol type values   | 0x0001/0x0003/CAN/DSA end the chain | parse_sll_special_protocol_values_end_chain |
    //! | ARPHRD_NETLINK/RADIOTAP/FRAD | Protocol type is not an EtherType | parse_sll_arphrd_non_ethertype_payloads |
    //! | ARPHRD_IPGRE/IP6GRE    | GRE protocol type dispatch | parse_sll_arphrd_ipgre         |
    //! | Link-layer address     | Range covers meaningful octets only | parse_sll_ll_addr_range   |

    use super::*;

    /// Build a minimal SLL header.
    fn build_sll_header(
        packet_type: u16,
        arphrd_type: u16,
        ll_addr: &[u8; 6],
        protocol_type: u16,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE);
        buf.extend_from_slice(&packet_type.to_be_bytes());
        buf.extend_from_slice(&arphrd_type.to_be_bytes());
        buf.extend_from_slice(&6u16.to_be_bytes()); // ll_addr_len = 6
        buf.extend_from_slice(ll_addr);
        buf.extend_from_slice(&[0u8; 2]); // pad to 8 bytes
        buf.extend_from_slice(&protocol_type.to_be_bytes());
        assert_eq!(buf.len(), HEADER_SIZE);
        buf
    }

    /// SLL header with protocol type 0x0004 followed by `llc`.
    fn build_sll_llc(llc: &[u8]) -> Vec<u8> {
        let mut data = build_sll_header(2, 1, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0x0004);
        data.extend_from_slice(llc);
        data
    }

    #[test]
    fn parse_sll_llc_stp() {
        let data = build_sll_llc(&[0x42, 0x42, 0x03, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        let r = LinuxSllDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, HEADER_SIZE + 3);
        assert_eq!(r.next, DispatchHint::ByLlcSap(0x42));
        let layer = buf.layer_by_name("SLL").unwrap();
        assert_eq!(layer.range, 0..19);
        assert_eq!(buf.field_u8(layer, "llc_dsap"), Some(0x42));
        assert_eq!(buf.field_u8(layer, "llc_ssap"), Some(0x42));
        assert_eq!(buf.field_u8(layer, "llc_control"), Some(0x03));
        assert!(buf.field_by_name(layer, "llc_control_ext").is_none());
        assert_eq!(
            buf.field_by_name(layer, "llc_control").unwrap().range,
            18..19
        );
    }

    #[test]
    fn parse_sll_llc_i_frame() {
        let data = build_sll_llc(&[0xF0, 0xF0, 0x00, 0x02, 0xAB]);
        let mut buf = DissectBuffer::new();
        let r = LinuxSllDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, HEADER_SIZE + 4);
        assert_eq!(r.next, DispatchHint::ByLlcSap(0xF0));
        let layer = buf.layer_by_name("SLL").unwrap();
        assert_eq!(buf.field_u8(layer, "llc_control_ext"), Some(0x02));
        assert_eq!(
            buf.field_by_name(layer, "llc_control_ext").unwrap().range,
            19..20
        );
    }

    #[test]
    fn parse_sll_llc_truncated() {
        let data = build_sll_llc(&[0x42, 0x42]);
        let mut buf = DissectBuffer::new();
        assert_eq!(
            LinuxSllDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 19,
                actual: 18
            })
        );
    }

    #[test]
    fn parse_sll_special_protocol_values_end_chain() {
        for proto in [
            0x0001, 0x0003, 0x0005, 0x000C, 0x000D, 0x000E, 0x00F8, 0x05FF,
        ] {
            let data = build_sll_header(0, 1, &[0; 6], proto);
            let mut buf = DissectBuffer::new();
            let r = LinuxSllDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(r.next, DispatchHint::End, "protocol {proto:#06x}");
            assert_eq!(r.bytes_consumed, HEADER_SIZE);
        }
    }

    #[test]
    fn parse_sll_arphrd_non_ethertype_payloads() {
        // ARPHRD_NETLINK: protocol type is a Netlink family (NETLINK_ROUTE = 0x0000
        // or others); ARPHRD_IEEE80211_RADIOTAP and ARPHRD_FRAD: ignored.
        for arphrd in [824, 803, 770] {
            let data = build_sll_header(0, arphrd, &[0; 6], 0x0800);
            let mut buf = DissectBuffer::new();
            let r = LinuxSllDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(r.next, DispatchHint::End, "arphrd {arphrd}");
        }
        // 0x0004 under ARPHRD_NETLINK is a Netlink family, not LLC.
        let data = build_sll_header(0, 824, &[0; 6], 0x0004);
        let mut buf = DissectBuffer::new();
        let r = LinuxSllDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, HEADER_SIZE);
        assert_eq!(r.next, DispatchHint::End);
    }

    #[test]
    fn parse_sll_arphrd_ipgre() {
        let data = build_sll_header(0, 778, &[0; 6], 0x0800);
        let mut buf = DissectBuffer::new();
        let r = LinuxSllDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.next, DispatchHint::ByEtherType(0x0800));
        let data = build_sll_header(0, 823, &[0; 6], 0x86DD);
        let mut buf = DissectBuffer::new();
        let r = LinuxSllDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn parse_sll_ll_addr_range() {
        let mut data = build_sll_header(0, 1, &[1, 2, 3, 4, 5, 6], 0x0800);
        let mut buf = DissectBuffer::new();
        LinuxSllDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("SLL").unwrap();
        assert_eq!(buf.field_by_name(layer, "ll_addr").unwrap().range, 6..12);

        data[5] = 0; // ll_addr_len = 0
        let mut buf = DissectBuffer::new();
        LinuxSllDissector.dissect(&data, &mut buf, 10).unwrap();
        let layer = buf.layer_by_name("SLL").unwrap();
        let f = buf.field_by_name(layer, "ll_addr").unwrap();
        assert_eq!(f.range, 16..16);
        assert_eq!(f.value, FieldValue::Bytes(&[]));

        data[5] = 20; // longer than the 8-octet slot
        let mut buf = DissectBuffer::new();
        LinuxSllDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("SLL").unwrap();
        assert_eq!(buf.field_by_name(layer, "ll_addr").unwrap().range, 6..14);
    }

    #[test]
    fn classify_payload_rules() {
        let mut data = build_sll_header(0, 1, &[0; 6], 0x0004);
        data.extend_from_slice(&[0x42, 0x42, 0x03]);
        assert_eq!(
            classify_payload(&data, 1, 0x0800),
            Ok(CookedPayload::EtherType(0x0800))
        );
        assert!(matches!(
            classify_payload(&data, 1, 0x0004),
            Ok(CookedPayload::Llc(l)) if l.dsap == 0x42
        ));
        assert_eq!(
            classify_payload(&data, 1, 0x0000),
            Ok(CookedPayload::Opaque)
        );
        assert_eq!(
            classify_payload(&data, 1, 0x0001),
            Ok(CookedPayload::Opaque)
        );
        assert_eq!(
            classify_payload(&data, 824, 0x0004),
            Ok(CookedPayload::Opaque)
        );
        assert_eq!(
            classify_payload(&data, 778, 0x6558),
            Ok(CookedPayload::EtherType(0x6558))
        );
    }

    #[test]
    fn parse_sll_ipv4() {
        let data = build_sll_header(0, 1, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 0x0800);
        let dissector = LinuxSllDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
        assert_eq!(buf.layers().len(), 1);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "SLL");
        assert_eq!(layer.range, 0..16);

        // Check packet_type
        let pt = buf.field_by_name(layer, "packet_type").unwrap();
        assert_eq!(pt.value, FieldValue::U16(0));

        // Check arphrd_type
        let arphrd = buf.field_by_name(layer, "arphrd_type").unwrap();
        assert_eq!(arphrd.value, FieldValue::U16(1));

        // Check ll_addr_len
        let ll_len = buf.field_by_name(layer, "ll_addr_len").unwrap();
        assert_eq!(ll_len.value, FieldValue::U16(6));

        // Check ll_addr
        let ll = buf.field_by_name(layer, "ll_addr").unwrap();
        assert_eq!(
            ll.value,
            FieldValue::Bytes(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );

        // Check protocol_type
        let proto = buf.field_by_name(layer, "protocol_type").unwrap();
        assert_eq!(proto.value, FieldValue::U16(0x0800));
    }

    #[test]
    fn parse_sll_ipv6() {
        let data = build_sll_header(4, 1, &[0; 6], 0x86DD);
        let dissector = LinuxSllDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn parse_sll_arp() {
        let data = build_sll_header(1, 1, &[0xff; 6], 0x0806);
        let dissector = LinuxSllDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::ByEtherType(0x0806));
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U16(1)
        );
    }

    #[test]
    fn parse_sll_with_offset() {
        let mut data = vec![0u8; 5]; // prefix padding
        data.extend_from_slice(&build_sll_header(0, 1, &[0x01; 6], 0x0800));
        let dissector = LinuxSllDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data[5..], &mut buf, 5).unwrap();

        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(buf.layers()[0].range, 5..21);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "protocol_type").unwrap().range,
            19..21
        );
    }

    #[test]
    fn parse_sll_truncated() {
        let data = [0u8; 15]; // 1 byte short
        let dissector = LinuxSllDissector;
        let mut buf = DissectBuffer::new();
        let err = dissector.dissect(&data, &mut buf, 0).unwrap_err();

        match err {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, HEADER_SIZE);
                assert_eq!(actual, 15);
            }
            _ => panic!("expected Truncated error, got {err:?}"),
        }
    }

    #[test]
    fn parse_sll_empty_data() {
        let data = [];
        let dissector = LinuxSllDissector;
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
    fn parse_sll_protocol_type_zero_ends_chain() {
        let data = build_sll_header(0, 1, &[0; 6], 0x0000);
        let dissector = LinuxSllDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn parse_sll_unknown_arphrd() {
        let data = build_sll_header(0, 9999, &[0; 6], 0x0800);
        let dissector = LinuxSllDissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "arphrd_type").unwrap().value,
            FieldValue::U16(9999)
        );
    }

    #[test]
    fn parse_sll_unknown_packet_type() {
        let data = build_sll_header(999, 1, &[0; 6], 0x0800);
        let dissector = LinuxSllDissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U16(999)
        );
    }

    #[test]
    fn parse_sll_loopback() {
        let data = build_sll_header(0, 772, &[0; 6], 0x0800);
        let dissector = LinuxSllDissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "arphrd_type").unwrap().value,
            FieldValue::U16(772)
        );
    }

    #[test]
    fn dissector_metadata() {
        let d = LinuxSllDissector;
        assert_eq!(d.name(), "Linux cooked capture v1");
        assert_eq!(d.short_name(), "SLL");
        assert_eq!(d.field_descriptors().len(), 9);
    }

    #[test]
    fn parse_sll_multicast() {
        let data = build_sll_header(2, 1, &[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01], 0x0800);
        let dissector = LinuxSllDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U16(2)
        );
    }

    #[test]
    fn parse_sll_otherhost() {
        let data = build_sll_header(3, 1, &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01], 0x0800);
        let dissector = LinuxSllDissector;
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U16(3)
        );
    }

    #[test]
    fn parse_sll_unknown_protocol_type() {
        let data = build_sll_header(0, 1, &[0; 6], 0x5678);
        let dissector = LinuxSllDissector;
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::ByEtherType(0x5678));
    }

    #[test]
    fn references_and_layer_are_populated() {
        let dissector = LinuxSllDissector;
        let references = dissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Link));
    }
}
