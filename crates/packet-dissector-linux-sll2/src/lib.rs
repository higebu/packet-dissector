//! Linux cooked capture v2 (SLL2) dissector.
//!
//! Parses the 20-byte pseudo-header prepended by the Linux kernel when
//! capturing on the "any" device (or any cooked-mode capture using
//! `LINKTYPE_LINUX_SLL2 = 276`).
//!
//! ## References
//! - LINKTYPE_LINUX_SLL2: <https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html>
//! - Linux `sll.h`: <https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/sll.h>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

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

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("protocol_type", "Protocol Type", FieldType::U16),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U16),
    FieldDescriptor::new("interface_index", "Interface Index", FieldType::U32),
    FieldDescriptor::new("arphrd_type", "ARPHRD Type", FieldType::U16),
    FieldDescriptor::new("packet_type", "Packet Type", FieldType::U8),
    FieldDescriptor::new("ll_addr_len", "Link-layer Address Length", FieldType::U8),
    FieldDescriptor::new("ll_addr", "Link-layer Address", FieldType::Bytes),
];

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
        let ll_addr = &data[12..20];
        let meaningful_len = (ll_addr_len as usize).min(8);

        buf.begin_layer(
            "SLL2",
            None,
            FIELD_DESCRIPTORS,
            offset..offset + HEADER_SIZE,
        );
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
            FieldValue::Bytes(&ll_addr[..meaningful_len]),
            offset + 12..offset + 20,
        );
        buf.end_layer();

        // Dispatch based on the protocol type field (EtherType).
        let next = if protocol_type == 0 {
            DispatchHint::End
        } else {
            DispatchHint::ByEtherType(protocol_type)
        };

        Ok(DissectResult::new(HEADER_SIZE, next))
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
    fn dissector_metadata() {
        let d = LinuxSll2Dissector;
        assert_eq!(d.name(), "Linux cooked capture v2");
        assert_eq!(d.short_name(), "SLL2");
        assert_eq!(d.field_descriptors().len(), 7);
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
}
