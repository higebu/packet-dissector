//! Linux cooked capture v1 (SLL) dissector.
//!
//! Parses the 16-byte pseudo-header prepended by the Linux kernel when
//! capturing on the "any" device (or any cooked-mode capture using
//! `LINKTYPE_LINUX_SLL = 113`).
//!
//! ## References
//! - LINKTYPE_LINUX_SLL: <https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html>
//! - Linux `sll.h`: <https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/sll.h>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

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

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("packet_type", "Packet Type", FieldType::U16),
    FieldDescriptor::new("arphrd_type", "ARPHRD Type", FieldType::U16),
    FieldDescriptor::new("ll_addr_len", "Link-layer Address Length", FieldType::U16),
    FieldDescriptor::new("ll_addr", "Link-layer Address", FieldType::Bytes),
    FieldDescriptor::new("protocol_type", "Protocol Type", FieldType::U16),
];

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
        let ll_addr = &data[6..14];
        let meaningful_len = (ll_addr_len as usize).min(8);
        let protocol_type = read_be_u16(data, 14)?;

        buf.begin_layer("SLL", None, FIELD_DESCRIPTORS, offset..offset + HEADER_SIZE);
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
            FieldValue::Bytes(&ll_addr[..meaningful_len]),
            offset + 6..offset + 14,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PROTOCOL_TYPE],
            FieldValue::U16(protocol_type),
            offset + 14..offset + 16,
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
        assert_eq!(d.field_descriptors().len(), 5);
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
}
