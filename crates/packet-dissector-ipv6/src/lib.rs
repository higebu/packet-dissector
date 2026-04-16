//! IPv6 (Internet Protocol version 6) dissector with extension header support.
//!
//! ## References
//! - RFC 8200: Internet Protocol, Version 6 (IPv6) Specification:
//!   <https://www.rfc-editor.org/rfc/rfc8200>
//!   - Section 3: IPv6 Header Format
//!     <https://www.rfc-editor.org/rfc/rfc8200#section-3>
//!   - Section 4: IPv6 Extension Headers
//!     <https://www.rfc-editor.org/rfc/rfc8200#section-4>
//!   - Section 4.3: Hop-by-Hop Options Header
//!     <https://www.rfc-editor.org/rfc/rfc8200#section-4.3>
//!   - Section 4.4: Routing Header
//!     <https://www.rfc-editor.org/rfc/rfc8200#section-4.4>
//!   - Section 4.5: Fragment Header
//!     <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>
//!   - Section 4.6: Destination Options Header
//!     <https://www.rfc-editor.org/rfc/rfc8200#section-4.6>
//! - RFC 9673 (updates RFC 8200 Hop-by-Hop processing procedures):
//!   <https://www.rfc-editor.org/rfc/rfc9673>
//! - RFC 6275, Section 6.1: Mobility Header:
//!   <https://www.rfc-editor.org/rfc/rfc6275#section-6.1>

#![deny(missing_docs)]

mod ext;

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::lookup::ip_protocol_name;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_ipv6_addr};

pub use ext::{
    DestinationOptionsDissector, FragmentDissector, GenericRoutingDissector, HopByHopDissector,
    MobilityDissector, RoutingDissector,
};

/// IPv6 fixed header size.
///
/// RFC 8200, Section 3: <https://www.rfc-editor.org/rfc/rfc8200#section-3>
const HEADER_SIZE: usize = 40;

/// Expected IP version for IPv6.
///
/// RFC 8200, Section 3: <https://www.rfc-editor.org/rfc/rfc8200#section-3>
const IPV6_VERSION: u8 = 6;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_VERSION: usize = 0;
const FD_TRAFFIC_CLASS: usize = 1;
const FD_FLOW_LABEL: usize = 2;
const FD_PAYLOAD_LENGTH: usize = 3;
const FD_NEXT_HEADER: usize = 4;
const FD_HOP_LIMIT: usize = 5;
const FD_SRC: usize = 6;
const FD_DST: usize = 7;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 8200, Section 3 — Version (4-bit IP version number = 6)
    // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
    FieldDescriptor::new("version", "Version", FieldType::U8),
    // RFC 8200, Section 3 — Traffic Class (8-bit, see Section 7)
    // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
    FieldDescriptor::new("traffic_class", "Traffic Class", FieldType::U8),
    // RFC 8200, Section 3 — Flow Label (20-bit, see Section 6)
    // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
    FieldDescriptor::new("flow_label", "Flow Label", FieldType::U32),
    // RFC 8200, Section 3 — Payload Length (16-bit unsigned integer)
    // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
    FieldDescriptor::new("payload_length", "Payload Length", FieldType::U16),
    // RFC 8200, Section 3 — Next Header (8-bit selector, IANA Protocol Numbers)
    // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
    FieldDescriptor {
        name: "next_header",
        display_name: "Next Header",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(p) => ip_protocol_name(*p),
            _ => None,
        }),
        format_fn: None,
    },
    // RFC 8200, Section 3 — Hop Limit (8-bit unsigned integer)
    // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
    FieldDescriptor::new("hop_limit", "Hop Limit", FieldType::U8),
    // RFC 8200, Section 3 — Source Address (128-bit, see RFC 4291)
    // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
    FieldDescriptor::new("src", "Source Address", FieldType::Ipv6Addr),
    // RFC 8200, Section 3 — Destination Address (128-bit, see RFC 4291)
    // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
    FieldDescriptor::new("dst", "Destination Address", FieldType::Ipv6Addr),
];

/// IPv6 dissector.
pub struct Ipv6Dissector;

impl Dissector for Ipv6Dissector {
    fn name(&self) -> &'static str {
        "Internet Protocol version 6"
    }

    fn short_name(&self) -> &'static str {
        "IPv6"
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

        // RFC 8200, Section 3 — IPv6 Header Format
        // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
        let version = (data[0] >> 4) & 0x0F;

        // RFC 8200, Section 3 — Version must be 6
        // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
        if version != IPV6_VERSION {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: version as u32,
            });
        }
        // RFC 8200, Section 3 — Traffic Class spans low 4 bits of byte 0 and
        // high 4 bits of byte 1.
        // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
        let traffic_class = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);
        // RFC 8200, Section 3 — Flow Label is 20 bits: low 4 bits of byte 1
        // concatenated with bytes 2 and 3.
        // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
        let flow_label =
            ((data[1] as u32 & 0x0F) << 16) | ((data[2] as u32) << 8) | (data[3] as u32);

        let payload_length = read_be_u16(data, 4)?;
        let next_header = data[6];
        let hop_limit = data[7];

        let src = read_ipv6_addr(data, 8)?;
        let dst = read_ipv6_addr(data, 24)?;

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + HEADER_SIZE,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TRAFFIC_CLASS],
            FieldValue::U8(traffic_class),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLOW_LABEL],
            FieldValue::U32(flow_label),
            offset + 1..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PAYLOAD_LENGTH],
            FieldValue::U16(payload_length),
            offset + 4..offset + 6,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_NEXT_HEADER],
            FieldValue::U8(next_header),
            offset + 6..offset + 7,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HOP_LIMIT],
            FieldValue::U8(hop_limit),
            offset + 7..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SRC],
            FieldValue::Ipv6Addr(src),
            offset + 8..offset + 24,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DST],
            FieldValue::Ipv6Addr(dst),
            offset + 24..offset + 40,
        );
        buf.end_layer();

        Ok(DissectResult::new(
            HEADER_SIZE,
            DispatchHint::ByIpProtocol(next_header),
        ))
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 8200 (IPv6) Coverage — fixed header
    //!
    //! | RFC Section | Description                  | Test                                    |
    //! |-------------|------------------------------|-----------------------------------------|
    //! | 3           | Header Format                | parse_ipv6_basic                        |
    //! | 3           | Version (must be 6)          | parse_ipv6_basic, invalid_version       |
    //! | 3           | Traffic Class bit packing    | traffic_class_and_flow_label            |
    //! | 3           | Flow Label bit packing       | traffic_class_and_flow_label            |
    //! | 3           | Max Traffic Class/Flow Label | traffic_class_and_flow_label_max        |
    //! | 3           | Payload Length               | parse_ipv6_basic                        |
    //! | 3           | Next Header (dispatch)       | parse_ipv6_basic, dispatch_next_header  |
    //! | 3           | Hop Limit                    | parse_ipv6_basic                        |
    //! | 3           | Source / Destination Address | parse_ipv6_basic                        |
    //! | 3           | Field ranges with offset     | offset_applied_correctly                |
    //! | —           | Truncated header             | truncated_header                        |
    //! | —           | Empty buffer                 | empty_buffer_truncated                  |
    //! | —           | Dissector metadata           | dissector_metadata                      |
    //! | —           | Field descriptors            | field_descriptors_match                 |
    //! | —           | Next Header name lookup      | next_header_name_lookup                 |
    //! | —           | Payload Length = 0 (Jumbo)   | payload_length_zero_is_accepted         |
    //! | —           | Hop Limit = 0                | hop_limit_zero_is_accepted              |
    //! | —           | Field count                  | field_descriptors_count                 |

    use super::*;

    /// Build a minimal IPv6 header (40 bytes, no extension headers).
    fn build_ipv6_header(
        traffic_class: u8,
        flow_label: u32,
        payload_length: u16,
        next_header: u8,
        hop_limit: u8,
        src: [u8; 16],
        dst: [u8; 16],
    ) -> Vec<u8> {
        assert!(flow_label <= 0xF_FFFF, "Flow Label is 20 bits");
        let mut pkt = vec![0u8; HEADER_SIZE];
        // RFC 8200, Section 3 — Version(4) | Traffic Class(8) | Flow Label(20)
        // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
        pkt[0] = (IPV6_VERSION << 4) | ((traffic_class >> 4) & 0x0F);
        pkt[1] = ((traffic_class & 0x0F) << 4) | (((flow_label >> 16) & 0x0F) as u8);
        pkt[2] = ((flow_label >> 8) & 0xFF) as u8;
        pkt[3] = (flow_label & 0xFF) as u8;
        pkt[4..6].copy_from_slice(&payload_length.to_be_bytes());
        pkt[6] = next_header;
        pkt[7] = hop_limit;
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        pkt
    }

    #[test]
    fn parse_ipv6_basic() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let data = build_ipv6_header(0, 0, 20, 6, 64, src, dst);

        let mut buf = DissectBuffer::new();
        let result = Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

        let layer = buf.layer_by_name("IPv6").unwrap();
        assert_eq!(layer.range, 0..HEADER_SIZE);
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(6)
        );
        assert_eq!(
            buf.field_by_name(layer, "traffic_class").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "flow_label").unwrap().value,
            FieldValue::U32(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "payload_length").unwrap().value,
            FieldValue::U16(20)
        );
        assert_eq!(
            buf.field_by_name(layer, "next_header").unwrap().value,
            FieldValue::U8(6)
        );
        assert_eq!(
            buf.field_by_name(layer, "hop_limit").unwrap().value,
            FieldValue::U8(64)
        );
        assert_eq!(
            buf.field_by_name(layer, "src").unwrap().value,
            FieldValue::Ipv6Addr(src)
        );
        assert_eq!(
            buf.field_by_name(layer, "dst").unwrap().value,
            FieldValue::Ipv6Addr(dst)
        );

        // Field byte ranges (RFC 8200, Section 3).
        assert_eq!(buf.field_by_name(layer, "version").unwrap().range, 0..1);
        assert_eq!(
            buf.field_by_name(layer, "traffic_class").unwrap().range,
            0..2
        );
        assert_eq!(buf.field_by_name(layer, "flow_label").unwrap().range, 1..4);
        assert_eq!(
            buf.field_by_name(layer, "payload_length").unwrap().range,
            4..6
        );
        assert_eq!(buf.field_by_name(layer, "next_header").unwrap().range, 6..7);
        assert_eq!(buf.field_by_name(layer, "hop_limit").unwrap().range, 7..8);
        assert_eq!(buf.field_by_name(layer, "src").unwrap().range, 8..24);
        assert_eq!(buf.field_by_name(layer, "dst").unwrap().range, 24..40);
    }

    #[test]
    fn traffic_class_and_flow_label() {
        // RFC 8200, Section 3 — Version=6, Traffic Class=0xAB, Flow Label=0xCDEF0.
        // Byte 0: 0110 1010  (version=6, TC high 4 bits=0xA)
        // Byte 1: 1011 1100  (TC low 4 bits=0xB, FL high 4 bits=0xC)
        // Byte 2: 0xDE
        // Byte 3: 0xF0
        let data = build_ipv6_header(0xAB, 0xC_DEF0, 0, 6, 64, [0; 16], [0; 16]);
        assert_eq!(data[0], 0x6A);
        assert_eq!(data[1], 0xBC);
        assert_eq!(data[2], 0xDE);
        assert_eq!(data[3], 0xF0);

        let mut buf = DissectBuffer::new();
        Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("IPv6").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "traffic_class").unwrap().value,
            FieldValue::U8(0xAB)
        );
        assert_eq!(
            buf.field_by_name(layer, "flow_label").unwrap().value,
            FieldValue::U32(0xC_DEF0)
        );
    }

    #[test]
    fn traffic_class_and_flow_label_max() {
        // All Traffic Class bits (0xFF) and all Flow Label bits (0xF_FFFF) set.
        let data = build_ipv6_header(0xFF, 0xF_FFFF, 0, 6, 64, [0; 16], [0; 16]);
        let mut buf = DissectBuffer::new();
        Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("IPv6").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(6)
        );
        assert_eq!(
            buf.field_by_name(layer, "traffic_class").unwrap().value,
            FieldValue::U8(0xFF)
        );
        assert_eq!(
            buf.field_by_name(layer, "flow_label").unwrap().value,
            FieldValue::U32(0xF_FFFF)
        );
    }

    #[test]
    fn invalid_version() {
        // RFC 8200, Section 3 — Version must be 6.
        let mut data = build_ipv6_header(0, 0, 0, 6, 64, [0; 16], [0; 16]);
        data[0] = 0x40; // Version=4 (IPv4)
        let mut buf = DissectBuffer::new();
        let err = Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "version",
                value: 4,
            }
        ));
    }

    #[test]
    fn truncated_header() {
        // RFC 8200, Section 3 — Fixed header is 40 bytes.
        let data = [0x60u8; 39]; // 1 byte short.
        let mut buf = DissectBuffer::new();
        let err = Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 40,
                actual: 39,
            }
        ));
    }

    #[test]
    fn empty_buffer_truncated() {
        let mut buf = DissectBuffer::new();
        let err = Ipv6Dissector.dissect(&[], &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 40,
                actual: 0,
            }
        ));
    }

    #[test]
    fn offset_applied_correctly() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let data = build_ipv6_header(0, 0, 0, 6, 64, src, dst);

        let mut buf = DissectBuffer::new();
        Ipv6Dissector.dissect(&data, &mut buf, 14).unwrap();

        let layer = buf.layer_by_name("IPv6").unwrap();
        assert_eq!(layer.range, 14..54);
        assert_eq!(buf.field_by_name(layer, "src").unwrap().range, 22..38);
        assert_eq!(buf.field_by_name(layer, "dst").unwrap().range, 38..54);
    }

    #[test]
    fn dispatch_next_header() {
        // Next Header must dispatch to the declared IP protocol number.
        for proto in [6u8, 17, 58, 59, 44, 43, 0, 60, 135] {
            let data = build_ipv6_header(0, 0, 0, proto, 64, [0; 16], [0; 16]);
            let mut buf = DissectBuffer::new();
            let result = Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(result.next, DispatchHint::ByIpProtocol(proto));
        }
    }

    #[test]
    fn payload_length_zero_is_accepted() {
        // RFC 2675 Jumbograms use Payload Length=0; the dissector must not
        // reject this.
        let data = build_ipv6_header(0, 0, 0, 6, 64, [0; 16], [0; 16]);
        let mut buf = DissectBuffer::new();
        assert!(Ipv6Dissector.dissect(&data, &mut buf, 0).is_ok());
    }

    #[test]
    fn hop_limit_zero_is_accepted() {
        // RFC 8200, Section 3 — a destination node SHOULD process a Hop
        // Limit=0 packet normally; the dissector must accept it.
        let data = build_ipv6_header(0, 0, 0, 6, 0, [0; 16], [0; 16]);
        let mut buf = DissectBuffer::new();
        Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("IPv6").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "hop_limit").unwrap().value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn next_header_name_lookup() {
        // Next Header display_fn resolves the IANA protocol name (TCP=6).
        let data = build_ipv6_header(0, 0, 0, 6, 64, [0; 16], [0; 16]);
        let mut buf = DissectBuffer::new();
        Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("IPv6").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "next_header_name"),
            Some("TCP")
        );
    }

    #[test]
    fn dissector_metadata() {
        let d = Ipv6Dissector;
        assert_eq!(d.name(), "Internet Protocol version 6");
        assert_eq!(d.short_name(), "IPv6");
    }

    #[test]
    fn field_descriptors_match() {
        let descriptors = Ipv6Dissector.field_descriptors();
        assert_eq!(descriptors.len(), 8);
        assert_eq!(descriptors[FD_VERSION].name, "version");
        assert_eq!(descriptors[FD_TRAFFIC_CLASS].name, "traffic_class");
        assert_eq!(descriptors[FD_FLOW_LABEL].name, "flow_label");
        assert_eq!(descriptors[FD_PAYLOAD_LENGTH].name, "payload_length");
        assert_eq!(descriptors[FD_NEXT_HEADER].name, "next_header");
        assert!(descriptors[FD_NEXT_HEADER].display_fn.is_some());
        assert_eq!(descriptors[FD_HOP_LIMIT].name, "hop_limit");
        assert_eq!(descriptors[FD_SRC].name, "src");
        assert_eq!(descriptors[FD_DST].name, "dst");
    }

    #[test]
    fn field_descriptors_count() {
        // Fixed header has exactly 8 fields (no options).
        let data = build_ipv6_header(0, 0, 0, 6, 64, [0; 16], [0; 16]);
        let mut buf = DissectBuffer::new();
        Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("IPv6").unwrap();
        assert_eq!(buf.layer_fields(layer).len(), 8);
    }
}
