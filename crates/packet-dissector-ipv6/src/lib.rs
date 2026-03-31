//! IPv6 (Internet Protocol version 6) dissector with extension header support.
//!
//! ## References
//! - RFC 8200: <https://www.rfc-editor.org/rfc/rfc8200>
//!   - Section 4.3: Hop-by-Hop Options Header
//!   - Section 4.4: Routing Header
//!   - Section 4.5: Fragment Header
//!   - Section 4.6: Destination Options Header
//! - RFC 9673 (updates RFC 8200 Hop-by-Hop processing procedures): <https://www.rfc-editor.org/rfc/rfc9673>
//! - RFC 6275: Mobility Support in IPv6: <https://www.rfc-editor.org/rfc/rfc6275>

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
const HEADER_SIZE: usize = 40;

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
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("traffic_class", "Traffic Class", FieldType::U8),
    FieldDescriptor::new("flow_label", "Flow Label", FieldType::U32),
    FieldDescriptor::new("payload_length", "Payload Length", FieldType::U16),
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
    FieldDescriptor::new("hop_limit", "Hop Limit", FieldType::U8),
    FieldDescriptor::new("src", "Source Address", FieldType::Ipv6Addr),
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
        let version = (data[0] >> 4) & 0x0F;

        if version != 6 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: version as u32,
            });
        }
        let traffic_class = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);
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
