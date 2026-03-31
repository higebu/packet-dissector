//! UDP (User Datagram Protocol) dissector.
//!
//! ## References
//! - RFC 768: <https://www.rfc-editor.org/rfc/rfc768>
//! - RFC 9868 (updates RFC 768; defines UDP surplus area options — not parsed here):
//!   <https://www.rfc-editor.org/rfc/rfc9868>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

/// UDP header size (always 8 bytes).
const HEADER_SIZE: usize = 8;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_SRC_PORT: usize = 0;
const FD_DST_PORT: usize = 1;
const FD_LENGTH: usize = 2;
const FD_CHECKSUM: usize = 3;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("src_port", "Source Port", FieldType::U16),
    FieldDescriptor::new("dst_port", "Destination Port", FieldType::U16),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
];

/// UDP dissector.
pub struct UdpDissector;

impl Dissector for UdpDissector {
    fn name(&self) -> &'static str {
        "User Datagram Protocol"
    }

    fn short_name(&self) -> &'static str {
        "UDP"
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

        // RFC 768 — UDP Header Format
        let src_port = read_be_u16(data, 0)?;
        let dst_port = read_be_u16(data, 2)?;
        let length = read_be_u16(data, 4)?;
        let checksum = read_be_u16(data, 6)?;

        // RFC 768 — "The minimum value of the length is eight."
        if (length as usize) < HEADER_SIZE {
            return Err(PacketError::InvalidFieldValue {
                field: "length",
                value: length as u32,
            });
        }

        // RFC 768 — Length includes the header; data buffer must be large enough.
        if (length as usize) > data.len() {
            return Err(PacketError::Truncated {
                expected: length as usize,
                actual: data.len(),
            });
        }

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + HEADER_SIZE,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SRC_PORT],
            FieldValue::U16(src_port),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DST_PORT],
            FieldValue::U16(dst_port),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LENGTH],
            FieldValue::U16(length),
            offset + 4..offset + 6,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM],
            FieldValue::U16(checksum),
            offset + 6..offset + 8,
        );
        buf.end_layer();

        Ok(DissectResult::new(
            HEADER_SIZE,
            DispatchHint::ByUdpPort(src_port, dst_port),
        ))
    }
}
