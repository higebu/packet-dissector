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

        // RFC 768 — Length includes the header and data (minimum 8).
        // RFC 9868, Section 7 reframes any bytes beyond `length` but within the
        // IP transport payload as the "surplus area" used for UDP Options. The
        // dissector therefore consumes only HEADER_SIZE and leaves surplus
        // bytes (if any) for upstream handling; only `length > data.len()` is
        // treated as truncation.
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

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC Coverage
    //
    // RFC 768 is a 3-page document without numbered sections; citations below
    // reference the field description paragraphs by field name. RFC 9868 uses
    // numbered sections and is cited accordingly.
    //
    // | RFC Section                            | Description                                        | Test                              |
    // |----------------------------------------|----------------------------------------------------|-----------------------------------|
    // | RFC 768 §Header                        | src/dst/length/checksum parsed at correct offsets  | parse_basic                       |
    // | RFC 768 §Header                        | Minimum datagram (length = 8, header only)         | parse_header_only                 |
    // | RFC 768 §Source Port                   | Optional; value zero allowed                       | parse_source_port_zero            |
    // | RFC 768 §Checksum                      | Zero means "transmitter generated no checksum"     | parse_checksum_zero_not_computed  |
    // | RFC 768 §Length                        | length < 8 rejected as InvalidFieldValue           | parse_length_below_minimum        |
    // | RFC 768 §Length                        | length > data.len() rejected as Truncated          | parse_length_exceeds_data         |
    // | RFC 9868 §7                            | data.len() > length accepted (surplus area)        | parse_surplus_area_accepted       |
    // | RFC 768 §Header                        | Truncated header (< 8 bytes) rejected              | parse_truncated_header            |
    // | RFC 768 §Header                        | Non-zero dissect offset propagates to field ranges | parse_with_offset                 |
    // | RFC 768 §Header                        | Dispatch hint carries both ports in order          | dispatch_hint_carries_both_ports  |
    // | ---                                    | Dissector metadata                                 | dissector_metadata                |
    // | ---                                    | Field descriptors ordering                         | field_descriptors_ordering        |

    /// Build a UDP datagram sized to the declared `length`, with a zero payload.
    fn build_udp(src_port: u16, dst_port: u16, length: u16, checksum: u16) -> Vec<u8> {
        let buf_len = (length as usize).max(HEADER_SIZE);
        let mut pkt = vec![0u8; buf_len];
        pkt[0..2].copy_from_slice(&src_port.to_be_bytes());
        pkt[2..4].copy_from_slice(&dst_port.to_be_bytes());
        pkt[4..6].copy_from_slice(&length.to_be_bytes());
        pkt[6..8].copy_from_slice(&checksum.to_be_bytes());
        pkt
    }

    #[test]
    fn parse_basic() {
        // RFC 768 §Header — verify all four 16-bit fields at offsets 0/2/4/6.
        let data = build_udp(12345, 53, 20, 0xABCD);
        let mut buf = DissectBuffer::new();
        let result = UdpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, HEADER_SIZE);

        let layer = buf.layer_by_name("UDP").unwrap();
        assert_eq!(layer.name, "UDP");
        assert_eq!(layer.range, 0..HEADER_SIZE);

        let src = buf.field_by_name(layer, "src_port").unwrap();
        assert_eq!(src.value, FieldValue::U16(12345));
        assert_eq!(src.range, 0..2);

        let dst = buf.field_by_name(layer, "dst_port").unwrap();
        assert_eq!(dst.value, FieldValue::U16(53));
        assert_eq!(dst.range, 2..4);

        let length = buf.field_by_name(layer, "length").unwrap();
        assert_eq!(length.value, FieldValue::U16(20));
        assert_eq!(length.range, 4..6);

        let checksum = buf.field_by_name(layer, "checksum").unwrap();
        assert_eq!(checksum.value, FieldValue::U16(0xABCD));
        assert_eq!(checksum.range, 6..8);
    }

    #[test]
    fn parse_header_only() {
        // RFC 768 §Length — "minimum value of the length is eight"; header-only is valid.
        let data = build_udp(1, 2, 8, 0);
        let mut buf = DissectBuffer::new();
        let result = UdpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        let layer = buf.layer_by_name("UDP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U16(8)
        );
    }

    #[test]
    fn parse_source_port_zero() {
        // RFC 768 §Source Port — "If not used, a value of zero is inserted."
        let data = build_udp(0, 53, 8, 0);
        let mut buf = DissectBuffer::new();
        UdpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("UDP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "src_port").unwrap().value,
            FieldValue::U16(0)
        );
    }

    #[test]
    fn parse_checksum_zero_not_computed() {
        // RFC 768 §Checksum — "An all zero transmitted checksum value means
        // that the transmitter generated no checksum". The dissector must
        // preserve this value verbatim rather than rejecting it.
        let data = build_udp(1234, 5678, 8, 0);
        let mut buf = DissectBuffer::new();
        UdpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("UDP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "checksum").unwrap().value,
            FieldValue::U16(0)
        );
    }

    #[test]
    fn parse_length_below_minimum() {
        // RFC 768 §Length — "the minimum value of the length is eight".
        let mut data = vec![0u8; 8];
        data[4] = 0x00;
        data[5] = 0x07; // length = 7

        let mut buf = DissectBuffer::new();
        let err = UdpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidFieldValue {
                field: "length",
                value: 7,
            }
        );
    }

    #[test]
    fn parse_length_exceeds_data() {
        // RFC 768 §Length — declared length covers header+data; must not
        // exceed the captured buffer.
        let mut data = build_udp(1234, 5678, 20, 0);
        data.truncate(12);

        let mut buf = DissectBuffer::new();
        let err = UdpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: 20,
                actual: 12,
            }
        );
    }

    #[test]
    fn parse_surplus_area_accepted() {
        // RFC 9868, Section 7 — the IP transport payload beyond UDP Length
        // but within the IP Length is the "surplus area". The dissector must
        // accept `data.len() > length` without error and consume only the
        // 8-byte header, leaving the surplus bytes for upstream processing.
        let mut data = build_udp(1234, 5678, 8, 0xDEAD); // length = 8 (header only)
        data.extend_from_slice(&[0xAA; 16]); // 16 bytes of surplus area

        let mut buf = DissectBuffer::new();
        let result = UdpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        let layer = buf.layer_by_name("UDP").unwrap();
        assert_eq!(layer.range, 0..HEADER_SIZE);
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U16(8)
        );
    }

    #[test]
    fn parse_truncated_header() {
        // RFC 768 §Header — fixed 8-byte header is required.
        let data = [0u8; 4];
        let mut buf = DissectBuffer::new();
        let err = UdpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: 4,
            }
        );
    }

    #[test]
    fn parse_with_offset() {
        // Non-zero dissect offset must propagate to every field range so that
        // callers can locate header bytes in the outer packet.
        let data = build_udp(80, 443, 8, 0);
        let mut buf = DissectBuffer::new();
        UdpDissector.dissect(&data, &mut buf, 42).unwrap();

        let layer = buf.layer_by_name("UDP").unwrap();
        assert_eq!(layer.range, 42..50);
        assert_eq!(buf.field_by_name(layer, "src_port").unwrap().range, 42..44);
        assert_eq!(buf.field_by_name(layer, "dst_port").unwrap().range, 44..46);
        assert_eq!(buf.field_by_name(layer, "length").unwrap().range, 46..48);
        assert_eq!(buf.field_by_name(layer, "checksum").unwrap().range, 48..50);
    }

    #[test]
    fn dispatch_hint_carries_both_ports() {
        // Source and destination ports must both reach the registry so that
        // port-based dispatch can fall back from the lower port to the higher.
        let data = build_udp(54321, 53, 8, 0);
        let mut buf = DissectBuffer::new();
        let result = UdpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.next, DispatchHint::ByUdpPort(54321, 53));

        let data2 = build_udp(53, 54321, 8, 0);
        let mut buf2 = DissectBuffer::new();
        let result2 = UdpDissector.dissect(&data2, &mut buf2, 0).unwrap();
        assert_eq!(result2.next, DispatchHint::ByUdpPort(53, 54321));
    }

    #[test]
    fn dissector_metadata() {
        let d = UdpDissector;
        assert_eq!(d.name(), "User Datagram Protocol");
        assert_eq!(d.short_name(), "UDP");
    }

    #[test]
    fn field_descriptors_ordering() {
        // The field descriptor ordering is part of the public contract and
        // must match the documented RFC 768 header layout.
        let fds = UdpDissector.field_descriptors();
        assert_eq!(fds.len(), 4);
        assert_eq!(fds[FD_SRC_PORT].name, "src_port");
        assert_eq!(fds[FD_DST_PORT].name, "dst_port");
        assert_eq!(fds[FD_LENGTH].name, "length");
        assert_eq!(fds[FD_CHECKSUM].name, "checksum");
        for fd in fds {
            assert_eq!(fd.field_type, FieldType::U16);
        }
    }
}
