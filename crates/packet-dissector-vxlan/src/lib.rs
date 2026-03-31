//! VXLAN (Virtual eXtensible Local Area Network) dissector.
//!
//! ## References
//! - RFC 7348: <https://www.rfc-editor.org/rfc/rfc7348>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u24;

/// VXLAN header size.
///
/// RFC 7348, Section 5 — The VXLAN header is exactly 8 octets:
/// flags (1) + reserved (3) + VNI (3) + reserved (1).
/// <https://www.rfc-editor.org/rfc/rfc7348#section-5>
const HEADER_SIZE: usize = 8;

/// EtherType for Transparent Ethernet Bridging (inner Ethernet frame).
///
/// Used to dispatch the inner payload to the Ethernet dissector.
const ETHERTYPE_TEB: u16 = 0x6558;

/// Mask for the I (VNI valid) flag in the flags byte.
///
/// RFC 7348, Section 5 — Bit 4 of byte 0 (the I flag) MUST be set to 1
/// to indicate a valid VNI is present.
/// <https://www.rfc-editor.org/rfc/rfc7348#section-5>
const FLAG_I_MASK: u8 = 0x08;

/// Field descriptor indices for [`VxlanDissector::field_descriptors`].
const FD_FLAGS: usize = 0;
const FD_VNI_VALID: usize = 1;
const FD_RESERVED: usize = 2;
const FD_VNI: usize = 3;
const FD_RESERVED2: usize = 4;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("flags", "Flags", FieldType::U8),
    FieldDescriptor::new("vni_valid", "VNI Valid (I flag)", FieldType::U8),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U32),
    FieldDescriptor::new("vni", "VXLAN Network Identifier", FieldType::U32),
    FieldDescriptor::new("reserved2", "Reserved", FieldType::U8),
];

/// VXLAN dissector.
pub struct VxlanDissector;

impl Dissector for VxlanDissector {
    fn name(&self) -> &'static str {
        "Virtual eXtensible Local Area Network"
    }

    fn short_name(&self) -> &'static str {
        "VXLAN"
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

        let flags = data[0];

        // RFC 7348 §5: I flag MUST be 1; without it the VNI is undefined.
        let i_flag = (flags & FLAG_I_MASK) >> 3;
        if i_flag == 0 {
            return Err(PacketError::InvalidHeader(
                "VXLAN I flag (VNI valid) must be set to 1",
            ));
        }

        let reserved = read_be_u24(data, 1)?;
        let vni = read_be_u24(data, 4)?;
        let reserved2 = data[7];

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + HEADER_SIZE,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAGS],
            FieldValue::U8(flags),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VNI_VALID],
            FieldValue::U8(i_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_RESERVED],
            FieldValue::U32(reserved),
            offset + 1..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VNI],
            FieldValue::U32(vni),
            offset + 4..offset + 7,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_RESERVED2],
            FieldValue::U8(reserved2),
            offset + 7..offset + 8,
        );
        buf.end_layer();

        // Inner payload is always an Ethernet frame; dispatch via TEB EtherType.
        Ok(DissectResult::new(
            HEADER_SIZE,
            DispatchHint::ByEtherType(ETHERTYPE_TEB),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 7348 (VXLAN) Coverage
    //
    // | RFC Section | Description                   | Test                             |
    // |-------------|-------------------------------|----------------------------------|
    // | §5          | Header format (8 bytes)       | parse_vxlan_basic                |
    // | §5          | I flag validation             | parse_vxlan_i_flag_not_set       |
    // | §5          | VNI parsing (24-bit)          | parse_vxlan_basic                |
    // | §5          | Reserved fields               | parse_vxlan_basic                |
    // | §5          | Truncated packet              | parse_vxlan_truncated            |
    // | §5          | Dispatch to inner Ethernet    | parse_vxlan_basic                |
    // | §5          | Max VNI value                 | parse_vxlan_max_vni              |
    // | §5          | Byte offset correctness       | parse_vxlan_with_offset          |

    /// Helper: dissect raw bytes at offset 0 and return the result.
    fn dissect(data: &[u8]) -> Result<(DissectBuffer<'_>, DissectResult), PacketError> {
        let mut buf = DissectBuffer::new();
        let result = VxlanDissector.dissect(data, &mut buf, 0)?;
        Ok((buf, result))
    }

    #[test]
    fn parse_vxlan_basic() {
        // I flag set, VNI = 100 (0x000064)
        let raw: &[u8] = &[
            0x08, 0x00, 0x00, 0x00, // flags (I=1), reserved
            0x00, 0x00, 0x64, 0x00, // VNI=100, reserved
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));

        let layer = buf.layer_by_name("VXLAN").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "flags").unwrap().value,
            FieldValue::U8(0x08)
        );
        assert_eq!(
            buf.field_by_name(layer, "vni_valid").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "reserved").unwrap().value,
            FieldValue::U32(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "vni").unwrap().value,
            FieldValue::U32(100)
        );
        assert_eq!(
            buf.field_by_name(layer, "reserved2").unwrap().value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_vxlan_max_vni() {
        // VNI = 0xFFFFFF (16,777,215)
        let raw: &[u8] = &[
            0x08, 0x00, 0x00, 0x00, // flags (I=1), reserved
            0xFF, 0xFF, 0xFF, 0x00, // VNI=16777215, reserved
        ];
        let (buf, _result) = dissect(raw).unwrap();

        let layer = buf.layer_by_name("VXLAN").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "vni").unwrap().value,
            FieldValue::U32(0x00FF_FFFF)
        );
    }

    #[test]
    fn parse_vxlan_truncated() {
        let raw: &[u8] = &[0x08, 0x00, 0x00]; // Only 3 bytes
        let err = VxlanDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 3
            }
        ));
    }

    #[test]
    fn parse_vxlan_i_flag_not_set() {
        // I flag not set (flags = 0x00)
        let raw: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // flags (I=0), reserved
            0x00, 0x00, 0x64, 0x00, // VNI=100, reserved
        ];
        let err = VxlanDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        match err {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("I flag"), "Error message: {msg}");
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn parse_vxlan_with_offset() {
        // Verify byte ranges use the offset parameter correctly
        let raw: &[u8] = &[
            0x08, 0x00, 0x00, 0x00, // flags (I=1), reserved
            0x00, 0x00, 0x64, 0x00, // VNI=100, reserved
        ];
        let mut buf = DissectBuffer::new();
        let result = VxlanDissector.dissect(raw, &mut buf, 42).unwrap();
        assert_eq!(result.bytes_consumed, 8);

        let layer = buf.layer_by_name("VXLAN").unwrap();
        assert_eq!(layer.range, 42..50);
        assert_eq!(buf.field_by_name(layer, "flags").unwrap().range, 42..43);
        assert_eq!(buf.field_by_name(layer, "reserved").unwrap().range, 43..46);
        assert_eq!(buf.field_by_name(layer, "vni").unwrap().range, 46..49);
        assert_eq!(buf.field_by_name(layer, "reserved2").unwrap().range, 49..50);
    }

    #[test]
    fn field_descriptors_consistent() {
        let descs = VxlanDissector.field_descriptors();
        assert_eq!(descs.len(), 5);
        assert_eq!(descs[FD_FLAGS].name, "flags");
        assert_eq!(descs[FD_VNI_VALID].name, "vni_valid");
        assert_eq!(descs[FD_RESERVED].name, "reserved");
        assert_eq!(descs[FD_VNI].name, "vni");
        assert_eq!(descs[FD_RESERVED2].name, "reserved2");
    }
}
