//! VXLAN (Virtual eXtensible Local Area Network) dissector.
//!
//! [`VxlanDissector`] decodes RFC 7348 VXLAN on UDP port 4789, including
//! the Group Based Policy extension (VXLAN-GBP) when the G bit is set.
//! [`VxlanGpeDissector`] decodes the Generic Protocol Extension for VXLAN
//! (VXLAN-GPE) on UDP port 4790.
//!
//! ## References
//! - RFC 7348: <https://www.rfc-editor.org/rfc/rfc7348>
//! - draft-smith-vxlan-group-policy-05 (VXLAN-GBP; expired individual
//!   Internet-Draft, not an RFC):
//!   <https://datatracker.ietf.org/doc/html/draft-smith-vxlan-group-policy-05>
//! - draft-ietf-nvo3-vxlan-gpe-13 (VXLAN-GPE; expired working-group
//!   Internet-Draft, not an RFC):
//!   <https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-13>
//! - RFC 9305, Section 6.1 (LISP-GPE Next Protocol registry, shared by
//!   VXLAN-GPE): <https://www.rfc-editor.org/rfc/rfc9305#section-6.1>

#![deny(missing_docs)]

mod gpe;

pub use gpe::VxlanGpeDissector;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24};

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
/// RFC 7348, Section 5 — "the I flag MUST be set to 1 for a valid VXLAN
/// Network ID (VNI)."
/// <https://www.rfc-editor.org/rfc/rfc7348#section-5>
const FLAG_I_MASK: u8 = 0x08;

/// Mask for the G (Group Based Policy Extension) bit in the flags byte.
///
/// draft-smith-vxlan-group-policy-05, Section 2.1 — "G Bit: Bit 0 of the
/// initial word is defined as the G (Group Based Policy Extension) bit."
/// <https://datatracker.ietf.org/doc/html/draft-smith-vxlan-group-policy-05#section-2.1>
const FLAG_G_MASK: u8 = 0x80;

/// Mask for the D (Don't Learn) bit in the second header byte (bit 9 of the
/// first word).
///
/// draft-smith-vxlan-group-policy-05, Section 2.1 —
/// <https://datatracker.ietf.org/doc/html/draft-smith-vxlan-group-policy-05#section-2.1>
const GBP_D_MASK: u8 = 0x40;

/// Mask for the A (Policy Applied) bit in the second header byte (bit 12 of
/// the first word).
///
/// draft-smith-vxlan-group-policy-05, Section 2.1 —
/// <https://datatracker.ietf.org/doc/html/draft-smith-vxlan-group-policy-05#section-2.1>
const GBP_A_MASK: u8 = 0x08;

/// Bits of header bytes 1-3 (as a 24-bit value) that stay reserved when the
/// G bit is set: everything except D, A and the Group Policy ID.
///
/// draft-smith-vxlan-group-policy-05, Section 2.1 —
/// <https://datatracker.ietf.org/doc/html/draft-smith-vxlan-group-policy-05#section-2.1>
const GBP_RESERVED_MASK: u32 = ((!(GBP_D_MASK | GBP_A_MASK)) as u32) << 16;

/// Field descriptor indices for [`VxlanDissector::field_descriptors`].
const FD_FLAGS: usize = 0;
const FD_VNI_VALID: usize = 1;
const FD_RESERVED: usize = 2;
const FD_VNI: usize = 3;
const FD_RESERVED2: usize = 4;
const FD_GBP: usize = 5;
const FD_DONT_LEARN: usize = 6;
const FD_POLICY_APPLIED: usize = 7;
const FD_GROUP_POLICY_ID: usize = 8;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("flags", "Flags", FieldType::U8),
    FieldDescriptor::new("vni_valid", "VNI Valid (I flag)", FieldType::U8),
    // Bytes 1-3. When the VXLAN-GBP G bit is set, the D, A and Group Policy
    // ID bits are masked out (they have their own fields).
    FieldDescriptor::new("reserved", "Reserved", FieldType::U32),
    FieldDescriptor::new("vni", "VXLAN Network Identifier", FieldType::U32),
    FieldDescriptor::new("reserved2", "Reserved", FieldType::U8),
    // draft-smith-vxlan-group-policy-05 (expired Internet-Draft) — present
    // only when the G bit is set.
    // https://datatracker.ietf.org/doc/html/draft-smith-vxlan-group-policy-05#section-2.1
    FieldDescriptor::new(
        "gbp",
        "Group Based Policy Extension (G flag)",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("dont_learn", "Don't Learn (D flag)", FieldType::U8).optional(),
    FieldDescriptor::new("policy_applied", "Policy Applied (A flag)", FieldType::U8).optional(),
    FieldDescriptor::new("group_policy_id", "Group Policy ID", FieldType::U16).optional(),
];

/// VXLAN dissector.
pub struct VxlanDissector;

/// Specification references for the VXLAN dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 7348",
        "Virtual eXtensible Local Area Network (VXLAN): A Framework for Overlaying Virtualized Layer 2 Networks over Layer 3 Networks",
        "https://www.rfc-editor.org/rfc/rfc7348",
    ),
    SpecReference::new(
        "draft-smith-vxlan-group-policy-05",
        "VXLAN Group Policy Option (expired Internet-Draft)",
        "https://datatracker.ietf.org/doc/html/draft-smith-vxlan-group-policy-05",
    ),
];

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

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Tunnel)
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

        // RFC 7348, Section 5 — "the I flag MUST be set to 1 for a valid
        // VXLAN Network ID (VNI)." The section does not tell receivers to
        // discard a packet with I=0, so the flag is reported and the payload
        // is still dispatched.
        // https://www.rfc-editor.org/rfc/rfc7348#section-5
        let i_flag = (flags & FLAG_I_MASK) >> 3;
        // draft-smith-vxlan-group-policy-05, Section 2.1 — G bit. RFC 7348
        // reserves this bit, so a sender that does not use GBP sets it to 0.
        // https://datatracker.ietf.org/doc/html/draft-smith-vxlan-group-policy-05#section-2.1
        let gbp = flags & FLAG_G_MASK != 0;

        // RFC 7348, Section 5 — "Reserved fields (24 bits and 8 bits): MUST
        // be set to zero on transmission and ignored on receipt."
        // https://www.rfc-editor.org/rfc/rfc7348#section-5
        let mut reserved = read_be_u24(data, 1)?;
        if gbp {
            reserved &= GBP_RESERVED_MASK;
        }
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
        if gbp {
            // draft-smith-vxlan-group-policy-05, Section 2.1 — D bit (bit 9),
            // A bit (bit 12) and the 16-bit Group Policy ID.
            // https://datatracker.ietf.org/doc/html/draft-smith-vxlan-group-policy-05#section-2.1
            let group_policy_id = read_be_u16(data, 2)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_GBP],
                FieldValue::U8(1),
                offset..offset + 1,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_DONT_LEARN],
                FieldValue::U8(u8::from(data[1] & GBP_D_MASK != 0)),
                offset + 1..offset + 2,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_POLICY_APPLIED],
                FieldValue::U8(u8::from(data[1] & GBP_A_MASK != 0)),
                offset + 1..offset + 2,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_GROUP_POLICY_ID],
                FieldValue::U16(group_policy_id),
                offset + 2..offset + 4,
            );
        }
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

        // RFC 7348, Section 5 — the inner payload is always an Ethernet
        // frame; dispatch via the TEB EtherType.
        // https://www.rfc-editor.org/rfc/rfc7348#section-5
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
    // | §5          | I=0 reported, still dispatched| parse_vxlan_i_flag_not_set       |
    // | §5          | VNI parsing (24-bit)          | parse_vxlan_basic                |
    // | §5          | Reserved fields               | parse_vxlan_basic                |
    // | §5          | Truncated packet              | parse_vxlan_truncated            |
    // | §5          | Dispatch to inner Ethernet    | parse_vxlan_basic                |
    // | §5          | Max VNI value                 | parse_vxlan_max_vni              |
    // | §5          | Byte offset correctness       | parse_vxlan_with_offset          |
    // | §5          | Reserved bits without G       | parse_vxlan_without_gbp_keeps_reserved |
    //
    // # draft-smith-vxlan-group-policy-05 (VXLAN-GBP) Coverage
    //
    // | Section | Description                         | Test                                           |
    // |---------|-------------------------------------|------------------------------------------------|
    // | §2.1    | G bit, Group Policy ID              | parse_vxlan_gbp                                |
    // | §2.1    | D (Don't Learn), A (Policy Applied) | parse_vxlan_gbp_dont_learn_and_policy_applied  |
    // | §2.1    | Remaining R bits with G=1           | parse_vxlan_gbp_reserved_bits                  |

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

    /// RFC 7348, Section 5 — the I flag "MUST be set to 1 for a valid VXLAN
    /// Network ID (VNI)", but the section gives receivers no instruction to
    /// discard a packet with I=0. The header is decoded, the flag reported
    /// and the payload still dispatched.
    #[test]
    fn parse_vxlan_i_flag_not_set() {
        let raw: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // flags (I=0), reserved
            0x00, 0x00, 0x64, 0x00, // VNI=100, reserved
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));
        let layer = buf.layer_by_name("VXLAN").unwrap();
        assert_eq!(buf.field_u8(layer, "vni_valid"), Some(0));
        assert_eq!(buf.field_u32(layer, "vni"), Some(100));
    }

    /// draft-smith-vxlan-group-policy-05, Section 2.1 — G=1 carries the
    /// Group Policy ID in bytes 2-3.
    #[test]
    fn parse_vxlan_gbp() {
        let raw: &[u8] = &[
            0x88, 0x00, 0x12, 0x34, // G=1 I=1, D=0 A=0, Group Policy ID 0x1234
            0x00, 0x00, 0x64, 0x00, // VNI=100, reserved
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));
        let layer = buf.layer_by_name("VXLAN").unwrap();
        assert_eq!(buf.field_u8(layer, "flags"), Some(0x88));
        assert_eq!(buf.field_u8(layer, "vni_valid"), Some(1));
        assert_eq!(buf.field_u8(layer, "gbp"), Some(1));
        assert_eq!(buf.field_u8(layer, "dont_learn"), Some(0));
        assert_eq!(buf.field_u8(layer, "policy_applied"), Some(0));
        assert_eq!(buf.field_u16(layer, "group_policy_id"), Some(0x1234));
        assert_eq!(buf.field_u32(layer, "vni"), Some(100));
        // Bytes 1-3 minus the GBP D, A and Group Policy ID bits.
        assert_eq!(buf.field_u32(layer, "reserved"), Some(0));
    }

    /// draft-smith-vxlan-group-policy-05, Section 2.1 — with G=1 the bits of
    /// bytes 1-3 other than D, A and the Group Policy ID stay reserved and
    /// are still reported.
    #[test]
    fn parse_vxlan_gbp_reserved_bits() {
        let raw: &[u8] = &[
            0x88, 0xFF, 0x00, 0x01, // G=1 I=1, all bits of byte 1 set
            0x00, 0x00, 0x01, 0x00, // VNI=1, reserved
        ];
        let (buf, _) = dissect(raw).unwrap();
        let layer = buf.layer_by_name("VXLAN").unwrap();
        assert_eq!(buf.field_u32(layer, "reserved"), Some(0x00B7_0000));
        assert_eq!(buf.field_u8(layer, "dont_learn"), Some(1));
        assert_eq!(buf.field_u8(layer, "policy_applied"), Some(1));
    }

    /// draft-smith-vxlan-group-policy-05, Section 2.1 — D is bit 9 and A is
    /// bit 12 of the first word.
    #[test]
    fn parse_vxlan_gbp_dont_learn_and_policy_applied() {
        let raw: &[u8] = &[
            0x88, 0x48, 0x00, 0x0A, // G=1 I=1, D=1 A=1, Group Policy ID 10
            0x00, 0x00, 0x01, 0x00, // VNI=1, reserved
        ];
        let mut buf = DissectBuffer::new();
        VxlanDissector.dissect(raw, &mut buf, 10).unwrap();
        let layer = buf.layer_by_name("VXLAN").unwrap();
        assert_eq!(buf.field_u8(layer, "dont_learn"), Some(1));
        assert_eq!(buf.field_u8(layer, "policy_applied"), Some(1));
        assert_eq!(buf.field_u16(layer, "group_policy_id"), Some(10));
        assert_eq!(buf.field_by_name(layer, "gbp").unwrap().range, 10..11);
        assert_eq!(
            buf.field_by_name(layer, "dont_learn").unwrap().range,
            11..12
        );
        assert_eq!(
            buf.field_by_name(layer, "policy_applied").unwrap().range,
            11..12
        );
        assert_eq!(
            buf.field_by_name(layer, "group_policy_id").unwrap().range,
            12..14
        );
    }

    /// RFC 7348, Section 5 — without G=1 the bits are reserved and the GBP
    /// fields are not decoded.
    #[test]
    fn parse_vxlan_without_gbp_keeps_reserved() {
        let raw: &[u8] = &[
            0x08, 0x48, 0x12, 0x34, // I=1, reserved bits set
            0x00, 0x00, 0x01, 0x00, // VNI=1, reserved
        ];
        let (buf, _) = dissect(raw).unwrap();
        let layer = buf.layer_by_name("VXLAN").unwrap();
        assert_eq!(buf.field_u32(layer, "reserved"), Some(0x0048_1234));
        assert!(buf.field_by_name(layer, "gbp").is_none());
        assert!(buf.field_by_name(layer, "group_policy_id").is_none());
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
        assert_eq!(descs.len(), 9);
        assert_eq!(descs[FD_FLAGS].name, "flags");
        assert_eq!(descs[FD_VNI_VALID].name, "vni_valid");
        assert_eq!(descs[FD_RESERVED].name, "reserved");
        assert_eq!(descs[FD_VNI].name, "vni");
        assert_eq!(descs[FD_RESERVED2].name, "reserved2");
        assert_eq!(descs[FD_GBP].name, "gbp");
        assert_eq!(descs[FD_DONT_LEARN].name, "dont_learn");
        assert_eq!(descs[FD_POLICY_APPLIED].name, "policy_applied");
        assert_eq!(descs[FD_GROUP_POLICY_ID].name, "group_policy_id");
    }

    #[test]
    fn references_and_layer() {
        let references = VxlanDissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(VxlanDissector.layer(), Some(ProtocolLayer::Tunnel));
    }
}
