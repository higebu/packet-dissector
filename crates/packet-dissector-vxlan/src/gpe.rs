//! VXLAN-GPE (Generic Protocol Extension for VXLAN) dissector.
//!
//! The specification is an expired IETF working-group Internet-Draft, not an
//! RFC. VXLAN-GPE shares its Next Protocol values with LISP-GPE.
//!
//! ## References
//! - draft-ietf-nvo3-vxlan-gpe-13:
//!   <https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-13>
//! - RFC 9305, Section 6.1 (LISP-GPE Next Protocol registry):
//!   <https://www.rfc-editor.org/rfc/rfc9305#section-6.1>
//! - RFC 8300, Section 10.1 (NSH EtherType 0x894F):
//!   <https://www.rfc-editor.org/rfc/rfc8300#section-10.1>

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24};

/// VXLAN-GPE header size (draft-ietf-nvo3-vxlan-gpe-13, Section 3.1).
///
/// <https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-13#section-3.1>
const HEADER_SIZE: usize = 8;

/// Flag masks in the first header byte `|R|R|Ver|I|P|B|O|`.
///
/// draft-ietf-nvo3-vxlan-gpe-13, Sections 3.1-3.5 —
/// <https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-13#section-3.1>
const VERSION_MASK: u8 = 0x30;
const FLAG_I_MASK: u8 = 0x08;
const FLAG_P_MASK: u8 = 0x04;
const FLAG_B_MASK: u8 = 0x02;
const FLAG_O_MASK: u8 = 0x01;

/// The only defined VXLAN-GPE version (Section 3.5 — "The initial version
/// for VXLAN-GPE is 0.").
///
/// <https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-13#section-3.5>
const SUPPORTED_VERSION: u8 = 0;

/// Next Protocol values (RFC 9305, Section 6.1 registry).
///
/// <https://www.rfc-editor.org/rfc/rfc9305#section-6.1>
const NEXT_PROTOCOL_IPV4: u8 = 0x01;
const NEXT_PROTOCOL_IPV6: u8 = 0x02;
const NEXT_PROTOCOL_ETHERNET: u8 = 0x03;
const NEXT_PROTOCOL_NSH: u8 = 0x04;

/// EtherTypes used to dispatch the payload.
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// Transparent Ethernet Bridging (inner Ethernet frame).
const ETHERTYPE_TEB: u16 = 0x6558;
/// NSH (RFC 8300, Section 10.1 — IEEE-assigned EtherType 0x894F).
///
/// <https://www.rfc-editor.org/rfc/rfc8300#section-10.1>
const ETHERTYPE_NSH: u16 = 0x894F;

/// Return the registry name of a VXLAN-GPE Next Protocol value.
///
/// draft-ietf-nvo3-vxlan-gpe-13, Section 11.2 (Table 1) and RFC 9305,
/// Section 6.1.
/// <https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-13#section-11.2>
/// <https://www.rfc-editor.org/rfc/rfc9305#section-6.1>
fn next_protocol_name(value: u8) -> Option<&'static str> {
    match value {
        0x00 => Some("Reserved"),
        NEXT_PROTOCOL_IPV4 => Some("IPv4"),
        NEXT_PROTOCOL_IPV6 => Some("IPv6"),
        NEXT_PROTOCOL_ETHERNET => Some("Ethernet"),
        NEXT_PROTOCOL_NSH => Some("NSH"),
        0x7E | 0x7F => Some("Experimentation and testing"),
        0xFE | 0xFF => Some("Experimentation and testing (shim headers)"),
        _ => None,
    }
}

const FD_FLAGS: usize = 0;
const FD_VERSION: usize = 1;
const FD_VNI_VALID: usize = 2;
const FD_NEXT_PROTOCOL_PRESENT: usize = 3;
const FD_BUM: usize = 4;
const FD_OAM: usize = 5;
const FD_RESERVED: usize = 6;
const FD_NEXT_PROTOCOL: usize = 7;
const FD_VNI: usize = 8;
const FD_RESERVED2: usize = 9;
const FD_PAYLOAD_NOT_DECODED: usize = 10;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("flags", "Flags", FieldType::U8),
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("vni_valid", "Instance (I flag)", FieldType::U8).optional(),
    FieldDescriptor::new(
        "next_protocol_present",
        "Next Protocol Present (P flag)",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("bum", "BUM Traffic (B flag)", FieldType::U8).optional(),
    FieldDescriptor::new("oam", "OAM (O flag)", FieldType::U8).optional(),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U16).optional(),
    // Fields below `version` are present only for version 0.
    FieldDescriptor::new("next_protocol", "Next Protocol", FieldType::U8)
        .optional()
        // Section 3.2 — the field is a Next Protocol only when P=1; with
        // P=0 "the "Next Protocol" field must be set to zero and the payload
        // MUST be ETHERNET(L2)", so no name is given.
        // https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-13#section-3.2
        .with_display_fn(|v, siblings| {
            let p_set = siblings
                .iter()
                .find(|f| f.name() == "next_protocol_present")
                .and_then(|f| f.value.as_u8())
                == Some(1);
            match v {
                FieldValue::U8(n) if p_set => next_protocol_name(*n),
                _ => None,
            }
        }),
    FieldDescriptor::new("vni", "VXLAN Network Identifier", FieldType::U32).optional(),
    FieldDescriptor::new("reserved2", "Reserved", FieldType::U8).optional(),
    FieldDescriptor::new(
        "payload_not_decoded",
        "Payload Not Decoded (unsupported version)",
        FieldType::U8,
    )
    .optional(),
];

/// Specification references for the VXLAN-GPE dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "draft-ietf-nvo3-vxlan-gpe-13",
        "Generic Protocol Extension for VXLAN (VXLAN-GPE) (expired Internet-Draft)",
        "https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-13",
    ),
    SpecReference::new(
        "RFC 9305",
        "Locator/ID Separation Protocol (LISP) Generic Protocol Extension",
        "https://www.rfc-editor.org/rfc/rfc9305",
    ),
];

/// VXLAN-GPE dissector (UDP port 4790).
pub struct VxlanGpeDissector;

impl Dissector for VxlanGpeDissector {
    fn name(&self) -> &'static str {
        "Generic Protocol Extension for VXLAN"
    }

    fn short_name(&self) -> &'static str {
        "VXLAN-GPE"
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

        // draft-ietf-nvo3-vxlan-gpe-13, Section 3.1 —
        // |R|R|Ver|I|P|B|O| Reserved (16) | Next Protocol | VNI (24) | Reserved |
        // https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-13#section-3.1
        let flags = data[0];
        let version = (flags & VERSION_MASK) >> 4;
        let p_flag = flags & FLAG_P_MASK != 0;
        let reserved = read_be_u16(data, 1)?;
        let next_protocol = data[3];
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
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );

        // Section 3.1 — "If a receiver does not support the version indicated
        // it MUST drop the packet." Only the flags byte and the version are
        // reported: the rest of the version-0 layout may not apply.
        // https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-13#section-3.1
        if version != SUPPORTED_VERSION {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_PAYLOAD_NOT_DECODED],
                FieldValue::U8(1),
                offset..offset + 1,
            );
            buf.end_layer();
            return Ok(DissectResult::new(HEADER_SIZE, DispatchHint::End));
        }

        let flag = |mask: u8| FieldValue::U8(u8::from(flags & mask != 0));
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VNI_VALID],
            flag(FLAG_I_MASK),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_NEXT_PROTOCOL_PRESENT],
            flag(FLAG_P_MASK),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_BUM],
            flag(FLAG_B_MASK),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_OAM],
            flag(FLAG_O_MASK),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_RESERVED],
            FieldValue::U16(reserved),
            offset + 1..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_NEXT_PROTOCOL],
            FieldValue::U8(next_protocol),
            offset + 3..offset + 4,
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

        // Section 3.2 — "When UDP dest port=4790, P = 0 the "Next Protocol"
        // field must be set to zero and the payload MUST be ETHERNET(L2)".
        // Otherwise dispatch by Next Protocol (RFC 9305, Section 6.1).
        // https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-13#section-3.2
        // https://www.rfc-editor.org/rfc/rfc9305#section-6.1
        let next = if !p_flag {
            DispatchHint::ByEtherType(ETHERTYPE_TEB)
        } else {
            match next_protocol {
                NEXT_PROTOCOL_IPV4 => DispatchHint::ByEtherType(ETHERTYPE_IPV4),
                NEXT_PROTOCOL_IPV6 => DispatchHint::ByEtherType(ETHERTYPE_IPV6),
                NEXT_PROTOCOL_ETHERNET => DispatchHint::ByEtherType(ETHERTYPE_TEB),
                NEXT_PROTOCOL_NSH => DispatchHint::ByEtherType(ETHERTYPE_NSH),
                // Reserved, unassigned, experimental and shim-header values
                // have no dissector.
                _ => DispatchHint::End,
            }
        };
        Ok(DissectResult::new(HEADER_SIZE, next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # draft-ietf-nvo3-vxlan-gpe-13 (VXLAN-GPE) Coverage
    //
    // | Section | Description                          | Test                                  |
    // |---------|--------------------------------------|---------------------------------------|
    // | §3.1    | Header format, flags, VNI            | parse_gpe_ipv4                        |
    // | §3.1    | R bits ignored on receipt            | parse_gpe_reserved_bits_ignored       |
    // | §3.1    | Unsupported version: report, no decode | parse_gpe_unsupported_version       |
    // | §3.1    | Truncated header                     | parse_gpe_truncated                   |
    // | §3.1    | Byte offsets                         | parse_gpe_with_offset                 |
    // | §3.2    | Next Protocol IPv4                   | parse_gpe_ipv4                        |
    // | §3.2    | Next Protocol IPv6                   | parse_gpe_ipv6                        |
    // | §3.2    | Next Protocol Ethernet               | parse_gpe_ethernet                    |
    // | §3.2    | Next Protocol NSH                    | parse_gpe_nsh                         |
    // | §3.2    | Unassigned / experimental values     | parse_gpe_unknown_next_protocol       |
    // | §3.2    | P=0 → Ethernet payload               | parse_gpe_p_flag_clear_is_ethernet    |
    // | §3.3    | B (BUM) flag                         | parse_gpe_bum_and_oam_flags           |
    // | §3.4    | O (OAM) flag                         | parse_gpe_bum_and_oam_flags           |
    // | §11.2   | Next Protocol names                  | next_protocol_names                   |

    fn dissect(data: &[u8]) -> (DissectBuffer<'_>, DissectResult) {
        let mut buf = DissectBuffer::new();
        let result = VxlanGpeDissector.dissect(data, &mut buf, 0).unwrap();
        (buf, result)
    }

    fn gpe(flags: u8, next_protocol: u8) -> [u8; 8] {
        [flags, 0x00, 0x00, next_protocol, 0x00, 0x00, 0x64, 0x00]
    }

    #[test]
    fn parse_gpe_ipv4() {
        // Ver 0, I=1, P=1; Next Protocol 0x01 (IPv4); VNI 100
        let raw = gpe(0x0C, 0x01);
        let (buf, result) = dissect(&raw);
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

        let layer = buf.layer_by_name("VXLAN-GPE").unwrap();
        assert_eq!(layer.range, 0..8);
        assert_eq!(buf.field_u8(layer, "flags"), Some(0x0C));
        assert_eq!(buf.field_u8(layer, "version"), Some(0));
        assert_eq!(buf.field_u8(layer, "vni_valid"), Some(1));
        assert_eq!(buf.field_u8(layer, "next_protocol_present"), Some(1));
        assert_eq!(buf.field_u8(layer, "bum"), Some(0));
        assert_eq!(buf.field_u8(layer, "oam"), Some(0));
        assert_eq!(buf.field_u16(layer, "reserved"), Some(0));
        assert_eq!(buf.field_u8(layer, "next_protocol"), Some(1));
        assert_eq!(
            buf.resolve_display_name(layer, "next_protocol_name"),
            Some("IPv4")
        );
        assert_eq!(buf.field_u32(layer, "vni"), Some(100));
        assert_eq!(buf.field_u8(layer, "reserved2"), Some(0));
    }

    #[test]
    fn parse_gpe_ipv6() {
        let raw = gpe(0x0C, 0x02);
        let (_, result) = dissect(&raw);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn parse_gpe_ethernet() {
        let raw = gpe(0x0C, 0x03);
        let (_, result) = dissect(&raw);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));
    }

    /// NSH (RFC 8300) is dispatched by its IEEE EtherType 0x894F
    /// (RFC 8300, Section 10.1), so an NSH dissector registered there picks
    /// it up. <https://www.rfc-editor.org/rfc/rfc8300#section-10.1>
    #[test]
    fn parse_gpe_nsh() {
        let raw = gpe(0x0C, 0x04);
        let (_, result) = dissect(&raw);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x894F));
    }

    #[test]
    fn parse_gpe_unknown_next_protocol() {
        for np in [0x00, 0x05, 0x7E, 0x80, 0xFF] {
            let raw = gpe(0x0C, np);
            let (buf, result) = dissect(&raw);
            assert_eq!(result.next, DispatchHint::End, "next protocol {np:#x}");
            let layer = buf.layer_by_name("VXLAN-GPE").unwrap();
            assert_eq!(buf.field_u8(layer, "next_protocol"), Some(np));
        }
    }

    /// §3.2 — "When UDP dest port=4790, P = 0 the "Next Protocol" field must
    /// be set to zero and the payload MUST be ETHERNET(L2)".
    #[test]
    fn parse_gpe_p_flag_clear_is_ethernet() {
        let raw = gpe(0x08, 0x01);
        let (buf, result) = dissect(&raw);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));
        let layer = buf.layer_by_name("VXLAN-GPE").unwrap();
        assert_eq!(buf.field_u8(layer, "next_protocol_present"), Some(0));
        // Without P the field is not a Next Protocol, so it gets no name.
        assert_eq!(buf.field_u8(layer, "next_protocol"), Some(1));
        assert_eq!(buf.resolve_display_name(layer, "next_protocol_name"), None);
    }

    #[test]
    fn parse_gpe_bum_and_oam_flags() {
        let raw = gpe(0x0F, 0x01);
        let (buf, _) = dissect(&raw);
        let layer = buf.layer_by_name("VXLAN-GPE").unwrap();
        assert_eq!(buf.field_u8(layer, "bum"), Some(1));
        assert_eq!(buf.field_u8(layer, "oam"), Some(1));
    }

    /// §3.1 — "The bits designated "R" above are reserved flags. These MUST
    /// be set to zero on transmission and ignored on receipt."
    #[test]
    fn parse_gpe_reserved_bits_ignored() {
        let raw: [u8; 8] = [0xCC, 0xAB, 0xCD, 0x02, 0x00, 0x00, 0x01, 0xEE];
        let (buf, result) = dissect(&raw);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
        let layer = buf.layer_by_name("VXLAN-GPE").unwrap();
        assert_eq!(buf.field_u8(layer, "version"), Some(0));
        assert_eq!(buf.field_u16(layer, "reserved"), Some(0xABCD));
        assert_eq!(buf.field_u8(layer, "reserved2"), Some(0xEE));
    }

    /// §3.1 — "If a receiver does not support the version indicated it MUST
    /// drop the packet." The header is reported but the payload is not
    /// decoded.
    #[test]
    fn parse_gpe_unsupported_version() {
        let raw = gpe(0x1C, 0x01);
        let (buf, result) = dissect(&raw); // Ver = 1
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::End);
        let layer = buf.layer_by_name("VXLAN-GPE").unwrap();
        assert_eq!(buf.field_u8(layer, "version"), Some(1));
        assert_eq!(buf.field_u8(layer, "payload_not_decoded"), Some(1));
        // The version-0 bit layout does not apply to other versions.
        assert!(buf.field_by_name(layer, "next_protocol").is_none());
        assert!(buf.field_by_name(layer, "vni").is_none());
    }

    #[test]
    fn parse_gpe_truncated() {
        let err = VxlanGpeDissector
            .dissect(&[0x0C, 0x00, 0x00], &mut DissectBuffer::new(), 0)
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
    fn parse_gpe_with_offset() {
        let raw = gpe(0x0C, 0x01);
        let mut buf = DissectBuffer::new();
        VxlanGpeDissector.dissect(&raw, &mut buf, 20).unwrap();
        let layer = buf.layer_by_name("VXLAN-GPE").unwrap();
        assert_eq!(layer.range, 20..28);
        assert_eq!(buf.field_by_name(layer, "reserved").unwrap().range, 21..23);
        assert_eq!(
            buf.field_by_name(layer, "next_protocol").unwrap().range,
            23..24
        );
        assert_eq!(buf.field_by_name(layer, "vni").unwrap().range, 24..27);
        assert_eq!(buf.field_by_name(layer, "reserved2").unwrap().range, 27..28);
    }

    #[test]
    fn next_protocol_names() {
        assert_eq!(next_protocol_name(0x00), Some("Reserved"));
        assert_eq!(next_protocol_name(0x01), Some("IPv4"));
        assert_eq!(next_protocol_name(0x02), Some("IPv6"));
        assert_eq!(next_protocol_name(0x03), Some("Ethernet"));
        assert_eq!(next_protocol_name(0x04), Some("NSH"));
        assert_eq!(
            next_protocol_name(0x7E),
            Some("Experimentation and testing")
        );
        assert_eq!(
            next_protocol_name(0xFF),
            Some("Experimentation and testing (shim headers)")
        );
        assert_eq!(next_protocol_name(0x05), None);
    }

    #[test]
    fn references_and_layer() {
        assert!(!VxlanGpeDissector.references().is_empty());
        for r in VxlanGpeDissector.references() {
            assert!(r.url.starts_with("https://"));
        }
        assert_eq!(VxlanGpeDissector.layer(), Some(ProtocolLayer::Tunnel));
        assert_eq!(VxlanGpeDissector.short_name(), "VXLAN-GPE");
        assert_eq!(VxlanGpeDissector.field_descriptors().len(), 11);
    }
}
