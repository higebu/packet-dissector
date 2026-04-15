//! GENEVE (Generic Network Virtualization Encapsulation) dissector.
//!
//! ## References
//! - RFC 8926: <https://www.rfc-editor.org/rfc/rfc8926>
//!   - §3.4 Tunnel Header Fields: <https://www.rfc-editor.org/rfc/rfc8926#section-3.4>
//!   - §3.5 Tunnel Options: <https://www.rfc-editor.org/rfc/rfc8926#section-3.5>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24};

/// Minimum GENEVE header size (fixed header only, no options).
///
/// RFC 8926, Section 3.4 — The fixed tunnel header is 8 octets
/// (Ver/Opt Len/O/C/Rsvd/Protocol Type/VNI/Reserved).
/// <https://www.rfc-editor.org/rfc/rfc8926#section-3.4>
const MIN_HEADER_SIZE: usize = 8;

/// Field descriptor indices for [`GeneveDissector::field_descriptors`].
const FD_VERSION: usize = 0;
const FD_OPT_LEN: usize = 1;
const FD_OAM: usize = 2;
const FD_CRITICAL: usize = 3;
const FD_RESERVED: usize = 4;
const FD_PROTOCOL_TYPE: usize = 5;
const FD_VNI: usize = 6;
const FD_RESERVED2: usize = 7;
const FD_OPTIONS: usize = 8;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("opt_len", "Options Length", FieldType::U8),
    FieldDescriptor::new("oam", "OAM", FieldType::U8),
    FieldDescriptor::new("critical", "Critical Options Present", FieldType::U8),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U8),
    FieldDescriptor::new("protocol_type", "Protocol Type", FieldType::U16),
    FieldDescriptor::new("vni", "Virtual Network Identifier", FieldType::U32),
    FieldDescriptor::new("reserved2", "Reserved", FieldType::U8),
    FieldDescriptor::new("options", "Options", FieldType::Bytes).optional(),
];

/// GENEVE dissector.
pub struct GeneveDissector;

impl Dissector for GeneveDissector {
    fn name(&self) -> &'static str {
        "Generic Network Virtualization Encapsulation"
    }

    fn short_name(&self) -> &'static str {
        "GENEVE"
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
        if data.len() < MIN_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 8926, Section 3.4 — Version (2 bits, must be 0)
        let version = (data[0] >> 6) & 0x03;
        if version != 0 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: version as u32,
            });
        }

        // RFC 8926, Section 3.4 — Opt Len (6 bits, in 4-byte multiples)
        let opt_len = data[0] & 0x3F;
        let header_len = MIN_HEADER_SIZE + (opt_len as usize) * 4;

        if data.len() < header_len {
            return Err(PacketError::Truncated {
                expected: header_len,
                actual: data.len(),
            });
        }

        // RFC 8926, Section 3.4 — O (OAM) flag
        let oam = (data[1] >> 7) & 1;
        // RFC 8926, Section 3.4 — C (Critical) flag
        let critical = (data[1] >> 6) & 1;
        // RFC 8926, Section 3.4 — Reserved (6 bits)
        let reserved = data[1] & 0x3F;

        // RFC 8926, Section 3.4 — Protocol Type (EtherType)
        let protocol_type = read_be_u16(data, 2)?;

        // RFC 8926, Section 3.4 — VNI (24 bits)
        let vni = read_be_u24(data, 4)?;

        // RFC 8926, Section 3.4 — Reserved (8 bits)
        let reserved2 = data[7];

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + header_len,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_OPT_LEN],
            FieldValue::U8(opt_len),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_OAM],
            FieldValue::U8(oam),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CRITICAL],
            FieldValue::U8(critical),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_RESERVED],
            FieldValue::U8(reserved),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PROTOCOL_TYPE],
            FieldValue::U16(protocol_type),
            offset + 2..offset + 4,
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

        // RFC 8926, Section 3.5 — Tunnel Options (variable-length TLVs).
        // The individual option TLVs are not parsed here; the raw option block
        // is exposed verbatim for downstream inspection.
        if opt_len > 0 {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_OPTIONS],
                FieldValue::Bytes(&data[8..header_len]),
                offset + 8..offset + header_len,
            );
        }
        buf.end_layer();

        Ok(DissectResult::new(
            header_len,
            DispatchHint::ByEtherType(protocol_type),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 8926 (GENEVE) Coverage
    //
    // | RFC Section | Description                     | Test                              |
    // |-------------|---------------------------------|-----------------------------------|
    // | 3.4         | Tunnel header fields            | parse_geneve_basic                |
    // | 3.4         | Version validation (Ver != 0)   | parse_geneve_invalid_version      |
    // | 3.4         | All invalid versions rejected   | parse_geneve_all_invalid_versions |
    // | 3.4         | OAM (O) flag                    | parse_geneve_oam_flag             |
    // | 3.4         | Critical (C) flag               | parse_geneve_critical_flag        |
    // | 3.4         | Reserved bits ignored on recv   | parse_geneve_reserved_bits_set    |
    // | 3.4         | VNI parsing (24 bits)           | parse_geneve_vni                  |
    // | 3.4         | Protocol Type dispatch          | parse_geneve_dispatch_ipv6        |
    // | 3.4         | Truncated fixed header          | parse_geneve_truncated            |
    // | 3.4         | Offset handling                 | parse_geneve_with_offset          |
    // | 3.5         | Variable-length options present | parse_geneve_with_options         |
    // | 3.5         | Max Opt Len (63 × 4 bytes)      | parse_geneve_max_opt_len          |
    // | 3.5         | Truncated options               | parse_geneve_truncated_options    |

    /// Helper: dissect raw bytes at offset 0 and return the result.
    fn dissect(data: &[u8]) -> Result<(DissectBuffer<'_>, DissectResult), PacketError> {
        let mut buf = DissectBuffer::new();
        let result = GeneveDissector.dissect(data, &mut buf, 0)?;
        Ok((buf, result))
    }

    #[test]
    fn parse_geneve_basic() {
        // Minimal GENEVE header: Ver=0, OptLen=0, O=0, C=0,
        // Protocol Type=0x6558 (Transparent Ethernet Bridging), VNI=1
        let raw: &[u8] = &[
            0x00, // Ver=0, OptLen=0
            0x00, // O=0, C=0, Rsvd=0
            0x65, 0x58, // Protocol Type: Transparent Ethernet Bridging
            0x00, 0x00, 0x01, // VNI = 1
            0x00, // Reserved
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));

        let layer = buf.layer_by_name("GENEVE").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "opt_len").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "oam").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "critical").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "reserved").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "protocol_type").unwrap().value,
            FieldValue::U16(0x6558)
        );
        assert_eq!(
            buf.field_by_name(layer, "vni").unwrap().value,
            FieldValue::U32(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "reserved2").unwrap().value,
            FieldValue::U8(0)
        );
        assert!(buf.field_by_name(layer, "options").is_none());
    }

    #[test]
    fn parse_geneve_invalid_version() {
        // Version = 1 (bits 6-7 of byte 0)
        let raw: &[u8] = &[
            0x40, // Ver=1, OptLen=0
            0x00, // O=0, C=0
            0x65, 0x58, // Protocol Type
            0x00, 0x00, 0x01, // VNI
            0x00, // Reserved
        ];
        let err = GeneveDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "version",
                value: 1
            }
        ));
    }

    #[test]
    fn parse_geneve_with_options() {
        // OptLen=2 → 8 bytes of options (2 × 4)
        let raw: &[u8] = &[
            0x02, // Ver=0, OptLen=2
            0x00, // O=0, C=0
            0x65, 0x58, // Protocol Type
            0x00, 0x00, 0x0A, // VNI = 10
            0x00, // Reserved
            // Options: 8 bytes (2 × 4-byte words)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 16);

        let layer = buf.layer_by_name("GENEVE").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "opt_len").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "vni").unwrap().value,
            FieldValue::U32(10)
        );
        assert_eq!(
            buf.field_by_name(layer, "options").unwrap().value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        );
    }

    #[test]
    fn parse_geneve_oam_flag() {
        // O=1
        let raw: &[u8] = &[
            0x00, // Ver=0, OptLen=0
            0x80, // O=1, C=0
            0x65, 0x58, // Protocol Type
            0x00, 0x00, 0x01, // VNI
            0x00, // Reserved
        ];
        let (buf, _) = dissect(raw).unwrap();
        let layer = buf.layer_by_name("GENEVE").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "oam").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "critical").unwrap().value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_geneve_critical_flag() {
        // C=1
        let raw: &[u8] = &[
            0x00, // Ver=0, OptLen=0
            0x40, // O=0, C=1
            0x65, 0x58, // Protocol Type
            0x00, 0x00, 0x01, // VNI
            0x00, // Reserved
        ];
        let (buf, _) = dissect(raw).unwrap();
        let layer = buf.layer_by_name("GENEVE").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "oam").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "critical").unwrap().value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_geneve_vni() {
        // VNI = 0xABCDEF
        let raw: &[u8] = &[
            0x00, // Ver=0, OptLen=0
            0x00, // O=0, C=0
            0x65, 0x58, // Protocol Type
            0xAB, 0xCD, 0xEF, // VNI = 0xABCDEF
            0x00, // Reserved
        ];
        let (buf, _) = dissect(raw).unwrap();
        let layer = buf.layer_by_name("GENEVE").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "vni").unwrap().value,
            FieldValue::U32(0x00AB_CDEF)
        );
    }

    #[test]
    fn parse_geneve_dispatch_ipv6() {
        // Protocol Type = 0x86DD (IPv6)
        let raw: &[u8] = &[
            0x00, // Ver=0, OptLen=0
            0x00, // O=0, C=0
            0x86, 0xDD, // Protocol Type: IPv6
            0x00, 0x00, 0x01, // VNI
            0x00, // Reserved
        ];
        let (_, result) = dissect(raw).unwrap();
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn parse_geneve_truncated() {
        let raw: &[u8] = &[0x00, 0x00, 0x65, 0x58, 0x00, 0x00, 0x01]; // 7 bytes
        let err = GeneveDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 7
            }
        ));
    }

    #[test]
    fn parse_geneve_truncated_options() {
        // OptLen=1 but no option bytes present
        let raw: &[u8] = &[
            0x01, // Ver=0, OptLen=1
            0x00, // O=0, C=0
            0x65, 0x58, // Protocol Type
            0x00, 0x00, 0x01, // VNI
            0x00, // Reserved
                  // Missing 4 bytes of options
        ];
        let err = GeneveDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 12,
                actual: 8
            }
        ));
    }

    #[test]
    fn parse_geneve_with_offset() {
        let raw: &[u8] = &[
            0x01, // Ver=0, OptLen=1
            0xC0, // O=1, C=1
            0x65, 0x58, // Protocol Type
            0x00, 0x00, 0x0A, // VNI = 10
            0x00, // Reserved
            0xAA, 0xBB, 0xCC, 0xDD, // Options (4 bytes)
        ];
        let mut buf = DissectBuffer::new();
        let result = GeneveDissector.dissect(raw, &mut buf, 100).unwrap();
        assert_eq!(result.bytes_consumed, 12);

        let layer = buf.layer_by_name("GENEVE").unwrap();
        assert_eq!(layer.range, 100..112);
        assert_eq!(buf.field_by_name(layer, "version").unwrap().range, 100..101);
        assert_eq!(
            buf.field_by_name(layer, "protocol_type").unwrap().range,
            102..104
        );
        assert_eq!(buf.field_by_name(layer, "vni").unwrap().range, 104..107);
        assert_eq!(buf.field_by_name(layer, "options").unwrap().range, 108..112);
    }

    #[test]
    fn parse_geneve_all_invalid_versions() {
        // RFC 8926 §3.4: "Packets received by a tunnel endpoint with an unknown
        // version MUST be dropped." Version is 2 bits — only 0 is defined.
        for version in [1u8, 2, 3] {
            let raw: &[u8] = &[
                version << 6, // Ver in top 2 bits, OptLen=0
                0x00,
                0x65,
                0x58,
                0x00,
                0x00,
                0x01,
                0x00,
            ];
            let err = GeneveDissector
                .dissect(raw, &mut DissectBuffer::new(), 0)
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    PacketError::InvalidFieldValue {
                        field: "version",
                        value,
                    } if value == u32::from(version)
                ),
                "expected InvalidFieldValue for Ver={version}, got {err:?}",
            );
        }
    }

    #[test]
    fn parse_geneve_reserved_bits_set() {
        // RFC 8926 §3.4: Rsvd. (6 bits) and Reserved (8 bits) "MUST be zero on
        // transmission and MUST be ignored on receipt." A well-behaved dissector
        // surfaces the bits as parsed values without rejecting the packet.
        let raw: &[u8] = &[
            0x00, // Ver=0, OptLen=0
            0x3F, // O=0, C=0, Rsvd.=0x3F (all reserved bits set)
            0x65, 0x58, // Protocol Type
            0x00, 0x00, 0x01, // VNI
            0xFF, // Reserved (8 bits) all set
        ];
        let (buf, _) = dissect(raw).unwrap();
        let layer = buf.layer_by_name("GENEVE").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "reserved").unwrap().value,
            FieldValue::U8(0x3F)
        );
        assert_eq!(
            buf.field_by_name(layer, "reserved2").unwrap().value,
            FieldValue::U8(0xFF)
        );
        // OAM / Critical must not be affected by the high 2 bits already = 0.
        assert_eq!(
            buf.field_by_name(layer, "oam").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "critical").unwrap().value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_geneve_max_opt_len() {
        // RFC 8926 §3.4: "Opt Len (6 bits): The length of the option fields,
        // expressed in 4-byte multiples, not including the 8-byte fixed tunnel
        // header." The 6-bit field caps Opt Len at 63 (= 252 bytes of options),
        // yielding a 260-byte total header.
        const MAX_OPT_LEN_WORDS: u8 = 0x3F;
        const OPTIONS_BYTES: usize = MAX_OPT_LEN_WORDS as usize * 4;
        const TOTAL_HEADER: usize = 8 + OPTIONS_BYTES;

        let mut raw = vec![0u8; TOTAL_HEADER];
        raw[0] = MAX_OPT_LEN_WORDS; // Ver=0, OptLen=63
        raw[1] = 0x00; // O=0, C=0
        raw[2] = 0x65;
        raw[3] = 0x58; // Protocol Type = TEB
        raw[4] = 0x00;
        raw[5] = 0x00;
        raw[6] = 0x2A; // VNI=42
        raw[7] = 0x00;
        for (i, slot) in raw[8..].iter_mut().enumerate() {
            *slot = (i & 0xFF) as u8;
        }

        let (buf, result) = dissect(&raw).unwrap();
        assert_eq!(result.bytes_consumed, TOTAL_HEADER);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));

        let layer = buf.layer_by_name("GENEVE").unwrap();
        assert_eq!(layer.range, 0..TOTAL_HEADER);
        assert_eq!(
            buf.field_by_name(layer, "opt_len").unwrap().value,
            FieldValue::U8(MAX_OPT_LEN_WORDS)
        );
        let options = buf.field_by_name(layer, "options").unwrap();
        assert_eq!(options.range, 8..TOTAL_HEADER);
        assert_eq!(options.value, FieldValue::Bytes(&raw[8..TOTAL_HEADER]));
    }

    #[test]
    fn field_descriptors_consistent() {
        let descs = GeneveDissector.field_descriptors();
        assert_eq!(descs.len(), 9);
        assert_eq!(descs[FD_VERSION].name, "version");
        assert_eq!(descs[FD_OPT_LEN].name, "opt_len");
        assert_eq!(descs[FD_OAM].name, "oam");
        assert_eq!(descs[FD_CRITICAL].name, "critical");
        assert_eq!(descs[FD_RESERVED].name, "reserved");
        assert_eq!(descs[FD_PROTOCOL_TYPE].name, "protocol_type");
        assert_eq!(descs[FD_VNI].name, "vni");
        assert_eq!(descs[FD_RESERVED2].name, "reserved2");
        assert_eq!(descs[FD_OPTIONS].name, "options");
    }
}
