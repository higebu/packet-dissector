//! GRE (Generic Routing Encapsulation) dissector.
//!
//! ## References
//! - RFC 2784: <https://www.rfc-editor.org/rfc/rfc2784>
//! - RFC 2890 (Key and Sequence Number Extensions; updates RFC 2784):
//!   <https://www.rfc-editor.org/rfc/rfc2890>
//! - RFC 9601 (ECN propagation requirement for GRE tunnels; updates RFC 2784):
//!   <https://www.rfc-editor.org/rfc/rfc9601>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Minimum GRE header size (no optional fields).
///
/// RFC 2784, Section 2 — The base header contains only the flags/version
/// word (2 octets) and the Protocol Type field (2 octets).
const MIN_HEADER_SIZE: usize = 4;

/// Mask selecting bits of the first 16-bit header word that RFC 2784 requires
/// a non-RFC-1701 receiver to discard when non-zero.
///
/// RFC 2784, Section 2.3 — "Receivers MUST discard a packet where any of bits
/// 1-5 are non-zero, unless that receiver implements RFC 1701". RFC 2890
/// reassigns bits 2 and 3 as the K (Key Present) and S (Sequence Number
/// Present) flags, so the remaining must-be-zero bits are {1, 4, 5}:
/// `1 << (15 - 1) | 1 << (15 - 4) | 1 << (15 - 5) == 0x4C00`.
///
/// RFC 2784, Section 2.3 — <https://www.rfc-editor.org/rfc/rfc2784#section-2.3>
const RESERVED_MUST_BE_ZERO_MASK: u16 = 0x4C00;

/// Field descriptor indices for [`GreDissector::field_descriptors`].
const FD_CHECKSUM_PRESENT: usize = 0;
const FD_KEY_PRESENT: usize = 1;
const FD_SEQUENCE_NUMBER_PRESENT: usize = 2;
const FD_RESERVED0: usize = 3;
const FD_VERSION: usize = 4;
const FD_PROTOCOL_TYPE: usize = 5;
const FD_CHECKSUM: usize = 6;
const FD_RESERVED1: usize = 7;
const FD_KEY: usize = 8;
const FD_SEQUENCE_NUMBER: usize = 9;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("checksum_present", "Checksum Present", FieldType::U8),
    FieldDescriptor::new("key_present", "Key Present", FieldType::U8),
    FieldDescriptor::new(
        "sequence_number_present",
        "Sequence Number Present",
        FieldType::U8,
    ),
    FieldDescriptor::new("reserved0", "Reserved0", FieldType::U16),
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("protocol_type", "Protocol Type", FieldType::U16),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16).optional(),
    FieldDescriptor::new("reserved1", "Reserved1", FieldType::U16).optional(),
    FieldDescriptor::new("key", "Key", FieldType::U32).optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U32).optional(),
];

/// GRE dissector.
pub struct GreDissector;

impl Dissector for GreDissector {
    fn name(&self) -> &'static str {
        "Generic Routing Encapsulation"
    }

    fn short_name(&self) -> &'static str {
        "GRE"
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

        // RFC 2784, Section 2 — Flags/version word (first 2 octets)
        // https://www.rfc-editor.org/rfc/rfc2784#section-2
        let flags_ver = read_be_u16(data, 0)?;

        // RFC 2784, Section 2.1 — Bit 0: Checksum Present (C)
        // https://www.rfc-editor.org/rfc/rfc2784#section-2.1
        let c_flag = ((flags_ver >> 15) & 1) as u8;
        // RFC 2890, Section 2 — Bit 2: Key Present (K)
        // https://www.rfc-editor.org/rfc/rfc2890#section-2
        let k_flag = ((flags_ver >> 13) & 1) as u8;
        // RFC 2890, Section 2 — Bit 3: Sequence Number Present (S)
        // https://www.rfc-editor.org/rfc/rfc2890#section-2
        let s_flag = ((flags_ver >> 12) & 1) as u8;
        // RFC 2890, Section 2 — Reserved0 occupies bits 4-12 of the flags
        // word. RFC 2784, Section 2.3 requires bits 6-12 be ignored on
        // receipt; bits 4-5 are validated below.
        // https://www.rfc-editor.org/rfc/rfc2890#section-2
        let reserved0 = (flags_ver >> 3) & 0x01FF;
        // RFC 2784, Section 2.3.1 — Bits 13-15: Version Number (MUST be 0)
        // https://www.rfc-editor.org/rfc/rfc2784#section-2.3.1
        let version = (flags_ver & 0x0007) as u8;

        // RFC 2784, Section 2.3 — Reject packets that set reserved bits
        // {1, 4, 5} of the flags word. This implementation does not support
        // RFC 1701, so non-zero values in these bits are invalid.
        // https://www.rfc-editor.org/rfc/rfc2784#section-2.3
        if flags_ver & RESERVED_MUST_BE_ZERO_MASK != 0 {
            return Err(PacketError::InvalidFieldValue {
                field: "reserved0",
                value: (flags_ver & RESERVED_MUST_BE_ZERO_MASK) as u32,
            });
        }

        if version != 0 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: version as u32,
            });
        }

        // Compute expected header length based on flags
        let mut header_len = MIN_HEADER_SIZE;
        if c_flag != 0 {
            header_len += 4; // Checksum (2) + Reserved1 (2)
        }
        if k_flag != 0 {
            header_len += 4; // Key (4)
        }
        if s_flag != 0 {
            header_len += 4; // Sequence Number (4)
        }

        if data.len() < header_len {
            return Err(PacketError::Truncated {
                expected: header_len,
                actual: data.len(),
            });
        }

        let protocol_type = read_be_u16(data, 2)?;

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + header_len,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM_PRESENT],
            FieldValue::U8(c_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_KEY_PRESENT],
            FieldValue::U8(k_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER_PRESENT],
            FieldValue::U8(s_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_RESERVED0],
            FieldValue::U16(reserved0),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PROTOCOL_TYPE],
            FieldValue::U16(protocol_type),
            offset + 2..offset + 4,
        );

        // Optional fields — order is always: Checksum+Reserved1, Key, Sequence Number
        let mut pos = MIN_HEADER_SIZE;

        // RFC 2784, Sections 2.5 & 2.6 — Checksum and Reserved1
        // https://www.rfc-editor.org/rfc/rfc2784#section-2.5
        // https://www.rfc-editor.org/rfc/rfc2784#section-2.6
        if c_flag != 0 {
            let checksum = read_be_u16(data, pos)?;
            let reserved1 = read_be_u16(data, pos + 2)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_CHECKSUM],
                FieldValue::U16(checksum),
                offset + pos..offset + pos + 2,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_RESERVED1],
                FieldValue::U16(reserved1),
                offset + pos + 2..offset + pos + 4,
            );
            pos += 4;
        }

        // RFC 2890, Section 2.1 — Key
        // https://www.rfc-editor.org/rfc/rfc2890#section-2.1
        if k_flag != 0 {
            let key = read_be_u32(data, pos)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_KEY],
                FieldValue::U32(key),
                offset + pos..offset + pos + 4,
            );
            pos += 4;
        }

        // RFC 2890, Section 2.2 — Sequence Number
        // https://www.rfc-editor.org/rfc/rfc2890#section-2.2
        if s_flag != 0 {
            let seq = read_be_u32(data, pos)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                FieldValue::U32(seq),
                offset + pos..offset + pos + 4,
            );
        }

        buf.end_layer();

        // RFC 2784, Section 2.4 — Protocol Type is an EtherType value.
        // https://www.rfc-editor.org/rfc/rfc2784#section-2.4
        Ok(DissectResult::new(
            header_len,
            DispatchHint::ByEtherType(protocol_type),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 2784 / RFC 2890 (GRE) Coverage
    //
    // | RFC Section  | Description                          | Test                                  |
    // |--------------|--------------------------------------|---------------------------------------|
    // | 2784 §2      | Base header format                   | parse_gre_basic                       |
    // | 2784 §2.3    | Reserved0 bits 6-12 ignored          | parse_gre_reserved_bits_6_to_12       |
    // | 2784 §2.3    | Reject non-zero bit 1                | parse_gre_rejects_reserved_bit1       |
    // | 2784 §2.3    | Reject non-zero bit 4                | parse_gre_rejects_reserved_bit4       |
    // | 2784 §2.3    | Reject non-zero bit 5                | parse_gre_rejects_reserved_bit5       |
    // | 2784 §2.3.1  | Version validation                   | parse_gre_invalid_version             |
    // | 2784 §2.4    | Protocol Type dispatch (IPv6)        | parse_gre_dispatch_ipv6               |
    // | 2784 §2.5    | Checksum present                     | parse_gre_with_checksum               |
    // | 2784 §2.6    | Reserved1 present                    | parse_gre_with_checksum               |
    // | 2890 §2.1    | Key present                          | parse_gre_with_key                    |
    // | 2890 §2.2    | Sequence Number present              | parse_gre_with_sequence_number        |
    // | 2784 + 2890  | All optional fields                  | parse_gre_all_options                 |
    // | 2784 §2      | Truncated base header                | parse_gre_truncated                   |
    // | 2784 §2      | Truncated optional fields            | parse_gre_truncated_optional_fields   |

    /// Helper: dissect raw bytes at offset 0 and return the result.
    fn dissect(data: &[u8]) -> Result<(DissectBuffer<'_>, DissectResult), PacketError> {
        let mut buf = DissectBuffer::new();
        let result = GreDissector.dissect(data, &mut buf, 0)?;
        Ok((buf, result))
    }

    #[test]
    fn parse_gre_basic() {
        // Minimal GRE header: C=0, K=0, S=0, Ver=0, Protocol Type=0x0800 (IPv4)
        let raw: &[u8] = &[
            0x00, 0x00, // flags=0, version=0
            0x08, 0x00, // Protocol Type: IPv4
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "checksum_present").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "key_present").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_number_present")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "reserved0").unwrap().value,
            FieldValue::U16(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "protocol_type").unwrap().value,
            FieldValue::U16(0x0800)
        );
        assert!(buf.field_by_name(layer, "checksum").is_none());
        assert!(buf.field_by_name(layer, "key").is_none());
        assert!(buf.field_by_name(layer, "sequence_number").is_none());
    }

    #[test]
    fn parse_gre_with_checksum() {
        // C=1 → Checksum + Reserved1 present (8 bytes total)
        let raw: &[u8] = &[
            0x80, 0x00, // C=1, rest=0
            0x08, 0x00, // Protocol Type: IPv4
            0xAB, 0xCD, // Checksum
            0x00, 0x00, // Reserved1
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 8);

        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "checksum_present").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "checksum").unwrap().value,
            FieldValue::U16(0xABCD)
        );
        assert_eq!(
            buf.field_by_name(layer, "reserved1").unwrap().value,
            FieldValue::U16(0)
        );
    }

    #[test]
    fn parse_gre_with_key() {
        // K=1 → Key present (8 bytes total)
        let raw: &[u8] = &[
            0x20, 0x00, // K=1 (bit 2 of byte 0 = 0x20)
            0x08, 0x00, // Protocol Type: IPv4
            0x00, 0x01, 0x02, 0x03, // Key
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 8);

        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "key_present").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "key").unwrap().value,
            FieldValue::U32(0x00010203)
        );
        assert!(buf.field_by_name(layer, "checksum").is_none());
    }

    #[test]
    fn parse_gre_with_sequence_number() {
        // S=1 → Sequence Number present (8 bytes total)
        let raw: &[u8] = &[
            0x10, 0x00, // S=1 (bit 3 of byte 0 = 0x10)
            0x86, 0xDD, // Protocol Type: IPv6
            0x00, 0x00, 0x00, 0x2A, // Sequence Number = 42
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));

        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "sequence_number_present")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_number").unwrap().value,
            FieldValue::U32(42)
        );
    }

    #[test]
    fn parse_gre_all_options() {
        // C=1, K=1, S=1 → 16 bytes total
        let raw: &[u8] = &[
            0xB0, 0x00, // C=1, K=1, S=1 (0x80|0x20|0x10 = 0xB0)
            0x08, 0x00, // Protocol Type: IPv4
            0x12, 0x34, // Checksum
            0x00, 0x00, // Reserved1
            0xDE, 0xAD, 0xBE, 0xEF, // Key
            0x00, 0x00, 0x00, 0x01, // Sequence Number = 1
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 16);

        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "checksum_present").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "key_present").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_number_present")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "checksum").unwrap().value,
            FieldValue::U16(0x1234)
        );
        assert_eq!(
            buf.field_by_name(layer, "key").unwrap().value,
            FieldValue::U32(0xDEADBEEF)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_number").unwrap().value,
            FieldValue::U32(1)
        );
    }

    #[test]
    fn parse_gre_truncated() {
        let raw: &[u8] = &[0x00, 0x00, 0x08]; // Only 3 bytes
        let err = GreDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 3
            }
        ));
    }

    #[test]
    fn parse_gre_invalid_version() {
        // Version = 1 (bits 13-15 of the flags word)
        let raw: &[u8] = &[
            0x00, 0x01, // Version = 1
            0x08, 0x00, // Protocol Type: IPv4
        ];
        let err = GreDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "version",
                value: 1,
            }
        ));
    }

    #[test]
    fn parse_gre_truncated_optional_fields() {
        // C=1 but only 4 bytes available (need 8)
        let raw: &[u8] = &[
            0x80, 0x00, // C=1
            0x08, 0x00, // Protocol Type: IPv4
        ];
        let err = GreDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 4
            }
        ));
    }

    #[test]
    fn parse_gre_dispatch_ipv6() {
        let raw: &[u8] = &[
            0x00, 0x00, // flags=0
            0x86, 0xDD, // Protocol Type: IPv6
        ];
        let (_, result) = dissect(raw).unwrap();
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
    }

    /// RFC 2784, Section 2.3: "Receivers MUST discard a packet where any of
    /// bits 1-5 are non-zero, unless that receiver implements RFC 1701."
    /// Bit 1 of the flags word was R (Routing Present) in RFC 1701 and has
    /// no definition in RFC 2784 or RFC 2890; a non-zero value MUST cause
    /// rejection.
    #[test]
    fn parse_gre_rejects_reserved_bit1() {
        // 0x40 = bit 1 set (binary 0100 0000 in byte 0).
        let raw: &[u8] = &[0x40, 0x00, 0x08, 0x00];
        let err = GreDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "reserved0",
                value: 0x4000,
            }
        ));
    }

    /// RFC 2784, Section 2.3: bit 4 of the flags word MUST be zero for
    /// non-RFC-1701 receivers.
    #[test]
    fn parse_gre_rejects_reserved_bit4() {
        // 0x08 = bit 4 set (binary 0000 1000 in byte 0).
        let raw: &[u8] = &[0x08, 0x00, 0x08, 0x00];
        let err = GreDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "reserved0",
                value: 0x0800,
            }
        ));
    }

    /// RFC 2784, Section 2.3: bit 5 of the flags word MUST be zero for
    /// non-RFC-1701 receivers.
    #[test]
    fn parse_gre_rejects_reserved_bit5() {
        // 0x04 = bit 5 set (binary 0000 0100 in byte 0).
        let raw: &[u8] = &[0x04, 0x00, 0x08, 0x00];
        let err = GreDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidFieldValue {
                field: "reserved0",
                value: 0x0400,
            }
        ));
    }

    /// RFC 2784, Section 2.3: "Bits 6-12 are reserved for future use. These
    /// bits MUST be sent as zero and MUST be ignored on receipt." The
    /// dissector must accept such packets and expose the received bits via
    /// the `reserved0` field.
    #[test]
    fn parse_gre_reserved_bits_6_to_12() {
        // Set bits 6-12 all to 1. In byte terms:
        //   byte 0 bits (RFC 6, RFC 7) = 0x03
        //   byte 1 bits (RFC 8..12)    = 0xF8
        // flags_ver = 0x03F8. Reserved0 = (flags_ver >> 3) & 0x1FF = 0x7F.
        let raw: &[u8] = &[0x03, 0xF8, 0x08, 0x00];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 4);

        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "reserved0").unwrap().value,
            FieldValue::U16(0x7F)
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_gre_with_offset() {
        // Verify byte ranges use the offset parameter correctly
        let raw: &[u8] = &[
            0x20, 0x00, // K=1
            0x08, 0x00, // Protocol Type: IPv4
            0x00, 0x00, 0x00, 0x01, // Key = 1
        ];
        let mut buf = DissectBuffer::new();
        let result = GreDissector.dissect(raw, &mut buf, 100).unwrap();
        assert_eq!(result.bytes_consumed, 8);

        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(layer.range, 100..108);
        assert_eq!(
            buf.field_by_name(layer, "protocol_type").unwrap().range,
            102..104
        );
        assert_eq!(buf.field_by_name(layer, "key").unwrap().range, 104..108);
    }

    #[test]
    fn field_descriptors_consistent() {
        let descs = GreDissector.field_descriptors();
        assert_eq!(descs.len(), 10);
        assert_eq!(descs[FD_CHECKSUM_PRESENT].name, "checksum_present");
        assert_eq!(descs[FD_KEY_PRESENT].name, "key_present");
        assert_eq!(
            descs[FD_SEQUENCE_NUMBER_PRESENT].name,
            "sequence_number_present"
        );
        assert_eq!(descs[FD_RESERVED0].name, "reserved0");
        assert_eq!(descs[FD_VERSION].name, "version");
        assert_eq!(descs[FD_PROTOCOL_TYPE].name, "protocol_type");
        assert_eq!(descs[FD_CHECKSUM].name, "checksum");
        assert_eq!(descs[FD_RESERVED1].name, "reserved1");
        assert_eq!(descs[FD_KEY].name, "key");
        assert_eq!(descs[FD_SEQUENCE_NUMBER].name, "sequence_number");
    }
}
