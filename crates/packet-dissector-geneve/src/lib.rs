//! GENEVE (Generic Network Virtualization Encapsulation) dissector.
//!
//! ## References
//! - RFC 8926: <https://www.rfc-editor.org/rfc/rfc8926>
//!   - §3.4 Tunnel Header Fields: <https://www.rfc-editor.org/rfc/rfc8926#section-3.4>
//!   - §3.5 Tunnel Options: <https://www.rfc-editor.org/rfc/rfc8926#section-3.5>
//! - IANA Geneve Option Class registry:
//!   <https://www.iana.org/assignments/nvo3/nvo3.xhtml#geneve-option-class>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
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
const FD_TUNNEL_OPTIONS: usize = 9;
const FD_OPTIONS_MALFORMED: usize = 10;

/// Size of a Geneve option header (Option Class, Type, R, Length).
///
/// RFC 8926, Section 3.5 — <https://www.rfc-editor.org/rfc/rfc8926#section-3.5>
const OPTION_HEADER_SIZE: usize = 4;

/// Return the IANA "Geneve Option Class" registry description of `class`.
///
/// IANA Geneve Option Class registry —
/// <https://www.iana.org/assignments/nvo3/nvo3.xhtml#geneve-option-class>
fn option_class_name(class: u16) -> Option<&'static str> {
    match class {
        0x0100 => Some("Linux"),
        0x0101 => Some("Open vSwitch (OVS)"),
        0x0102 => Some("Open Virtual Networking (OVN)"),
        0x0103 => Some("In-band Network Telemetry (INT)"),
        0x0104 => Some("VMware, Inc."),
        0x0105 | 0x0108..=0x0110 => Some("Amazon.com, Inc."),
        0x0106 | 0x0130..=0x0131 => Some("Cisco Systems, Inc."),
        0x0107 => Some("Oracle Corporation"),
        0x0111..=0x0118 => Some("IBM"),
        0x0119..=0x0128 => Some("Ericsson"),
        0x0129 => Some("Oxide Computer Company"),
        0x0132..=0x0135 => Some("Google LLC"),
        0x0136 => Some("InfoQuick Global Connection Tech Ltd."),
        0x0137..=0x0140 => Some("Alibaba, inc"),
        0x0141..=0x0144 => Some("Palo Alto Networks"),
        0x0145..=0x0149 => Some("Huawei Technologies Co., Ltd"),
        0x014A => Some("EMnify GmbH"),
        0x014B => Some("Cilium"),
        0x014C => Some("Corelight, Inc."),
        0x014D => Some("1NCE GmbH"),
        0x014E..=0x0157 => Some("Cloud of China Telecom (CTYUN)"),
        0x0158..=0x0161 => Some("Volcengine, inc"),
        0x0162 => Some("nat64.net"),
        0x0163 => Some("Multi Segment SD-WAN"),
        0x0164 => Some("cPacket Networks"),
        0x0165..=0x0167 => Some("Tencent"),
        0x0168 => Some("ExtraHop Networks, Inc."),
        0x0169 => Some("Soosan INT Co., Ltd."),
        0x016A..=0x016C => Some("Spacelink, Inc"),
        0x016D => Some("617A Corporation"),
        0x016E => Some("Zscaler"),
        0x016F..=0x0170 => Some("7Generation"),
        0xFF00..=0xFFFF => Some("Experimental Use"),
        _ => None,
    }
}

/// Child field descriptor indices for one Geneve option object.
const OFD_CLASS: usize = 0;
const OFD_TYPE: usize = 1;
const OFD_CRITICAL: usize = 2;
const OFD_RESERVED: usize = 3;
const OFD_LENGTH: usize = 4;
const OFD_DATA: usize = 5;

/// Fields of one tunnel option (RFC 8926, Section 3.5).
///
/// <https://www.rfc-editor.org/rfc/rfc8926#section-3.5>
static OPTION_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("class", "Option Class", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(c) => option_class_name(*c),
        _ => None,
    }),
    FieldDescriptor::new("type", "Type", FieldType::U8),
    FieldDescriptor::new("critical", "Critical (C bit of Type)", FieldType::U8),
    FieldDescriptor::new("reserved", "Reserved (R)", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("data", "Option Data", FieldType::Bytes),
];

/// Descriptor of one option object inside `tunnel_options`.
static FD_OPTION: FieldDescriptor = FieldDescriptor::new("option", "Option", FieldType::Object)
    .with_children(OPTION_FIELD_DESCRIPTORS);

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
    FieldDescriptor::new("tunnel_options", "Tunnel Options", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_OPTION)),
    // RFC 8926, Section 3.5 — set when an option runs past Opt Len.
    // https://www.rfc-editor.org/rfc/rfc8926#section-3.5
    FieldDescriptor::new(
        "options_malformed",
        "Options Length Mismatch",
        FieldType::U8,
    )
    .optional(),
];

/// GENEVE dissector.
pub struct GeneveDissector;

/// Specification references for the GENEVE dissector.
static REFERENCES: &[SpecReference] = &[SpecReference::new(
    "RFC 8926",
    "Geneve: Generic Network Virtualization Encapsulation",
    "https://www.rfc-editor.org/rfc/rfc8926",
)];

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
        // The raw option block is kept in `options`; `tunnel_options` lists
        // the decoded option headers and their data.
        // https://www.rfc-editor.org/rfc/rfc8926#section-3.5
        if opt_len > 0 {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_OPTIONS],
                FieldValue::Bytes(&data[8..header_len]),
                offset + 8..offset + header_len,
            );
            push_tunnel_options(buf, data, offset, header_len);
        }
        buf.end_layer();

        Ok(DissectResult::new(
            header_len,
            DispatchHint::ByEtherType(protocol_type),
        ))
    }
}

/// Push the `tunnel_options` array for the option block
/// `data[MIN_HEADER_SIZE..header_len]`.
///
/// RFC 8926, Section 3.5 — "Packets in which the total length of all
/// options is not equal to the 'Opt Len' in the base header are invalid".
/// Opt Len and every option are 4-byte multiples, so a mismatch shows up as
/// an option that runs past the end of the block. Decoding stops there and
/// `options_malformed` covers the rest of the block; the payload after Opt
/// Len is still dispatched.
/// <https://www.rfc-editor.org/rfc/rfc8926#section-3.5>
fn push_tunnel_options<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    header_len: usize,
) {
    let list_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_TUNNEL_OPTIONS],
        FieldValue::Array(0..0),
        offset + MIN_HEADER_SIZE..offset + header_len,
    );
    let mut pos = MIN_HEADER_SIZE;
    let mut malformed_at = None;
    // The block is a 4-byte multiple, so a whole option header always fits.
    while pos < header_len {
        // |Option Class (16)|Type (8)|R|R|R|Length (5)|
        let class = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let option_type = data[pos + 2];
        let reserved = data[pos + 3] >> 5;
        let length = data[pos + 3] & 0x1F;
        let data_start = pos + OPTION_HEADER_SIZE;
        let end = data_start + length as usize * 4;
        if end > header_len {
            malformed_at = Some(pos);
            break;
        }

        let obj_idx = buf.begin_container(
            &FD_OPTION,
            FieldValue::Object(0..0),
            offset + pos..offset + end,
        );
        buf.push_field(
            &OPTION_FIELD_DESCRIPTORS[OFD_CLASS],
            FieldValue::U16(class),
            offset + pos..offset + pos + 2,
        );
        buf.push_field(
            &OPTION_FIELD_DESCRIPTORS[OFD_TYPE],
            FieldValue::U8(option_type),
            offset + pos + 2..offset + pos + 3,
        );
        // RFC 8926, Section 3.5 — "The high-order bit of the option type
        // indicates that this is a critical option."
        // https://www.rfc-editor.org/rfc/rfc8926#section-3.5
        buf.push_field(
            &OPTION_FIELD_DESCRIPTORS[OFD_CRITICAL],
            FieldValue::U8(option_type >> 7),
            offset + pos + 2..offset + pos + 3,
        );
        // RFC 8926, Section 3.5 — "R (3 bits): ... MUST be ignored on
        // receipt."
        // https://www.rfc-editor.org/rfc/rfc8926#section-3.5
        buf.push_field(
            &OPTION_FIELD_DESCRIPTORS[OFD_RESERVED],
            FieldValue::U8(reserved),
            offset + pos + 3..offset + pos + 4,
        );
        // RFC 8926, Section 3.5 — "Length (5 bits): Length of the option,
        // expressed in 4-byte multiples, excluding the option header."
        // https://www.rfc-editor.org/rfc/rfc8926#section-3.5
        buf.push_field(
            &OPTION_FIELD_DESCRIPTORS[OFD_LENGTH],
            FieldValue::U8(length),
            offset + pos + 3..offset + pos + 4,
        );
        buf.push_field(
            &OPTION_FIELD_DESCRIPTORS[OFD_DATA],
            FieldValue::Bytes(&data[data_start..end]),
            offset + data_start..offset + end,
        );
        buf.end_container(obj_idx);
        pos = end;
    }
    buf.end_container(list_idx);

    if let Some(bad) = malformed_at {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_OPTIONS_MALFORMED],
            FieldValue::U8(1),
            offset + bad..offset + header_len,
        );
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
    // | 3.5         | Option TLV (class/type/C/R/len) | parse_geneve_option_tlv           |
    // | 3.5         | Multiple options, R ignored     | parse_geneve_two_options          |
    // | 3.5         | Option overruns Opt Len         | parse_geneve_option_overruns_opt_len |
    // | 3.5         | Well-formed options not flagged | parse_geneve_options_well_formed_not_flagged |
    // | 7 / IANA    | Geneve Option Class names       | option_class_names                |

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
            // Option: class 0x0102, type 0x03, R=0, length 1 (4 bytes)
            0x01, 0x02, 0x03, 0x01, 0x05, 0x06, 0x07, 0x08,
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
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x01, 0x05, 0x06, 0x07, 0x08])
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
            0xAA, 0xBB, 0xCC, 0x00, // Option: class 0xAABB, type 0xCC, length 0
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
        // Two options filling 252 bytes: 4 + 31 × 4 = 128 and 4 + 30 × 4 = 124
        // (RFC 8926 §3.5 — "The total length of each option may be between
        // 4 and 128 bytes"). https://www.rfc-editor.org/rfc/rfc8926#section-3.5
        raw[8..12].copy_from_slice(&[0xFF, 0x00, 0x01, 31]);
        raw[136..140].copy_from_slice(&[0xFF, 0x01, 0x02, 30]);

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
        let list = tunnel_options(&buf);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].1.len(), 124);
        assert_eq!(list[1].1.len(), 120);
    }

    /// Return `(class, data)` for each parsed tunnel option object.
    fn tunnel_options<'a>(buf: &'a DissectBuffer<'a>) -> Vec<(u16, &'a [u8])> {
        let layer = buf.layer_by_name("GENEVE").unwrap();
        let list = buf.field_by_name(layer, "tunnel_options").unwrap();
        let range = list.value.as_container_range().unwrap();
        buf.nested_fields(range)
            .iter()
            .filter_map(|f| f.value.as_container_range())
            .map(|obj| {
                let fields = buf.nested_fields(obj);
                let class = fields
                    .iter()
                    .find(|f| f.name() == "class")
                    .and_then(|f| f.value.as_u16())
                    .unwrap();
                let data = fields
                    .iter()
                    .find(|f| f.name() == "data")
                    .and_then(|f| f.value.as_bytes())
                    .unwrap();
                (class, data)
            })
            .collect()
    }

    /// RFC 8926 §3.5 — one option: class 0x0102 (OVN), type 0x80 with the
    /// critical bit set, R=0, length 1 (4 bytes of data).
    /// <https://www.rfc-editor.org/rfc/rfc8926#section-3.5>
    #[test]
    fn parse_geneve_option_tlv() {
        let raw: &[u8] = &[
            0x02, 0x00, 0x65, 0x58, // Ver 0, Opt Len 2, O=0, C=0, TEB
            0x00, 0x00, 0x64, 0x00, // VNI 100
            0x01, 0x02, 0x80, 0x01, // class 0x0102, type 0x80, R=0, length 1
            0xDE, 0xAD, 0xBE, 0xEF, // option data
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 16);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));

        let layer = buf.layer_by_name("GENEVE").unwrap();
        let list = buf.field_by_name(layer, "tunnel_options").unwrap();
        assert_eq!(list.range, 8..16);
        let objects: Vec<_> = buf
            .nested_fields(list.value.as_container_range().unwrap())
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].range, 8..16);
        let obj = objects[0].value.as_container_range().unwrap();
        let fields = buf.nested_fields(obj);
        let get = |name: &str| fields.iter().find(|f| f.name() == name).unwrap();
        assert_eq!(get("class").value, FieldValue::U16(0x0102));
        assert_eq!(get("class").range, 8..10);
        assert_eq!(
            buf.resolve_nested_display_name(obj, "class_name"),
            Some("Open Virtual Networking (OVN)")
        );
        assert_eq!(get("type").value, FieldValue::U8(0x80));
        assert_eq!(get("type").range, 10..11);
        assert_eq!(get("critical").value, FieldValue::U8(1));
        assert_eq!(get("reserved").value, FieldValue::U8(0));
        assert_eq!(get("length").value, FieldValue::U8(1));
        assert_eq!(get("length").range, 11..12);
        assert_eq!(
            get("data").value,
            FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
        );
        assert_eq!(get("data").range, 12..16);
    }

    /// RFC 8926 §3.5 — options follow one another; a zero Length option has
    /// only the 4-byte header; R bits "MUST be ignored on receipt".
    /// <https://www.rfc-editor.org/rfc/rfc8926#section-3.5>
    #[test]
    fn parse_geneve_two_options() {
        let raw: &[u8] = &[
            0x03, 0x00, 0x65, 0x58, // Opt Len 3 (12 bytes)
            0x00, 0x00, 0x01, 0x00, // VNI 1
            0x01, 0x01, 0x05, 0xE0, // class 0x0101 (OVS), type 5, R=0b111, length 0
            0xFF, 0x10, 0x7F, 0x01, // class 0xFF10 (experimental), type 0x7F, length 1
            0x01, 0x02, 0x03, 0x04, // option data
        ];
        let (buf, _) = dissect(raw).unwrap();
        let list = tunnel_options(&buf);
        assert_eq!(list, vec![(0x0101, &[][..]), (0xFF10, &[1, 2, 3, 4][..])]);

        let layer = buf.layer_by_name("GENEVE").unwrap();
        let range = buf
            .field_by_name(layer, "tunnel_options")
            .unwrap()
            .value
            .as_container_range()
            .unwrap()
            .clone();
        let objects: Vec<_> = buf
            .nested_fields(&range)
            .iter()
            .filter_map(|f| f.value.as_container_range())
            .collect();
        let first = buf.nested_fields(objects[0]);
        let reserved = first.iter().find(|f| f.name() == "reserved").unwrap();
        assert_eq!(reserved.value, FieldValue::U8(0x07));
        let critical = first.iter().find(|f| f.name() == "critical").unwrap();
        assert_eq!(critical.value, FieldValue::U8(0));
        assert_eq!(
            buf.resolve_nested_display_name(objects[0], "class_name"),
            Some("Open vSwitch (OVS)")
        );
        assert_eq!(
            buf.resolve_nested_display_name(objects[1], "class_name"),
            Some("Experimental Use")
        );
    }

    /// RFC 8926 §3.5 — "Packets in which the total length of all options is
    /// not equal to the 'Opt Len' in the base header are invalid". The
    /// options before the one that runs past Opt Len are decoded, the
    /// mismatch is reported in `options_malformed`, and the payload after
    /// Opt Len is still dispatched.
    /// <https://www.rfc-editor.org/rfc/rfc8926#section-3.5>
    #[test]
    fn parse_geneve_option_overruns_opt_len() {
        let raw: &[u8] = &[
            0x03, 0x00, 0x65, 0x58, // Opt Len 3 (12 bytes)
            0x00, 0x00, 0x01, 0x00, // VNI 1
            0x01, 0x00, 0x01, 0x00, // option: class 0x0100, length 0
            0x01, 0x02, 0x01, 0x02, // option: length 2 → 12 bytes, 8 left
            0x00, 0x00, 0x00, 0x00, // option data (partial)
            0xAA, 0xBB, // payload
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 20);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));
        let layer = buf.layer_by_name("GENEVE").unwrap();
        let malformed = buf.field_by_name(layer, "options_malformed").unwrap();
        assert_eq!(malformed.value, FieldValue::U8(1));
        assert_eq!(malformed.range, 12..20);
        assert_eq!(tunnel_options(&buf), vec![(0x0100, &[][..])]);
    }

    /// Well-formed options carry no `options_malformed` field.
    #[test]
    fn parse_geneve_options_well_formed_not_flagged() {
        let raw: &[u8] = &[
            0x01, 0x00, 0x65, 0x58, // Opt Len 1
            0x00, 0x00, 0x01, 0x00, // VNI 1
            0x01, 0x00, 0x01, 0x00, // option: class 0x0100, length 0
        ];
        let (buf, _) = dissect(raw).unwrap();
        let layer = buf.layer_by_name("GENEVE").unwrap();
        assert!(buf.field_by_name(layer, "options_malformed").is_none());
    }

    #[test]
    fn option_class_names() {
        assert_eq!(option_class_name(0x0100), Some("Linux"));
        assert_eq!(
            option_class_name(0x0103),
            Some("In-band Network Telemetry (INT)")
        );
        assert_eq!(option_class_name(0x0109), Some("Amazon.com, Inc."));
        assert_eq!(option_class_name(0x014B), Some("Cilium"));
        assert_eq!(option_class_name(0x0170), Some("7Generation"));
        assert_eq!(option_class_name(0xFF00), Some("Experimental Use"));
        assert_eq!(option_class_name(0x0000), None);
        assert_eq!(option_class_name(0x012A), None);
        assert_eq!(option_class_name(0x0171), None);
    }

    #[test]
    fn field_descriptors_consistent() {
        let descs = GeneveDissector.field_descriptors();
        assert_eq!(descs.len(), 11);
        assert_eq!(descs[FD_VERSION].name, "version");
        assert_eq!(descs[FD_OPT_LEN].name, "opt_len");
        assert_eq!(descs[FD_OAM].name, "oam");
        assert_eq!(descs[FD_CRITICAL].name, "critical");
        assert_eq!(descs[FD_RESERVED].name, "reserved");
        assert_eq!(descs[FD_PROTOCOL_TYPE].name, "protocol_type");
        assert_eq!(descs[FD_VNI].name, "vni");
        assert_eq!(descs[FD_RESERVED2].name, "reserved2");
        assert_eq!(descs[FD_OPTIONS].name, "options");
        assert_eq!(descs[FD_TUNNEL_OPTIONS].name, "tunnel_options");
        assert_eq!(descs[FD_OPTIONS_MALFORMED].name, "options_malformed");
    }

    /// Every dissector in this crate must cite the specifications it
    /// implements and declare where it sits in the dissection stack.
    #[test]
    fn references_and_layer_are_populated() {
        fn assert_layer_and_references(dissector: &dyn Dissector) {
            let references = dissector.references();
            assert!(!references.is_empty());
            for reference in references {
                assert!(!reference.id.is_empty());
                assert!(!reference.title.is_empty());
                assert!(
                    reference.url.starts_with("https://"),
                    "{} url must start with https://",
                    reference.id
                );
            }
            assert_eq!(dissector.layer(), Some(ProtocolLayer::Tunnel));
        }

        assert_layer_and_references(&GeneveDissector);
    }
}
