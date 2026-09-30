//! ERSPAN (Encapsulated Remote Switch Port Analyzer) dissector.
//!
//! ERSPAN carries mirrored frames inside GRE. The GRE Protocol Type selects
//! the variant: 0x88BE for Type I and Type II, 0x22EB for Type III
//! (draft-foschiano-erspan-03, Section 4). Type I has no ERSPAN header and
//! is told apart from Type II by the GRE Sequence Number Present (S) bit
//! (Sections 4.1 and 4.2).
//!
//! The draft places a 4-octet CRC after the mirrored frame of Types II and
//! III (Sections 4.2 and 4.3). Whether captures carry it varies by platform,
//! so it is not stripped: it stays part of the payload handed to the next
//! dissector.
//!
//! ERSPAN is specified only in an expired individual Internet-Draft; there
//! is no RFC.
//!
//! ## References
//! - draft-foschiano-erspan-03:
//!   <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03>
//! - RFC 2784, Section 2.4 (GRE Protocol Type):
//!   <https://www.rfc-editor.org/rfc/rfc2784#section-2.4>
//! - RFC 2890, Section 2.2 (GRE Sequence Number):
//!   <https://www.rfc-editor.org/rfc/rfc2890#section-2.2>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

use packet_dissector_core::util::{read_be_u32, read_be_u64};

/// ERSPAN Type II header size (draft-foschiano-erspan-03, Section 4.2 —
/// "ERSPAN Type II header (8 octets [42:49])").
///
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.2>
const TYPE2_HEADER_SIZE: usize = 8;

/// ERSPAN Type III mandatory header size (draft-foschiano-erspan-03,
/// Section 4.3 — "a mandatory 12-octet portion").
///
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3>
const TYPE3_HEADER_SIZE: usize = 12;

/// ERSPAN Type III platform-specific sub-header size
/// (draft-foschiano-erspan-03, Section 4.3 — "an optional 8-octet
/// platform-specific sub-header").
///
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3>
const TYPE3_SUBHEADER_SIZE: usize = 8;

/// Ver value of an ERSPAN Type II header (draft-foschiano-erspan-03,
/// Section 4.2 — "Set to 0x1 for Type II.").
///
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.2>
const VERSION_TYPE2: u8 = 1;

/// Ver value of an ERSPAN Type III header (draft-foschiano-erspan-03,
/// Section 4.3 — "For Type-III packets it is set to 0x2.").
///
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3>
const VERSION_TYPE3: u8 = 2;

/// Frame Type "Ethernet frame (802.3 frame)" (draft-foschiano-erspan-03,
/// Section 4.3).
///
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3>
const FRAME_TYPE_ETHERNET: u8 = 0;

/// Frame Type "IP Packet" (draft-foschiano-erspan-03, Section 4.3).
///
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3>
const FRAME_TYPE_IP: u8 = 2;

/// EtherType of Transparent Ethernet Bridging, under which the Ethernet
/// dissector is registered for tunnelled frames.
const ETHERTYPE_TEB: u16 = 0x6558;

/// IPv4 EtherType.
const ETHERTYPE_IPV4: u16 = 0x0800;

/// IPv6 EtherType.
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Mask of the 58-bit Platform Specific Info field (draft-foschiano-erspan-03,
/// Section 4.3).
///
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3>
const PLATFORM_INFO_MASK: u64 = (1 << 58) - 1;

/// Name of the Type II En (trunk encapsulation type) value.
///
/// draft-foschiano-erspan-03, Section 4.2 —
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.2>
fn encap_type_name(en: u8) -> &'static str {
    match en {
        0 => "Originally without VLAN tag",
        1 => "Originally ISL encapsulated",
        2 => "Originally 802.1Q encapsulated",
        _ => "VLAN tag preserved in frame",
    }
}

/// Name of the Type III BSO (Bad/Short/Oversized) value.
///
/// draft-foschiano-erspan-03, Section 4.3 —
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3>
fn bso_name(bso: u8) -> &'static str {
    match bso {
        0 => "Good frame or unknown integrity",
        1 => "Short frame",
        2 => "Oversized frame",
        _ => "Bad frame (CRC or alignment error)",
    }
}

/// Name of the Type III FT (Frame Type) value.
///
/// draft-foschiano-erspan-03, Section 4.3 —
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3>
fn frame_type_name(ft: u8) -> &'static str {
    match ft {
        FRAME_TYPE_ETHERNET => "Ethernet frame",
        FRAME_TYPE_IP => "IP packet",
        _ => "Reserved",
    }
}

/// Name of the Type III D (Direction) value.
///
/// draft-foschiano-erspan-03, Section 4.3 —
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3>
fn direction_name(d: u8) -> &'static str {
    if d == 0 { "Ingress" } else { "Egress" }
}

/// Name of the Type III Gra (Timestamp Granularity) value.
///
/// draft-foschiano-erspan-03, Section 4.3 —
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3>
fn granularity_name(gra: u8) -> &'static str {
    match gra {
        0 => "100 microseconds",
        1 => "100 nanoseconds",
        2 => "IEEE 1588",
        _ => "User configurable",
    }
}

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_VERSION: usize = 0;
const FD_VLAN: usize = 1;
const FD_COS: usize = 2;
const FD_ENCAP_TYPE: usize = 3;
const FD_BSO: usize = 4;
const FD_TRUNCATED: usize = 5;
const FD_SESSION_ID: usize = 6;
const FD_RESERVED: usize = 7;
const FD_INDEX: usize = 8;
const FD_TIMESTAMP: usize = 9;
const FD_SGT: usize = 10;
const FD_PDU_FRAME: usize = 11;
const FD_FRAME_TYPE: usize = 12;
const FD_HW_ID: usize = 13;
const FD_DIRECTION: usize = 14;
const FD_GRANULARITY: usize = 15;
const FD_OPTIONAL_SUBHEADER: usize = 16;
const FD_PLATFORM_ID: usize = 17;
const FD_PLATFORM_INFO: usize = 18;

/// Field descriptors shared by the Type II and Type III headers.
///
/// draft-foschiano-erspan-03, Sections 4.2 and 4.3 —
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.2>
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("vlan", "VLAN", FieldType::U16),
    FieldDescriptor::new("cos", "Class of Service", FieldType::U8),
    // Type II only.
    FieldDescriptor::new("encap_type", "Encapsulation Type", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(en) => Some(encap_type_name(*en)),
            _ => None,
        }),
    // Type III only.
    FieldDescriptor::new("bso", "Bad/Short/Oversized", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(bso) => Some(bso_name(*bso)),
            _ => None,
        }),
    FieldDescriptor::new("truncated", "Truncated", FieldType::U8),
    FieldDescriptor::new("session_id", "Session ID", FieldType::U16),
    // Type II only.
    FieldDescriptor::new("reserved", "Reserved", FieldType::U16).optional(),
    FieldDescriptor::new("index", "Index", FieldType::U32).optional(),
    // Type III only.
    FieldDescriptor::new("timestamp", "Timestamp", FieldType::U32).optional(),
    FieldDescriptor::new("sgt", "Security Group Tag", FieldType::U16).optional(),
    FieldDescriptor::new("pdu_frame", "PDU Frame", FieldType::U8).optional(),
    FieldDescriptor::new("frame_type", "Frame Type", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(ft) => Some(frame_type_name(*ft)),
            _ => None,
        }),
    FieldDescriptor::new("hw_id", "Hardware ID", FieldType::U8).optional(),
    FieldDescriptor::new("direction", "Direction", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(d) => Some(direction_name(*d)),
            _ => None,
        }),
    FieldDescriptor::new("granularity", "Timestamp Granularity", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(gra) => Some(granularity_name(*gra)),
            _ => None,
        }),
    FieldDescriptor::new("optional_subheader", "Optional Sub-header", FieldType::U8).optional(),
    FieldDescriptor::new("platform_id", "Platform ID", FieldType::U8).optional(),
    FieldDescriptor::new("platform_info", "Platform Specific Info", FieldType::U64).optional(),
];

/// Specification references for the ERSPAN dissectors.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "draft-foschiano-erspan-03",
        "Cisco Systems' Encapsulated Remote Switch Port Analyzer (ERSPAN)",
        "https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03",
    ),
    SpecReference::new(
        "RFC 2784",
        "Generic Routing Encapsulation (GRE)",
        "https://www.rfc-editor.org/rfc/rfc2784",
    ),
    SpecReference::new(
        "RFC 2890",
        "Key and Sequence Number Extensions to GRE",
        "https://www.rfc-editor.org/rfc/rfc2890",
    ),
];

/// Push the field at descriptor index `fd` with a `U8` value.
fn push_u8(buf: &mut DissectBuffer<'_>, fd: usize, value: u8, range: core::ops::Range<usize>) {
    buf.push_field(&FIELD_DESCRIPTORS[fd], FieldValue::U8(value), range);
}

/// Push the field at descriptor index `fd` with a `U16` value.
fn push_u16(buf: &mut DissectBuffer<'_>, fd: usize, value: u16, range: core::ops::Range<usize>) {
    buf.push_field(&FIELD_DESCRIPTORS[fd], FieldValue::U16(value), range);
}

/// Push the field at descriptor index `fd` with a `U32` value.
fn push_u32(buf: &mut DissectBuffer<'_>, fd: usize, value: u32, range: core::ops::Range<usize>) {
    buf.push_field(&FIELD_DESCRIPTORS[fd], FieldValue::U32(value), range);
}

/// Push the Ver, VLAN and COS fields, and the T and Session ID fields,
/// which Type II and Type III share in their first word. Bits 19-20 (En for
/// Type II, BSO for Type III) are pushed by the caller.
///
/// draft-foschiano-erspan-03, Sections 4.2 and 4.3 —
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.2>
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3>
fn push_common_word(buf: &mut DissectBuffer<'_>, word: u32, offset: usize, bits_19_20_fd: usize) {
    push_u8(buf, FD_VERSION, (word >> 28) as u8, offset..offset + 1);
    push_u16(
        buf,
        FD_VLAN,
        ((word >> 16) & 0x0FFF) as u16,
        offset..offset + 2,
    );
    push_u8(
        buf,
        FD_COS,
        ((word >> 13) & 0x07) as u8,
        offset + 2..offset + 3,
    );
    push_u8(
        buf,
        bits_19_20_fd,
        ((word >> 11) & 0x03) as u8,
        offset + 2..offset + 3,
    );
    push_u8(
        buf,
        FD_TRUNCATED,
        ((word >> 10) & 0x01) as u8,
        offset + 2..offset + 3,
    );
    push_u16(
        buf,
        FD_SESSION_ID,
        (word & 0x03FF) as u16,
        offset + 2..offset + 4,
    );
}

/// Return an error unless `data` holds at least `expected` bytes.
fn ensure_len(data: &[u8], expected: usize) -> Result<(), PacketError> {
    if data.len() < expected {
        return Err(PacketError::Truncated {
            expected,
            actual: data.len(),
        });
    }
    Ok(())
}

/// ERSPAN Type I / Type II dissector (GRE Protocol Type 0x88BE).
///
/// draft-foschiano-erspan-03, Section 4 — "Type I and II's value is 0x88BE".
/// Type I has no ERSPAN header and its GRE header has S=0 (Section 4.1);
/// Type II sets S=1 and adds an 8-octet header (Section 4.2). The variant is
/// chosen from the `sequence_number_present` field of the enclosing GRE
/// layer. Without a GRE layer, a Ver nibble of 1 selects Type II.
///
/// A Type I packet consumes no bytes and emits no layer: the mirrored
/// Ethernet frame follows GRE directly.
///
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4>
pub struct ErspanDissector;

/// ERSPAN Type III dissector (GRE Protocol Type 0x22EB).
///
/// draft-foschiano-erspan-03, Section 4 — "Type III's is 0x22EB".
///
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3>
pub struct ErspanType3Dissector;

/// Whether the packet in `data` is ERSPAN Type II rather than Type I.
///
/// draft-foschiano-erspan-03, Section 4.1 (Type I GRE header has S=0) and
/// Section 4.2 ("the S bit is set to 1") —
/// <https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.1>
fn is_type2(data: &[u8], buf: &DissectBuffer<'_>) -> bool {
    if let Some(layer) = buf.layers().last() {
        if layer.name == "GRE" {
            if let Some(s) = buf.field_u8(layer, "sequence_number_present") {
                return s == 1;
            }
        }
    }
    data.first().is_some_and(|b| b >> 4 == VERSION_TYPE2)
}

impl Dissector for ErspanDissector {
    fn name(&self) -> &'static str {
        "Encapsulated Remote Switch Port Analyzer"
    }

    fn short_name(&self) -> &'static str {
        "ERSPAN"
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
        // draft-foschiano-erspan-03, Section 4.1 — Type I: "barebones IP+GRE
        // encapsulation ... on top of the raw mirrored frame".
        // https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.1
        if !is_type2(data, buf) {
            return Ok(DissectResult::new(
                0,
                DispatchHint::ByEtherType(ETHERTYPE_TEB),
            ));
        }

        // draft-foschiano-erspan-03, Section 4.2 — Type II header.
        // https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.2
        ensure_len(data, TYPE2_HEADER_SIZE)?;
        let word0 = read_be_u32(data, 0)?;
        let word1 = read_be_u32(data, 4)?;
        let version = (word0 >> 28) as u8;
        if version != VERSION_TYPE2 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }

        buf.begin_layer(
            "ERSPAN",
            None,
            FIELD_DESCRIPTORS,
            offset..offset + TYPE2_HEADER_SIZE,
        );
        push_common_word(buf, word0, offset, FD_ENCAP_TYPE);
        // Reserved (12 bits) and Index (20 bits).
        push_u16(
            buf,
            FD_RESERVED,
            (word1 >> 20) as u16,
            offset + 4..offset + 6,
        );
        push_u32(buf, FD_INDEX, word1 & 0x000F_FFFF, offset + 5..offset + 8);
        buf.end_layer();

        // draft-foschiano-erspan-03, Section 4.2 — "The above 8-octet header
        // is immediately followed by the original mirrored frame".
        // https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.2
        Ok(DissectResult::new(
            TYPE2_HEADER_SIZE,
            DispatchHint::ByEtherType(ETHERTYPE_TEB),
        ))
    }
}

impl Dissector for ErspanType3Dissector {
    fn name(&self) -> &'static str {
        "Encapsulated Remote Switch Port Analyzer"
    }

    fn short_name(&self) -> &'static str {
        "ERSPAN"
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
        // draft-foschiano-erspan-03, Section 4.3 — Type III header.
        // https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.3
        ensure_len(data, TYPE3_HEADER_SIZE)?;
        let word0 = read_be_u32(data, 0)?;
        let timestamp = read_be_u32(data, 4)?;
        let word2 = read_be_u32(data, 8)?;
        let version = (word0 >> 28) as u8;
        if version != VERSION_TYPE3 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }

        let frame_type = ((word2 >> 10) & 0x1F) as u8;
        // O — "The ERSPAN payload starts after the O flag when O == 0b or
        // after 8 octets when O == 1b."
        let subheader = word2 & 0x01 != 0;
        let header_len = if subheader {
            TYPE3_HEADER_SIZE + TYPE3_SUBHEADER_SIZE
        } else {
            TYPE3_HEADER_SIZE
        };
        ensure_len(data, header_len)?;

        buf.begin_layer(
            "ERSPAN",
            None,
            FIELD_DESCRIPTORS,
            offset..offset + header_len,
        );
        push_common_word(buf, word0, offset, FD_BSO);
        push_u32(buf, FD_TIMESTAMP, timestamp, offset + 4..offset + 8);
        push_u16(buf, FD_SGT, (word2 >> 16) as u16, offset + 8..offset + 10);
        push_u8(
            buf,
            FD_PDU_FRAME,
            ((word2 >> 15) & 0x01) as u8,
            offset + 10..offset + 11,
        );
        push_u8(buf, FD_FRAME_TYPE, frame_type, offset + 10..offset + 11);
        push_u8(
            buf,
            FD_HW_ID,
            ((word2 >> 4) & 0x3F) as u8,
            offset + 10..offset + 12,
        );
        push_u8(
            buf,
            FD_DIRECTION,
            ((word2 >> 3) & 0x01) as u8,
            offset + 11..offset + 12,
        );
        push_u8(
            buf,
            FD_GRANULARITY,
            ((word2 >> 1) & 0x03) as u8,
            offset + 11..offset + 12,
        );
        push_u8(
            buf,
            FD_OPTIONAL_SUBHEADER,
            subheader as u8,
            offset + 11..offset + 12,
        );
        if subheader {
            // Platf ID (6 bits) and Platform Specific Info (58 bits).
            let sub = read_be_u64(data, TYPE3_HEADER_SIZE)?;
            push_u8(
                buf,
                FD_PLATFORM_ID,
                (sub >> 58) as u8,
                offset + TYPE3_HEADER_SIZE..offset + TYPE3_HEADER_SIZE + 1,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_PLATFORM_INFO],
                FieldValue::U64(sub & PLATFORM_INFO_MASK),
                offset + TYPE3_HEADER_SIZE..offset + header_len,
            );
        }
        buf.end_layer();

        // FT — "00000 --> Ethernet frame (802.3 frame)", "00010 --> IP
        // Packet", "Other values --> Reserved for future use". An IP packet
        // is dispatched by its version nibble.
        let next = match frame_type {
            FRAME_TYPE_ETHERNET => DispatchHint::ByEtherType(ETHERTYPE_TEB),
            FRAME_TYPE_IP => match data.get(header_len).map(|b| b >> 4) {
                Some(4) => DispatchHint::ByEtherType(ETHERTYPE_IPV4),
                Some(6) => DispatchHint::ByEtherType(ETHERTYPE_IPV6),
                _ => DispatchHint::End,
            },
            _ => DispatchHint::End,
        };
        Ok(DissectResult::new(header_len, next))
    }
}

#[cfg(test)]
mod tests {
    //! # draft-foschiano-erspan-03 Coverage
    //!
    //! | Section | Description                                   | Test                                   |
    //! |---------|-----------------------------------------------|----------------------------------------|
    //! | 4       | Type I/II vs III by GRE Protocol Type         | registry integration tests             |
    //! | 4.1     | Type I: no ERSPAN header (GRE S=0)            | type1_without_gre_sequence             |
    //! | 4.1     | Type I without a GRE layer (Ver nibble != 1)  | type1_without_gre_layer                |
    //! | 4.1     | GRE S=0 wins over a Ver nibble of 1           | type1_gre_s_bit_overrides_version      |
    //! | 4.2     | Type II header fields                         | type2_header_fields                    |
    //! | 4.2     | GRE S=1 wins over a Ver nibble other than 1   | type2_gre_s_bit_overrides_version      |
    //! | 4.2     | Type II without a GRE layer (Ver nibble = 1)  | type2_without_gre_layer                |
    //! | 4.2     | Type II En / encapsulation names              | type2_encap_type_names                 |
    //! | 4.2     | Type II Ver must be 1                         | type2_version_mismatch                 |
    //! | 4.2     | Type II truncated header                      | type2_truncated                        |
    //! | 4.3     | Type III header fields, O=0                   | type3_header_fields                    |
    //! | 4.3     | Type III platform-specific sub-header (O=1)   | type3_platform_subheader               |
    //! | 4.3     | Type III sub-header truncated                 | type3_platform_subheader_truncated     |
    //! | 4.3     | Type III FT=2 (IP packet) → IPv4 / IPv6       | type3_ft_ip_dispatch                   |
    //! | 4.3     | Type III FT reserved → End                    | type3_ft_reserved_ends                 |
    //! | 4.3     | Type III BSO / Gra / D names                  | type3_display_names                    |
    //! | 4.3     | Type III Ver must be 2                        | type3_version_mismatch                 |
    //! | 4.3     | Type III truncated header                     | type3_truncated                        |
    //! | —       | Dissector metadata                            | dissector_metadata                     |

    use super::*;

    /// Push a GRE layer carrying only the `sequence_number_present` flag, as
    /// the GRE dissector would (RFC 2890, Section 2 —
    /// <https://www.rfc-editor.org/rfc/rfc2890#section-2>).
    fn push_gre_layer(buf: &mut DissectBuffer<'_>, s: u8) {
        static GRE_FD: FieldDescriptor = FieldDescriptor::new(
            "sequence_number_present",
            "Sequence Number Present",
            FieldType::U8,
        );
        buf.begin_layer("GRE", None, &[], 0..8);
        buf.push_field(&GRE_FD, FieldValue::U8(s), 0..1);
        buf.end_layer();
    }

    /// Type II header: Ver=1, VLAN=100, COS=5, En=2 (802.1Q), T=1,
    /// Session ID=0x155, Reserved=0, Index=0xABCDE.
    const TYPE2_HEADER: [u8; 8] = [0x10, 0x64, 0xB5, 0x55, 0x00, 0x0A, 0xBC, 0xDE];

    #[test]
    fn type1_without_gre_sequence() {
        let data = [0xFFu8; 14];
        let mut buf = DissectBuffer::new();
        push_gre_layer(&mut buf, 0);
        let r = ErspanDissector.dissect(&data, &mut buf, 8).unwrap();
        assert_eq!(r.bytes_consumed, 0);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x6558));
        assert_eq!(buf.layers().len(), 1, "Type I emits no ERSPAN layer");
    }

    #[test]
    fn type1_gre_s_bit_overrides_version() {
        // A mirrored frame whose destination MAC starts with nibble 1.
        let data = [
            0x10u8, 0x64, 0xB5, 0x55, 0x00, 0x0A, 0xBC, 0xDE, 0, 0, 0, 0, 8, 0,
        ];
        let mut buf = DissectBuffer::new();
        push_gre_layer(&mut buf, 0);
        let r = ErspanDissector.dissect(&data, &mut buf, 8).unwrap();
        assert_eq!(r.bytes_consumed, 0);
        assert!(buf.layer_by_name("ERSPAN").is_none());
    }

    #[test]
    fn type2_gre_s_bit_overrides_version() {
        // GRE S=1 selects Type II, so a Ver nibble of 2 is a version error.
        let mut data = TYPE2_HEADER;
        data[0] = 0x20 | (data[0] & 0x0F);
        let mut buf = DissectBuffer::new();
        push_gre_layer(&mut buf, 1);
        assert!(matches!(
            ErspanDissector.dissect(&data, &mut buf, 8),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                ..
            })
        ));
    }

    #[test]
    fn type1_without_gre_layer() {
        // Destination MAC starting with 0x00: Ver nibble is not 1.
        let data = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0, 0, 0, 0, 0, 8, 0];
        let mut buf = DissectBuffer::new();
        let r = ErspanDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 0);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x6558));
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn type2_header_fields() {
        let mut data = TYPE2_HEADER.to_vec();
        data.extend_from_slice(&[0xAA; 14]);
        let mut buf = DissectBuffer::new();
        push_gre_layer(&mut buf, 1);
        let r = ErspanDissector.dissect(&data, &mut buf, 8).unwrap();
        assert_eq!(r.bytes_consumed, 8);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x6558));

        let layer = buf.layer_by_name("ERSPAN").unwrap();
        assert_eq!(layer.range, 8..16);
        assert_eq!(buf.field_u8(layer, "version"), Some(1));
        assert_eq!(buf.field_u16(layer, "vlan"), Some(100));
        assert_eq!(buf.field_u8(layer, "cos"), Some(5));
        assert_eq!(buf.field_u8(layer, "encap_type"), Some(2));
        assert_eq!(buf.field_u8(layer, "truncated"), Some(1));
        assert_eq!(buf.field_u16(layer, "session_id"), Some(0x155));
        assert_eq!(buf.field_u16(layer, "reserved"), Some(0));
        assert_eq!(buf.field_u32(layer, "index"), Some(0xABCDE));
        assert!(buf.field_by_name(layer, "timestamp").is_none());
        assert!(buf.field_by_name(layer, "bso").is_none());

        // Field byte ranges.
        let session = buf.field_by_name(layer, "session_id").unwrap();
        assert_eq!(session.range, 10..12);
        let index = buf.field_by_name(layer, "index").unwrap();
        assert_eq!(index.range, 13..16);
    }

    #[test]
    fn type2_without_gre_layer() {
        let mut buf = DissectBuffer::new();
        let r = ErspanDissector.dissect(&TYPE2_HEADER, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 8);
        assert!(buf.layer_by_name("ERSPAN").is_some());
    }

    #[test]
    fn type2_encap_type_names() {
        for (en, name) in [
            (0u8, "Originally without VLAN tag"),
            (1, "Originally ISL encapsulated"),
            (2, "Originally 802.1Q encapsulated"),
            (3, "VLAN tag preserved in frame"),
        ] {
            let mut data = TYPE2_HEADER;
            data[2] = (data[2] & !0x18) | (en << 3);
            let mut buf = DissectBuffer::new();
            push_gre_layer(&mut buf, 1);
            ErspanDissector.dissect(&data, &mut buf, 8).unwrap();
            let layer = buf.layer_by_name("ERSPAN").unwrap();
            assert_eq!(buf.field_u8(layer, "encap_type"), Some(en));
            assert_eq!(
                buf.resolve_display_name(layer, "encap_type_name"),
                Some(name)
            );
        }
    }

    #[test]
    fn type2_version_mismatch() {
        let mut data = TYPE2_HEADER;
        data[0] = 0x20 | (data[0] & 0x0F);
        let mut buf = DissectBuffer::new();
        push_gre_layer(&mut buf, 1);
        assert_eq!(
            ErspanDissector.dissect(&data, &mut buf, 8),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 2
            })
        );
    }

    #[test]
    fn type2_truncated() {
        let mut buf = DissectBuffer::new();
        push_gre_layer(&mut buf, 1);
        assert_eq!(
            ErspanDissector.dissect(&TYPE2_HEADER[..7], &mut buf, 8),
            Err(PacketError::Truncated {
                expected: 8,
                actual: 7
            })
        );
        let mut buf = DissectBuffer::new();
        push_gre_layer(&mut buf, 1);
        assert_eq!(
            ErspanDissector.dissect(&[], &mut buf, 8),
            Err(PacketError::Truncated {
                expected: 8,
                actual: 0
            })
        );
    }

    /// Type III header: Ver=2, VLAN=0x123, COS=3, BSO=1, T=0,
    /// Session ID=0x2AA, Timestamp=0x01020304, SGT=0xBEEF, P=1, FT=0,
    /// Hw ID=0x2A, D=1, Gra=2, O as given.
    fn type3_header(ft: u8, o: bool) -> [u8; 12] {
        let w2: u32 = (0xBEEF << 16)
            | (1 << 15)
            | (u32::from(ft) << 10)
            | (0x2A << 4)
            | (1 << 3)
            | (2 << 1)
            | u32::from(o);
        let w2 = w2.to_be_bytes();
        [
            0x21, 0x23, 0x6A, 0xAA, 0x01, 0x02, 0x03, 0x04, w2[0], w2[1], w2[2], w2[3],
        ]
    }

    #[test]
    fn type3_header_fields() {
        let mut data = type3_header(0, false).to_vec();
        data.extend_from_slice(&[0xAA; 14]);
        let mut buf = DissectBuffer::new();
        let r = ErspanType3Dissector.dissect(&data, &mut buf, 42).unwrap();
        assert_eq!(r.bytes_consumed, 12);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x6558));

        let layer = buf.layer_by_name("ERSPAN").unwrap();
        assert_eq!(layer.range, 42..54);
        assert_eq!(buf.field_u8(layer, "version"), Some(2));
        assert_eq!(buf.field_u16(layer, "vlan"), Some(0x123));
        assert_eq!(buf.field_u8(layer, "cos"), Some(3));
        assert_eq!(buf.field_u8(layer, "bso"), Some(1));
        assert_eq!(buf.field_u8(layer, "truncated"), Some(0));
        assert_eq!(buf.field_u16(layer, "session_id"), Some(0x2AA));
        assert_eq!(buf.field_u32(layer, "timestamp"), Some(0x0102_0304));
        assert_eq!(buf.field_u16(layer, "sgt"), Some(0xBEEF));
        assert_eq!(buf.field_u8(layer, "pdu_frame"), Some(1));
        assert_eq!(buf.field_u8(layer, "frame_type"), Some(0));
        assert_eq!(buf.field_u8(layer, "hw_id"), Some(0x2A));
        assert_eq!(buf.field_u8(layer, "direction"), Some(1));
        assert_eq!(buf.field_u8(layer, "granularity"), Some(2));
        assert_eq!(buf.field_u8(layer, "optional_subheader"), Some(0));
        assert!(buf.field_by_name(layer, "platform_id").is_none());
        assert!(buf.field_by_name(layer, "encap_type").is_none());
        assert!(buf.field_by_name(layer, "index").is_none());
        assert_eq!(
            buf.resolve_display_name(layer, "frame_type_name"),
            Some("Ethernet frame")
        );
        let ts = buf.field_by_name(layer, "timestamp").unwrap();
        assert_eq!(ts.range, 46..50);
    }

    #[test]
    fn type3_platform_subheader() {
        let mut data = type3_header(0, true).to_vec();
        // Platf ID = 0x3, Reserved, Port ID = 0x0102; upper timestamp.
        data.extend_from_slice(&[0x0C, 0x00, 0x01, 0x02, 0xDE, 0xAD, 0xBE, 0xEF]);
        data.extend_from_slice(&[0xAA; 14]);
        let mut buf = DissectBuffer::new();
        let r = ErspanType3Dissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 20);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x6558));
        let layer = buf.layer_by_name("ERSPAN").unwrap();
        assert_eq!(layer.range, 0..20);
        assert_eq!(buf.field_u8(layer, "optional_subheader"), Some(1));
        assert_eq!(buf.field_u8(layer, "platform_id"), Some(3));
        assert_eq!(
            buf.field_u64(layer, "platform_info"),
            Some(0x0000_0102_DEAD_BEEF)
        );
        let info = buf.field_by_name(layer, "platform_info").unwrap();
        assert_eq!(info.range, 12..20);
    }

    #[test]
    fn type3_platform_subheader_truncated() {
        let mut data = type3_header(0, true).to_vec();
        data.extend_from_slice(&[0x0C, 0x00, 0x01]);
        let mut buf = DissectBuffer::new();
        assert_eq!(
            ErspanType3Dissector.dissect(&data, &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 20,
                actual: 15
            })
        );
    }

    #[test]
    fn type3_ft_ip_dispatch() {
        for (first, next) in [
            (0x45u8, DispatchHint::ByEtherType(0x0800)),
            (0x60, DispatchHint::ByEtherType(0x86DD)),
            (0x00, DispatchHint::End),
        ] {
            let mut data = type3_header(2, false).to_vec();
            data.push(first);
            data.extend_from_slice(&[0; 19]);
            let mut buf = DissectBuffer::new();
            let r = ErspanType3Dissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(r.bytes_consumed, 12);
            assert_eq!(r.next, next);
            let layer = buf.layer_by_name("ERSPAN").unwrap();
            assert_eq!(
                buf.resolve_display_name(layer, "frame_type_name"),
                Some("IP packet")
            );
        }
        // FT=2 with no payload at all.
        let data = type3_header(2, false);
        let mut buf = DissectBuffer::new();
        let r = ErspanType3Dissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.next, DispatchHint::End);
    }

    #[test]
    fn type3_ft_reserved_ends() {
        let mut data = type3_header(1, false).to_vec();
        data.extend_from_slice(&[0x45; 20]);
        let mut buf = DissectBuffer::new();
        let r = ErspanType3Dissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 12);
        assert_eq!(r.next, DispatchHint::End);
        let layer = buf.layer_by_name("ERSPAN").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "frame_type_name"),
            Some("Reserved")
        );
    }

    #[test]
    fn type3_display_names() {
        let data = type3_header(0, false);
        let mut buf = DissectBuffer::new();
        ErspanType3Dissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ERSPAN").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "bso_name"),
            Some("Short frame")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "direction_name"),
            Some("Egress")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "granularity_name"),
            Some("IEEE 1588")
        );
        assert_eq!(bso_name(0), "Good frame or unknown integrity");
        assert_eq!(bso_name(2), "Oversized frame");
        assert_eq!(bso_name(3), "Bad frame (CRC or alignment error)");
        assert_eq!(granularity_name(0), "100 microseconds");
        assert_eq!(granularity_name(1), "100 nanoseconds");
        assert_eq!(granularity_name(3), "User configurable");
        assert_eq!(direction_name(0), "Ingress");
    }

    #[test]
    fn type3_version_mismatch() {
        let mut data = type3_header(0, false);
        data[0] = 0x10 | (data[0] & 0x0F);
        let mut buf = DissectBuffer::new();
        assert_eq!(
            ErspanType3Dissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 1
            })
        );
    }

    #[test]
    fn type3_truncated() {
        let data = type3_header(0, false);
        let mut buf = DissectBuffer::new();
        assert_eq!(
            ErspanType3Dissector.dissect(&data[..11], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 12,
                actual: 11
            })
        );
    }

    #[test]
    fn dissector_metadata() {
        for d in [
            &ErspanDissector as &dyn Dissector,
            &ErspanType3Dissector as &dyn Dissector,
        ] {
            assert_eq!(d.short_name(), "ERSPAN");
            assert_eq!(d.name(), "Encapsulated Remote Switch Port Analyzer");
            assert_eq!(d.layer(), Some(ProtocolLayer::Tunnel));
            assert!(!d.references().is_empty());
            assert!(d.field_descriptors().iter().any(|f| f.name == "session_id"));
        }
    }
}
