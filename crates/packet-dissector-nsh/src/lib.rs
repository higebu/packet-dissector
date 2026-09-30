//! NSH (Network Service Header) dissector.
//!
//! Decodes the NSH Base Header, the Service Path Header and the Context
//! Headers of MD Type 1 (fixed length) and MD Type 2 (variable-length
//! Context Headers), and dispatches the payload by Next Protocol.
//!
//! ## References
//! - RFC 8300: <https://www.rfc-editor.org/rfc/rfc8300>
//! - RFC 9451 (O bit; updates RFC 8300):
//!   <https://www.rfc-editor.org/rfc/rfc9451>
//! - IANA "Network Service Header (NSH) Parameters":
//!   <https://www.iana.org/assignments/nsh/nsh.xhtml>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u32;

/// Minimum value of the Length field, in 4-byte words: the Base Header and
/// the Service Path Header.
///
/// RFC 8300, Section 2.2 — "it MUST be 0x2 or greater for MD Type 0x2"
/// <https://www.rfc-editor.org/rfc/rfc8300#section-2.2>
const MIN_LENGTH_WORDS: u8 = 2;

/// Size of the Base Header plus the Service Path Header, in bytes.
///
/// RFC 8300, Sections 2.2 and 2.3 —
/// <https://www.rfc-editor.org/rfc/rfc8300#section-2.2>
const MIN_HEADER_SIZE: usize = MIN_LENGTH_WORDS as usize * 4;

/// Length of an MD Type 1 NSH, in 4-byte words.
///
/// RFC 8300, Section 2.2 — "The length MUST be 0x6 for MD Type 0x1"
/// <https://www.rfc-editor.org/rfc/rfc8300#section-2.2>
const MD_TYPE_1_LENGTH_WORDS: u8 = 6;

/// Size of a Variable-Length Context Header without its metadata.
///
/// RFC 8300, Section 2.5.1 — <https://www.rfc-editor.org/rfc/rfc8300#section-2.5.1>
const CONTEXT_HEADER_SIZE: usize = 4;

/// NSH Version defined by RFC 8300, Section 2.2 — "It MUST be set to 0x0 by
/// the sender".
///
/// <https://www.rfc-editor.org/rfc/rfc8300#section-2.2>
const VERSION_0: u8 = 0;

/// MD Type 0x1 — Fixed-Length Context Header (RFC 8300, Section 2.4).
///
/// <https://www.rfc-editor.org/rfc/rfc8300#section-2.4>
const MD_TYPE_1: u8 = 0x1;

/// MD Type 0x2 — Variable-Length Context Headers (RFC 8300, Section 2.5).
///
/// <https://www.rfc-editor.org/rfc/rfc8300#section-2.5>
const MD_TYPE_2: u8 = 0x2;

/// Next Protocol values (RFC 8300, Section 2.2).
///
/// <https://www.rfc-editor.org/rfc/rfc8300#section-2.2>
const NEXT_PROTOCOL_IPV4: u8 = 0x1;
const NEXT_PROTOCOL_IPV6: u8 = 0x2;
const NEXT_PROTOCOL_ETHERNET: u8 = 0x3;
const NEXT_PROTOCOL_NSH: u8 = 0x4;
const NEXT_PROTOCOL_MPLS: u8 = 0x5;

/// EtherTypes the payload is dispatched under.
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// Transparent Ethernet Bridging, under which the Ethernet dissector is
/// registered for tunnelled frames.
const ETHERTYPE_TEB: u16 = 0x6558;
/// NSH (RFC 8300, Section 10.1).
///
/// <https://www.rfc-editor.org/rfc/rfc8300#section-10.1>
const ETHERTYPE_NSH: u16 = 0x894F;
/// MPLS unicast (RFC 3032 — <https://www.rfc-editor.org/rfc/rfc3032>).
const ETHERTYPE_MPLS: u16 = 0x8847;

/// Name of an MD Type value (IANA "NSH MD Types" registry, RFC 8300,
/// Section 9.1.3).
///
/// <https://www.rfc-editor.org/rfc/rfc8300#section-9.1.3>
fn md_type_name(md_type: u8) -> Option<&'static str> {
    match md_type {
        0x0 => Some("Reserved"),
        MD_TYPE_1 => Some("NSH MD Type 1"),
        MD_TYPE_2 => Some("NSH MD Type 2"),
        0xF => Some("Experimentation"),
        _ => None,
    }
}

/// Name of a Next Protocol value (IANA "NSH Next Protocol" registry).
///
/// - RFC 8300, Section 9.1.6 — <https://www.rfc-editor.org/rfc/rfc8300#section-9.1.6>
/// - RFC 8393 (0x0) — <https://www.rfc-editor.org/rfc/rfc8393>
/// - RFC 9452 (0x6) — <https://www.rfc-editor.org/rfc/rfc9452>
/// - RFC 9516 (0x7) — <https://www.rfc-editor.org/rfc/rfc9516>
fn next_protocol_name(np: u8) -> Option<&'static str> {
    match np {
        0x0 => Some("None"),
        NEXT_PROTOCOL_IPV4 => Some("IPv4"),
        NEXT_PROTOCOL_IPV6 => Some("IPv6"),
        NEXT_PROTOCOL_ETHERNET => Some("Ethernet"),
        NEXT_PROTOCOL_NSH => Some("NSH"),
        NEXT_PROTOCOL_MPLS => Some("MPLS"),
        0x6 => Some("IOAM"),
        0x7 => Some("SFC Active OAM"),
        0xFE => Some("Experiment 1"),
        0xFF => Some("Experiment 2"),
        _ => None,
    }
}

/// Name of a Metadata Class value (IANA "NSH MD Class" registry, RFC 8300,
/// Section 9.1.4).
///
/// <https://www.rfc-editor.org/rfc/rfc8300#section-9.1.4>
fn md_class_name(class: u16) -> Option<&'static str> {
    match class {
        0x0000 => Some("IETF Base NSH MD Class"),
        0x0200 => Some("BBF Specific NSH Metadata"),
        0xFFF6..=0xFFFE => Some("Experimental"),
        0xFFFF => Some("Reserved"),
        _ => None,
    }
}

/// Child field descriptor indices for one Variable-Length Context Header.
const CFD_MD_CLASS: usize = 0;
const CFD_TYPE: usize = 1;
const CFD_UNASSIGNED: usize = 2;
const CFD_LENGTH: usize = 3;
const CFD_VALUE: usize = 4;

/// Fields of one Variable-Length Context Header (RFC 8300, Section 2.5.1).
///
/// <https://www.rfc-editor.org/rfc/rfc8300#section-2.5.1>
static CONTEXT_HEADER_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("md_class", "Metadata Class", FieldType::U16).with_display_fn(|v, _| {
        match v {
            FieldValue::U16(c) => md_class_name(*c),
            _ => None,
        }
    }),
    FieldDescriptor::new("type", "Type", FieldType::U8),
    FieldDescriptor::new("unassigned", "Unassigned", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("value", "Variable-Length Metadata", FieldType::Bytes),
];

/// Descriptor of one Context Header object inside `context_headers`.
static FD_CONTEXT_HEADER: FieldDescriptor =
    FieldDescriptor::new("context_header", "Context Header", FieldType::Object)
        .with_children(CONTEXT_HEADER_FIELD_DESCRIPTORS);

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_VERSION: usize = 0;
const FD_OAM: usize = 1;
const FD_UNASSIGNED1: usize = 2;
const FD_TTL: usize = 3;
const FD_LENGTH: usize = 4;
const FD_UNASSIGNED2: usize = 5;
const FD_MD_TYPE: usize = 6;
const FD_NEXT_PROTOCOL: usize = 7;
const FD_SPI: usize = 8;
const FD_SI: usize = 9;
const FD_CONTEXT: usize = 10;
const FD_CONTEXT_HEADERS: usize = 11;
const FD_CONTEXT_HEADERS_MALFORMED: usize = 12;
const FD_LENGTH_INVALID: usize = 13;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 8300, Section 2.2 — Base Header.
    // https://www.rfc-editor.org/rfc/rfc8300#section-2.2
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("oam", "OAM", FieldType::U8),
    FieldDescriptor::new("unassigned1", "Unassigned", FieldType::U8),
    FieldDescriptor::new("ttl", "TTL", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("unassigned2", "Unassigned", FieldType::U8),
    FieldDescriptor::new("md_type", "MD Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => md_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("next_protocol", "Next Protocol", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(n) => next_protocol_name(*n),
            _ => None,
        },
    ),
    // RFC 8300, Section 2.3 — Service Path Header.
    // https://www.rfc-editor.org/rfc/rfc8300#section-2.3
    FieldDescriptor::new("spi", "Service Path Identifier", FieldType::U32),
    FieldDescriptor::new("si", "Service Index", FieldType::U8),
    // RFC 8300, Section 2.4 — Fixed-Length Context Header (MD Type 1), or
    // the raw context of an MD Type this dissector does not know.
    // https://www.rfc-editor.org/rfc/rfc8300#section-2.4
    FieldDescriptor::new("context", "Context Header", FieldType::Bytes).optional(),
    // RFC 8300, Section 2.5.1 — Variable-Length Context Headers (MD Type 2).
    // https://www.rfc-editor.org/rfc/rfc8300#section-2.5.1
    FieldDescriptor::new("context_headers", "Context Headers", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_CONTEXT_HEADER)),
    FieldDescriptor::new(
        "context_headers_malformed",
        "Context Headers Length Mismatch",
        FieldType::U8,
    )
    .optional(),
    // RFC 8300, Section 2.2 — set when an MD Type 1 NSH has a Length other
    // than 0x6.
    // https://www.rfc-editor.org/rfc/rfc8300#section-2.2
    FieldDescriptor::new(
        "length_invalid",
        "Length Invalid for MD Type",
        FieldType::U8,
    )
    .optional(),
];

/// Specification references for the NSH dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 8300",
        "Network Service Header (NSH)",
        "https://www.rfc-editor.org/rfc/rfc8300",
    ),
    SpecReference::new(
        "RFC 9451",
        "Operations, Administration, and Maintenance (OAM) Packet and Behavior in the Network Service Header (NSH)",
        "https://www.rfc-editor.org/rfc/rfc9451",
    ),
];

/// Push the field at descriptor index `fd` with a `U8` value.
fn push_u8(buf: &mut DissectBuffer<'_>, fd: usize, value: u8, range: core::ops::Range<usize>) {
    buf.push_field(&FIELD_DESCRIPTORS[fd], FieldValue::U8(value), range);
}

/// NSH dissector.
pub struct NshDissector;

impl Dissector for NshDissector {
    fn name(&self) -> &'static str {
        "Network Service Header"
    }

    fn short_name(&self) -> &'static str {
        "NSH"
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

        // RFC 8300, Section 2.2 — Base Header:
        // |Ver|O|U|    TTL    |   Length  |U|U|U|U|MD Type| Next Protocol |
        // https://www.rfc-editor.org/rfc/rfc8300#section-2.2
        let word0 = read_be_u32(data, 0)?;
        let version = (word0 >> 30) as u8;
        let oam = ((word0 >> 29) & 0x01) as u8;
        let unassigned1 = ((word0 >> 28) & 0x01) as u8;
        let ttl = ((word0 >> 22) & 0x3F) as u8;
        let length = ((word0 >> 16) & 0x3F) as u8;
        let unassigned2 = ((word0 >> 12) & 0x0F) as u8;
        let md_type = ((word0 >> 8) & 0x0F) as u8;
        let next_protocol = (word0 & 0xFF) as u8;

        // RFC 8300, Section 2.2 — "Length: The total length, in 4-byte
        // words, of the NSH including the Base Header, the Service Path
        // Header, ..." The Base Header and Service Path Header alone take
        // two words.
        // https://www.rfc-editor.org/rfc/rfc8300#section-2.2
        if length < MIN_LENGTH_WORDS {
            return Err(PacketError::InvalidFieldValue {
                field: "length",
                value: u32::from(length),
            });
        }
        let header_len = usize::from(length) * 4;
        if data.len() < header_len {
            return Err(PacketError::Truncated {
                expected: header_len,
                actual: data.len(),
            });
        }

        // RFC 8300, Section 2.3 — Service Path Header: SPI (24 bits), SI
        // (8 bits).
        // https://www.rfc-editor.org/rfc/rfc8300#section-2.3
        let word1 = read_be_u32(data, 4)?;

        buf.begin_layer("NSH", None, FIELD_DESCRIPTORS, offset..offset + header_len);
        push_u8(buf, FD_VERSION, version, offset..offset + 1);
        // RFC 9451, Section 3 — "O bit: Setting this bit indicates an NSH
        // OAM packet."
        // https://www.rfc-editor.org/rfc/rfc9451#section-3
        push_u8(buf, FD_OAM, oam, offset..offset + 1);
        push_u8(buf, FD_UNASSIGNED1, unassigned1, offset..offset + 1);
        push_u8(buf, FD_TTL, ttl, offset..offset + 2);
        push_u8(buf, FD_LENGTH, length, offset + 1..offset + 2);
        push_u8(buf, FD_UNASSIGNED2, unassigned2, offset + 2..offset + 3);
        push_u8(buf, FD_MD_TYPE, md_type, offset + 2..offset + 3);
        push_u8(buf, FD_NEXT_PROTOCOL, next_protocol, offset + 3..offset + 4);
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SPI],
            FieldValue::U32(word1 >> 8),
            offset + 4..offset + 7,
        );
        push_u8(buf, FD_SI, (word1 & 0xFF) as u8, offset + 7..offset + 8);

        // RFC 8300, Section 2.2 — "The length MUST be 0x6 for MD Type 0x1".
        // The context is still shown as far as Length reaches.
        // https://www.rfc-editor.org/rfc/rfc8300#section-2.2
        if version == VERSION_0 && md_type == MD_TYPE_1 && length != MD_TYPE_1_LENGTH_WORDS {
            push_u8(buf, FD_LENGTH_INVALID, 1, offset + 1..offset + 2);
        }

        if header_len > MIN_HEADER_SIZE {
            // Context Headers are only decoded for Version 0; the layout of
            // other versions is unknown, so their context is shown raw.
            if version == VERSION_0 && md_type == MD_TYPE_2 {
                push_context_headers(buf, data, offset, header_len);
            } else {
                // RFC 8300, Section 2.4 — MD Type 1 carries a 16-byte
                // Fixed-Length Context Header whose content the RFC does not
                // define. Any other MD Type or Version has no defined
                // format, so its context is shown raw as well.
                // https://www.rfc-editor.org/rfc/rfc8300#section-2.4
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_CONTEXT],
                    FieldValue::Bytes(&data[MIN_HEADER_SIZE..header_len]),
                    offset + MIN_HEADER_SIZE..offset + header_len,
                );
            }
        }
        buf.end_layer();

        // RFC 8300, Section 2.2 — "If ... the SFF does not understand the
        // version of the protocol as indicated in the base header, the
        // packet MUST be discarded". The payload layout of other versions is
        // unknown, so dissection stops.
        // https://www.rfc-editor.org/rfc/rfc8300#section-2.2
        if version != VERSION_0 {
            return Ok(DissectResult::new(header_len, DispatchHint::End));
        }

        // RFC 8300, Section 2.2 — "Next Protocol: Indicates the protocol
        // type of the encapsulated data." For OAM packets, RFC 9451,
        // Section 3 — "When SFC OAM data is included in the inner packet,
        // the Next Protocol field is set to reflect the structure of that
        // inner OAM packet." The discard rules for O=1 in the same section
        // apply to SFC data plane elements, not to a dissector, so the
        // payload is dispatched by Next Protocol regardless of the O bit.
        // https://www.rfc-editor.org/rfc/rfc8300#section-2.2
        // https://www.rfc-editor.org/rfc/rfc9451#section-3
        let next = match next_protocol {
            NEXT_PROTOCOL_IPV4 => DispatchHint::ByEtherType(ETHERTYPE_IPV4),
            NEXT_PROTOCOL_IPV6 => DispatchHint::ByEtherType(ETHERTYPE_IPV6),
            NEXT_PROTOCOL_ETHERNET => DispatchHint::ByEtherType(ETHERTYPE_TEB),
            NEXT_PROTOCOL_NSH => DispatchHint::ByEtherType(ETHERTYPE_NSH),
            NEXT_PROTOCOL_MPLS => DispatchHint::ByEtherType(ETHERTYPE_MPLS),
            _ => DispatchHint::End,
        };
        Ok(DissectResult::new(header_len, next))
    }
}

/// Push the `context_headers` array for the Variable-Length Context Headers
/// in `data[MIN_HEADER_SIZE..header_len]`.
///
/// RFC 8300, Section 2.5.1 — "The receiver MUST round the Length field up to
/// the nearest 4-byte-word boundary, to locate and process the next field in
/// the packet. The receiver MUST access only those bytes in the metadata
/// indicated by the Length field". A Context Header that runs past the NSH
/// Length stops decoding; `context_headers_malformed` then covers the rest,
/// and the payload after the NSH Length is still dispatched.
/// <https://www.rfc-editor.org/rfc/rfc8300#section-2.5.1>
fn push_context_headers<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    header_len: usize,
) {
    let list_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_CONTEXT_HEADERS],
        FieldValue::Array(0..0),
        offset + MIN_HEADER_SIZE..offset + header_len,
    );
    let mut pos = MIN_HEADER_SIZE;
    let mut malformed_at = None;
    // header_len is a multiple of 4, so a whole Context Header fits.
    while pos + CONTEXT_HEADER_SIZE <= header_len {
        // |          Metadata Class       |      Type     |U|    Length   |
        let class = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let md_type = data[pos + 2];
        let unassigned = data[pos + 3] >> 7;
        let length = data[pos + 3] & 0x7F;
        let value_start = pos + CONTEXT_HEADER_SIZE;
        let value_end = value_start + usize::from(length);
        let end = value_start + usize::from(length).div_ceil(4) * 4;
        if end > header_len {
            malformed_at = Some(pos);
            break;
        }

        let obj_idx = buf.begin_container(
            &FD_CONTEXT_HEADER,
            FieldValue::Object(0..0),
            offset + pos..offset + end,
        );
        buf.push_field(
            &CONTEXT_HEADER_FIELD_DESCRIPTORS[CFD_MD_CLASS],
            FieldValue::U16(class),
            offset + pos..offset + pos + 2,
        );
        buf.push_field(
            &CONTEXT_HEADER_FIELD_DESCRIPTORS[CFD_TYPE],
            FieldValue::U8(md_type),
            offset + pos + 2..offset + pos + 3,
        );
        buf.push_field(
            &CONTEXT_HEADER_FIELD_DESCRIPTORS[CFD_UNASSIGNED],
            FieldValue::U8(unassigned),
            offset + pos + 3..offset + pos + 4,
        );
        buf.push_field(
            &CONTEXT_HEADER_FIELD_DESCRIPTORS[CFD_LENGTH],
            FieldValue::U8(length),
            offset + pos + 3..offset + pos + 4,
        );
        buf.push_field(
            &CONTEXT_HEADER_FIELD_DESCRIPTORS[CFD_VALUE],
            FieldValue::Bytes(&data[value_start..value_end]),
            offset + value_start..offset + value_end,
        );
        buf.end_container(obj_idx);
        pos = end;
    }
    buf.end_container(list_idx);

    if let Some(bad) = malformed_at {
        push_u8(
            buf,
            FD_CONTEXT_HEADERS_MALFORMED,
            1,
            offset + bad..offset + header_len,
        );
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 8300 (NSH) Coverage
    //!
    //! | RFC Section    | Description                                   | Test                                  |
    //! |----------------|-----------------------------------------------|---------------------------------------|
    //! | 8300 §2.2      | Base Header fields                            | parse_md_type1                        |
    //! | 8300 §2.2      | Length below 2 words is invalid               | parse_length_too_small                |
    //! | 8300 §2.2      | Truncated base header / NSH length            | parse_truncated                       |
    //! | 8300 §2.2      | Unknown Version: header only, no dispatch     | parse_unknown_version                 |
    //! | 8300 §2.2      | MD Type / Next Protocol names                 | md_type_and_next_protocol_names       |
    //! | 8300 §2.2      | Next Protocol dispatch                        | next_protocol_dispatch                |
    //! | 9451 §3        | O bit set: payload still by Next Protocol     | parse_oam_bit                         |
    //! | 8300 §2.3      | Service Path Header (SPI, SI)                 | parse_md_type1                        |
    //! | 8300 §2.4      | MD Type 1 Fixed-Length Context Header         | parse_md_type1                        |
    //! | 8300 §2.5      | MD Type 2 with no Context Headers             | parse_md_type2_no_context             |
    //! | 8300 §2.5.1    | MD Type 2 Variable-Length Context Headers     | parse_md_type2_context_headers        |
    //! | 8300 §2.5.1    | Context Header overruns NSH length            | parse_md_type2_context_overrun        |
    //! | 8300 §9.1.4    | MD Class names                                | md_class_names, display_fns           |
    //! | 8300 §2.2      | Unassigned / reserved MD Type: raw context    | parse_unknown_md_type                 |
    //! | 8300 §2.2      | MD Type 1 Length must be 6                    | parse_md_type1_bad_length             |
    //! | 8300 §2.2      | Unknown Version: MD Type 2 context left raw   | parse_unknown_version                 |
    //! | —              | Dissector metadata                            | dissector_metadata                    |

    use super::*;

    /// Base header + Service Path Header.
    ///
    /// Ver=0, O as given, TTL=63, Length=`len`, MD Type=`md`, Next
    /// Protocol=`np`, SPI=0x123456, SI=255.
    fn header(o: bool, len: u8, md: u8, np: u8) -> Vec<u8> {
        let w0: u32 = (u32::from(o) << 29)
            | (63 << 22)
            | (u32::from(len) << 16)
            | (u32::from(md) << 8)
            | u32::from(np);
        let mut v = w0.to_be_bytes().to_vec();
        v.extend_from_slice(&[0x12, 0x34, 0x56, 0xFF]);
        v
    }

    #[test]
    fn parse_md_type1() {
        let mut data = header(false, 6, 1, 1);
        data.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]);
        data.extend_from_slice(&[0x45, 0x00]);
        let mut buf = DissectBuffer::new();
        let r = NshDissector.dissect(&data, &mut buf, 14).unwrap();
        assert_eq!(r.bytes_consumed, 24);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x0800));

        let layer = buf.layer_by_name("NSH").unwrap();
        assert_eq!(layer.range, 14..38);
        assert_eq!(buf.field_u8(layer, "version"), Some(0));
        assert_eq!(buf.field_u8(layer, "oam"), Some(0));
        assert_eq!(buf.field_u8(layer, "ttl"), Some(63));
        assert_eq!(buf.field_u8(layer, "length"), Some(6));
        assert_eq!(buf.field_u8(layer, "md_type"), Some(1));
        assert_eq!(buf.field_u8(layer, "next_protocol"), Some(1));
        assert_eq!(buf.field_u32(layer, "spi"), Some(0x12_3456));
        assert_eq!(buf.field_u8(layer, "si"), Some(255));
        assert_eq!(buf.field_bytes(layer, "context"), Some(&data[8..24]));
        assert!(buf.field_by_name(layer, "context_headers").is_none());
        assert_eq!(buf.field_by_name(layer, "spi").unwrap().range, 18..21);
        assert_eq!(buf.field_by_name(layer, "si").unwrap().range, 21..22);
        assert_eq!(buf.field_by_name(layer, "context").unwrap().range, 22..38);
        assert_eq!(buf.field_by_name(layer, "ttl").unwrap().range, 14..16);
    }

    #[test]
    fn parse_md_type2_no_context() {
        let mut data = header(false, 2, 2, 3);
        data.extend_from_slice(&[0xFF; 14]);
        let mut buf = DissectBuffer::new();
        let r = NshDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 8);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x6558));
        let layer = buf.layer_by_name("NSH").unwrap();
        assert!(buf.field_by_name(layer, "context").is_none());
        assert!(buf.field_by_name(layer, "context_headers").is_none());
    }

    /// Collect `(md_class, type, length, value)` of each Context Header.
    fn context_headers<'a>(buf: &'a DissectBuffer<'a>) -> Vec<(u16, u8, u8, &'a [u8])> {
        let layer = buf.layer_by_name("NSH").unwrap();
        let list = buf.field_by_name(layer, "context_headers").unwrap();
        let range = list.value.as_container_range().unwrap();
        buf.nested_fields(range)
            .iter()
            .filter_map(|f| f.value.as_container_range())
            .map(|r| {
                let fields = buf.nested_fields(r);
                let get = |n: &str| &fields.iter().find(|f| f.name() == n).unwrap().value;
                (
                    get("md_class").as_u16().unwrap(),
                    get("type").as_u8().unwrap(),
                    get("length").as_u8().unwrap(),
                    get("value").as_bytes().unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn parse_md_type2_context_headers() {
        // Two Context Headers: 0x0000/0x04 len 3 (padded to 4), and
        // 0x0200/0x81 (U bit set) len 0. Length = 2 + 2 + 1 = 5 words.
        let mut data = header(false, 5, 2, 5);
        data.extend_from_slice(&[0x00, 0x00, 0x04, 0x03, 0xAA, 0xBB, 0xCC, 0x00]);
        data.extend_from_slice(&[0x02, 0x00, 0x81, 0x80]);
        data.extend_from_slice(&[0x00, 0x01, 0x01, 0x40]);
        let mut buf = DissectBuffer::new();
        let r = NshDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 20);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x8847));
        let hdrs = context_headers(&buf);
        assert_eq!(
            hdrs,
            vec![
                (0x0000, 0x04, 3, &[0xAA, 0xBB, 0xCC][..]),
                (0x0200, 0x81, 0, &[][..]),
            ]
        );
        let layer = buf.layer_by_name("NSH").unwrap();
        assert!(
            buf.field_by_name(layer, "context_headers_malformed")
                .is_none()
        );
        let list = buf.field_by_name(layer, "context_headers").unwrap();
        assert_eq!(list.range, 8..20);
        // The U bit is reported separately from Length.
        let range = list.value.as_container_range().unwrap();
        let objs: Vec<_> = buf
            .nested_fields(range)
            .iter()
            .filter_map(|f| f.value.as_container_range().cloned())
            .collect();
        assert_eq!(objs.len(), 2);
        let second = buf.nested_fields(&objs[1]);
        let u = second.iter().find(|f| f.name() == "unassigned").unwrap();
        assert_eq!(u.value, FieldValue::U8(1));
        let first = buf.nested_fields(&objs[0]);
        let v = first.iter().find(|f| f.name() == "value").unwrap();
        assert_eq!(v.range, 12..15);
    }

    #[test]
    fn parse_md_type2_context_overrun() {
        // Context Header claims 8 bytes of metadata but Length leaves 4.
        let mut data = header(false, 4, 2, 1);
        data.extend_from_slice(&[0x00, 0x00, 0x01, 0x08, 0xAA, 0xBB, 0xCC, 0xDD]);
        data.extend_from_slice(&[0x45; 20]);
        let mut buf = DissectBuffer::new();
        let r = NshDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 16);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x0800));
        assert!(context_headers(&buf).is_empty());
        let layer = buf.layer_by_name("NSH").unwrap();
        assert_eq!(buf.field_u8(layer, "context_headers_malformed"), Some(1));
        let bad = buf
            .field_by_name(layer, "context_headers_malformed")
            .unwrap();
        assert_eq!(bad.range, 8..16);
    }

    #[test]
    fn parse_md_type1_bad_length() {
        let mut data = header(false, 3, 1, 1);
        data.extend_from_slice(&[1, 2, 3, 4]);
        let mut buf = DissectBuffer::new();
        let r = NshDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 12);
        let layer = buf.layer_by_name("NSH").unwrap();
        assert_eq!(buf.field_u8(layer, "length_invalid"), Some(1));
        assert_eq!(buf.field_bytes(layer, "context"), Some(&[1u8, 2, 3, 4][..]));

        // A well-formed MD Type 1 header is not flagged.
        let mut data = header(false, 6, 1, 1);
        data.extend_from_slice(&[0; 16]);
        let mut buf = DissectBuffer::new();
        NshDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("NSH").unwrap();
        assert!(buf.field_by_name(layer, "length_invalid").is_none());
    }

    #[test]
    fn parse_unknown_md_type() {
        // Unassigned (0x3) and Reserved (0x0) MD Types.
        for md in [0x3u8, 0x0] {
            let mut data = header(false, 3, md, 1);
            data.extend_from_slice(&[1, 2, 3, 4]);
            let mut buf = DissectBuffer::new();
            let r = NshDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(r.bytes_consumed, 12);
            let layer = buf.layer_by_name("NSH").unwrap();
            assert_eq!(buf.field_bytes(layer, "context"), Some(&[1u8, 2, 3, 4][..]));
            assert!(buf.field_by_name(layer, "context_headers").is_none());
        }

        let mut data = header(false, 3, 0xF, 1);
        data.extend_from_slice(&[1, 2, 3, 4]);
        let mut buf = DissectBuffer::new();
        let r = NshDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 12);
        let layer = buf.layer_by_name("NSH").unwrap();
        assert_eq!(buf.field_bytes(layer, "context"), Some(&[1u8, 2, 3, 4][..]));
        assert_eq!(
            buf.resolve_display_name(layer, "md_type_name"),
            Some("Experimentation")
        );
    }

    #[test]
    fn parse_oam_bit() {
        let data = header(true, 2, 2, 2);
        let mut buf = DissectBuffer::new();
        let r = NshDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.next, DispatchHint::ByEtherType(0x86DD));
        let layer = buf.layer_by_name("NSH").unwrap();
        assert_eq!(buf.field_u8(layer, "oam"), Some(1));
    }

    #[test]
    fn parse_unknown_version() {
        // MD Type 2 with a Context Header that would overrun under the
        // Version 0 rules; it is left raw instead.
        let mut data = header(false, 3, 2, 1);
        data[0] |= 0x80; // Ver = 2
        data.extend_from_slice(&[0x00, 0x00, 0x01, 0x08]);
        let mut buf = DissectBuffer::new();
        let r = NshDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 12);
        assert_eq!(r.next, DispatchHint::End);
        let layer = buf.layer_by_name("NSH").unwrap();
        assert_eq!(buf.field_u8(layer, "version"), Some(2));
        assert!(buf.field_by_name(layer, "context_headers").is_none());
        assert!(
            buf.field_by_name(layer, "context_headers_malformed")
                .is_none()
        );
        assert_eq!(
            buf.field_bytes(layer, "context"),
            Some(&[0x00u8, 0x00, 0x01, 0x08][..])
        );
    }

    #[test]
    fn parse_length_too_small() {
        for len in [0u8, 1] {
            let data = header(false, len, 2, 1);
            let mut buf = DissectBuffer::new();
            assert_eq!(
                NshDissector.dissect(&data, &mut buf, 0),
                Err(PacketError::InvalidFieldValue {
                    field: "length",
                    value: u32::from(len)
                })
            );
        }
    }

    #[test]
    fn parse_truncated() {
        let data = header(false, 6, 1, 1);
        let mut buf = DissectBuffer::new();
        assert_eq!(
            NshDissector.dissect(&data[..7], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 8,
                actual: 7
            })
        );
        assert_eq!(
            NshDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 24,
                actual: 8
            })
        );
        // Fewer than 8 bytes: the Base Header and Service Path Header are
        // checked before the Length field is used.
        assert_eq!(
            NshDissector.dissect(&data[..4], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 8,
                actual: 4
            })
        );
    }

    #[test]
    fn next_protocol_dispatch() {
        for (np, next) in [
            (1u8, DispatchHint::ByEtherType(0x0800)),
            (2, DispatchHint::ByEtherType(0x86DD)),
            (3, DispatchHint::ByEtherType(0x6558)),
            (4, DispatchHint::ByEtherType(0x894F)),
            (5, DispatchHint::ByEtherType(0x8847)),
            (6, DispatchHint::End),
            (7, DispatchHint::End),
            (0, DispatchHint::End),
            (0xFE, DispatchHint::End),
            (0x42, DispatchHint::End),
        ] {
            let data = header(false, 2, 2, np);
            let mut buf = DissectBuffer::new();
            let r = NshDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(r.next, next, "next protocol {np:#x}");
        }
    }

    #[test]
    fn md_type_and_next_protocol_names() {
        assert_eq!(md_type_name(0), Some("Reserved"));
        assert_eq!(md_type_name(1), Some("NSH MD Type 1"));
        assert_eq!(md_type_name(2), Some("NSH MD Type 2"));
        assert_eq!(md_type_name(3), None);
        assert_eq!(md_type_name(0xF), Some("Experimentation"));
        assert_eq!(next_protocol_name(0), Some("None"));
        assert_eq!(next_protocol_name(1), Some("IPv4"));
        assert_eq!(next_protocol_name(2), Some("IPv6"));
        assert_eq!(next_protocol_name(3), Some("Ethernet"));
        assert_eq!(next_protocol_name(4), Some("NSH"));
        assert_eq!(next_protocol_name(5), Some("MPLS"));
        assert_eq!(next_protocol_name(6), Some("IOAM"));
        assert_eq!(next_protocol_name(7), Some("SFC Active OAM"));
        assert_eq!(next_protocol_name(8), None);
        assert_eq!(next_protocol_name(0xFE), Some("Experiment 1"));
        assert_eq!(next_protocol_name(0xFF), Some("Experiment 2"));

        let data = header(false, 2, 2, 5);
        let mut buf = DissectBuffer::new();
        NshDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("NSH").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "next_protocol_name"),
            Some("MPLS")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "md_type_name"),
            Some("NSH MD Type 2")
        );
    }

    /// The display functions name their own value type and nothing else.
    #[test]
    fn display_fns() {
        let class = CONTEXT_HEADER_FIELD_DESCRIPTORS[CFD_MD_CLASS]
            .display_fn
            .unwrap();
        assert_eq!(
            class(&FieldValue::U16(0x0200), &[]),
            Some("BBF Specific NSH Metadata")
        );
        assert_eq!(class(&FieldValue::U8(0), &[]), None);
        for (fd, name) in [(FD_MD_TYPE, "NSH MD Type 1"), (FD_NEXT_PROTOCOL, "IPv4")] {
            let display = FIELD_DESCRIPTORS[fd].display_fn.unwrap();
            assert_eq!(display(&FieldValue::U8(1), &[]), Some(name));
            assert_eq!(display(&FieldValue::U16(1), &[]), None);
        }
    }

    #[test]
    fn md_class_names() {
        assert_eq!(md_class_name(0x0000), Some("IETF Base NSH MD Class"));
        assert_eq!(md_class_name(0x0200), Some("BBF Specific NSH Metadata"));
        assert_eq!(md_class_name(0xFFF6), Some("Experimental"));
        assert_eq!(md_class_name(0xFFFE), Some("Experimental"));
        assert_eq!(md_class_name(0xFFFF), Some("Reserved"));
        assert_eq!(md_class_name(0x0001), None);
    }

    #[test]
    fn dissector_metadata() {
        let d = NshDissector;
        assert_eq!(d.name(), "Network Service Header");
        assert_eq!(d.short_name(), "NSH");
        assert_eq!(d.layer(), Some(ProtocolLayer::Tunnel));
        assert!(d.references().iter().any(|r| r.id == "RFC 8300"));
        assert!(d.field_descriptors().iter().any(|f| f.name == "spi"));
    }
}
