//! MPLS (Multiprotocol Label Switching) dissector.
//!
//! Parses MPLS label stack entries as defined in RFC 3032, with the
//! Traffic Class (TC) field renamed from "Experimental" per RFC 5462, and
//! names special-purpose labels (RFC 7274). After the stack it decodes:
//!
//! - an Associated Channel Header (ACH) after a bottom-of-stack GAL
//!   (RFC 5586) or when the payload starts with 0001 (PW Associated
//!   Channel, RFC 4385, Section 5), emitted as an `ACH` layer and dispatched
//!   by Channel Type;
//! - a PW MPLS Control Word when the payload starts with 0000 (RFC 4385,
//!   Section 3), emitted as a `PW-CW` layer. The PW payload type is
//!   signalled out of band, so an Ethernet payload (RFC 4448) is only
//!   assumed when the bytes after the control word form a plausible
//!   Ethernet header, and the guess is shown in `payload_heuristic`.
//!
//! Other bottom labels use the first-nibble heuristic documented in RFC 4928.
//!
//! ## References
//! - RFC 3032 (MPLS Label Stack Encoding): <https://www.rfc-editor.org/rfc/rfc3032>
//! - RFC 4182 (updates RFC 3032 — Explicit NULL may appear anywhere in the stack):
//!   <https://www.rfc-editor.org/rfc/rfc4182>
//! - RFC 4385 (PW Control Word and PW Associated Channel):
//!   <https://www.rfc-editor.org/rfc/rfc4385>
//! - RFC 4448 (Ethernet over MPLS pseudowires): <https://www.rfc-editor.org/rfc/rfc4448>
//! - RFC 4928 (first-nibble heuristic / ECMP): <https://www.rfc-editor.org/rfc/rfc4928>
//! - RFC 5332 (MPLS Multicast Encapsulations): <https://www.rfc-editor.org/rfc/rfc5332>
//! - RFC 5462 (EXP field renamed to TC): <https://www.rfc-editor.org/rfc/rfc5462>
//! - RFC 5586 (MPLS Generic Associated Channel — GAL, label 13):
//!   <https://www.rfc-editor.org/rfc/rfc5586>
//! - RFC 6790 (Entropy Label Indicator, label 7): <https://www.rfc-editor.org/rfc/rfc6790>
//! - RFC 7026 (retires ACH TLVs; updates RFC 5586):
//!   <https://www.rfc-editor.org/rfc/rfc7026>
//! - RFC 7274 (Special-Purpose MPLS Label registry, Extension Label):
//!   <https://www.rfc-editor.org/rfc/rfc7274>
//! - RFC 9017 (Special-Purpose Label terminology):
//!   <https://www.rfc-editor.org/rfc/rfc9017>
//! - IANA Special-Purpose MPLS Label Values:
//!   <https://www.iana.org/assignments/mpls-label-values/mpls-label-values.xhtml>
//! - IANA MPLS Generalized Associated Channel (G-ACh) Types:
//!   <https://www.iana.org/assignments/g-ach-parameters/g-ach-parameters.xhtml>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Size of a single MPLS label stack entry in bytes.
///
/// RFC 3032, Section 2.1 — each label stack entry is exactly 4 octets.
const LABEL_ENTRY_SIZE: usize = 4;

/// Size of the Associated Channel Header (RFC 5586, Section 2.1; RFC 4385,
/// Section 5).
///
/// <https://www.rfc-editor.org/rfc/rfc5586#section-2.1>
const ACH_SIZE: usize = 4;

/// Size of the PW MPLS Control Word (RFC 4385, Section 3).
///
/// <https://www.rfc-editor.org/rfc/rfc4385#section-3>
const CONTROL_WORD_SIZE: usize = 4;

/// First nibble of a PW MPLS Control Word (RFC 4385, Section 3 — "0 0 0 0").
///
/// <https://www.rfc-editor.org/rfc/rfc4385#section-3>
const NIBBLE_CONTROL_WORD: u8 = 0x0;

/// First nibble of an Associated Channel Header (RFC 4385, Section 5 —
/// "Bits 0..3 MUST be 0001").
///
/// <https://www.rfc-editor.org/rfc/rfc4385#section-5>
const NIBBLE_ACH: u8 = 0x1;

/// EtherType used to dispatch an Ethernet PW payload to the Ethernet
/// dissector (Transparent Ethernet Bridging).
const ETHERTYPE_TEB: u16 = 0x6558;

/// Field descriptor index for the `label_stack` array.
const FD_LABEL_STACK: usize = 0;

/// Child field descriptor indices for each label stack entry.
const FD_ENTRY_LABEL: usize = 0;
const FD_ENTRY_TC: usize = 1;
const FD_ENTRY_S: usize = 2;
const FD_ENTRY_TTL: usize = 3;
const FD_ENTRY_ENTROPY_LABEL: usize = 4;
const FD_ENTRY_EXTENDED_SPECIAL_PURPOSE: usize = 5;

/// Return the IANA "Special-Purpose MPLS Label Values" name of `label`.
///
/// RFC 7274, Section 3 — <https://www.rfc-editor.org/rfc/rfc7274#section-3>;
/// IANA registry —
/// <https://www.iana.org/assignments/mpls-label-values/mpls-label-values.xhtml>
fn special_purpose_label_name(label: u32) -> Option<&'static str> {
    match label {
        LABEL_IPV4_EXPLICIT_NULL => Some("IPv4 Explicit NULL Label"),
        LABEL_ROUTER_ALERT => Some("Router Alert Label"),
        LABEL_IPV6_EXPLICIT_NULL => Some("IPv6 Explicit NULL Label"),
        LABEL_IMPLICIT_NULL => Some("Implicit NULL Label"),
        4 => Some("MPLS Network Actions"),
        LABEL_ELI => Some("Entropy Label Indicator (ELI)"),
        LABEL_GAL => Some("Generic Associated Channel Label"),
        14 => Some("OAM Alert Label"),
        LABEL_XL => Some("Extension Label (XL)"),
        _ => None,
    }
}

/// Child field descriptors for each label stack entry object.
static ENTRY_CHILDREN: &[FieldDescriptor] = &[
    // The name is looked up only for entries that are not an entropy label
    // (RFC 6790, Section 3) or an extended special-purpose label (RFC 7274,
    // Section 3.1), whose values are not special-purpose labels.
    // https://www.rfc-editor.org/rfc/rfc6790#section-3
    // https://www.rfc-editor.org/rfc/rfc7274#section-3.1
    FieldDescriptor::new("label", "Label", FieldType::U32).with_display_fn(|v, siblings| {
        if siblings
            .iter()
            .any(|f| matches!(f.name(), "entropy_label" | "extended_special_purpose"))
        {
            return None;
        }
        match v {
            FieldValue::U32(label) => special_purpose_label_name(*label),
            _ => None,
        }
    }),
    FieldDescriptor::new("tc", "Traffic Class", FieldType::U8),
    FieldDescriptor::new("s", "Bottom of Stack", FieldType::U8),
    FieldDescriptor::new("ttl", "Time to Live", FieldType::U8),
    // RFC 6790, Section 3 — set on the label that follows an ELI.
    // https://www.rfc-editor.org/rfc/rfc6790#section-3
    FieldDescriptor::new("entropy_label", "Entropy Label", FieldType::U8).optional(),
    // RFC 7274, Section 3.1 — set on the label that follows an XL.
    // https://www.rfc-editor.org/rfc/rfc7274#section-3.1
    FieldDescriptor::new(
        "extended_special_purpose",
        "Extended Special-Purpose Label",
        FieldType::U8,
    )
    .optional(),
];

/// Field descriptor for an individual label stack entry (Object container).
static ENTRY_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("entry", "Entry", FieldType::Object).with_children(ENTRY_CHILDREN);

static FIELD_DESCRIPTORS: &[FieldDescriptor] =
    &[
        FieldDescriptor::new("label_stack", "Label Stack", FieldType::Array)
            .with_children(ENTRY_CHILDREN),
    ];

/// Return the IANA "MPLS Generalized Associated Channel (G-ACh) Types"
/// description of `channel_type` (registry updated 2026-09-28).
///
/// <https://www.iana.org/assignments/g-ach-parameters/g-ach-parameters.xhtml>
fn ach_channel_type_name(channel_type: u16) -> Option<&'static str> {
    match channel_type {
        0x0000 => Some("Reserved"),
        0x0001 => Some("Management Communication Channel (MCC)"),
        0x0002 => Some("Signaling Communication Channel (SCC)"),
        0x0007 => Some("BFD Control, PW-ACH encapsulation (without IP/UDP Headers)"),
        0x0008 => Some("S-BFD Control, PW-ACH/L2SS encapsulation (without IP/UDP Headers)"),
        0x0009 => Some("MPLS-TP Dual-Homing Coordination message"),
        0x000A => Some("MPLS Direct Loss Measurement (DLM)"),
        0x000B => Some("MPLS Inferred Loss Measurement (ILM)"),
        0x000C => Some("MPLS Delay Measurement (DM)"),
        0x000D => Some("MPLS Direct Loss and Delay Measurement (DLM+DM)"),
        0x000E => Some("MPLS Inferred Loss and Delay Measurement (ILM+DM)"),
        0x000F => Some("Residence Time Measurement"),
        0x0010 => Some("Time Bucket Jitter Measurement"),
        0x0011 => Some("Multi-packet Delay Measurement"),
        0x0012 => Some("Average Delay Measurement"),
        0x0013 => Some("Multipoint BFD Session"),
        0x0014 => Some("STAMP Session-Sender"),
        0x0015 => Some("STAMP Session-Reflector"),
        0x0021 => Some("Associated Channel carries an IPv4 packet"),
        0x0022 => Some("MPLS-TP CC message"),
        0x0023 => Some("MPLS-TP CV message"),
        0x0024 => Some("Protection State Coordination Protocol - Channel Type (PSC-CT)"),
        0x0025 => Some("On-Demand CV"),
        0x0026 => Some("LI"),
        0x0027 => Some("PW OAM Message"),
        0x0028 => Some("MAC Withdraw OAM Message"),
        0x0029 => Some("PW Status Refresh Reduction"),
        0x002A => Some("Ring Protection Switching (RPS) Protocol"),
        0x0057 => Some("Associated Channel carries an IPv6 packet"),
        0x0058 => Some("Fault OAM"),
        0x0059 => Some("G-ACh Advertisement Protocol"),
        0x7FF8..=0x7FFF => Some("Reserved for Experimental Use"),
        0x8902 => Some("G.8113.1 OAM"),
        _ => None,
    }
}

/// Field descriptor indices for the `ACH` layer.
const FD_ACH_VERSION: usize = 0;
const FD_ACH_RESERVED: usize = 1;
const FD_ACH_CHANNEL_TYPE: usize = 2;

/// Fields of the Associated Channel Header (RFC 5586, Section 2.1; RFC 4385,
/// Section 5): `|0 0 0 1|Version|Reserved|Channel Type|`.
///
/// <https://www.rfc-editor.org/rfc/rfc5586#section-2.1>
static ACH_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U8),
    FieldDescriptor::new("channel_type", "Channel Type", FieldType::U16).with_display_fn(|v, _| {
        match v {
            FieldValue::U16(ct) => ach_channel_type_name(*ct),
            _ => None,
        }
    }),
];

/// Field descriptor indices for the `PW-CW` layer.
const FD_CW_FLAGS: usize = 0;
const FD_CW_FRG: usize = 1;
const FD_CW_LENGTH: usize = 2;
const FD_CW_SEQUENCE_NUMBER: usize = 3;
const FD_CW_PAYLOAD_HEURISTIC: usize = 4;

/// Fields of the Preferred PW MPLS Control Word (RFC 4385, Section 3):
/// `|0 0 0 0|Flags|FRG|Length|Sequence Number|`.
///
/// <https://www.rfc-editor.org/rfc/rfc4385#section-3>
static CW_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("flags", "Flags", FieldType::U8),
    FieldDescriptor::new("frg", "Fragmentation (FRG)", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U16),
    // Set when the payload type was guessed from the payload bytes rather
    // than known from the PW type (which is signalled out of band).
    FieldDescriptor::new("payload_heuristic", "Payload Heuristic", FieldType::Str).optional(),
];

/// Reserved label value: IPv4 Explicit NULL (RFC 3032, Section 2.1 — updated by RFC 4182).
///
/// Legal anywhere in the label stack (RFC 4182 relaxed the original
/// bottom-of-stack restriction); when popped from the bottom of the stack
/// the network-layer protocol MUST be IPv4.
const LABEL_IPV4_EXPLICIT_NULL: u32 = 0;

/// Reserved label value: Router Alert Label (RFC 3032, Section 2.1).
///
/// Legal anywhere except the bottom of the label stack. Parsing is lossless
/// even if the value appears at the bottom (Postel's Law).
const LABEL_ROUTER_ALERT: u32 = 1;

/// Reserved label value: IPv6 Explicit NULL (RFC 3032, Section 2.1 — updated by RFC 4182).
///
/// Legal anywhere in the label stack (RFC 4182 relaxed the original
/// bottom-of-stack restriction); when popped from the bottom of the stack
/// the network-layer protocol MUST be IPv6.
const LABEL_IPV6_EXPLICIT_NULL: u32 = 2;

/// Reserved label value: Implicit NULL Label (RFC 3032, Section 2.1).
///
/// A signalling-only value that "never actually appears in the encapsulation";
/// it is named if it does appear.
const LABEL_IMPLICIT_NULL: u32 = 3;

/// Special-purpose label value: Entropy Label Indicator (ELI).
///
/// RFC 6790, Section 3 — the label that follows the ELI is an entropy label.
/// <https://www.rfc-editor.org/rfc/rfc6790#section-3>
const LABEL_ELI: u32 = 7;

/// Reserved label value: Generic Associated Channel Label (GAL).
///
/// RFC 5586, Section 4 — indicates that a Generic Associated Channel Header
/// (ACH) immediately follows the label stack. The GAL MUST appear at the
/// bottom of the label stack (S=1) and MUST NOT be used with pseudowires.
const LABEL_GAL: u32 = 13;

/// Special-purpose label value: Extension Label (XL).
///
/// RFC 7274, Section 3.1 — the label that follows the XL is an extended
/// special-purpose label.
/// <https://www.rfc-editor.org/rfc/rfc7274#section-3.1>
const LABEL_XL: u32 = 15;

/// Specification references for the MPLS dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 3032",
        "MPLS Label Stack Encoding",
        "https://www.rfc-editor.org/rfc/rfc3032",
    ),
    SpecReference::new(
        "RFC 4182",
        "Removing a Restriction on the use of MPLS Explicit NULL",
        "https://www.rfc-editor.org/rfc/rfc4182",
    ),
    SpecReference::new(
        "RFC 4385",
        "Pseudowire Emulation Edge-to-Edge (PWE3) Control Word for Use over an MPLS PSN",
        "https://www.rfc-editor.org/rfc/rfc4385",
    ),
    SpecReference::new(
        "RFC 4448",
        "Encapsulation Methods for Transport of Ethernet over MPLS Networks",
        "https://www.rfc-editor.org/rfc/rfc4448",
    ),
    SpecReference::new(
        "RFC 4928",
        "Avoiding Equal Cost Multipath Treatment in MPLS Networks",
        "https://www.rfc-editor.org/rfc/rfc4928",
    ),
    SpecReference::new(
        "RFC 5332",
        "MPLS Multicast Encapsulations",
        "https://www.rfc-editor.org/rfc/rfc5332",
    ),
    SpecReference::new(
        "RFC 5462",
        "Multiprotocol Label Switching (MPLS) Label Stack Entry: \"EXP\" Field Renamed to \"Traffic Class\" Field",
        "https://www.rfc-editor.org/rfc/rfc5462",
    ),
    SpecReference::new(
        "RFC 5586",
        "MPLS Generic Associated Channel",
        "https://www.rfc-editor.org/rfc/rfc5586",
    ),
    SpecReference::new(
        "RFC 6790",
        "The Use of Entropy Labels in MPLS Forwarding",
        "https://www.rfc-editor.org/rfc/rfc6790",
    ),
    SpecReference::new(
        "RFC 7026",
        "Retiring TLVs from the Associated Channel Header of the MPLS Generic Associated Channel",
        "https://www.rfc-editor.org/rfc/rfc7026",
    ),
    SpecReference::new(
        "RFC 7274",
        "Allocating and Retiring Special-Purpose MPLS Labels",
        "https://www.rfc-editor.org/rfc/rfc7274",
    ),
    SpecReference::new(
        "RFC 9017",
        "Special-Purpose Label Terminology",
        "https://www.rfc-editor.org/rfc/rfc9017",
    ),
];

/// Return whether `ethertype` is one the Ethernet PW heuristic accepts as
/// the type of an inner Ethernet frame (not counting VLAN tags).
fn is_known_inner_ethertype(ethertype: u16) -> bool {
    matches!(
        ethertype,
        0x0800 // IPv4
            | 0x86DD // IPv6
            | 0x0806 // ARP
            | 0x8847 // MPLS unicast
            | 0x8848 // MPLS upstream-assigned
            | 0x8863 // PPPoE Discovery
            | 0x8864 // PPPoE Session
            | 0x8809 // Slow Protocols (LACP)
            | 0x88CC // LLDP
    )
}

/// Return whether `ethertype` is an IEEE 802.1Q C-tag or 802.1ad S-tag TPID.
fn is_vlan_tpid(ethertype: u16) -> bool {
    matches!(ethertype, 0x8100 | 0x88A8)
}

/// Return whether `payload` starts with a plausible Ethernet header: a known
/// EtherType, or up to two VLAN tags (802.1ad S-tag, 802.1Q C-tag) followed
/// by one.
///
/// RFC 4448, Section 4.6 — an Ethernet PW carries the frame without its
/// preamble and FCS, so the first EtherType sits at bytes 12-13.
/// <https://www.rfc-editor.org/rfc/rfc4448#section-4.6>
fn looks_like_ethernet(payload: &[u8]) -> bool {
    let mut pos = 12;
    for _ in 0..=2 {
        let Ok(ethertype) = read_be_u16(payload, pos) else {
            return false;
        };
        if !is_vlan_tpid(ethertype) {
            return is_known_inner_ethertype(ethertype);
        }
        pos += 4;
    }
    false
}

/// Associated Channel Header dissector.
///
/// Decodes `|0 0 0 1|Version|Reserved|Channel Type|` and dispatches the
/// message by Channel Type ([`DispatchHint::ByAchChannelType`]). The MPLS
/// dissector emits this layer after a GAL (RFC 5586) or for a PW Associated
/// Channel (RFC 4385, Section 5). RFC 7026 retired ACH TLVs ("A G-ACh message
/// MUST NOT be preceded by an ACH TLV"), so the message follows the 4-byte
/// header directly.
///
/// - RFC 5586, Section 2.1: <https://www.rfc-editor.org/rfc/rfc5586#section-2.1>
/// - RFC 4385, Section 5: <https://www.rfc-editor.org/rfc/rfc4385#section-5>
/// - RFC 7026, Section 3: <https://www.rfc-editor.org/rfc/rfc7026#section-3>
pub struct AchDissector;

/// Specification references for the ACH dissector.
static ACH_REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 5586",
        "MPLS Generic Associated Channel",
        "https://www.rfc-editor.org/rfc/rfc5586",
    ),
    SpecReference::new(
        "RFC 4385",
        "Pseudowire Emulation Edge-to-Edge (PWE3) Control Word for Use over an MPLS PSN",
        "https://www.rfc-editor.org/rfc/rfc4385",
    ),
    SpecReference::new(
        "RFC 7026",
        "Retiring TLVs from the Associated Channel Header of the MPLS Generic Associated Channel",
        "https://www.rfc-editor.org/rfc/rfc7026",
    ),
];

impl Dissector for AchDissector {
    fn name(&self) -> &'static str {
        "MPLS Associated Channel Header"
    }

    fn short_name(&self) -> &'static str {
        "ACH"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        ACH_FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        ACH_REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Network)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < ACH_SIZE {
            return Err(PacketError::Truncated {
                expected: ACH_SIZE,
                actual: data.len(),
            });
        }
        let word = read_be_u32(data, 0)?;
        // RFC 4385, Section 5 — "Bits 0..3 MUST be 0001."
        // https://www.rfc-editor.org/rfc/rfc4385#section-5
        let nibble = (word >> 28) as u8;
        if nibble != NIBBLE_ACH {
            return Err(PacketError::InvalidFieldValue {
                field: "ach_nibble",
                value: u32::from(nibble),
            });
        }
        let version = ((word >> 24) & 0x0F) as u8;
        let reserved = ((word >> 16) & 0xFF) as u8;
        let channel_type = (word & 0xFFFF) as u16;

        buf.begin_layer(
            self.short_name(),
            None,
            ACH_FIELD_DESCRIPTORS,
            offset..offset + ACH_SIZE,
        );
        buf.push_field(
            &ACH_FIELD_DESCRIPTORS[FD_ACH_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        // RFC 4385, Section 5 — "Reserved: MUST be sent as 0, and ignored on
        // reception."
        // https://www.rfc-editor.org/rfc/rfc4385#section-5
        buf.push_field(
            &ACH_FIELD_DESCRIPTORS[FD_ACH_RESERVED],
            FieldValue::U8(reserved),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &ACH_FIELD_DESCRIPTORS[FD_ACH_CHANNEL_TYPE],
            FieldValue::U16(channel_type),
            offset + 2..offset + 4,
        );
        buf.end_layer();

        // RFC 4385, Section 5 — "This specification defines version 0."
        // https://www.rfc-editor.org/rfc/rfc4385#section-5
        let next = if version == 0 {
            DispatchHint::ByAchChannelType(channel_type)
        } else {
            DispatchHint::End
        };
        Ok(DissectResult::new(ACH_SIZE, next))
    }
}

/// PW MPLS Control Word dissector.
///
/// Decodes the Preferred PW MPLS Control Word
/// `|0 0 0 0|Flags|FRG|Length|Sequence Number|`. The PW type, and hence the
/// payload type, is signalled out of band, so the payload is only
/// dispatched as Ethernet (RFC 4448) when it starts with a plausible
/// Ethernet header; the guess is recorded in `payload_heuristic`. A
/// non-zero Length bounds the payload.
///
/// - RFC 4385, Section 3: <https://www.rfc-editor.org/rfc/rfc4385#section-3>
/// - RFC 4448, Section 4.6: <https://www.rfc-editor.org/rfc/rfc4448#section-4.6>
pub struct PwControlWordDissector;

/// Specification references for the PW control word dissector.
static CW_REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 4385",
        "Pseudowire Emulation Edge-to-Edge (PWE3) Control Word for Use over an MPLS PSN",
        "https://www.rfc-editor.org/rfc/rfc4385",
    ),
    SpecReference::new(
        "RFC 4448",
        "Encapsulation Methods for Transport of Ethernet over MPLS Networks",
        "https://www.rfc-editor.org/rfc/rfc4448",
    ),
];

impl Dissector for PwControlWordDissector {
    fn name(&self) -> &'static str {
        "PW MPLS Control Word"
    }

    fn short_name(&self) -> &'static str {
        "PW-CW"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        CW_FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        CW_REFERENCES
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
        if data.len() < CONTROL_WORD_SIZE {
            return Err(PacketError::Truncated {
                expected: CONTROL_WORD_SIZE,
                actual: data.len(),
            });
        }
        let word = read_be_u32(data, 0)?;
        // RFC 4385, Section 3 — the control word starts with 0000.
        // https://www.rfc-editor.org/rfc/rfc4385#section-3
        let nibble = (word >> 28) as u8;
        if nibble != NIBBLE_CONTROL_WORD {
            return Err(PacketError::InvalidFieldValue {
                field: "control_word_nibble",
                value: u32::from(nibble),
            });
        }
        // |0 0 0 0| Flags (4) | FRG (2) | Length (6) | Sequence Number (16) |
        let flags = ((word >> 24) & 0x0F) as u8;
        let frg = ((word >> 22) & 0x03) as u8;
        let length = ((word >> 16) & 0x3F) as u8;
        let sequence_number = (word & 0xFFFF) as u16;

        // RFC 4385, Section 3 — "If the MPLS payload is less than 64 bytes,
        // the length field MUST be set to the length of the PW payload plus
        // the length of the PWMCW. Otherwise it MUST be set to zero." A value
        // below the control word size cannot be valid and is not used.
        // https://www.rfc-editor.org/rfc/rfc4385#section-3
        let payload_len = (length as usize).checked_sub(CONTROL_WORD_SIZE);
        let payload = &data[CONTROL_WORD_SIZE..];
        let payload = match payload_len {
            Some(len) => &payload[..len.min(payload.len())],
            None => payload,
        };

        buf.begin_layer(
            self.short_name(),
            None,
            CW_FIELD_DESCRIPTORS,
            offset..offset + CONTROL_WORD_SIZE,
        );
        buf.push_field(
            &CW_FIELD_DESCRIPTORS[FD_CW_FLAGS],
            FieldValue::U8(flags),
            offset..offset + 1,
        );
        buf.push_field(
            &CW_FIELD_DESCRIPTORS[FD_CW_FRG],
            FieldValue::U8(frg),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &CW_FIELD_DESCRIPTORS[FD_CW_LENGTH],
            FieldValue::U8(length),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &CW_FIELD_DESCRIPTORS[FD_CW_SEQUENCE_NUMBER],
            FieldValue::U16(sequence_number),
            offset + 2..offset + 4,
        );

        // RFC 4385, Section 3 — "The PW set-up protocol or configuration
        // mechanism determines whether a PW uses a PWMCW", and the PW type
        // (hence the payload type) is signalled out of band. Only a
        // plausible Ethernet header is decoded, and the guess is recorded.
        // https://www.rfc-editor.org/rfc/rfc4385#section-3
        let next = if looks_like_ethernet(payload) {
            buf.push_field(
                &CW_FIELD_DESCRIPTORS[FD_CW_PAYLOAD_HEURISTIC],
                FieldValue::Str("ethernet"),
                offset..offset + CONTROL_WORD_SIZE,
            );
            DispatchHint::ByEtherType(ETHERTYPE_TEB)
        } else {
            DispatchHint::End
        };
        buf.end_layer();

        let result = DissectResult::new(CONTROL_WORD_SIZE, next);
        Ok(match payload_len {
            Some(len) => result.with_payload_len(len),
            None => result,
        })
    }
}

/// MPLS dissector.
///
/// Parses one or more 4-byte label stack entries, then an Associated Channel
/// Header or a PW control word when present, and dispatches to the
/// next-layer protocol.
pub struct MplsDissector;

impl Dissector for MplsDissector {
    fn name(&self) -> &'static str {
        "Multiprotocol Label Switching"
    }

    fn short_name(&self) -> &'static str {
        "MPLS"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Network)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < LABEL_ENTRY_SIZE {
            return Err(PacketError::Truncated {
                expected: LABEL_ENTRY_SIZE,
                actual: data.len(),
            });
        }

        let mut pos = 0;

        // We need to pre-scan to find the total stack size before emitting
        // fields, so we can set the layer/array range correctly. However,
        // to avoid a double pass, we'll use begin_layer + begin_container
        // first and update ranges via end_container / end_layer.

        buf.begin_layer(self.short_name(), None, FIELD_DESCRIPTORS, offset..offset);

        let array_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_LABEL_STACK],
            FieldValue::Array(0..0),
            offset..offset,
        );

        // The previous entry's label when it was a special-purpose label
        // (not an entropy or extended special-purpose label). After the
        // loop it describes the bottom entry.
        let mut previous_label = None;

        // RFC 3032, Section 2.1 — parse label stack entries until Bottom of Stack (S=1).
        // The TC field follows the RFC 5462 rename (EXP → TC).
        // Returns the bottom label for next-layer dispatch.
        let bottom_label = loop {
            if data.len() < pos + LABEL_ENTRY_SIZE {
                return Err(PacketError::Truncated {
                    expected: pos + LABEL_ENTRY_SIZE,
                    actual: data.len(),
                });
            }

            let word = read_be_u32(data, pos)?;

            let label = word >> 12;
            let tc = ((word >> 9) & 0x07) as u8;
            let s = ((word >> 8) & 0x01) as u8;
            let ttl = (word & 0xFF) as u8;

            // All sub-fields share the same byte range (sub-byte fields, like IPv4 flags).
            let entry_start = offset + pos;
            let entry_end = entry_start + LABEL_ENTRY_SIZE;

            let obj_idx = buf.begin_container(
                &ENTRY_DESCRIPTOR,
                FieldValue::Object(0..0),
                entry_start..entry_end,
            );
            buf.push_field(
                &ENTRY_CHILDREN[FD_ENTRY_LABEL],
                FieldValue::U32(label),
                entry_start..entry_end,
            );
            buf.push_field(
                &ENTRY_CHILDREN[FD_ENTRY_TC],
                FieldValue::U8(tc),
                entry_start..entry_end,
            );
            buf.push_field(
                &ENTRY_CHILDREN[FD_ENTRY_S],
                FieldValue::U8(s),
                entry_start..entry_end,
            );
            buf.push_field(
                &ENTRY_CHILDREN[FD_ENTRY_TTL],
                FieldValue::U8(ttl),
                entry_start..entry_end,
            );
            match previous_label {
                // RFC 6790, Section 3 — the label after an ELI is the
                // entropy label.
                // https://www.rfc-editor.org/rfc/rfc6790#section-3
                Some(LABEL_ELI) => buf.push_field(
                    &ENTRY_CHILDREN[FD_ENTRY_ENTROPY_LABEL],
                    FieldValue::U8(1),
                    entry_start..entry_end,
                ),
                // RFC 7274, Section 3.1 — the label after an XL is an
                // extended special-purpose label.
                // https://www.rfc-editor.org/rfc/rfc7274#section-3.1
                Some(LABEL_XL) => buf.push_field(
                    &ENTRY_CHILDREN[FD_ENTRY_EXTENDED_SPECIAL_PURPOSE],
                    FieldValue::U8(1),
                    entry_start..entry_end,
                ),
                _ => {}
            }
            buf.end_container(obj_idx);

            // An entropy or extended special-purpose label carries an
            // arbitrary value, so it is not treated as a special-purpose
            // label itself.
            previous_label = match previous_label {
                Some(LABEL_ELI | LABEL_XL) => None,
                _ => Some(label),
            };

            pos += LABEL_ENTRY_SIZE;

            if s == 1 {
                break label;
            }
        };

        buf.end_container(array_idx);

        // Fix the array field range now that we know total size.
        if let Some(field) = buf.field_mut(array_idx as usize) {
            field.range = offset..offset + pos;
        }

        // Fix the layer range.
        if let Some(layer) = buf.last_layer_mut() {
            layer.range = offset..offset + pos;
        }

        buf.end_layer();

        // Determine next-layer protocol from the bottom label (S=1).
        //
        // RFC 3032, Section 2.1 — the label stack contains no explicit
        // network-layer protocol identifier; the payload type must be
        // inferable from the bottom label.  Reserved label semantics are
        // fixed by RFC 3032 / RFC 5586; all other bottom labels are told
        // apart by the first nibble of the payload (RFC 4928, Section 3;
        // RFC 4385, Sections 3 and 5). A bottom-of-stack entropy label or
        // extended special-purpose label carries an arbitrary value, not a
        // special-purpose label.
        // https://www.rfc-editor.org/rfc/rfc3032#section-2.1
        let bottom_is_special = previous_label.is_some();
        let payload = &data[pos..];
        let first_nibble = payload.first().map(|b| b >> 4);
        let has_word = payload.len() >= 4;
        let next = match (bottom_is_special, bottom_label) {
            // RFC 3032, Section 2.1 (updated by RFC 4182): Label 0 → IPv4.
            (true, LABEL_IPV4_EXPLICIT_NULL) => DispatchHint::ByEtherType(0x0800),
            // RFC 3032, Section 2.1 (updated by RFC 4182): Label 2 → IPv6.
            (true, LABEL_IPV6_EXPLICIT_NULL) => DispatchHint::ByEtherType(0x86DD),
            // RFC 5586, Section 4 — bottom-of-stack GAL signals that an
            // Associated Channel Header (first nibble 0001, Section 2.1)
            // follows the label stack, not an IP packet. Anything else, or a
            // header cut short, is not decoded.
            // https://www.rfc-editor.org/rfc/rfc5586#section-4
            (true, LABEL_GAL) => {
                if has_word && first_nibble == Some(NIBBLE_ACH) {
                    let ach = AchDissector.dissect(payload, buf, offset + pos)?;
                    return Ok(DissectResult::new(pos + ach.bytes_consumed, ach.next));
                }
                DispatchHint::End
            }
            _ => match first_nibble {
                // RFC 4928, Section 3 — existing equipment infers IPv4 or
                // IPv6 from the first nibble of the MPLS payload.
                // https://www.rfc-editor.org/rfc/rfc4928#section-3
                Some(4) => DispatchHint::ByEtherType(0x0800),
                Some(6) => DispatchHint::ByEtherType(0x86DD),
                // RFC 4385, Section 5 — PW Associated Channel Header. Without
                // a GAL only the first nibble identifies it, so the
                // Reserved octet, which "MUST be sent as 0", must be zero too.
                // https://www.rfc-editor.org/rfc/rfc4385#section-5
                Some(NIBBLE_ACH) if has_word && payload[1] == 0 => {
                    let ach = AchDissector.dissect(payload, buf, offset + pos)?;
                    return Ok(DissectResult::new(pos + ach.bytes_consumed, ach.next));
                }
                // RFC 4385, Section 3 — PW MPLS Control Word.
                // https://www.rfc-editor.org/rfc/rfc4385#section-3
                Some(NIBBLE_CONTROL_WORD) if has_word => {
                    let cw = PwControlWordDissector.dissect(payload, buf, offset + pos)?;
                    let result = DissectResult::new(pos + cw.bytes_consumed, cw.next);
                    return Ok(match cw.payload_len {
                        Some(len) => result.with_payload_len(len),
                        None => result,
                    });
                }
                _ => DispatchHint::End,
            },
        };
        Ok(DissectResult::new(pos, next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 3032 / RFC 4928 / RFC 5462 / RFC 5586 (MPLS) Coverage
    //
    // | RFC Section | Description                        | Test                                |
    // |-------------|------------------------------------|-------------------------------------|
    // | 3032 §2.1   | Label stack entry format           | parse_mpls_single_label             |
    // | 3032 §2.1   | Label stack (multiple)             | parse_mpls_two_labels               |
    // | 3032 §2.1   | Max 20-bit label value             | parse_mpls_max_label_value          |
    // | 3032 §2.1   | IPv4 Explicit NULL (0)             | parse_mpls_ipv4_explicit_null       |
    // | 3032 §2.1   | IPv6 Explicit NULL (2)             | parse_mpls_ipv6_explicit_null       |
    // | 5586 §4     | GAL bottom → ACH → channel type    | parse_mpls_gal_ach_bfd              |
    // | 5586 §2.1   | GAL without a valid ACH            | parse_mpls_gal_without_valid_ach    |
    // | 4385 §5     | PW-ACH (first nibble 1)            | parse_mpls_pw_ach_ipv4              |
    // | 4385 §5     | ACH version, reserved              | parse_mpls_ach_unknown_version      |
    // | 4385 §3     | PW control word + Ethernet guess   | parse_mpls_pw_control_word_ethernet |
    // | 4385 §3     | CW Flags/FRG/Length bound payload  | parse_mpls_pw_control_word_length_and_flags |
    // | 4385 §3     | CW Length 1-3 ignored              | parse_mpls_pw_control_word_invalid_length_ignored |
    // | 4385 §3     | CW with unknown payload            | parse_mpls_pw_control_word_unknown_payload |
    // | 4385 §3     | Truncated CW                       | parse_mpls_pw_control_word_truncated |
    // | 4448 §4.6   | Ethernet PW payload heuristic      | parse_mpls_pw_control_word_ethernet |
    // | 6790 §3     | Entropy label after ELI            | parse_mpls_entropy_label_after_eli  |
    // | 7274 §3.1   | Extended special-purpose after XL  | parse_mpls_extended_special_purpose_label_after_xl |
    // | 7274 §3     | Special-purpose label names        | special_purpose_label_names, parse_mpls_label_name_field |
    // | IANA G-ACh  | Channel type names                 | ach_channel_type_names              |
    // | 4928 §3     | Unknown first nibble → End         | parse_mpls_payload_unknown_nibble   |
    // | 6790 §3     | Bottom EL/ESPL is not reserved     | parse_mpls_bottom_entropy_label_is_not_reserved |
    // | 4385 §5     | PW-ACH needs zero Reserved w/o GAL | parse_mpls_pw_ach_requires_zero_reserved_without_gal |
    // | 4385 §3     | Heuristic bounded by CW Length     | parse_mpls_pw_control_word_heuristic_respects_length |
    // | 4448 §4.6   | QinQ / PPPoE Ethernet PW payload   | parse_mpls_pw_control_word_qinq_and_pppoe |
    // | 5586 / 4385 | Standalone ACH / CW dissectors     | standalone_ach_and_control_word_dissectors |
    // | 4928 §3     | First nibble heuristic IPv4        | parse_mpls_payload_heuristic        |
    // | 4928 §3     | First nibble heuristic IPv6        | parse_mpls_payload_heuristic_ipv6   |
    // | 4928 §3     | No payload after stack             | parse_mpls_no_payload               |
    // | 5462 §2     | TC field (renamed EXP)             | parse_mpls_tc_field                 |
    // | 3032 §2.1   | Truncated packet                   | parse_mpls_truncated                |
    // | 3032 §2.1   | Truncated mid-stack                | parse_mpls_truncated_mid_stack      |
    // | 3032 §2.1   | Offset handling                    | parse_mpls_with_offset              |
    // | 3032 §2.1   | Reserved label constants           | reserved_label_constants            |

    /// Helper: dissect raw bytes at offset 0 and return the result.
    fn dissect(data: &[u8]) -> Result<(DissectBuffer<'_>, DissectResult), PacketError> {
        let mut buf = DissectBuffer::new();
        let result = MplsDissector.dissect(data, &mut buf, 0)?;
        Ok((buf, result))
    }

    /// Build a single MPLS label stack entry.
    fn mpls_entry(label: u32, tc: u8, s: u8, ttl: u8) -> [u8; 4] {
        let word: u32 =
            (label << 12) | ((tc as u32 & 0x07) << 9) | ((s as u32 & 0x01) << 8) | ttl as u32;
        word.to_be_bytes()
    }

    /// Extract the label stack array range from a parsed buffer.
    fn label_stack_range(buf: &DissectBuffer) -> core::ops::Range<u32> {
        let layer = buf.layer_by_name("MPLS").expect("MPLS layer not found");
        let field = buf
            .field_by_name(layer, "label_stack")
            .expect("label_stack field not found");
        match &field.value {
            FieldValue::Array(r) => r.clone(),
            _ => panic!("label_stack is not an Array"),
        }
    }

    /// Get the Object range for an entry at the given index within the array.
    fn entry_object_range(
        buf: &DissectBuffer,
        array_range: &core::ops::Range<u32>,
        index: usize,
    ) -> core::ops::Range<u32> {
        let children = buf.nested_fields(array_range);
        // Each object in the array is a container field; find the index-th Object.
        let mut obj_count = 0;
        for field in children {
            if let FieldValue::Object(r) = &field.value {
                if obj_count == index {
                    return r.clone();
                }
                obj_count += 1;
            }
        }
        panic!("entry object at index {index} not found");
    }

    /// Get a named field value from an entry's Object fields.
    fn entry_field_value<'a>(
        buf: &'a DissectBuffer,
        obj_range: &core::ops::Range<u32>,
        name: &str,
    ) -> &'a FieldValue<'a> {
        let fields = buf.nested_fields(obj_range);
        &fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("field '{name}' not found"))
            .value
    }

    #[test]
    fn parse_mpls_single_label() {
        let entry = mpls_entry(100, 0, 1, 64);
        // 0x45 triggers the IPv4 first-nibble heuristic for next-layer dispatch
        let mut raw = entry.to_vec();
        raw.push(0x45);

        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 4);

        let array_range = label_stack_range(&buf);
        let obj_range = entry_object_range(&buf, &array_range, 0);
        assert_eq!(
            *entry_field_value(&buf, &obj_range, "label"),
            FieldValue::U32(100)
        );
        assert_eq!(
            *entry_field_value(&buf, &obj_range, "tc"),
            FieldValue::U8(0)
        );
        assert_eq!(*entry_field_value(&buf, &obj_range, "s"), FieldValue::U8(1));
        assert_eq!(
            *entry_field_value(&buf, &obj_range, "ttl"),
            FieldValue::U8(64)
        );
    }

    #[test]
    fn parse_mpls_two_labels() {
        let outer = mpls_entry(200, 5, 0, 128);
        let inner = mpls_entry(300, 3, 1, 64);
        let mut raw = Vec::new();
        raw.extend_from_slice(&outer);
        raw.extend_from_slice(&inner);
        raw.push(0x45);

        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 8);

        let array_range = label_stack_range(&buf);

        let obj0 = entry_object_range(&buf, &array_range, 0);
        assert_eq!(
            *entry_field_value(&buf, &obj0, "label"),
            FieldValue::U32(200)
        );
        assert_eq!(*entry_field_value(&buf, &obj0, "tc"), FieldValue::U8(5));
        assert_eq!(*entry_field_value(&buf, &obj0, "s"), FieldValue::U8(0));
        assert_eq!(*entry_field_value(&buf, &obj0, "ttl"), FieldValue::U8(128));

        let obj1 = entry_object_range(&buf, &array_range, 1);
        assert_eq!(
            *entry_field_value(&buf, &obj1, "label"),
            FieldValue::U32(300)
        );
        assert_eq!(*entry_field_value(&buf, &obj1, "tc"), FieldValue::U8(3));
        assert_eq!(*entry_field_value(&buf, &obj1, "s"), FieldValue::U8(1));
        assert_eq!(*entry_field_value(&buf, &obj1, "ttl"), FieldValue::U8(64));
    }

    #[test]
    fn parse_mpls_ipv4_explicit_null() {
        // Label=0 (IPv4 Explicit NULL), S=1
        let entry = mpls_entry(0, 0, 1, 255);
        let (_, result) = dissect(&entry).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
    }

    #[test]
    fn parse_mpls_ipv6_explicit_null() {
        // Label=2 (IPv6 Explicit NULL), S=1
        let entry = mpls_entry(2, 0, 1, 255);
        let (_, result) = dissect(&entry).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn parse_mpls_payload_heuristic() {
        // Non-reserved label, payload first nibble = 4 → IPv4
        let entry = mpls_entry(1000, 0, 1, 64);
        let mut raw = entry.to_vec();
        raw.push(0x45); // IPv4 version nibble

        let (_, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
    }

    #[test]
    fn parse_mpls_payload_heuristic_ipv6() {
        // Non-reserved label, payload first nibble = 6 → IPv6
        let entry = mpls_entry(1000, 0, 1, 64);
        let mut raw = entry.to_vec();
        raw.push(0x60); // IPv6 version nibble

        let (_, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn parse_mpls_no_payload() {
        // Non-reserved label with no payload bytes after the stack → End
        let entry = mpls_entry(1000, 0, 1, 64);
        let (_, result) = dissect(&entry).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn parse_mpls_tc_field() {
        // RFC 5462 — verify all 3 TC bits are extracted correctly
        let entry = mpls_entry(500, 7, 1, 32);
        let (buf, _) = dissect(&entry).expect("dissect failed");
        let array_range = label_stack_range(&buf);
        let obj_range = entry_object_range(&buf, &array_range, 0);
        assert_eq!(
            *entry_field_value(&buf, &obj_range, "tc"),
            FieldValue::U8(7)
        );
    }

    #[test]
    fn parse_mpls_truncated() {
        // Less than 4 bytes
        let raw: &[u8] = &[0x00, 0x00, 0x01];
        let err = MplsDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 3,
            }
        ));
    }

    #[test]
    fn parse_mpls_truncated_mid_stack() {
        // First entry has S=0, but no second entry available
        let entry = mpls_entry(100, 0, 0, 64); // S=0 → more entries expected
        let err = MplsDissector
            .dissect(&entry, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 4,
            }
        ));
    }

    #[test]
    fn parse_mpls_with_offset() {
        // Verify byte ranges use the offset parameter correctly
        let entry = mpls_entry(100, 0, 1, 64);
        let mut buf = DissectBuffer::new();
        let result = MplsDissector
            .dissect(&entry, &mut buf, 14)
            .expect("dissect failed");
        assert_eq!(result.bytes_consumed, 4);

        let layer = buf.layer_by_name("MPLS").expect("MPLS layer not found");
        assert_eq!(layer.range, 14..18);

        let field = buf
            .field_by_name(layer, "label_stack")
            .expect("label_stack not found");
        assert_eq!(field.range, 14..18);
    }

    #[test]
    fn field_descriptors_consistent() {
        let descs = MplsDissector.field_descriptors();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[FD_LABEL_STACK].name, "label_stack");
        assert_eq!(descs[FD_LABEL_STACK].field_type, FieldType::Array);

        let children = descs[FD_LABEL_STACK].children.expect("children is None");
        assert_eq!(children.len(), 6);
        assert_eq!(children[0].name, "label");
        assert_eq!(children[1].name, "tc");
        assert_eq!(children[2].name, "s");
        assert_eq!(children[3].name, "ttl");
        assert_eq!(children[4].name, "entropy_label");
        assert_eq!(children[5].name, "extended_special_purpose");
    }

    #[test]
    fn reserved_label_constants() {
        // RFC 3032, Section 2.1 — Reserved Label Values
        assert_eq!(LABEL_IPV4_EXPLICIT_NULL, 0);
        assert_eq!(LABEL_ROUTER_ALERT, 1);
        assert_eq!(LABEL_IPV6_EXPLICIT_NULL, 2);
        assert_eq!(LABEL_IMPLICIT_NULL, 3);
        // RFC 6790, Section 3 — Entropy Label Indicator.
        assert_eq!(LABEL_ELI, 7);
        // RFC 5586, Section 4 — Generic Associated Channel Label.
        assert_eq!(LABEL_GAL, 13);
        // RFC 7274, Section 3 — Extension Label.
        assert_eq!(LABEL_XL, 15);
    }

    #[test]
    fn parse_mpls_max_label_value() {
        // RFC 3032, Section 2.1 — Label is 20 bits (max 0xFFFFF).
        let entry = mpls_entry(0xFFFFF, 0, 1, 64);
        let (buf, _) = dissect(&entry).expect("dissect failed");
        let array_range = label_stack_range(&buf);
        let obj_range = entry_object_range(&buf, &array_range, 0);
        assert_eq!(
            *entry_field_value(&buf, &obj_range, "label"),
            FieldValue::U32(0xFFFFF)
        );
    }

    /// Find the value of `name` inside the first layer called `layer`.
    fn layer_field<'a>(buf: &'a DissectBuffer<'a>, layer: &str, name: &str) -> &'a FieldValue<'a> {
        let layer = buf.layer_by_name(layer).expect("layer not found");
        &buf.field_by_name(layer, name)
            .expect("field not found")
            .value
    }

    /// Resolve `<name>_name` of the entry at `index`.
    fn entry_label_name(buf: &DissectBuffer, index: usize) -> Option<&'static str> {
        let array_range = label_stack_range(buf);
        let obj = entry_object_range(buf, &array_range, index);
        buf.resolve_nested_display_name(&obj, "label_name")
    }

    /// RFC 5586, Section 4 — GAL at the bottom of the stack: an ACH follows
    /// (RFC 5586, Section 2.1). The example is VCCV BFD, channel type 0x0007
    /// (RFC 5885, Section 3.2).
    #[test]
    fn parse_mpls_gal_ach_bfd() {
        let mut raw = mpls_entry(LABEL_GAL, 0, 1, 1).to_vec();
        raw.extend_from_slice(&[0x10, 0x00, 0x00, 0x07]); // ACH: v0, channel type 0x0007
        raw.extend_from_slice(&[0x20, 0x40, 0x05, 0x18]); // BFD control packet (start)

        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByAchChannelType(0x0007));

        let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
        assert_eq!(names, ["MPLS", "ACH"]);
        let ach = buf.layer_by_name("ACH").unwrap();
        assert_eq!(ach.range, 4..8);
        assert_eq!(*layer_field(&buf, "ACH", "version"), FieldValue::U8(0));
        assert_eq!(*layer_field(&buf, "ACH", "reserved"), FieldValue::U8(0));
        assert_eq!(
            *layer_field(&buf, "ACH", "channel_type"),
            FieldValue::U16(0x0007)
        );
        assert_eq!(
            buf.resolve_display_name(ach, "channel_type_name"),
            Some("BFD Control, PW-ACH encapsulation (without IP/UDP Headers)")
        );
        assert_eq!(buf.field_by_name(ach, "channel_type").unwrap().range, 6..8);
        assert_eq!(
            entry_label_name(&buf, 0),
            Some("Generic Associated Channel Label")
        );
    }

    /// RFC 4385, Section 5 — without GAL, a first nibble of 0001 is a PW
    /// Associated Channel Header. Channel type 0x0021 carries IPv4
    /// (RFC 4385, Section 6).
    #[test]
    fn parse_mpls_pw_ach_ipv4() {
        let mut raw = mpls_entry(1000, 0, 1, 64).to_vec();
        raw.extend_from_slice(&[0x10, 0x00, 0x00, 0x21]);
        raw.push(0x45);
        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByAchChannelType(0x0021));
        let ach = buf.layer_by_name("ACH").unwrap();
        assert_eq!(
            buf.resolve_display_name(ach, "channel_type_name"),
            Some("Associated Channel carries an IPv4 packet")
        );
    }

    /// RFC 4385, Section 5 — "This specification defines version 0." An ACH
    /// with another version is reported but not dispatched. Reserved bits
    /// are "ignored on reception".
    #[test]
    fn parse_mpls_ach_unknown_version() {
        let mut raw = mpls_entry(LABEL_GAL, 0, 1, 1).to_vec();
        raw.extend_from_slice(&[0x11, 0xAB, 0x00, 0x07]); // version 1, reserved 0xAB
        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(*layer_field(&buf, "ACH", "version"), FieldValue::U8(1));
        assert_eq!(*layer_field(&buf, "ACH", "reserved"), FieldValue::U8(0xAB));
    }

    /// RFC 5586, Section 2.1 — the ACH first nibble is 0001. A GAL followed by
    /// anything else, or by fewer than 4 bytes, has no decodable ACH.
    #[test]
    fn parse_mpls_gal_without_valid_ach() {
        let mut raw = mpls_entry(LABEL_GAL, 0, 1, 1).to_vec();
        raw.extend_from_slice(&[0x45, 0x00, 0x00, 0x14]);
        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(result.next, DispatchHint::End);
        assert!(buf.layer_by_name("ACH").is_none());

        let mut short = mpls_entry(LABEL_GAL, 0, 1, 1).to_vec();
        short.extend_from_slice(&[0x10, 0x00]);
        let (buf, result) = dissect(&short).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(result.next, DispatchHint::End);
        assert!(buf.layer_by_name("ACH").is_none());
    }

    /// RFC 4385, Section 3 — first nibble 0000 is the PW MPLS Control Word:
    /// Flags (4), FRG (2), Length (6), Sequence Number (16). The payload of an
    /// Ethernet PW (RFC 4448, Section 4.6) is recognised by a plausible
    /// Ethernet header, and the guess is visible in `payload_heuristic`.
    #[test]
    fn parse_mpls_pw_control_word_ethernet() {
        let mut raw = mpls_entry(16, 0, 1, 64).to_vec();
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // CW, sequence 1
        raw.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
        raw.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]); // src MAC
        raw.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        raw.extend_from_slice(&[0x45, 0x00]);

        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));
        assert_eq!(result.payload_len, None);

        let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
        assert_eq!(names, ["MPLS", "PW-CW"]);
        let cw = buf.layer_by_name("PW-CW").unwrap();
        assert_eq!(cw.range, 4..8);
        assert_eq!(*layer_field(&buf, "PW-CW", "flags"), FieldValue::U8(0));
        assert_eq!(*layer_field(&buf, "PW-CW", "frg"), FieldValue::U8(0));
        assert_eq!(*layer_field(&buf, "PW-CW", "length"), FieldValue::U8(0));
        assert_eq!(
            *layer_field(&buf, "PW-CW", "sequence_number"),
            FieldValue::U16(1)
        );
        assert_eq!(
            *layer_field(&buf, "PW-CW", "payload_heuristic"),
            FieldValue::Str("ethernet")
        );
        assert_eq!(
            buf.field_by_name(cw, "sequence_number").unwrap().range,
            6..8
        );
    }

    /// RFC 4385, Section 3 — the non-zero Length (PW payload plus control
    /// word) bounds the payload, so Ethernet padding is not decoded. Flags
    /// and FRG are decoded from bits 4-7 and 8-9.
    #[test]
    fn parse_mpls_pw_control_word_length_and_flags() {
        let mut raw = mpls_entry(16, 0, 1, 64).to_vec();
        // Flags 0b1010, FRG 0b10, Length 22 (18-byte payload + 4-byte CW), sequence 0x1234
        raw.extend_from_slice(&[0x0A, 0x96, 0x12, 0x34]);
        raw.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        raw.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        raw.extend_from_slice(&[0x81, 0x00, 0x00, 0x64, 0x86, 0xDD]); // VLAN 100, IPv6
        raw.extend_from_slice(&[0x00; 6]); // padding
        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));
        assert_eq!(result.payload_len, Some(18));
        assert_eq!(*layer_field(&buf, "PW-CW", "flags"), FieldValue::U8(0x0A));
        assert_eq!(*layer_field(&buf, "PW-CW", "frg"), FieldValue::U8(0x02));
        assert_eq!(*layer_field(&buf, "PW-CW", "length"), FieldValue::U8(22));
        assert_eq!(
            *layer_field(&buf, "PW-CW", "sequence_number"),
            FieldValue::U16(0x1234)
        );
    }

    /// When the bytes after the control word do not look like Ethernet the
    /// payload type is unknown (it is signalled out of band), so dissection
    /// ends at the control word and no heuristic is claimed.
    #[test]
    fn parse_mpls_pw_control_word_unknown_payload() {
        let mut raw = mpls_entry(16, 0, 1, 64).to_vec();
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        raw.extend_from_slice(&[0xAA; 14]); // EtherType 0xAAAA is not known
        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::End);
        let cw = buf.layer_by_name("PW-CW").unwrap();
        assert!(buf.field_by_name(cw, "payload_heuristic").is_none());

        // Too short for an Ethernet header.
        let mut short = mpls_entry(16, 0, 1, 64).to_vec();
        short.extend_from_slice(&[0x00, 0x00, 0x00, 0x02, 0x00, 0x11]);
        let (_, result) = dissect(&short).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::End);

        // VLAN tag followed by an unknown EtherType.
        let mut vlan = mpls_entry(16, 0, 1, 64).to_vec();
        vlan.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        vlan.extend_from_slice(&[0x02; 12]);
        vlan.extend_from_slice(&[0x81, 0x00, 0x00, 0x64, 0xAA, 0xAA]);
        let (_, result) = dissect(&vlan).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::End);
    }

    /// A control word cut short is not decoded; the MPLS layer still is.
    #[test]
    fn parse_mpls_pw_control_word_truncated() {
        let mut raw = mpls_entry(16, 0, 1, 64).to_vec();
        raw.extend_from_slice(&[0x00, 0x00]);
        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(result.next, DispatchHint::End);
        assert!(buf.layer_by_name("PW-CW").is_none());
    }

    /// RFC 4385, Section 3 — a Length of 1-3 cannot include the 4-byte
    /// control word, so it does not bound the payload.
    #[test]
    fn parse_mpls_pw_control_word_invalid_length_ignored() {
        let mut raw = mpls_entry(16, 0, 1, 64).to_vec();
        raw.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]); // Length 2
        raw.extend_from_slice(&[0x02; 12]);
        raw.extend_from_slice(&[0x08, 0x06]); // ARP
        let (_, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));
        assert_eq!(result.payload_len, None);
    }

    /// RFC 7274, Section 3 and the IANA Special-Purpose MPLS Label Values
    /// registry — label names.
    #[test]
    fn special_purpose_label_names() {
        assert_eq!(
            special_purpose_label_name(0),
            Some("IPv4 Explicit NULL Label")
        );
        assert_eq!(special_purpose_label_name(1), Some("Router Alert Label"));
        assert_eq!(
            special_purpose_label_name(2),
            Some("IPv6 Explicit NULL Label")
        );
        assert_eq!(special_purpose_label_name(3), Some("Implicit NULL Label"));
        assert_eq!(special_purpose_label_name(4), Some("MPLS Network Actions"));
        assert_eq!(special_purpose_label_name(5), None);
        assert_eq!(
            special_purpose_label_name(7),
            Some("Entropy Label Indicator (ELI)")
        );
        assert_eq!(
            special_purpose_label_name(13),
            Some("Generic Associated Channel Label")
        );
        assert_eq!(special_purpose_label_name(14), Some("OAM Alert Label"));
        assert_eq!(special_purpose_label_name(15), Some("Extension Label (XL)"));
        assert_eq!(special_purpose_label_name(16), None);
    }

    /// Label names are exposed as `label_name` on each entry.
    #[test]
    fn parse_mpls_label_name_field() {
        let mut raw = mpls_entry(1, 0, 0, 64).to_vec();
        raw.extend_from_slice(&mpls_entry(0, 0, 1, 64));
        let (buf, _) = dissect(&raw).expect("dissect failed");
        assert_eq!(entry_label_name(&buf, 0), Some("Router Alert Label"));
        assert_eq!(entry_label_name(&buf, 1), Some("IPv4 Explicit NULL Label"));
    }

    /// RFC 6790, Section 3 — the label after an Entropy Label Indicator is an
    /// entropy label. Its value is not a special-purpose label.
    #[test]
    fn parse_mpls_entropy_label_after_eli() {
        let mut raw = mpls_entry(100, 0, 0, 64).to_vec();
        raw.extend_from_slice(&mpls_entry(LABEL_ELI, 0, 0, 0));
        raw.extend_from_slice(&mpls_entry(7, 0, 1, 0)); // entropy label with value 7
        raw.push(0x45);
        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 12);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

        let array_range = label_stack_range(&buf);
        let eli = entry_object_range(&buf, &array_range, 1);
        let el = entry_object_range(&buf, &array_range, 2);
        assert!(
            buf.nested_fields(&eli)
                .iter()
                .all(|f| f.name() != "entropy_label")
        );
        assert_eq!(
            *entry_field_value(&buf, &el, "entropy_label"),
            FieldValue::U8(1)
        );
        assert_eq!(
            entry_label_name(&buf, 1),
            Some("Entropy Label Indicator (ELI)")
        );
        assert_eq!(entry_label_name(&buf, 2), None);
    }

    /// RFC 7274, Section 3.1 — the label after the Extension Label is an
    /// extended special-purpose label, not a special-purpose one.
    #[test]
    fn parse_mpls_extended_special_purpose_label_after_xl() {
        let mut raw = mpls_entry(LABEL_XL, 0, 0, 64).to_vec();
        raw.extend_from_slice(&mpls_entry(13, 0, 0, 64));
        raw.extend_from_slice(&mpls_entry(100, 0, 1, 64));
        let (buf, _) = dissect(&raw).expect("dissect failed");
        let array_range = label_stack_range(&buf);
        let esp = entry_object_range(&buf, &array_range, 1);
        assert_eq!(
            *entry_field_value(&buf, &esp, "extended_special_purpose"),
            FieldValue::U8(1)
        );
        assert_eq!(entry_label_name(&buf, 0), Some("Extension Label (XL)"));
        assert_eq!(entry_label_name(&buf, 1), None);
    }

    /// RFC 4928, Section 3 — a first nibble other than 0, 1, 4 or 6 is not
    /// IP, a control word or an ACH, so dissection ends at the label stack.
    /// <https://www.rfc-editor.org/rfc/rfc4928#section-3>
    #[test]
    fn parse_mpls_payload_unknown_nibble() {
        for first in [0x20, 0x50, 0xF0] {
            let mut raw = mpls_entry(1000, 0, 1, 64).to_vec();
            raw.extend_from_slice(&[first, 0x00, 0x00, 0x00]);
            let (buf, result) = dissect(&raw).expect("dissect failed");
            assert_eq!(result.bytes_consumed, 4);
            assert_eq!(result.next, DispatchHint::End);
            assert_eq!(buf.layers().len(), 1);
        }
    }

    /// A bottom-of-stack entropy label (RFC 6790, Section 3) or extended
    /// special-purpose label (RFC 7274, Section 3.1) is not a reserved label,
    /// even when its value is 0, 2 or 13.
    #[test]
    fn parse_mpls_bottom_entropy_label_is_not_reserved() {
        let mut raw = mpls_entry(LABEL_ELI, 0, 0, 0).to_vec();
        raw.extend_from_slice(&mpls_entry(LABEL_GAL, 0, 1, 0)); // EL value 13
        raw.push(0x45);
        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
        assert!(buf.layer_by_name("ACH").is_none());

        let mut raw = mpls_entry(LABEL_XL, 0, 0, 0).to_vec();
        raw.extend_from_slice(&mpls_entry(0, 0, 1, 0)); // ESPL value 0
        raw.push(0x60);
        let (_, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
    }

    /// RFC 4385, Section 5 — Reserved "MUST be sent as 0". Without a GAL the
    /// first nibble alone identifies a PW-ACH, so a non-zero reserved octet
    /// is taken as a sign that the payload is something else (for example an
    /// Ethernet PW without a control word) and is not decoded as an ACH.
    #[test]
    fn parse_mpls_pw_ach_requires_zero_reserved_without_gal() {
        let mut raw = mpls_entry(1000, 0, 1, 64).to_vec();
        raw.extend_from_slice(&[0x10, 0x5E, 0x00, 0x07, 0x00, 0x01]);
        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(result.next, DispatchHint::End);
        assert!(buf.layer_by_name("ACH").is_none());
    }

    /// RFC 4385, Section 3 — when Length bounds the payload, the Ethernet
    /// heuristic only looks at the payload, not at the padding after it.
    #[test]
    fn parse_mpls_pw_control_word_heuristic_respects_length() {
        let mut raw = mpls_entry(16, 0, 1, 64).to_vec();
        raw.extend_from_slice(&[0x00, 0x0A, 0x00, 0x01]); // Length 10: 6-byte payload
        raw.extend_from_slice(&[0x00; 6]); // payload
        raw.extend_from_slice(&[0x00; 6]); // padding
        raw.extend_from_slice(&[0x08, 0x00]); // padding that looks like an EtherType
        let (buf, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(result.payload_len, Some(6));
        let cw = buf.layer_by_name("PW-CW").unwrap();
        assert!(buf.field_by_name(cw, "payload_heuristic").is_none());
    }

    /// RFC 4448, Section 4.6 — an Ethernet PW commonly carries QinQ frames
    /// (802.1ad S-tag, then 802.1Q C-tag) and PPPoE.
    #[test]
    fn parse_mpls_pw_control_word_qinq_and_pppoe() {
        let mut raw = mpls_entry(16, 0, 1, 64).to_vec();
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        raw.extend_from_slice(&[0x02; 12]);
        raw.extend_from_slice(&[0x88, 0xA8, 0x00, 0x0A, 0x81, 0x00, 0x00, 0x14, 0x08, 0x00]);
        let (_, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));

        let mut raw = mpls_entry(16, 0, 1, 64).to_vec();
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        raw.extend_from_slice(&[0x02; 12]);
        raw.extend_from_slice(&[0x88, 0x64]);
        let (_, result) = dissect(&raw).expect("dissect failed");
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));
    }

    /// The ACH and control word dissectors also work on their own and
    /// reject input that does not start with their first nibble.
    #[test]
    fn standalone_ach_and_control_word_dissectors() {
        let mut buf = DissectBuffer::new();
        let result = AchDissector
            .dissect(&[0x10, 0x00, 0x00, 0x21], &mut buf, 0)
            .unwrap();
        assert_eq!(result.next, DispatchHint::ByAchChannelType(0x0021));
        assert!(matches!(
            AchDissector.dissect(&[0x10, 0x00], &mut DissectBuffer::new(), 0),
            Err(PacketError::Truncated {
                expected: 4,
                actual: 2
            })
        ));
        assert!(matches!(
            AchDissector.dissect(&[0x00, 0x00, 0x00, 0x21], &mut DissectBuffer::new(), 0),
            Err(PacketError::InvalidFieldValue {
                field: "ach_nibble",
                value: 0
            })
        ));

        let result = PwControlWordDissector
            .dissect(&[0x00, 0x00, 0x00, 0x05], &mut DissectBuffer::new(), 0)
            .unwrap();
        assert_eq!(result.next, DispatchHint::End);
        assert!(matches!(
            PwControlWordDissector.dissect(&[0x00], &mut DissectBuffer::new(), 0),
            Err(PacketError::Truncated {
                expected: 4,
                actual: 1
            })
        ));
        assert!(matches!(
            PwControlWordDissector.dissect(&[0x10, 0x00, 0x00, 0x05], &mut DissectBuffer::new(), 0),
            Err(PacketError::InvalidFieldValue {
                field: "control_word_nibble",
                value: 1
            })
        ));
    }

    #[test]
    fn ach_channel_type_names() {
        assert_eq!(ach_channel_type_name(0x0000), Some("Reserved"));
        assert_eq!(ach_channel_type_name(0x0022), Some("MPLS-TP CC message"));
        assert_eq!(
            ach_channel_type_name(0x0057),
            Some("Associated Channel carries an IPv6 packet")
        );
        assert_eq!(
            ach_channel_type_name(0x000A),
            Some("MPLS Direct Loss Measurement (DLM)")
        );
        assert_eq!(ach_channel_type_name(0x8902), Some("G.8113.1 OAM"));
        assert_eq!(
            ach_channel_type_name(0x7FF9),
            Some("Reserved for Experimental Use")
        );
        assert_eq!(ach_channel_type_name(0x0003), None);
    }

    #[test]
    fn references_and_layer_are_populated() {
        fn check(dissector: &dyn Dissector, layer: ProtocolLayer) {
            let references = dissector.references();
            assert!(!references.is_empty());
            for reference in references {
                assert!(!reference.id.is_empty());
                assert!(reference.url.starts_with("https://"));
            }
            assert_eq!(dissector.layer(), Some(layer));
        }
        check(&MplsDissector, ProtocolLayer::Network);
        check(&AchDissector, ProtocolLayer::Network);
        check(&PwControlWordDissector, ProtocolLayer::Tunnel);
        assert_eq!(AchDissector.short_name(), "ACH");
        assert_eq!(AchDissector.field_descriptors().len(), 3);
        assert_eq!(PwControlWordDissector.short_name(), "PW-CW");
        assert_eq!(PwControlWordDissector.field_descriptors().len(), 5);
    }
}
