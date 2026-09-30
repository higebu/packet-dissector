//! GRE (Generic Routing Encapsulation) dissector.
//!
//! Version 0 follows RFC 2784 / RFC 2890. Packets that set the RFC 1701
//! Routing Present, Strict Source Route or Recursion Control bits are
//! decoded with the RFC 1701 layout, which RFC 2784, Section 2.3 allows
//! for receivers that implement RFC 1701. Version 1 is the Enhanced GRE
//! header used by PPTP (RFC 2637, Section 4.1). Other versions are
//! reported with their base header and end dissection.
//!
//! ## References
//! - RFC 2784: <https://www.rfc-editor.org/rfc/rfc2784>
//! - RFC 2890 (Key and Sequence Number Extensions; updates RFC 2784):
//!   <https://www.rfc-editor.org/rfc/rfc2890>
//! - RFC 9601 (ECN propagation requirement for GRE tunnels; updates RFC 2784):
//!   <https://www.rfc-editor.org/rfc/rfc9601>
//! - RFC 1701 (GRE, Routing and Recursion Control):
//!   <https://www.rfc-editor.org/rfc/rfc1701>
//! - RFC 2637, Section 4.1 (PPTP Enhanced GRE header):
//!   <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
//! - RFC 7637, Section 3.2 (NVGRE VSID and FlowID in the Key field):
//!   <https://www.rfc-editor.org/rfc/rfc7637#section-3.2>

#![deny(missing_docs)]

use packet_dissector_core::checksum::{
    ChecksumStatus, checksum_status_descriptor, verify_ip_payload_checksum,
};
use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Minimum GRE header size (no optional fields).
///
/// RFC 2784, Section 2 — The base header contains only the flags/version
/// word (2 octets) and the Protocol Type field (2 octets).
const MIN_HEADER_SIZE: usize = 4;

/// Mask selecting the RFC 1701 Routing Present, Strict Source Route and
/// Recursion Control bits (bits 1 and 4-7) of the flags word.
///
/// RFC 2784, Section 2.3 — "Receivers MUST discard a packet where any of bits
/// 1-5 are non-zero, unless that receiver implements RFC 1701". RFC 2890
/// reassigns bits 2 and 3 as the K (Key Present) and S (Sequence Number
/// Present) flags. This dissector implements RFC 1701 and decodes bit 1 as
/// Routing Present, bit 4 as Strict Source Route and bits 5-7 as Recursion
/// Control. Bits 6-7 are reserved in RFC 2784 but carry the low bits of
/// Recursion Control, so the RFC 1701 fields are reported whenever any of
/// bits 1 and 4-7 is non-zero.
///
/// RFC 2784, Section 2.3 — <https://www.rfc-editor.org/rfc/rfc2784#section-2.3>
/// RFC 1701 — <https://www.rfc-editor.org/rfc/rfc1701>
const RFC1701_FIELDS_MASK: u16 = 0x4F00;

/// Routing Present (R) flag, bit 1 of the flags word (RFC 1701).
///
/// RFC 1701 — <https://www.rfc-editor.org/rfc/rfc1701>
const ROUTING_PRESENT_FLAG: u16 = 0x4000;

/// GRE version 0 (RFC 2784, Section 2.3.1).
///
/// <https://www.rfc-editor.org/rfc/rfc2784#section-2.3.1>
const VERSION_GRE: u8 = 0;

/// GRE version 1, Enhanced GRE (RFC 2637, Section 4.1 — "Ver (Bits 13-15)
/// Must contain 1 (enhanced GRE).").
///
/// <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
const VERSION_ENHANCED_GRE: u8 = 1;

/// Acknowledgment sequence number present (A) flag, bit 8 of the flags word
/// in Enhanced GRE (RFC 2637, Section 4.1).
///
/// <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
const ENHANCED_GRE_ACK_FLAG: u16 = 0x0080;

/// Protocol Type of Transparent Ethernet Bridging, used by NVGRE
/// (RFC 7637, Section 3.2).
///
/// <https://www.rfc-editor.org/rfc/rfc7637#section-3.2>
const PROTOCOL_TYPE_TEB: u16 = 0x6558;

/// Size of an RFC 1701 Source Route Entry header (Address Family, SRE
/// Offset, SRE Length).
///
/// RFC 1701 — <https://www.rfc-editor.org/rfc/rfc1701>
const SRE_HEADER_SIZE: usize = 4;

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
const FD_ROUTING_PRESENT: usize = 10;
const FD_STRICT_SOURCE_ROUTE: usize = 11;
const FD_RECURSION_CONTROL: usize = 12;
const FD_OFFSET: usize = 13;
const FD_ROUTING: usize = 14;
const FD_ACK_PRESENT: usize = 15;
const FD_PAYLOAD_LENGTH: usize = 16;
const FD_CALL_ID: usize = 17;
const FD_ACK_NUMBER: usize = 18;
const FD_VSID: usize = 19;
const FD_FLOW_ID: usize = 20;
const FD_CHECKSUM_STATUS: usize = 21;

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
    // RFC 1701 fields — present only when one of bits 1, 4-7 is set.
    // https://www.rfc-editor.org/rfc/rfc1701
    FieldDescriptor::new("routing_present", "Routing Present", FieldType::U8).optional(),
    FieldDescriptor::new("strict_source_route", "Strict Source Route", FieldType::U8).optional(),
    FieldDescriptor::new("recursion_control", "Recursion Control", FieldType::U8).optional(),
    FieldDescriptor::new("offset", "Offset", FieldType::U16).optional(),
    FieldDescriptor::new("routing", "Routing", FieldType::Bytes).optional(),
    // RFC 2637, Section 4.1 — Enhanced GRE (version 1) fields.
    // https://www.rfc-editor.org/rfc/rfc2637#section-4.1
    FieldDescriptor::new(
        "acknowledgment_present",
        "Acknowledgment Sequence Number Present",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("payload_length", "Payload Length", FieldType::U16).optional(),
    FieldDescriptor::new("call_id", "Call ID", FieldType::U16).optional(),
    FieldDescriptor::new(
        "acknowledgment_number",
        "Acknowledgment Number",
        FieldType::U32,
    )
    .optional(),
    // RFC 7637, Section 3.2 — NVGRE split of the Key field.
    // https://www.rfc-editor.org/rfc/rfc7637#section-3.2
    FieldDescriptor::new("vsid", "Virtual Subnet ID", FieldType::U32).optional(),
    FieldDescriptor::new("flow_id", "FlowID", FieldType::U8).optional(),
    checksum_status_descriptor("checksum_status", "Checksum Status"),
];

/// GRE dissector.
pub struct GreDissector;

/// Specification references for the GRE dissector.
static REFERENCES: &[SpecReference] = &[
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
    SpecReference::new(
        "RFC 9601",
        "Propagating Explicit Congestion Notification across IP Tunnel Headers Separated by a Shim",
        "https://www.rfc-editor.org/rfc/rfc9601",
    ),
    SpecReference::new(
        "RFC 1701",
        "Generic Routing Encapsulation (GRE)",
        "https://www.rfc-editor.org/rfc/rfc1701",
    ),
    SpecReference::new(
        "RFC 2637",
        "Point-to-Point Tunneling Protocol (PPTP)",
        "https://www.rfc-editor.org/rfc/rfc2637",
    ),
    SpecReference::new(
        "RFC 7637",
        "NVGRE: Network Virtualization Using Generic Routing Encapsulation",
        "https://www.rfc-editor.org/rfc/rfc7637",
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

/// Return the length of the RFC 1701 Routing field (the SRE list including
/// the terminating NULL SRE) that starts at `start`.
///
/// RFC 1701 — "The routing field is terminated with a "NULL" SRE containing
/// an address family of type 0x0000 and a length of 0." and "If the SRE
/// Length is 0, this indicates this is the last SRE in the Routing field."
/// <https://www.rfc-editor.org/rfc/rfc1701>
fn routing_len(data: &[u8], start: usize) -> Result<usize, PacketError> {
    let mut pos = start;
    loop {
        let sre_end = pos + SRE_HEADER_SIZE;
        if data.len() < sre_end {
            return Err(PacketError::Truncated {
                expected: sre_end,
                actual: data.len(),
            });
        }
        // SRE Length (1 octet) follows Address Family (2) and SRE Offset (1).
        let sre_length = data[pos + 3] as usize;
        pos = sre_end + sre_length;
        if data.len() < pos {
            return Err(PacketError::Truncated {
                expected: pos,
                actual: data.len(),
            });
        }
        if sre_length == 0 {
            return Ok(pos - start);
        }
    }
}

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

        // RFC 2784, Section 2 — Flags/version word (first 2 octets)
        // https://www.rfc-editor.org/rfc/rfc2784#section-2
        let flags_ver = read_be_u16(data, 0)?;
        // RFC 2784, Section 2.3.1 — Bits 13-15: Version Number
        // https://www.rfc-editor.org/rfc/rfc2784#section-2.3.1
        let version = (flags_ver & 0x0007) as u8;
        // RFC 2784, Section 2.4 — Protocol Type
        // https://www.rfc-editor.org/rfc/rfc2784#section-2.4
        let protocol_type = read_be_u16(data, 2)?;

        match version {
            VERSION_GRE => dissect_v0(data, buf, offset, flags_ver, protocol_type),
            VERSION_ENHANCED_GRE => dissect_v1(data, buf, offset, flags_ver, protocol_type),
            _ => {
                // RFC 2784, Section 2.3.1 — "The Version Number field MUST
                // contain the value zero." Only version 1 (RFC 2637, Section
                // 4.1) is known besides it. The layout after the base header
                // is unknown, so report the base header and stop.
                // https://www.rfc-editor.org/rfc/rfc2784#section-2.3.1
                // https://www.rfc-editor.org/rfc/rfc2637#section-4.1
                buf.begin_layer(
                    "GRE",
                    None,
                    FIELD_DESCRIPTORS,
                    offset..offset + MIN_HEADER_SIZE,
                );
                push_base_fields(
                    buf,
                    offset,
                    flags_ver,
                    protocol_type,
                    reserved0_bits(flags_ver),
                );
                buf.end_layer();
                Ok(DissectResult::new(MIN_HEADER_SIZE, DispatchHint::End))
            }
        }
    }
}

/// Reserved0: bits 4-12 of the flags/version word (RFC 2890, Section 2).
///
/// <https://www.rfc-editor.org/rfc/rfc2890#section-2>
fn reserved0_bits(flags_ver: u16) -> u16 {
    (flags_ver >> 3) & 0x01FF
}

/// Push the fields of the base header shared by all versions.
fn push_base_fields(
    buf: &mut DissectBuffer<'_>,
    offset: usize,
    flags_ver: u16,
    protocol_type: u16,
    reserved0: u16,
) {
    // RFC 2784, Section 2.1 — Bit 0: Checksum Present (C)
    // https://www.rfc-editor.org/rfc/rfc2784#section-2.1
    push_u8(
        buf,
        FD_CHECKSUM_PRESENT,
        ((flags_ver >> 15) & 1) as u8,
        offset..offset + 1,
    );
    // RFC 2890, Section 2 — Bit 2: Key Present (K)
    // https://www.rfc-editor.org/rfc/rfc2890#section-2
    push_u8(
        buf,
        FD_KEY_PRESENT,
        ((flags_ver >> 13) & 1) as u8,
        offset..offset + 1,
    );
    // RFC 2890, Section 2 — Bit 3: Sequence Number Present (S)
    // https://www.rfc-editor.org/rfc/rfc2890#section-2
    push_u8(
        buf,
        FD_SEQUENCE_NUMBER_PRESENT,
        ((flags_ver >> 12) & 1) as u8,
        offset..offset + 1,
    );
    // RFC 2890, Section 2 — Reserved0 occupies bits 4-12 of the flags word.
    // https://www.rfc-editor.org/rfc/rfc2890#section-2
    push_u16(buf, FD_RESERVED0, reserved0, offset..offset + 2);
    push_u8(
        buf,
        FD_VERSION,
        (flags_ver & 0x0007) as u8,
        offset..offset + 2,
    );
    // RFC 2784, Section 2.4 — Protocol Type
    // https://www.rfc-editor.org/rfc/rfc2784#section-2.4
    push_u16(buf, FD_PROTOCOL_TYPE, protocol_type, offset + 2..offset + 4);
}

/// Dissect a version 0 header (RFC 2784 / RFC 2890, and RFC 1701 when any of
/// bits 1, 4-7 is set).
///
/// - RFC 2784: <https://www.rfc-editor.org/rfc/rfc2784>
/// - RFC 2890: <https://www.rfc-editor.org/rfc/rfc2890>
/// - RFC 1701: <https://www.rfc-editor.org/rfc/rfc1701>
fn dissect_v0<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    flags_ver: u16,
    protocol_type: u16,
) -> Result<DissectResult, PacketError> {
    let c_flag = flags_ver & 0x8000 != 0;
    let k_flag = flags_ver & 0x2000 != 0;
    let s_flag = flags_ver & 0x1000 != 0;
    // RFC 2784, Section 2.3 — bits 1-5 may only be non-zero for RFC 1701.
    // https://www.rfc-editor.org/rfc/rfc2784#section-2.3
    // https://www.rfc-editor.org/rfc/rfc1701
    let rfc1701 = flags_ver & RFC1701_FIELDS_MASK != 0;
    // RFC 1701 — Routing Present (bit 1)
    // https://www.rfc-editor.org/rfc/rfc1701
    let r_flag = flags_ver & ROUTING_PRESENT_FLAG != 0;

    // RFC 1701 — "If either the Checksum Present bit or the Routing Present
    // bit are set, BOTH the Checksum and Offset fields are present in the
    // GRE packet."
    // https://www.rfc-editor.org/rfc/rfc1701
    let mut header_len = MIN_HEADER_SIZE;
    if c_flag || r_flag {
        header_len += 4; // Checksum (2) + Reserved1 / Offset (2)
    }
    if k_flag {
        header_len += 4; // Key (4)
    }
    if s_flag {
        header_len += 4; // Sequence Number (4)
    }
    if data.len() < header_len {
        return Err(PacketError::Truncated {
            expected: header_len,
            actual: data.len(),
        });
    }
    let routing_start = header_len;
    if r_flag {
        header_len += routing_len(data, routing_start)?;
    }

    buf.begin_layer("GRE", None, FIELD_DESCRIPTORS, offset..offset + header_len);
    push_base_fields(
        buf,
        offset,
        flags_ver,
        protocol_type,
        reserved0_bits(flags_ver),
    );

    if rfc1701 {
        // RFC 1701 — Routing Present (bit 1), Strict Source Route (bit 4),
        // Recursion Control (bits 5-7).
        // https://www.rfc-editor.org/rfc/rfc1701
        push_u8(buf, FD_ROUTING_PRESENT, r_flag as u8, offset..offset + 1);
        push_u8(
            buf,
            FD_STRICT_SOURCE_ROUTE,
            ((flags_ver >> 11) & 1) as u8,
            offset..offset + 1,
        );
        push_u8(
            buf,
            FD_RECURSION_CONTROL,
            ((flags_ver >> 8) & 0x07) as u8,
            offset..offset + 1,
        );
    }

    let mut pos = MIN_HEADER_SIZE;

    // RFC 2784, Sections 2.5 & 2.6 — Checksum and Reserved1; RFC 1701 names
    // the second field Offset, valid only when Routing Present is set.
    // https://www.rfc-editor.org/rfc/rfc2784#section-2.5
    // https://www.rfc-editor.org/rfc/rfc2784#section-2.6
    // https://www.rfc-editor.org/rfc/rfc1701
    if c_flag || r_flag {
        let checksum = read_be_u16(data, pos)?;
        let second = read_be_u16(data, pos + 2)?;
        // RFC 1701 — the Checksum "contains valid information only if the
        // Checksum Present bit is set to 1", so it is only shown with C=1.
        // https://www.rfc-editor.org/rfc/rfc1701
        if c_flag {
            push_u16(buf, FD_CHECKSUM, checksum, offset + pos..offset + pos + 2);
        }
        let fd = if r_flag { FD_OFFSET } else { FD_RESERVED1 };
        push_u16(buf, fd, second, offset + pos + 2..offset + pos + 4);
        pos += 4;
    }
    if buf.verify_checksums() {
        // RFC 2784, Section 2.5 — "the Checksum field contains the IP (one's
        // complement) checksum sum of the all the 16 bit words in the GRE
        // header and the payload packet." It is present only with C=1
        // (Section 2.1); otherwise the status sits on the C bit.
        // https://www.rfc-editor.org/rfc/rfc2784#section-2.5
        let (status, range) = if c_flag {
            (
                verify_ip_payload_checksum(buf, offset, data),
                offset + MIN_HEADER_SIZE..offset + MIN_HEADER_SIZE + 2,
            )
        } else {
            (ChecksumStatus::NotPresent, offset..offset + 1)
        };
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM_STATUS],
            status.to_field_value(),
            range,
        );
    }

    // RFC 2890, Section 2.1 — Key
    // https://www.rfc-editor.org/rfc/rfc2890#section-2.1
    if k_flag {
        let key = read_be_u32(data, pos)?;
        push_u32(buf, FD_KEY, key, offset + pos..offset + pos + 4);
        // RFC 7637, Section 3.2 — "The C (Checksum Present) and S (Sequence
        // Number Present) bits in the GRE header MUST be zero." "The K (Key
        // Present) bit in the GRE header MUST be set to one. The 32-bit Key
        // field in the GRE header is used to carry the Virtual Subnet ID
        // (VSID) and the FlowID". Protocol Type is 0x6558.
        // https://www.rfc-editor.org/rfc/rfc7637#section-3.2
        if protocol_type == PROTOCOL_TYPE_TEB && !c_flag && !s_flag {
            push_u32(buf, FD_VSID, key >> 8, offset + pos..offset + pos + 3);
            push_u8(
                buf,
                FD_FLOW_ID,
                (key & 0xFF) as u8,
                offset + pos + 3..offset + pos + 4,
            );
        }
        pos += 4;
    }

    // RFC 2890, Section 2.2 — Sequence Number
    // https://www.rfc-editor.org/rfc/rfc2890#section-2.2
    if s_flag {
        let seq = read_be_u32(data, pos)?;
        push_u32(buf, FD_SEQUENCE_NUMBER, seq, offset + pos..offset + pos + 4);
    }

    // RFC 1701 — Routing (variable): a list of Source Route Entries.
    // https://www.rfc-editor.org/rfc/rfc1701
    if r_flag {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ROUTING],
            FieldValue::Bytes(&data[routing_start..header_len]),
            offset + routing_start..offset + header_len,
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

/// Dissect an Enhanced GRE (version 1) header.
///
/// RFC 2637, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
fn dissect_v1<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    flags_ver: u16,
    protocol_type: u16,
) -> Result<DissectResult, PacketError> {
    let c_flag = flags_ver & 0x8000 != 0;
    let k_flag = flags_ver & 0x2000 != 0;
    let s_flag = flags_ver & 0x1000 != 0;
    // RFC 2637, Section 4.1 — "A (Bit 8) Acknowledgment sequence number
    // present."
    // https://www.rfc-editor.org/rfc/rfc2637#section-4.1
    let a_flag = flags_ver & ENHANCED_GRE_ACK_FLAG != 0;

    let mut header_len = MIN_HEADER_SIZE;
    if c_flag {
        header_len += 4; // Checksum (2) + Reserved1 (2)
    }
    if k_flag {
        header_len += 4; // Payload Length (2) + Call ID (2)
    }
    if s_flag {
        header_len += 4; // Sequence Number (4)
    }
    if a_flag {
        header_len += 4; // Acknowledgment Number (4)
    }
    if data.len() < header_len {
        return Err(PacketError::Truncated {
            expected: header_len,
            actual: data.len(),
        });
    }

    buf.begin_layer("GRE", None, FIELD_DESCRIPTORS, offset..offset + header_len);
    // RFC 2637, Section 4.1 — bits 4-12 without the A flag: s, Recur and
    // Flags, all "Set to zero (0)".
    // https://www.rfc-editor.org/rfc/rfc2637#section-4.1
    let reserved0 = reserved0_bits(flags_ver & !ENHANCED_GRE_ACK_FLAG);
    push_base_fields(buf, offset, flags_ver, protocol_type, reserved0);
    push_u8(buf, FD_ACK_PRESENT, a_flag as u8, offset + 1..offset + 2);
    // RFC 2637, Section 4.1 — "R (Bit 1) Routing Present. Set to zero (0)."
    // A set R bit is reported so the violation is visible; no Routing field
    // is parsed.
    // https://www.rfc-editor.org/rfc/rfc2637#section-4.1
    if flags_ver & ROUTING_PRESENT_FLAG != 0 {
        push_u8(buf, FD_ROUTING_PRESENT, 1, offset..offset + 1);
    }

    let mut pos = MIN_HEADER_SIZE;

    // RFC 2637, Section 4.1 — "C (Bit 0) Checksum Present. Set to zero (0)."
    // A set C bit still announces the RFC 2784 Checksum and Reserved1 fields.
    // https://www.rfc-editor.org/rfc/rfc2637#section-4.1
    // https://www.rfc-editor.org/rfc/rfc2784#section-2.5
    if c_flag {
        let checksum = read_be_u16(data, pos)?;
        let reserved1 = read_be_u16(data, pos + 2)?;
        push_u16(buf, FD_CHECKSUM, checksum, offset + pos..offset + pos + 2);
        push_u16(
            buf,
            FD_RESERVED1,
            reserved1,
            offset + pos + 2..offset + pos + 4,
        );
        pos += 4;
    }

    // RFC 2637, Section 4.1 — Key: "Payload Length (High 2 octets of Key)
    // Size of the payload, not including the GRE header" and "Call ID (Low 2
    // octets) Contains the Peer's Call ID for the session to which this
    // packet belongs."
    // https://www.rfc-editor.org/rfc/rfc2637#section-4.1
    let mut payload_length = None;
    if k_flag {
        let len = read_be_u16(data, pos)?;
        let call_id = read_be_u16(data, pos + 2)?;
        push_u16(buf, FD_PAYLOAD_LENGTH, len, offset + pos..offset + pos + 2);
        push_u16(buf, FD_CALL_ID, call_id, offset + pos + 2..offset + pos + 4);
        payload_length = Some(len);
        pos += 4;
    }

    // RFC 2637, Section 4.1 — "Sequence Number ... Present if S bit (Bit 3)
    // is one (1)."
    // https://www.rfc-editor.org/rfc/rfc2637#section-4.1
    if s_flag {
        let seq = read_be_u32(data, pos)?;
        push_u32(buf, FD_SEQUENCE_NUMBER, seq, offset + pos..offset + pos + 4);
        pos += 4;
    }

    // RFC 2637, Section 4.1 — "Acknowledgment Number ... Present if A bit
    // (Bit 8) is one (1)."
    // https://www.rfc-editor.org/rfc/rfc2637#section-4.1
    if a_flag {
        let ack = read_be_u32(data, pos)?;
        push_u32(buf, FD_ACK_NUMBER, ack, offset + pos..offset + pos + 4);
    }

    buf.end_layer();

    // RFC 2637, Section 4.1 — S is "Set to zero (0) if payload is not present
    // (GRE packet is an Acknowledgment only)". "The payload section contains
    // a PPP data packet without any media specific framing elements."
    // https://www.rfc-editor.org/rfc/rfc2637#section-4.1
    // A set R bit ("Set to zero (0)") would add Routing fields whose
    // position RFC 2637 does not define, so the payload offset is unknown
    // and nothing is dispatched.
    let r_flag = flags_ver & ROUTING_PRESENT_FLAG != 0;
    match payload_length {
        Some(len) if s_flag && len > 0 && !r_flag => Ok(DissectResult::new(
            header_len,
            DispatchHint::ByEtherType(protocol_type),
        )
        .with_payload_len(len as usize)),
        _ => Ok(DissectResult::new(header_len, DispatchHint::End)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 2784 / RFC 2890 / RFC 1701 / RFC 2637 / RFC 7637 (GRE) Coverage
    //
    // RFC 1701 has no numbered sections; its rows cite the header-format
    // text of the document.
    //
    // | RFC Section  | Description                          | Test                                                |
    // |--------------|--------------------------------------|-----------------------------------------------------|
    // | 2784 §2      | Base header format                   | parse_gre_basic                                     |
    // | 2784 §2      | Byte ranges honour the offset        | parse_gre_with_offset                               |
    // | 2784 §2.3    | Reserved0 bits 6-12 ignored          | parse_gre_reserved_bits_6_to_12                     |
    // | 2784 §2.3.1  | Unknown version reported, not error  | parse_gre_unknown_version                           |
    // | 2784 §2.4    | Protocol Type dispatch (IPv6)        | parse_gre_dispatch_ipv6                             |
    // | 2784 §2.5    | Checksum present                     | parse_gre_with_checksum                             |
    // | 2784 §2.6    | Reserved1 present                    | parse_gre_with_checksum                             |
    // | 2890 §2.1    | Key present                          | parse_gre_with_key                                  |
    // | 2890 §2.2    | Sequence Number present              | parse_gre_with_sequence_number                      |
    // | 2784 + 2890  | All optional fields                  | parse_gre_all_options                               |
    // | 2784 §2      | Truncated base header                | parse_gre_truncated                                 |
    // | 2784 §2      | Truncated optional fields            | parse_gre_truncated_optional_fields                 |
    // | 2784 §2.3    | Bit 1 accepted as RFC 1701 R         | parse_gre_rfc1701_routing                           |
    // | 1701         | Routing Present, Offset, SRE list    | parse_gre_rfc1701_routing                           |
    // | 1701         | Routing after Key / Sequence Number  | parse_gre_rfc1701_routing_after_key_and_sequence    |
    // | 1701         | Strict Source Route, Recursion       | parse_gre_rfc1701_strict_source_route_and_recursion |
    // | 1701         | Recursion Control bit 5              | parse_gre_rfc1701_recursion_bit5                    |
    // | 1701         | Recursion Control bits 6-7           | parse_gre_reserved_bits_6_to_12                     |
    // | 1701         | Unterminated / truncated SRE list    | parse_gre_rfc1701_routing_unterminated              |
    // | 1701         | Truncated SRE header                 | parse_gre_rfc1701_routing_missing_sre               |
    // | 2637 §4.1    | Enhanced GRE data + ack              | parse_gre_v1_data_with_ack                          |
    // | 2637 §4.1    | Enhanced GRE ack only (S=0)          | parse_gre_v1_ack_only                               |
    // | 2637 §4.1    | Enhanced GRE data without ack        | parse_gre_v1_data_without_ack                       |
    // | 2637 §4.1    | S=1 with zero Payload Length         | parse_gre_v1_sequence_with_zero_payload_length      |
    // | 2637 §4.1    | Neither S nor A set                  | parse_gre_v1_no_sequence_no_ack                     |
    // | 2637 §4.1    | K=0 (violates K "Set to one")        | parse_gre_v1_without_key                            |
    // | 2637 §4.1    | R=1 reported (violates "Set to zero")| parse_gre_v1_routing_present_reported               |
    // | 2637 §4.1    | Truncated Acknowledgment Number      | parse_gre_v1_truncated_ack                          |
    // | 2637 §4.1    | C=1 in Enhanced GRE                  | parse_gre_v1_with_checksum                          |
    // | 7637 §3.2    | NVGRE VSID / FlowID                  | parse_gre_nvgre_key_split                           |
    // | 7637 §3.2    | Key not split outside NVGRE          | parse_gre_key_not_split_outside_nvgre               |
    // | 7637 §3.2    | NVGRE split with reserved bits 6-7   | parse_gre_nvgre_key_split_with_reserved_bits        |

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

    /// RFC 2784, Section 2.3.1 — versions other than 0 (GRE) and 1
    /// (Enhanced GRE, RFC 2637) are unknown. The layer is still reported
    /// with its flags and version, and dissection ends there.
    /// <https://www.rfc-editor.org/rfc/rfc2784#section-2.3.1>
    /// <https://www.rfc-editor.org/rfc/rfc2637>
    #[test]
    fn parse_gre_unknown_version() {
        let raw: &[u8] = &[
            0x00, 0x07, // Version = 7
            0x08, 0x00, // Protocol Type: IPv4
            0xAA, 0xBB, // trailing bytes, not interpreted
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(layer.range, 0..4);
        assert_eq!(buf.field_u8(layer, "version"), Some(7));
        assert_eq!(buf.field_u16(layer, "protocol_type"), Some(0x0800));
        assert!(buf.field_by_name(layer, "key").is_none());
    }

    /// RFC 2637, Section 4.1 — Enhanced GRE data packet with a piggy-backed
    /// acknowledgment (K=1, S=1, A=1, Ver=1).
    /// <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
    #[test]
    fn parse_gre_v1_data_with_ack() {
        let raw: &[u8] = &[
            0x30, 0x81, // K=1 S=1 A=1, ver=1
            0x88, 0x0B, // Protocol Type: PPP
            0x00, 0x0A, // Payload Length = 10
            0x00, 0x2A, // Call ID = 42
            0x00, 0x00, 0x00, 0x01, // Sequence Number = 1
            0x00, 0x00, 0x00, 0x00, // Acknowledgment Number = 0
            0xC0, 0x21, 0x0B, 0x01, 0x00, 0x08, // PPP LCP Discard-Request
            0x00, 0x00, 0x00, 0x00, // magic number
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 16);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x880B));
        assert_eq!(result.payload_len, Some(10));

        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(layer.range, 0..16);
        assert_eq!(buf.field_u8(layer, "checksum_present"), Some(0));
        assert_eq!(buf.field_u8(layer, "key_present"), Some(1));
        assert_eq!(buf.field_u8(layer, "sequence_number_present"), Some(1));
        assert_eq!(buf.field_u8(layer, "acknowledgment_present"), Some(1));
        assert_eq!(buf.field_u16(layer, "reserved0"), Some(0));
        assert_eq!(buf.field_u8(layer, "version"), Some(1));
        assert_eq!(buf.field_u16(layer, "protocol_type"), Some(0x880B));
        assert_eq!(buf.field_u16(layer, "payload_length"), Some(10));
        assert_eq!(buf.field_u16(layer, "call_id"), Some(42));
        assert_eq!(buf.field_u32(layer, "sequence_number"), Some(1));
        assert_eq!(buf.field_u32(layer, "acknowledgment_number"), Some(0));
        assert!(buf.field_by_name(layer, "key").is_none());
        assert_eq!(
            buf.field_by_name(layer, "payload_length").unwrap().range,
            4..6
        );
        assert_eq!(buf.field_by_name(layer, "call_id").unwrap().range, 6..8);
        assert_eq!(
            buf.field_by_name(layer, "acknowledgment_number")
                .unwrap()
                .range,
            12..16
        );
    }

    /// RFC 2637, Section 4.1 — acknowledgment-only packet (S=0, A=1): no
    /// payload, so dissection ends at GRE.
    /// <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
    #[test]
    fn parse_gre_v1_ack_only() {
        let raw: &[u8] = &[
            0x20, 0x81, // K=1 A=1, ver=1
            0x88, 0x0B, // Protocol Type: PPP
            0x00, 0x00, // Payload Length = 0
            0x00, 0x2A, // Call ID = 42
            0x00, 0x00, 0x00, 0x05, // Acknowledgment Number = 5
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 12);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(buf.field_u8(layer, "sequence_number_present"), Some(0));
        assert_eq!(buf.field_u16(layer, "payload_length"), Some(0));
        assert_eq!(buf.field_u16(layer, "call_id"), Some(42));
        assert_eq!(buf.field_u32(layer, "acknowledgment_number"), Some(5));
        assert!(buf.field_by_name(layer, "sequence_number").is_none());
        assert_eq!(
            buf.field_by_name(layer, "acknowledgment_number")
                .unwrap()
                .range,
            8..12
        );
    }

    /// RFC 2637, Section 4.1 — data packet without an acknowledgment (A=0).
    /// <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
    #[test]
    fn parse_gre_v1_data_without_ack() {
        let raw: &[u8] = &[
            0x30, 0x01, // K=1 S=1, ver=1
            0x88, 0x0B, // Protocol Type: PPP
            0x00, 0x04, // Payload Length = 4
            0x12, 0x34, // Call ID
            0x00, 0x00, 0x00, 0x07, // Sequence Number = 7
            0x00, 0x21, 0x45, 0x00, // PPP payload
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 12);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x880B));
        assert_eq!(result.payload_len, Some(4));

        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(buf.field_u8(layer, "acknowledgment_present"), Some(0));
        assert_eq!(buf.field_u16(layer, "call_id"), Some(0x1234));
        assert_eq!(buf.field_u32(layer, "sequence_number"), Some(7));
        assert!(buf.field_by_name(layer, "acknowledgment_number").is_none());
    }

    /// RFC 2637, Section 4.1 — S=1 with a zero Payload Length carries no
    /// payload to dispatch.
    /// <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
    #[test]
    fn parse_gre_v1_sequence_with_zero_payload_length() {
        let raw: &[u8] = &[
            0x30, 0x01, // K=1 S=1, ver=1
            0x88, 0x0B, // Protocol Type: PPP
            0x00, 0x00, // Payload Length = 0
            0x00, 0x01, // Call ID
            0x00, 0x00, 0x00, 0x02, // Sequence Number
        ];
        let (_, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 12);
        assert_eq!(result.next, DispatchHint::End);
    }

    /// RFC 2637, Section 4.1 — malformed v1 header with neither S nor A
    /// set: no payload and no acknowledgment. Must not panic.
    /// <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
    #[test]
    fn parse_gre_v1_no_sequence_no_ack() {
        let raw: &[u8] = &[
            0x20, 0x01, // K=1, ver=1
            0x88, 0x0B, // Protocol Type: PPP
            0x00, 0x00, // Payload Length = 0
            0x00, 0x2A, // Call ID = 42
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::End);
        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(buf.field_u16(layer, "call_id"), Some(42));
    }

    /// RFC 2637, Section 4.1 — Enhanced GRE without K=1 has no Payload
    /// Length / Call ID, so nothing can be dispatched.
    /// <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
    #[test]
    fn parse_gre_v1_without_key() {
        let raw: &[u8] = &[
            0x10, 0x01, // S=1, ver=1 (K=0 violates RFC 2637)
            0x88, 0x0B, // Protocol Type: PPP
            0x00, 0x00, 0x00, 0x03, // Sequence Number = 3
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::End);
        let layer = buf.layer_by_name("GRE").unwrap();
        assert!(buf.field_by_name(layer, "payload_length").is_none());
        assert_eq!(buf.field_u32(layer, "sequence_number"), Some(3));
    }

    /// RFC 2637, Section 4.1 — "R (Bit 1) Routing Present. Set to zero
    /// (0)." A set R bit is reported, but no Routing field is parsed.
    /// <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
    #[test]
    fn parse_gre_v1_routing_present_reported() {
        let raw: &[u8] = &[
            0x70, 0x01, // R=1 K=1 S=1, ver=1
            0x88, 0x0B, // Protocol Type: PPP
            0x00, 0x04, 0x00, 0x2A, // Payload Length 4, Call ID
            0x00, 0x00, 0x00, 0x01, // Sequence Number
            0x00, 0x00, 0x00, 0x00, // unknown (Routing?) then payload
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 12);
        // The layout after the header is undefined with R=1, so the payload
        // is not dispatched.
        assert_eq!(result.next, DispatchHint::End);
        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(buf.field_u8(layer, "routing_present"), Some(1));
        assert!(buf.field_by_name(layer, "routing").is_none());

        let without_r: &[u8] = &[0x20, 0x01, 0x88, 0x0B, 0x00, 0x00, 0x00, 0x2A];
        let (buf, _) = dissect(without_r).unwrap();
        let layer = buf.layer_by_name("GRE").unwrap();
        assert!(buf.field_by_name(layer, "routing_present").is_none());
    }

    /// RFC 2637, Section 4.1 — the Acknowledgment Number is counted in the
    /// header length, so a missing one is a truncation.
    /// <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
    #[test]
    fn parse_gre_v1_truncated_ack() {
        let raw: &[u8] = &[
            0x30, 0x81, // K=1 S=1 A=1, ver=1
            0x88, 0x0B, // Protocol Type: PPP
            0x00, 0x00, 0x00, 0x2A, // Payload Length, Call ID
            0x00, 0x00, 0x00, 0x01, // Sequence Number
            0x00, 0x00, // Acknowledgment Number (truncated)
        ];
        let err = GreDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 16,
                actual: 14
            }
        ));
    }

    /// RFC 2637, Section 4.1 — C "Set to zero (0)" in Enhanced GRE, but a
    /// set C bit still announces the Checksum and Reserved1 fields.
    /// <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
    #[test]
    fn parse_gre_v1_with_checksum() {
        let raw: &[u8] = &[
            0xA0, 0x01, // C=1 K=1, ver=1
            0x88, 0x0B, // Protocol Type: PPP
            0xAB, 0xCD, 0x00, 0x00, // Checksum, Reserved1
            0x00, 0x00, 0x00, 0x2A, // Payload Length, Call ID
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 12);
        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(buf.field_u16(layer, "checksum"), Some(0xABCD));
        assert_eq!(buf.field_u16(layer, "call_id"), Some(42));
        assert_eq!(buf.field_by_name(layer, "call_id").unwrap().range, 10..12);
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
    /// This dissector implements RFC 1701, where bit 1 is Routing Present:
    /// the Checksum and Offset fields and a list of Source Route Entries
    /// terminated by a NULL SRE follow.
    /// <https://www.rfc-editor.org/rfc/rfc2784#section-2.3>
    /// <https://www.rfc-editor.org/rfc/rfc1701>
    #[test]
    fn parse_gre_rfc1701_routing() {
        let raw: &[u8] = &[
            0x40, 0x00, // R=1
            0x08, 0x00, // Protocol Type: IPv4
            0x00, 0x00, // Checksum (not valid, C=0)
            0x00, 0x04, // Offset = 4
            0x08, 0x00, 0x00, 0x04, // SRE: AF IPv4, SRE Offset 0, SRE Length 4
            0x0A, 0x00, 0x00, 0x01, // Routing Information: 10.0.0.1
            0x00, 0x00, 0x00, 0x00, // NULL SRE
            0x45, 0x00, // payload
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 20);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(layer.range, 0..20);
        assert_eq!(buf.field_u8(layer, "routing_present"), Some(1));
        assert_eq!(buf.field_u8(layer, "strict_source_route"), Some(0));
        assert_eq!(buf.field_u8(layer, "recursion_control"), Some(0));
        // RFC 1701 — the Checksum field "contains valid information only if
        // the Checksum Present bit is set to 1", so with C=0 it is not shown.
        // https://www.rfc-editor.org/rfc/rfc1701
        assert!(buf.field_by_name(layer, "checksum").is_none());
        assert_eq!(buf.field_u16(layer, "offset"), Some(4));
        assert!(buf.field_by_name(layer, "reserved1").is_none());
        let routing = buf.field_by_name(layer, "routing").unwrap();
        assert_eq!(routing.range, 8..20);
        assert_eq!(
            routing.value,
            FieldValue::Bytes(&[
                0x08, 0x00, 0x00, 0x04, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
            ])
        );
    }

    /// RFC 1701 — Routing follows the Key and Sequence Number fields.
    /// <https://www.rfc-editor.org/rfc/rfc1701>
    #[test]
    fn parse_gre_rfc1701_routing_after_key_and_sequence() {
        let raw: &[u8] = &[
            0x70, 0x00, // R=1 K=1 S=1
            0x86, 0xDD, // Protocol Type: IPv6
            0x00, 0x00, 0x00, 0x00, // Checksum, Offset
            0x00, 0x00, 0x00, 0x09, // Key
            0x00, 0x00, 0x00, 0x02, // Sequence Number
            0x00, 0x00, 0x00, 0x00, // NULL SRE
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 20);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(buf.field_u32(layer, "key"), Some(9));
        assert_eq!(buf.field_u32(layer, "sequence_number"), Some(2));
        assert_eq!(buf.field_by_name(layer, "routing").unwrap().range, 16..20);
    }

    /// RFC 1701 — bit 4 is Strict Source Route and bits 5-7 are Recursion
    /// Control. Without R=1 neither Offset nor Routing is present.
    /// <https://www.rfc-editor.org/rfc/rfc1701>
    #[test]
    fn parse_gre_rfc1701_strict_source_route_and_recursion() {
        // byte 0 = 0000 1111: s=1, Recur=0b111
        let raw: &[u8] = &[0x0F, 0x00, 0x08, 0x00];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(buf.field_u8(layer, "routing_present"), Some(0));
        assert_eq!(buf.field_u8(layer, "strict_source_route"), Some(1));
        assert_eq!(buf.field_u8(layer, "recursion_control"), Some(7));
        assert!(buf.field_by_name(layer, "offset").is_none());
        assert!(buf.field_by_name(layer, "routing").is_none());
        // reserved0 still exposes the raw bits 4-12.
        assert_eq!(buf.field_u16(layer, "reserved0"), Some(0x1E0));
    }

    /// RFC 1701 — only bit 5 (the top bit of Recursion Control) set.
    /// <https://www.rfc-editor.org/rfc/rfc1701>
    #[test]
    fn parse_gre_rfc1701_recursion_bit5() {
        let raw: &[u8] = &[0x04, 0x00, 0x08, 0x00];
        let (buf, _) = dissect(raw).unwrap();
        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(buf.field_u8(layer, "strict_source_route"), Some(0));
        assert_eq!(buf.field_u8(layer, "recursion_control"), Some(4));
    }

    /// RFC 1701 — a Routing field that is not terminated by a NULL SRE
    /// within the data is truncated.
    /// <https://www.rfc-editor.org/rfc/rfc1701>
    #[test]
    fn parse_gre_rfc1701_routing_unterminated() {
        let raw: &[u8] = &[
            0x40, 0x00, // R=1
            0x08, 0x00, // Protocol Type: IPv4
            0x00, 0x00, 0x00, 0x00, // Checksum, Offset
            0x08, 0x00, 0x00, 0x04, // SRE with 4 octets of Routing Information
            0x0A, 0x00, // truncated Routing Information
        ];
        let err = GreDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 16,
                actual: 14
            }
        ));
    }

    /// RFC 1701 — a missing SRE header is truncated too.
    /// <https://www.rfc-editor.org/rfc/rfc1701>
    #[test]
    fn parse_gre_rfc1701_routing_missing_sre() {
        let raw: &[u8] = &[
            0x40, 0x00, // R=1
            0x08, 0x00, // Protocol Type: IPv4
            0x00, 0x00, 0x00, 0x00, // Checksum, Offset
            0x00, 0x00, // partial SRE header
        ];
        let err = GreDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 12,
                actual: 10
            }
        ));
    }

    /// RFC 7637, Section 3.2 — NVGRE carries the VSID (upper 24 bits) and
    /// FlowID (lower 8 bits) in the Key field of a Transparent Ethernet
    /// Bridging (0x6558) packet with C=0, K=1, S=0.
    /// <https://www.rfc-editor.org/rfc/rfc7637#section-3.2>
    #[test]
    fn parse_gre_nvgre_key_split() {
        let raw: &[u8] = &[
            0x20, 0x00, // K=1
            0x65, 0x58, // Protocol Type: Transparent Ethernet Bridging
            0x00, 0x00, 0x64, 0x01, // VSID 100, FlowID 1
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x6558));
        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(buf.field_u32(layer, "key"), Some(0x6401));
        assert_eq!(buf.field_u32(layer, "vsid"), Some(100));
        assert_eq!(buf.field_u8(layer, "flow_id"), Some(1));
        assert_eq!(buf.field_by_name(layer, "vsid").unwrap().range, 4..7);
        assert_eq!(buf.field_by_name(layer, "flow_id").unwrap().range, 7..8);
    }

    /// RFC 7637, Section 3.2 only requires C=0, K=1 and S=0; reserved bits 6-7
    /// ("MUST be ignored on receipt", RFC 2784, Section 2.3) do not stop the
    /// NVGRE split.
    /// <https://www.rfc-editor.org/rfc/rfc7637#section-3.2>
    /// <https://www.rfc-editor.org/rfc/rfc2784#section-2.3>
    #[test]
    fn parse_gre_nvgre_key_split_with_reserved_bits() {
        let raw: &[u8] = &[
            0x22, 0x00, // K=1, bit 6 set
            0x65, 0x58, // Protocol Type: Transparent Ethernet Bridging
            0x00, 0x00, 0x64, 0x01, // VSID 100, FlowID 1
        ];
        let (buf, _) = dissect(raw).unwrap();
        let layer = buf.layer_by_name("GRE").unwrap();
        assert_eq!(buf.field_u32(layer, "vsid"), Some(100));
        assert_eq!(buf.field_u8(layer, "flow_id"), Some(1));
    }

    /// RFC 7637, Section 3.2 — the Key is not split for other protocol
    /// types, or when C or S is set (NVGRE requires both to be zero).
    /// <https://www.rfc-editor.org/rfc/rfc7637#section-3.2>
    #[test]
    fn parse_gre_key_not_split_outside_nvgre() {
        let ipv4: &[u8] = &[0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, 0x01];
        let (buf, _) = dissect(ipv4).unwrap();
        let layer = buf.layer_by_name("GRE").unwrap();
        assert!(buf.field_by_name(layer, "vsid").is_none());
        assert!(buf.field_by_name(layer, "flow_id").is_none());

        let with_seq: &[u8] = &[
            0x30, 0x00, 0x65, 0x58, 0x00, 0x00, 0x64, 0x01, 0x00, 0x00, 0x00, 0x01,
        ];
        let (buf, _) = dissect(with_seq).unwrap();
        let layer = buf.layer_by_name("GRE").unwrap();
        assert!(buf.field_by_name(layer, "vsid").is_none());
    }

    /// RFC 2784, Section 2.3: "Bits 6-12 are reserved for future use. These
    /// bits MUST be sent as zero and MUST be ignored on receipt." The
    /// dissector must accept such packets and expose the received bits via
    /// the `reserved0` field.
    /// <https://www.rfc-editor.org/rfc/rfc2784#section-2.3>
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
        // Bits 6-7 are the low bits of RFC 1701 Recursion Control.
        // https://www.rfc-editor.org/rfc/rfc1701
        assert_eq!(buf.field_u8(layer, "recursion_control"), Some(3));
        assert_eq!(buf.field_u8(layer, "routing_present"), Some(0));
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
        assert_eq!(descs.len(), 21);
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
        assert_eq!(descs[FD_ROUTING_PRESENT].name, "routing_present");
        assert_eq!(descs[FD_STRICT_SOURCE_ROUTE].name, "strict_source_route");
        assert_eq!(descs[FD_RECURSION_CONTROL].name, "recursion_control");
        assert_eq!(descs[FD_OFFSET].name, "offset");
        assert_eq!(descs[FD_ROUTING].name, "routing");
        assert_eq!(descs[FD_ACK_PRESENT].name, "acknowledgment_present");
        assert_eq!(descs[FD_PAYLOAD_LENGTH].name, "payload_length");
        assert_eq!(descs[FD_CALL_ID].name, "call_id");
        assert_eq!(descs[FD_ACK_NUMBER].name, "acknowledgment_number");
        assert_eq!(descs[FD_VSID].name, "vsid");
        assert_eq!(descs[FD_FLOW_ID].name, "flow_id");
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

        assert_layer_and_references(&GreDissector);
    }
}
