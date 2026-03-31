//! IPv6 Extension Header dissectors.
//!
//! ## References
//! - RFC 8200, Section 4: <https://www.rfc-editor.org/rfc/rfc8200#section-4>
//!   - Section 4.3: Hop-by-Hop Options Header
//!   - Section 4.4: Routing Header
//!   - Section 4.5: Fragment Header
//!   - Section 4.6: Destination Options Header
//! - RFC 9673 (updates RFC 8200 Hop-by-Hop processing procedures): <https://www.rfc-editor.org/rfc/rfc9673>
//! - RFC 6275, Section 6.1: Mobility Header: <https://www.rfc-editor.org/rfc/rfc6275#section-6.1>

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Minimum size for Hop-by-Hop / Destination Options / Routing fixed fields.
const TLV_HEADER_MIN: usize = 2;

/// Fragment Header is always 8 bytes.
const FRAGMENT_HEADER_SIZE: usize = 8;

/// Minimum Routing Header fixed fields (Next Header, Hdr Ext Len, Routing Type, Segments Left).
const ROUTING_FIXED_SIZE: usize = 4;

/// Mobility Header fixed fields: Payload Proto, Header Len, MH Type, Reserved, Checksum.
const MH_FIXED_SIZE: usize = 6;

// --- Hop-by-Hop Options (Section 4.3) ---

/// Hop-by-Hop Options Header dissector.
///
/// RFC 8200, Section 4.3: Carries optional information that must be
/// examined by every node along a packet's delivery path.
pub struct HopByHopDissector;

/// Field descriptors shared by TLV-style extension headers (Hop-by-Hop and Destination Options).
static TLV_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("next_header", "Next Header", FieldType::U8),
    FieldDescriptor::new("hdr_ext_len", "Header Extension Length", FieldType::U8),
    FieldDescriptor::new("options", "Options", FieldType::Bytes).optional(),
];

impl Dissector for HopByHopDissector {
    fn name(&self) -> &'static str {
        "IPv6 Hop-by-Hop Options Header"
    }

    fn short_name(&self) -> &'static str {
        "IPv6 Hop-by-Hop"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        TLV_FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        dissect_tlv_ext_header(data, buf, offset, "IPv6 Hop-by-Hop")
    }
}

// --- Destination Options (Section 4.6) ---

/// Destination Options Header dissector.
///
/// RFC 8200, Section 4.6: Carries optional information that needs to be
/// examined only by the packet's destination node(s).
pub struct DestinationOptionsDissector;

impl Dissector for DestinationOptionsDissector {
    fn name(&self) -> &'static str {
        "IPv6 Destination Options Header"
    }

    fn short_name(&self) -> &'static str {
        "IPv6 Destination Options"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        TLV_FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        dissect_tlv_ext_header(data, buf, offset, "IPv6 Destination Options")
    }
}

/// Shared parsing logic for TLV-style extension headers (Hop-by-Hop and Destination Options).
///
/// RFC 8200, Sections 4.3/4.6:
/// - Next Header: 8 bits
/// - Hdr Ext Len: 8 bits (length in 8-octet units, not including first 8 octets)
/// - Options: variable length, TLV-encoded
fn dissect_tlv_ext_header<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    name: &'static str,
) -> Result<DissectResult, PacketError> {
    if data.len() < TLV_HEADER_MIN {
        return Err(PacketError::Truncated {
            expected: TLV_HEADER_MIN,
            actual: data.len(),
        });
    }

    let next_header = data[0];
    let hdr_ext_len = data[1];
    // RFC 8200, Section 4.3 — total length = (Hdr Ext Len + 1) * 8
    let total_len = (hdr_ext_len as usize + 1) * 8;

    if data.len() < total_len {
        return Err(PacketError::Truncated {
            expected: total_len,
            actual: data.len(),
        });
    }

    buf.begin_layer(
        name,
        None,
        TLV_FIELD_DESCRIPTORS,
        offset..offset + total_len,
    );

    buf.push_field(
        &TLV_FIELD_DESCRIPTORS[0],
        FieldValue::U8(next_header),
        offset..offset + 1,
    );
    buf.push_field(
        &TLV_FIELD_DESCRIPTORS[1],
        FieldValue::U8(hdr_ext_len),
        offset + 1..offset + 2,
    );

    // RFC 8200, Section 4.2 — Options are TLV-encoded after the 2-byte fixed header
    if total_len > TLV_HEADER_MIN {
        buf.push_field(
            &TLV_FIELD_DESCRIPTORS[2],
            FieldValue::Bytes(&data[TLV_HEADER_MIN..total_len]),
            offset + TLV_HEADER_MIN..offset + total_len,
        );
    }

    buf.end_layer();

    Ok(DissectResult::new(
        total_len,
        DispatchHint::ByIpProtocol(next_header),
    ))
}

// --- Routing Header (Section 4.4) ---

/// Routing Header dispatcher.
///
/// RFC 8200, Section 4.4: Used by an IPv6 source to list one or more
/// intermediate nodes to be "visited" on the way to a packet's destination.
///
/// This is a thin dispatcher registered at IP protocol 43. It peeks at the
/// Routing Type field and returns [`DispatchHint::ByIpv6RoutingType`] so the
/// registry can delegate to a type-specific dissector (e.g. SRv6 for type 4)
/// or fall back to [`GenericRoutingDissector`].
pub struct RoutingDissector;

/// Minimum bytes needed to read Next Header, Hdr Ext Len, and Routing Type.
const ROUTING_DISPATCH_MIN: usize = 3;

impl Dissector for RoutingDissector {
    fn name(&self) -> &'static str {
        "IPv6 Routing Header"
    }

    fn short_name(&self) -> &'static str {
        "IPv6 Routing"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        // This is a thin dispatcher; it does not produce any fields itself.
        &[]
    }

    fn dissect(
        &self,
        data: &[u8],
        _buf: &mut DissectBuffer,
        _offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < ROUTING_DISPATCH_MIN {
            return Err(PacketError::Truncated {
                expected: ROUTING_DISPATCH_MIN,
                actual: data.len(),
            });
        }

        // RFC 8200, Section 4.4 — Routing Type is at byte offset 2.
        // bytes_consumed is 0 because this is a thin dispatcher: the
        // type-specific dissector (e.g. SRv6Dissector) or the
        // GenericRoutingDissector will parse and consume the full header.
        let routing_type = data[2];

        Ok(DissectResult::new(
            0,
            DispatchHint::ByIpv6RoutingType(routing_type),
        ))
    }
}

/// Generic Routing Header dissector (fallback for unrecognised Routing Types).
///
/// Parses the common Routing Header fields and stores type-specific data as
/// raw bytes. Registered as the routing fallback in `DissectorRegistry`.
pub struct GenericRoutingDissector;

static GENERIC_ROUTING_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("next_header", "Next Header", FieldType::U8),
    FieldDescriptor::new("hdr_ext_len", "Header Extension Length", FieldType::U8),
    FieldDescriptor::new("routing_type", "Routing Type", FieldType::U8),
    FieldDescriptor::new("segments_left", "Segments Left", FieldType::U8),
    FieldDescriptor::new("data", "Type-Specific Data", FieldType::Bytes).optional(),
];

impl Dissector for GenericRoutingDissector {
    fn name(&self) -> &'static str {
        "IPv6 Routing Header"
    }

    fn short_name(&self) -> &'static str {
        "IPv6 Routing"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        GENERIC_ROUTING_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < ROUTING_FIXED_SIZE {
            return Err(PacketError::Truncated {
                expected: ROUTING_FIXED_SIZE,
                actual: data.len(),
            });
        }

        let next_header = data[0];
        let hdr_ext_len = data[1];
        // RFC 8200, Section 4.4 — total length = (Hdr Ext Len + 1) * 8
        let total_len = (hdr_ext_len as usize + 1) * 8;

        if data.len() < total_len {
            return Err(PacketError::Truncated {
                expected: total_len,
                actual: data.len(),
            });
        }

        // RFC 8200, Section 4.4 — Routing Type and Segments Left
        let routing_type = data[2];
        let segments_left = data[3];

        buf.begin_layer(
            self.short_name(),
            None,
            GENERIC_ROUTING_DESCRIPTORS,
            offset..offset + total_len,
        );

        buf.push_field(
            &GENERIC_ROUTING_DESCRIPTORS[0],
            FieldValue::U8(next_header),
            offset..offset + 1,
        );
        buf.push_field(
            &GENERIC_ROUTING_DESCRIPTORS[1],
            FieldValue::U8(hdr_ext_len),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &GENERIC_ROUTING_DESCRIPTORS[2],
            FieldValue::U8(routing_type),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &GENERIC_ROUTING_DESCRIPTORS[3],
            FieldValue::U8(segments_left),
            offset + 3..offset + 4,
        );

        // Type-specific data after the 4 fixed bytes
        if total_len > ROUTING_FIXED_SIZE {
            buf.push_field(
                &GENERIC_ROUTING_DESCRIPTORS[4],
                FieldValue::Bytes(&data[ROUTING_FIXED_SIZE..total_len]),
                offset + ROUTING_FIXED_SIZE..offset + total_len,
            );
        }

        buf.end_layer();

        Ok(DissectResult::new(
            total_len,
            DispatchHint::ByIpProtocol(next_header),
        ))
    }
}

// --- Fragment Header (Section 4.5) ---

/// Fragment Header dissector.
///
/// RFC 8200, Section 4.5: The Fragment header is used by an IPv6 source
/// to send a packet larger than would fit in the path MTU.
/// The Fragment header is always exactly 8 bytes.
pub struct FragmentDissector;

static FRAGMENT_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("next_header", "Next Header", FieldType::U8),
    FieldDescriptor::new("fragment_offset", "Fragment Offset", FieldType::U16),
    FieldDescriptor::new("m_flag", "More Fragments", FieldType::U8),
    FieldDescriptor::new("identification", "Identification", FieldType::U32),
];

impl Dissector for FragmentDissector {
    fn name(&self) -> &'static str {
        "IPv6 Fragment Header"
    }

    fn short_name(&self) -> &'static str {
        "IPv6 Fragment"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FRAGMENT_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < FRAGMENT_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: FRAGMENT_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let next_header = data[0];
        // data[1] is reserved

        // RFC 8200, Section 4.5 — Fragment Offset (13 bits) | Res (2 bits) | M (1 bit)
        let frag_off_m = read_be_u16(data, 2)?;
        let fragment_offset = (frag_off_m >> 3) & 0x1FFF;
        let m_flag = (frag_off_m & 0x01) != 0;

        let identification = read_be_u32(data, 4)?;

        buf.begin_layer(
            self.short_name(),
            None,
            FRAGMENT_DESCRIPTORS,
            offset..offset + FRAGMENT_HEADER_SIZE,
        );

        buf.push_field(
            &FRAGMENT_DESCRIPTORS[0],
            FieldValue::U8(next_header),
            offset..offset + 1,
        );
        buf.push_field(
            &FRAGMENT_DESCRIPTORS[1],
            FieldValue::U16(fragment_offset),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FRAGMENT_DESCRIPTORS[2],
            FieldValue::U8(m_flag as u8),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FRAGMENT_DESCRIPTORS[3],
            FieldValue::U32(identification),
            offset + 4..offset + 8,
        );

        buf.end_layer();

        Ok(DissectResult::new(
            FRAGMENT_HEADER_SIZE,
            DispatchHint::ByIpProtocol(next_header),
        ))
    }
}

// --- Mobility Header (RFC 6275) ---

/// Mobility Header (MH) dissector.
///
/// RFC 6275, Section 6.1: Used to support Mobile IPv6. The header length
/// is `(Header Len + 1) * 8` bytes.
pub struct MobilityDissector;

static MOBILITY_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("payload_proto", "Payload Protocol", FieldType::U8),
    FieldDescriptor::new("header_len", "Header Length", FieldType::U8),
    FieldDescriptor::new("mh_type", "MH Type", FieldType::U8),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    FieldDescriptor::new("message_data", "Message Data", FieldType::Bytes).optional(),
];

impl Dissector for MobilityDissector {
    fn name(&self) -> &'static str {
        "IPv6 Mobility Header"
    }

    fn short_name(&self) -> &'static str {
        "IPv6 Mobility"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        MOBILITY_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < MH_FIXED_SIZE {
            return Err(PacketError::Truncated {
                expected: MH_FIXED_SIZE,
                actual: data.len(),
            });
        }

        let payload_proto = data[0];
        let header_len = data[1];
        // RFC 6275, Section 6.1 — total length = (Header Len + 1) * 8
        let total_len = (header_len as usize + 1) * 8;

        if data.len() < total_len {
            return Err(PacketError::Truncated {
                expected: total_len,
                actual: data.len(),
            });
        }

        // RFC 6275, Section 6.1 — MH Type and Checksum
        let mh_type = data[2];
        // data[3] is Reserved
        let checksum = read_be_u16(data, 4)?;

        buf.begin_layer(
            self.short_name(),
            None,
            MOBILITY_DESCRIPTORS,
            offset..offset + total_len,
        );

        buf.push_field(
            &MOBILITY_DESCRIPTORS[0],
            FieldValue::U8(payload_proto),
            offset..offset + 1,
        );
        buf.push_field(
            &MOBILITY_DESCRIPTORS[1],
            FieldValue::U8(header_len),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &MOBILITY_DESCRIPTORS[2],
            FieldValue::U8(mh_type),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &MOBILITY_DESCRIPTORS[3],
            FieldValue::U16(checksum),
            offset + 4..offset + 6,
        );

        // RFC 6275, Section 6.1 — Message Data follows the 6-byte fixed fields
        if total_len > MH_FIXED_SIZE {
            buf.push_field(
                &MOBILITY_DESCRIPTORS[4],
                FieldValue::Bytes(&data[MH_FIXED_SIZE..total_len]),
                offset + MH_FIXED_SIZE..offset + total_len,
            );
        }

        buf.end_layer();

        Ok(DissectResult::new(
            total_len,
            DispatchHint::ByIpProtocol(payload_proto),
        ))
    }
}
