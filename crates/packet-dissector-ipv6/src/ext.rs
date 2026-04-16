//! IPv6 Extension Header dissectors.
//!
//! ## References
//! - RFC 8200, Section 4: IPv6 Extension Headers
//!   <https://www.rfc-editor.org/rfc/rfc8200#section-4>
//!   - Section 4.2: Options (TLV encoding)
//!     <https://www.rfc-editor.org/rfc/rfc8200#section-4.2>
//!   - Section 4.3: Hop-by-Hop Options Header
//!     <https://www.rfc-editor.org/rfc/rfc8200#section-4.3>
//!   - Section 4.4: Routing Header
//!     <https://www.rfc-editor.org/rfc/rfc8200#section-4.4>
//!   - Section 4.5: Fragment Header
//!     <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>
//!   - Section 4.6: Destination Options Header
//!     <https://www.rfc-editor.org/rfc/rfc8200#section-4.6>
//! - RFC 9673 (updates RFC 8200 Hop-by-Hop processing procedures):
//!   <https://www.rfc-editor.org/rfc/rfc9673>
//! - RFC 6275, Section 6.1: Mobility Header:
//!   <https://www.rfc-editor.org/rfc/rfc6275#section-6.1>

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Minimum bytes needed to read Next Header + Hdr Ext Len for a TLV-style
/// extension header (Hop-by-Hop or Destination Options).
///
/// RFC 8200, Section 4.3: <https://www.rfc-editor.org/rfc/rfc8200#section-4.3>
/// RFC 8200, Section 4.6: <https://www.rfc-editor.org/rfc/rfc8200#section-4.6>
const TLV_HEADER_MIN: usize = 2;

/// Fragment Header is always 8 bytes.
///
/// RFC 8200, Section 4.5: <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>
const FRAGMENT_HEADER_SIZE: usize = 8;

/// Minimum Routing Header fixed fields (Next Header, Hdr Ext Len, Routing Type, Segments Left).
///
/// RFC 8200, Section 4.4: <https://www.rfc-editor.org/rfc/rfc8200#section-4.4>
const ROUTING_FIXED_SIZE: usize = 4;

/// Mobility Header fixed fields: Payload Proto, Header Len, MH Type, Reserved, Checksum.
///
/// RFC 6275, Section 6.1: <https://www.rfc-editor.org/rfc/rfc6275#section-6.1>
const MH_FIXED_SIZE: usize = 6;

// --- Hop-by-Hop Options (Section 4.3) ---

/// Hop-by-Hop Options Header dissector.
///
/// RFC 8200, Section 4.3: Carries optional information that must be
/// examined by every node along a packet's delivery path.
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.3>
///
/// RFC 9673 updates RFC 8200's processing procedures (the on-wire format is
/// unchanged).
/// <https://www.rfc-editor.org/rfc/rfc9673>
pub struct HopByHopDissector;

/// Field descriptors shared by TLV-style extension headers (Hop-by-Hop and Destination Options).
static TLV_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 8200, Sections 4.3 / 4.6 — Next Header (8-bit IANA Protocol Number)
    // <https://www.rfc-editor.org/rfc/rfc8200#section-4.3>
    // <https://www.rfc-editor.org/rfc/rfc8200#section-4.6>
    FieldDescriptor::new("next_header", "Next Header", FieldType::U8),
    // RFC 8200, Sections 4.3 / 4.6 — Hdr Ext Len (length in 8-octet units,
    // excluding the first 8 octets)
    FieldDescriptor::new("hdr_ext_len", "Header Extension Length", FieldType::U8),
    // RFC 8200, Section 4.2 — Options (TLV-encoded, variable length)
    // <https://www.rfc-editor.org/rfc/rfc8200#section-4.2>
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
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.6>
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
/// RFC 8200, Sections 4.3 / 4.6:
/// - Next Header: 8 bits
/// - Hdr Ext Len: 8 bits (length in 8-octet units, not including first 8 octets)
/// - Options: variable length, TLV-encoded
///
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.3>
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.6>
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
    // <https://www.rfc-editor.org/rfc/rfc8200#section-4.3>
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
    // <https://www.rfc-editor.org/rfc/rfc8200#section-4.2>
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
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.4>
///
/// This is a thin dispatcher registered at IP protocol 43. It peeks at the
/// Routing Type field and returns [`DispatchHint::ByIpv6RoutingType`] so the
/// registry can delegate to a type-specific dissector (e.g. SRv6 for type 4)
/// or fall back to [`GenericRoutingDissector`].
pub struct RoutingDissector;

/// Minimum bytes needed to read Next Header, Hdr Ext Len, and Routing Type.
///
/// RFC 8200, Section 4.4: <https://www.rfc-editor.org/rfc/rfc8200#section-4.4>
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
        // <https://www.rfc-editor.org/rfc/rfc8200#section-4.4>
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
/// RFC 8200, Section 4.4: <https://www.rfc-editor.org/rfc/rfc8200#section-4.4>
///
/// Parses the common Routing Header fields and stores type-specific data as
/// raw bytes. Registered as the routing fallback in `DissectorRegistry`.
pub struct GenericRoutingDissector;

static GENERIC_ROUTING_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 8200, Section 4.4 — Next Header (8-bit IANA Protocol Number)
    // <https://www.rfc-editor.org/rfc/rfc8200#section-4.4>
    FieldDescriptor::new("next_header", "Next Header", FieldType::U8),
    // RFC 8200, Section 4.4 — Hdr Ext Len (length in 8-octet units,
    // excluding the first 8 octets)
    FieldDescriptor::new("hdr_ext_len", "Header Extension Length", FieldType::U8),
    // RFC 8200, Section 4.4 — Routing Type (8-bit variant selector)
    FieldDescriptor::new("routing_type", "Routing Type", FieldType::U8),
    // RFC 8200, Section 4.4 — Segments Left (8-bit unsigned)
    FieldDescriptor::new("segments_left", "Segments Left", FieldType::U8),
    // RFC 8200, Section 4.4 — type-specific data (variable length)
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
        // <https://www.rfc-editor.org/rfc/rfc8200#section-4.4>
        let total_len = (hdr_ext_len as usize + 1) * 8;

        if data.len() < total_len {
            return Err(PacketError::Truncated {
                expected: total_len,
                actual: data.len(),
            });
        }

        // RFC 8200, Section 4.4 — Routing Type and Segments Left
        // <https://www.rfc-editor.org/rfc/rfc8200#section-4.4>
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
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>
pub struct FragmentDissector;

/// Field descriptor indices for [`FRAGMENT_DESCRIPTORS`].
const FRAG_FD_NEXT_HEADER: usize = 0;
const FRAG_FD_RESERVED: usize = 1;
const FRAG_FD_FRAGMENT_OFFSET: usize = 2;
const FRAG_FD_RES: usize = 3;
const FRAG_FD_M_FLAG: usize = 4;
const FRAG_FD_IDENTIFICATION: usize = 5;

static FRAGMENT_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 8200, Section 4.5 — Next Header (8-bit IANA Protocol Number)
    // <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>
    FieldDescriptor::new("next_header", "Next Header", FieldType::U8),
    // RFC 8200, Section 4.5 — Reserved (8 bits, zero on transmission,
    // ignored on reception). Exposed for dissection fidelity.
    FieldDescriptor::new("reserved", "Reserved", FieldType::U8),
    // RFC 8200, Section 4.5 — Fragment Offset (13-bit unsigned, 8-octet units)
    FieldDescriptor::new("fragment_offset", "Fragment Offset", FieldType::U16),
    // RFC 8200, Section 4.5 — Res (2 bits, zero on transmission, ignored on
    // reception). Exposed for dissection fidelity.
    FieldDescriptor::new("res", "Res", FieldType::U8),
    // RFC 8200, Section 4.5 — M flag (1 = more fragments; 0 = last fragment)
    FieldDescriptor::new("m_flag", "More Fragments", FieldType::U8),
    // RFC 8200, Section 4.5 — Identification (32 bits)
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
        // RFC 8200, Section 4.5 — Reserved (8-bit, byte 1)
        // <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>
        let reserved = data[1];

        // RFC 8200, Section 4.5 — Fragment Offset (13 bits) | Res (2 bits) | M (1 bit)
        // <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>
        let frag_off_m = read_be_u16(data, 2)?;
        let fragment_offset = (frag_off_m >> 3) & 0x1FFF;
        let res = ((frag_off_m >> 1) & 0x03) as u8;
        let m_flag = (frag_off_m & 0x01) != 0;

        let identification = read_be_u32(data, 4)?;

        buf.begin_layer(
            self.short_name(),
            None,
            FRAGMENT_DESCRIPTORS,
            offset..offset + FRAGMENT_HEADER_SIZE,
        );

        buf.push_field(
            &FRAGMENT_DESCRIPTORS[FRAG_FD_NEXT_HEADER],
            FieldValue::U8(next_header),
            offset..offset + 1,
        );
        buf.push_field(
            &FRAGMENT_DESCRIPTORS[FRAG_FD_RESERVED],
            FieldValue::U8(reserved),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FRAGMENT_DESCRIPTORS[FRAG_FD_FRAGMENT_OFFSET],
            FieldValue::U16(fragment_offset),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FRAGMENT_DESCRIPTORS[FRAG_FD_RES],
            FieldValue::U8(res),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FRAGMENT_DESCRIPTORS[FRAG_FD_M_FLAG],
            FieldValue::U8(m_flag as u8),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FRAGMENT_DESCRIPTORS[FRAG_FD_IDENTIFICATION],
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
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.1>
pub struct MobilityDissector;

/// Field descriptor indices for [`MOBILITY_DESCRIPTORS`].
const MH_FD_PAYLOAD_PROTO: usize = 0;
const MH_FD_HEADER_LEN: usize = 1;
const MH_FD_MH_TYPE: usize = 2;
const MH_FD_RESERVED: usize = 3;
const MH_FD_CHECKSUM: usize = 4;
const MH_FD_MESSAGE_DATA: usize = 5;

static MOBILITY_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 6275, Section 6.1.1 — Payload Proto (8-bit IANA Protocol Number)
    // <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.1>
    FieldDescriptor::new("payload_proto", "Payload Protocol", FieldType::U8),
    // RFC 6275, Section 6.1.1 — Header Len (length in 8-octet units,
    // excluding the first 8 octets)
    FieldDescriptor::new("header_len", "Header Length", FieldType::U8),
    // RFC 6275, Section 6.1.1 — MH Type (8-bit mobility message selector)
    FieldDescriptor::new("mh_type", "MH Type", FieldType::U8),
    // RFC 6275, Section 6.1.1 — Reserved (8-bit, zero on transmission,
    // ignored on reception). Exposed for dissection fidelity.
    FieldDescriptor::new("reserved", "Reserved", FieldType::U8),
    // RFC 6275, Section 6.1.1 — Checksum (16-bit one's complement)
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    // RFC 6275, Section 6.1.1 — Message Data (variable length)
    FieldDescriptor::new("message_data", "Message Data", FieldType::Bytes).optional(),
];

/// Byte offset where Mobility Header message data begins
/// (after Payload Proto, Header Len, MH Type, Reserved, Checksum).
const MH_MESSAGE_DATA_OFFSET: usize = 6;

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
        // RFC 6275, Section 6.1.1 — total length = (Header Len + 1) * 8
        // <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.1>
        let total_len = (header_len as usize + 1) * 8;

        if data.len() < total_len {
            return Err(PacketError::Truncated {
                expected: total_len,
                actual: data.len(),
            });
        }

        // RFC 6275, Section 6.1.1 — MH Type, Reserved, and Checksum
        // <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.1>
        let mh_type = data[2];
        let reserved = data[3];
        let checksum = read_be_u16(data, 4)?;

        buf.begin_layer(
            self.short_name(),
            None,
            MOBILITY_DESCRIPTORS,
            offset..offset + total_len,
        );

        buf.push_field(
            &MOBILITY_DESCRIPTORS[MH_FD_PAYLOAD_PROTO],
            FieldValue::U8(payload_proto),
            offset..offset + 1,
        );
        buf.push_field(
            &MOBILITY_DESCRIPTORS[MH_FD_HEADER_LEN],
            FieldValue::U8(header_len),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &MOBILITY_DESCRIPTORS[MH_FD_MH_TYPE],
            FieldValue::U8(mh_type),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &MOBILITY_DESCRIPTORS[MH_FD_RESERVED],
            FieldValue::U8(reserved),
            offset + 3..offset + 4,
        );
        buf.push_field(
            &MOBILITY_DESCRIPTORS[MH_FD_CHECKSUM],
            FieldValue::U16(checksum),
            offset + 4..offset + 6,
        );

        // RFC 6275, Section 6.1.1 — Message Data follows the 6-byte fixed fields
        // <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.1>
        if total_len > MH_MESSAGE_DATA_OFFSET {
            buf.push_field(
                &MOBILITY_DESCRIPTORS[MH_FD_MESSAGE_DATA],
                FieldValue::Bytes(&data[MH_MESSAGE_DATA_OFFSET..total_len]),
                offset + MH_MESSAGE_DATA_OFFSET..offset + total_len,
            );
        }

        buf.end_layer();

        Ok(DissectResult::new(
            total_len,
            DispatchHint::ByIpProtocol(payload_proto),
        ))
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 8200 (IPv6 Extension Headers) Coverage
    //!
    //! | RFC Section | Description                        | Test                                       |
    //! |-------------|------------------------------------|--------------------------------------------|
    //! | 4.3         | Hop-by-Hop Options Header          | hop_by_hop_basic                           |
    //! | 4.3         | Hop-by-Hop with options bytes      | hop_by_hop_with_options                    |
    //! | 4.3         | Hop-by-Hop truncated (< 2 bytes)   | hop_by_hop_truncated_min                   |
    //! | 4.3         | Hop-by-Hop truncated (< total_len) | hop_by_hop_truncated_total_len             |
    //! | 4.3         | Hop-by-Hop metadata                | hop_by_hop_metadata                        |
    //! | 4.6         | Destination Options Header         | destination_options_basic                   |
    //! | 4.6         | Destination Options truncated      | destination_options_truncated               |
    //! | 4.6         | Destination Options metadata       | destination_options_metadata                |
    //! | 4.4         | Routing dispatcher                 | routing_dispatcher_basic                   |
    //! | 4.4         | Routing dispatcher truncated       | routing_dispatcher_truncated               |
    //! | 4.4         | Routing dispatcher metadata        | routing_dispatcher_metadata                |
    //! | 4.4         | Generic Routing Header             | generic_routing_basic                      |
    //! | 4.4         | Generic Routing with data          | generic_routing_with_data                  |
    //! | 4.4         | Generic Routing truncated (fixed)  | generic_routing_truncated_fixed            |
    //! | 4.4         | Generic Routing truncated (total)  | generic_routing_truncated_total_len        |
    //! | 4.4         | Generic Routing metadata           | generic_routing_metadata                   |
    //! | 4.5         | Fragment Header                    | fragment_basic                             |
    //! | 4.5         | Fragment Offset & M flag parsing   | fragment_offset_and_m_flag                 |
    //! | 4.5         | Fragment reserved fields            | fragment_reserved_fields                   |
    //! | 4.5         | Fragment truncated                 | fragment_truncated                          |
    //! | 4.5         | Fragment metadata                  | fragment_metadata                           |
    //! | 4.5         | Fragment field count                | fragment_field_count                        |
    //!
    //! # RFC 6275 (Mobility Header) Coverage
    //!
    //! | RFC Section | Description                        | Test                                       |
    //! |-------------|------------------------------------|--------------------------------------------|
    //! | 6.1         | MH Header Format                   | mobility_basic                             |
    //! | 6.1         | MH with message data               | mobility_with_data                         |
    //! | 6.1         | MH reserved byte                   | mobility_reserved_field                    |
    //! | 6.1         | MH truncated (fixed)               | mobility_truncated_fixed                   |
    //! | 6.1         | MH truncated (payload)             | mobility_truncated_total_len               |
    //! | 6.1         | MH metadata                        | mobility_metadata                          |
    //! | 6.1         | MH field count                     | mobility_field_count                       |

    use super::*;

    // ---- Hop-by-Hop Options (Section 4.3) ----

    #[test]
    fn hop_by_hop_basic() {
        // RFC 8200, Section 4.3 — Minimum header: Hdr Ext Len=0 → 8 bytes.
        // Next Header=6 (TCP), PadN padding.
        let data: [u8; 8] = [6, 0, 1, 4, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        let result = HopByHopDissector.dissect(&data, &mut buf, 40).unwrap();

        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

        let layer = buf.layer_by_name("IPv6 Hop-by-Hop").unwrap();
        assert_eq!(layer.range, 40..48);
        assert_eq!(
            buf.field_by_name(layer, "next_header").unwrap().value,
            FieldValue::U8(6)
        );
        assert_eq!(
            buf.field_by_name(layer, "hdr_ext_len").unwrap().value,
            FieldValue::U8(0)
        );
        // Options bytes present (6 bytes of padding after 2-byte fixed header).
        assert!(buf.field_by_name(layer, "options").is_some());
    }

    #[test]
    fn hop_by_hop_with_options() {
        // Hdr Ext Len=1 → (1+1)*8 = 16 bytes total, options = 14 bytes.
        let mut data = vec![17u8, 1]; // NH=UDP, Hdr Ext Len=1
        data.extend_from_slice(&[0u8; 14]); // 14 bytes of options/padding
        let mut buf = DissectBuffer::new();
        let result = HopByHopDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 16);
        assert_eq!(result.next, DispatchHint::ByIpProtocol(17));

        let layer = buf.layer_by_name("IPv6 Hop-by-Hop").unwrap();
        let options = buf.field_by_name(layer, "options").unwrap();
        assert_eq!(options.value, FieldValue::Bytes(&[0u8; 14]));
        assert_eq!(options.range, 2..16);
    }

    #[test]
    fn hop_by_hop_truncated_min() {
        // Less than TLV_HEADER_MIN (2 bytes).
        let data = [0u8; 1];
        let mut buf = DissectBuffer::new();
        let err = HopByHopDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 2,
                actual: 1
            }
        ));
    }

    #[test]
    fn hop_by_hop_truncated_total_len() {
        // 2 bytes present but Hdr Ext Len=0 → needs 8 bytes.
        let data = [6u8, 0]; // NH=TCP, Hdr Ext Len=0
        let mut buf = DissectBuffer::new();
        let err = HopByHopDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 2
            }
        ));
    }

    #[test]
    fn hop_by_hop_metadata() {
        let d = HopByHopDissector;
        assert_eq!(d.name(), "IPv6 Hop-by-Hop Options Header");
        assert_eq!(d.short_name(), "IPv6 Hop-by-Hop");
        assert_eq!(d.field_descriptors().len(), 3);
    }

    // ---- Destination Options (Section 4.6) ----

    #[test]
    fn destination_options_basic() {
        let data: [u8; 8] = [6, 0, 1, 4, 0, 0, 0, 0]; // NH=TCP, Hdr Ext Len=0
        let mut buf = DissectBuffer::new();
        let result = DestinationOptionsDissector
            .dissect(&data, &mut buf, 40)
            .unwrap();

        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

        let layer = buf.layer_by_name("IPv6 Destination Options").unwrap();
        assert_eq!(layer.range, 40..48);
    }

    #[test]
    fn destination_options_truncated() {
        let data = [6u8]; // 1 byte, need at least 2.
        let mut buf = DissectBuffer::new();
        let err = DestinationOptionsDissector
            .dissect(&data, &mut buf, 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 2,
                actual: 1
            }
        ));
    }

    #[test]
    fn destination_options_metadata() {
        let d = DestinationOptionsDissector;
        assert_eq!(d.name(), "IPv6 Destination Options Header");
        assert_eq!(d.short_name(), "IPv6 Destination Options");
    }

    // ---- Routing Header dispatcher (Section 4.4) ----

    #[test]
    fn routing_dispatcher_basic() {
        // RoutingDissector peeks Routing Type, consumes 0 bytes.
        let data: [u8; 8] = [6, 0, 2, 1, 0, 0, 0, 0]; // RT=2
        let mut buf = DissectBuffer::new();
        let result = RoutingDissector.dissect(&data, &mut buf, 40).unwrap();

        assert_eq!(result.bytes_consumed, 0);
        assert_eq!(result.next, DispatchHint::ByIpv6RoutingType(2));
        assert_eq!(buf.layers().len(), 0); // thin dispatcher produces no layer
    }

    #[test]
    fn routing_dispatcher_truncated() {
        let data = [6u8, 0]; // 2 bytes, need at least 3 to read Routing Type.
        let mut buf = DissectBuffer::new();
        let err = RoutingDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 3,
                actual: 2
            }
        ));
    }

    #[test]
    fn routing_dispatcher_metadata() {
        let d = RoutingDissector;
        assert_eq!(d.name(), "IPv6 Routing Header");
        assert_eq!(d.short_name(), "IPv6 Routing");
        assert_eq!(d.field_descriptors().len(), 0); // thin dispatcher
    }

    // ---- Generic Routing Header (Section 4.4) ----

    #[test]
    fn generic_routing_basic() {
        // RFC 8200, Section 4.4 — 8 bytes, Routing Type=2, Segments Left=1.
        let data: [u8; 8] = [6, 0, 2, 1, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        let result = GenericRoutingDissector
            .dissect(&data, &mut buf, 40)
            .unwrap();

        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

        let layer = buf.layer_by_name("IPv6 Routing").unwrap();
        assert_eq!(layer.range, 40..48);
        assert_eq!(
            buf.field_by_name(layer, "routing_type").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "segments_left").unwrap().value,
            FieldValue::U8(1)
        );
        // type-specific data = 4 bytes after the 4 fixed bytes.
        assert!(buf.field_by_name(layer, "data").is_some());
    }

    #[test]
    fn generic_routing_with_data() {
        // Hdr Ext Len=1 → (1+1)*8 = 16 bytes total, type-specific = 12 bytes.
        let mut data = vec![17u8, 1, 4, 3]; // NH=UDP, Hdr Ext Len=1, RT=4, SL=3
        data.extend_from_slice(&[0xAAu8; 12]); // 12 bytes type-specific
        let mut buf = DissectBuffer::new();
        let result = GenericRoutingDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 16);

        let layer = buf.layer_by_name("IPv6 Routing").unwrap();
        let ts_data = buf.field_by_name(layer, "data").unwrap();
        assert_eq!(ts_data.value, FieldValue::Bytes(&[0xAA; 12]));
        assert_eq!(ts_data.range, 4..16);
    }

    #[test]
    fn generic_routing_truncated_fixed() {
        let data = [6u8, 0, 2]; // 3 bytes, need at least 4 for fixed fields.
        let mut buf = DissectBuffer::new();
        let err = GenericRoutingDissector
            .dissect(&data, &mut buf, 0)
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
    fn generic_routing_truncated_total_len() {
        // Fixed fields OK but data shorter than total_len.
        // Hdr Ext Len=1 → total=16 bytes, only 8 provided.
        let data: [u8; 8] = [6, 1, 2, 1, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        let err = GenericRoutingDissector
            .dissect(&data, &mut buf, 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 16,
                actual: 8
            }
        ));
    }

    #[test]
    fn generic_routing_metadata() {
        let d = GenericRoutingDissector;
        assert_eq!(d.name(), "IPv6 Routing Header");
        assert_eq!(d.short_name(), "IPv6 Routing");
        assert_eq!(d.field_descriptors().len(), 5);
    }

    // ---- Fragment Header (Section 4.5) ----

    #[test]
    fn fragment_basic() {
        // RFC 8200, Section 4.5 — 8 bytes.
        // NH=6 (TCP), Reserved=0, Fragment Offset=7, Res=0, M=1, ID=0xDEADBEEF
        let data: [u8; 8] = [6, 0, 0x00, 0x39, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut buf = DissectBuffer::new();
        let result = FragmentDissector.dissect(&data, &mut buf, 40).unwrap();

        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

        let layer = buf.layer_by_name("IPv6 Fragment").unwrap();
        assert_eq!(layer.range, 40..48);
        assert_eq!(
            buf.field_by_name(layer, "next_header").unwrap().value,
            FieldValue::U8(6)
        );
        assert_eq!(
            buf.field_by_name(layer, "fragment_offset").unwrap().value,
            FieldValue::U16(7)
        );
        assert_eq!(
            buf.field_by_name(layer, "m_flag").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "identification").unwrap().value,
            FieldValue::U32(0xDEADBEEF)
        );
    }

    #[test]
    fn fragment_offset_and_m_flag() {
        // Fragment Offset=0x1FFF (max 13-bit), M=0.
        // Bytes 2-3: 0x1FFF << 3 | 0 = 0xFFF8
        let data: [u8; 8] = [6, 0, 0xFF, 0xF8, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        FragmentDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("IPv6 Fragment").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "fragment_offset").unwrap().value,
            FieldValue::U16(0x1FFF)
        );
        assert_eq!(
            buf.field_by_name(layer, "m_flag").unwrap().value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn fragment_reserved_fields() {
        // RFC 8200, Section 4.5 — Reserved byte (data[1]) and Res (2 bits)
        // are exposed for dissection fidelity.
        // data[1] = 0xAA (non-zero reserved), Res = 0b11 = bits 1-2 of byte 3.
        // Bytes 2-3: fragment_offset=0 | Res=3 | M=0 = 0x0006
        let data: [u8; 8] = [6, 0xAA, 0x00, 0x06, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        FragmentDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("IPv6 Fragment").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "reserved").unwrap().value,
            FieldValue::U8(0xAA)
        );
        assert_eq!(
            buf.field_by_name(layer, "res").unwrap().value,
            FieldValue::U8(3)
        );
    }

    #[test]
    fn fragment_truncated() {
        let data = [6u8, 0, 0, 0]; // 4 bytes, need 8.
        let mut buf = DissectBuffer::new();
        let err = FragmentDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 4
            }
        ));
    }

    #[test]
    fn fragment_metadata() {
        let d = FragmentDissector;
        assert_eq!(d.name(), "IPv6 Fragment Header");
        assert_eq!(d.short_name(), "IPv6 Fragment");
    }

    #[test]
    fn fragment_field_count() {
        // 6 fields: next_header, reserved, fragment_offset, res, m_flag, identification.
        let data: [u8; 8] = [6, 0, 0, 0, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        FragmentDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("IPv6 Fragment").unwrap();
        assert_eq!(buf.layer_fields(layer).len(), 6);
    }

    // ---- Mobility Header (RFC 6275, Section 6.1) ----

    #[test]
    fn mobility_basic() {
        // RFC 6275, Section 6.1.1 — Minimum 8 bytes (Header Len=0).
        // Payload Proto=6 (TCP), MH Type=1, Reserved=0, Checksum=0xABCD.
        let data: [u8; 8] = [6, 0, 1, 0, 0xAB, 0xCD, 0, 0];
        let mut buf = DissectBuffer::new();
        let result = MobilityDissector.dissect(&data, &mut buf, 40).unwrap();

        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

        let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
        assert_eq!(layer.range, 40..48);
        assert_eq!(
            buf.field_by_name(layer, "payload_proto").unwrap().value,
            FieldValue::U8(6)
        );
        assert_eq!(
            buf.field_by_name(layer, "header_len").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "mh_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "reserved").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "checksum").unwrap().value,
            FieldValue::U16(0xABCD)
        );
    }

    #[test]
    fn mobility_with_data() {
        // Header Len=1 → (1+1)*8 = 16 bytes, message data = 10 bytes.
        let mut data = vec![59u8, 1, 5, 0, 0x12, 0x34]; // NH=No Next Header, MH Type=5
        data.extend_from_slice(&[0xBB; 10]); // 10 bytes message data
        let mut buf = DissectBuffer::new();
        let result = MobilityDissector.dissect(&data, &mut buf, 40).unwrap();

        assert_eq!(result.bytes_consumed, 16);
        assert_eq!(result.next, DispatchHint::ByIpProtocol(59));

        let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
        let msg_data = buf.field_by_name(layer, "message_data").unwrap();
        assert_eq!(msg_data.value, FieldValue::Bytes(&[0xBB; 10]));
        assert_eq!(msg_data.range, 46..56);
    }

    #[test]
    fn mobility_reserved_field() {
        // RFC 6275, Section 6.1.1 — Reserved byte at offset 3.
        let data: [u8; 8] = [59, 0, 0, 0xFF, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        MobilityDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "reserved").unwrap().value,
            FieldValue::U8(0xFF)
        );
        assert_eq!(buf.field_by_name(layer, "reserved").unwrap().range, 3..4);
    }

    #[test]
    fn mobility_truncated_fixed() {
        let data = [6u8, 0, 1, 0, 0]; // 5 bytes, need at least 6.
        let mut buf = DissectBuffer::new();
        let err = MobilityDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 6,
                actual: 5
            }
        ));
    }

    #[test]
    fn mobility_truncated_total_len() {
        // Header Len=1 → total=16 bytes, only 8 provided.
        let data: [u8; 8] = [6, 1, 1, 0, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        let err = MobilityDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 16,
                actual: 8
            }
        ));
    }

    #[test]
    fn mobility_metadata() {
        let d = MobilityDissector;
        assert_eq!(d.name(), "IPv6 Mobility Header");
        assert_eq!(d.short_name(), "IPv6 Mobility");
    }

    #[test]
    fn mobility_field_count() {
        // With Header Len=0 (total=8): 6 fields (including reserved and message_data).
        let data: [u8; 8] = [59, 0, 0, 0, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        MobilityDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
        // payload_proto, header_len, mh_type, reserved, checksum, message_data
        assert_eq!(buf.layer_fields(layer).len(), 6);
    }
}
