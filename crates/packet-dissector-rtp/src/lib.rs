//! RTP (Real-time Transport Protocol) dissector.
//!
//! ## References
//! - RFC 3550, Section 5.1 — RTP Fixed Header Fields:
//!   <https://www.rfc-editor.org/rfc/rfc3550#section-5.1>
//! - RFC 3550, Section 5.3.1 — RTP Header Extension:
//!   <https://www.rfc-editor.org/rfc/rfc3550#section-5.3.1>
//! - RFC 8285 (Obsoletes RFC 5285) — A General Mechanism for RTP Header
//!   Extensions, Sections 4.2 and 4.3:
//!   <https://www.rfc-editor.org/rfc/rfc8285#section-4>
//! - RFC 3551, Section 6 — static payload types:
//!   <https://www.rfc-editor.org/rfc/rfc3551#section-6>
//! - RFC 5761, Section 4 — RTP and RTCP multiplexed on a single port:
//!   <https://www.rfc-editor.org/rfc/rfc5761#section-4>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};
use packet_dissector_rtcp::RtcpDissector;

/// Minimum RTP header size in bytes (fixed header without CSRC list or extension).
/// RFC 3550, Section 5.1 — "The first twelve octets are present in every RTP packet"
/// <https://www.rfc-editor.org/rfc/rfc3550#section-5.1>
const MIN_HEADER_SIZE: usize = 12;

/// RTP version defined by RFC 3550.
/// RFC 3550, Section 5.1 — "The version defined by this specification is two (2)."
/// <https://www.rfc-editor.org/rfc/rfc3550#section-5.1>
const RTP_VERSION: u8 = 2;

/// Values of the second octet that are RTCP packet types when RTP and RTCP
/// share a port (seen as RTP they are M=1 with payload types 64-95).
///
/// RFC 5761, Section 4 — "future RTCP packet type assignments SHOULD be made
/// after the current assignments in the range 209-223, then in the range
/// 194-199, so that only the RTP payload types in the range 64-95 are
/// blocked." and "payload type values in the range 64-95 MUST NOT be used."
/// <https://www.rfc-editor.org/rfc/rfc5761#section-4>
const RTCP_MUX_PACKET_TYPES: core::ops::RangeInclusive<u8> = 192..=223;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_VERSION: usize = 0;
const FD_PADDING: usize = 1;
const FD_EXTENSION: usize = 2;
const FD_CSRC_COUNT: usize = 3;
const FD_MARKER: usize = 4;
const FD_PAYLOAD_TYPE: usize = 5;
const FD_SEQUENCE_NUMBER: usize = 6;
const FD_TIMESTAMP: usize = 7;
const FD_SSRC: usize = 8;
const FD_CSRC_LIST: usize = 9;
const FD_PAYLOAD: usize = 10;
const FD_PADDING_LENGTH: usize = 11;
const FD_EXT_PROFILE: usize = 12;
const FD_EXT_LENGTH: usize = 13;
const FD_EXT_DATA: usize = 14;
const FD_EXT_APPBITS: usize = 15;
const FD_EXT_ELEMENTS: usize = 16;

/// Field descriptor indices for [`EXT_ELEMENT_FIELDS`].
const EFD_ID: usize = 0;
const EFD_LENGTH: usize = 1;
const EFD_DATA: usize = 2;

/// "defined by profile" value of the one-byte header form.
///
/// RFC 8285, Section 4.2 — "MUST have the fixed bit pattern 0xBEDE".
/// <https://www.rfc-editor.org/rfc/rfc8285#section-4.2>
const EXT_PROFILE_ONE_BYTE: u16 = 0xBEDE;

/// "defined by profile" value of the two-byte header form, without the
/// 4-bit appbits.
///
/// RFC 8285, Section 4.3 — "In the two-byte header form, the 16-bit value
/// defined by the RTP specification for a header extension, labeled in the
/// RTP specification as "defined by profile", is defined as shown below."
/// (0x100 in the upper 12 bits, appbits in the lower 4 bits).
/// <https://www.rfc-editor.org/rfc/rfc8285#section-4.3>
const EXT_PROFILE_TWO_BYTE: u16 = 0x1000;

/// One-byte form ID that terminates processing.
///
/// RFC 8285, Section 4.2 — "If the ID value 15 is encountered, its length
/// field MUST be ignored, processing of the entire extension MUST terminate
/// at that point".
/// <https://www.rfc-editor.org/rfc/rfc8285#section-4.2>
const ONE_BYTE_ID_TERMINATE: u8 = 15;

/// Returns the encoding name of a static RTP/AVP payload type.
///
/// RFC 3551, Section 6, Tables 4 and 5; "payload type values in the range
/// 96-127 MAY be defined dynamically".
/// <https://www.rfc-editor.org/rfc/rfc3551#section-6>
fn payload_type_name(pt: u8) -> Option<&'static str> {
    match pt {
        0 => Some("PCMU"),
        3 => Some("GSM"),
        4 => Some("G723"),
        5 | 6 | 16 | 17 => Some("DVI4"),
        7 => Some("LPC"),
        8 => Some("PCMA"),
        9 => Some("G722"),
        10 | 11 => Some("L16"),
        12 => Some("QCELP"),
        13 => Some("CN"),
        14 => Some("MPA"),
        15 => Some("G728"),
        18 => Some("G729"),
        25 => Some("CelB"),
        26 => Some("JPEG"),
        28 => Some("nv"),
        31 => Some("H261"),
        32 => Some("MPV"),
        33 => Some("MP2T"),
        34 => Some("H263"),
        96..=127 => Some("dynamic"),
        _ => None,
    }
}

/// Child descriptors of an RFC 8285 extension element.
static EXT_ELEMENT_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("id", "ID", FieldType::U8),
    // Number of data bytes (the one-byte form's encoded value plus one).
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("data", "Data", FieldType::Bytes),
];

/// Container descriptor for one element of `ext_elements`; its children are
/// listed on the array descriptor.
static FD_EXT_ELEMENT: FieldDescriptor =
    FieldDescriptor::new("ext_element", "Extension Element", FieldType::Object);

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("padding", "Padding", FieldType::U8),
    FieldDescriptor::new("extension", "Extension", FieldType::U8),
    FieldDescriptor::new("csrc_count", "CSRC Count", FieldType::U8),
    FieldDescriptor::new("marker", "Marker", FieldType::U8),
    FieldDescriptor::new("payload_type", "Payload Type", FieldType::U8).with_display_fn(|v, _| {
        match v {
            FieldValue::U8(pt) => payload_type_name(*pt),
            _ => None,
        }
    }),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U16),
    FieldDescriptor::new("timestamp", "Timestamp", FieldType::U32),
    FieldDescriptor::new("ssrc", "SSRC", FieldType::U32),
    FieldDescriptor::new("csrc_list", "CSRC List", FieldType::Array).optional(),
    FieldDescriptor::new("payload", "Payload", FieldType::Bytes).optional(),
    FieldDescriptor::new("padding_length", "Padding Length", FieldType::U8).optional(),
    FieldDescriptor::new("ext_profile", "Extension Profile", FieldType::U16).optional(),
    FieldDescriptor::new("ext_length", "Extension Length", FieldType::U16).optional(),
    FieldDescriptor::new("ext_data", "Extension Data", FieldType::Bytes).optional(),
    // RFC 8285, Section 4.3 — https://www.rfc-editor.org/rfc/rfc8285#section-4.3
    FieldDescriptor::new("ext_appbits", "Extension Appbits", FieldType::U8).optional(),
    // RFC 8285, Sections 4.2, 4.3 — https://www.rfc-editor.org/rfc/rfc8285#section-4.2
    FieldDescriptor::new("ext_elements", "Extension Elements", FieldType::Array)
        .optional()
        .with_children(EXT_ELEMENT_FIELDS),
];

/// RFC 8285 header extension form.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExtForm {
    /// One-byte header (RFC 8285, Section 4.2 —
    /// <https://www.rfc-editor.org/rfc/rfc8285#section-4.2>).
    OneByte,
    /// Two-byte header (RFC 8285, Section 4.3 —
    /// <https://www.rfc-editor.org/rfc/rfc8285#section-4.3>).
    TwoByte,
}

impl ExtForm {
    fn from_profile(profile: u16) -> Option<Self> {
        if profile == EXT_PROFILE_ONE_BYTE {
            Some(Self::OneByte)
        } else if profile & 0xFFF0 == EXT_PROFILE_TWO_BYTE {
            Some(Self::TwoByte)
        } else {
            None
        }
    }
}

/// Iterate the RFC 8285 extension elements of `body`, calling `visit` with
/// `(offset, header_len, id, data)` for each one.
///
/// Iteration stops at the end of the extension, at a terminating ID in the
/// one-byte form, or at the first malformed element (a two-byte header
/// without its length octet, or element data that overruns the extension).
/// Elements before a malformed one are still visited; the raw extension
/// bytes remain available as `ext_data`.
///
/// RFC 8285, Section 4.1.2 — "The entire extension is parsed byte by byte to
/// find each extension element (no alignment is needed), and parsing stops
/// (1) at the end of the entire header extension or (2) in the "one-byte
/// headers only" case, on encountering an identifier with the reserved value
/// of 15 -- whichever happens earlier." and "When a padding byte is found, it
/// is ignored, and the parser moves on to interpreting the next byte."
/// <https://www.rfc-editor.org/rfc/rfc8285#section-4.1.2>
fn walk_ext_elements<'a>(
    form: ExtForm,
    body: &'a [u8],
    mut visit: impl FnMut(usize, usize, u8, &'a [u8]),
) {
    let mut pos = 0;
    while let Some(&first) = body.get(pos) {
        // Padding byte.
        if first == 0 {
            pos += 1;
            continue;
        }
        let (id, header_len, data_len) = match form {
            ExtForm::OneByte => {
                let id = first >> 4;
                // RFC 8285, Section 4.2 — ID 15 terminates processing.
                // https://www.rfc-editor.org/rfc/rfc8285#section-4.2
                // RFC 8285, Section 4.1.2 — "An extension element with an ID
                // value equal to 0 MUST NOT have an associated length field
                // greater than 0.  If such an extension element is
                // encountered, its length field MUST be ignored, processing
                // of the entire extension MUST terminate at that point".
                // https://www.rfc-editor.org/rfc/rfc8285#section-4.1.2
                if id == ONE_BYTE_ID_TERMINATE || id == 0 {
                    return;
                }
                // RFC 8285, Section 4.2 — "The 4-bit length is the number,
                // minus one, of data bytes".
                (id, 1, usize::from(first & 0x0F) + 1)
            }
            ExtForm::TwoByte => {
                // RFC 8285, Section 4.3 — "The 8-bit length field is the
                // length of extension data in bytes".
                let Some(&len) = body.get(pos + 1) else {
                    return;
                };
                (first, 2, usize::from(len))
            }
        };
        let data_start = pos + header_len;
        let Some(data) = body.get(data_start..data_start + data_len) else {
            return;
        };
        visit(pos, header_len, id, data);
        pos = data_start + data_len;
    }
}

/// Specification references for the RTP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 3550",
        "RTP: A Transport Protocol for Real-Time Applications",
        "https://www.rfc-editor.org/rfc/rfc3550",
    ),
    SpecReference::new(
        "RFC 8285",
        "A General Mechanism for RTP Header Extensions",
        "https://www.rfc-editor.org/rfc/rfc8285",
    ),
    SpecReference::new(
        "RFC 3551",
        "RTP Profile for Audio and Video Conferences with Minimal Control",
        "https://www.rfc-editor.org/rfc/rfc3551#section-6",
    ),
];

/// RTP dissector.
pub struct RtpDissector;

impl Dissector for RtpDissector {
    fn name(&self) -> &'static str {
        "Real-time Transport Protocol"
    }

    fn short_name(&self) -> &'static str {
        "RTP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        // RFC 5761, Section 4 — "the RTCP packet type field occupies the same
        // position in the packet as the combination of the RTP marker (M)
        // bit and the RTP payload type (PT). This field can be used to
        // distinguish RTP and RTCP packets". A version-2 packet whose second
        // octet is an RTCP packet type is handed to the RTCP dissector. When
        // it is not a well-formed RTCP packet (RTCP rejects it before
        // pushing anything), it is decoded as RTP below, so a stream that is
        // not multiplexed and uses M=1 with PT 64-95 is still shown as RTP.
        // https://www.rfc-editor.org/rfc/rfc5761#section-4
        if let [byte0, byte1, ..] = *data {
            if byte0 >> 6 == RTP_VERSION && RTCP_MUX_PACKET_TYPES.contains(&byte1) {
                if let Ok(result) = RtcpDissector.dissect(data, buf, offset) {
                    return Ok(result);
                }
            }
        }

        // RFC 3550, Section 5.1 — minimum 12-byte fixed header
        // https://www.rfc-editor.org/rfc/rfc3550#section-5.1
        if data.len() < MIN_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 3550, Section 5.1 — Fixed header fields
        // https://www.rfc-editor.org/rfc/rfc3550#section-5.1
        let byte0 = data[0];
        let version = (byte0 >> 6) & 0x03;
        let padding = (byte0 >> 5) & 0x01;
        let extension_bit = (byte0 >> 4) & 0x01;
        let cc = byte0 & 0x0F;

        // RFC 3550, Section 5.1 — "The version defined by this specification is two (2)."
        // https://www.rfc-editor.org/rfc/rfc3550#section-5.1
        if version != RTP_VERSION {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: version as u32,
            });
        }

        let byte1 = data[1];
        let marker = (byte1 >> 7) & 0x01;
        let payload_type = byte1 & 0x7F;
        let sequence_number = read_be_u16(data, 2)?;
        let timestamp = read_be_u32(data, 4)?;
        let ssrc = read_be_u32(data, 8)?;

        let csrc_end = MIN_HEADER_SIZE + (cc as usize) * 4;
        if data.len() < csrc_end {
            return Err(PacketError::Truncated {
                expected: csrc_end,
                actual: data.len(),
            });
        }

        // Compute header_end before begin_layer so we can set the correct range.
        // We need to check extension and padding sizes first.
        let mut header_end = csrc_end;

        // RFC 3550, Section 5.3.1 — Header Extension
        // https://www.rfc-editor.org/rfc/rfc3550#section-5.3.1
        let ext_info = if extension_bit == 1 {
            let ext_header_start = csrc_end;

            // Need at least 4 bytes for extension header (profile + length)
            if data.len() < ext_header_start + 4 {
                return Err(PacketError::Truncated {
                    expected: ext_header_start + 4,
                    actual: data.len(),
                });
            }

            let ext_profile = read_be_u16(data, ext_header_start)?;

            // RFC 3550, Section 5.3.1 — length counts 32-bit words, excluding
            // the 4-byte extension header itself (zero is valid).
            // https://www.rfc-editor.org/rfc/rfc3550#section-5.3.1
            let ext_length = read_be_u16(data, ext_header_start + 2)?;

            let ext_data_bytes = (ext_length as usize) * 4;
            let ext_total = 4 + ext_data_bytes;

            if data.len() < ext_header_start + ext_total {
                return Err(PacketError::Truncated {
                    expected: ext_header_start + ext_total,
                    actual: data.len(),
                });
            }

            header_end = ext_header_start + ext_total;
            Some((
                ext_header_start,
                ext_profile,
                ext_length,
                ext_data_bytes,
                ext_total,
            ))
        } else {
            None
        };

        // RFC 3550, Section 5.1 — "If the padding bit is set, the packet
        // contains one or more additional padding octets at the end which are
        // not part of the payload. The last octet of the padding contains a
        // count of how many padding octets should be ignored, including itself."
        // https://www.rfc-editor.org/rfc/rfc3550#section-5.1
        let pad_count = if padding == 1 {
            if data.len() <= header_end {
                return Err(PacketError::InvalidHeader(
                    "RTP padding bit set but no payload/padding bytes present",
                ));
            }
            let pc = data[data.len() - 1];
            if pc == 0 {
                return Err(PacketError::InvalidHeader(
                    "RTP padding count must be >= 1 (includes the count byte itself)",
                ));
            }
            if (pc as usize) > data.len() - header_end {
                return Err(PacketError::InvalidHeader(
                    "RTP padding count exceeds available payload bytes",
                ));
            }
            Some(pc)
        } else {
            None
        };

        // RFC 3550, Section 5.1 — the RTP packet is [fixed header | CSRC list |
        // optional extension | payload | optional padding]. Because the
        // payload is opaque to the dissector and no next layer follows
        // (DispatchHint::End), the RTP layer claims the entire packet.
        // https://www.rfc-editor.org/rfc/rfc3550#section-5.1
        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + data.len(),
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PADDING],
            FieldValue::U8(padding),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_EXTENSION],
            FieldValue::U8(extension_bit),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CSRC_COUNT],
            FieldValue::U8(cc),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MARKER],
            FieldValue::U8(marker),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PAYLOAD_TYPE],
            FieldValue::U8(payload_type),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
            FieldValue::U16(sequence_number),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TIMESTAMP],
            FieldValue::U32(timestamp),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SSRC],
            FieldValue::U32(ssrc),
            offset + 8..offset + 12,
        );

        if cc > 0 {
            let array_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_CSRC_LIST],
                FieldValue::Array(0..0),
                (offset + MIN_HEADER_SIZE)..(offset + csrc_end),
            );
            for i in 0..cc as usize {
                let csrc_offset = MIN_HEADER_SIZE + i * 4;
                let csrc_val = read_be_u32(data, csrc_offset)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_CSRC_LIST],
                    FieldValue::U32(csrc_val),
                    (offset + csrc_offset)..(offset + csrc_offset + 4),
                );
            }
            buf.end_container(array_idx);
        }

        if let Some((ext_header_start, ext_profile, ext_length, ext_data_bytes, ext_total)) =
            ext_info
        {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_EXT_PROFILE],
                FieldValue::U16(ext_profile),
                (offset + ext_header_start)..(offset + ext_header_start + 2),
            );

            let form = ExtForm::from_profile(ext_profile);
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_EXT_LENGTH],
                FieldValue::U16(ext_length),
                (offset + ext_header_start + 2)..(offset + ext_header_start + 4),
            );

            let body_start = ext_header_start + 4;
            let body = &data[body_start..ext_header_start + ext_total];
            if ext_data_bytes > 0 {
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_EXT_DATA],
                    FieldValue::Bytes(body),
                    (offset + body_start)..(offset + ext_header_start + ext_total),
                );
            }

            if form == Some(ExtForm::TwoByte) {
                // RFC 8285, Section 4.3 — "The appbits field is 4 bits that are
                // application dependent".
                // https://www.rfc-editor.org/rfc/rfc8285#section-4.3
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_EXT_APPBITS],
                    FieldValue::U8((ext_profile & 0x000F) as u8),
                    (offset + ext_header_start + 1)..(offset + ext_header_start + 2),
                );
            }

            // RFC 8285, Sections 4.2, 4.3 — split the extension into
            // elements. A malformed trailing element ends the list; the raw
            // bytes stay in `ext_data`. The array is only emitted when at
            // least one element is found.
            // https://www.rfc-editor.org/rfc/rfc8285#section-4
            if let Some(form) = form {
                let base = offset + body_start;
                let mut array_idx = None;
                walk_ext_elements(form, body, |pos, header_len, id, element| {
                    if array_idx.is_none() {
                        array_idx = Some(buf.begin_container(
                            &FIELD_DESCRIPTORS[FD_EXT_ELEMENTS],
                            FieldValue::Array(0..0),
                            base..base + body.len(),
                        ));
                    }
                    let start = base + pos;
                    let data_start = start + header_len;
                    let data_end = data_start + element.len();
                    let obj_idx = buf.begin_container(
                        &FD_EXT_ELEMENT,
                        FieldValue::Object(0..0),
                        start..data_end,
                    );
                    buf.push_field(
                        &EXT_ELEMENT_FIELDS[EFD_ID],
                        FieldValue::U8(id),
                        start..start + 1,
                    );
                    buf.push_field(
                        &EXT_ELEMENT_FIELDS[EFD_LENGTH],
                        FieldValue::U8(element.len() as u8),
                        data_start - 1..data_start,
                    );
                    buf.push_field(
                        &EXT_ELEMENT_FIELDS[EFD_DATA],
                        FieldValue::Bytes(element),
                        data_start..data_end,
                    );
                    buf.end_container(obj_idx);
                });
                if let Some(array_idx) = array_idx {
                    buf.end_container(array_idx);
                }
            }
        }

        // RFC 3550, Section 5.1 — payload follows the fixed header, CSRC list
        // and optional extension, and precedes any padding at the end of the
        // packet. Treat the payload as opaque bytes.
        // https://www.rfc-editor.org/rfc/rfc3550#section-5.1
        let payload_end = data.len() - pad_count.map(|pc| pc as usize).unwrap_or(0);
        if payload_end > header_end {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_PAYLOAD],
                FieldValue::Bytes(&data[header_end..payload_end]),
                (offset + header_end)..(offset + payload_end),
            );
        }

        if let Some(pc) = pad_count {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_PADDING_LENGTH],
                FieldValue::U8(pc),
                (offset + data.len() - 1)..(offset + data.len()),
            );
        }

        buf.end_layer();

        // RTP payload is audio/video data — no further protocol dissection.
        // The whole RTP packet (header + payload + padding) is consumed.
        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 3550 (RTP) Coverage
    //
    // | RFC Section | Description                | Test                                   |
    // |-------------|----------------------------|----------------------------------------|
    // | 5.1         | Fixed Header Fields        | parse_rtp_basic                        |
    // | 5.1         | Version validation         | parse_rtp_invalid_version              |
    // | 5.1         | Payload extraction         | parse_rtp_with_payload                 |
    // | 5.1         | Padding bit                | parse_rtp_with_padding                 |
    // | 5.1         | Padding — no payload       | parse_rtp_padding_no_payload           |
    // | 5.1         | Padding — count zero       | parse_rtp_padding_count_zero           |
    // | 5.1         | Padding — count overflow   | parse_rtp_padding_count_exceeds_payload|
    // | 5.1         | Padding — only padding     | parse_rtp_padding_only_no_payload_data |
    // | 5.1         | Marker bit                 | parse_rtp_marker_set                   |
    // | 5.1         | CSRC list                  | parse_rtp_with_csrc                    |
    // | 5.1         | CSRC max (15)              | parse_rtp_with_max_csrc                |
    // | 5.1         | Truncated header           | parse_rtp_truncated                    |
    // | 5.1         | Truncated CSRC             | parse_rtp_truncated_csrc               |
    // | 5.3.1       | Header Extension           | parse_rtp_with_extension               |
    // | 5.3.1       | Zero-length extension      | parse_rtp_zero_length_extension        |
    // | 5.1 + 5.3.1 | CSRC + Extension           | parse_rtp_with_csrc_and_extension      |
    // | 5.3.1       | Truncated extension header | parse_rtp_truncated_extension_header   |
    // | 5.3.1       | Truncated extension data   | parse_rtp_truncated_extension_data     |
    //
    // # RFC 8285 (RTP Header Extensions) Coverage
    //
    // | RFC Section | Description                            | Test                                      |
    // |-------------|----------------------------------------|-------------------------------------------|
    // | 4.2         | One-byte form, element ID/len/data     | rfc8285_one_byte_single_element           |
    // | 4.1.2, 4.2  | Padding between and after elements     | rfc8285_one_byte_two_elements_with_padding|
    // | 4.2         | ID 15 terminates processing            | rfc8285_one_byte_id15_terminates          |
    // | 4.1.2       | ID 0 with length > 0 terminates        | rfc8285_one_byte_id0_nonzero_len_terminates |
    // | 4.3         | Two-byte form, appbits                 | rfc8285_two_byte_elements                 |
    // | 4.3         | Two-byte zero-length element           | rfc8285_two_byte_elements                 |
    // | 4.1.2       | Element overrunning extension → raw    | rfc8285_element_overrun_keeps_raw         |
    // | 4.3         | Two-byte form has no ID 15 terminator  | rfc8285_two_byte_id15_is_an_element       |
    // | 4.1         | Other profiles keep raw ext_data only  | parse_rtp_with_csrc_and_extension         |
    //
    // # RFC 3551 (RTP/AVP) Coverage
    //
    // | RFC Section | Description                            | Test                                      |
    // |-------------|----------------------------------------|-------------------------------------------|
    // | 6           | Static payload type names (Tables 4/5) | payload_type_names                        |
    // | 6           | Dynamic range 96-127                   | payload_type_names                        |
    //
    // # RFC 5761 (RTP/RTCP Multiplexing) Coverage
    //
    // | RFC Section | Description                            | Test                                      |
    // |-------------|----------------------------------------|-------------------------------------------|
    // | 4           | Octet 2 in 192-223 dissected as RTCP   | rfc5761_rtcp_packet_types_go_to_rtcp      |
    // | 4           | M=1 with PT outside 64-95 stays RTP    | rfc5761_marker_outside_rtcp_range_is_rtp  |
    // | 4           | Not well-formed RTCP falls back to RTP | rfc5761_invalid_rtcp_falls_back_to_rtp    |

    /// Build a minimal RTP header (12 bytes): V=2, P=0, X=0, CC=0, M=0, PT=0.
    fn minimal_rtp_header(pt: u8, seq: u16, ts: u32, ssrc: u32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        // byte 0: V=2, P=0, X=0, CC=0
        buf.push(0x80);
        // byte 1: M=0, PT
        buf.push(pt & 0x7F);
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&ts.to_be_bytes());
        buf.extend_from_slice(&ssrc.to_be_bytes());
        buf
    }

    #[test]
    fn parse_rtp_basic() {
        let data = minimal_rtp_header(111, 1000, 160_000, 0x12345678);
        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        // RFC 3550, Section 5.1 — the RTP layer claims the full packet (no
        // payload here, so bytes_consumed equals the fixed header size).
        assert_eq!(result.bytes_consumed, 12);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(buf.layers().len(), 1);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "RTP");
        assert_eq!(layer.range, 0..12);
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "padding").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "extension").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "csrc_count").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "marker").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "payload_type").unwrap().value,
            FieldValue::U8(111)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_number").unwrap().value,
            FieldValue::U16(1000)
        );
        assert_eq!(
            buf.field_by_name(layer, "timestamp").unwrap().value,
            FieldValue::U32(160_000)
        );
        assert_eq!(
            buf.field_by_name(layer, "ssrc").unwrap().value,
            FieldValue::U32(0x12345678)
        );
        assert!(buf.field_by_name(layer, "csrc_list").is_none());
    }

    #[test]
    fn parse_rtp_with_padding() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set P=1
        data[0] |= 0x20;
        // Append payload + padding: 4 bytes audio data + 4 bytes padding (last byte = count)
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // payload
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // 4 bytes padding, count=4

        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        // RFC 3550, Section 5.1 — layer covers the entire RTP packet (header,
        // payload, and padding). The padding_length field sits inside it.
        assert_eq!(result.bytes_consumed, 20);
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 0..20);
        assert_eq!(
            buf.field_by_name(layer, "padding").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "payload").unwrap().value,
            FieldValue::Bytes(&[0xAA, 0xBB, 0xCC, 0xDD])
        );
        assert_eq!(buf.field_by_name(layer, "payload").unwrap().range, 12..16);
        assert_eq!(
            buf.field_by_name(layer, "padding_length").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            buf.field_by_name(layer, "padding_length").unwrap().range,
            19..20
        );
    }

    #[test]
    fn parse_rtp_with_payload() {
        // Fixed header + payload (no padding, no CSRC, no extension).
        let mut data = minimal_rtp_header(96, 1, 100, 0xDEADBEEF);
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]);

        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        // RFC 3550, Section 5.1 — the RTP packet comprises header + payload;
        // the dissector consumes the whole packet.
        assert_eq!(result.bytes_consumed, 17);
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 0..17);
        assert_eq!(
            buf.field_by_name(layer, "payload").unwrap().value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05])
        );
        assert_eq!(buf.field_by_name(layer, "payload").unwrap().range, 12..17);
        assert!(buf.field_by_name(layer, "padding_length").is_none());
    }

    #[test]
    fn parse_rtp_padding_only_no_payload_data() {
        // P=1 with padding bytes only (no real payload). Valid per RFC 3550.
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        data[0] |= 0x20;
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // 4-byte padding, count=4

        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 16);
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 0..16);
        // No payload bytes between the header and the padding.
        assert!(buf.field_by_name(layer, "payload").is_none());
        assert_eq!(
            buf.field_by_name(layer, "padding_length").unwrap().value,
            FieldValue::U8(4)
        );
    }

    #[test]
    fn parse_rtp_padding_no_payload() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set P=1 but no trailing bytes
        data[0] |= 0x20;
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(err, PacketError::InvalidHeader(_)),
            "expected InvalidHeader for P=1 with no payload, got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_padding_count_zero() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        data[0] |= 0x20;
        // Last byte = 0 is invalid (count must include itself, so >= 1)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(err, PacketError::InvalidHeader(_)),
            "expected InvalidHeader for padding count 0, got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_padding_count_exceeds_payload() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        data[0] |= 0x20;
        // Only 2 bytes of payload but padding count says 10
        data.extend_from_slice(&[0x00, 0x0A]);
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(err, PacketError::InvalidHeader(_)),
            "expected InvalidHeader for excessive padding count, got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_marker_set() {
        let mut data = minimal_rtp_header(96, 500, 8000, 0x11223344);
        // Set M=1
        data[1] |= 0x80;
        let mut buf = DissectBuffer::new();
        RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "marker").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "payload_type").unwrap().value,
            FieldValue::U8(96)
        );
    }

    #[test]
    fn parse_rtp_with_csrc() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set CC=2
        data[0] = (data[0] & 0xF0) | 0x02;
        // Append 2 CSRC entries
        data.extend_from_slice(&0x11111111u32.to_be_bytes());
        data.extend_from_slice(&0x22222222u32.to_be_bytes());

        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 20); // 12 + 2*4
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 0..20);
        assert_eq!(
            buf.field_by_name(layer, "csrc_count").unwrap().value,
            FieldValue::U8(2)
        );

        let csrc_list = buf.field_by_name(layer, "csrc_list").unwrap();
        let range = match &csrc_list.value {
            FieldValue::Array(r) => r.clone(),
            _ => panic!("expected Array"),
        };
        let elements = buf.nested_fields(&range);
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0].value, FieldValue::U32(0x11111111));
        assert_eq!(elements[1].value, FieldValue::U32(0x22222222));
    }

    #[test]
    fn parse_rtp_with_extension() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set X=1
        data[0] |= 0x10;
        // Extension header: profile=0xBEDE, length=1 (1 × 32-bit word = 4 bytes)
        data.extend_from_slice(&0xBEDEu16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        // Extension data: 4 bytes
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 20); // 12 + 4 (ext header) + 4 (ext data)
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 0..20);
        assert_eq!(
            buf.field_by_name(layer, "extension").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "ext_profile").unwrap().value,
            FieldValue::U16(0xBEDE)
        );
        assert_eq!(
            buf.field_by_name(layer, "ext_length").unwrap().value,
            FieldValue::U16(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "ext_data").unwrap().value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04])
        );
        // RFC 8285, Section 4.1.2 — the first byte is ID 0 with a non-zero
        // length, so processing stops before any element and no
        // `ext_elements` array is emitted.
        // https://www.rfc-editor.org/rfc/rfc8285#section-4.1.2
        assert!(buf.field_by_name(layer, "ext_elements").is_none());
    }

    #[test]
    fn parse_rtp_zero_length_extension() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set X=1
        data[0] |= 0x10;
        // Extension header: profile=0x1234, length=0 (zero is valid per RFC 3550)
        data.extend_from_slice(&0x1234u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());

        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 16); // 12 + 4 (ext header only)
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "ext_profile").unwrap().value,
            FieldValue::U16(0x1234)
        );
        assert_eq!(
            buf.field_by_name(layer, "ext_length").unwrap().value,
            FieldValue::U16(0)
        );
        assert!(buf.field_by_name(layer, "ext_data").is_none());
    }

    #[test]
    fn parse_rtp_with_csrc_and_extension() {
        let mut data = minimal_rtp_header(8, 42, 320_000, 0xDEADBEEF);
        // Set CC=1, X=1
        data[0] = (data[0] & 0xE0) | 0x11; // V=2, P=0, X=1, CC=1
        // CSRC entry
        data.extend_from_slice(&0xCAFEBABEu32.to_be_bytes());
        // Extension header: profile=0xABCD, length=2
        data.extend_from_slice(&0xABCDu16.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes());
        // Extension data: 8 bytes
        data.extend_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);

        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();

        // 12 (fixed) + 4 (1 CSRC) + 4 (ext header) + 8 (ext data) = 28
        assert_eq!(result.bytes_consumed, 28);

        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 0..28);
        assert_eq!(
            buf.field_by_name(layer, "csrc_count").unwrap().value,
            FieldValue::U8(1)
        );
        let csrc_list = buf.field_by_name(layer, "csrc_list").unwrap();
        let range = match &csrc_list.value {
            FieldValue::Array(r) => r.clone(),
            _ => panic!("expected Array"),
        };
        let elements = buf.nested_fields(&range);
        assert_eq!(elements.len(), 1);
        assert_eq!(elements[0].value, FieldValue::U32(0xCAFEBABE));

        assert_eq!(
            buf.field_by_name(layer, "ext_profile").unwrap().value,
            FieldValue::U16(0xABCD)
        );
        assert_eq!(
            buf.field_by_name(layer, "ext_length").unwrap().value,
            FieldValue::U16(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "ext_data").unwrap().value,
            FieldValue::Bytes(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
        );
        // Profile 0xABCD is not an RFC 8285 form: no elements are decoded.
        assert!(buf.field_by_name(layer, "ext_elements").is_none());
    }

    /// Build an RTP packet with X=1 and the given extension profile and body.
    fn rtp_with_extension(profile: u16, body: &[u8]) -> Vec<u8> {
        assert_eq!(body.len() % 4, 0);
        let mut data = minimal_rtp_header(96, 1, 0, 0x1234_5678);
        data[0] |= 0x10;
        data.extend_from_slice(&profile.to_be_bytes());
        data.extend_from_slice(&((body.len() / 4) as u16).to_be_bytes());
        data.extend_from_slice(body);
        data.extend_from_slice(&[0xAA, 0xBB]); // payload
        data
    }

    /// `(id, length, data)` for each element of `ext_elements`.
    fn ext_elements<'a>(buf: &'a DissectBuffer<'a>) -> Vec<(u8, u8, &'a [u8])> {
        let layer = &buf.layers()[0];
        let FieldValue::Array(ref r) = buf.field_by_name(layer, "ext_elements").unwrap().value
        else {
            panic!("expected Array");
        };
        buf.nested_fields(r)
            .iter()
            .filter_map(|f| match &f.value {
                FieldValue::Object(o) => Some(o.clone()),
                _ => None,
            })
            .map(|o| {
                let fields = buf.nested_fields(&o);
                let get = |n: &str| fields.iter().find(|f| f.name() == n).unwrap().value.clone();
                let (FieldValue::U8(id), FieldValue::U8(len), FieldValue::Bytes(d)) =
                    (get("id"), get("length"), get("data"))
                else {
                    panic!("unexpected element field types");
                };
                (id, len, d)
            })
            .collect()
    }

    #[test]
    fn rfc8285_one_byte_single_element() {
        // Issue example: ID 1, L=0 (1 byte) data 0x7f, 2 padding bytes.
        let data = rtp_with_extension(0xBEDE, &[0x10, 0x7F, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        RtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(ext_elements(&buf), [(1, 1, &[0x7F][..])]);
        let layer = &buf.layers()[0];
        // ext_data is kept for existing filters.
        assert_eq!(
            buf.field_by_name(layer, "ext_data").unwrap().value,
            FieldValue::Bytes(&[0x10, 0x7F, 0x00, 0x00])
        );
        assert!(buf.field_by_name(layer, "ext_appbits").is_none());
        // Element ranges: object covers header + data, data covers 1 byte.
        let FieldValue::Array(ref r) = buf.field_by_name(layer, "ext_elements").unwrap().value
        else {
            panic!("expected Array");
        };
        let obj = buf
            .nested_fields(r)
            .iter()
            .find(|f| matches!(f.value, FieldValue::Object(_)))
            .unwrap();
        assert_eq!(obj.range, 16..18);
    }

    #[test]
    fn rfc8285_one_byte_two_elements_with_padding() {
        // ID 1 (2 bytes), padding byte, ID 2 (4 bytes), trailing padding.
        let data = rtp_with_extension(
            0xBEDE,
            &[
                0x11, 0xAA, 0xBB, 0x00, 0x23, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00,
            ],
        );
        let mut buf = DissectBuffer::new();
        RtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(
            ext_elements(&buf),
            [
                (1, 2, &[0xAA, 0xBB][..]),
                (2, 4, &[0x01, 0x02, 0x03, 0x04][..])
            ]
        );
    }

    #[test]
    fn rfc8285_one_byte_id15_terminates() {
        // ID 1, then ID 15 (length ignored), then bytes that must not be parsed.
        let data = rtp_with_extension(0xBEDE, &[0x10, 0x01, 0xFF, 0x35, 0x99, 0x00, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        RtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(ext_elements(&buf), [(1, 1, &[0x01][..])]);
    }

    #[test]
    fn rfc8285_one_byte_id0_nonzero_len_terminates() {
        let data = rtp_with_extension(0xBEDE, &[0x10, 0x01, 0x03, 0x20, 0x99, 0x00, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        RtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(ext_elements(&buf), [(1, 1, &[0x01][..])]);
    }

    #[test]
    fn rfc8285_two_byte_elements() {
        // appbits = 0x5; ID 1 L=0, ID 2 L=1 data 0x42, padding, ID 3 L=4 data.
        let data = rtp_with_extension(
            0x1005,
            &[
                0x01, 0x00, 0x02, 0x01, 0x42, 0x00, 0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
            ],
        );
        let mut buf = DissectBuffer::new();
        RtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(
            ext_elements(&buf),
            [
                (1, 0, &[][..]),
                (2, 1, &[0x42][..]),
                (3, 4, &[0xDE, 0xAD, 0xBE, 0xEF][..])
            ]
        );
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "ext_appbits").unwrap().value,
            FieldValue::U8(5)
        );
        // Fields follow the descriptor order: ... ext_data, ext_appbits,
        // ext_elements.
        let names: Vec<_> = buf.layer_fields(layer).iter().map(|f| f.name()).collect();
        let pos = |n: &str| names.iter().position(|x| *x == n).unwrap();
        assert!(pos("ext_length") < pos("ext_data"));
        assert!(pos("ext_data") < pos("ext_appbits"));
        assert!(pos("ext_appbits") < pos("ext_elements"));
    }

    #[test]
    fn rfc8285_element_overrun_keeps_raw() {
        // One-byte: ID 1 claims 16 bytes but only 3 remain. No error; the
        // raw bytes stay in ext_data.
        let data = rtp_with_extension(0xBEDE, &[0x1F, 0x01, 0x02, 0x03]);
        let mut buf = DissectBuffer::new();
        RtpDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "ext_elements").is_none());
        assert_eq!(
            buf.field_by_name(layer, "ext_data").unwrap().value,
            FieldValue::Bytes(&[0x1F, 0x01, 0x02, 0x03])
        );
        // Elements before the malformed one are kept.
        let data = rtp_with_extension(0xBEDE, &[0x10, 0x7F, 0x2F, 0x01]);
        let mut buf = DissectBuffer::new();
        RtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(ext_elements(&buf), [(1, 1, &[0x7F][..])]);
        // Two-byte: length octet missing at the end.
        let data = rtp_with_extension(0x1000, &[0x01, 0x01, 0xAA, 0x02]);
        let mut buf = DissectBuffer::new();
        RtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(ext_elements(&buf), [(1, 1, &[0xAA][..])]);
    }

    #[test]
    fn rfc8285_two_byte_id15_is_an_element() {
        // ID 15 terminates only the one-byte form (RFC 8285, Section 4.3 —
        // https://www.rfc-editor.org/rfc/rfc8285#section-4.3 allows IDs
        // 1-255).
        let data = rtp_with_extension(0x1000, &[0x0F, 0x01, 0x55, 0x00]);
        let mut buf = DissectBuffer::new();
        RtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(ext_elements(&buf), [(15, 1, &[0x55][..])]);
    }

    #[test]
    fn payload_type_names() {
        for (pt, name) in [
            (0, "PCMU"),
            (3, "GSM"),
            (4, "G723"),
            (5, "DVI4"),
            (6, "DVI4"),
            (7, "LPC"),
            (8, "PCMA"),
            (9, "G722"),
            (10, "L16"),
            (11, "L16"),
            (12, "QCELP"),
            (13, "CN"),
            (14, "MPA"),
            (15, "G728"),
            (16, "DVI4"),
            (17, "DVI4"),
            (18, "G729"),
            (25, "CelB"),
            (26, "JPEG"),
            (28, "nv"),
            (31, "H261"),
            (32, "MPV"),
            (33, "MP2T"),
            (34, "H263"),
            (96, "dynamic"),
            (127, "dynamic"),
        ] {
            assert_eq!(payload_type_name(pt), Some(name), "PT {pt}");
        }
        for pt in [1, 2, 19, 20, 24, 35, 72, 76, 95] {
            assert_eq!(payload_type_name(pt), None, "PT {pt}");
        }

        let data = minimal_rtp_header(0, 1, 0, 1);
        let mut buf = DissectBuffer::new();
        RtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "payload_type_name"),
            Some("PCMU")
        );
    }

    #[test]
    fn parse_rtp_truncated() {
        let data = [0x80, 0x00, 0x00]; // Only 3 bytes
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PacketError::Truncated {
                    expected: 12,
                    actual: 3
                }
            ),
            "expected Truncated, got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_invalid_version() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set version to 3
        data[0] = (3 << 6) | (data[0] & 0x3F);
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PacketError::InvalidFieldValue {
                    field: "version",
                    value: 3
                }
            ),
            "expected InvalidFieldValue for version, got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_truncated_csrc() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set CC=3 but don't add any CSRC data
        data[0] = (data[0] & 0xF0) | 0x03;
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PacketError::Truncated {
                    expected: 24,
                    actual: 12
                }
            ),
            "expected Truncated(24, 12), got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_truncated_extension_header() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set X=1 but don't add extension header bytes
        data[0] |= 0x10;
        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PacketError::Truncated {
                    expected: 16,
                    actual: 12
                }
            ),
            "expected Truncated(16, 12), got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_truncated_extension_data() {
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        // Set X=1
        data[0] |= 0x10;
        // Extension header: profile=0x0000, length=2 (needs 8 bytes of data)
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes());
        // Only add 4 bytes instead of 8
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let mut buf = DissectBuffer::new();
        let err = RtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PacketError::Truncated {
                    expected: 24,
                    actual: 20
                }
            ),
            "expected Truncated(24, 20), got {err:?}"
        );
    }

    #[test]
    fn parse_rtp_with_offset() {
        let mut data = vec![0xFF; 10]; // 10 bytes of prefix
        data.extend_from_slice(&minimal_rtp_header(96, 100, 3200, 0xABCDEF01));
        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data[10..], &mut buf, 10).unwrap();

        assert_eq!(result.bytes_consumed, 12);
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 10..22);
        assert_eq!(buf.field_by_name(layer, "ssrc").unwrap().range, 18..22);
    }

    #[test]
    fn parse_rtp_with_max_csrc() {
        // RFC 3550, Section 5.1 — CC is 4 bits, max 15 contributing sources.
        let mut data = minimal_rtp_header(0, 1, 100, 0xAABBCCDD);
        data[0] = (data[0] & 0xF0) | 0x0F; // CC=15
        for i in 0..15u32 {
            data.extend_from_slice(&(0x10_00_00_00 + i).to_be_bytes());
        }

        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 12 + 15 * 4);

        let layer = &buf.layers()[0];
        let csrc_list = buf.field_by_name(layer, "csrc_list").unwrap();
        let range = match &csrc_list.value {
            FieldValue::Array(r) => r.clone(),
            _ => panic!("expected Array"),
        };
        assert_eq!(buf.nested_fields(&range).len(), 15);
    }

    #[test]
    fn field_descriptors_complete() {
        let descriptors = RtpDissector.field_descriptors();
        assert_eq!(descriptors.len(), 17);
        assert_eq!(descriptors[15].name, "ext_appbits");
        assert!(descriptors[15].optional);
        assert_eq!(descriptors[16].name, "ext_elements");
        assert!(descriptors[16].optional);
        // Array children list the element fields directly, like other
        // dissectors' arrays of objects.
        let children: Vec<_> = descriptors[16]
            .children
            .unwrap()
            .iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(children, ["id", "length", "data"]);
        assert_eq!(descriptors[0].name, "version");
        assert_eq!(descriptors[9].name, "csrc_list");
        assert!(descriptors[9].optional);
        assert_eq!(descriptors[10].name, "payload");
        assert!(descriptors[10].optional);
        assert_eq!(descriptors[11].name, "padding_length");
        assert!(descriptors[11].optional);
        assert_eq!(descriptors[12].name, "ext_profile");
        assert!(descriptors[12].optional);
    }

    #[test]
    fn name_and_short_name() {
        assert_eq!(RtpDissector.name(), "Real-time Transport Protocol");
        assert_eq!(RtpDissector.short_name(), "RTP");
    }

    #[test]
    fn references_and_layer() {
        let references = RtpDissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(RtpDissector.layer(), Some(ProtocolLayer::Application));
    }

    #[test]
    fn rfc5761_rtcp_packet_types_go_to_rtcp() {
        // Minimal RR: V=2 RC=0, PT=201, length 1, SSRC — seen as RTP it would
        // be M=1, PT=73.
        let data = [0x80, 0xC9, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78];
        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(buf.layers().len(), 1);
        assert_eq!(buf.layers()[0].name, "RTCP");

        // Both ends of the RTCP range (192 and 223) are delegated too.
        for pt in [192u8, 223] {
            let data = [0x80, pt, 0x00, 0x00];
            let mut buf = DissectBuffer::new();
            RtpDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(buf.layers()[0].name, "RTCP", "octet 2 = {pt}");
        }
    }

    #[test]
    fn rfc5761_marker_outside_rtcp_range_is_rtp() {
        // M=1 with PT 63 (octet 2 = 191) and PT 96 (octet 2 = 224) are RTP.
        for byte1 in [0xBFu8, 0xE0] {
            let mut data = minimal_rtp_header(0, 1, 2, 3);
            data[1] = byte1;
            let mut buf = DissectBuffer::new();
            RtpDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert_eq!(layer.name, "RTP");
            assert_eq!(
                buf.field_by_name(layer, "marker").unwrap().value,
                FieldValue::U8(1)
            );
        }
    }

    #[test]
    fn rfc5761_invalid_rtcp_falls_back_to_rtp() {
        // M=1, PT=72 (octet 2 = 200 = SR) but the "length" (the RTP sequence
        // number) overruns the datagram, so it is not RTCP.
        let mut data = minimal_rtp_header(72, 0x1234, 2, 3);
        data[1] |= 0x80;
        let mut buf = DissectBuffer::new();
        let result = RtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 12);
        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "RTP");
        assert_eq!(
            buf.field_by_name(layer, "payload_type").unwrap().value,
            FieldValue::U8(72)
        );
    }
}
