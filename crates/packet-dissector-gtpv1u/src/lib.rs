//! GTPv1-U (GPRS Tunnelling Protocol User Plane) dissector.
//!
//! ## References
//! - 3GPP TS 29.281: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.281/>
//! - 3GPP TS 38.415 (PDU Session Container, PDU Set Information Container):
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.415/>
//! - 3GPP TS 38.425 (NR RAN Container):
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.425/>

#![deny(missing_docs)]

mod ext_header;
mod ie;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

use ext_header::{
    EXT_HEADER_FIELD_DESCRIPTORS, FD_EXT_COMPREHENSION, FD_EXT_LENGTH, FD_EXT_TYPE,
    gtpv1u_ext_header_type_name, push_ext_header_content,
};
#[cfg(test)]
use ie::gtpv1u_ie_type_name;

/// Specification references for the GTPv1-U dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "3GPP TS 29.281",
        "General Packet Radio System (GPRS) Tunnelling Protocol User Plane (GTPv1-U)",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.281/",
    ),
    SpecReference::new(
        "3GPP TS 38.415",
        "NG-RAN; PDU Session User Plane protocol",
        "https://www.3gpp.org/ftp/Specs/archive/38_series/38.415/",
    ),
    SpecReference::new(
        "3GPP TS 38.425",
        "NG-RAN; NR user plane protocol",
        "https://www.3gpp.org/ftp/Specs/archive/38_series/38.425/",
    ),
];

/// Map a GTPv1-U message type code to its name.
///
/// 3GPP TS 29.281, Section 6.1, Table 6.1-1 — GTP-U Message Types.
/// <https://www.3gpp.org/ftp/Specs/archive/29_series/29.281/>
fn gtpv1u_message_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Echo Request"),
        2 => Some("Echo Response"),
        26 => Some("Error Indication"),
        31 => Some("Supported Extension Headers Notification"),
        253 => Some("Tunnel Status"),
        254 => Some("End Marker"),
        255 => Some("G-PDU"),
        _ => None,
    }
}

/// Minimum GTP-U header size (mandatory fields only).
///
/// 3GPP TS 29.281, Section 5.1 — The GTP-U header is a variable length
/// header whose minimum length is 8 bytes.
const MIN_HEADER_SIZE: usize = 8;

/// Extended header size when any of E, S, or PN flags are set.
///
/// 3GPP TS 29.281, Section 5.1 — If and only if one or more of these three
/// flags are set, the fields Sequence Number, N-PDU and Extension Header
/// shall be present.
const EXTENDED_HEADER_SIZE: usize = 12;

/// GTP-U message type for G-PDU (user data).
///
/// 3GPP TS 29.281, Section 6.1, Table 6.1-1.
const MSG_TYPE_G_PDU: u8 = 255;

const FD_VERSION: usize = 0;
const FD_PT: usize = 1;
const FD_E: usize = 2;
const FD_S: usize = 3;
const FD_PN: usize = 4;
const FD_MESSAGE_TYPE: usize = 5;
const FD_LENGTH: usize = 6;
const FD_TEID: usize = 7;
const FD_SEQUENCE_NUMBER: usize = 8;
const FD_N_PDU_NUMBER: usize = 9;
const FD_NEXT_EXTENSION_HEADER_TYPE: usize = 10;
const FD_EXTENSION_HEADERS: usize = 11;
const FD_IES: usize = 12;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("pt", "Protocol Type", FieldType::U8),
    FieldDescriptor::new("e", "Extension Header Flag", FieldType::U8),
    FieldDescriptor::new("s", "Sequence Number Flag", FieldType::U8),
    FieldDescriptor::new("pn", "N-PDU Number Flag", FieldType::U8),
    FieldDescriptor {
        name: "message_type",
        display_name: "Message Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => gtpv1u_message_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("teid", "Tunnel Endpoint Identifier", FieldType::U32),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("n_pdu_number", "N-PDU Number", FieldType::U8).optional(),
    FieldDescriptor::new(
        "next_extension_header_type",
        "Next Extension Header Type",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("extension_headers", "Extension Headers", FieldType::Array).optional(),
    FieldDescriptor::new("ies", "Information Elements", FieldType::Array).optional(),
];

/// Container descriptor for a GTPv1-U extension header entry.
///
/// `display_fn` resolves the outer container's label to the extension header
/// type name (e.g. "PDU Session Container") by looking up the inner `type`
/// field.
static FD_EXTENSION_HEADER: FieldDescriptor = FieldDescriptor {
    name: "extension_header",
    display_name: "Extension Header",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => gtpv1u_ext_header_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// GTPv1-U dissector.
///
/// Parses GTP-U headers as defined in 3GPP TS 29.281. Supports the mandatory
/// 8-byte header, optional Sequence Number / N-PDU Number / Extension Header
/// fields, and extension header chains.
///
/// Extension header contents are decoded per type (3GPP TS 29.281,
/// Section 5.2.2), and the Information Elements of signalling messages are
/// decoded into an `ies` array (Section 8).
///
/// For G-PDU messages (type 255), the dissector dispatches to the inner IP
/// layer when the T-PDU looks like a complete IPv4 or IPv6 packet: the first
/// nibble selects the version and the IP length field must match the T-PDU
/// length. GTP-U does not signal the T-PDU type (Section 6.1 allows IP,
/// Ethernet and Unstructured T-PDUs), so any other T-PDU is left undecoded.
pub struct Gtpv1uDissector;

impl Dissector for Gtpv1uDissector {
    fn name(&self) -> &'static str {
        "GPRS Tunnelling Protocol User Plane"
    }

    fn short_name(&self) -> &'static str {
        "GTPv1-U"
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
        // 3GPP TS 29.281, Section 5.1 — minimum 8 bytes
        if data.len() < MIN_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // 3GPP TS 29.281, Section 5.1 — Octet 1: flags
        let version = (data[0] >> 5) & 0x07;
        let pt = (data[0] >> 4) & 0x01;
        let e_flag = (data[0] >> 2) & 0x01;
        let s_flag = (data[0] >> 1) & 0x01;
        let pn_flag = data[0] & 0x01;

        // 3GPP TS 29.281, Section 5.1 — "The version number shall be set to '1'."
        if version != 1 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: version as u32,
            });
        }

        // 3GPP TS 29.281, Section 5.1 — PT=1 for GTP, PT=0 for GTP'
        if pt != 1 {
            return Err(PacketError::InvalidFieldValue {
                field: "pt",
                value: pt as u32,
            });
        }

        // 3GPP TS 29.281, Section 5.1 — Octet 2: Message Type
        let message_type = data[1];

        // 3GPP TS 29.281, Section 5.1 — Octets 3-4: Length
        let length = read_be_u16(data, 2)?;

        // 3GPP TS 29.281, Section 5.1 — Octets 5-8: TEID
        let teid = read_be_u32(data, 4)?;

        let has_optional = e_flag != 0 || s_flag != 0 || pn_flag != 0;

        // Validate that we have enough data for the payload indicated by length.
        // Length covers everything after the first 8 mandatory bytes.
        let total_gtp_size = MIN_HEADER_SIZE + length as usize;
        if data.len() < total_gtp_size {
            return Err(PacketError::Truncated {
                expected: total_gtp_size,
                actual: data.len(),
            });
        }
        // 3GPP TS 29.281, Section 5.1 — "Length: This field indicates the
        // length in octets of the payload, i.e. the rest of the packet
        // following the mandatory part of the GTP header (that is the first
        // 8 octets). The Sequence Number, the N-PDU Number or any Extension
        // headers shall be considered to be part of the payload". Nothing
        // past the GTP-PDU belongs to it.
        let data = &data[..total_gtp_size];

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + MIN_HEADER_SIZE,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PT],
            FieldValue::U8(pt),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_E],
            FieldValue::U8(e_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_S],
            FieldValue::U8(s_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PN],
            FieldValue::U8(pn_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_TYPE],
            FieldValue::U8(message_type),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LENGTH],
            FieldValue::U16(length),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TEID],
            FieldValue::U32(teid),
            offset + 4..offset + 8,
        );

        // 3GPP TS 29.281, Section 5.1 — Optional fields present when any flag set
        let mut header_end = MIN_HEADER_SIZE;

        if has_optional {
            // `data` is bounded by Length and the input was at least
            // `total_gtp_size` octets long, so a short `data` means Length
            // does not cover the optional fields.
            if data.len() < EXTENDED_HEADER_SIZE {
                return Err(PacketError::InvalidHeader(
                    "GTPv1-U Length does not cover the optional header fields",
                ));
            }

            // 3GPP TS 29.281, Section 5.1 — Octets 9-10: Sequence Number
            let seq = read_be_u16(data, 8)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                FieldValue::U16(seq),
                offset + 8..offset + 10,
            );

            // 3GPP TS 29.281, Section 5.1 — Octet 11: N-PDU Number
            let n_pdu = data[10];
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_N_PDU_NUMBER],
                FieldValue::U8(n_pdu),
                offset + 10..offset + 11,
            );

            // 3GPP TS 29.281, Section 5.1 — Octet 12: Next Extension Header Type
            let next_ext_type = data[11];
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_NEXT_EXTENSION_HEADER_TYPE],
                FieldValue::U8(next_ext_type),
                offset + 11..offset + 12,
            );

            header_end = EXTENDED_HEADER_SIZE;

            // 3GPP TS 29.281, Section 5.2 — Parse extension header chain
            if e_flag != 0 && next_ext_type != 0 {
                let ext_range_start = offset + EXTENDED_HEADER_SIZE;
                let ext_array_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_EXTENSION_HEADERS],
                    FieldValue::Array(0..0),
                    ext_range_start..ext_range_start,
                );
                let ext_end = parse_extension_headers(buf, data, EXTENDED_HEADER_SIZE, offset)?;
                // Update the container range end
                if let Some(field) = buf.field_mut(ext_array_idx as usize) {
                    field.range = ext_range_start..offset + ext_end;
                }
                buf.end_container(ext_array_idx);
                header_end = ext_end;
            }
        }

        let (consumed, next) = if message_type == MSG_TYPE_G_PDU {
            // 3GPP TS 29.281, Section 6.1 — "In G-PDU message, GTP-U header
            // is followed by a T-PDU."
            (header_end, t_pdu_dispatch(&data[header_end..]))
        } else {
            // 3GPP TS 29.281, Sections 7 and 8 — signalling messages carry
            // TV / TLV Information Elements after the header.
            if header_end < data.len() {
                let ies_start = offset + header_end;
                let arr = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_IES],
                    FieldValue::Array(0..0),
                    ies_start..offset + data.len(),
                );
                ie::parse_ies(buf, &data[header_end..], ies_start);
                buf.end_container(arr);
            }
            (data.len(), DispatchHint::End)
        };

        if let Some(layer) = buf.last_layer_mut() {
            layer.range = offset..offset + consumed;
        }
        buf.end_layer();

        Ok(DissectResult::new(consumed, next))
    }
}

/// Parse a chain of GTP-U extension headers.
///
/// 3GPP TS 29.281, Section 5.2.1 — Each extension header has:
/// - Octet 1: Length in 4-octet units
/// - Octets 2..m: Content
/// - Octet m+1: Next Extension Header Type
///
/// Returns the parsed extension headers and the byte offset where the chain
/// ends (relative to the start of `data`).
fn parse_extension_headers<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    start: usize,
    packet_offset: usize,
) -> Result<usize, PacketError> {
    // 3GPP TS 29.281 does not specify a maximum chain length.
    // Cap at 64 to prevent infinite loops from malformed packets
    // where the next-type field points back into the chain.
    const MAX_EXT_HEADERS: usize = 64;

    let mut count = 0usize;
    let mut pos = start;

    // The next_ext_type for the first extension header was already read
    // from data[11]. We enter this function only when it's non-zero.
    let mut next_type = data[11];
    // Offset of the octet that carries `next_type`.
    let mut type_pos = 11;

    while next_type != 0 {
        if count >= MAX_EXT_HEADERS {
            return Err(PacketError::InvalidHeader(
                "GTPv1-U extension header chain exceeds maximum depth",
            ));
        }
        // 3GPP TS 29.281, Section 5.2.1 — need at least 4 bytes for
        // the minimum extension header (length=1 → 4 octets). `data` is
        // bounded by the GTP Length, so running past it means the Length
        // ends inside the extension header chain.
        if pos >= data.len() {
            return Err(PacketError::InvalidHeader(
                "GTPv1-U extension header chain exceeds the GTP Length",
            ));
        }

        // 3GPP TS 29.281, Section 5.2.1 — Extension Header Length
        let ext_len_units = data[pos] as usize;
        if ext_len_units == 0 {
            return Err(PacketError::InvalidHeader(
                "GTPv1-U extension header length must be > 0",
            ));
        }
        let ext_len_bytes = ext_len_units * 4;

        if pos + ext_len_bytes > data.len() {
            return Err(PacketError::InvalidHeader(
                "GTPv1-U extension header chain exceeds the GTP Length",
            ));
        }

        // Content is between length byte and the next extension header type byte
        let content_start = pos + 1;
        let content_end = pos + ext_len_bytes - 1;
        let content = &data[content_start..content_end];

        // Last byte is the Next Extension Header Type
        let next = data[pos + ext_len_bytes - 1];

        let obj_idx = buf.begin_container(
            &FD_EXTENSION_HEADER,
            FieldValue::Object(0..0),
            packet_offset + pos..packet_offset + pos + ext_len_bytes,
        );
        // The type is carried in the preceding Next Extension Header Type
        // octet (Section 5.2.1, Figure 5.2.1-1).
        buf.push_field(
            &EXT_HEADER_FIELD_DESCRIPTORS[FD_EXT_TYPE],
            FieldValue::U8(next_type),
            packet_offset + type_pos..packet_offset + type_pos + 1,
        );
        buf.push_field(
            &EXT_HEADER_FIELD_DESCRIPTORS[FD_EXT_LENGTH],
            FieldValue::U8(ext_len_units as u8),
            packet_offset + pos..packet_offset + pos + 1,
        );
        // Section 5.2.1, Figure 5.2.1-2 — bits 8 and 7 of the type
        buf.push_field(
            &EXT_HEADER_FIELD_DESCRIPTORS[FD_EXT_COMPREHENSION],
            FieldValue::U8(next_type >> 6),
            packet_offset + type_pos..packet_offset + type_pos + 1,
        );
        push_ext_header_content(buf, next_type, content, packet_offset + content_start);
        buf.end_container(obj_idx);

        next_type = next;
        type_pos = pos + ext_len_bytes - 1;
        pos += ext_len_bytes;
        count += 1;
    }

    Ok(pos)
}

/// Choose the dissector for a G-PDU's T-PDU.
///
/// 3GPP TS 29.281, Section 6.1 — "A T-PDU is an original packet, for example
/// an IP datagram, Ethernet frame or unstructured PDU Data". GTP-U does not
/// say which, so the T-PDU is sent to IPv4 / IPv6 only when its first nibble
/// is the IP version and the IP length field matches the T-PDU length.
fn t_pdu_dispatch(t_pdu: &[u8]) -> DispatchHint {
    let Some(&first) = t_pdu.first() else {
        return DispatchHint::End;
    };
    match first >> 4 {
        // RFC 791, Section 3.1 — Total Length is the length of the datagram
        // including header and data.
        // <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
        4 if read_be_u16(t_pdu, 2).is_ok_and(|len| usize::from(len) == t_pdu.len()) => {
            DispatchHint::ByEtherType(0x0800)
        }
        // RFC 8200, Section 3 — Payload Length is the length of the payload
        // following the 40-octet fixed header.
        // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
        6 if t_pdu.len() >= 40
            && read_be_u16(t_pdu, 4).is_ok_and(|len| usize::from(len) + 40 == t_pdu.len()) =>
        {
            DispatchHint::ByEtherType(0x86DD)
        }
        _ => DispatchHint::End,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::Field;

    // # 3GPP TS 29.281 / TS 38.415 / TS 38.425 Coverage
    //
    // | Section                     | Description                          | Test                                                       |
    // |-----------------------------|--------------------------------------|------------------------------------------------------------|
    // | TS 29.281 5.1               | Basic G-PDU (8-byte header)          | test_gpdu_basic                                            |
    // | TS 29.281 5.1               | G-PDU with optional fields           | test_gpdu_with_optional_fields                             |
    // | TS 29.281 5.1               | Version validation                   | test_invalid_version                                       |
    // | TS 29.281 5.1               | PT validation                        | test_invalid_pt                                            |
    // | TS 29.281 5.1               | Truncated header                     | test_truncated_header                                      |
    // | TS 29.281 5.1               | Truncated optional fields            | test_truncated_optional                                    |
    // | TS 29.281 5.1               | Length too short for optional fields | test_length_too_short_for_optional_fields                  |
    // | TS 29.281 5.1               | Echo Request (type 1)                | test_echo_request                                          |
    // | TS 29.281 5.1               | Length validation                    | test_length_exceeds_data                                   |
    // | TS 29.281 5.1               | Bytes after the GTP-PDU ignored      | test_trailing_bytes_after_gtp_pdu_are_ignored              |
    // | TS 29.281 5.1               | Non-zero packet offset               | test_with_nonzero_offset                                   |
    // | TS 29.281 5.2.1             | Extension header chain               | test_extension_headers                                     |
    // | TS 29.281 5.2.1             | Multiple extension headers           | test_multiple_extension_headers                            |
    // | TS 29.281 5.2.1             | Container label = type name          | extension_header_container_resolves_to_type_name           |
    // | TS 29.281 5.2.1             | Extension header truncated           | test_extension_header_truncated                            |
    // | TS 29.281 5.2.1             | Extension header zero length         | test_extension_header_zero_length                          |
    // | TS 29.281 5.2.1             | Length ends inside the chain         | test_length_ending_inside_extension_header_chain           |
    // | TS 29.281 5.2.1             | Fig. 5.2.1-2 comprehension bits      | test_comprehension_display_names                           |
    // | TS 29.281 5.2.1             | Fig. 5.2.1-3 type names              | test_ext_header_type_names                                 |
    // | TS 29.281 5.2.1             | Field display names                  | test_extension_header_field_display_names                  |
    // | TS 29.281 5.2.2.1           | UDP Port                             | test_error_indication_with_udp_port_extension_header       |
    // | TS 29.281 5.2.2.2           | PDCP PDU Number                      | test_pdcp_pdu_number                                       |
    // | TS 29.281 5.2.2.2A          | Long PDCP PDU Number                 | test_long_pdcp_pdu_number                                  |
    // | TS 29.281 5.2.2.3           | Service Class Indicator              | test_service_class_indicator                               |
    // | TS 29.281 5.2.2.4           | RAN Container (raw)                  | test_ran_container_is_raw                                  |
    // | TS 29.281 5.2.2.6           | NR RAN Container PDU Type            | test_nr_ran_container_pdu_type                             |
    // | TS 29.281 5.2.2.7           | PDU Session Container, no T-PDU      | test_pdu_session_container_ul_without_tpdu                 |
    // | TS 38.415 5.5.2.1           | DL PDU SESSION INFORMATION           | test_pdu_session_container_dl_ppi_and_sequence_number      |
    // | TS 38.415 5.5.2.1           | DL optional fields                   | test_pdu_session_container_dl_all_optional_fields          |
    // | TS 38.415 5.5.2.2           | UL optional fields / New IE Flags    | test_pdu_session_container_ul_all_optional_fields          |
    // | TS 38.415 5.5.2             | Short content falls back to raw      | test_pdu_session_container_short_content_falls_back_to_raw |
    // | TS 38.415 5.5.3.1           | Reserved PDU Type is raw             | test_pdu_session_container_unknown_pdu_type_is_raw         |
    // | TS 38.415 6.5.2.1           | PDU Set Information Container        | test_pdu_set_information_container                         |
    // | TS 38.415 5.5/6.5           | Short contents fall back to raw      | test_short_extension_contents_fall_back_to_raw             |
    // | TS 29.281 6.1               | G-PDU with IPv6 payload              | test_gpdu_ipv6_payload                                     |
    // | TS 29.281 6.1               | Non-IP T-PDU not sent to IP          | test_gpdu_ethernet_tpdu_not_sent_to_ip                     |
    // | TS 29.281 6.1               | End Marker (type 254)                | test_end_marker                                            |
    // | TS 29.281 6.1               | Message Type Name lookup             | test_message_type_name                                     |
    // | TS 29.281 7.3.1 / 8.3 / 8.4 | Error Indication IEs                 | test_error_indication_ies                                  |
    // | TS 29.281 7.2.2 / 8.2       | Echo Response Recovery               | test_echo_response_recovery                                |
    // | TS 29.281 7.2.3 / 8.5       | Extension Header Type List           | test_supported_extension_headers_notification              |
    // | TS 29.281 7.3.2 / 8.7 / 8.8 | Tunnel Status IEs                    | test_tunnel_status_ies                                     |
    // | TS 29.281 8.4 / 8.6         | IPv6 peer, Private Extension         | test_peer_address_ipv6_and_private_extension               |
    // | TS 29.281 8.1               | Malformed IE values kept raw         | test_ie_malformed_values_are_raw                           |
    // | TS 29.281 8.1               | Unknown TV / truncated IEs           | test_ie_unknown_tv_and_truncated_tlv_stop_parsing          |
    // | TS 29.281 8.1               | IE type names                        | test_ie_type_names                                         |
    // | —                           | References and layer                 | test_references_and_layer                                  |

    /// Minimal IPv4 header (20 bytes) whose Total Length (20) matches the
    /// T-PDU length, so the G-PDU dispatches to IPv4.
    const IPV4_STUB: [u8; 20] = [
        0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    /// Build a minimal G-PDU header (8 bytes) with an IPv4 payload stub.
    fn make_gpdu_basic() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Octet 1: Version=1, PT=1, Spare=0, E=0, S=0, PN=0
        // 001 1 0 0 0 0 = 0x30
        pkt.push(0x30);
        // Octet 2: Message Type = 255 (G-PDU)
        pkt.push(0xFF);
        // Octets 3-4: Length = 20 (IPv4 minimum header as payload)
        pkt.extend_from_slice(&20u16.to_be_bytes());
        // Octets 5-8: TEID = 0x12345678
        pkt.extend_from_slice(&0x12345678u32.to_be_bytes());
        // Payload: minimal IPv4 header stub (20 bytes, version nibble = 4)
        pkt.extend_from_slice(&IPV4_STUB);
        pkt
    }

    #[test]
    fn test_gpdu_basic() {
        let data = make_gpdu_basic();
        let mut buf = DissectBuffer::new();
        let dissector = Gtpv1uDissector;
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "GTPv1-U");
        assert_eq!(layer.range, 0..8);

        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "pt").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "e").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "s").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "pn").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "message_type").unwrap().value,
            FieldValue::U8(255)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("G-PDU")
        );
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U16(20)
        );
        assert_eq!(
            buf.field_by_name(layer, "teid").unwrap().value,
            FieldValue::U32(0x12345678)
        );
    }

    #[test]
    fn test_gpdu_with_optional_fields() {
        let mut pkt = Vec::new();
        // Octet 1: Version=1, PT=1, Spare=0, E=0, S=1, PN=0
        // 001 1 0 0 1 0 = 0x32
        pkt.push(0x32);
        // Message Type = 255 (G-PDU)
        pkt.push(0xFF);
        // Length = 24 (4 optional bytes + 20 payload)
        pkt.extend_from_slice(&24u16.to_be_bytes());
        // TEID
        pkt.extend_from_slice(&0xAABBCCDDu32.to_be_bytes());
        // Sequence Number = 0x0042
        pkt.extend_from_slice(&0x0042u16.to_be_bytes());
        // N-PDU Number = 0
        pkt.push(0x00);
        // Next Extension Header Type = 0 (no extensions)
        pkt.push(0x00);
        // Payload: minimal IPv4 stub
        pkt.extend_from_slice(&IPV4_STUB);

        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 12);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "s").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_number").unwrap().value,
            FieldValue::U16(0x0042)
        );
        assert_eq!(
            buf.field_by_name(layer, "n_pdu_number").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "next_extension_header_type")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn test_invalid_version() {
        let mut data = make_gpdu_basic();
        // Set version to 2: 010 1 0 0 0 0 = 0x50
        data[0] = 0x50;
        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidHeader(_) | PacketError::InvalidFieldValue { .. }
        ));
    }

    #[test]
    fn test_invalid_pt() {
        let mut data = make_gpdu_basic();
        // Set PT=0: 001 0 0 0 0 0 = 0x20
        data[0] = 0x20;
        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidHeader(_) | PacketError::InvalidFieldValue { .. }
        ));
    }

    #[test]
    fn test_truncated_header() {
        let data = vec![0x30, 0xFF, 0x00]; // only 3 bytes
        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { expected: 8, .. }));
    }

    #[test]
    fn test_truncated_optional() {
        let mut pkt = Vec::new();
        // S flag set → needs 12 bytes
        pkt.push(0x32);
        pkt.push(0xFF);
        pkt.extend_from_slice(&4u16.to_be_bytes()); // length=4
        pkt.extend_from_slice(&0u32.to_be_bytes()); // TEID
        // Only 8 bytes, but optional fields need 12
        // Add 4 bytes of payload so length field is satisfied
        // but optional fields are missing
        pkt.extend_from_slice(&[0u8; 4]);

        // Actually the length check passes (8+4=12), but we only have
        // the mandatory header. The data is exactly 12 bytes but the
        // optional field parsing should work. Let me construct a proper
        // truncated case: length says 4 bytes of payload but we don't
        // have enough bytes for the optional header.
        let mut pkt2 = Vec::new();
        pkt2.push(0x32); // S=1
        pkt2.push(0xFF);
        pkt2.extend_from_slice(&4u16.to_be_bytes()); // length=4
        pkt2.extend_from_slice(&0u32.to_be_bytes()); // TEID
        // 8 bytes total, need 12 for optional fields, but length says
        // total = 8+4=12 and we only have 8 bytes of data
        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&pkt2, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    #[test]
    fn test_echo_request() {
        let mut pkt = Vec::new();
        // Echo Request: Version=1, PT=1, S=1 (mandatory for Echo)
        // 001 1 0 0 1 0 = 0x32
        pkt.push(0x32);
        // Message Type = 1 (Echo Request)
        pkt.push(0x01);
        // Length = 4 (seq + npdu + next ext)
        pkt.extend_from_slice(&4u16.to_be_bytes());
        // TEID = 0 (for Echo Request)
        pkt.extend_from_slice(&0u32.to_be_bytes());
        // Sequence Number
        pkt.extend_from_slice(&0x0001u16.to_be_bytes());
        // N-PDU Number
        pkt.push(0x00);
        // Next Extension Header Type
        pkt.push(0x00);

        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 12);
        // Echo Request has no T-PDU payload → None
        assert_eq!(result.next, DispatchHint::End);

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "message_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("Echo Request")
        );
        assert_eq!(
            buf.field_by_name(layer, "teid").unwrap().value,
            FieldValue::U32(0)
        );
    }

    #[test]
    fn test_length_exceeds_data() {
        let mut pkt = Vec::new();
        pkt.push(0x30);
        pkt.push(0xFF);
        // Length = 100 but we provide very little data
        pkt.extend_from_slice(&100u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // TEID
        // Only 8 bytes total, length says 108

        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    #[test]
    fn test_extension_headers() {
        let mut pkt = Vec::new();
        // Version=1, PT=1, E=1
        // 001 1 0 1 0 0 = 0x34
        pkt.push(0x34);
        // Message Type = 255 (G-PDU)
        pkt.push(0xFF);
        // Length placeholder (will fix)
        let len_pos = pkt.len();
        pkt.extend_from_slice(&0u16.to_be_bytes());
        // TEID
        pkt.extend_from_slice(&0x11223344u32.to_be_bytes());
        // Sequence Number (present but not meaningful when only E set)
        pkt.extend_from_slice(&0u16.to_be_bytes());
        // N-PDU Number
        pkt.push(0x00);
        // Next Extension Header Type = 0x85 (PDU Session Container)
        pkt.push(0x85);

        // Extension header: PDU Session Container
        // Length = 1 (4 bytes total)
        pkt.push(0x01);
        // Content: 2 bytes
        pkt.extend_from_slice(&[0x00, 0x09]);
        // Next Extension Header Type = 0 (no more)
        pkt.push(0x00);

        // Payload: IPv4 stub
        pkt.extend_from_slice(&IPV4_STUB);

        // Fix length: everything after first 8 bytes
        let length = (pkt.len() - MIN_HEADER_SIZE) as u16;
        pkt[len_pos..len_pos + 2].copy_from_slice(&length.to_be_bytes());

        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        // Header: 12 base + 4 extension = 16
        assert_eq!(result.bytes_consumed, 16);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "e").unwrap().value,
            FieldValue::U8(1)
        );

        let ext_headers = buf.field_by_name(layer, "extension_headers").unwrap();
        let ext_range = ext_headers.value.as_container_range().unwrap();
        let elems = buf.nested_fields(ext_range);
        // One Object container
        assert!(elems[0].value.is_object());
        let obj_range = elems[0].value.as_container_range().unwrap();
        let ext = buf.nested_fields(obj_range);
        let ext_type = ext.iter().find(|f| f.name() == "type").unwrap();
        assert_eq!(ext_type.value, FieldValue::U8(0x85));
        // TS 38.415, Section 5.5.2.1 — DL PDU SESSION INFORMATION, QFI 9
        let pdu_type = ext.iter().find(|f| f.name() == "pdu_type").unwrap();
        assert_eq!(pdu_type.value, FieldValue::U8(0));
        let qfi = ext.iter().find(|f| f.name() == "qfi").unwrap();
        assert_eq!(qfi.value, FieldValue::U8(9));
        assert!(ext.iter().all(|f| f.name() != "content"));
    }

    #[test]
    fn extension_header_container_resolves_to_type_name() {
        let mut pkt = Vec::new();
        // Version=1, PT=1, E=1 → 0x34
        pkt.push(0x34);
        pkt.push(0xFF); // Message Type = G-PDU
        let len_pos = pkt.len();
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0x11223344u32.to_be_bytes()); // TEID
        pkt.extend_from_slice(&0u16.to_be_bytes()); // Sequence Number
        pkt.push(0x00); // N-PDU Number
        pkt.push(0x85); // Next Extension Header Type = PDU Session Container

        // Extension header: type carried via next-field above
        pkt.push(0x01); // Length = 1 (4 bytes)
        pkt.extend_from_slice(&[0x09, 0x00]); // content
        pkt.push(0x00); // Next Extension Header Type = 0

        // Payload: IPv4 stub
        pkt.extend_from_slice(&IPV4_STUB);

        let length = (pkt.len() - MIN_HEADER_SIZE) as u16;
        pkt[len_pos..len_pos + 2].copy_from_slice(&length.to_be_bytes());

        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let ext_headers = buf.field_by_name(layer, "extension_headers").unwrap();
        let ext_range = ext_headers.value.as_container_range().unwrap().clone();
        let elems = buf.nested_fields(&ext_range);
        let (offset, object) = elems
            .iter()
            .enumerate()
            .find(|(_, f)| matches!(f.value, FieldValue::Object(_)))
            .expect("extension header Object must be present");
        assert_eq!(object.descriptor.display_name, "Extension Header");
        let obj_idx = ext_range.start + offset as u32;
        assert_eq!(
            buf.resolve_container_display_name(obj_idx),
            Some("PDU Session Container"),
        );
    }

    #[test]
    fn test_extension_header_truncated() {
        let mut pkt = Vec::new();
        // E=1
        pkt.push(0x34);
        pkt.push(0xFF);
        // Length covers optional fields + extension header that exceeds data
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // TEID
        // Optional fields
        pkt.extend_from_slice(&0u16.to_be_bytes()); // seq
        pkt.push(0x00); // npdu
        pkt.push(0x85); // next ext type = 0x85

        // Extension header: length=2 (8 bytes) but only 2 bytes available
        pkt.push(0x02);
        pkt.push(0x00);
        // Missing 6 more bytes

        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    #[test]
    fn test_extension_header_zero_length() {
        let mut pkt = Vec::new();
        // E=1
        pkt.push(0x34);
        pkt.push(0xFF);
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.push(0x00);
        pkt.push(0x85); // next ext type

        // Extension header with length = 0 (invalid)
        pkt.push(0x00);
        pkt.extend_from_slice(&[0u8; 7]);

        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidHeader(_) | PacketError::InvalidFieldValue { .. }
        ));
    }

    #[test]
    fn test_gpdu_ipv6_payload() {
        let mut pkt = Vec::new();
        pkt.push(0x30); // no optional flags
        pkt.push(0xFF); // G-PDU
        pkt.extend_from_slice(&40u16.to_be_bytes()); // length = 40 (IPv6 header)
        pkt.extend_from_slice(&0xDEADBEEFu32.to_be_bytes()); // TEID
        // IPv6 stub: version nibble = 6
        pkt.push(0x60); // Version=6
        pkt.extend_from_slice(&[0u8; 39]);

        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn test_end_marker() {
        let mut pkt = Vec::new();
        // Version=1, PT=1, no flags
        pkt.push(0x30);
        // Message Type = 254 (End Marker)
        pkt.push(0xFE);
        // Length = 0 (no payload)
        pkt.extend_from_slice(&0u16.to_be_bytes());
        // TEID
        pkt.extend_from_slice(&0x00000001u32.to_be_bytes());

        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::End);

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "message_type").unwrap().value,
            FieldValue::U8(254)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("End Marker")
        );
    }

    #[test]
    fn test_message_type_name() {
        // Known types
        assert_eq!(gtpv1u_message_type_name(1), Some("Echo Request"));
        assert_eq!(gtpv1u_message_type_name(2), Some("Echo Response"));
        assert_eq!(gtpv1u_message_type_name(26), Some("Error Indication"));
        assert_eq!(
            gtpv1u_message_type_name(31),
            Some("Supported Extension Headers Notification")
        );
        assert_eq!(gtpv1u_message_type_name(253), Some("Tunnel Status"));
        assert_eq!(gtpv1u_message_type_name(254), Some("End Marker"));
        assert_eq!(gtpv1u_message_type_name(255), Some("G-PDU"));
        // Unknown types return None
        assert_eq!(gtpv1u_message_type_name(0), None);
        assert_eq!(gtpv1u_message_type_name(100), None);
    }

    #[test]
    fn test_multiple_extension_headers() {
        let mut pkt = Vec::new();
        // Version=1, PT=1, E=1
        pkt.push(0x34);
        pkt.push(0xFF); // G-PDU
        let len_pos = pkt.len();
        pkt.extend_from_slice(&0u16.to_be_bytes()); // length placeholder
        pkt.extend_from_slice(&0x00000001u32.to_be_bytes()); // TEID
        pkt.extend_from_slice(&0u16.to_be_bytes()); // seq
        pkt.push(0x00); // npdu
        pkt.push(0x85); // next ext type = PDU Session Container

        // First extension header (4 bytes)
        pkt.push(0x01); // length = 1 (4 bytes)
        pkt.extend_from_slice(&[0x01, 0x02]); // content
        pkt.push(0x40); // next ext type = UDP Port

        // Second extension header (4 bytes)
        pkt.push(0x01); // length = 1 (4 bytes)
        pkt.extend_from_slice(&[0xAB, 0xCD]); // content
        pkt.push(0x00); // no more

        // Payload: IPv4 stub
        pkt.extend_from_slice(&IPV4_STUB);

        // Fix length
        let length = (pkt.len() - MIN_HEADER_SIZE) as u16;
        pkt[len_pos..len_pos + 2].copy_from_slice(&length.to_be_bytes());

        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        // 12 base + 4 + 4 = 20
        assert_eq!(result.bytes_consumed, 20);

        let layer = &buf.layers()[0];
        let ext_headers = buf.field_by_name(layer, "extension_headers").unwrap();
        let ext_range = ext_headers.value.as_container_range().unwrap();
        let elems = buf.nested_fields(ext_range);
        let objs: Vec<_> = elems.iter().filter(|f| f.value.is_object()).collect();
        assert_eq!(objs.len(), 2);

        // First: type 0x85
        let first_range = objs[0].value.as_container_range().unwrap();
        let first = buf.nested_fields(first_range);
        assert_eq!(
            first.iter().find(|f| f.name() == "type").unwrap().value,
            FieldValue::U8(0x85)
        );
        // Second: type 0x40
        let second_range = objs[1].value.as_container_range().unwrap();
        let second = buf.nested_fields(second_range);
        assert_eq!(
            second.iter().find(|f| f.name() == "type").unwrap().value,
            FieldValue::U8(0x40)
        );
    }

    #[test]
    fn test_with_nonzero_offset() {
        // Simulate being called after Ethernet+IPv4+UDP headers
        let offset = 42; // typical Eth(14) + IPv4(20) + UDP(8)
        let data = make_gpdu_basic();
        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&data, &mut buf, offset).unwrap();

        assert_eq!(result.bytes_consumed, 8);
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 42..50);
        // Field ranges should be offset-adjusted
        assert_eq!(buf.field_by_name(layer, "version").unwrap().range, 42..43);
        assert_eq!(buf.field_by_name(layer, "teid").unwrap().range, 46..50);
    }

    #[test]
    fn test_references_and_layer() {
        let dissector = Gtpv1uDissector;
        let refs = dissector.references();
        assert!(!refs.is_empty());
        for r in refs {
            assert!(!r.id.is_empty());
            assert!(r.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Tunnel));
    }

    // -----------------------------------------------------------------------
    // Helpers for extension header / IE assertions
    // -----------------------------------------------------------------------

    /// Build a GTP-U PDU from `first_octet`, `message_type`, TEID 1 and the
    /// bytes following the mandatory header; Length is computed.
    fn make_pdu(first_octet: u8, message_type: u8, rest: &[u8]) -> Vec<u8> {
        let mut pkt = vec![first_octet, message_type];
        pkt.extend_from_slice(&(rest.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(rest);
        pkt
    }

    /// Build a G-PDU (E=1) carrying one extension header of `ext_type` whose
    /// Length is `units` and whose content is `content` (padded with zeros).
    fn make_gpdu_with_ext(ext_type: u8, units: u8, content: &[u8], tpdu: &[u8]) -> Vec<u8> {
        let mut rest = vec![0x00, 0x00, 0x00, ext_type, units];
        let content_len = units as usize * 4 - 2;
        let mut c = content.to_vec();
        c.resize(content_len, 0);
        rest.extend_from_slice(&c);
        rest.push(0x00); // no more extension headers
        rest.extend_from_slice(tpdu);
        make_pdu(0x34, 0xFF, &rest)
    }

    /// Return the child fields of the `idx`-th extension header object.
    fn ext_header<'a>(buf: &'a DissectBuffer<'a>, idx: usize) -> &'a [Field<'a>] {
        let layer = &buf.layers()[0];
        let arr = buf.field_by_name(layer, "extension_headers").unwrap();
        let elems = buf.nested_fields(arr.value.as_container_range().unwrap());
        let obj = elems
            .iter()
            .filter(|f| f.value.is_object())
            .nth(idx)
            .unwrap();
        buf.nested_fields(obj.value.as_container_range().unwrap())
    }

    /// Return the child fields of the `idx`-th IE object.
    fn ie<'a>(buf: &'a DissectBuffer<'a>, idx: usize) -> &'a [Field<'a>] {
        let layer = &buf.layers()[0];
        let arr = buf.field_by_name(layer, "ies").unwrap();
        let elems = buf.nested_fields(arr.value.as_container_range().unwrap());
        let obj = elems
            .iter()
            .filter(|f| f.value.is_object())
            .nth(idx)
            .unwrap();
        buf.nested_fields(obj.value.as_container_range().unwrap())
    }

    fn ie_count(buf: &DissectBuffer<'_>) -> usize {
        let layer = &buf.layers()[0];
        let arr = buf.field_by_name(layer, "ies").unwrap();
        buf.nested_fields(arr.value.as_container_range().unwrap())
            .iter()
            .filter(|f| f.value.is_object())
            .count()
    }

    fn get<'a>(fields: &'a [Field<'a>], name: &str) -> &'a FieldValue<'a> {
        &fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("field {name} missing"))
            .value
    }

    fn has(fields: &[Field<'_>], name: &str) -> bool {
        fields.iter().any(|f| f.name() == name)
    }

    // -----------------------------------------------------------------------
    // Extension headers (TS 29.281 Section 5.2)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pdu_session_container_ul_without_tpdu() {
        // TS 29.281 Section 5.2.2.7 — a G-PDU may carry only the container.
        let pkt = [
            0x34, 0xff, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x85, 0x01, 0x10,
            0x09, 0x00,
        ];
        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 16);
        assert_eq!(result.next, DispatchHint::End);

        let ext = ext_header(&buf, 0);
        assert_eq!(*get(ext, "type"), FieldValue::U8(0x85));
        // Bits 8-7 of 0x85 = '10'
        assert_eq!(*get(ext, "comprehension"), FieldValue::U8(2));
        assert_eq!(*get(ext, "pdu_type"), FieldValue::U8(1));
        assert_eq!(*get(ext, "qmp"), FieldValue::U8(0));
        assert_eq!(*get(ext, "dl_delay_ind"), FieldValue::U8(0));
        assert_eq!(*get(ext, "ul_delay_ind"), FieldValue::U8(0));
        assert_eq!(*get(ext, "snp"), FieldValue::U8(0));
        assert_eq!(*get(ext, "n3n9_delay_ind"), FieldValue::U8(0));
        assert_eq!(*get(ext, "new_ie_flag"), FieldValue::U8(0));
        assert_eq!(*get(ext, "qfi"), FieldValue::U8(9));
        assert!(!has(ext, "content"));

        let layer = &buf.layers()[0];
        let arr = buf.field_by_name(layer, "extension_headers").unwrap();
        let range = arr.value.as_container_range().unwrap();
        let pdu_type_idx = buf
            .nested_fields(range)
            .iter()
            .position(|f| f.name() == "pdu_type")
            .unwrap();
        let pdu_type = &buf.nested_fields(range)[pdu_type_idx];
        assert_eq!(pdu_type.range, 13..14);
    }

    #[test]
    fn test_pdu_session_container_dl_ppi_and_sequence_number() {
        // TS 38.415 Section 5.5.2.1: PDU type 0, SNP=1; PPP=1, RQI=1, QFI=5;
        // PPI=3; DL QFI Sequence Number = 0x000102.
        let content = [0x04, 0xC5, 0x60, 0x00, 0x01, 0x02];
        let pkt = make_gpdu_with_ext(0x85, 2, &content, &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let ext = ext_header(&buf, 0);
        assert_eq!(*get(ext, "pdu_type"), FieldValue::U8(0));
        assert_eq!(*get(ext, "qmp"), FieldValue::U8(0));
        assert_eq!(*get(ext, "snp"), FieldValue::U8(1));
        assert_eq!(*get(ext, "msnp"), FieldValue::U8(0));
        assert_eq!(*get(ext, "ppp"), FieldValue::U8(1));
        assert_eq!(*get(ext, "rqi"), FieldValue::U8(1));
        assert_eq!(*get(ext, "qfi"), FieldValue::U8(5));
        assert_eq!(*get(ext, "ppi"), FieldValue::U8(3));
        assert_eq!(*get(ext, "bssi"), FieldValue::U8(0));
        assert_eq!(*get(ext, "ttnbi"), FieldValue::U8(0));
        assert_eq!(
            *get(ext, "dl_qfi_sequence_number"),
            FieldValue::U32(0x000102)
        );
        assert!(!has(ext, "dl_sending_time_stamp"));
    }

    #[test]
    fn test_pdu_session_container_dl_all_optional_fields() {
        // QMP=1, SNP=1, MSNP=1; PPP=1, QFI=1; octet 3: PPI=0, BSSI=1, TTNBI=1
        let mut content = vec![0x0E, 0x81, 0x03];
        content.extend_from_slice(&0x0102030405060708u64.to_be_bytes()); // DL Sending TS
        content.extend_from_slice(&[0x00, 0x00, 0x07]); // DL QFI SN
        content.extend_from_slice(&0x0A0B0C0Du32.to_be_bytes()); // DL MBS QFI SN
        content.extend_from_slice(&[0x01, 0x00, 0x00]); // BSSize
        content.extend_from_slice(&[0x00, 0x64]); // TTNB
        // 3+8+3+4+3+2 = 23 octets → Length 7 (26 octets incl. padding)
        let pkt = make_gpdu_with_ext(0x85, 7, &content, &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let ext = ext_header(&buf, 0);
        assert_eq!(*get(ext, "bssi"), FieldValue::U8(1));
        assert_eq!(*get(ext, "ttnbi"), FieldValue::U8(1));
        assert_eq!(
            *get(ext, "dl_sending_time_stamp"),
            FieldValue::U64(0x0102030405060708)
        );
        assert_eq!(*get(ext, "dl_qfi_sequence_number"), FieldValue::U32(7));
        assert_eq!(
            *get(ext, "dl_mbs_qfi_sequence_number"),
            FieldValue::U32(0x0A0B0C0D)
        );
        assert_eq!(*get(ext, "burst_size"), FieldValue::U32(0x010000));
        assert_eq!(*get(ext, "time_to_next_burst"), FieldValue::U16(100));
    }

    #[test]
    fn test_pdu_session_container_ul_all_optional_fields() {
        // PDU type 1, QMP=1, DL Delay Ind=1, UL Delay Ind=1, SNP=1;
        // N3/N9 Delay Ind=1, New IE Flag=1, QFI=2.
        let mut content = vec![0x1F, 0xC2];
        content.extend_from_slice(&1u64.to_be_bytes()); // DL Sending TS Repeated
        content.extend_from_slice(&2u64.to_be_bytes()); // DL Received TS
        content.extend_from_slice(&3u64.to_be_bytes()); // UL Sending TS
        content.extend_from_slice(&10u32.to_be_bytes()); // DL Delay Result
        content.extend_from_slice(&11u32.to_be_bytes()); // UL Delay Result
        content.extend_from_slice(&[0x00, 0x01, 0x00]); // UL QFI SN
        content.extend_from_slice(&12u32.to_be_bytes()); // N3/N9 Delay Result
        content.push(0x1F); // New IE Flags: bits 0-4
        content.push(0x01); // D1 UL PDCP Delay Result Ind
        content.extend_from_slice(&9574u16.to_be_bytes()); // UL Congestion
        content.extend_from_slice(&100u16.to_be_bytes()); // DL Congestion
        content.extend_from_slice(&1000u32.to_be_bytes()); // UL Available Bitrate
        content.extend_from_slice(&2000u32.to_be_bytes()); // DL Available Bitrate
        assert_eq!(content.len(), 55);
        let pkt = make_gpdu_with_ext(0x85, 15, &content, &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let ext = ext_header(&buf, 0);
        assert_eq!(*get(ext, "pdu_type"), FieldValue::U8(1));
        assert_eq!(*get(ext, "qfi"), FieldValue::U8(2));
        assert_eq!(
            *get(ext, "dl_sending_time_stamp_repeated"),
            FieldValue::U64(1)
        );
        assert_eq!(*get(ext, "dl_received_time_stamp"), FieldValue::U64(2));
        assert_eq!(*get(ext, "ul_sending_time_stamp"), FieldValue::U64(3));
        assert_eq!(*get(ext, "dl_delay_result"), FieldValue::U32(10));
        assert_eq!(*get(ext, "ul_delay_result"), FieldValue::U32(11));
        assert_eq!(*get(ext, "ul_qfi_sequence_number"), FieldValue::U32(0x100));
        assert_eq!(*get(ext, "n3n9_delay_result"), FieldValue::U32(12));
        assert_eq!(*get(ext, "new_ie_flags"), FieldValue::U8(0x1F));
        assert_eq!(*get(ext, "d1_ul_pdcp_delay_result_ind"), FieldValue::U8(1));
        assert_eq!(
            *get(ext, "ul_congestion_information"),
            FieldValue::U16(9574)
        );
        assert_eq!(*get(ext, "dl_congestion_information"), FieldValue::U16(100));
        assert_eq!(*get(ext, "ul_available_bitrate"), FieldValue::U32(1000));
        assert_eq!(*get(ext, "dl_available_bitrate"), FieldValue::U32(2000));
    }

    #[test]
    fn test_pdu_session_container_short_content_falls_back_to_raw() {
        // DL with QMP=1 needs 8 more octets than a Length-1 header carries.
        let pkt = make_gpdu_with_ext(0x85, 1, &[0x08, 0x01], &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let ext = ext_header(&buf, 0);
        assert_eq!(*get(ext, "content"), FieldValue::Bytes(&[0x08, 0x01]));
        assert!(!has(ext, "qfi"));

        // UL with New IE Flag=1 but no New IE Flags octet.
        let pkt = make_gpdu_with_ext(0x85, 1, &[0x10, 0x41], &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert!(has(ext_header(&buf, 0), "content"));

        // UL whose New IE Flags demand octets that are absent.
        let pkt = make_gpdu_with_ext(0x85, 1, &[0x10, 0x41], &[]);
        let mut pkt2 = pkt.clone();
        // Length 2: content = 10 41 1E 00 00 00 (flags 0x1E need 12 octets)
        pkt2.truncate(12);
        pkt2.extend_from_slice(&[0x02, 0x10, 0x41, 0x1E, 0, 0, 0, 0x00]);
        let len = (pkt2.len() - 8) as u16;
        pkt2[2..4].copy_from_slice(&len.to_be_bytes());
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt2, &mut buf, 0).unwrap();
        assert!(has(ext_header(&buf, 0), "content"));
    }

    #[test]
    fn test_pdu_session_container_unknown_pdu_type_is_raw() {
        let pkt = make_gpdu_with_ext(0x85, 1, &[0x20, 0x01], &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let ext = ext_header(&buf, 0);
        assert_eq!(*get(ext, "content"), FieldValue::Bytes(&[0x20, 0x01]));
    }

    #[test]
    fn test_pdcp_pdu_number() {
        // TS 29.281 Section 5.2.2.2
        let pkt = make_gpdu_with_ext(0xC0, 1, &[0x12, 0x34], &IPV4_STUB);
        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
        let ext = ext_header(&buf, 0);
        assert_eq!(*get(ext, "comprehension"), FieldValue::U8(3));
        assert_eq!(*get(ext, "pdcp_pdu_number"), FieldValue::U16(0x1234));
    }

    #[test]
    fn test_long_pdcp_pdu_number() {
        // TS 29.281 Section 5.2.2.2A — 18-bit number, both type codes.
        for ext_type in [0x03, 0x82] {
            let content = [0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x00];
            let pkt = make_gpdu_with_ext(ext_type, 2, &content, &[]);
            let mut buf = DissectBuffer::new();
            Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
            let ext = ext_header(&buf, 0);
            assert_eq!(*get(ext, "long_pdcp_pdu_number"), FieldValue::U32(0x3FFFE));
        }
        // Wrong length falls back to raw content.
        let pkt = make_gpdu_with_ext(0x03, 1, &[0x01, 0x02], &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert!(has(ext_header(&buf, 0), "content"));
    }

    #[test]
    fn test_service_class_indicator() {
        // TS 29.281 Section 5.2.2.3
        let pkt = make_gpdu_with_ext(0x20, 1, &[0x85, 0x00], &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let ext = ext_header(&buf, 0);
        assert_eq!(*get(ext, "comprehension"), FieldValue::U8(0));
        assert_eq!(*get(ext, "service_class_indicator"), FieldValue::U8(0x85));
    }

    #[test]
    fn test_pdu_set_information_container() {
        // TS 38.415 Section 6.5.2.1: EDB=1, EPDU=1, PSSI=1; QFI=9, PSSN=0x2A5;
        // PSI=7; PSN=3; PSSize=0x000400. Both type codes.
        for ext_type in [0x04, 0x86] {
            let content = [0x0E, 0x26, 0xA5, 0x07, 0x03, 0x00, 0x04, 0x00];
            let pkt = make_gpdu_with_ext(ext_type, 3, &content, &[]);
            let mut buf = DissectBuffer::new();
            Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
            let ext = ext_header(&buf, 0);
            assert_eq!(*get(ext, "pdu_type"), FieldValue::U8(0));
            assert_eq!(*get(ext, "edb"), FieldValue::U8(1));
            assert_eq!(*get(ext, "epdu"), FieldValue::U8(1));
            assert_eq!(*get(ext, "pssi"), FieldValue::U8(1));
            assert_eq!(*get(ext, "qfi"), FieldValue::U8(9));
            assert_eq!(*get(ext, "pssn"), FieldValue::U16(0x2A5));
            assert_eq!(*get(ext, "psi"), FieldValue::U8(7));
            assert_eq!(*get(ext, "psn"), FieldValue::U8(3));
            assert_eq!(*get(ext, "pdu_set_size"), FieldValue::U32(0x400));
        }
        // PSSI=1 without room for PSSize falls back to raw.
        let content = [0x02, 0x24, 0x00, 0x00, 0x00, 0x00];
        let pkt = make_gpdu_with_ext(0x04, 2, &content, &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert!(has(ext_header(&buf, 0), "content"));
    }

    #[test]
    fn test_nr_ran_container_pdu_type() {
        // TS 38.425 Section 5.5.3.1 — PDU Type 1 (DL DATA DELIVERY STATUS)
        let pkt = make_gpdu_with_ext(0x84, 1, &[0x10, 0x00], &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let ext = ext_header(&buf, 0);
        assert_eq!(*get(ext, "nr_ran_pdu_type"), FieldValue::U8(1));
        assert_eq!(*get(ext, "content"), FieldValue::Bytes(&[0x10, 0x00]));
    }

    #[test]
    fn test_ran_container_is_raw() {
        let pkt = make_gpdu_with_ext(0x81, 1, &[0xAA, 0xBB], &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let ext = ext_header(&buf, 0);
        assert_eq!(*get(ext, "comprehension"), FieldValue::U8(2));
        assert_eq!(*get(ext, "content"), FieldValue::Bytes(&[0xAA, 0xBB]));
    }

    #[test]
    fn test_comprehension_display_names() {
        let pkt = make_gpdu_with_ext(0x40, 1, &[0x08, 0x68], &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let ext = ext_header(&buf, 0);
        let f = ext.iter().find(|f| f.name() == "comprehension").unwrap();
        let display = f.descriptor.display_fn.unwrap();
        for (v, expected) in [
            (0u8, "Comprehension not required; forward"),
            (
                1,
                "Comprehension not required; discard at Intermediate Node",
            ),
            (2, "Comprehension required by Endpoint Receiver"),
            (3, "Comprehension required by all recipients"),
        ] {
            assert_eq!(display(&FieldValue::U8(v), &[]), Some(expected));
        }
    }

    #[test]
    fn test_length_ending_inside_extension_header_chain() {
        // Length = 4 covers only the optional fields, but E=1 announces a
        // PDU Session Container that lies after the GTP-PDU.
        let pkt = [
            0x34, 0xff, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x85, 0x01, 0x10,
            0x09, 0x00,
        ];
        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn test_length_too_short_for_optional_fields() {
        // S=1 but Length = 0: the optional fields lie outside the GTP-PDU.
        let pkt = [
            0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x00,
        ];
        let mut buf = DissectBuffer::new();
        let err = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn test_trailing_bytes_after_gtp_pdu_are_ignored() {
        // End Marker (Length 0) followed by junk.
        let pkt = [0x30, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xDE, 0xAD];
        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "ies").is_none());
    }

    // -----------------------------------------------------------------------
    // T-PDU dispatch (TS 29.281 Section 6.1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_gpdu_ethernet_tpdu_not_sent_to_ip() {
        // Ethernet frame whose destination MAC starts with 0x45: the first
        // nibble looks like IPv4, but the IPv4 Total Length does not match.
        let mut tpdu = vec![0x45, 0x00, 0x5E, 0x00, 0x00, 0x01];
        tpdu.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00]);
        tpdu.extend_from_slice(&[0u8; 20]);
        let pkt = make_pdu(0x30, 0xFF, &tpdu);
        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::End);

        // IPv6 nibble with inconsistent Payload Length.
        let mut tpdu = vec![0x60, 0, 0, 0, 0x00, 0x10];
        tpdu.resize(40, 0);
        let pkt = make_pdu(0x30, 0xFF, &tpdu);
        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.next, DispatchHint::End);

        // Too short to be an IPv4 header.
        let pkt = make_pdu(0x30, 0xFF, &[0x45, 0x00]);
        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.next, DispatchHint::End);
    }

    // -----------------------------------------------------------------------
    // Signalling messages and IEs (TS 29.281 Sections 7 and 8)
    // -----------------------------------------------------------------------

    #[test]
    fn test_error_indication_ies() {
        let pkt = [
            0x32, 0x1a, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x01, 0x85, 0x00, 0x04, 0xc0, 0xa8, 0x00, 0x01,
        ];
        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 24);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(buf.layers()[0].range, 0..24);
        assert_eq!(ie_count(&buf), 2);

        let teid = ie(&buf, 0);
        assert_eq!(*get(teid, "type"), FieldValue::U8(16));
        assert!(!has(teid, "length"));
        assert_eq!(*get(teid, "teid_data_i"), FieldValue::U32(1));

        let peer = ie(&buf, 1);
        assert_eq!(*get(peer, "type"), FieldValue::U8(133));
        assert_eq!(*get(peer, "length"), FieldValue::U16(4));
        assert_eq!(
            *get(peer, "gtpu_peer_address"),
            FieldValue::Ipv4Addr([192, 168, 0, 1])
        );

        let layer = &buf.layers()[0];
        let arr = buf.field_by_name(layer, "ies").unwrap();
        let range = arr.value.as_container_range().unwrap().clone();
        let first_obj = buf
            .nested_fields(&range)
            .iter()
            .position(|f| f.value.is_object())
            .unwrap();
        assert_eq!(
            buf.resolve_container_display_name(range.start + first_obj as u32),
            Some("Tunnel Endpoint Identifier Data I")
        );
    }

    #[test]
    fn test_error_indication_with_udp_port_extension_header() {
        // TS 29.281 Section 5.2.2.1 — UDP Port 2152 carried in Error Indication
        let mut rest = vec![0x00, 0x00, 0x00, 0x40, 0x01, 0x08, 0x68, 0x00];
        rest.extend_from_slice(&[0x10, 0x00, 0x00, 0x00, 0x07]);
        let pkt = make_pdu(0x36, 26, &rest);
        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, pkt.len());
        let ext = ext_header(&buf, 0);
        assert_eq!(*get(ext, "udp_port"), FieldValue::U16(2152));
        assert_eq!(*get(ie(&buf, 0), "teid_data_i"), FieldValue::U32(7));
    }

    #[test]
    fn test_echo_response_recovery() {
        let pkt = [
            0x32, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x0e, 0x00,
        ];
        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 14);
        let rec = ie(&buf, 0);
        assert_eq!(*get(rec, "type"), FieldValue::U8(14));
        assert_eq!(*get(rec, "restart_counter"), FieldValue::U8(0));
        let layer = &buf.layers()[0];
        let arr = buf.field_by_name(layer, "ies").unwrap();
        assert_eq!(arr.range, 12..14);
    }

    #[test]
    fn test_supported_extension_headers_notification() {
        // TS 29.281 Section 8.5 — the one-octet Length is the number of types.
        let rest = [0x00, 0x00, 0x00, 0x00, 0x8D, 0x03, 0x85, 0x40, 0xC0];
        let pkt = make_pdu(0x32, 31, &rest);
        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, pkt.len());
        let list = ie(&buf, 0);
        assert_eq!(*get(list, "type"), FieldValue::U8(141));
        assert_eq!(*get(list, "length"), FieldValue::U16(3));
        let arr = list
            .iter()
            .find(|f| f.name() == "extension_header_types")
            .unwrap();
        let types: Vec<_> = buf
            .nested_fields(arr.value.as_container_range().unwrap())
            .iter()
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(
            types,
            vec![
                FieldValue::U8(0x85),
                FieldValue::U8(0x40),
                FieldValue::U8(0xC0)
            ]
        );
        let first = &buf.nested_fields(arr.value.as_container_range().unwrap())[0];
        assert_eq!(
            (first.descriptor.display_fn.unwrap())(&first.value, &[]),
            Some("PDU Session Container")
        );
    }

    #[test]
    fn test_tunnel_status_ies() {
        // Message type 253; GTP-U Tunnel Status Information (SPOC=1) and
        // Recovery Time Stamp.
        let rest = [
            0x00, 0x00, 0x00, 0x00, 0xE6, 0x00, 0x01, 0x01, 0xE7, 0x00, 0x04, 0xE8, 0x00, 0x00,
            0x01,
        ];
        let pkt = make_pdu(0x32, 253, &rest);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "message_type_name"),
            Some("Tunnel Status")
        );
        assert_eq!(*get(ie(&buf, 0), "spoc"), FieldValue::U8(1));
        assert_eq!(
            *get(ie(&buf, 1), "recovery_time_stamp"),
            FieldValue::U32(0xE8000001)
        );
    }

    #[test]
    fn test_peer_address_ipv6_and_private_extension() {
        let mut rest = vec![0x00, 0x00, 0x00, 0x00, 0x85, 0x00, 0x10];
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        rest.extend_from_slice(&addr);
        rest.extend_from_slice(&[0xFF, 0x00, 0x04, 0x00, 0x7B, 0xAA, 0xBB]);
        let pkt = make_pdu(0x32, 26, &rest);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            *get(ie(&buf, 0), "gtpu_peer_address"),
            FieldValue::Ipv6Addr(addr)
        );
        let pe = ie(&buf, 1);
        assert_eq!(*get(pe, "extension_identifier"), FieldValue::U16(123));
        assert_eq!(
            *get(pe, "extension_value"),
            FieldValue::Bytes(&[0xAA, 0xBB])
        );
    }

    #[test]
    fn test_ie_malformed_values_are_raw() {
        // Peer address of length 5, Tunnel Status of length 0, Recovery Time
        // Stamp of length 2, Private Extension of length 1, unknown TLV 232.
        let rest = [
            0x00, 0x00, 0x00, 0x00, // optional fields
            0x85, 0x00, 0x05, 1, 2, 3, 4, 5, // 133
            0xE6, 0x00, 0x00, // 230
            0xE7, 0x00, 0x02, 0x01, 0x02, // 231
            0xE8, 0x00, 0x01, 0x09, // 232 (spare)
            0xFF, 0x00, 0x01, 0x00, // 255
        ];
        let pkt = make_pdu(0x32, 26, &rest);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(ie_count(&buf), 5);
        assert_eq!(
            *get(ie(&buf, 0), "value"),
            FieldValue::Bytes(&[1, 2, 3, 4, 5])
        );
        assert_eq!(*get(ie(&buf, 1), "value"), FieldValue::Bytes(&[]));
        assert_eq!(*get(ie(&buf, 2), "value"), FieldValue::Bytes(&[1, 2]));
        assert_eq!(*get(ie(&buf, 3), "value"), FieldValue::Bytes(&[9]));
        assert_eq!(*get(ie(&buf, 4), "value"), FieldValue::Bytes(&[0]));
    }

    #[test]
    fn test_ie_unknown_tv_and_truncated_tlv_stop_parsing() {
        // Recovery, then TV type 2 (unknown length) → rest is raw.
        let rest = [0x00, 0x00, 0x00, 0x00, 0x0E, 0x05, 0x02, 0xAA, 0xBB];
        let pkt = make_pdu(0x32, 1, &rest);
        let mut buf = DissectBuffer::new();
        let result = Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, pkt.len());
        assert_eq!(ie_count(&buf), 2);
        assert_eq!(*get(ie(&buf, 0), "restart_counter"), FieldValue::U8(5));
        let unknown = ie(&buf, 1);
        assert_eq!(*get(unknown, "type"), FieldValue::U8(2));
        assert_eq!(*get(unknown, "value"), FieldValue::Bytes(&[0xAA, 0xBB]));

        // Truncated TV (TEID Data I needs 4 octets).
        let rest = [0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01];
        let pkt = make_pdu(0x32, 26, &rest);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(*get(ie(&buf, 0), "value"), FieldValue::Bytes(&[0x00, 0x01]));

        // TLV whose Length runs past the message.
        let rest = [0x00, 0x00, 0x00, 0x00, 0x85, 0x00, 0x10, 0x01];
        let pkt = make_pdu(0x32, 26, &rest);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let t = ie(&buf, 0);
        assert!(!has(t, "length"));
        assert_eq!(*get(t, "value"), FieldValue::Bytes(&[0x00, 0x10, 0x01]));

        // Extension Header Type List without its Length octet.
        let rest = [0x00, 0x00, 0x00, 0x00, 0x8D];
        let pkt = make_pdu(0x32, 31, &rest);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(*get(ie(&buf, 0), "value"), FieldValue::Bytes(&[]));
    }

    #[test]
    fn test_ie_type_names() {
        assert_eq!(gtpv1u_ie_type_name(14), Some("Recovery"));
        assert_eq!(
            gtpv1u_ie_type_name(16),
            Some("Tunnel Endpoint Identifier Data I")
        );
        assert_eq!(gtpv1u_ie_type_name(133), Some("GTP-U Peer Address"));
        assert_eq!(gtpv1u_ie_type_name(141), Some("Extension Header Type List"));
        assert_eq!(
            gtpv1u_ie_type_name(230),
            Some("GTP-U Tunnel Status Information")
        );
        assert_eq!(gtpv1u_ie_type_name(231), Some("Recovery Time Stamp"));
        assert_eq!(gtpv1u_ie_type_name(255), Some("Private Extension"));
        assert_eq!(gtpv1u_ie_type_name(1), None);
    }

    #[test]
    fn test_ext_header_type_names() {
        for t in [0x01, 0x02, 0xC1, 0xC2] {
            assert_eq!(
                gtpv1u_ext_header_type_name(t),
                Some("Reserved - Control Plane only")
            );
        }
        assert_eq!(
            gtpv1u_ext_header_type_name(0x03),
            Some("Long PDCP PDU Number")
        );
        assert_eq!(
            gtpv1u_ext_header_type_name(0x82),
            Some("Long PDCP PDU Number")
        );
        assert_eq!(
            gtpv1u_ext_header_type_name(0x04),
            Some("PDU Set Information Container")
        );
        assert_eq!(
            gtpv1u_ext_header_type_name(0x86),
            Some("PDU Set Information Container")
        );
        assert_eq!(gtpv1u_ext_header_type_name(0x05), None);
    }

    /// Resolve the display name of the child field `name` in `fields`.
    fn display(fields: &[Field<'_>], name: &str) -> Option<&'static str> {
        let f = fields.iter().find(|f| f.name() == name).unwrap();
        (f.descriptor.display_fn.unwrap())(&f.value, fields)
    }

    #[test]
    fn test_extension_header_field_display_names() {
        let cases: [(u8, &[u8], &str, &str, &str); 6] = [
            (
                0x85,
                &[0x00, 0x01],
                "pdu_type",
                "DL PDU SESSION INFORMATION",
                "PDU Session Container",
            ),
            (
                0x85,
                &[0x10, 0x01],
                "pdu_type",
                "UL PDU SESSION INFORMATION",
                "PDU Session Container",
            ),
            (
                0x84,
                &[0x20, 0x00],
                "nr_ran_pdu_type",
                "ASSISTANCE INFORMATION DATA",
                "NR RAN Container",
            ),
            (
                0x84,
                &[0x00, 0x00],
                "nr_ran_pdu_type",
                "DL USER DATA",
                "NR RAN Container",
            ),
            (
                0x40,
                &[0x08, 0x68],
                "comprehension",
                "Comprehension not required; discard at Intermediate Node",
                "UDP Port",
            ),
            (
                0xC0,
                &[0x00, 0x01],
                "comprehension",
                "Comprehension required by all recipients",
                "PDCP PDU Number",
            ),
        ];
        for (ext_type, content, field, expected, type_name) in cases {
            let pkt = make_gpdu_with_ext(ext_type, 1, content, &[]);
            let mut buf = DissectBuffer::new();
            Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
            let ext = ext_header(&buf, 0);
            assert_eq!(display(ext, field), Some(expected));
            assert_eq!(display(ext, "type"), Some(type_name));
        }

        let content = [0x00, 0x24, 0x00, 0x00, 0x00, 0x00];
        let pkt = make_gpdu_with_ext(0x04, 2, &content, &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let ext = ext_header(&buf, 0);
        assert_eq!(display(ext, "pdu_type"), Some("DL PDU SET INFORMATION"));

        for (t, name) in [
            (0x00, "No more extension headers"),
            (0x20, "Service Class Indicator"),
            (0x81, "RAN Container"),
            (0x83, "Xw RAN Container"),
        ] {
            assert_eq!(gtpv1u_ext_header_type_name(t), Some(name));
        }
    }

    #[test]
    fn test_short_extension_contents_fall_back_to_raw() {
        // DL PDU SESSION INFORMATION with PPP=1 but no PPI octet.
        let pkt = make_gpdu_with_ext(0x85, 1, &[0x00, 0x81], &[]);
        let mut buf = DissectBuffer::new();
        Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert!(has(ext_header(&buf, 0), "content"));

        // PDU Set Information Container shorter than its fixed part, and
        // with a reserved PDU Type.
        for content in [[0x00u8, 0x24], [0x10, 0x24]] {
            let pkt = make_gpdu_with_ext(0x04, 1, &content, &[]);
            let mut buf = DissectBuffer::new();
            Gtpv1uDissector.dissect(&pkt, &mut buf, 0).unwrap();
            assert!(has(ext_header(&buf, 0), "content"));
        }
    }
}
