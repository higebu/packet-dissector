//! Internet Key Exchange (IKE) dissector.
//!
//! Supports both IKEv1 (ISAKMP) and IKEv2 headers. They share the same
//! 28-byte header layout and are distinguished by the Major Version field.
//!
//! ## References
//! - RFC 2408: Internet Security Association and Key Management Protocol (ISAKMP):
//!   <https://www.rfc-editor.org/rfc/rfc2408>
//! - RFC 7296: Internet Key Exchange Protocol Version 2 (IKEv2):
//!   <https://www.rfc-editor.org/rfc/rfc7296>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// IKE header size: 28 bytes (fixed).
///
/// RFC 7296, Section 3.1: <https://www.rfc-editor.org/rfc/rfc7296#section-3.1>
/// RFC 2408, Section 3.1: <https://www.rfc-editor.org/rfc/rfc2408#section-3.1>
const HEADER_SIZE: usize = 28;

/// Generic Payload Header size: 4 bytes.
///
/// RFC 7296, Section 3.2: <https://www.rfc-editor.org/rfc/rfc7296#section-3.2>
const GENERIC_PAYLOAD_HEADER_SIZE: usize = 4;

/// Non-ESP marker size for NAT-T (4 bytes of zeros).
///
/// RFC 3948, Section 2.1: <https://www.rfc-editor.org/rfc/rfc3948#section-2.1>
const NON_ESP_MARKER_SIZE: usize = 4;

/// Returns a human-readable name for IKE exchange types.
///
/// IKEv1 exchange types: RFC 2408, Section 3.1
/// <https://www.rfc-editor.org/rfc/rfc2408#section-3.1>
///
/// IKEv2 exchange types: RFC 7296, Section 3.1
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.1>
fn exchange_type_name(v: u8) -> Option<&'static str> {
    match v {
        // IKEv1 / ISAKMP exchange types (RFC 2408, Section 3.1)
        0 => Some("None"),
        1 => Some("Base"),
        2 => Some("Identity Protection"),
        3 => Some("Authentication Only"),
        4 => Some("Aggressive"),
        5 => Some("Informational (v1)"),
        32 => Some("Quick Mode"),
        33 => Some("New Group Mode"),
        // IKEv2 exchange types (RFC 7296, Section 3.1)
        34 => Some("IKE_SA_INIT"),
        35 => Some("IKE_AUTH"),
        36 => Some("CREATE_CHILD_SA"),
        37 => Some("INFORMATIONAL"),
        _ => None,
    }
}

/// Returns a human-readable name for IKE payload types.
///
/// IKEv2 payload types: RFC 7296, Section 3.2
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.2>
fn payload_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("No Next Payload"),
        // IKEv1 payload types (RFC 2408, Section 3.1)
        1 => Some("Security Association (v1)"),
        2 => Some("Proposal (v1)"),
        3 => Some("Transform (v1)"),
        4 => Some("Key Exchange (v1)"),
        5 => Some("Identification (v1)"),
        6 => Some("Certificate (v1)"),
        7 => Some("Certificate Request (v1)"),
        8 => Some("Hash (v1)"),
        9 => Some("Signature (v1)"),
        10 => Some("Nonce (v1)"),
        11 => Some("Notification (v1)"),
        12 => Some("Delete (v1)"),
        13 => Some("Vendor ID (v1)"),
        // IKEv2 payload types (RFC 7296, Section 3.2)
        33 => Some("Security Association"),
        34 => Some("Key Exchange"),
        35 => Some("Identification - Initiator"),
        36 => Some("Identification - Responder"),
        37 => Some("Certificate"),
        38 => Some("Certificate Request"),
        39 => Some("Authentication"),
        40 => Some("Nonce"),
        41 => Some("Notify"),
        42 => Some("Delete"),
        43 => Some("Vendor ID"),
        44 => Some("Traffic Selector - Initiator"),
        45 => Some("Traffic Selector - Responder"),
        46 => Some("Encrypted and Authenticated"),
        47 => Some("Configuration"),
        48 => Some("Extensible Authentication Protocol"),
        _ => None,
    }
}

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_INITIATOR_SPI: usize = 0;
const FD_RESPONDER_SPI: usize = 1;
const FD_NEXT_PAYLOAD: usize = 2;
const FD_MAJOR_VERSION: usize = 3;
const FD_MINOR_VERSION: usize = 4;
const FD_EXCHANGE_TYPE: usize = 5;
const FD_FLAGS: usize = 6;
const FD_FLAG_INITIATOR: usize = 7;
const FD_FLAG_RESPONSE: usize = 8;
const FD_FLAG_VERSION: usize = 9;
const FD_MESSAGE_ID: usize = 10;
const FD_LENGTH: usize = 11;
const FD_PAYLOADS: usize = 12;

/// Child field descriptor indices for [`PAYLOAD_CHILDREN`].
const PFD_PAYLOAD_TYPE: usize = 0;
const PFD_CRITICAL: usize = 1;
const PFD_PAYLOAD_LENGTH: usize = 2;
const PFD_PAYLOAD_DATA: usize = 3;

/// Payload child field descriptors.
static PAYLOAD_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "payload_type",
        display_name: "Payload Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => payload_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("critical", "Critical", FieldType::U8),
    FieldDescriptor::new("payload_length", "Payload Length", FieldType::U16),
    FieldDescriptor::new("payload_data", "Payload Data", FieldType::Bytes).optional(),
];

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 7296, Section 3.1 — Initiator SPI
    // <https://www.rfc-editor.org/rfc/rfc7296#section-3.1>
    FieldDescriptor::new("initiator_spi", "Initiator SPI", FieldType::Bytes),
    // RFC 7296, Section 3.1 — Responder SPI
    FieldDescriptor::new("responder_spi", "Responder SPI", FieldType::Bytes),
    // RFC 7296, Section 3.1 — Next Payload
    FieldDescriptor {
        name: "next_payload",
        display_name: "Next Payload",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => payload_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    // RFC 7296, Section 3.1 — Major Version
    FieldDescriptor::new("major_version", "Major Version", FieldType::U8),
    // RFC 7296, Section 3.1 — Minor Version
    FieldDescriptor::new("minor_version", "Minor Version", FieldType::U8),
    // RFC 7296, Section 3.1 — Exchange Type
    FieldDescriptor {
        name: "exchange_type",
        display_name: "Exchange Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => exchange_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    // RFC 7296, Section 3.1 — Flags
    FieldDescriptor::new("flags", "Flags", FieldType::U8),
    // RFC 7296, Section 3.1 — Flag: Initiator (bit 3)
    FieldDescriptor::new("flag_initiator", "Initiator Flag", FieldType::U8),
    // RFC 7296, Section 3.1 — Flag: Response (bit 5)
    FieldDescriptor::new("flag_response", "Response Flag", FieldType::U8),
    // RFC 7296, Section 3.1 — Flag: Version (bit 6)
    FieldDescriptor::new("flag_version", "Version Flag", FieldType::U8),
    // RFC 7296, Section 3.1 — Message ID
    FieldDescriptor::new("message_id", "Message ID", FieldType::U32),
    // RFC 7296, Section 3.1 — Length
    FieldDescriptor::new("length", "Length", FieldType::U32),
    // RFC 7296, Section 3.2 — Payloads
    FieldDescriptor::new("payloads", "Payloads", FieldType::Array)
        .optional()
        .with_children(PAYLOAD_CHILDREN),
];

/// IKE dissector.
///
/// Parses the IKE header (28 bytes) shared by IKEv1 (ISAKMP, RFC 2408)
/// and IKEv2 (RFC 7296), plus the chain of generic payload headers.
pub struct IkeDissector;

impl Dissector for IkeDissector {
    fn name(&self) -> &'static str {
        "Internet Key Exchange"
    }

    fn short_name(&self) -> &'static str {
        "IKE"
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
        // Check for NAT-T Non-ESP marker (4 bytes of zeros on port 4500).
        // RFC 3948, Section 2.1: <https://www.rfc-editor.org/rfc/rfc3948#section-2.1>
        // "A non-ESP marker is 4 bytes of zero aligning with the SPI field
        //  of an ESP header."
        let (hdr_data, hdr_offset) =
            if data.len() >= NON_ESP_MARKER_SIZE + HEADER_SIZE && data[..4] == [0, 0, 0, 0] {
                (&data[NON_ESP_MARKER_SIZE..], offset + NON_ESP_MARKER_SIZE)
            } else {
                (data, offset)
            };

        if hdr_data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: hdr_data.len(),
            });
        }

        // RFC 7296, Section 3.1 — Initiator SPI (8 bytes)
        // <https://www.rfc-editor.org/rfc/rfc7296#section-3.1>
        let initiator_spi = &hdr_data[0..8];

        // RFC 7296, Section 3.1 — Responder SPI (8 bytes)
        let responder_spi = &hdr_data[8..16];

        // RFC 7296, Section 3.1 — Next Payload (1 byte)
        let next_payload = hdr_data[16];

        // RFC 7296, Section 3.1 — Version (1 byte: upper 4 = major, lower 4 = minor)
        let version_byte = hdr_data[17];
        let major_version = version_byte >> 4;
        let minor_version = version_byte & 0x0F;

        // RFC 7296, Section 3.1 — Exchange Type (1 byte)
        let exchange_type = hdr_data[18];

        // RFC 7296, Section 3.1 — Flags (1 byte)
        // <https://www.rfc-editor.org/rfc/rfc7296#section-3.1>
        // "  +-+-+-+-+-+-+-+-+
        //    |X|X|R|V|I|X|X|X|
        //    +-+-+-+-+-+-+-+-+"
        let flags = hdr_data[19];
        let flag_initiator = (flags >> 3) & 1;
        let flag_version = (flags >> 4) & 1;
        let flag_response = (flags >> 5) & 1;

        // RFC 7296, Section 3.1 — Message ID (4 bytes)
        let message_id = read_be_u32(hdr_data, 20)?;

        // RFC 7296, Section 3.1 — Length (4 bytes)
        // "Length of the total message (header + payloads) in octets."
        let length = read_be_u32(hdr_data, 24)?;

        if (length as usize) < HEADER_SIZE {
            return Err(PacketError::InvalidHeader(
                "IKE Length less than minimum header size",
            ));
        }

        let total_consumed = if hdr_offset > offset {
            // NAT-T marker was present
            core::cmp::min(length as usize, hdr_data.len()) + NON_ESP_MARKER_SIZE
        } else {
            core::cmp::min(length as usize, hdr_data.len())
        };

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_consumed,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_INITIATOR_SPI],
            FieldValue::Bytes(initiator_spi),
            hdr_offset..hdr_offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_RESPONDER_SPI],
            FieldValue::Bytes(responder_spi),
            hdr_offset + 8..hdr_offset + 16,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_NEXT_PAYLOAD],
            FieldValue::U8(next_payload),
            hdr_offset + 16..hdr_offset + 17,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MAJOR_VERSION],
            FieldValue::U8(major_version),
            hdr_offset + 17..hdr_offset + 18,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MINOR_VERSION],
            FieldValue::U8(minor_version),
            hdr_offset + 17..hdr_offset + 18,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_EXCHANGE_TYPE],
            FieldValue::U8(exchange_type),
            hdr_offset + 18..hdr_offset + 19,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAGS],
            FieldValue::U8(flags),
            hdr_offset + 19..hdr_offset + 20,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAG_INITIATOR],
            FieldValue::U8(flag_initiator),
            hdr_offset + 19..hdr_offset + 20,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAG_RESPONSE],
            FieldValue::U8(flag_response),
            hdr_offset + 19..hdr_offset + 20,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAG_VERSION],
            FieldValue::U8(flag_version),
            hdr_offset + 19..hdr_offset + 20,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_ID],
            FieldValue::U32(message_id),
            hdr_offset + 20..hdr_offset + 24,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LENGTH],
            FieldValue::U32(length),
            hdr_offset + 24..hdr_offset + 28,
        );

        // Parse generic payload chain (RFC 7296, Section 3.2)
        // <https://www.rfc-editor.org/rfc/rfc7296#section-3.2>
        let msg_len = core::cmp::min(length as usize, hdr_data.len());
        let payload_area = &hdr_data[HEADER_SIZE..msg_len];
        if !payload_area.is_empty() && next_payload != 0 {
            let array_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_PAYLOADS],
                FieldValue::Array(0..0),
                hdr_offset + HEADER_SIZE..hdr_offset + msg_len,
            );
            parse_payload_chain(buf, next_payload, payload_area, hdr_offset + HEADER_SIZE);
            buf.end_container(array_idx);
        }

        buf.end_layer();

        Ok(DissectResult::new(total_consumed, DispatchHint::End))
    }
}

/// Parse the chain of generic payload headers.
///
/// RFC 7296, Section 3.2: <https://www.rfc-editor.org/rfc/rfc7296#section-3.2>
///
/// Each generic payload header has:
/// - Next Payload (1 byte)
/// - Critical bit + Reserved (1 byte)
/// - Payload Length (2 bytes, includes the 4-byte header)
fn parse_payload_chain<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    first_payload_type: u8,
    data: &'pkt [u8],
    base_offset: usize,
) {
    let mut pos = 0;
    let mut current_type = first_payload_type;

    // Type 0 means "No Next Payload"
    while current_type != 0 && pos + GENERIC_PAYLOAD_HEADER_SIZE <= data.len() {
        let _next_payload = data[pos];
        // RFC 7296, Section 3.2 — Critical bit is the high bit of the second byte
        let critical = (data[pos + 1] >> 7) & 1;
        let payload_length = read_be_u16(data, pos + 2).unwrap_or_default() as usize;

        // Payload length includes the 4-byte header itself
        if payload_length < GENERIC_PAYLOAD_HEADER_SIZE {
            break;
        }

        // If payload extends beyond available data, clamp to what we have
        let end = core::cmp::min(pos + payload_length, data.len());
        let payload_offset = base_offset + pos;

        let obj_idx = buf.begin_container(
            &PAYLOAD_CHILDREN[PFD_PAYLOAD_TYPE],
            FieldValue::Object(0..0),
            payload_offset..base_offset + end,
        );

        buf.push_field(
            &PAYLOAD_CHILDREN[PFD_PAYLOAD_TYPE],
            FieldValue::U8(current_type),
            payload_offset..payload_offset + 1,
        );
        buf.push_field(
            &PAYLOAD_CHILDREN[PFD_CRITICAL],
            FieldValue::U8(critical),
            payload_offset + 1..payload_offset + 2,
        );
        buf.push_field(
            &PAYLOAD_CHILDREN[PFD_PAYLOAD_LENGTH],
            FieldValue::U16(payload_length as u16),
            payload_offset + 2..payload_offset + 4,
        );

        // Payload data (after the 4-byte generic header)
        if end > pos + GENERIC_PAYLOAD_HEADER_SIZE {
            buf.push_field(
                &PAYLOAD_CHILDREN[PFD_PAYLOAD_DATA],
                FieldValue::Bytes(&data[pos + GENERIC_PAYLOAD_HEADER_SIZE..end]),
                payload_offset + GENERIC_PAYLOAD_HEADER_SIZE..base_offset + end,
            );
        }

        buf.end_container(obj_idx);

        current_type = data[pos]; // next payload type from the current header
        pos += payload_length;
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 7296 (IKEv2) / RFC 2408 (ISAKMP) Coverage
    //!
    //! | RFC Section | Description              | Test                              |
    //! |-------------|--------------------------|-----------------------------------|
    //! | 3.1 (7296)  | IKE Header Format        | parse_ikev2_sa_init               |
    //! | 3.1 (7296)  | Version field            | parse_ikev2_sa_init               |
    //! | 3.1 (7296)  | Exchange Type            | parse_ikev2_sa_init               |
    //! | 3.1 (7296)  | Flags                    | parse_ikev2_response_flags        |
    //! | 3.1 (7296)  | Message ID               | parse_ikev2_sa_init               |
    //! | 3.1 (7296)  | Length                    | parse_ikev2_sa_init               |
    //! | 3.2 (7296)  | Generic Payload Header   | parse_ikev2_with_payloads         |
    //! | 3.1 (2408)  | ISAKMP Header (v1)       | parse_ikev1_header                |
    //! | —           | NAT-T Non-ESP marker     | parse_nat_t_with_marker           |
    //! | —           | Truncated header         | truncated_header                  |
    //! | —           | Invalid length           | invalid_length                    |
    //! | —           | Header only (no payload) | parse_header_only                 |

    use super::*;

    /// Build a minimal IKE header (28 bytes).
    #[allow(clippy::too_many_arguments)]
    fn make_ike_header(
        initiator_spi: &[u8; 8],
        responder_spi: &[u8; 8],
        next_payload: u8,
        major: u8,
        minor: u8,
        exchange_type: u8,
        flags: u8,
        message_id: u32,
        length: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(28);
        buf.extend_from_slice(initiator_spi);
        buf.extend_from_slice(responder_spi);
        buf.push(next_payload);
        buf.push((major << 4) | (minor & 0x0F));
        buf.push(exchange_type);
        buf.push(flags);
        buf.extend_from_slice(&message_id.to_be_bytes());
        buf.extend_from_slice(&length.to_be_bytes());
        buf
    }

    #[test]
    fn parse_ikev2_sa_init() {
        let data = make_ike_header(
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            &[0x00; 8],
            33, // SA payload
            2,  // IKEv2
            0,
            34,   // IKE_SA_INIT
            0x08, // Initiator flag
            0,
            28, // header only
        );

        let mut buf = DissectBuffer::new();
        let result = IkeDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 28);
        assert_eq!(result.next, DispatchHint::End);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "IKE");
        let fields = buf.layer_fields(layer);
        assert_eq!(
            buf.field_by_name(layer, "initiator_spi").unwrap().value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        );
        assert_eq!(
            buf.field_by_name(layer, "responder_spi").unwrap().value,
            FieldValue::Bytes(&[0x00; 8])
        );
        assert_eq!(
            buf.field_by_name(layer, "next_payload").unwrap().value,
            FieldValue::U8(33)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "next_payload_name"),
            Some("Security Association")
        );
        assert_eq!(
            buf.field_by_name(layer, "major_version").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "minor_version").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "exchange_type").unwrap().value,
            FieldValue::U8(34)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "exchange_type_name"),
            Some("IKE_SA_INIT")
        );
        assert_eq!(
            buf.field_by_name(layer, "flags").unwrap().value,
            FieldValue::U8(0x08)
        );
        assert_eq!(
            buf.field_by_name(layer, "flag_initiator").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flag_response").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "message_id").unwrap().value,
            FieldValue::U32(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U32(28)
        );
        // Suppress unused variable warning
        let _ = fields;
    }

    #[test]
    fn parse_ikev2_response_flags() {
        let data = make_ike_header(
            &[0x01; 8], &[0x02; 8], 0, // no payload
            2, 0, 34, 0x20, // Response flag
            1, 28,
        );

        let mut buf = DissectBuffer::new();
        IkeDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "flag_response").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flag_initiator").unwrap().value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_ikev1_header() {
        let data = make_ike_header(
            &[0xAA; 8], &[0xBB; 8], 1, // SA payload (v1)
            1, // IKEv1
            0, 2, // Identity Protection
            0, 0, 28,
        );

        let mut buf = DissectBuffer::new();
        let result = IkeDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 28);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "major_version").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "exchange_type_name"),
            Some("Identity Protection")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "next_payload_name"),
            Some("Security Association (v1)")
        );
    }

    #[test]
    fn parse_ikev2_with_payloads() {
        // Header with one SA payload (type 33), then one KE payload (type 34)
        let mut data = make_ike_header(
            &[0x01; 8],
            &[0x00; 8],
            33, // first payload = SA
            2,
            0,
            34, // IKE_SA_INIT
            0x08,
            0,
            28 + 8 + 8, // header + 2 payloads of 8 bytes each
        );

        // SA payload: next=34(KE), critical=0, length=8, data=[0xAA, 0xBB, 0xCC, 0xDD]
        data.extend_from_slice(&[34, 0x00, 0x00, 0x08, 0xAA, 0xBB, 0xCC, 0xDD]);
        // KE payload: next=0(none), critical=0, length=8, data=[0x11, 0x22, 0x33, 0x44]
        data.extend_from_slice(&[0, 0x00, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44]);

        let mut buf = DissectBuffer::new();
        let result = IkeDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 44);

        let layer = &buf.layers()[0];
        let payloads_field = buf.field_by_name(layer, "payloads").unwrap();
        if let FieldValue::Array(ref children_range) = payloads_field.value {
            let children = buf.nested_fields(children_range);
            // Two Object containers
            let objects: Vec<&_> = children
                .iter()
                .filter(|f| matches!(f.value, FieldValue::Object(_)))
                .collect();
            assert_eq!(objects.len(), 2);

            // First payload is SA (type 33)
            if let FieldValue::Object(ref obj_range) = objects[0].value {
                let obj_fields = buf.nested_fields(obj_range);
                let pt = obj_fields
                    .iter()
                    .find(|f| f.name() == "payload_type")
                    .unwrap();
                assert_eq!(pt.value, FieldValue::U8(33));
                let display = pt.descriptor.display_fn.unwrap()(&pt.value, &[]);
                assert_eq!(display, Some("Security Association"));
                let pd = obj_fields
                    .iter()
                    .find(|f| f.name() == "payload_data")
                    .unwrap();
                assert_eq!(pd.value, FieldValue::Bytes(&[0xAA, 0xBB, 0xCC, 0xDD]));
            } else {
                panic!("expected Object");
            }

            // Second payload is KE (type 34)
            if let FieldValue::Object(ref obj_range) = objects[1].value {
                let obj_fields = buf.nested_fields(obj_range);
                let pt = obj_fields
                    .iter()
                    .find(|f| f.name() == "payload_type")
                    .unwrap();
                assert_eq!(pt.value, FieldValue::U8(34));
            } else {
                panic!("expected Object");
            }
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn parse_nat_t_with_marker() {
        // NAT-T: 4 bytes of zeros + IKE header
        let mut data = vec![0x00, 0x00, 0x00, 0x00]; // Non-ESP marker
        data.extend_from_slice(&make_ike_header(
            &[0x01; 8], &[0x02; 8], 0, 2, 0, 34, 0x08, 0, 28,
        ));

        let mut buf = DissectBuffer::new();
        let result = IkeDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 32); // 4 (marker) + 28 (header)
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 0..32);
        // Header fields should reference offsets starting at 4 (after marker)
        assert_eq!(
            buf.field_by_name(layer, "initiator_spi").unwrap().range,
            4..12
        );
    }

    #[test]
    fn truncated_header() {
        let data = [0u8; 27]; // Less than 28 bytes
        let mut buf = DissectBuffer::new();
        let err = IkeDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 28,
                actual: 27
            }
        ));
    }

    #[test]
    fn invalid_length() {
        let data = make_ike_header(
            &[0x01; 8], &[0x02; 8], 0, 2, 0, 34, 0, 0, 10, // length < 28
        );

        let mut buf = DissectBuffer::new();
        let err = IkeDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_header_only() {
        let data = make_ike_header(
            &[0x01; 8], &[0x02; 8], 0, // No Next Payload
            2, 0, 37, // INFORMATIONAL
            0x20, 42, 28,
        );

        let mut buf = DissectBuffer::new();
        let result = IkeDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 28);
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "payloads").is_none());
        assert_eq!(
            buf.resolve_display_name(layer, "next_payload_name"),
            Some("No Next Payload")
        );
    }

    #[test]
    fn offset_applied_correctly() {
        let data = make_ike_header(&[0x01; 8], &[0x02; 8], 0, 2, 0, 34, 0, 0, 28);
        let mut buf = DissectBuffer::new();
        IkeDissector.dissect(&data, &mut buf, 200).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 200..228);
        assert_eq!(
            buf.field_by_name(layer, "initiator_spi").unwrap().range,
            200..208
        );
    }

    #[test]
    fn field_descriptors_match() {
        let descriptors = IkeDissector.field_descriptors();
        assert_eq!(descriptors.len(), 13);
        assert_eq!(descriptors[0].name, "initiator_spi");
        assert_eq!(descriptors[12].name, "payloads");
        assert!(descriptors[12].children.is_some());
    }

    #[test]
    fn unknown_exchange_type_no_name() {
        let data = make_ike_header(&[0x01; 8], &[0x02; 8], 0, 2, 0, 200, 0, 0, 28);
        let mut buf = DissectBuffer::new();
        IkeDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "exchange_type_name"),
            None
        );
    }

    #[test]
    fn payload_length_too_small() {
        // Payload with length < 4 (generic header size) should stop parsing
        let mut data = make_ike_header(&[0x01; 8], &[0x00; 8], 33, 2, 0, 34, 0x08, 0, 28 + 4);
        data.extend_from_slice(&[0, 0x00, 0x00, 0x02]); // length=2 < 4
        let mut buf = DissectBuffer::new();
        let result = IkeDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 32);
        // Payload chain should be empty due to invalid length
        // The array container was created but has no children since the payload
        // chain broke immediately. Check there are no payload objects.
        let layer = &buf.layers()[0];
        let payloads = buf.field_by_name(layer, "payloads");
        // The array was still created since next_payload != 0 and payload_area is non-empty,
        // but the chain parsing produced no objects, so it should be an empty array.
        if let Some(f) = payloads {
            if let FieldValue::Array(ref r) = f.value {
                assert_eq!(buf.nested_fields(r).len(), 0);
            }
        }
    }
}
