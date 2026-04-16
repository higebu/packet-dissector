//! L2TPv3 (Layer Two Tunneling Protocol — Version 3) dissector.
//!
//! Provides two dissectors:
//! - [`L2tpv3Dissector`] for L2TPv3 over IP (protocol 115)
//! - [`L2tpv3UdpDissector`] for L2TPv3 over UDP (port 1701)
//!
//! ## References
//! - RFC 3931: <https://www.rfc-editor.org/rfc/rfc3931>
//! - RFC 5641 (Circuit Status AVP extensions): <https://www.rfc-editor.org/rfc/rfc5641>
//! - RFC 9601 (ECN propagation): <https://www.rfc-editor.org/rfc/rfc9601>

#![deny(missing_docs)]

mod avp;
mod message_type;

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

use avp::AVP_CHILD_FIELDS;

/// Returns a human-readable name for an L2TPv3 control message type code.
///
/// RFC 3931, Section 3.1: <https://www.rfc-editor.org/rfc/rfc3931#section-3.1>
fn l2tpv3_message_type_name(code: u16) -> Option<&'static str> {
    let name = message_type::message_type_name(code);
    if name == "Unknown" { None } else { Some(name) }
}

// ---------------------------------------------------------------------------
// L2tpv3Dissector — L2TPv3 over IP (protocol 115)
// ---------------------------------------------------------------------------

/// Minimum data size: Session ID (4 bytes).
///
/// RFC 3931, Section 4.1.1 — L2TPv3 over IP always starts with a 32-bit
/// Session ID.
const IP_MIN_SIZE: usize = 4;

/// Control message header size when carried over IP: 4 bytes of zeros
/// (Session ID = 0) plus 12-byte control header (flags/version, length,
/// CCID, Ns, Nr).
///
/// RFC 3931, Section 4.1.1.2 — "L2TP over IP uses the reserved Session ID
/// of zero (0) when sending control messages."
const IP_CONTROL_HEADER_SIZE: usize = 16;

/// L2TPv3 version value.
///
/// RFC 3931, Section 3.2.1 — "Version MUST be set to 3."
const L2TPV3_VERSION: u8 = 3;

// Field descriptor indices for L2tpv3Dissector.
const IP_FD_SESSION_ID: usize = 0;
const IP_FD_IS_CONTROL: usize = 1;
const IP_FD_T_BIT: usize = 2;
const IP_FD_L_BIT: usize = 3;
const IP_FD_S_BIT: usize = 4;
const IP_FD_VERSION: usize = 5;
const IP_FD_LENGTH: usize = 6;
const IP_FD_CONTROL_CONNECTION_ID: usize = 7;
const IP_FD_NS: usize = 8;
const IP_FD_NR: usize = 9;
const IP_FD_MESSAGE_TYPE: usize = 10;
const IP_FD_AVPS: usize = 11;

static IP_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("session_id", "Session ID", FieldType::U32),
    FieldDescriptor::new("is_control", "Is Control", FieldType::U8),
    // Control-only fields (optional)
    FieldDescriptor::new("t_bit", "T Bit", FieldType::U8).optional(),
    FieldDescriptor::new("l_bit", "L Bit", FieldType::U8).optional(),
    FieldDescriptor::new("s_bit", "S Bit", FieldType::U8).optional(),
    FieldDescriptor::new("version", "Version", FieldType::U8).optional(),
    FieldDescriptor::new("length", "Length", FieldType::U16).optional(),
    FieldDescriptor::new(
        "control_connection_id",
        "Control Connection ID",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("ns", "Ns", FieldType::U16).optional(),
    FieldDescriptor::new("nr", "Nr", FieldType::U16).optional(),
    FieldDescriptor {
        name: "message_type",
        display_name: "Message Type",
        field_type: FieldType::U16,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(t) => l2tpv3_message_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("avps", "AVPs", FieldType::Array)
        .optional()
        .with_children(AVP_CHILD_FIELDS),
];

/// L2TPv3 over IP dissector (IP protocol 115).
///
/// RFC 3931, Section 4.1.1: <https://www.rfc-editor.org/rfc/rfc3931#section-4.1.1>
pub struct L2tpv3Dissector;

impl Dissector for L2tpv3Dissector {
    fn name(&self) -> &'static str {
        "Layer Two Tunneling Protocol v3"
    }

    fn short_name(&self) -> &'static str {
        "L2TPv3"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        IP_FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < IP_MIN_SIZE {
            return Err(PacketError::Truncated {
                expected: IP_MIN_SIZE,
                actual: data.len(),
            });
        }

        // RFC 3931, Section 4.1.1 — First 4 bytes: Session ID
        let session_id = read_be_u32(data, 0)?;

        if session_id != 0 {
            // Data message — Session ID is non-zero.
            // RFC 3931, Section 4.1.1.1 — Cookie size is negotiated
            // out-of-band and cannot be determined from the wire.
            buf.begin_layer(
                self.short_name(),
                None,
                IP_FIELD_DESCRIPTORS,
                offset..offset + IP_MIN_SIZE,
            );
            buf.push_field(
                &IP_FIELD_DESCRIPTORS[IP_FD_SESSION_ID],
                FieldValue::U32(session_id),
                offset..offset + 4,
            );
            buf.push_field(
                &IP_FIELD_DESCRIPTORS[IP_FD_IS_CONTROL],
                FieldValue::U8(0),
                offset..offset + 4,
            );
            buf.end_layer();

            return Ok(DissectResult::new(IP_MIN_SIZE, DispatchHint::End));
        }

        // Control message — Session ID == 0
        // RFC 3931, Section 4.1.1.2 — Control header follows the 4 zero bytes
        if data.len() < IP_CONTROL_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: IP_CONTROL_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 3931, Section 3.2.1 — Flags/Version word at bytes [4..6]
        let flags_ver = read_be_u16(data, 4)?;
        let t_bit = ((flags_ver >> 15) & 1) as u8;
        let l_bit = ((flags_ver >> 14) & 1) as u8;
        let s_bit = ((flags_ver >> 11) & 1) as u8;
        let version = (flags_ver & 0x000F) as u8;

        if version != L2TPV3_VERSION {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: version as u32,
            });
        }

        // RFC 3931, Section 3.2.1 — Length at bytes [6..8]
        let length = read_be_u16(data, 6)?;
        // RFC 3931, Section 3.2.1 — Control Connection ID at bytes [8..12]
        let ccid = read_be_u32(data, 8)?;
        // RFC 3931, Section 3.2.1 — Ns at bytes [12..14]
        let ns = read_be_u16(data, 12)?;
        // RFC 3931, Section 3.2.1 — Nr at bytes [14..16]
        let nr = read_be_u16(data, 14)?;

        // RFC 3931, Section 3.2.1 — the control header following the
        // flags/version field is 12 bytes (Length, CCID, Ns, Nr).
        if (length as usize) < IP_CONTROL_HEADER_SIZE - 4 {
            return Err(PacketError::InvalidHeader(
                "L2TPv3 control message length field smaller than minimum header size",
            ));
        }

        // Total message size: 4 (session_id zeros) + length (from Length field).
        // The Length field counts from the flags/version word, so the total
        // consumed bytes from the start of our data is 4 + length.
        let total_consumed = 4 + length as usize;
        if total_consumed > data.len() {
            return Err(PacketError::Truncated {
                expected: total_consumed,
                actual: data.len(),
            });
        }

        buf.begin_layer(
            self.short_name(),
            None,
            IP_FIELD_DESCRIPTORS,
            offset..offset + total_consumed,
        );
        buf.push_field(
            &IP_FIELD_DESCRIPTORS[IP_FD_SESSION_ID],
            FieldValue::U32(session_id),
            offset..offset + 4,
        );
        buf.push_field(
            &IP_FIELD_DESCRIPTORS[IP_FD_IS_CONTROL],
            FieldValue::U8(1),
            offset..offset + 4,
        );
        buf.push_field(
            &IP_FIELD_DESCRIPTORS[IP_FD_T_BIT],
            FieldValue::U8(t_bit),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &IP_FIELD_DESCRIPTORS[IP_FD_L_BIT],
            FieldValue::U8(l_bit),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &IP_FIELD_DESCRIPTORS[IP_FD_S_BIT],
            FieldValue::U8(s_bit),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &IP_FIELD_DESCRIPTORS[IP_FD_VERSION],
            FieldValue::U8(version),
            offset + 4..offset + 6,
        );
        buf.push_field(
            &IP_FIELD_DESCRIPTORS[IP_FD_LENGTH],
            FieldValue::U16(length),
            offset + 6..offset + 8,
        );
        buf.push_field(
            &IP_FIELD_DESCRIPTORS[IP_FD_CONTROL_CONNECTION_ID],
            FieldValue::U32(ccid),
            offset + 8..offset + 12,
        );
        buf.push_field(
            &IP_FIELD_DESCRIPTORS[IP_FD_NS],
            FieldValue::U16(ns),
            offset + 12..offset + 14,
        );
        buf.push_field(
            &IP_FIELD_DESCRIPTORS[IP_FD_NR],
            FieldValue::U16(nr),
            offset + 14..offset + 16,
        );

        // Parse AVPs from the body
        let avp_data = &data[IP_CONTROL_HEADER_SIZE..total_consumed];
        push_avp_fields(
            buf,
            avp_data,
            offset + IP_CONTROL_HEADER_SIZE,
            offset + total_consumed,
            &IP_FIELD_DESCRIPTORS[IP_FD_MESSAGE_TYPE],
            &IP_FIELD_DESCRIPTORS[IP_FD_AVPS],
        );

        buf.end_layer();

        Ok(DissectResult::new(total_consumed, DispatchHint::End))
    }
}

// ---------------------------------------------------------------------------
// Shared helper
// ---------------------------------------------------------------------------

/// Append message_type and avps fields to `fields`.
///
/// Both IP and UDP control paths share identical AVP field-building logic;
/// this helper avoids the duplication.
fn push_avp_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    avp_data: &'pkt [u8],
    avp_buf_start: usize,
    avps_end: usize,
    msg_type_fd: &'static FieldDescriptor,
    avps_fd: &'static FieldDescriptor,
) {
    if let Some(mt) = avp::extract_message_type(avp_data) {
        let mt_range = if avp_data.len() >= 8 {
            let mt_start = avp_buf_start + 6;
            mt_start..mt_start + 2
        } else {
            avp_buf_start..avp_buf_start + 2
        };
        buf.push_field(msg_type_fd, FieldValue::U16(mt), mt_range);
    }
    if !avp_data.is_empty() {
        let array_idx =
            buf.begin_container(avps_fd, FieldValue::Array(0..0), avp_buf_start..avps_end);
        avp::parse_avps(avp_data, avp_buf_start, buf);
        buf.end_container(array_idx);
    }
}

// ---------------------------------------------------------------------------
// L2tpv3UdpDissector — L2TPv3 over UDP (port 1701)
// ---------------------------------------------------------------------------

/// Minimum size for UDP variant: flags/version (2 bytes) + length or reserved
/// (2 bytes) = 4 bytes.
const UDP_MIN_SIZE: usize = 4;

/// Control header size for UDP variant: flags/version (2) + length (2) +
/// CCID (4) + Ns (2) + Nr (2) = 12 bytes.
///
/// RFC 3931, Section 4.1.2.2 — Control Connection over UDP
const UDP_CONTROL_HEADER_SIZE: usize = 12;

/// Data header size for UDP variant: flags/version (2) + reserved (2) +
/// Session ID (4) = 8 bytes.
///
/// RFC 3931, Section 4.1.2.1 — Session Header over UDP
const UDP_DATA_HEADER_SIZE: usize = 8;

// Field descriptor indices for L2tpv3UdpDissector.
const UDP_FD_T_BIT: usize = 0;
const UDP_FD_L_BIT: usize = 1;
const UDP_FD_S_BIT: usize = 2;
const UDP_FD_VERSION: usize = 3;
const UDP_FD_LENGTH: usize = 4;
const UDP_FD_CONTROL_CONNECTION_ID: usize = 5;
const UDP_FD_NS: usize = 6;
const UDP_FD_NR: usize = 7;
const UDP_FD_SESSION_ID: usize = 8;
const UDP_FD_MESSAGE_TYPE: usize = 9;
const UDP_FD_AVPS: usize = 10;

static UDP_FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("t_bit", "T Bit", FieldType::U8),
    // Control-only bits. In data messages the L and S bits are reserved and
    // MUST be 0 (RFC 3931, Section 4.1.2.1), so they are surfaced only when a
    // control header is present.
    FieldDescriptor::new("l_bit", "L Bit", FieldType::U8).optional(),
    FieldDescriptor::new("s_bit", "S Bit", FieldType::U8).optional(),
    FieldDescriptor::new("version", "Version", FieldType::U8),
    // Control-only fields
    FieldDescriptor::new("length", "Length", FieldType::U16).optional(),
    FieldDescriptor::new(
        "control_connection_id",
        "Control Connection ID",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("ns", "Ns", FieldType::U16).optional(),
    FieldDescriptor::new("nr", "Nr", FieldType::U16).optional(),
    // Data-only fields
    FieldDescriptor::new("session_id", "Session ID", FieldType::U32).optional(),
    FieldDescriptor {
        name: "message_type",
        display_name: "Message Type",
        field_type: FieldType::U16,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(t) => l2tpv3_message_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("avps", "AVPs", FieldType::Array)
        .optional()
        .with_children(AVP_CHILD_FIELDS),
];

/// L2TPv3 over UDP dissector (UDP port 1701).
///
/// RFC 3931, Section 4.1.2: <https://www.rfc-editor.org/rfc/rfc3931#section-4.1.2>
pub struct L2tpv3UdpDissector;

impl Dissector for L2tpv3UdpDissector {
    fn name(&self) -> &'static str {
        "Layer Two Tunneling Protocol v3 (UDP)"
    }

    fn short_name(&self) -> &'static str {
        "L2TPv3-UDP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        UDP_FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < UDP_MIN_SIZE {
            return Err(PacketError::Truncated {
                expected: UDP_MIN_SIZE,
                actual: data.len(),
            });
        }

        // RFC 3931, Section 3.2.1 — Flags/Version word
        let flags_ver = read_be_u16(data, 0)?;
        let t_bit = ((flags_ver >> 15) & 1) as u8;
        let version = (flags_ver & 0x000F) as u8;

        if version != L2TPV3_VERSION {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: version as u32,
            });
        }

        if t_bit == 1 {
            // Control message
            if data.len() < UDP_CONTROL_HEADER_SIZE {
                return Err(PacketError::Truncated {
                    expected: UDP_CONTROL_HEADER_SIZE,
                    actual: data.len(),
                });
            }

            // RFC 3931, Section 3.2.1 — In control messages the L bit (bit 1)
            // and S bit (bit 4) MUST be 1, indicating that Length and the
            // Ns/Nr sequence numbers are present. They share the same
            // flags/version word as the T and Ver fields.
            let l_bit = ((flags_ver >> 14) & 1) as u8;
            let s_bit = ((flags_ver >> 11) & 1) as u8;

            // RFC 3931, Section 3.2.1
            let length = read_be_u16(data, 2)?;

            // Validate that the Length field covers at least the fixed-size
            // control header; otherwise the AVP slice would be invalid.
            if (length as usize) < UDP_CONTROL_HEADER_SIZE {
                return Err(PacketError::InvalidHeader(
                    "L2TPv3 UDP control Length smaller than minimum header size",
                ));
            }

            let ccid = read_be_u32(data, 4)?;
            let ns = read_be_u16(data, 8)?;
            let nr = read_be_u16(data, 10)?;

            let total_consumed = length as usize;
            if total_consumed > data.len() {
                return Err(PacketError::Truncated {
                    expected: total_consumed,
                    actual: data.len(),
                });
            }

            buf.begin_layer(
                self.short_name(),
                None,
                UDP_FIELD_DESCRIPTORS,
                offset..offset + total_consumed,
            );
            buf.push_field(
                &UDP_FIELD_DESCRIPTORS[UDP_FD_T_BIT],
                FieldValue::U8(t_bit),
                offset..offset + 1,
            );
            buf.push_field(
                &UDP_FIELD_DESCRIPTORS[UDP_FD_L_BIT],
                FieldValue::U8(l_bit),
                offset..offset + 1,
            );
            buf.push_field(
                &UDP_FIELD_DESCRIPTORS[UDP_FD_S_BIT],
                FieldValue::U8(s_bit),
                offset..offset + 1,
            );
            buf.push_field(
                &UDP_FIELD_DESCRIPTORS[UDP_FD_VERSION],
                FieldValue::U8(version),
                offset..offset + 2,
            );
            buf.push_field(
                &UDP_FIELD_DESCRIPTORS[UDP_FD_LENGTH],
                FieldValue::U16(length),
                offset + 2..offset + 4,
            );
            buf.push_field(
                &UDP_FIELD_DESCRIPTORS[UDP_FD_CONTROL_CONNECTION_ID],
                FieldValue::U32(ccid),
                offset + 4..offset + 8,
            );
            buf.push_field(
                &UDP_FIELD_DESCRIPTORS[UDP_FD_NS],
                FieldValue::U16(ns),
                offset + 8..offset + 10,
            );
            buf.push_field(
                &UDP_FIELD_DESCRIPTORS[UDP_FD_NR],
                FieldValue::U16(nr),
                offset + 10..offset + 12,
            );

            let avp_data = &data[UDP_CONTROL_HEADER_SIZE..total_consumed];
            push_avp_fields(
                buf,
                avp_data,
                offset + UDP_CONTROL_HEADER_SIZE,
                offset + total_consumed,
                &UDP_FIELD_DESCRIPTORS[UDP_FD_MESSAGE_TYPE],
                &UDP_FIELD_DESCRIPTORS[UDP_FD_AVPS],
            );

            buf.end_layer();

            Ok(DissectResult::new(total_consumed, DispatchHint::End))
        } else {
            // Data message
            // RFC 3931, Section 4.1.2.1
            if data.len() < UDP_DATA_HEADER_SIZE {
                return Err(PacketError::Truncated {
                    expected: UDP_DATA_HEADER_SIZE,
                    actual: data.len(),
                });
            }

            let session_id = read_be_u32(data, 4)?;

            buf.begin_layer(
                self.short_name(),
                None,
                UDP_FIELD_DESCRIPTORS,
                offset..offset + UDP_DATA_HEADER_SIZE,
            );
            buf.push_field(
                &UDP_FIELD_DESCRIPTORS[UDP_FD_T_BIT],
                FieldValue::U8(t_bit),
                offset..offset + 1,
            );
            buf.push_field(
                &UDP_FIELD_DESCRIPTORS[UDP_FD_VERSION],
                FieldValue::U8(version),
                offset..offset + 2,
            );
            buf.push_field(
                &UDP_FIELD_DESCRIPTORS[UDP_FD_SESSION_ID],
                FieldValue::U32(session_id),
                offset + 4..offset + 8,
            );
            buf.end_layer();

            Ok(DissectResult::new(UDP_DATA_HEADER_SIZE, DispatchHint::End))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 3931 (L2TPv3) Coverage
    //
    // | RFC Section | Description                       | Test                                  |
    // |-------------|-----------------------------------|---------------------------------------|
    // | 4.1.1.1     | IP data message (session_id != 0) | parse_l2tpv3_ip_data_message          |
    // | 4.1.1.2     | IP control message (session_id=0) | parse_l2tpv3_ip_control_message       |
    // | 4.1.1.2     | IP control: version validation    | parse_l2tpv3_ip_invalid_version       |
    // | 4.1.1       | IP truncated (< 4 bytes)          | parse_l2tpv3_ip_truncated             |
    // | 4.1.1.2     | IP truncated control (< 16 bytes) | parse_l2tpv3_ip_truncated_control     |
    // | 4.1.1.2     | IP control with AVPs              | parse_l2tpv3_ip_control_with_avps     |
    // | 4.1.1.2     | IP control ZLB ACK                | parse_l2tpv3_ip_control_zlb           |
    // | 4.1.1       | IP data with offset               | parse_l2tpv3_ip_with_offset           |
    // | 3.2.1       | UDP control message (T/L/S/Ver)   | parse_l2tpv3_udp_control_message      |
    // | 4.1.2.1     | UDP data message (T=0)            | parse_l2tpv3_udp_data_message         |
    // | 4.1.2.1     | UDP data omits L/S bit fields     | parse_l2tpv3_udp_data_has_no_l_s_bits |
    // | 3.2.1       | UDP invalid version               | parse_l2tpv3_udp_invalid_version      |
    // | 4.1.2       | UDP truncated                     | parse_l2tpv3_udp_truncated            |
    // | 4.1.2.2     | UDP truncated control             | parse_l2tpv3_udp_truncated_control    |
    // | 4.1.2.2     | UDP truncated data                | parse_l2tpv3_udp_truncated_data       |
    // | 4.1.2.2     | UDP control with AVPs             | parse_l2tpv3_udp_control_with_avps    |
    // | —           | IP field descriptors consistent   | field_descriptors_consistent_ip       |
    // | —           | UDP field descriptors consistent  | field_descriptors_consistent_udp      |

    // ---- L2tpv3Dissector (IP) tests ----

    #[test]
    fn parse_l2tpv3_ip_data_message() {
        // Data message: Session ID = 0x12345678
        let raw: &[u8] = &[0x12, 0x34, 0x56, 0x78];
        let mut buf = DissectBuffer::new();
        let result = L2tpv3Dissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("L2TPv3").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "session_id").unwrap().value,
            FieldValue::U32(0x12345678)
        );
        assert_eq!(
            buf.field_by_name(layer, "is_control").unwrap().value,
            FieldValue::U8(0)
        );
        assert!(buf.field_by_name(layer, "version").is_none());
        assert!(buf.field_by_name(layer, "avps").is_none());
    }

    #[test]
    fn parse_l2tpv3_ip_control_message() {
        // Control message: Session ID=0, T=1, L=1, S=1, Ver=3,
        // Length=12 (control header only, no AVPs), CCID=0x42, Ns=1, Nr=0
        let raw: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // Session ID = 0
            0xC8, 0x03, // T=1, L=1, S=1, Ver=3
            0x00, 0x0C, // Length=12
            0x00, 0x00, 0x00, 0x42, // CCID=0x42
            0x00, 0x01, // Ns=1
            0x00, 0x00, // Nr=0
        ];
        let mut buf = DissectBuffer::new();
        let result = L2tpv3Dissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 16);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("L2TPv3").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "session_id").unwrap().value,
            FieldValue::U32(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "is_control").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "t_bit").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "l_bit").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "s_bit").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U16(12)
        );
        assert_eq!(
            buf.field_by_name(layer, "control_connection_id")
                .unwrap()
                .value,
            FieldValue::U32(0x42)
        );
        assert_eq!(
            buf.field_by_name(layer, "ns").unwrap().value,
            FieldValue::U16(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "nr").unwrap().value,
            FieldValue::U16(0)
        );
    }

    #[test]
    fn parse_l2tpv3_ip_control_with_avps() {
        // Control message with one AVP (Message Type = SCCRQ)
        let raw: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // Session ID = 0
            0xC8, 0x03, // T=1, L=1, S=1, Ver=3
            0x00, 0x14, // Length=20 (12 + 8 AVP)
            0x00, 0x00, 0x00, 0x01, // CCID=1
            0x00, 0x00, // Ns=0
            0x00, 0x00, // Nr=0
            // AVP: Message Type (M=1, Length=8, Vendor=0, Type=0, Value=1)
            0x80, 0x08, // M=1, Length=8
            0x00, 0x00, // Vendor ID=0
            0x00, 0x00, // Attribute Type=0
            0x00, 0x01, // Value: SCCRQ (1)
        ];
        let mut buf = DissectBuffer::new();
        let result = L2tpv3Dissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 24); // 4 (zeros) + 20 (length)

        let layer = buf.layer_by_name("L2TPv3").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "message_type").unwrap().value,
            FieldValue::U16(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("SCCRQ")
        );
        assert!(buf.field_by_name(layer, "avps").is_some());
        let avps_field = buf.field_by_name(layer, "avps").unwrap();
        assert!(avps_field.value.is_array());
    }

    #[test]
    fn parse_l2tpv3_ip_control_zlb() {
        // ZLB (Zero Length Body) ACK: control header with no AVPs
        let raw: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // Session ID = 0
            0xC8, 0x03, // T=1, L=1, S=1, Ver=3
            0x00, 0x0C, // Length=12 (header only)
            0x00, 0x00, 0x00, 0x00, // CCID=0
            0x00, 0x05, // Ns=5
            0x00, 0x03, // Nr=3
        ];
        let mut buf = DissectBuffer::new();
        let result = L2tpv3Dissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 16);

        let layer = buf.layer_by_name("L2TPv3").unwrap();
        assert!(buf.field_by_name(layer, "message_type").is_none());
        assert!(buf.field_by_name(layer, "avps").is_none());
        assert_eq!(
            buf.field_by_name(layer, "ns").unwrap().value,
            FieldValue::U16(5)
        );
        assert_eq!(
            buf.field_by_name(layer, "nr").unwrap().value,
            FieldValue::U16(3)
        );
    }

    #[test]
    fn parse_l2tpv3_ip_invalid_version() {
        let raw: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // Session ID = 0
            0xC8, 0x02, // Ver=2 (invalid)
            0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let err = L2tpv3Dissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidHeader(_) | PacketError::InvalidFieldValue { .. }
        ));
    }

    #[test]
    fn parse_l2tpv3_ip_truncated() {
        let raw: &[u8] = &[0x00, 0x00, 0x01];
        let err = L2tpv3Dissector
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

    #[test]
    fn parse_l2tpv3_ip_truncated_control() {
        // Session ID=0 but only 10 bytes (need 16)
        let raw: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // Session ID = 0
            0xC8, 0x03, 0x00, 0x0C, 0x00, 0x00,
        ];
        let err = L2tpv3Dissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 16,
                actual: 10
            }
        ));
    }

    #[test]
    fn parse_l2tpv3_ip_with_offset() {
        let raw: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD]; // data session
        let mut buf = DissectBuffer::new();
        let result = L2tpv3Dissector.dissect(raw, &mut buf, 50).unwrap();
        assert_eq!(result.bytes_consumed, 4);

        let layer = buf.layer_by_name("L2TPv3").unwrap();
        assert_eq!(layer.range, 50..54);
        assert_eq!(
            buf.field_by_name(layer, "session_id").unwrap().range,
            50..54
        );
    }

    // ---- L2tpv3UdpDissector tests ----

    #[test]
    fn parse_l2tpv3_udp_control_message() {
        // T=1, Ver=3, Length=12 (header only), CCID=0x10, Ns=0, Nr=0
        let raw: &[u8] = &[
            0xC8, 0x03, // T=1, L=1, S=1, Ver=3
            0x00, 0x0C, // Length=12
            0x00, 0x00, 0x00, 0x10, // CCID=0x10
            0x00, 0x00, // Ns=0
            0x00, 0x00, // Nr=0
        ];
        let mut buf = DissectBuffer::new();
        let result = L2tpv3UdpDissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 12);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("L2TPv3-UDP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "t_bit").unwrap().value,
            FieldValue::U8(1)
        );
        // RFC 3931, Section 3.2.1 — L bit MUST be 1 in control messages.
        assert_eq!(
            buf.field_by_name(layer, "l_bit").unwrap().value,
            FieldValue::U8(1)
        );
        // RFC 3931, Section 3.2.1 — S bit MUST be 1 in control messages.
        assert_eq!(
            buf.field_by_name(layer, "s_bit").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U16(12)
        );
        assert_eq!(
            buf.field_by_name(layer, "control_connection_id")
                .unwrap()
                .value,
            FieldValue::U32(0x10)
        );
        assert_eq!(
            buf.field_by_name(layer, "ns").unwrap().value,
            FieldValue::U16(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "nr").unwrap().value,
            FieldValue::U16(0)
        );
    }

    #[test]
    fn parse_l2tpv3_udp_data_has_no_l_s_bits() {
        // In UDP data messages the L and S bits are reserved (MUST be 0) per
        // RFC 3931, Section 4.1.2.1 and are not surfaced as separate fields.
        let raw: &[u8] = &[
            0x00, 0x03, // T=0, Ver=3
            0x00, 0x00, // Reserved
            0xDE, 0xAD, 0xBE, 0xEF, // Session ID
        ];
        let mut buf = DissectBuffer::new();
        L2tpv3UdpDissector.dissect(raw, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("L2TPv3-UDP").unwrap();
        assert!(buf.field_by_name(layer, "l_bit").is_none());
        assert!(buf.field_by_name(layer, "s_bit").is_none());
    }

    #[test]
    fn parse_l2tpv3_udp_data_message() {
        // T=0, Ver=3, Reserved=0, Session ID=0xDEADBEEF
        let raw: &[u8] = &[
            0x00, 0x03, // T=0, Ver=3
            0x00, 0x00, // Reserved
            0xDE, 0xAD, 0xBE, 0xEF, // Session ID
        ];
        let mut buf = DissectBuffer::new();
        let result = L2tpv3UdpDissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("L2TPv3-UDP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "t_bit").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.field_by_name(layer, "session_id").unwrap().value,
            FieldValue::U32(0xDEADBEEF)
        );
        assert!(buf.field_by_name(layer, "control_connection_id").is_none());
    }

    #[test]
    fn parse_l2tpv3_udp_control_with_avps() {
        // Control with Message Type AVP (SCCRP = 2)
        let raw: &[u8] = &[
            0xC8, 0x03, // T=1, L=1, S=1, Ver=3
            0x00, 0x14, // Length=20 (12 + 8)
            0x00, 0x00, 0x00, 0x05, // CCID=5
            0x00, 0x01, // Ns=1
            0x00, 0x01, // Nr=1
            // AVP: Message Type = SCCRP (2)
            0x80, 0x08, // M=1, Length=8
            0x00, 0x00, // Vendor=0
            0x00, 0x00, // Type=0
            0x00, 0x02, // Value: SCCRP
        ];
        let mut buf = DissectBuffer::new();
        let result = L2tpv3UdpDissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 20);

        let layer = buf.layer_by_name("L2TPv3-UDP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "l_bit").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "s_bit").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "message_type").unwrap().value,
            FieldValue::U16(2)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("SCCRP")
        );
        assert!(buf.field_by_name(layer, "avps").is_some());
    }

    #[test]
    fn parse_l2tpv3_udp_invalid_version() {
        let raw: &[u8] = &[
            0xC8, 0x02, // T=1, Ver=2
            0x00, 0x0C,
        ];
        let err = L2tpv3UdpDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::InvalidHeader(_) | PacketError::InvalidFieldValue { .. }
        ));
    }

    #[test]
    fn parse_l2tpv3_udp_truncated() {
        let raw: &[u8] = &[0xC8, 0x03, 0x00];
        let err = L2tpv3UdpDissector
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

    #[test]
    fn parse_l2tpv3_udp_truncated_control() {
        // T=1 but only 8 bytes (need 12)
        let raw: &[u8] = &[
            0xC8, 0x03, // T=1, Ver=3
            0x00, 0x0C, 0x00, 0x00, 0x00, 0x00,
        ];
        let err = L2tpv3UdpDissector
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
    fn parse_l2tpv3_udp_truncated_data() {
        // T=0 but only 6 bytes (need 8)
        let raw: &[u8] = &[0x00, 0x03, 0x00, 0x00, 0xDE, 0xAD];
        let err = L2tpv3UdpDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 6
            }
        ));
    }

    #[test]
    fn field_descriptors_consistent_ip() {
        let descs = L2tpv3Dissector.field_descriptors();
        assert_eq!(descs.len(), 12);
        assert_eq!(descs[IP_FD_SESSION_ID].name, "session_id");
        assert_eq!(descs[IP_FD_IS_CONTROL].name, "is_control");
        assert_eq!(descs[IP_FD_T_BIT].name, "t_bit");
        assert_eq!(descs[IP_FD_L_BIT].name, "l_bit");
        assert_eq!(descs[IP_FD_S_BIT].name, "s_bit");
        assert_eq!(descs[IP_FD_VERSION].name, "version");
        assert_eq!(descs[IP_FD_LENGTH].name, "length");
        assert_eq!(
            descs[IP_FD_CONTROL_CONNECTION_ID].name,
            "control_connection_id"
        );
        assert_eq!(descs[IP_FD_NS].name, "ns");
        assert_eq!(descs[IP_FD_NR].name, "nr");
        assert_eq!(descs[IP_FD_MESSAGE_TYPE].name, "message_type");
        assert_eq!(descs[IP_FD_AVPS].name, "avps");
    }

    #[test]
    fn field_descriptors_consistent_udp() {
        let descs = L2tpv3UdpDissector.field_descriptors();
        assert_eq!(descs.len(), 11);
        assert_eq!(descs[UDP_FD_T_BIT].name, "t_bit");
        assert_eq!(descs[UDP_FD_L_BIT].name, "l_bit");
        assert_eq!(descs[UDP_FD_S_BIT].name, "s_bit");
        assert_eq!(descs[UDP_FD_VERSION].name, "version");
        assert_eq!(descs[UDP_FD_LENGTH].name, "length");
        assert_eq!(
            descs[UDP_FD_CONTROL_CONNECTION_ID].name,
            "control_connection_id"
        );
        assert_eq!(descs[UDP_FD_NS].name, "ns");
        assert_eq!(descs[UDP_FD_NR].name, "nr");
        assert_eq!(descs[UDP_FD_SESSION_ID].name, "session_id");
        assert_eq!(descs[UDP_FD_MESSAGE_TYPE].name, "message_type");
        assert_eq!(descs[UDP_FD_AVPS].name, "avps");
    }
}
