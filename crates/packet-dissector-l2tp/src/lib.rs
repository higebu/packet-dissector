//! L2TP (Layer 2 Tunneling Protocol, version 2) dissector.
//!
//! Implements parsing of the L2TPv2 header defined in RFC 2661,
//! Section 3.1. Data messages dispatch their payload to PPP; control
//! messages are terminal (AVPs are not dissected by this crate).
//!
//! ## References
//! - RFC 2661 (L2TPv2): <https://www.rfc-editor.org/rfc/rfc2661>
//! - RFC 9601 (ECN propagation across tunnels, updates RFC 2661):
//!   <https://www.rfc-editor.org/rfc/rfc9601>
//!
//! RFC 9601 updates RFC 2661 by adding configuration guidance and an
//! optional ECN Capability AVP (Attribute Type 103); it does not
//! modify the L2TPv2 header format.

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

/// Minimum L2TP header size (no optional fields).
///
/// RFC 2661, Section 3.1 — The minimum header contains the flags/version
/// word (2 octets), Tunnel ID (2 octets), and Session ID (2 octets).
/// <https://www.rfc-editor.org/rfc/rfc2661#section-3.1>
const MIN_HEADER_SIZE: usize = 6;

/// Required L2TP version number.
///
/// RFC 2661, Section 3.1 — "Ver MUST be 2, indicating the version of
/// the L2TP data message header."
/// <https://www.rfc-editor.org/rfc/rfc2661#section-3.1>
const L2TP_VERSION: u8 = 2;

/// EtherType used to dispatch L2TP data-message payloads to the PPP dissector.
///
/// RFC 2661, Section 1 — "L2TP facilitates the tunneling of PPP packets."
/// <https://www.rfc-editor.org/rfc/rfc2661#section-1>
const ETHERTYPE_PPP: u16 = 0x880B;

/// Field descriptor indices for [`L2tpDissector::field_descriptors`].
const FD_IS_CONTROL: usize = 0;
const FD_LENGTH_PRESENT: usize = 1;
const FD_SEQUENCE_PRESENT: usize = 2;
const FD_OFFSET_PRESENT: usize = 3;
const FD_PRIORITY: usize = 4;
const FD_VERSION: usize = 5;
const FD_LENGTH: usize = 6;
const FD_TUNNEL_ID: usize = 7;
const FD_SESSION_ID: usize = 8;
const FD_NS: usize = 9;
const FD_NR: usize = 10;
const FD_OFFSET_SIZE: usize = 11;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("is_control", "Type (T)", FieldType::U8),
    FieldDescriptor::new("length_present", "Length Present (L)", FieldType::U8),
    FieldDescriptor::new("sequence_present", "Sequence Present (S)", FieldType::U8),
    FieldDescriptor::new("offset_present", "Offset Present (O)", FieldType::U8),
    FieldDescriptor::new("priority", "Priority (P)", FieldType::U8),
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U16).optional(),
    FieldDescriptor::new("tunnel_id", "Tunnel ID", FieldType::U16),
    FieldDescriptor::new("session_id", "Session ID", FieldType::U16),
    FieldDescriptor::new("ns", "Ns", FieldType::U16).optional(),
    FieldDescriptor::new("nr", "Nr", FieldType::U16).optional(),
    FieldDescriptor::new("offset_size", "Offset Size", FieldType::U16).optional(),
];

/// L2TP dissector.
pub struct L2tpDissector;

impl Dissector for L2tpDissector {
    fn name(&self) -> &'static str {
        "Layer 2 Tunneling Protocol"
    }

    fn short_name(&self) -> &'static str {
        "L2TP"
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
        if data.len() < MIN_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 2661, Section 3.1 — Flags and Version (first 2 octets)
        // <https://www.rfc-editor.org/rfc/rfc2661#section-3.1>
        //
        //  0                   1
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        let flags_ver = read_be_u16(data, 0)?;

        // RFC 2661, Section 3.1 — Bit 0: Type (T)
        // "set to 0 for a data message and 1 for a control message"
        // <https://www.rfc-editor.org/rfc/rfc2661#section-3.1>
        let t_flag = ((flags_ver >> 15) & 1) as u8;
        // RFC 2661, Section 3.1 — Bit 1: Length (L)
        let l_flag = ((flags_ver >> 14) & 1) as u8;
        // RFC 2661, Section 3.1 — Bit 4: Sequence (S)
        let s_flag = ((flags_ver >> 11) & 1) as u8;
        // RFC 2661, Section 3.1 — Bit 6: Offset (O)
        let o_flag = ((flags_ver >> 9) & 1) as u8;
        // RFC 2661, Section 3.1 — Bit 7: Priority (P)
        let p_flag = ((flags_ver >> 8) & 1) as u8;
        // RFC 2661, Section 3.1 — Bits 2, 3, 5, 8-11: reserved (x)
        // "The x bits are reserved for future extensions. All reserved
        //  bits MUST be set to 0 on outgoing messages and ignored on
        //  incoming messages."
        // <https://www.rfc-editor.org/rfc/rfc2661#section-3.1>
        // This parser ignores the reserved bits as required.
        // RFC 2661, Section 3.1 — Bits 12-15: Version
        let version = (flags_ver & 0x000F) as u8;

        // RFC 2661, Section 3.1 — "Ver MUST be 2, indicating the version
        // of the L2TP data message header described in this document...
        // Packets received with an unknown Ver field MUST be discarded."
        // <https://www.rfc-editor.org/rfc/rfc2661#section-3.1>
        if version != L2TP_VERSION {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: version as u32,
            });
        }

        // RFC 2661, Section 3.1 — Control message constraints:
        // "The L bit MUST be set to 1 for control messages."
        // "The S bit MUST be set to 1 for control messages."
        // "The O bit MUST be set to 0 (zero) for control messages."
        // "The P bit MUST be set to 0 for all control messages."
        if t_flag == 1 {
            if l_flag == 0 {
                return Err(PacketError::InvalidHeader(
                    "L2TP control message must have L bit set",
                ));
            }
            if s_flag == 0 {
                return Err(PacketError::InvalidHeader(
                    "L2TP control message must have S bit set",
                ));
            }
            if o_flag == 1 {
                return Err(PacketError::InvalidHeader(
                    "L2TP control message must not have O bit set",
                ));
            }
            if p_flag == 1 {
                return Err(PacketError::InvalidHeader(
                    "L2TP control message must not have P bit set",
                ));
            }
        }

        // Compute expected header length based on flags.
        let mut header_len = 2; // flags/version word
        if l_flag != 0 {
            header_len += 2; // Length (2)
        }
        header_len += 4; // Tunnel ID (2) + Session ID (2)
        if s_flag != 0 {
            header_len += 4; // Ns (2) + Nr (2)
        }
        if o_flag != 0 {
            header_len += 2; // Offset Size (2)
        }

        if data.len() < header_len {
            return Err(PacketError::Truncated {
                expected: header_len,
                actual: data.len(),
            });
        }

        let mut pos = 2;

        // Read optional Length field value before begin_layer so we can
        // validate early. The field is emitted later with push_field.
        let msg_length: Option<u16> = if l_flag != 0 {
            let length = read_be_u16(data, pos)?;
            pos += 2;
            Some(length)
        } else {
            None
        };

        // Tunnel ID (always present)
        let tunnel_id = read_be_u16(data, pos)?;
        pos += 2;

        // Session ID (always present)
        let session_id = read_be_u16(data, pos)?;
        pos += 2;

        // RFC 2661, Section 3.1 — Ns and Nr (optional, present when S bit is set)
        // "Ns indicates the sequence number for this data or control
        //  message, beginning at zero and incrementing by one (modulo
        //  2**16) for each message sent."
        // "Nr indicates the sequence number expected in the next control
        //  message to be received... In data messages, Nr is reserved
        //  and, if present (as indicated by the S-bit), MUST be ignored
        //  upon receipt."
        // <https://www.rfc-editor.org/rfc/rfc2661#section-3.1>
        // For dissection the Nr value is still surfaced; upper-layer
        // consumers apply the "ignored" semantics.
        let seq = if s_flag != 0 {
            let ns = read_be_u16(data, pos)?;
            pos += 2;
            let nr = read_be_u16(data, pos)?;
            pos += 2;
            Some((ns, nr))
        } else {
            None
        };

        // RFC 2661, Section 3.1 — Offset Size (optional, present when O bit is set)
        // "The Offset Size field, if present, specifies the number of
        //  octets past the L2TP header at which the payload data is
        //  expected to start. Actual data within the offset padding is
        //  undefined."
        // <https://www.rfc-editor.org/rfc/rfc2661#section-3.1>
        let offset_size_val = if o_flag != 0 {
            let offset_size = read_be_u16(data, pos)?;
            pos += 2;

            // Skip past the Offset Pad bytes; their contents are undefined
            // per the quote above.
            let pad = offset_size as usize;
            if data.len() < pos + pad {
                return Err(PacketError::Truncated {
                    expected: pos + pad,
                    actual: data.len(),
                });
            }
            pos += pad;
            Some(offset_size)
        } else {
            None
        };

        // Determine total message size: use Length field when present,
        // otherwise consume all remaining data in the UDP payload.
        // RFC 2661, Section 3.1 — "indicates the total length of the
        // message in octets"
        let consumed = if let Some(length) = msg_length {
            let length = length as usize;
            if length < pos {
                return Err(PacketError::InvalidHeader(
                    "L2TP Length field is smaller than header size",
                ));
            }
            if length > data.len() {
                return Err(PacketError::Truncated {
                    expected: length,
                    actual: data.len(),
                });
            }
            length
        } else {
            data.len()
        };

        // Compute the layer range: data messages span the header only,
        // control messages span the entire L2TP message.
        let layer_range = if t_flag == 0 {
            offset..offset + pos
        } else {
            offset..offset + consumed
        };

        buf.begin_layer(self.short_name(), None, FIELD_DESCRIPTORS, layer_range);

        // Always-present flag fields (derived from the first 2 bytes)
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_IS_CONTROL],
            FieldValue::U8(t_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LENGTH_PRESENT],
            FieldValue::U8(l_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SEQUENCE_PRESENT],
            FieldValue::U8(s_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_OFFSET_PRESENT],
            FieldValue::U8(o_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PRIORITY],
            FieldValue::U8(p_flag),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 2,
        );

        // RFC 2661, Section 3.1 — Length (optional, present when L bit is set)
        // "indicates the total length of the message in octets"
        let mut field_pos = 2;
        if let Some(length) = msg_length {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_LENGTH],
                FieldValue::U16(length),
                offset + field_pos..offset + field_pos + 2,
            );
            field_pos += 2;
        }

        // RFC 2661, Section 3.1 — Tunnel ID (always present)
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TUNNEL_ID],
            FieldValue::U16(tunnel_id),
            offset + field_pos..offset + field_pos + 2,
        );
        field_pos += 2;

        // RFC 2661, Section 3.1 — Session ID (always present)
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SESSION_ID],
            FieldValue::U16(session_id),
            offset + field_pos..offset + field_pos + 2,
        );
        field_pos += 2;

        // RFC 2661, Section 3.1 — Ns and Nr (optional, present when S bit is set)
        if let Some((ns, nr)) = seq {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_NS],
                FieldValue::U16(ns),
                offset + field_pos..offset + field_pos + 2,
            );
            field_pos += 2;

            buf.push_field(
                &FIELD_DESCRIPTORS[FD_NR],
                FieldValue::U16(nr),
                offset + field_pos..offset + field_pos + 2,
            );
            field_pos += 2;
        }

        // RFC 2661, Section 3.1 — Offset Size (optional, present when O bit is set)
        if let Some(offset_size) = offset_size_val {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_OFFSET_SIZE],
                FieldValue::U16(offset_size),
                offset + field_pos..offset + field_pos + 2,
            );
        }

        buf.end_layer();

        // RFC 2661, Section 1 — "L2TP facilitates the tunneling of PPP packets."
        // <https://www.rfc-editor.org/rfc/rfc2661#section-1>
        if t_flag == 0 {
            // Data message: consume header only, dispatch to PPP.
            // When the Length field is present, bound the PPP payload to
            // the L2TP message boundary so trailing bytes (padding or
            // bundled messages) are not mis-parsed by the PPP dissector.
            if msg_length.is_some() {
                let payload_range = (offset + pos)..(offset + consumed);
                Ok(DissectResult::with_embedded_payload(
                    pos,
                    DispatchHint::ByEtherType(ETHERTYPE_PPP),
                    payload_range,
                ))
            } else {
                Ok(DissectResult::new(
                    pos,
                    DispatchHint::ByEtherType(ETHERTYPE_PPP),
                ))
            }
        } else {
            // Control message: consume the entire L2TP message.
            Ok(DissectResult::new(consumed, DispatchHint::End))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 2661 (L2TP) Coverage
    //
    // | RFC Section | Description                    | Test                                |
    // |-------------|--------------------------------|-------------------------------------|
    // | §3.1        | Minimum data header (6 bytes)  | parse_l2tp_data_minimal             |
    // | §3.1        | Control message (12 bytes)     | parse_l2tp_control                  |
    // | §3.1        | Data with Length (L bit)        | parse_l2tp_data_with_length         |
    // | §3.1        | Data with Sequence (S bit)      | parse_l2tp_data_with_sequence       |
    // | §3.1        | Data with Offset (O bit)        | parse_l2tp_data_with_offset         |
    // | §3.1        | Data with all optional fields   | parse_l2tp_data_all_optional        |
    // | §3.1        | Version validation              | parse_l2tp_invalid_version          |
    // | §3.1        | Control without L bit           | parse_l2tp_control_missing_length   |
    // | §3.1        | Control without S bit           | parse_l2tp_control_missing_sequence |
    // | §3.1        | Control with O bit              | parse_l2tp_control_offset_set       |
    // | §3.1        | Control with P bit              | parse_l2tp_control_priority_set     |
    // | §3.1        | Truncated packet                | parse_l2tp_truncated                |
    // | §3.1        | Truncated optional fields       | parse_l2tp_truncated_optional       |
    // | §3.1        | Byte offset correctness         | parse_l2tp_with_offset              |
    // | §3.1        | Dispatch: Data→PPP, Ctrl→End     | parse_l2tp_dispatch_hint            |
    // | §3.1        | field_descriptors consistency    | field_descriptors_consistent        |
    // | §3.1        | Offset padding                  | parse_l2tp_data_with_offset_padding |
    // | §3.1        | Truncated offset padding         | parse_l2tp_truncated_offset_padding |
    // | §3.1        | Data dispatch (no L, unbounded)  | parse_l2tp_consumes_payload_no_length |
    // | §3.1        | Data dispatch (L, bounded)       | parse_l2tp_consumes_payload_with_length |
    // | §3.1        | Length < header (invalid)        | parse_l2tp_length_too_small |
    // | §3.1        | Length > data (truncated)        | parse_l2tp_length_exceeds_data |
    // | §3.1        | Reserved (x) bits ignored        | parse_l2tp_reserved_bits_ignored |

    /// Helper: dissect raw bytes at offset 0 and return the result.
    fn dissect(data: &[u8]) -> Result<(DissectBuffer<'_>, DissectResult), PacketError> {
        let mut buf = DissectBuffer::new();
        let result = L2tpDissector.dissect(data, &mut buf, 0)?;
        Ok((buf, result))
    }

    #[test]
    fn parse_l2tp_data_minimal() {
        // Minimal data message: T=0, L=0, S=0, O=0, P=0, Ver=2
        // Tunnel ID = 1, Session ID = 2
        let raw: &[u8] = &[
            0x00, 0x02, // flags: T=0,L=0,S=0,O=0,P=0, Ver=2
            0x00, 0x01, // Tunnel ID = 1
            0x00, 0x02, // Session ID = 2
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 6);
        assert_eq!(result.next, DispatchHint::ByEtherType(ETHERTYPE_PPP));

        let layer = buf.layer_by_name("L2TP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "is_control").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "length_present").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_present").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "offset_present").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "priority").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "tunnel_id").unwrap().value,
            FieldValue::U16(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "session_id").unwrap().value,
            FieldValue::U16(2)
        );
        assert!(buf.field_by_name(layer, "length").is_none());
        assert!(buf.field_by_name(layer, "ns").is_none());
        assert!(buf.field_by_name(layer, "nr").is_none());
        assert!(buf.field_by_name(layer, "offset_size").is_none());
    }

    #[test]
    fn parse_l2tp_control() {
        // Control message: T=1, L=1, S=1, O=0, P=0, Ver=2
        // Length = 12, Tunnel ID = 100, Session ID = 0, Ns = 0, Nr = 0
        let raw: &[u8] = &[
            0xC8, 0x02, // T=1, L=1, S=1, O=0, P=0, Ver=2
            0x00, 0x0C, // Length = 12
            0x00, 0x64, // Tunnel ID = 100
            0x00, 0x00, // Session ID = 0
            0x00, 0x00, // Ns = 0
            0x00, 0x00, // Nr = 0
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 12);

        let layer = buf.layer_by_name("L2TP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "is_control").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "length_present").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_present").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U16(12)
        );
        assert_eq!(
            buf.field_by_name(layer, "tunnel_id").unwrap().value,
            FieldValue::U16(100)
        );
        assert_eq!(
            buf.field_by_name(layer, "session_id").unwrap().value,
            FieldValue::U16(0)
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
    fn parse_l2tp_data_with_length() {
        // Data message with L bit set: T=0, L=1, Ver=2
        let raw: &[u8] = &[
            0x40, 0x02, // T=0, L=1, Ver=2
            0x00, 0x08, // Length = 8
            0x00, 0x0A, // Tunnel ID = 10
            0x00, 0x14, // Session ID = 20
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 8);

        let layer = buf.layer_by_name("L2TP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U16(8)
        );
        assert_eq!(
            buf.field_by_name(layer, "tunnel_id").unwrap().value,
            FieldValue::U16(10)
        );
        assert_eq!(
            buf.field_by_name(layer, "session_id").unwrap().value,
            FieldValue::U16(20)
        );
    }

    #[test]
    fn parse_l2tp_data_with_sequence() {
        // Data message with S bit set: T=0, S=1, Ver=2
        let raw: &[u8] = &[
            0x08, 0x02, // T=0, S=1, Ver=2
            0x00, 0x05, // Tunnel ID = 5
            0x00, 0x06, // Session ID = 6
            0x00, 0x07, // Ns = 7
            0x00, 0x08, // Nr = 8
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 10);

        let layer = buf.layer_by_name("L2TP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "ns").unwrap().value,
            FieldValue::U16(7)
        );
        assert_eq!(
            buf.field_by_name(layer, "nr").unwrap().value,
            FieldValue::U16(8)
        );
    }

    #[test]
    fn parse_l2tp_data_with_offset() {
        // Data message with O bit set: T=0, O=1, Ver=2
        // Offset Size = 0 (no padding)
        let raw: &[u8] = &[
            0x02, 0x02, // T=0, O=1, Ver=2
            0x00, 0x01, // Tunnel ID = 1
            0x00, 0x02, // Session ID = 2
            0x00, 0x00, // Offset Size = 0
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 8);

        let layer = buf.layer_by_name("L2TP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "offset_size").unwrap().value,
            FieldValue::U16(0)
        );
    }

    #[test]
    fn parse_l2tp_data_with_offset_padding() {
        // Data message with O bit set and 4 bytes of padding
        let raw: &[u8] = &[
            0x02, 0x02, // T=0, O=1, Ver=2
            0x00, 0x01, // Tunnel ID = 1
            0x00, 0x02, // Session ID = 2
            0x00, 0x04, // Offset Size = 4
            0x00, 0x00, 0x00, 0x00, // 4 bytes of padding
        ];
        let (buf, result) = dissect(raw).unwrap();
        // 2 (flags) + 4 (tid+sid) + 2 (offset_size) + 4 (padding) = 12
        assert_eq!(result.bytes_consumed, 12);

        let layer = buf.layer_by_name("L2TP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "offset_size").unwrap().value,
            FieldValue::U16(4)
        );
    }

    #[test]
    fn parse_l2tp_data_all_optional() {
        // Data message with all optional fields: T=0, L=1, S=1, O=1, P=1, Ver=2
        let raw: &[u8] = &[
            0x4B, 0x02, // T=0, L=1, S=1, O=1, P=1, Ver=2
            0x00, 0x10, // Length = 16
            0x00, 0x0A, // Tunnel ID = 10
            0x00, 0x14, // Session ID = 20
            0x00, 0x01, // Ns = 1
            0x00, 0x02, // Nr = 2
            0x00, 0x02, // Offset Size = 2
            0x00, 0x00, // 2 bytes of padding
        ];
        let (buf, result) = dissect(raw).unwrap();
        // 2 + 2 + 4 + 4 + 2 + 2 (padding) = 16
        assert_eq!(result.bytes_consumed, 16);

        let layer = buf.layer_by_name("L2TP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "is_control").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "length_present").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_present").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "offset_present").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "priority").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U16(16)
        );
        assert_eq!(
            buf.field_by_name(layer, "tunnel_id").unwrap().value,
            FieldValue::U16(10)
        );
        assert_eq!(
            buf.field_by_name(layer, "session_id").unwrap().value,
            FieldValue::U16(20)
        );
        assert_eq!(
            buf.field_by_name(layer, "ns").unwrap().value,
            FieldValue::U16(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "nr").unwrap().value,
            FieldValue::U16(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "offset_size").unwrap().value,
            FieldValue::U16(2)
        );
    }

    #[test]
    fn parse_l2tp_invalid_version() {
        // Version = 3 (invalid)
        let raw: &[u8] = &[
            0x00, 0x03, // Ver=3
            0x00, 0x01, // Tunnel ID
            0x00, 0x02, // Session ID
        ];
        let err = L2tpDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        match err {
            PacketError::InvalidFieldValue { field, value } => {
                assert_eq!(field, "version");
                assert_eq!(value, 3);
            }
            other => panic!("Expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn parse_l2tp_control_missing_length() {
        // Control message with L=0 (invalid): T=1, L=0, S=1, Ver=2
        let raw: &[u8] = &[
            0x88, 0x02, // T=1, L=0, S=1, Ver=2
            0x00, 0x01, 0x00, 0x02, // Tunnel ID, Session ID
            0x00, 0x00, 0x00, 0x00, // Ns, Nr
        ];
        let err = L2tpDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        match err {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("L bit"), "Error message: {msg}");
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn parse_l2tp_control_missing_sequence() {
        // Control message with S=0 (invalid): T=1, L=1, S=0, Ver=2
        let raw: &[u8] = &[
            0xC0, 0x02, // T=1, L=1, S=0, Ver=2
            0x00, 0x08, // Length = 8
            0x00, 0x01, // Tunnel ID
            0x00, 0x02, // Session ID
        ];
        let err = L2tpDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        match err {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("S bit"), "Error message: {msg}");
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn parse_l2tp_control_offset_set() {
        // Control message with O=1 (invalid): T=1, L=1, S=1, O=1, Ver=2
        let raw: &[u8] = &[
            0xCA, 0x02, // T=1, L=1, S=1, O=1, Ver=2
            0x00, 0x0E, // Length = 14
            0x00, 0x01, 0x00, 0x02, // Tunnel ID, Session ID
            0x00, 0x00, 0x00, 0x00, // Ns, Nr
            0x00, 0x00, // Offset Size
        ];
        let err = L2tpDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        match err {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("O bit"), "Error message: {msg}");
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn parse_l2tp_control_priority_set() {
        // Control message with P=1 (invalid): T=1, L=1, S=1, P=1, Ver=2
        let raw: &[u8] = &[
            0xC9, 0x02, // T=1, L=1, S=1, P=1, Ver=2
            0x00, 0x0C, // Length = 12
            0x00, 0x01, 0x00, 0x02, // Tunnel ID, Session ID
            0x00, 0x00, 0x00, 0x00, // Ns, Nr
        ];
        let err = L2tpDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        match err {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("P bit"), "Error message: {msg}");
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn parse_l2tp_truncated() {
        let raw: &[u8] = &[0x00, 0x02, 0x00]; // Only 3 bytes
        let err = L2tpDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 6,
                actual: 3
            }
        ));
    }

    #[test]
    fn parse_l2tp_truncated_optional() {
        // S bit set but not enough data for Ns/Nr
        let raw: &[u8] = &[
            0x08, 0x02, // T=0, S=1, Ver=2
            0x00, 0x01, // Tunnel ID
            0x00, 0x02, // Session ID
                  // Missing Ns and Nr
        ];
        let err = L2tpDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 10,
                actual: 6
            }
        ));
    }

    #[test]
    fn parse_l2tp_truncated_offset_padding() {
        // O bit set, Offset Size = 10 but not enough data for padding
        let raw: &[u8] = &[
            0x02, 0x02, // T=0, O=1, Ver=2
            0x00, 0x01, // Tunnel ID
            0x00, 0x02, // Session ID
            0x00,
            0x0A, // Offset Size = 10
                  // Only 0 bytes of padding available (need 10)
        ];
        let err = L2tpDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 18,
                actual: 8
            }
        ));
    }

    #[test]
    fn parse_l2tp_with_offset() {
        // Verify byte ranges use the offset parameter correctly
        // Control message at offset 42
        let raw: &[u8] = &[
            0xC8, 0x02, // T=1, L=1, S=1, Ver=2
            0x00, 0x0C, // Length = 12
            0x00, 0x01, // Tunnel ID = 1
            0x00, 0x02, // Session ID = 2
            0x00, 0x03, // Ns = 3
            0x00, 0x04, // Nr = 4
        ];
        let mut buf = DissectBuffer::new();
        let result = L2tpDissector.dissect(raw, &mut buf, 42).unwrap();
        assert_eq!(result.bytes_consumed, 12);

        let layer = buf.layer_by_name("L2TP").unwrap();
        assert_eq!(layer.range, 42..54);
        // Length at offset 42+2..42+4
        assert_eq!(buf.field_by_name(layer, "length").unwrap().range, 44..46);
        // Tunnel ID at offset 42+4..42+6
        assert_eq!(buf.field_by_name(layer, "tunnel_id").unwrap().range, 46..48);
        // Session ID at offset 42+6..42+8
        assert_eq!(
            buf.field_by_name(layer, "session_id").unwrap().range,
            48..50
        );
        // Ns at offset 42+8..42+10
        assert_eq!(buf.field_by_name(layer, "ns").unwrap().range, 50..52);
        // Nr at offset 42+10..42+12
        assert_eq!(buf.field_by_name(layer, "nr").unwrap().range, 52..54);
    }

    #[test]
    fn parse_l2tp_dispatch_hint() {
        // Data messages dispatch to PPP via EtherType 0x880B.
        let data_raw: &[u8] = &[0x00, 0x02, 0x00, 0x01, 0x00, 0x02];
        let (_, result) = dissect(data_raw).unwrap();
        assert_eq!(result.next, DispatchHint::ByEtherType(ETHERTYPE_PPP));

        // Control messages are terminal.
        let ctrl_raw: &[u8] = &[
            0xC8, 0x02, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        ];
        let (_, result) = dissect(ctrl_raw).unwrap();
        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn field_descriptors_consistent() {
        let descs = L2tpDissector.field_descriptors();
        assert_eq!(descs.len(), 12);
        assert_eq!(descs[FD_IS_CONTROL].name, "is_control");
        assert_eq!(descs[FD_LENGTH_PRESENT].name, "length_present");
        assert_eq!(descs[FD_SEQUENCE_PRESENT].name, "sequence_present");
        assert_eq!(descs[FD_OFFSET_PRESENT].name, "offset_present");
        assert_eq!(descs[FD_PRIORITY].name, "priority");
        assert_eq!(descs[FD_VERSION].name, "version");
        assert_eq!(descs[FD_LENGTH].name, "length");
        assert_eq!(descs[FD_TUNNEL_ID].name, "tunnel_id");
        assert_eq!(descs[FD_SESSION_ID].name, "session_id");
        assert_eq!(descs[FD_NS].name, "ns");
        assert_eq!(descs[FD_NR].name, "nr");
        assert_eq!(descs[FD_OFFSET_SIZE].name, "offset_size");
    }

    #[test]
    fn parse_l2tp_consumes_payload_no_length() {
        // Without L bit, the dissector consumes only the header; the
        // remaining bytes are PPP payload dispatched via ByEtherType.
        // No embedded_payload is set because the message boundary is unknown.
        let raw: &[u8] = &[
            0x00, 0x02, // flags: T=0, Ver=2
            0x00, 0x01, // Tunnel ID = 1
            0x00, 0x02, // Session ID = 2
            0xFF, 0x03, 0x00, 0x21, // PPP payload (not consumed by L2TP)
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 6); // header only
        assert_eq!(result.next, DispatchHint::ByEtherType(ETHERTYPE_PPP));
        assert!(result.embedded_payload.is_none());
        let layer = buf.layer_by_name("L2TP").unwrap();
        assert_eq!(layer.range, 0..6);
    }

    #[test]
    fn parse_l2tp_consumes_payload_with_length() {
        // With L bit, the dissector bounds the PPP payload to the L2TP
        // message boundary via embedded_payload.
        let raw: &[u8] = &[
            0x40, 0x02, // T=0, L=1, Ver=2
            0x00, 0x0C, // Length = 12 (header 8 + 4 payload)
            0x00, 0x01, // Tunnel ID = 1
            0x00, 0x02, // Session ID = 2
            0xFF, 0x03, 0x00, 0x21, // 4 bytes of PPP payload
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 8); // header only
        assert_eq!(result.next, DispatchHint::ByEtherType(ETHERTYPE_PPP));
        assert_eq!(result.embedded_payload, Some(8..12)); // PPP bounded to L2TP Length
        let layer = buf.layer_by_name("L2TP").unwrap();
        assert_eq!(layer.range, 0..8);
    }

    #[test]
    fn parse_l2tp_length_too_small() {
        // Length field smaller than the computed header size → InvalidHeader
        let raw: &[u8] = &[
            0x40, 0x02, // T=0, L=1, Ver=2
            0x00, 0x04, // Length = 4 (less than minimum header of 8 with L bit)
            0x00, 0x01, // Tunnel ID
            0x00, 0x02, // Session ID
        ];
        let err = L2tpDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        match err {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("smaller"), "Error message: {msg}");
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn parse_l2tp_length_exceeds_data() {
        // Length field larger than available data → Truncated
        let raw: &[u8] = &[
            0x40, 0x02, // T=0, L=1, Ver=2
            0x00, 0x20, // Length = 32 (more than 8 bytes available)
            0x00, 0x01, // Tunnel ID
            0x00, 0x02, // Session ID
        ];
        let err = L2tpDissector
            .dissect(raw, &mut DissectBuffer::new(), 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 32,
                actual: 8
            }
        ));
    }

    #[test]
    fn parse_l2tp_reserved_bits_ignored() {
        // RFC 2661, Section 3.1 — "All reserved bits MUST be set to 0 on
        // outgoing messages and ignored on incoming messages."
        // <https://www.rfc-editor.org/rfc/rfc2661#section-3.1>
        //
        // Build a data message with every reserved bit set to 1:
        //   bit  2 = 1 (mask 0x2000)
        //   bit  3 = 1 (mask 0x1000)
        //   bit  5 = 1 (mask 0x0400)
        //   bits 8-11 = 1111 (mask 0x00F0)
        //   Ver       = 2
        // Byte 0 = 0x34 (00110100 — bits 2, 3, 5 set; T/L/S/O/P clear)
        // Byte 1 = 0xF2 (11110010 — reserved bits 8-11 set; Ver=2)
        let raw: &[u8] = &[
            0x34, 0xF2, // reserved bits set, Ver=2, all flags clear
            0x00, 0x0A, // Tunnel ID = 10
            0x00, 0x14, // Session ID = 20
        ];
        let (buf, result) = dissect(raw).unwrap();
        assert_eq!(result.bytes_consumed, 6);
        assert_eq!(result.next, DispatchHint::ByEtherType(ETHERTYPE_PPP));

        let layer = buf.layer_by_name("L2TP").unwrap();
        // All five defined flags remain 0; reserved bits must not leak in.
        assert_eq!(
            buf.field_by_name(layer, "is_control").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "length_present").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_present").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "offset_present").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "priority").unwrap().value,
            FieldValue::U8(0)
        );
        // Reserved bits in the upper nibble of the second byte must not
        // contaminate the 4-bit Version field.
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "tunnel_id").unwrap().value,
            FieldValue::U16(10)
        );
        assert_eq!(
            buf.field_by_name(layer, "session_id").unwrap().value,
            FieldValue::U16(20)
        );
    }
}
