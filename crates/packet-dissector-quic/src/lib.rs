//! QUIC protocol dissector (header parsing only — payload is encrypted).
//!
//! Parses QUIC Long Headers (Initial, 0-RTT, Handshake, Retry, Version
//! Negotiation) and Short Headers. Since QUIC payload is encrypted, the
//! dissector terminates the chain and does not dispatch to further dissectors.
//!
//! ## References
//! - RFC 8999 (QUIC Invariants): <https://www.rfc-editor.org/rfc/rfc8999>
//! - RFC 9000 (QUIC v1): <https://www.rfc-editor.org/rfc/rfc9000>
//! - RFC 9001 (QUIC-TLS): <https://www.rfc-editor.org/rfc/rfc9001>
//! - RFC 9369 (QUIC v2): <https://www.rfc-editor.org/rfc/rfc9369>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u32;

/// Minimum header size: a single byte is needed to determine header form.
const MIN_HEADER_SIZE: usize = 1;

/// Minimum Long Header size: 1 (flags) + 4 (version) + 1 (DCID len) + 1 (SCID len).
///
/// RFC 9000, Section 17.2 — <https://www.rfc-editor.org/rfc/rfc9000#section-17.2>
const MIN_LONG_HEADER_SIZE: usize = 7;

/// QUIC version 1 (RFC 9000).
const VERSION_1: u32 = 0x0000_0001;

/// QUIC version 2 (RFC 9369).
const VERSION_2: u32 = 0x6b33_43cf;

/// Version Negotiation pseudo-version (RFC 9000, Section 17.2.1).
const VERSION_NEGOTIATION: u32 = 0x0000_0000;

/// Retry Integrity Tag size in bytes.
///
/// RFC 9000, Section 17.2.5 — <https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5>
/// RFC 9001, Section 5.8 — <https://www.rfc-editor.org/rfc/rfc9001#section-5.8>
const RETRY_INTEGRITY_TAG_SIZE: usize = 16;

/// Logical Long Header packet kind, independent of the on-wire type bits.
///
/// QUIC v1 and v2 use different type bits for the same logical packet kind;
/// see [`packet_kind`] for the mapping.
#[derive(Copy, Clone, PartialEq, Eq)]
enum PacketKind {
    /// Initial packet (carries the first CRYPTO frames and ACKs).
    Initial,
    /// 0-RTT packet (early application data before handshake completion).
    ZeroRtt,
    /// Handshake packet (carries cryptographic handshake messages).
    Handshake,
    /// Retry packet (server address-validation token).
    Retry,
}

/// Resolve the logical [`PacketKind`] from a QUIC version and the two
/// "Long Packet Type" bits from byte 0.
///
/// QUIC v1: RFC 9000, Section 17.2, Table 5 —
/// <https://www.rfc-editor.org/rfc/rfc9000#section-17.2>
///
/// QUIC v2: RFC 9369, Section 3.2 —
/// <https://www.rfc-editor.org/rfc/rfc9369#section-3.2>
fn packet_kind(version: u32, type_bits: u8) -> Option<PacketKind> {
    match version {
        VERSION_1 => match type_bits {
            0 => Some(PacketKind::Initial),
            1 => Some(PacketKind::ZeroRtt),
            2 => Some(PacketKind::Handshake),
            3 => Some(PacketKind::Retry),
            _ => None,
        },
        VERSION_2 => match type_bits {
            1 => Some(PacketKind::Initial),
            2 => Some(PacketKind::ZeroRtt),
            3 => Some(PacketKind::Handshake),
            0 => Some(PacketKind::Retry),
            _ => None,
        },
        _ => None,
    }
}

/// Human-readable name for a logical packet kind (used for `packet_type_name`).
fn packet_kind_short(kind: PacketKind) -> &'static str {
    match kind {
        PacketKind::Initial => "Initial",
        PacketKind::ZeroRtt => "0-RTT",
        PacketKind::Handshake => "Handshake",
        PacketKind::Retry => "Retry",
    }
}

/// Display name for a logical packet kind (used as layer display_name).
fn packet_kind_display(kind: PacketKind) -> &'static str {
    match kind {
        PacketKind::Initial => "QUIC Initial",
        PacketKind::ZeroRtt => "QUIC 0-RTT",
        PacketKind::Handshake => "QUIC Handshake",
        PacketKind::Retry => "QUIC Retry",
    }
}

/// Returns a human-readable name for the QUIC version field.
fn version_name(version: u32) -> Option<&'static str> {
    match version {
        VERSION_NEGOTIATION => Some("Version Negotiation"),
        VERSION_1 => Some("QUIC v1"),
        VERSION_2 => Some("QUIC v2"),
        _ => None,
    }
}

/// Decode a QUIC variable-length integer (RFC 9000, Section 16).
///
/// The two most significant bits of the first byte encode the length:
/// - `0b00` → 1 byte  (6-bit value, max 63)
/// - `0b01` → 2 bytes (14-bit value, max 16383)
/// - `0b10` → 4 bytes (30-bit value, max 1073741823)
/// - `0b11` → 8 bytes (62-bit value, max 4611686018427387903)
///
/// Returns `Some((value, bytes_consumed))` on success, `None` if `data` is
/// too short.
fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    let prefix = data[0] >> 6;
    let len = 1usize << prefix; // 1, 2, 4, or 8
    if data.len() < len {
        return None;
    }
    let value = match len {
        1 => u64::from(data[0] & 0x3f),
        2 => {
            let raw = u16::from_be_bytes([data[0], data[1]]);
            u64::from(raw & 0x3fff)
        }
        4 => {
            let raw = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            u64::from(raw & 0x3fff_ffff)
        }
        8 => {
            let raw = u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            raw & 0x3fff_ffff_ffff_ffff
        }
        _ => unreachable!(),
    };
    Some((value, len))
}

/// Index constants for [`FIELD_DESCRIPTORS`].
const FD_HEADER_FORM: usize = 0;
const FD_FIXED_BIT: usize = 1;
const FD_PACKET_TYPE: usize = 2;
const FD_VERSION: usize = 3;
const FD_DCID_LENGTH: usize = 4;
const FD_DCID: usize = 5;
const FD_SCID_LENGTH: usize = 6;
const FD_SCID: usize = 7;
const FD_TOKEN_LENGTH: usize = 8;
const FD_TOKEN: usize = 9;
const FD_LENGTH: usize = 10;
const FD_SUPPORTED_VERSIONS: usize = 11;
const FD_RETRY_TOKEN: usize = 12;
const FD_RETRY_INTEGRITY_TAG: usize = 13;
const FD_SPIN_BIT: usize = 14;
const FD_KEY_PHASE: usize = 15;

/// Field descriptors for the QUIC dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // 0: header_form
    FieldDescriptor {
        name: "header_form",
        display_name: "Header Form",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(0) => Some("Short Header"),
            FieldValue::U8(1) => Some("Long Header"),
            _ => None,
        }),
        format_fn: None,
    },
    // 1: fixed_bit
    FieldDescriptor::new("fixed_bit", "Fixed Bit", FieldType::U8),
    // 2: packet_type (long header only)
    //
    // The display name depends on the QUIC version because v1 and v2 use
    // different Long Packet Type bit values for the same logical packet kind.
    // RFC 9000, Section 17.2, Table 5 — <https://www.rfc-editor.org/rfc/rfc9000#section-17.2>
    // RFC 9369, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc9369#section-3.2>
    FieldDescriptor {
        name: "packet_type",
        display_name: "Packet Type",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, siblings| match v {
            FieldValue::U8(pt) => {
                let version =
                    siblings
                        .iter()
                        .find(|f| f.name() == "version")
                        .and_then(|f| match &f.value {
                            FieldValue::U32(ver) => Some(*ver),
                            _ => None,
                        })?;
                packet_kind(version, *pt).map(packet_kind_short)
            }
            _ => None,
        }),
        format_fn: None,
    },
    // 3: version (long header only)
    FieldDescriptor {
        name: "version",
        display_name: "Version",
        field_type: FieldType::U32,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U32(ver) => version_name(*ver),
            _ => None,
        }),
        format_fn: None,
    },
    // 4: dcid_length (long header only)
    FieldDescriptor::new(
        "dcid_length",
        "Destination Connection ID Length",
        FieldType::U8,
    )
    .optional(),
    // 5: dcid (long header only)
    FieldDescriptor::new("dcid", "Destination Connection ID", FieldType::Bytes).optional(),
    // 6: scid_length (long header only)
    FieldDescriptor::new("scid_length", "Source Connection ID Length", FieldType::U8).optional(),
    // 7: scid (long header only)
    FieldDescriptor::new("scid", "Source Connection ID", FieldType::Bytes).optional(),
    // 8: token_length (Initial only)
    FieldDescriptor::new("token_length", "Token Length", FieldType::U64).optional(),
    // 9: token (Initial only)
    FieldDescriptor::new("token", "Token", FieldType::Bytes).optional(),
    // 10: length (non-Retry long header)
    FieldDescriptor::new("length", "Length", FieldType::U64).optional(),
    // 11: supported_versions (Version Negotiation only)
    FieldDescriptor::new("supported_versions", "Supported Versions", FieldType::Array).optional(),
    // 12: retry_token (Retry only) — RFC 9000, Section 17.2.5
    FieldDescriptor::new("retry_token", "Retry Token", FieldType::Bytes).optional(),
    // 13: retry_integrity_tag (Retry only) — RFC 9001, Section 5.8
    FieldDescriptor::new(
        "retry_integrity_tag",
        "Retry Integrity Tag",
        FieldType::Bytes,
    )
    .optional(),
    // 14: spin_bit (short header only)
    FieldDescriptor::new("spin_bit", "Spin Bit", FieldType::U8).optional(),
    // 15: key_phase (short header only)
    FieldDescriptor::new("key_phase", "Key Phase", FieldType::U8).optional(),
];

/// Dummy descriptor for version entries inside the supported_versions Array.
static FD_VERSION_ENTRY: FieldDescriptor =
    FieldDescriptor::new("version", "Version", FieldType::U32);

/// QUIC packet header dissector.
pub struct QuicDissector;

impl Dissector for QuicDissector {
    fn name(&self) -> &'static str {
        "QUIC"
    }

    fn short_name(&self) -> &'static str {
        "QUIC"
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

        let first_byte = data[0];
        let header_form = (first_byte >> 7) & 1;

        if header_form == 1 {
            self.dissect_long_header(data, buf, offset, first_byte)
        } else {
            self.dissect_short_header(data, buf, offset, first_byte)
        }
    }
}

impl QuicDissector {
    /// Push the common Long Header fields shared by all long header types:
    /// version, dcid_length, dcid, scid_length, scid.
    #[allow(clippy::too_many_arguments)]
    fn push_common_long_fields<'pkt>(
        buf: &mut DissectBuffer<'pkt>,
        version: u32,
        dcid: &'pkt [u8],
        dcid_len: usize,
        scid: &'pkt [u8],
        scid_len: usize,
        scid_len_offset: usize,
        scid_start: usize,
        scid_end: usize,
        offset: usize,
    ) {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U32(version),
            offset + 1..offset + 5,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DCID_LENGTH],
            FieldValue::U8(dcid_len as u8),
            offset + 5..offset + 6,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DCID],
            FieldValue::Bytes(dcid),
            offset + 6..offset + 6 + dcid_len,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SCID_LENGTH],
            FieldValue::U8(scid_len as u8),
            offset + scid_len_offset..offset + scid_len_offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SCID],
            FieldValue::Bytes(scid),
            offset + scid_start..offset + scid_end,
        );
    }

    /// Parse a QUIC Long Header packet.
    ///
    /// RFC 9000, Section 17.2 — <https://www.rfc-editor.org/rfc/rfc9000#section-17.2>
    fn dissect_long_header<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
        first_byte: u8,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < MIN_LONG_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_LONG_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let header_form = (first_byte >> 7) & 1;
        let fixed_bit = (first_byte >> 6) & 1;
        let version = read_be_u32(data, 1)?;
        let dcid_len = data[5] as usize;

        let scid_len_offset = 6 + dcid_len;
        if data.len() < scid_len_offset + 1 {
            return Err(PacketError::Truncated {
                expected: scid_len_offset + 1,
                actual: data.len(),
            });
        }

        let dcid = &data[6..6 + dcid_len];
        let scid_len = data[scid_len_offset] as usize;
        let scid_start = scid_len_offset + 1;
        let scid_end = scid_start + scid_len;

        if data.len() < scid_end {
            return Err(PacketError::Truncated {
                expected: scid_end,
                actual: data.len(),
            });
        }

        let scid = &data[scid_start..scid_end];
        let mut cursor = scid_end;

        let display_name: Option<&'static str>;

        if version == VERSION_NEGOTIATION {
            // RFC 9000, Section 17.2.1 — Version Negotiation
            display_name = Some("QUIC Version Negotiation");

            buf.begin_layer(
                self.short_name(),
                display_name,
                FIELD_DESCRIPTORS,
                offset..offset + data.len(),
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_HEADER_FORM],
                FieldValue::U8(header_form),
                offset..offset + 1,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FIXED_BIT],
                FieldValue::U8(fixed_bit),
                offset..offset + 1,
            );

            Self::push_common_long_fields(
                buf,
                version,
                dcid,
                dcid_len,
                scid,
                scid_len,
                scid_len_offset,
                scid_start,
                scid_end,
                offset,
            );

            let versions_data = &data[cursor..];
            let array_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_SUPPORTED_VERSIONS],
                FieldValue::Array(0..0),
                offset + cursor..offset + data.len(),
            );
            let mut vi = 0;
            while vi + 4 <= versions_data.len() {
                let ver = read_be_u32(versions_data, vi)?;
                buf.push_field(
                    &FD_VERSION_ENTRY,
                    FieldValue::U32(ver),
                    offset + cursor + vi..offset + cursor + vi + 4,
                );
                vi += 4;
            }
            buf.end_container(array_idx);
        } else {
            // RFC 9000, Section 17.2 — Long Packet Type is bits 5..=4 of byte 0.
            // Table 5 (v1) and RFC 9369, Section 3.2 (v2) give version-specific
            // mappings from these bits to the logical packet kind.
            let packet_type = (first_byte >> 4) & 0x03;
            let kind = packet_kind(version, packet_type);
            display_name = kind.map(packet_kind_display);

            buf.begin_layer(
                self.short_name(),
                display_name,
                FIELD_DESCRIPTORS,
                offset..offset + data.len(),
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_HEADER_FORM],
                FieldValue::U8(header_form),
                offset..offset + 1,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FIXED_BIT],
                FieldValue::U8(fixed_bit),
                offset..offset + 1,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_PACKET_TYPE],
                FieldValue::U8(packet_type),
                offset..offset + 1,
            );
            Self::push_common_long_fields(
                buf,
                version,
                dcid,
                dcid_len,
                scid,
                scid_len,
                scid_len_offset,
                scid_start,
                scid_end,
                offset,
            );

            // RFC 9000, Section 17.2.2 — Initial packets carry Token Length + Token
            // before the Length field. Other long-header kinds (0-RTT, Handshake)
            // omit the token fields; Retry has no Token Length either.
            if matches!(kind, Some(PacketKind::Initial)) {
                if cursor >= data.len() {
                    return Err(PacketError::Truncated {
                        expected: cursor + 1,
                        actual: data.len(),
                    });
                }
                let (token_len, token_vi_size) =
                    decode_varint(&data[cursor..]).ok_or(PacketError::Truncated {
                        expected: cursor + 1,
                        actual: data.len(),
                    })?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_TOKEN_LENGTH],
                    FieldValue::U64(token_len),
                    offset + cursor..offset + cursor + token_vi_size,
                );
                cursor += token_vi_size;

                let token_len_usize = token_len as usize;
                if data.len() < cursor + token_len_usize {
                    return Err(PacketError::Truncated {
                        expected: cursor + token_len_usize,
                        actual: data.len(),
                    });
                }
                let token = &data[cursor..cursor + token_len_usize];
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_TOKEN],
                    FieldValue::Bytes(token),
                    offset + cursor..offset + cursor + token_len_usize,
                );
                cursor += token_len_usize;
            }

            match kind {
                Some(PacketKind::Retry) => {
                    // RFC 9000, Section 17.2.5 — Retry has a variable-length
                    // Retry Token followed by a 128-bit Retry Integrity Tag
                    // (RFC 9001, Section 5.8). No Length or Packet Number.
                    if data.len() < cursor + RETRY_INTEGRITY_TAG_SIZE {
                        return Err(PacketError::Truncated {
                            expected: cursor + RETRY_INTEGRITY_TAG_SIZE,
                            actual: data.len(),
                        });
                    }
                    let token_end = data.len() - RETRY_INTEGRITY_TAG_SIZE;
                    let retry_token = &data[cursor..token_end];
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_RETRY_TOKEN],
                        FieldValue::Bytes(retry_token),
                        offset + cursor..offset + token_end,
                    );
                    let integrity_tag = &data[token_end..];
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_RETRY_INTEGRITY_TAG],
                        FieldValue::Bytes(integrity_tag),
                        offset + token_end..offset + data.len(),
                    );
                }
                Some(PacketKind::Initial | PacketKind::ZeroRtt | PacketKind::Handshake) => {
                    // RFC 9000, Section 17.2 — Length field is a variable-length
                    // integer giving the combined length of Packet Number and
                    // Packet Payload. Both are header-protected and therefore
                    // opaque without decryption keys.
                    if cursor >= data.len() {
                        return Err(PacketError::Truncated {
                            expected: cursor + 1,
                            actual: data.len(),
                        });
                    }
                    let (length, length_vi_size) =
                        decode_varint(&data[cursor..]).ok_or(PacketError::Truncated {
                            expected: cursor + 1,
                            actual: data.len(),
                        })?;
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_LENGTH],
                        FieldValue::U64(length),
                        offset + cursor..offset + cursor + length_vi_size,
                    );
                }
                None => {
                    // Unknown version: the type-specific layout of the first
                    // byte is not defined. Emit only the version-invariant
                    // fields per RFC 8999, Section 5.1.
                }
            }
        }

        buf.end_layer();

        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }

    /// Parse a QUIC Short Header (1-RTT) packet.
    ///
    /// RFC 9000, Section 17.3 — <https://www.rfc-editor.org/rfc/rfc9000#section-17.3>
    ///
    /// Without connection state, the DCID length is unknown, so we only parse
    /// the first byte flags.
    fn dissect_short_header<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
        first_byte: u8,
    ) -> Result<DissectResult, PacketError> {
        let header_form = (first_byte >> 7) & 1;
        let fixed_bit = (first_byte >> 6) & 1;
        let spin_bit = (first_byte >> 5) & 1;
        let key_phase = (first_byte >> 2) & 1;

        buf.begin_layer(
            self.short_name(),
            Some("QUIC Short Header"),
            FIELD_DESCRIPTORS,
            offset..offset + data.len(),
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HEADER_FORM],
            FieldValue::U8(header_form),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FIXED_BIT],
            FieldValue::U8(fixed_bit),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SPIN_BIT],
            FieldValue::U8(spin_bit),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_KEY_PHASE],
            FieldValue::U8(key_phase),
            offset..offset + 1,
        );
        buf.end_layer();

        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 9000 / RFC 9001 / RFC 9369 Coverage
    //
    // | RFC Section         | Description                        | Test                                 |
    // |---------------------|------------------------------------|--------------------------------------|
    // | 9000 §17.2          | Long Header Format                 | test_parse_initial                   |
    // | 9000 §17.2          | Long Header: DCID/SCID             | test_parse_initial                   |
    // | 9000 §17.2.1        | Version Negotiation                | test_parse_version_negotiation       |
    // | 9000 §17.2.2        | Initial Packet                     | test_parse_initial                   |
    // | 9000 §17.2.2        | Initial Packet (with token)        | test_parse_initial_with_token        |
    // | 9000 §17.2.3        | 0-RTT Packet                       | test_parse_zero_rtt                  |
    // | 9000 §17.2.4        | Handshake Packet                   | test_parse_handshake                 |
    // | 9000 §17.2.5        | Retry Packet (token + integrity)   | test_parse_retry                     |
    // | 9000 §17.2.5        | Retry Packet (non-empty token)     | test_parse_retry_with_token          |
    // | 9001 §5.8           | Retry Integrity Tag (16 bytes)     | test_parse_retry                     |
    // | 9001 §5.8           | Retry truncated below 16-byte tag  | test_truncated_retry_integrity_tag   |
    // | 9000 §17.3, §17.3.1 | Short Header (1-RTT)               | test_parse_short_header              |
    // | 9000 §16            | Variable-Length Integer (1 byte)   | test_decode_varint_1byte             |
    // | 9000 §16            | Variable-Length Integer (2 bytes)  | test_decode_varint_2byte             |
    // | 9000 §16            | Variable-Length Integer (4 bytes)  | test_decode_varint_4byte             |
    // | 9000 §16            | Variable-Length Integer (8 bytes)  | test_decode_varint_8byte             |
    // | 9000 §16            | Variable-Length Integer truncated  | test_decode_varint_truncated         |
    // | 9369 §3.1           | QUIC v2 version field (0x6b3343cf) | test_parse_quic_v2_handshake         |
    // | 9369 §3.2           | QUIC v2 Initial (type=0b01)        | test_parse_quic_v2_initial           |
    // | 9369 §3.2           | QUIC v2 0-RTT (type=0b10)          | test_parse_quic_v2_zero_rtt          |
    // | 9369 §3.2           | QUIC v2 Handshake (type=0b11)      | test_parse_quic_v2_handshake         |
    // | 9369 §3.2           | QUIC v2 Retry (type=0b00)          | test_parse_quic_v2_retry             |
    // | 8999 §5.1           | Unknown version: invariant fields  | test_parse_unknown_version           |
    // | ---                 | Truncated (empty)                  | test_truncated_empty                 |
    // | ---                 | Truncated long header              | test_truncated_long_header           |
    // | ---                 | Truncated DCID                     | test_truncated_dcid                  |
    // | ---                 | Truncated SCID                     | test_truncated_scid                  |

    /// Encode a variable-length integer per RFC 9000, Section 16.
    fn encode_varint(value: u64) -> Vec<u8> {
        if value <= 63 {
            vec![value as u8]
        } else if value <= 16383 {
            let v = (value as u16) | 0x4000;
            v.to_be_bytes().to_vec()
        } else if value <= 0x3fff_ffff {
            let v = (value as u32) | 0x8000_0000;
            v.to_be_bytes().to_vec()
        } else {
            let v = value | 0xc000_0000_0000_0000;
            v.to_be_bytes().to_vec()
        }
    }

    /// Map a logical `PacketKind` to the on-wire Long Packet Type bits for a
    /// given QUIC version.
    ///
    /// RFC 9000 §17.2 Table 5 (v1); RFC 9369 §3.2 (v2).
    fn kind_to_type_bits(version: u32, kind: PacketKind) -> u8 {
        match (version, kind) {
            (VERSION_1, PacketKind::Initial) => 0,
            (VERSION_1, PacketKind::ZeroRtt) => 1,
            (VERSION_1, PacketKind::Handshake) => 2,
            (VERSION_1, PacketKind::Retry) => 3,
            (VERSION_2, PacketKind::Initial) => 1,
            (VERSION_2, PacketKind::ZeroRtt) => 2,
            (VERSION_2, PacketKind::Handshake) => 3,
            (VERSION_2, PacketKind::Retry) => 0,
            _ => 0,
        }
    }

    /// Build a QUIC Long Header packet for the given version and logical kind.
    ///
    /// * For `Initial`, `token` is the Token field (empty slice if absent) and
    ///   `payload` is the post-Length bytes (Packet Number + Packet Payload).
    /// * For `ZeroRtt` / `Handshake`, `token` is ignored; `payload` is
    ///   post-Length bytes.
    /// * For `Retry`, `token` is the Retry Token and `payload` must be exactly
    ///   the 16-byte Retry Integrity Tag (RFC 9001 §5.8).
    fn build_long_header(
        version: u32,
        kind: PacketKind,
        dcid: &[u8],
        scid: &[u8],
        token: Option<&[u8]>,
        payload: &[u8],
    ) -> Vec<u8> {
        let type_bits = kind_to_type_bits(version, kind);
        let first_byte = 0xc0 | (type_bits << 4);
        let mut pkt = vec![first_byte];
        pkt.extend_from_slice(&version.to_be_bytes());
        pkt.push(dcid.len() as u8);
        pkt.extend_from_slice(dcid);
        pkt.push(scid.len() as u8);
        pkt.extend_from_slice(scid);
        match kind {
            PacketKind::Initial => {
                let token = token.unwrap_or(&[]);
                pkt.extend_from_slice(&encode_varint(token.len() as u64));
                pkt.extend_from_slice(token);
                pkt.extend_from_slice(&encode_varint(payload.len() as u64));
                pkt.extend_from_slice(payload);
            }
            PacketKind::ZeroRtt | PacketKind::Handshake => {
                pkt.extend_from_slice(&encode_varint(payload.len() as u64));
                pkt.extend_from_slice(payload);
            }
            PacketKind::Retry => {
                if let Some(t) = token {
                    pkt.extend_from_slice(t);
                }
                // Payload must be the 16-byte Retry Integrity Tag.
                pkt.extend_from_slice(payload);
            }
        }
        pkt
    }

    /// Build a QUIC Version Negotiation packet.
    fn build_version_negotiation(dcid: &[u8], scid: &[u8], versions: &[u32]) -> Vec<u8> {
        let first_byte = 0x80; // header_form=1, rest can be arbitrary
        let mut pkt = vec![first_byte];
        pkt.extend_from_slice(&0u32.to_be_bytes()); // version = 0
        pkt.push(dcid.len() as u8);
        pkt.extend_from_slice(dcid);
        pkt.push(scid.len() as u8);
        pkt.extend_from_slice(scid);
        for &v in versions {
            pkt.extend_from_slice(&v.to_be_bytes());
        }
        pkt
    }

    /// Build a QUIC Short Header packet.
    fn build_short_header(spin_bit: u8, key_phase: u8, payload: &[u8]) -> Vec<u8> {
        let first_byte = 0x40 | (spin_bit << 5) | (key_phase << 2);
        let mut pkt = vec![first_byte];
        pkt.extend_from_slice(payload);
        pkt
    }

    // --- Variable-length integer tests ---

    #[test]
    fn test_decode_varint_1byte() {
        // RFC 9000, Section 16 — Example: 37 encoded as 0x25
        assert_eq!(decode_varint(&[0x25]), Some((37, 1)));
        assert_eq!(decode_varint(&[0x00]), Some((0, 1)));
        assert_eq!(decode_varint(&[0x3f]), Some((63, 1)));
    }

    #[test]
    fn test_decode_varint_2byte() {
        // RFC 9000, Section 16 — Example: 15293 encoded as 0x7bbd
        assert_eq!(decode_varint(&[0x7b, 0xbd]), Some((15293, 2)));
    }

    #[test]
    fn test_decode_varint_4byte() {
        // RFC 9000, Section 16 — Example: 494878333 encoded as 0x9d7f3e7d
        assert_eq!(
            decode_varint(&[0x9d, 0x7f, 0x3e, 0x7d]),
            Some((494878333, 4))
        );
    }

    #[test]
    fn test_decode_varint_8byte() {
        // RFC 9000, Section 16 — Example: 151288809941952652 encoded as 0xc2197c5eff14e88c
        assert_eq!(
            decode_varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
            Some((151288809941952652, 8))
        );
    }

    #[test]
    fn test_decode_varint_truncated() {
        assert_eq!(decode_varint(&[]), None);
        // 2-byte encoding but only 1 byte available
        assert_eq!(decode_varint(&[0x40]), None);
        // 4-byte encoding but only 2 bytes available
        assert_eq!(decode_varint(&[0x80, 0x00]), None);
        // 8-byte encoding but only 4 bytes available
        assert_eq!(decode_varint(&[0xc0, 0x00, 0x00, 0x00]), None);
    }

    // --- Long Header: Initial ---

    #[test]
    fn test_parse_initial() {
        let dcid = [0x01, 0x02, 0x03, 0x04];
        let scid = [0x05, 0x06];
        let payload = [0xAA; 10];
        // Initial with empty token
        let data = build_long_header(VERSION_1, PacketKind::Initial, &dcid, &scid, None, &payload);

        let mut buf = DissectBuffer::new();
        let result = QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, data.len());
        assert!(matches!(result.next, DispatchHint::End));

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(layer.display_name, Some("QUIC Initial"));
        assert_eq!(
            buf.field_by_name(layer, "header_form").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "fixed_bit").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "packet_type_name"),
            Some("Initial")
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U32(VERSION_1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "version_name"),
            Some("QUIC v1")
        );
        assert_eq!(
            buf.field_by_name(layer, "dcid_length").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            buf.field_by_name(layer, "dcid").unwrap().value,
            FieldValue::Bytes(&dcid)
        );
        assert_eq!(
            buf.field_by_name(layer, "scid_length").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "scid").unwrap().value,
            FieldValue::Bytes(&scid)
        );
        assert_eq!(
            buf.field_by_name(layer, "token_length").unwrap().value,
            FieldValue::U64(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "token").unwrap().value,
            FieldValue::Bytes(&[])
        );
        assert!(buf.field_by_name(layer, "length").is_some());
    }

    #[test]
    fn test_parse_initial_with_token() {
        let dcid = [0x01];
        let scid = [0x02];
        let token = [0xDE, 0xAD, 0xBE, 0xEF];
        let payload = [0xBB; 5];
        let data = build_long_header(
            VERSION_1,
            PacketKind::Initial,
            &dcid,
            &scid,
            Some(&token),
            &payload,
        );

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "token_length").unwrap().value,
            FieldValue::U64(4)
        );
        assert_eq!(
            buf.field_by_name(layer, "token").unwrap().value,
            FieldValue::Bytes(&token)
        );
    }

    // --- Long Header: 0-RTT ---

    #[test]
    fn test_parse_zero_rtt() {
        let dcid = [0x10, 0x20];
        let scid = [0x30];
        let payload = [0xCC; 8];
        let data = build_long_header(VERSION_1, PacketKind::ZeroRtt, &dcid, &scid, None, &payload);

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(layer.display_name, Some("QUIC 0-RTT"));
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "packet_type_name"),
            Some("0-RTT")
        );
        assert!(buf.field_by_name(layer, "token_length").is_none());
        assert!(buf.field_by_name(layer, "token").is_none());
        assert!(buf.field_by_name(layer, "length").is_some());
    }

    // --- Long Header: Handshake ---

    #[test]
    fn test_parse_handshake() {
        let dcid = [0x01, 0x02, 0x03];
        let scid = [0x04, 0x05, 0x06];
        let payload = [0xDD; 12];
        let data = build_long_header(
            VERSION_1,
            PacketKind::Handshake,
            &dcid,
            &scid,
            None,
            &payload,
        );

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(layer.display_name, Some("QUIC Handshake"));
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "packet_type_name"),
            Some("Handshake")
        );
        assert!(buf.field_by_name(layer, "length").is_some());
    }

    // --- Long Header: Retry ---

    #[test]
    fn test_parse_retry() {
        let dcid = [0xAA];
        let scid = [0xBB];
        let integrity_tag = [0xFF; 16];
        // RFC 9000 §17.2.5: empty Retry Token is permitted by the wire format
        // (clients MUST discard them per §17.2.5.2, but that is policy, not parse).
        let data = build_long_header(
            VERSION_1,
            PacketKind::Retry,
            &dcid,
            &scid,
            None,
            &integrity_tag,
        );

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(layer.display_name, Some("QUIC Retry"));
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "packet_type_name"),
            Some("Retry")
        );
        // RFC 9000 §17.2 — Retry has no Length or Packet Number.
        assert!(buf.field_by_name(layer, "length").is_none());
        // RFC 9000 §17.2.5 — Retry has no Token Length (the token fills the
        // packet up to the Integrity Tag), only Retry Token + Integrity Tag.
        assert!(buf.field_by_name(layer, "token_length").is_none());
        assert!(buf.field_by_name(layer, "token").is_none());
        assert_eq!(
            buf.field_by_name(layer, "retry_token").unwrap().value,
            FieldValue::Bytes(&[])
        );
        assert_eq!(
            buf.field_by_name(layer, "retry_integrity_tag")
                .unwrap()
                .value,
            FieldValue::Bytes(&integrity_tag)
        );
    }

    #[test]
    fn test_parse_retry_with_token() {
        let dcid = [0xAA, 0xBB];
        let scid = [0xCC];
        let token = [0x01, 0x02, 0x03, 0x04, 0x05];
        let integrity_tag = [0xA5; 16];
        let data = build_long_header(
            VERSION_1,
            PacketKind::Retry,
            &dcid,
            &scid,
            Some(&token),
            &integrity_tag,
        );

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "retry_token").unwrap().value,
            FieldValue::Bytes(&token)
        );
        assert_eq!(
            buf.field_by_name(layer, "retry_integrity_tag")
                .unwrap()
                .value,
            FieldValue::Bytes(&integrity_tag)
        );
    }

    #[test]
    fn test_truncated_retry_integrity_tag() {
        // RFC 9001 §5.8 — Retry Integrity Tag is 128 bits.  A packet that has
        // the Retry type but fewer than 16 bytes after the SCID cannot contain
        // a tag and must be reported as Truncated.
        let mut data = vec![0xf0]; // header_form=1, fixed=1, type=0b11 (v1 Retry)
        data.extend_from_slice(&VERSION_1.to_be_bytes());
        data.push(0); // DCID length = 0
        data.push(0); // SCID length = 0
        // Only 3 bytes where 16 are required for the Integrity Tag.
        data.extend_from_slice(&[0x00; 3]);
        let mut buf = DissectBuffer::new();
        let err = QuicDissector.dissect(&data, &mut buf, 0).unwrap_err();
        let PacketError::Truncated { expected, actual } = err else {
            panic!("expected Truncated, got {err:?}");
        };
        assert_eq!(actual, data.len());
        assert_eq!(expected, data.len() - 3 + RETRY_INTEGRITY_TAG_SIZE);
    }

    // --- Version Negotiation ---

    #[test]
    fn test_parse_version_negotiation() {
        let dcid = [0x01, 0x02];
        let scid = [0x03, 0x04];
        let data = build_version_negotiation(&dcid, &scid, &[VERSION_1, VERSION_2]);

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(layer.display_name, Some("QUIC Version Negotiation"));
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U32(VERSION_NEGOTIATION)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "version_name"),
            Some("Version Negotiation")
        );

        // No packet_type for Version Negotiation
        assert!(buf.field_by_name(layer, "packet_type").is_none());

        let versions_field = buf.field_by_name(layer, "supported_versions").unwrap();
        if let FieldValue::Array(ref range) = versions_field.value {
            let children = buf.nested_fields(range);
            assert_eq!(children.len(), 2);
            assert_eq!(children[0].value, FieldValue::U32(VERSION_1));
            assert_eq!(children[1].value, FieldValue::U32(VERSION_2));
        } else {
            panic!("expected Array");
        }
    }

    // --- Short Header ---

    #[test]
    fn test_parse_short_header() {
        let payload = [0x11; 20];
        let data = build_short_header(1, 1, &payload);

        let mut buf = DissectBuffer::new();
        let result = QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, data.len());
        assert!(matches!(result.next, DispatchHint::End));

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(layer.display_name, Some("QUIC Short Header"));
        assert_eq!(
            buf.field_by_name(layer, "header_form").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "header_form_name"),
            Some("Short Header")
        );
        assert_eq!(
            buf.field_by_name(layer, "spin_bit").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "key_phase").unwrap().value,
            FieldValue::U8(1)
        );
        // Short header doesn't have version or packet_type
        assert!(buf.field_by_name(layer, "version").is_none());
        assert!(buf.field_by_name(layer, "packet_type").is_none());
    }

    #[test]
    fn test_parse_short_header_no_spin() {
        let data = build_short_header(0, 0, &[0x22; 5]);

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "spin_bit").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "key_phase").unwrap().value,
            FieldValue::U8(0)
        );
    }

    // --- QUIC v2 (RFC 9369 §3.2) ---
    //
    // Type bit values differ from v1:
    //   Initial = 0b01, 0-RTT = 0b10, Handshake = 0b11, Retry = 0b00.

    #[test]
    fn test_parse_quic_v2_initial() {
        let dcid = [0x01];
        let scid = [0x02];
        let token = [0xDE, 0xAD];
        let payload = [0xEE; 6];
        let data = build_long_header(
            VERSION_2,
            PacketKind::Initial,
            &dcid,
            &scid,
            Some(&token),
            &payload,
        );

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(layer.display_name, Some("QUIC Initial"));
        // RFC 9369 §3.2 — Initial in v2 is 0b01.
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U8(0b01)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "packet_type_name"),
            Some("Initial")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "version_name"),
            Some("QUIC v2")
        );
        assert_eq!(
            buf.field_by_name(layer, "token_length").unwrap().value,
            FieldValue::U64(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "token").unwrap().value,
            FieldValue::Bytes(&token)
        );
        assert!(buf.field_by_name(layer, "length").is_some());
    }

    #[test]
    fn test_parse_quic_v2_zero_rtt() {
        let dcid = [0x10];
        let scid = [0x20];
        let payload = [0xCC; 8];
        let data = build_long_header(VERSION_2, PacketKind::ZeroRtt, &dcid, &scid, None, &payload);

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(layer.display_name, Some("QUIC 0-RTT"));
        // RFC 9369 §3.2 — 0-RTT in v2 is 0b10.
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U8(0b10)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "packet_type_name"),
            Some("0-RTT")
        );
        assert!(buf.field_by_name(layer, "token_length").is_none());
        assert!(buf.field_by_name(layer, "token").is_none());
        assert!(buf.field_by_name(layer, "length").is_some());
    }

    #[test]
    fn test_parse_quic_v2_handshake() {
        let dcid = [0x01, 0x02];
        let scid = [0x03];
        let payload = [0xDD; 12];
        let data = build_long_header(
            VERSION_2,
            PacketKind::Handshake,
            &dcid,
            &scid,
            None,
            &payload,
        );

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(layer.display_name, Some("QUIC Handshake"));
        // RFC 9369 §3.2 — Handshake in v2 is 0b11.
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U8(0b11)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "packet_type_name"),
            Some("Handshake")
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U32(VERSION_2)
        );
        assert!(buf.field_by_name(layer, "token_length").is_none());
        assert!(buf.field_by_name(layer, "length").is_some());
    }

    #[test]
    fn test_parse_quic_v2_retry() {
        let dcid = [0xAA];
        let scid = [0xBB];
        let token = [0x11, 0x22, 0x33];
        let integrity_tag = [0x7E; 16];
        let data = build_long_header(
            VERSION_2,
            PacketKind::Retry,
            &dcid,
            &scid,
            Some(&token),
            &integrity_tag,
        );

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(layer.display_name, Some("QUIC Retry"));
        // RFC 9369 §3.2 — Retry in v2 is 0b00 (the value that meant Initial in v1).
        assert_eq!(
            buf.field_by_name(layer, "packet_type").unwrap().value,
            FieldValue::U8(0b00)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "packet_type_name"),
            Some("Retry")
        );
        // Retry: no length, token/length fields are absent.
        assert!(buf.field_by_name(layer, "length").is_none());
        assert!(buf.field_by_name(layer, "token_length").is_none());
        assert_eq!(
            buf.field_by_name(layer, "retry_token").unwrap().value,
            FieldValue::Bytes(&token)
        );
        assert_eq!(
            buf.field_by_name(layer, "retry_integrity_tag")
                .unwrap()
                .value,
            FieldValue::Bytes(&integrity_tag)
        );
    }

    #[test]
    fn test_parse_unknown_version() {
        // RFC 8999 §5.1 — For unknown versions, only the version-invariant
        // fields (header form, version, DCID, SCID) have defined semantics.
        let dcid = [0x01, 0x02];
        let scid = [0x03];
        let mut data = vec![0xc0];
        data.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        data.push(dcid.len() as u8);
        data.extend_from_slice(&dcid);
        data.push(scid.len() as u8);
        data.extend_from_slice(&scid);
        // Some trailing bytes that are meaningless without version-specific rules.
        data.extend_from_slice(&[0x00, 0x00]);

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        // Unknown version: no layer-level display_name override.
        assert_eq!(layer.display_name, None);
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U32(0xDEAD_BEEF)
        );
        assert!(buf.resolve_display_name(layer, "version_name").is_none());
        assert_eq!(
            buf.field_by_name(layer, "dcid").unwrap().value,
            FieldValue::Bytes(&dcid)
        );
        assert_eq!(
            buf.field_by_name(layer, "scid").unwrap().value,
            FieldValue::Bytes(&scid)
        );
        // packet_type bits are recorded but have no version-defined name.
        assert!(buf.field_by_name(layer, "packet_type").is_some());
        assert!(
            buf.resolve_display_name(layer, "packet_type_name")
                .is_none()
        );
        // Neither token, length, nor retry fields should be emitted.
        assert!(buf.field_by_name(layer, "token_length").is_none());
        assert!(buf.field_by_name(layer, "length").is_none());
        assert!(buf.field_by_name(layer, "retry_token").is_none());
    }

    // --- Truncation errors ---

    #[test]
    fn test_truncated_empty() {
        let data: &[u8] = &[];
        let mut buf = DissectBuffer::new();
        let err = QuicDissector.dissect(data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 1,
                actual: 0
            }
        ));
    }

    #[test]
    fn test_truncated_long_header() {
        // Long header bit set, but only 4 bytes (need at least 7)
        let data = [0xc0, 0x00, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        let err = QuicDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 7,
                actual: 4
            }
        ));
    }

    #[test]
    fn test_truncated_dcid() {
        // DCID length says 10, but not enough data
        let mut data = vec![0xc0];
        data.extend_from_slice(&VERSION_1.to_be_bytes());
        data.push(10); // DCID length = 10
        data.extend_from_slice(&[0x00; 3]); // only 3 bytes of DCID + need SCID len byte
        let mut buf = DissectBuffer::new();
        let err = QuicDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    #[test]
    fn test_truncated_scid() {
        // DCID ok, SCID length exceeds data
        let mut data = vec![0xc0];
        data.extend_from_slice(&VERSION_1.to_be_bytes());
        data.push(2); // DCID length = 2
        data.extend_from_slice(&[0x01, 0x02]); // DCID
        data.push(10); // SCID length = 10
        data.extend_from_slice(&[0x03; 3]); // only 3 bytes of SCID
        let mut buf = DissectBuffer::new();
        let err = QuicDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    // --- Other tests ---

    #[test]
    fn test_field_descriptors() {
        let descriptors = QuicDissector.field_descriptors();
        assert_eq!(descriptors.len(), 16);
        assert_eq!(descriptors[FD_HEADER_FORM].name, "header_form");
        assert_eq!(descriptors[FD_RETRY_TOKEN].name, "retry_token");
        assert_eq!(
            descriptors[FD_RETRY_INTEGRITY_TAG].name,
            "retry_integrity_tag"
        );
        assert_eq!(descriptors[FD_KEY_PHASE].name, "key_phase");
    }

    #[test]
    fn test_dissect_with_offset() {
        let dcid = [0x01];
        let scid = [0x02];
        let payload = [0xAA; 5];
        let data = build_long_header(
            VERSION_1,
            PacketKind::Handshake,
            &dcid,
            &scid,
            None,
            &payload,
        );
        let offset = 42;

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, offset).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(layer.range, offset..offset + data.len());
        // version field should be at bytes 1..5 relative to data start
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().range,
            offset + 1..offset + 5
        );
    }

    #[test]
    fn test_version_negotiation_empty_versions() {
        let dcid = [0x01];
        let scid = [0x02];
        let data = build_version_negotiation(&dcid, &scid, &[]);

        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("QUIC").unwrap();
        let versions_field = buf.field_by_name(layer, "supported_versions").unwrap();
        if let FieldValue::Array(ref range) = versions_field.value {
            let children = buf.nested_fields(range);
            assert_eq!(children.len(), 0);
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn test_display_name_header_form() {
        // Long header
        let data = build_long_header(
            VERSION_1,
            PacketKind::Handshake,
            &[0x01],
            &[0x02],
            None,
            &[0xAA; 5],
        );
        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "header_form_name"),
            Some("Long Header")
        );

        // Short header
        let data = build_short_header(0, 0, &[0xBB; 5]);
        let mut buf = DissectBuffer::new();
        QuicDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("QUIC").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "header_form_name"),
            Some("Short Header")
        );
    }
}
