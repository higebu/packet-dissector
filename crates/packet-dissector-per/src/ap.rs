//! Helpers for the ASN.1 structures common to the 3GPP application
//! protocols (S1AP, NGAP, X2AP, XnAP, ...): octet-aligned fields, the
//! `ProtocolExtensionContainer`, `ProtocolIE-SingleContainer`, and the
//! preamble and tail of extensible SEQUENCEs.
//!
//! ## References
//! - ITU-T Rec. X.691 (02/2021), Sections 11.2, 16, 17, 19:
//!   <https://www.itu.int/rec/T-REC-X.691>
//! - 3GPP TS 36.413, Section 9.3.7 (S1AP containers):
//!   <https://www.3gpp.org/ftp/Specs/archive/36_series/36.413/>
//! - 3GPP TS 38.413, Section 9.4.8 (NGAP containers):
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/>

use core::ops::Range;

use packet_dissector_core::error::PacketError;

use crate::AperReader;

/// `maxProtocolExtensions` of the 3GPP application protocols.
///
/// 3GPP TS 36.413, Section 9.3.8; TS 38.413, Section 9.4.9 — both define
/// `maxProtocolExtensions INTEGER ::= 65535`.
pub const MAX_PROTOCOL_EXTENSIONS: u64 = 65535;

/// Checks that the decoder consumed the whole open type value.
///
/// ITU-T Rec. X.691, Section 11.2 — an open type field holds exactly the
/// complete encoding of its value: the encoded bits padded to an octet
/// boundary, or a single zero octet for an empty encoding (Section
/// 10.1.3). Leftover octets mean the value is malformed.
pub fn ensure_consumed(r: &AperReader<'_>, data: &[u8]) -> Result<(), PacketError> {
    if r.bit_position().div_ceil(8).max(1) != data.len() {
        return Err(PacketError::InvalidHeader(
            "APER open type value has trailing octets",
        ));
    }
    Ok(())
}

/// Aligns to an octet boundary, reads `n` octets and returns them with
/// their byte range relative to the start of the reader's buffer.
///
/// Used for octet-aligned fields: fixed-size OCTET STRINGs longer than two
/// octets (ITU-T Rec. X.691, Section 17.7) and the contents that follow a
/// length determinant (Sections 17.8, 30.5).
pub fn read_aligned_octets<'a>(
    r: &mut AperReader<'a>,
    n: usize,
) -> Result<(&'a [u8], Range<usize>), PacketError> {
    let octets = r.read_octets(n)?;
    let end = r.bit_position() / 8;
    Ok((octets, end - n..end))
}

/// Reads a fixed-size BIT STRING of `n` (at most 64) bits and returns the
/// value with its byte range relative to the start of the reader's buffer.
///
/// ITU-T Rec. X.691, Section 16.9–16.10: above 16 bits the string is
/// octet-aligned in the ALIGNED variant.
pub fn read_bit_string_field(
    r: &mut AperReader<'_>,
    n: u32,
) -> Result<(u64, Range<usize>), PacketError> {
    if n > 16 {
        r.align();
    }
    let start = r.bit_position();
    let value = r.read_fixed_bit_string(n)?;
    Ok((value, r.byte_range_since(start)))
}

/// Skips one `ProtocolIE-Field` or `ProtocolExtensionField`: `id` (INTEGER
/// (0..65535)), `criticality` (ENUMERATED {reject, ignore, notify}) and an
/// open type value (ITU-T Rec. X.691, Section 11.2).
fn skip_field(r: &mut AperReader<'_>) -> Result<(), PacketError> {
    r.read_constrained_whole_number(0, 65535)?;
    r.read_enumerated(3, false)?;
    let len = r.read_length(0, None)?;
    r.read_octets(len as usize)?;
    Ok(())
}

/// Skips a `ProtocolExtensionContainer`.
///
/// 3GPP TS 36.413, Section 9.3.7 — `SEQUENCE (SIZE
/// (1..maxProtocolExtensions)) OF ProtocolExtensionField`.
pub fn skip_protocol_extension_container(r: &mut AperReader<'_>) -> Result<(), PacketError> {
    let count = r.read_length(1, Some(MAX_PROTOCOL_EXTENSIONS))?;
    for _ in 0..count {
        skip_field(r)?;
    }
    Ok(())
}

/// Skips a `ProtocolIE-SingleContainer`, e.g. the value of a
/// `choice-Extensions` alternative.
///
/// 3GPP TS 36.413, Section 9.3.7 — a single `ProtocolIE-Field`.
pub fn skip_protocol_ie_single_container(r: &mut AperReader<'_>) -> Result<(), PacketError> {
    skip_field(r)
}

/// Skips the extension additions of an extensible SEQUENCE whose
/// extension bit was set.
///
/// ITU-T Rec. X.691, Section 19.8–19.9: a normally small length giving
/// the size of the presence bitmap (Section 11.9.3.4), the bitmap, then
/// each present addition as an open type.
pub fn skip_sequence_extension_additions(r: &mut AperReader<'_>) -> Result<(), PacketError> {
    let count = r.read_normally_small_length()?;
    let mut present = 0u64;
    for _ in 0..count {
        if r.read_bit()? {
            present += 1;
        }
    }
    for _ in 0..present {
        let len = r.read_length(0, None)?;
        r.read_octets(len as usize)?;
    }
    Ok(())
}

/// Reads the preamble of an extensible SEQUENCE with `optional` OPTIONAL
/// components. Returns the extension bit and the presence bitmap, the
/// first OPTIONAL component in the most significant of the `optional`
/// low bits.
///
/// ITU-T Rec. X.691, Section 19.1 (extension bit) and 19.2 (bitmap of
/// OPTIONAL components).
pub fn read_sequence_preamble(
    r: &mut AperReader<'_>,
    optional: u32,
) -> Result<(bool, u64), PacketError> {
    let extended = r.read_bit()?;
    let bitmap = r.read_bits(optional)?;
    Ok((extended, bitmap))
}

/// Skips what follows the root components of an extensible SEQUENCE: the
/// `iE-Extensions` container when present, and the extension additions
/// when the extension bit was set.
pub fn skip_sequence_tail(
    r: &mut AperReader<'_>,
    extended: bool,
    has_ie_extensions: bool,
) -> Result<(), PacketError> {
    if has_ie_extensions {
        skip_protocol_extension_container(r)?;
    }
    if extended {
        skip_sequence_extension_additions(r)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! # ITU-T X.691 helpers Coverage
    //!
    //! | Section | Description                                 | Test                                   |
    //! |---------|---------------------------------------------|----------------------------------------|
    //! | 10.1.3, 11.2 | Open type fully consumed               | ensure_consumed_checks_trailing_octets |
    //! | 17.7    | Octet-aligned fixed OCTET STRING            | aligned_octets_and_bit_string          |
    //! | 16.9-16.10 | Fixed BIT STRING above 16 bits aligned   | aligned_octets_and_bit_string          |
    //! | 19.1-19.2 | SEQUENCE preamble                         | sequence_preamble_and_tail             |
    //! | 19.8-19.9 | Extension additions skipped               | sequence_preamble_and_tail             |
    //! | TS 36.413 9.3.7 | ProtocolExtensionContainer skipped  | sequence_preamble_and_tail             |
    //! | TS 36.413 9.3.7 | ProtocolIE-SingleContainer skipped  | single_container                       |

    use super::*;

    #[test]
    fn ensure_consumed_checks_trailing_octets() {
        let data = [0x80, 0x00];
        let mut r = AperReader::new(&data);
        r.read_bit().unwrap();
        assert!(ensure_consumed(&r, &data).is_err());
        let r = AperReader::new(&data[..1]);
        // An empty encoding is a single zero octet.
        assert!(ensure_consumed(&r, &data[..1]).is_ok());
    }

    #[test]
    fn aligned_octets_and_bit_string() {
        // 1 bit, padding, 2 octets, then a 28-bit BIT STRING (aligned).
        let data = [0x80, 0xAA, 0xBB, 0x12, 0x34, 0x56, 0x70];
        let mut r = AperReader::new(&data);
        r.read_bit().unwrap();
        let (octets, range) = read_aligned_octets(&mut r, 2).unwrap();
        assert_eq!(octets, &[0xAA, 0xBB]);
        assert_eq!(range, 1..3);
        let (bits, range) = read_bit_string_field(&mut r, 28).unwrap();
        assert_eq!(bits, 0x1234567);
        assert_eq!(range, 3..7);
        // A short BIT STRING is not aligned.
        let data = [0b1010_1100];
        let mut r = AperReader::new(&data);
        r.read_bit().unwrap();
        let (bits, _) = read_bit_string_field(&mut r, 3).unwrap();
        assert_eq!(bits, 0b010);
    }

    #[test]
    fn sequence_preamble_and_tail() {
        // Extension bit 1, one OPTIONAL present (iE-Extensions); then a
        // container with one extension field (id 1, reject, 1-octet value),
        // then extension additions: bitmap size 1, present, 1-octet value.
        let data = [
            0b1100_0000, // ext=1, iE-Extensions present, padding
            0x00,
            0x00, // container count - 1 = 0 (constrained, 2 octets)
            0x00,
            0x01, // id = 1
            0x00, // criticality reject + padding
            0x01,
            0xFF,        // value length 1, value
            0b0000_0001, // bitmap size - 1 = 0 (normally small), bitmap: present
            0x01,
            0xEE, // addition open type
        ];
        let mut r = AperReader::new(&data);
        let (extended, bitmap) = read_sequence_preamble(&mut r, 1).unwrap();
        assert!(extended);
        assert_eq!(bitmap, 1);
        skip_sequence_tail(&mut r, extended, bitmap == 1).unwrap();
        assert_eq!(r.bit_position().div_ceil(8), data.len());
        // Nothing to skip.
        let mut r = AperReader::new(&[]);
        skip_sequence_tail(&mut r, false, false).unwrap();
    }

    #[test]
    fn single_container() {
        let data = [0x00, 0x05, 0x40, 0x02, 0xAB, 0xCD];
        let mut r = AperReader::new(&data);
        skip_protocol_ie_single_container(&mut r).unwrap();
        assert_eq!(r.bit_position(), 48);
        let mut r = AperReader::new(&data[..4]);
        assert!(skip_protocol_ie_single_container(&mut r).is_err());
    }
}
