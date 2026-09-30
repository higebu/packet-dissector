//! Decoding helpers for the ASN.1 constructs that 3GPP application
//! protocols (NGAP, XnAP, F1AP, E1AP, ...) share: open type values,
//! extensible SEQUENCEs with an OPTIONAL `iE-Extensions` component, and
//! the `ProtocolExtensionContainer` / `ProtocolIE-SingleContainer` types.
//!
//! ## References
//! - ITU-T Rec. X.691 (02/2021): <https://www.itu.int/rec/T-REC-X.691>
//! - 3GPP TS 38.413, Section 9.4.8 (NGAP containers):
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/>
//! - 3GPP TS 38.423, Section 9.3.8 (XnAP containers):
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.423/>
//! - 3GPP TS 38.473, Section 9.4.8 (F1AP containers):
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.473/>
//! - 3GPP TS 37.483, Section 9.4.8 (E1AP containers):
//!   <https://www.3gpp.org/ftp/Specs/archive/37_series/37.483/>

use core::ops::Range;

use packet_dissector_core::error::PacketError;

use crate::reader::AperReader;

/// `maxProtocolExtensions`, the same in every 3GPP application protocol.
///
/// 3GPP TS 38.413, Section 9.4.7; TS 38.423, Section 9.3.7; TS 38.473,
/// Section 9.4.7; TS 37.483, Section 9.4.7.
pub const MAX_PROTOCOL_EXTENSIONS: u64 = 65535;

/// Shifts a byte range relative to a value by `offset`.
pub fn shift(range: Range<usize>, offset: usize) -> Range<usize> {
    range.start + offset..range.end + offset
}

/// Checks that the decoder consumed the whole open type value `data`.
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
/// ITU-T Rec. X.691, Section 16.9–16.10.
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

/// Skips a `ProtocolExtensionContainer`.
///
/// `SEQUENCE (SIZE (1..maxProtocolExtensions)) OF ProtocolExtensionField`,
/// each field being `id` (INTEGER (0..65535)), `criticality` (ENUMERATED
/// {reject, ignore, notify}) and `extensionValue` (open type, ITU-T Rec.
/// X.691, Section 11.2) — e.g. 3GPP TS 38.413, Section 9.4.8.
pub fn skip_protocol_extension_container(r: &mut AperReader<'_>) -> Result<(), PacketError> {
    let count = r.read_length(1, Some(MAX_PROTOCOL_EXTENSIONS))?;
    for _ in 0..count {
        r.read_constrained_whole_number(0, 65535)?;
        r.read_enumerated(3, false)?;
        let len = r.read_length(0, None)?;
        r.read_octets(len as usize)?;
    }
    Ok(())
}

/// Skips a `ProtocolIE-SingleContainer`, e.g. the value of a
/// `choice-Extensions` alternative.
///
/// `ProtocolIE-Field`: `id` (INTEGER (0..65535)), `criticality`
/// (ENUMERATED {reject, ignore, notify}) and `value` (open type, ITU-T
/// Rec. X.691, Section 11.2) — e.g. 3GPP TS 38.413, Section 9.4.8.
pub fn skip_protocol_ie_single_container(r: &mut AperReader<'_>) -> Result<(), PacketError> {
    r.read_constrained_whole_number(0, 65535)?;
    r.read_enumerated(3, false)?;
    let len = r.read_length(0, None)?;
    r.read_octets(len as usize)?;
    Ok(())
}

/// Skips the extension additions of an extensible SEQUENCE whose
/// extension bit was set.
///
/// ITU-T Rec. X.691, Section 19.8–19.9: a normally small length giving
/// the size of the presence bitmap, the bitmap, then each present
/// addition as an open type.
pub fn skip_sequence_extension_additions(r: &mut AperReader<'_>) -> Result<(), PacketError> {
    let count = r.read_normally_small()?.saturating_add(1);
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

/// Reads the preamble of an extensible SEQUENCE with a single OPTIONAL
/// `iE-Extensions` component. Returns `(extended, has_ie_extensions)`.
///
/// ITU-T Rec. X.691, Section 19.1 (extension bit) and 19.2 (bitmap of
/// OPTIONAL components).
pub fn read_sequence_preamble(r: &mut AperReader<'_>) -> Result<(bool, bool), PacketError> {
    let extended = r.read_bit()?;
    let has_ie_extensions = r.read_bit()?;
    Ok((extended, has_ie_extensions))
}

/// Reads the preamble of an extensible SEQUENCE with `optional` OPTIONAL
/// or DEFAULT components. Returns `(extended, bitmap)`, where the first
/// OPTIONAL component in the ASN.1 definition is the most significant of
/// the `optional` low-order bits.
///
/// ITU-T Rec. X.691, Section 19.1 (extension bit) and 19.2 (bitmap of
/// OPTIONAL components).
pub fn read_sequence_preamble_bitmap(
    r: &mut AperReader<'_>,
    optional: u32,
) -> Result<(bool, u64), PacketError> {
    let extended = r.read_bit()?;
    let bitmap = r.read_bits(optional)?;
    Ok((extended, bitmap))
}

/// Skips what follows the root components of an extensible SEQUENCE:
/// the `iE-Extensions` container and the extension additions.
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
    //! # ITU-T X.691 (ALIGNED PER) Helper Coverage
    //!
    //! | X.691 Section | Description                              | Test                                   |
    //! |---------------|------------------------------------------|----------------------------------------|
    //! | 11.2          | Open type fully consumed                 | ensure_consumed_exact                  |
    //! | 10.1.3        | Empty encoding is one zero octet         | ensure_consumed_empty_encoding         |
    //! | 11.2          | Trailing octets rejected                 | ensure_consumed_trailing               |
    //! | 17.7          | Octet-aligned octets with range          | read_aligned_octets_range              |
    //! | 16.9          | Short BIT STRING, unaligned              | bit_string_field_unaligned             |
    //! | 16.10         | Long BIT STRING, aligned                 | bit_string_field_aligned               |
    //! | 19.8          | Extension additions skipped              | skip_extension_additions               |
    //! | 19.1–19.2     | Preamble and tail with iE-Extensions     | preamble_and_tail_with_extensions      |
    //! | 19.1–19.2     | Preamble with several OPTIONAL bits      | preamble_bitmap_multiple_optionals     |
    //! | —             | ProtocolIE-SingleContainer skipped       | skip_single_container                  |
    //! | —             | Range shift                              | shift_moves_range                      |

    use super::*;

    #[test]
    fn ensure_consumed_exact() {
        let data = [0xAB];
        let mut r = AperReader::new(&data);
        r.read_bits(3).unwrap();
        assert!(ensure_consumed(&r, &data).is_ok());
    }

    #[test]
    fn ensure_consumed_empty_encoding() {
        let data = [0x00];
        let r = AperReader::new(&data);
        assert!(ensure_consumed(&r, &data).is_ok());
    }

    #[test]
    fn ensure_consumed_trailing() {
        let data = [0x00, 0x00];
        let mut r = AperReader::new(&data);
        r.read_bits(8).unwrap();
        assert!(ensure_consumed(&r, &data).is_err());
    }

    #[test]
    fn read_aligned_octets_range() {
        let data = [0x80, 0x01, 0x02];
        let mut r = AperReader::new(&data);
        r.read_bit().unwrap();
        let (octets, range) = read_aligned_octets(&mut r, 2).unwrap();
        assert_eq!(octets, &[0x01, 0x02]);
        assert_eq!(range, 1..3);
    }

    #[test]
    fn bit_string_field_unaligned() {
        let mut r = AperReader::new(&[0b1011_0110]);
        r.read_bit().unwrap();
        let (v, range) = read_bit_string_field(&mut r, 6).unwrap();
        assert_eq!(v, 0b011011);
        assert_eq!(range, 0..1);
    }

    #[test]
    fn bit_string_field_aligned() {
        let data = [0x80, 0x12, 0x34, 0x56, 0x78, 0x90];
        let mut r = AperReader::new(&data);
        r.read_bit().unwrap();
        let (v, range) = read_bit_string_field(&mut r, 36).unwrap();
        assert_eq!(v, 0x1_2345_6789);
        assert_eq!(range, 1..6);
    }

    #[test]
    fn preamble_bitmap_multiple_optionals() {
        // Extension bit 1, then a 2-bit bitmap 10, then 0 more bits used.
        let mut r = AperReader::new(&[0b1100_0000]);
        assert_eq!(
            read_sequence_preamble_bitmap(&mut r, 2).unwrap(),
            (true, 0b10)
        );
        assert_eq!(r.bit_position(), 3);
        // No OPTIONAL components: only the extension bit is read.
        let mut r = AperReader::new(&[0b0000_0000]);
        assert_eq!(
            read_sequence_preamble_bitmap(&mut r, 0).unwrap(),
            (false, 0)
        );
        assert_eq!(r.bit_position(), 1);
        assert!(read_sequence_preamble_bitmap(&mut AperReader::new(&[]), 1).is_err());
    }

    #[test]
    fn skip_extension_additions() {
        // Normally small bitmap length 0 + 000000 (one addition), presence
        // bit 1, then an open type of one octet.
        let data = [0b0000_0001, 0x01, 0xAA];
        let mut r = AperReader::new(&data);
        skip_sequence_extension_additions(&mut r).unwrap();
        assert!(ensure_consumed(&r, &data).is_ok());
    }

    #[test]
    fn preamble_and_tail_with_extensions() {
        // ext=0, iE-Extensions present; container: count 1 (16-bit
        // constrained length 1..65535 → 0x0000), id 0x0001, criticality
        // ignore, open type length 1, value 0x00.
        let data = [0x40, 0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x00];
        let mut r = AperReader::new(&data);
        let (ext, ie_ext) = read_sequence_preamble(&mut r).unwrap();
        assert!(!ext);
        assert!(ie_ext);
        skip_sequence_tail(&mut r, ext, ie_ext).unwrap();
        assert!(ensure_consumed(&r, &data).is_ok());
    }

    #[test]
    fn skip_single_container() {
        let data = [0x00, 0x05, 0x40, 0x02, 0xAA, 0xBB];
        let mut r = AperReader::new(&data);
        skip_protocol_ie_single_container(&mut r).unwrap();
        assert!(ensure_consumed(&r, &data).is_ok());
    }

    #[test]
    fn shift_moves_range() {
        assert_eq!(shift(1..3, 10), 11..13);
    }
}
