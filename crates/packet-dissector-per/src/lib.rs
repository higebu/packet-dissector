//! Bit-level reader for ASN.1 ALIGNED PER (APER) encodings.
//!
//! Shared by the 3GPP application protocols (NGAP, S1AP, ...), whose
//! messages are encoded with the ALIGNED variant of PER. Small
//! constrained values (CHOICE indices, ENUMERATED indices, extension and
//! optional bits, short fixed-size strings, lengths with a small upper
//! bound) are bit-fields packed back to back; padding is only inserted
//! before fields that are "octet-aligned in the ALIGNED variant". This
//! reader keeps a bit cursor so that decoders do not have to hard-code
//! bit positions.
//!
//! ## References
//! - ITU-T Rec. X.691 (02/2021): <https://www.itu.int/rec/T-REC-X.691>

#![deny(missing_docs)]

pub mod ap;

use core::ops::Range;

use packet_dissector_core::error::PacketError;

/// A bit cursor over an APER-encoded buffer.
///
/// Bits are numbered from the most significant bit of the first octet
/// (ITU-T Rec. X.691, Section 3.7 / 10.1 — the first bit of a bit-field
/// is the leading bit of the octet).
#[derive(Debug, Clone)]
pub struct AperReader<'a> {
    data: &'a [u8],
    bit: usize,
}

/// Number of bits needed to encode values `0..=max` (0 when `max == 0`).
fn bits_for(max: u64) -> u32 {
    64 - max.leading_zeros()
}

impl<'a> AperReader<'a> {
    /// Creates a reader positioned at the first bit of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, bit: 0 }
    }

    /// Current position in bits from the start of the buffer.
    pub fn bit_position(&self) -> usize {
        self.bit
    }

    /// Byte range (relative to the start of the buffer) that covers every
    /// bit read since `start_bit`.
    pub fn byte_range_since(&self, start_bit: usize) -> Range<usize> {
        start_bit / 8..self.bit.div_ceil(8)
    }

    /// Returns an error unless `bits` more bits are available.
    fn ensure(&self, bits: usize) -> Result<(), PacketError> {
        let end = self.bit + bits;
        if end > self.data.len() * 8 {
            return Err(PacketError::Truncated {
                expected: end.div_ceil(8),
                actual: self.data.len(),
            });
        }
        Ok(())
    }

    /// Reads `n` (at most 64) bits as an unsigned big-endian number.
    pub fn read_bits(&mut self, n: u32) -> Result<u64, PacketError> {
        if n > 64 {
            return Err(PacketError::InvalidHeader(
                "APER bit-field wider than 64 bits",
            ));
        }
        self.ensure(n as usize)?;
        let mut value: u64 = 0;
        for _ in 0..n {
            let byte = self.data[self.bit / 8];
            let bit = (byte >> (7 - (self.bit % 8))) & 0x01;
            value = (value << 1) | u64::from(bit);
            self.bit += 1;
        }
        Ok(value)
    }

    /// Reads a single bit (extension bit, optional-component bit, ...).
    pub fn read_bit(&mut self) -> Result<bool, PacketError> {
        Ok(self.read_bits(1)? == 1)
    }

    /// Skips padding bits up to the next octet boundary.
    ///
    /// ITU-T Rec. X.691, Section 11.1 — "octet-aligned in the ALIGNED
    /// variant" fields start on an octet boundary.
    pub fn align(&mut self) {
        self.bit = self.bit.div_ceil(8) * 8;
    }

    /// Aligns to an octet boundary and returns the next `n` octets.
    pub fn read_octets(&mut self, n: usize) -> Result<&'a [u8], PacketError> {
        self.align();
        self.ensure(n * 8)?;
        let start = self.bit / 8;
        self.bit += n * 8;
        Ok(&self.data[start..start + n])
    }

    /// Decodes a constrained whole number in the range `lb..=ub`.
    ///
    /// ITU-T Rec. X.691, Section 11.5.7 (ALIGNED variant): a range of 1
    /// takes no bits, a range up to 255 is a minimal bit-field, a range of
    /// 256 is one octet-aligned octet, a range up to 64K is two
    /// octet-aligned octets, and larger ranges use the indefinite length
    /// case (a length in octets as a constrained whole number, then the
    /// octet-aligned value in the minimum number of octets).
    pub fn read_constrained_whole_number(&mut self, lb: u64, ub: u64) -> Result<u64, PacketError> {
        if ub < lb {
            return Err(PacketError::InvalidHeader("APER constraint ub < lb"));
        }
        let max = ub - lb;
        let value = if max == 0 {
            0
        } else if max < 255 {
            // Section 11.5.7.1 — bit-field case.
            self.read_bits(bits_for(max))?
        } else if max == 255 {
            // Section 11.5.7.2 — one-octet case.
            self.align();
            self.read_bits(8)?
        } else if max <= 0xFFFF {
            // Section 11.5.7.3 — two-octet case.
            self.align();
            self.read_bits(16)?
        } else {
            // Section 11.5.7.4 — indefinite length case.
            let max_octets = u64::from(bits_for(max).div_ceil(8));
            let len = self.read_constrained_whole_number(1, max_octets)?;
            self.align();
            // `len` is at most 8, so the multiplication cannot overflow.
            self.read_bits(len as u32 * 8)?
        };
        if value > max {
            return Err(PacketError::InvalidHeader(
                "APER constrained whole number out of range",
            ));
        }
        Ok(lb + value)
    }

    /// Decodes a normally small non-negative whole number.
    ///
    /// ITU-T Rec. X.691, Section 11.6: a single 0 bit followed by a 6-bit
    /// value, or a single 1 bit followed by a semi-constrained whole number
    /// (Section 11.7, a length determinant then the value octets).
    pub fn read_normally_small(&mut self) -> Result<u64, PacketError> {
        if !self.read_bit()? {
            return self.read_bits(6);
        }
        let len = self.read_length(0, None)?;
        if len == 0 || len > 8 {
            return Err(PacketError::InvalidHeader(
                "APER normally small number length unsupported",
            ));
        }
        let octets = self.read_octets(len as usize)?;
        Ok(octets
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    /// Reads a normally small length (ITU-T Rec. X.691, Section 11.9.3.4):
    /// `n` up to 64 is a zero bit and `n - 1` in six bits; a larger `n` is
    /// a one bit followed by a length determinant of `n` (Section 11.9.4.2).
    ///
    /// Used for the size of the extension addition bitmap of a SEQUENCE
    /// (Section 19.8).
    pub fn read_normally_small_length(&mut self) -> Result<u64, PacketError> {
        if !self.read_bit()? {
            return Ok(self.read_bits(6)? + 1);
        }
        self.read_length(0, None)
    }

    /// Decodes a length determinant with lower bound `lb` and optional
    /// upper bound `ub`.
    ///
    /// ITU-T Rec. X.691, Section 11.9: when `ub` is less than 64K the
    /// length is a constrained whole number (Section 11.9.4.1); otherwise
    /// it is octet-aligned in one octet (0..127) or two octets (up to
    /// 16K). Fragmented lengths (16K and above) are not supported.
    pub fn read_length(&mut self, lb: u64, ub: Option<u64>) -> Result<u64, PacketError> {
        if let Some(ub) = ub.filter(|&ub| ub < 0x1_0000) {
            return self.read_constrained_whole_number(lb, ub);
        }
        self.align();
        let first = self.read_bits(8)?;
        if first & 0x80 == 0 {
            Ok(first)
        } else if first & 0xC0 == 0x80 {
            let second = self.read_bits(8)?;
            Ok(((first & 0x3F) << 8) | second)
        } else {
            Err(PacketError::InvalidHeader(
                "APER fragmented length determinant not supported",
            ))
        }
    }

    /// Decodes an ENUMERATED index with `root_count` root values.
    ///
    /// Returns the position of the value in the full enumeration list:
    /// root values are `0..root_count`, extension additions follow at
    /// `root_count + n`.
    ///
    /// ITU-T Rec. X.691, Section 14: an extension bit when the type is
    /// extensible, then either a constrained whole number
    /// (`0..root_count-1`, Section 14.2) or a normally small number for an
    /// extension addition (Section 14.3).
    pub fn read_enumerated(
        &mut self,
        root_count: u64,
        extensible: bool,
    ) -> Result<u64, PacketError> {
        self.read_index(root_count, extensible)
    }

    /// Decodes a CHOICE index with `root_count` root alternatives.
    ///
    /// Returns the alternative index; extension alternatives follow the
    /// root at `root_count + n`.
    ///
    /// ITU-T Rec. X.691, Section 23.6–23.8: an extension bit when the type
    /// is extensible, then a constrained whole number (root) or a normally
    /// small number (extension addition).
    pub fn read_choice_index(
        &mut self,
        root_count: u64,
        extensible: bool,
    ) -> Result<u64, PacketError> {
        self.read_index(root_count, extensible)
    }

    fn read_index(&mut self, root_count: u64, extensible: bool) -> Result<u64, PacketError> {
        if root_count == 0 {
            return Err(PacketError::InvalidHeader("APER index with empty root"));
        }
        if extensible && self.read_bit()? {
            let n = self.read_normally_small()?;
            return root_count
                .checked_add(n)
                .ok_or(PacketError::InvalidHeader("APER extension index overflow"));
        }
        self.read_constrained_whole_number(0, root_count - 1)
    }

    /// Decodes a fixed-size BIT STRING of `n` (at most 64) bits.
    ///
    /// ITU-T Rec. X.691, Section 16.9–16.10: up to 16 bits it is a
    /// bit-field with no alignment; above 16 bits it is octet-aligned in
    /// the ALIGNED variant.
    pub fn read_fixed_bit_string(&mut self, n: u32) -> Result<u64, PacketError> {
        if n > 16 {
            self.align();
        }
        self.read_bits(n)
    }
}

/// Where the value of an octet-aligned length-prefixed field (an open type
/// or an unconstrained OCTET STRING) lies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extent {
    /// A single length determinant of `len_octets` octets followed by `len`
    /// contiguous value octets.
    Contiguous {
        /// Size of the length determinant (1 or 2 octets).
        len_octets: usize,
        /// Number of value octets.
        len: usize,
    },
    /// A fragmented value: `total` value octets spread over fragments that
    /// are separated by further length determinants, ending before `end`.
    Fragmented {
        /// Number of value octets, summed over all fragments.
        total: usize,
        /// Position just after the last octet of the encoding.
        end: usize,
    },
}

/// Size of one fragment unit of a fragmented length determinant.
///
/// ITU-T Rec. X.691, Section 11.9.3.8.
const FRAGMENT_UNIT: usize = 16384;

/// Reads the extent of an octet-aligned value whose unconstrained length
/// determinant starts at octet `pos` of `data`.
///
/// ITU-T Rec. X.691, Section 11.9.3.6 (one octet, 0..127), 11.9.3.7 (two
/// octets, up to 16K) and 11.9.3.8: a first octet `11mmmmmm` with `m` in
/// 1..4 is followed by `m` × 16K value octets and then another length
/// determinant; the last part uses the one- or two-octet form (possibly
/// zero).
pub fn read_extent(data: &[u8], pos: usize) -> Result<Extent, PacketError> {
    let truncated = |expected: usize| PacketError::Truncated {
        expected,
        actual: data.len(),
    };
    let mut p = pos;
    let mut total = 0usize;
    loop {
        let &first = data.get(p).ok_or_else(|| truncated(p + 1))?;
        let (len_octets, len) = match first {
            0x00..=0x7f => (1, usize::from(first)),
            0x80..=0xbf => {
                let &second = data.get(p + 1).ok_or_else(|| truncated(p + 2))?;
                (2, (usize::from(first & 0x3f) << 8) | usize::from(second))
            }
            _ => {
                let m = usize::from(first & 0x3f);
                if !(1..=4).contains(&m) {
                    return Err(PacketError::InvalidHeader(
                        "APER fragment multiplier out of range",
                    ));
                }
                let next = p + 1 + m * FRAGMENT_UNIT;
                if next > data.len() {
                    return Err(truncated(next));
                }
                total += m * FRAGMENT_UNIT;
                p = next;
                continue;
            }
        };
        if p == pos {
            return Ok(Extent::Contiguous { len_octets, len });
        }
        let end = p + len_octets + len;
        if end > data.len() {
            return Err(truncated(end));
        }
        return Ok(Extent::Fragmented {
            total: total + len,
            end,
        });
    }
}

#[cfg(test)]
mod tests {
    //! # ITU-T X.691 (ALIGNED PER) Reader Coverage
    //!
    //! | X.691 Section | Description                              | Test                                  |
    //! |---------------|------------------------------------------|---------------------------------------|
    //! | 10.1          | Bit order, MSB first                     | read_bits_msb_first                   |
    //! | 10.1          | Bit-fields spanning octets               | read_bits_across_octets               |
    //! | 10.1          | Truncation                               | read_bits_truncated                   |
    //! | 10.1          | Bit-field wider than 64 bits             | read_bits_too_wide                    |
    //! | 11.1          | Octet alignment                          | align_skips_padding                   |
    //! | 11.1          | Octet-aligned octets                     | read_octets_aligns_first              |
    //! | 11.1          | Octet-aligned octets, truncated          | read_octets_truncated                 |
    //! | 11.5.7        | Range of one, no bits                    | cwn_range_one                         |
    //! | 11.5.7.1      | Bit-field case                           | cwn_bit_field_case                    |
    //! | 11.5.7.1      | Value above ub                           | cwn_bit_field_out_of_range            |
    //! | 11.5.7.2      | One-octet case                           | cwn_one_octet_case                    |
    //! | 11.5.7.3      | Two-octet case                           | cwn_two_octet_case                    |
    //! | 11.5.7.4      | Indefinite length case                   | cwn_indefinite_length_case            |
    //! | 11.5.7.4      | Indefinite length case, lb offset        | cwn_indefinite_length_with_lb         |
    //! | 11.5.7        | ub < lb                                  | cwn_invalid_constraint                |
    //! | 11.6          | Normally small, 6-bit form               | normally_small_short                  |
    //! | 11.6          | Normally small, long form                | normally_small_long                   |
    //! | 11.6          | Normally small, bad length               | normally_small_bad_length             |
    //! | 11.9.3.4      | Normally small length (bitmap size)      | normally_small_length                 |
    //! | 11.9.4.1      | Constrained length                       | length_constrained                    |
    //! | 11.9.3.6      | Unconstrained length, one octet          | length_unconstrained_short            |
    //! | 11.9.3.7      | Unconstrained length, two octets         | length_unconstrained_long             |
    //! | 11.9.3.8      | Fragmented length (unsupported)          | length_fragmented_rejected            |
    //! | 14.2          | ENUMERATED root, extensible              | enumerated_root                       |
    //! | 14.3          | ENUMERATED extension addition            | enumerated_extension                  |
    //! | 14.2          | ENUMERATED, not extensible               | enumerated_not_extensible             |
    //! | 14            | ENUMERATED with empty root               | enumerated_empty_root                 |
    //! | 23.6–23.8     | CHOICE index                             | choice_index                          |
    //! | 16.9          | Fixed BIT STRING ≤ 16 bits               | fixed_bit_string_unaligned            |
    //! | 16.10         | Fixed BIT STRING > 16 bits               | fixed_bit_string_aligned              |
    //! | —             | Byte range of read bits                  | byte_range_since_covers_partial_octets|
    //! | 11.9.3.6      | Open type extent, one-octet length       | extent_short                          |
    //! | 11.9.3.7      | Open type extent, two-octet length       | extent_long                           |
    //! | 11.9.3.8      | Open type extent, fragmented             | extent_fragmented                     |
    //! | 11.9.3.8      | Fragmented, ends with a zero length      | extent_fragmented_zero_final          |
    //! | 11.9.3.8      | Fragment multiplier out of range         | extent_bad_fragment_multiplier        |
    //! | 11.9.3.8      | Truncated fragment / determinant         | extent_truncated                      |

    use super::*;

    #[test]
    fn read_bits_msb_first() {
        let mut r = AperReader::new(&[0b1010_0000]);
        assert!(r.read_bit().unwrap());
        assert!(!r.read_bit().unwrap());
        assert_eq!(r.read_bits(2).unwrap(), 0b10);
        assert_eq!(r.bit_position(), 4);
    }

    #[test]
    fn read_bits_across_octets() {
        let mut r = AperReader::new(&[0x0F, 0xF0]);
        r.read_bits(4).unwrap();
        assert_eq!(r.read_bits(8).unwrap(), 0xFF);
    }

    #[test]
    fn read_bits_truncated() {
        let mut r = AperReader::new(&[0x00]);
        r.read_bits(4).unwrap();
        assert_eq!(
            r.read_bits(8),
            Err(PacketError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn read_bits_too_wide() {
        let mut r = AperReader::new(&[0u8; 16]);
        assert!(matches!(
            r.read_bits(65),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn align_skips_padding() {
        let mut r = AperReader::new(&[0x80, 0x42]);
        r.read_bit().unwrap();
        r.align();
        assert_eq!(r.bit_position(), 8);
        r.align();
        assert_eq!(r.bit_position(), 8);
        assert_eq!(r.read_bits(8).unwrap(), 0x42);
    }

    #[test]
    fn read_octets_aligns_first() {
        let data = [0x80, 0x01, 0x02, 0x03];
        let mut r = AperReader::new(&data);
        r.read_bit().unwrap();
        assert_eq!(r.read_octets(3).unwrap(), &[0x01, 0x02, 0x03]);
        assert_eq!(r.bit_position(), 32);
    }

    #[test]
    fn read_octets_truncated() {
        let mut r = AperReader::new(&[0x00, 0x01]);
        assert!(matches!(
            r.read_octets(3),
            Err(PacketError::Truncated { .. })
        ));
    }

    #[test]
    fn cwn_range_one() {
        let mut r = AperReader::new(&[]);
        assert_eq!(r.read_constrained_whole_number(7, 7).unwrap(), 7);
        assert_eq!(r.bit_position(), 0);
    }

    #[test]
    fn cwn_bit_field_case() {
        // Range 10 (0..9) → 4 bits, no alignment.
        let mut r = AperReader::new(&[0b1001_0011]);
        assert_eq!(r.read_constrained_whole_number(0, 9).unwrap(), 9);
        assert_eq!(r.read_constrained_whole_number(1, 4).unwrap(), 1);
        assert_eq!(r.bit_position(), 6);
    }

    #[test]
    fn cwn_bit_field_out_of_range() {
        // Range 0..9 in 4 bits, value 15 is not permitted.
        let mut r = AperReader::new(&[0xF0]);
        assert!(matches!(
            r.read_constrained_whole_number(0, 9),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn cwn_one_octet_case() {
        // INTEGER (0..255) after one bit: aligned octet.
        let mut r = AperReader::new(&[0x80, 0xFF]);
        r.read_bit().unwrap();
        assert_eq!(r.read_constrained_whole_number(0, 255).unwrap(), 255);
        assert_eq!(r.bit_position(), 16);
    }

    #[test]
    fn cwn_two_octet_case() {
        let mut r = AperReader::new(&[0x80, 0x12, 0x34]);
        r.read_bit().unwrap();
        assert_eq!(r.read_constrained_whole_number(0, 65535).unwrap(), 0x1234);
    }

    #[test]
    fn cwn_indefinite_length_case() {
        // INTEGER (0..4294967295): 2-bit length (1..4 octets), pad, value.
        let mut r = AperReader::new(&[0x00, 0x01]);
        assert_eq!(r.read_constrained_whole_number(0, 0xFFFF_FFFF).unwrap(), 1);
        let mut r = AperReader::new(&[0xC0, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(
            r.read_constrained_whole_number(0, 0xFFFF_FFFF).unwrap(),
            0x1234_5678
        );
        // INTEGER (0..1099511627775): 3-bit length (1..5 octets).
        let mut r = AperReader::new(&[0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(
            r.read_constrained_whole_number(0, 0xFF_FFFF_FFFF).unwrap(),
            0xFF_FFFF_FFFF
        );
    }

    #[test]
    fn cwn_indefinite_length_with_lb() {
        let mut r = AperReader::new(&[0x00, 0x01]);
        assert_eq!(
            r.read_constrained_whole_number(10, 10 + 0xFFFF_FFFF)
                .unwrap(),
            11
        );
    }

    #[test]
    fn cwn_invalid_constraint() {
        let mut r = AperReader::new(&[0x00]);
        assert!(r.read_constrained_whole_number(5, 4).is_err());
    }

    #[test]
    fn normally_small_short() {
        // 0 | 000011
        let mut r = AperReader::new(&[0b0000_0110]);
        assert_eq!(r.read_normally_small().unwrap(), 3);
        assert_eq!(r.bit_position(), 7);
    }

    #[test]
    fn normally_small_long() {
        // 1 | pad | length 1 | 0x40
        let mut r = AperReader::new(&[0x80, 0x01, 0x40]);
        assert_eq!(r.read_normally_small().unwrap(), 64);
    }

    #[test]
    fn normally_small_length() {
        // 0 | 000000 → 1; 0 | 111111 → 64.
        let mut r = AperReader::new(&[0b0000_0000]);
        assert_eq!(r.read_normally_small_length().unwrap(), 1);
        let mut r = AperReader::new(&[0b0111_1110]);
        assert_eq!(r.read_normally_small_length().unwrap(), 64);
        // 1 | pad | length determinant 65.
        let mut r = AperReader::new(&[0x80, 0x41]);
        assert_eq!(r.read_normally_small_length().unwrap(), 65);
        assert_eq!(r.bit_position(), 16);
        assert!(
            AperReader::new(&[0x80])
                .read_normally_small_length()
                .is_err()
        );
    }

    #[test]
    fn normally_small_bad_length() {
        let mut r = AperReader::new(&[0x80, 0x00]);
        assert!(r.read_normally_small().is_err());
        let mut r = AperReader::new(&[0x80, 0x09]);
        assert!(r.read_normally_small().is_err());
    }

    #[test]
    fn length_constrained() {
        // SIZE (1..150): 8-bit bit-field, no alignment.
        let mut r = AperReader::new(&[0x85, 0x80]);
        r.read_bit().unwrap();
        assert_eq!(r.read_length(1, Some(150)).unwrap(), 12);
        assert_eq!(r.bit_position(), 9);
    }

    #[test]
    fn length_unconstrained_short() {
        let mut r = AperReader::new(&[0x80, 0x7F]);
        r.read_bit().unwrap();
        assert_eq!(r.read_length(0, None).unwrap(), 127);
        assert_eq!(r.bit_position(), 16);
        // An upper bound of 64K or more is treated as unconstrained.
        let mut r = AperReader::new(&[0x05]);
        assert_eq!(r.read_length(0, Some(0x1_0000)).unwrap(), 5);
    }

    #[test]
    fn length_unconstrained_long() {
        let mut r = AperReader::new(&[0x81, 0x00]);
        assert_eq!(r.read_length(0, None).unwrap(), 256);
    }

    #[test]
    fn length_fragmented_rejected() {
        let mut r = AperReader::new(&[0xC1]);
        assert!(matches!(
            r.read_length(0, None),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn enumerated_root() {
        // Extensible, 10 root values: 0 | 0011
        let mut r = AperReader::new(&[0x18]);
        assert_eq!(r.read_enumerated(10, true).unwrap(), 3);
        assert_eq!(r.bit_position(), 5);
    }

    #[test]
    fn enumerated_extension() {
        // 1 | 0 000001 → second extension addition.
        let mut r = AperReader::new(&[0x81]);
        assert_eq!(r.read_enumerated(10, true).unwrap(), 11);
    }

    #[test]
    fn enumerated_not_extensible() {
        let mut r = AperReader::new(&[0xC0]);
        assert_eq!(r.read_enumerated(4, false).unwrap(), 3);
        assert_eq!(r.bit_position(), 2);
    }

    #[test]
    fn enumerated_empty_root() {
        let mut r = AperReader::new(&[0x00]);
        assert!(r.read_enumerated(0, false).is_err());
    }

    #[test]
    fn choice_index() {
        // 6 alternatives, no extension marker: 3 bits.
        let mut r = AperReader::new(&[0x48]);
        assert_eq!(r.read_choice_index(6, false).unwrap(), 2);
        assert_eq!(r.bit_position(), 3);
    }

    #[test]
    fn fixed_bit_string_unaligned() {
        // 1 bit, then BIT STRING (SIZE(10)) packed right after it.
        let mut r = AperReader::new(&[0x80, 0x20]);
        r.read_bit().unwrap();
        assert_eq!(r.read_fixed_bit_string(10).unwrap(), 1);
        assert_eq!(r.bit_position(), 11);
    }

    #[test]
    fn fixed_bit_string_aligned() {
        // 1 bit, pad, BIT STRING (SIZE(36)).
        let mut r = AperReader::new(&[0x80, 0x12, 0x34, 0x56, 0x78, 0x90]);
        r.read_bit().unwrap();
        assert_eq!(r.read_fixed_bit_string(36).unwrap(), 0x1_2345_6789);
        assert_eq!(r.bit_position(), 44);
    }

    #[test]
    fn byte_range_since_covers_partial_octets() {
        let mut r = AperReader::new(&[0x00, 0x00, 0x00]);
        r.read_bits(3).unwrap();
        let start = r.bit_position();
        r.read_bits(7).unwrap();
        assert_eq!(r.byte_range_since(start), 0..2);
    }

    #[test]
    fn extent_short() {
        assert_eq!(
            read_extent(&[0xaa, 0x02, 1, 2], 1).unwrap(),
            Extent::Contiguous {
                len_octets: 1,
                len: 2
            }
        );
    }

    #[test]
    fn extent_long() {
        assert_eq!(
            read_extent(&[0x81, 0x00], 0).unwrap(),
            Extent::Contiguous {
                len_octets: 2,
                len: 256
            }
        );
    }

    #[test]
    fn extent_fragmented() {
        // One 16K fragment, then a final 5-octet part.
        let mut data = vec![0xc1];
        data.extend(std::iter::repeat_n(0u8, 16384));
        data.push(0x05);
        data.extend_from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(
            read_extent(&data, 0).unwrap(),
            Extent::Fragmented {
                total: 16389,
                end: data.len()
            }
        );
    }

    #[test]
    fn extent_fragmented_zero_final() {
        // Two 16K fragments in one determinant (m = 2), then length 0.
        let mut data = vec![0xc2];
        data.extend(std::iter::repeat_n(0u8, 32768));
        data.push(0x00);
        assert_eq!(
            read_extent(&data, 0).unwrap(),
            Extent::Fragmented {
                total: 32768,
                end: data.len()
            }
        );
    }

    #[test]
    fn extent_bad_fragment_multiplier() {
        for first in [0xc0, 0xc5] {
            assert!(matches!(
                read_extent(&[first], 0),
                Err(PacketError::InvalidHeader(_))
            ));
        }
    }

    #[test]
    fn extent_truncated() {
        for data in [&[][..], &[0x81][..], &[0xc1, 0x00][..]] {
            assert!(matches!(
                read_extent(data, 0),
                Err(PacketError::Truncated { .. })
            ));
        }
        // Final part longer than the data.
        let mut data = vec![0xc1];
        data.extend(std::iter::repeat_n(0u8, 16384));
        data.extend_from_slice(&[0x05, 0x00]);
        assert!(matches!(
            read_extent(&data, 0),
            Err(PacketError::Truncated { .. })
        ));
        // Fragment present but the next determinant is missing.
        let mut data = vec![0xc1];
        data.extend(std::iter::repeat_n(0u8, 16384));
        assert!(matches!(
            read_extent(&data, 0),
            Err(PacketError::Truncated { .. })
        ));
    }
}
