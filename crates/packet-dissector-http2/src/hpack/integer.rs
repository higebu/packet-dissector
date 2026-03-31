//! HPACK integer representation (RFC 7541, Section 5.1).

/// Decode an HPACK prefix-encoded integer.
///
/// `prefix_bits` is the number of bits in the first byte used for the integer
/// (1..=8). Returns `(value, bytes_consumed)`.
pub fn decode_integer(data: &[u8], prefix_bits: u8) -> Result<(u32, usize), &'static str> {
    debug_assert!((1..=8).contains(&prefix_bits));

    if data.is_empty() {
        return Err("empty data for integer decode");
    }

    let max_prefix = (1u32 << prefix_bits) - 1;
    let value = u32::from(data[0]) & max_prefix;

    if value < max_prefix {
        return Ok((value, 1));
    }

    // Multi-byte integer
    let mut result = max_prefix;
    let mut shift = 0u32;
    for (i, &byte) in data[1..].iter().enumerate() {
        let contribution = u32::from(byte & 0x7F);
        result = result
            .checked_add(contribution.checked_shl(shift).ok_or("integer overflow")?)
            .ok_or("integer overflow")?;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((result, i + 2));
        }
        if shift > 28 {
            return Err("integer overflow");
        }
    }

    Err("unterminated integer")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_small_value() {
        // Value 10 with 5-bit prefix: fits in one byte
        assert_eq!(decode_integer(&[10], 5), Ok((10, 1)));
    }

    #[test]
    fn decode_rfc_example_c1_1() {
        // RFC 7541 C.1.1: integer 10, 5-bit prefix → 0b_xxx0_1010
        assert_eq!(decode_integer(&[0x0A], 5), Ok((10, 1)));
    }

    #[test]
    fn decode_rfc_example_c1_2() {
        // RFC 7541 C.1.2: integer 1337, 5-bit prefix
        // 31 + (154 & 0x7F) * 1 + (10 & 0x7F) * 128 = 31 + 26 + 1280 = 1337
        assert_eq!(decode_integer(&[0x1F, 0x9A, 0x0A], 5), Ok((1337, 3)));
    }

    #[test]
    fn decode_rfc_example_c1_3() {
        // RFC 7541 C.1.3: integer 42 with 8-bit prefix
        assert_eq!(decode_integer(&[42], 8), Ok((42, 1)));
    }

    #[test]
    fn decode_max_prefix_boundary() {
        // 5-bit prefix, value = 31 (all prefix bits set)
        // 31 + 0 = 31
        assert_eq!(decode_integer(&[0x1F, 0x00], 5), Ok((31, 2)));
    }

    #[test]
    fn decode_empty_data() {
        assert!(decode_integer(&[], 5).is_err());
    }

    #[test]
    fn decode_unterminated() {
        // Continuation bit set but no more bytes
        assert!(decode_integer(&[0x1F, 0x80], 5).is_err());
    }
}
