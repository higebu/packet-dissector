//! Shared utility functions used by multiple dissectors.

/// Compute the byte offset of a sub-slice within a parent slice.
///
/// Both `data` and `sub` must point into the same allocation (e.g., `sub`
/// was obtained by slicing `data`).  The return value is the byte distance
/// from `data.as_ptr()` to `sub.as_ptr()`.
///
/// Returns [`InvalidHeader`](crate::error::PacketError::InvalidHeader) if
/// `sub` does not point within `data`'s address range.
pub fn slice_offset(data: &[u8], sub: &[u8]) -> Result<usize, crate::error::PacketError> {
    let data_start = data.as_ptr() as usize;
    let data_end = data_start + data.len();
    let sub_start = sub.as_ptr() as usize;
    if sub_start < data_start || sub_start > data_end {
        return Err(crate::error::PacketError::InvalidHeader(
            "sub-slice pointer is outside parent slice range",
        ));
    }
    Ok(sub_start - data_start)
}

/// Compute the byte offset of a `&str` within a byte slice.
///
/// This is a convenience wrapper around [`slice_offset`] for use with
/// parsers (e.g., `httparse`) that return `&str` references into a `&[u8]`
/// buffer.
pub fn str_offset(data: &[u8], s: &str) -> Result<usize, crate::error::PacketError> {
    slice_offset(data, s.as_bytes())
}

/// Trim optional whitespace (OWS = *(SP / HTAB)) from both ends of a byte
/// slice.
///
/// Defined identically for HTTP (RFC 9110, Section 5.6.3) and SIP
/// (RFC 3261, Section 25.1).
pub fn trim_ows(data: &[u8]) -> &[u8] {
    let start = data
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(data.len());
    let end = data
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(start, |p| p + 1);
    &data[start..end]
}

/// Read a big-endian `u16` from `data[offset..offset+2]`.
///
/// Returns [`Truncated`](crate::error::PacketError::Truncated) if `data` is too short.
#[inline]
pub fn read_be_u16(data: &[u8], offset: usize) -> Result<u16, crate::error::PacketError> {
    let needed = offset.saturating_add(2);
    if data.len() < needed {
        return Err(crate::error::PacketError::Truncated {
            expected: needed,
            actual: data.len(),
        });
    }
    Ok(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

/// Read a big-endian 24-bit value from `data[offset..offset+3]` as a `u32`.
///
/// Returns [`Truncated`](crate::error::PacketError::Truncated) if `data` is too short.
#[inline]
pub fn read_be_u24(data: &[u8], offset: usize) -> Result<u32, crate::error::PacketError> {
    let needed = offset.saturating_add(3);
    if data.len() < needed {
        return Err(crate::error::PacketError::Truncated {
            expected: needed,
            actual: data.len(),
        });
    }
    Ok(u32::from(data[offset]) << 16
        | u32::from(data[offset + 1]) << 8
        | u32::from(data[offset + 2]))
}

/// Read a big-endian `u32` from `data[offset..offset+4]`.
///
/// Returns [`Truncated`](crate::error::PacketError::Truncated) if `data` is too short.
#[inline]
pub fn read_be_u32(data: &[u8], offset: usize) -> Result<u32, crate::error::PacketError> {
    let needed = offset.saturating_add(4);
    if data.len() < needed {
        return Err(crate::error::PacketError::Truncated {
            expected: needed,
            actual: data.len(),
        });
    }
    Ok(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Read four bytes from `data[offset..offset+4]` as an IPv4 address.
///
/// Returns [`Truncated`](crate::error::PacketError::Truncated) if `data` is too short.
#[inline]
pub fn read_ipv4_addr(data: &[u8], offset: usize) -> Result<[u8; 4], crate::error::PacketError> {
    let needed = offset.saturating_add(4);
    if data.len() < needed {
        return Err(crate::error::PacketError::Truncated {
            expected: needed,
            actual: data.len(),
        });
    }
    Ok([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Read sixteen bytes from `data[offset..offset+16]` as an IPv6 address.
///
/// Returns [`Truncated`](crate::error::PacketError::Truncated) if `data` is too short.
#[inline]
pub fn read_ipv6_addr(data: &[u8], offset: usize) -> Result<[u8; 16], crate::error::PacketError> {
    let needed = offset.saturating_add(16);
    if data.len() < needed {
        return Err(crate::error::PacketError::Truncated {
            expected: needed,
            actual: data.len(),
        });
    }
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&data[offset..offset + 16]);
    Ok(addr)
}

/// Read a big-endian `u64` from `data[offset..offset+8]`.
///
/// Returns [`Truncated`](crate::error::PacketError::Truncated) if `data` is too short.
#[inline]
pub fn read_be_u64(data: &[u8], offset: usize) -> Result<u64, crate::error::PacketError> {
    let needed = offset.saturating_add(8);
    if data.len() < needed {
        return Err(crate::error::PacketError::Truncated {
            expected: needed,
            actual: data.len(),
        });
    }
    Ok(u64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}

/// Read a big-endian `i32` from `data[offset..offset+4]`.
///
/// Returns [`Truncated`](crate::error::PacketError::Truncated) if `data` is too short.
#[inline]
pub fn read_be_i32(data: &[u8], offset: usize) -> Result<i32, crate::error::PacketError> {
    let needed = offset.saturating_add(4);
    if data.len() < needed {
        return Err(crate::error::PacketError::Truncated {
            expected: needed,
            actual: data.len(),
        });
    }
    Ok(i32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Intern a MIME content type to a `&'static str` for zero-allocation dispatch.
///
/// Strips parameters (everything after `;`), trims whitespace, and performs
/// case-insensitive matching against well-known types. Returns `None` for
/// unrecognised types — callers should skip dispatch in that case.
///
/// Used by HTTP and SIP dissectors for `DispatchHint::ByContentType`.
pub fn intern_content_type(raw: &str) -> Option<&'static str> {
    let mime = raw.split(';').next().unwrap_or(raw).trim();
    match () {
        _ if mime.eq_ignore_ascii_case("application/sdp") => Some("application/sdp"),
        _ if mime.eq_ignore_ascii_case("application/json") => Some("application/json"),
        _ if mime.eq_ignore_ascii_case("text/html") => Some("text/html"),
        _ if mime.eq_ignore_ascii_case("text/plain") => Some("text/plain"),
        _ if mime.eq_ignore_ascii_case("text/xml") => Some("text/xml"),
        _ if mime.eq_ignore_ascii_case("application/xml") => Some("application/xml"),
        _ if mime.eq_ignore_ascii_case("application/octet-stream") => {
            Some("application/octet-stream")
        }
        _ if mime.eq_ignore_ascii_case("multipart/mixed") => Some("multipart/mixed"),
        _ if mime.eq_ignore_ascii_case("application/x-www-form-urlencoded") => {
            Some("application/x-www-form-urlencoded")
        }
        _ if mime.eq_ignore_ascii_case("application/pidf+xml") => Some("application/pidf+xml"),
        _ if mime.eq_ignore_ascii_case("application/rlmi+xml") => Some("application/rlmi+xml"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_ows_strips_spaces_and_tabs() {
        assert_eq!(trim_ows(b"  hello  "), b"hello");
        assert_eq!(trim_ows(b"\t hi \t"), b"hi");
        assert_eq!(trim_ows(b"no_ws"), b"no_ws");
        assert_eq!(trim_ows(b"   "), b"" as &[u8]);
        assert_eq!(trim_ows(b""), b"" as &[u8]);
    }

    #[test]
    fn slice_offset_computes_correct_offset() {
        let data = b"hello world";
        let sub = &data[6..11];
        assert_eq!(slice_offset(data, sub).unwrap(), 6);
    }

    #[test]
    fn slice_offset_returns_error_for_disjoint_slice() {
        let data = b"hello";
        let other = b"world";
        assert!(slice_offset(data, other).is_err());
    }

    #[test]
    fn str_offset_computes_correct_offset() {
        let data = b"GET /index HTTP/1.1";
        let s = std::str::from_utf8(&data[4..10]).unwrap();
        assert_eq!(str_offset(data, s).unwrap(), 4);
    }

    #[test]
    fn read_be_u16_at_offset_zero() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_be_u16(&data, 0).unwrap(), 0x0102);
    }

    #[test]
    fn read_be_u16_at_nonzero_offset() {
        let data = [0x00, 0x00, 0xAB, 0xCD];
        assert_eq!(read_be_u16(&data, 2).unwrap(), 0xABCD);
    }

    #[test]
    fn read_be_u16_truncated() {
        let data = [0x01];
        assert!(read_be_u16(&data, 0).is_err());
    }

    #[test]
    fn read_be_u24_returns_correct_value() {
        let data = [0x01, 0x02, 0x03];
        assert_eq!(read_be_u24(&data, 0).unwrap(), 0x00_01_02_03);
    }

    #[test]
    fn read_be_u24_at_offset() {
        let data = [0xFF, 0x10, 0x20, 0x30];
        assert_eq!(read_be_u24(&data, 1).unwrap(), 0x00_10_20_30);
    }

    #[test]
    fn read_be_u32_at_offset_zero() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(read_be_u32(&data, 0).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn read_be_u32_at_nonzero_offset() {
        let data = [0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_be_u32(&data, 2).unwrap(), 0x0102_0304);
    }

    #[test]
    fn read_be_u64_at_offset_zero() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_be_u64(&data, 0).unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn read_be_u64_at_nonzero_offset() {
        let data = [0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_be_u64(&data, 2).unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn read_ipv4_addr_at_offset_zero() {
        let data = [192, 168, 1, 1];
        assert_eq!(read_ipv4_addr(&data, 0).unwrap(), [192, 168, 1, 1]);
    }

    #[test]
    fn read_ipv4_addr_at_nonzero_offset() {
        let data = [0x00, 0x00, 10, 0, 0, 1];
        assert_eq!(read_ipv4_addr(&data, 2).unwrap(), [10, 0, 0, 1]);
    }

    #[test]
    fn read_ipv6_addr_at_offset_zero() {
        let data = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        assert_eq!(read_ipv6_addr(&data, 0).unwrap(), data);
    }

    #[test]
    fn read_ipv6_addr_at_nonzero_offset() {
        let mut data = [0u8; 18];
        data[2..18].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            read_ipv6_addr(&data, 2).unwrap(),
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn read_be_i32_positive() {
        let data = [0x00, 0x00, 0x00, 0x01];
        assert_eq!(read_be_i32(&data, 0).unwrap(), 1);
    }

    #[test]
    fn read_be_i32_negative() {
        let data = [0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(read_be_i32(&data, 0).unwrap(), -1);
    }

    #[test]
    fn read_be_i32_negative_at_nonzero_offset() {
        let data = [0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(read_be_i32(&data, 1).unwrap(), -1);
    }
}
