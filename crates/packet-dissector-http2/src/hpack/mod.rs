//! HPACK header compression decoder (RFC 7541).
//!
//! Decodes HPACK-compressed header blocks using the static table (61 entries)
//! and literal representations. Dynamic table entries are reported as
//! unresolved since the dissector is stateless (no connection tracking).

pub(crate) mod huffman;
mod integer;
mod static_table;

use integer::decode_integer;

/// A decoded header entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedHeader {
    /// Successfully decoded header name and value.
    /// Both name and value are `&'static str` for static table entries.
    /// For literal values, they are stored as byte ranges.
    Resolved {
        /// Header name — `&'static str` from the static table or `None` if literal.
        name: HeaderString,
        /// Header value — `&'static str` from the static table or `None` if literal.
        value: HeaderString,
    },
    /// Dynamic table reference that cannot be resolved without state.
    /// Contains the 1-based HPACK index.
    Unresolved(usize),
}

/// A string value from HPACK decoding — either a static table reference
/// or a literal that needs further processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderString {
    /// A `&'static str` from the HPACK static table.
    Static(&'static str),
    /// A literal string value (byte offset range within the HPACK block).
    /// Non-Huffman: the bytes can be directly interpreted as UTF-8.
    Literal(usize, usize),
    /// A Huffman-encoded literal — requires decoding.
    Huffman(usize, usize),
}

/// Decode an HPACK header block fragment.
///
/// Static table references and literal headers are fully decoded.
/// Dynamic table references (index > 61) produce [`DecodedHeader::Unresolved`].
/// Dynamic table size updates are silently skipped.
///
/// The `base_offset` is the byte offset of `data[0]` in the HPACK fragment
/// (used for literal byte ranges).
pub fn decode_header_block(data: &[u8]) -> Result<Vec<DecodedHeader>, &'static str> {
    let mut headers = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let first = data[pos];

        if first & 0x80 != 0 {
            // Indexed Header Field (Section 6.1): 1xxxxxxx
            let (index, consumed) = decode_integer(&data[pos..], 7)?;
            pos += consumed;
            headers.push(resolve_indexed(index as usize)?);
        } else if first & 0xC0 == 0x40 {
            // Literal with Incremental Indexing (Section 6.2.1): 01xxxxxx
            let (header, consumed) = decode_literal(&data[pos..], 6, pos)?;
            pos += consumed;
            headers.push(header);
        } else if first & 0xF0 == 0x00 {
            // Literal without Indexing (Section 6.2.2): 0000xxxx
            let (header, consumed) = decode_literal(&data[pos..], 4, pos)?;
            pos += consumed;
            headers.push(header);
        } else if first & 0xF0 == 0x10 {
            // Literal Never Indexed (Section 6.2.3): 0001xxxx
            let (header, consumed) = decode_literal(&data[pos..], 4, pos)?;
            pos += consumed;
            headers.push(header);
        } else if first & 0xE0 == 0x20 {
            // Dynamic Table Size Update (Section 6.3): 001xxxxx
            let (_new_size, consumed) = decode_integer(&data[pos..], 5)?;
            pos += consumed;
            // Skip — stateless dissector cannot track table size changes
        } else {
            return Err("invalid HPACK header field representation");
        }
    }

    Ok(headers)
}

/// Resolve an indexed header field from the static table.
fn resolve_indexed(index: usize) -> Result<DecodedHeader, &'static str> {
    if index == 0 {
        return Err("HPACK index 0 is invalid");
    }
    match static_table::lookup(index) {
        Some(entry) => Ok(DecodedHeader::Resolved {
            name: HeaderString::Static(entry.name),
            value: HeaderString::Static(entry.value),
        }),
        None => Ok(DecodedHeader::Unresolved(index)),
    }
}

/// Decode a literal header field representation.
/// `prefix_bits` is the number of bits used for the name index prefix.
/// `base_pos` is the position of data[0] within the full fragment.
fn decode_literal(
    data: &[u8],
    prefix_bits: u8,
    base_pos: usize,
) -> Result<(DecodedHeader, usize), &'static str> {
    let (name_index, mut consumed) = decode_integer(data, prefix_bits)?;

    let name = if name_index == 0 {
        // Name is a string literal
        let (name_hs, n) = decode_string(&data[consumed..], base_pos + consumed)?;
        consumed += n;
        name_hs
    } else {
        // Name from table lookup
        match static_table::lookup(name_index as usize) {
            Some(entry) => HeaderString::Static(entry.name),
            None => {
                // Dynamic table name reference — we still need to read the value
                let (value, n) = decode_string(&data[consumed..], base_pos + consumed)?;
                consumed += n;
                // Return with a synthetic name
                return Ok((
                    DecodedHeader::Resolved {
                        name: HeaderString::Static("[dynamic]"),
                        value,
                    },
                    consumed,
                ));
            }
        }
    };

    let (value, n) = decode_string(&data[consumed..], base_pos + consumed)?;
    consumed += n;

    Ok((DecodedHeader::Resolved { name, value }, consumed))
}

/// Decode an HPACK string literal (RFC 7541, Section 5.2).
/// Returns `(HeaderString, bytes_consumed)`.
/// `base_pos` is the position of `data[0]` within the full fragment.
fn decode_string(data: &[u8], base_pos: usize) -> Result<(HeaderString, usize), &'static str> {
    if data.is_empty() {
        return Err("empty data for string decode");
    }

    let huffman_encoded = data[0] & 0x80 != 0;
    let (length, consumed) = decode_integer(data, 7)?;
    let length = length as usize;

    let end = consumed + length;
    if end > data.len() {
        return Err("string length exceeds available data");
    }

    let str_start = base_pos + consumed;
    let str_end = base_pos + end;

    let hs = if huffman_encoded {
        HeaderString::Huffman(str_start, str_end)
    } else {
        HeaderString::Literal(str_start, str_end)
    };

    Ok((hs, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_indexed_method_get() {
        // Index 2 = :method GET → 0x82
        let data = [0x82];
        let headers = decode_header_block(&data).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers[0],
            DecodedHeader::Resolved {
                name: HeaderString::Static(":method"),
                value: HeaderString::Static("GET"),
            }
        );
    }

    #[test]
    fn decode_indexed_scheme_http() {
        // Index 6 = :scheme http → 0x86
        let data = [0x86];
        let headers = decode_header_block(&data).unwrap();
        assert_eq!(
            headers[0],
            DecodedHeader::Resolved {
                name: HeaderString::Static(":scheme"),
                value: HeaderString::Static("http"),
            }
        );
    }

    #[test]
    fn decode_indexed_path_root() {
        // Index 4 = :path / → 0x84
        let data = [0x84];
        let headers = decode_header_block(&data).unwrap();
        assert_eq!(
            headers[0],
            DecodedHeader::Resolved {
                name: HeaderString::Static(":path"),
                value: HeaderString::Static("/"),
            }
        );
    }

    #[test]
    fn decode_multiple_indexed() {
        // :method GET (0x82), :scheme http (0x86), :path / (0x84)
        let data = [0x82, 0x86, 0x84];
        let headers = decode_header_block(&data).unwrap();
        assert_eq!(headers.len(), 3);
        assert_eq!(
            headers[0],
            DecodedHeader::Resolved {
                name: HeaderString::Static(":method"),
                value: HeaderString::Static("GET"),
            }
        );
    }

    #[test]
    fn decode_literal_with_indexing_new_name() {
        // Literal with incremental indexing, new name "custom-key" = "custom-value"
        let mut data = vec![0x40];
        data.push(0x0a); // name length = 10, H=0
        data.extend_from_slice(b"custom-key");
        data.push(0x0c); // value length = 12, H=0
        data.extend_from_slice(b"custom-value");

        let headers = decode_header_block(&data).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers[0],
            DecodedHeader::Resolved {
                name: HeaderString::Literal(2, 12),
                value: HeaderString::Literal(13, 25),
            }
        );
    }

    #[test]
    fn decode_literal_indexed_name() {
        // Literal with indexing, name index 1 (:authority) = "www.example.com"
        let mut data = vec![0x41];
        data.push(0x0f); // value length = 15, H=0
        data.extend_from_slice(b"www.example.com");

        let headers = decode_header_block(&data).unwrap();
        assert_eq!(
            headers[0],
            DecodedHeader::Resolved {
                name: HeaderString::Static(":authority"),
                value: HeaderString::Literal(2, 17),
            }
        );
    }

    #[test]
    fn decode_dynamic_table_reference() {
        // Index 62 is in the dynamic table → should be Unresolved
        let data = [0xBE];
        let headers = decode_header_block(&data).unwrap();
        assert_eq!(headers[0], DecodedHeader::Unresolved(62));
    }

    #[test]
    fn decode_literal_with_huffman_value() {
        // Literal with indexing, name index 1 (:authority), Huffman-encoded value
        let mut data = vec![0x41];
        data.push(0x8c); // H=1, length = 12
        data.extend_from_slice(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);

        let headers = decode_header_block(&data).unwrap();
        assert_eq!(
            headers[0],
            DecodedHeader::Resolved {
                name: HeaderString::Static(":authority"),
                value: HeaderString::Huffman(2, 14),
            }
        );
    }

    #[test]
    fn decode_table_size_update() {
        // Dynamic table size update to 0: 0x20
        // Followed by indexed :method GET: 0x82
        let data = [0x20, 0x82];
        let headers = decode_header_block(&data).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers[0],
            DecodedHeader::Resolved {
                name: HeaderString::Static(":method"),
                value: HeaderString::Static("GET"),
            }
        );
    }

    #[test]
    fn decode_empty_block() {
        let headers = decode_header_block(&[]).unwrap();
        assert!(headers.is_empty());
    }

    #[test]
    fn decode_index_zero_is_error() {
        // 0x80 = indexed, index 0 → invalid
        let data = [0x80];
        assert!(decode_header_block(&data).is_err());
    }

    #[test]
    fn decode_literal_without_indexing() {
        // 0x00 = literal without indexing, new name
        let mut data = vec![0x00];
        data.push(0x04); // name length = 4
        data.extend_from_slice(b"test");
        data.push(0x03); // value length = 3
        data.extend_from_slice(b"abc");

        let headers = decode_header_block(&data).unwrap();
        assert_eq!(
            headers[0],
            DecodedHeader::Resolved {
                name: HeaderString::Literal(2, 6),
                value: HeaderString::Literal(7, 10),
            }
        );
    }

    #[test]
    fn decode_literal_never_indexed() {
        // 0x10 = literal never indexed, new name
        let mut data = vec![0x10];
        data.push(0x08); // name length = 8
        data.extend_from_slice(b"password");
        data.push(0x06); // value length = 6
        data.extend_from_slice(b"secret");

        let headers = decode_header_block(&data).unwrap();
        assert_eq!(
            headers[0],
            DecodedHeader::Resolved {
                name: HeaderString::Literal(2, 10),
                value: HeaderString::Literal(11, 17),
            }
        );
    }
}
