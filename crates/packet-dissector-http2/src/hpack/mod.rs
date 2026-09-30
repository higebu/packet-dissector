//! HPACK header compression decoder (RFC 7541).
//!
//! Decodes HPACK-compressed header blocks. With a [`DynamicTable`] the
//! decoder is a full RFC 7541 decoding context: dynamic table references
//! are resolved, literals with incremental indexing are inserted and
//! Dynamic Table Size Updates are applied. Without one (a single frame, or a
//! connection whose earlier header blocks were not seen), dynamic table
//! references are reported as unresolved and the table is not tracked.
//!
//! ## References
//! - RFC 7541: <https://www.rfc-editor.org/rfc/rfc7541>

mod dynamic_table;
pub(crate) mod huffman;
mod integer;
mod static_table;

pub(crate) use dynamic_table::DynamicTable;
use integer::decode_integer;

/// Number of entries in the static table.
/// RFC 7541, Appendix A — <https://www.rfc-editor.org/rfc/rfc7541#appendix-A>
const STATIC_TABLE_LEN: usize = 61;

/// Largest dynamic table size the decoder tracks.
///
/// SETTINGS_HEADER_TABLE_SIZE may be as large as 2^32 - 1 (RFC 9113,
/// Section 6.5.2 — <https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2>);
/// a Dynamic Table Size Update above this bound is reported as an error so
/// that the caller stops tracking the table instead of holding that much
/// memory per connection.
pub(crate) const MAX_TRACKED_TABLE_SIZE: usize = 64 * 1024;

/// A decoded header entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedHeader<'t> {
    /// Header with a known name and value.
    Resolved {
        /// Header name.
        name: HeaderString<'t>,
        /// Header value.
        value: HeaderString<'t>,
    },
    /// Literal header whose name refers to a dynamic table entry that is
    /// not known (no table is tracked). Contains the 1-based HPACK index of
    /// the name.
    UnresolvedName {
        /// 1-based HPACK index of the name.
        index: usize,
        /// Header value.
        value: HeaderString<'t>,
    },
    /// Indexed header field referring to a dynamic table entry that is not
    /// known (no table is tracked). Contains the 1-based HPACK index.
    Unresolved(usize),
}

/// A string value from HPACK decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderString<'t> {
    /// A `&'static str` from the HPACK static table.
    Static(&'static str),
    /// A literal string value (byte offset range within the HPACK block).
    /// Non-Huffman: the bytes can be directly interpreted as UTF-8.
    Literal(usize, usize),
    /// A Huffman-encoded literal (byte offset range within the HPACK
    /// block) — requires decoding.
    Huffman(usize, usize),
    /// Octets from the dynamic table (not part of the block).
    Owned(&'t [u8]),
}

/// Decode an HPACK header block, calling `emit` for every header field in
/// order.
///
/// With `table`, the block is decoded in that decoding context (RFC 7541,
/// Section 2.2 — <https://www.rfc-editor.org/rfc/rfc7541#section-2.2>):
/// indices past the static table must name a dynamic table entry, literals
/// with incremental indexing are added to it, and Dynamic Table Size Updates
/// change its maximum size. Without `table`, dynamic references produce
/// [`DecodedHeader::Unresolved`] / [`DecodedHeader::UnresolvedName`] and
/// size updates are skipped.
///
/// On error, the fields emitted before it stay emitted; the table may have
/// been changed by them.
pub fn decode_block(
    data: &[u8],
    mut table: Option<&mut DynamicTable>,
    emit: &mut dyn FnMut(DecodedHeader<'_>),
) -> Result<(), &'static str> {
    let mut pos = 0;
    // Whether a header field representation has been decoded yet.
    let mut after_field = false;

    while pos < data.len() {
        let first = data[pos];

        if first & 0xE0 != 0x20 {
            after_field = true;
        }
        if first & 0x80 != 0 {
            // Indexed Header Field (Section 6.1): 1xxxxxxx
            let (index, consumed) = decode_integer(&data[pos..], 7)?;
            pos += consumed;
            emit(resolve_indexed(index as usize, table.as_deref())?);
        } else if first & 0xC0 == 0x40 {
            // Literal with Incremental Indexing (Section 6.2.1): 01xxxxxx
            pos += decode_literal(data, pos, 6, table.as_deref_mut(), true, emit)?;
        } else if first & 0xF0 == 0x00 || first & 0xF0 == 0x10 {
            // Literal without Indexing (Section 6.2.2): 0000xxxx
            // Literal Never Indexed (Section 6.2.3): 0001xxxx
            pos += decode_literal(data, pos, 4, table.as_deref_mut(), false, emit)?;
        } else {
            // Dynamic Table Size Update (Section 6.3): 001xxxxx
            //
            // RFC 7541, Section 4.2 — "This dynamic table size update MUST
            // occur at the beginning of the first header block following
            // the change to the dynamic table size." —
            // <https://www.rfc-editor.org/rfc/rfc7541#section-4.2>
            if after_field {
                return Err("HPACK dynamic table size update after a header field");
            }
            let (new_size, consumed) = decode_integer(&data[pos..], 5)?;
            pos += consumed;
            if let Some(table) = table.as_deref_mut() {
                let new_size = new_size as usize;
                if new_size > MAX_TRACKED_TABLE_SIZE {
                    return Err("HPACK dynamic table size update exceeds the tracked maximum");
                }
                table.set_max_size(new_size);
            }
        }
    }

    Ok(())
}

/// Resolve an indexed header field.
///
/// RFC 7541, Section 2.3.3 — "Indices strictly greater than the sum of the
/// lengths of both tables MUST be treated as a decoding error." —
/// <https://www.rfc-editor.org/rfc/rfc7541#section-2.3.3>
fn resolve_indexed<'t>(
    index: usize,
    table: Option<&'t DynamicTable>,
) -> Result<DecodedHeader<'t>, &'static str> {
    if index == 0 {
        // RFC 7541, Section 6.1 — "The index value of 0 is not used. It
        // MUST be treated as a decoding error if found in an indexed header
        // field representation." —
        // <https://www.rfc-editor.org/rfc/rfc7541#section-6.1>
        return Err("HPACK index 0 is invalid");
    }
    if let Some(entry) = static_table::lookup(index) {
        return Ok(DecodedHeader::Resolved {
            name: HeaderString::Static(entry.name),
            value: HeaderString::Static(entry.value),
        });
    }
    match table {
        None => Ok(DecodedHeader::Unresolved(index)),
        Some(table) => {
            let entry = table
                .get(index - STATIC_TABLE_LEN)
                .ok_or("HPACK index past the dynamic table")?;
            Ok(DecodedHeader::Resolved {
                name: HeaderString::Owned(&entry.name),
                value: HeaderString::Owned(&entry.value),
            })
        }
    }
}

/// Decode a literal header field representation starting at `data[start]`
/// and return the number of octets it occupies.
///
/// `prefix_bits` is the number of bits of the name index prefix. When
/// `index` is set (Section 6.2.1) and a table is tracked, the field is added
/// to the table after it has been emitted.
fn decode_literal(
    data: &[u8],
    start: usize,
    prefix_bits: u8,
    table: Option<&mut DynamicTable>,
    index: bool,
    emit: &mut dyn FnMut(DecodedHeader<'_>),
) -> Result<usize, &'static str> {
    let (name_index, mut consumed) = decode_integer(&data[start..], prefix_bits)?;
    let name_index = name_index as usize;

    let name = if name_index == 0 {
        // Name is a string literal
        let (name_hs, n) = decode_string(data, start + consumed)?;
        consumed += n;
        Some(name_hs)
    } else {
        // `None` for a dynamic table name reference: resolved below when a
        // table is tracked, reported as unresolved otherwise.
        static_table::lookup(name_index).map(|entry| HeaderString::Static(entry.name))
    };

    let (value, n) = decode_string(data, start + consumed)?;
    consumed += n;

    let Some(table) = table else {
        match name {
            Some(name) => emit(DecodedHeader::Resolved { name, value }),
            None => emit(DecodedHeader::UnresolvedName {
                index: name_index,
                value,
            }),
        }
        return Ok(consumed);
    };

    if !index {
        let name = match name {
            Some(name) => name,
            None => HeaderString::Owned(
                &table
                    .get(name_index - STATIC_TABLE_LEN)
                    .ok_or("HPACK index past the dynamic table")?
                    .name,
            ),
        };
        emit(DecodedHeader::Resolved { name, value });
        return Ok(consumed);
    }

    // The entry needs its own copy of the (Huffman-decoded) octets; the
    // emitted field reuses them instead of decoding a second time.
    let name_bytes = match &name {
        Some(name) => string_bytes(data, name)?,
        None => table
            .get(name_index - STATIC_TABLE_LEN)
            .ok_or("HPACK index past the dynamic table")?
            .name
            .to_vec(),
    };
    let value_bytes = string_bytes(data, &value)?;
    emit(DecodedHeader::Resolved {
        name: name
            .filter(|n| !matches!(n, HeaderString::Huffman(..)))
            .unwrap_or(HeaderString::Owned(&name_bytes)),
        value: match value {
            HeaderString::Huffman(..) => HeaderString::Owned(&value_bytes),
            other => other,
        },
    });
    table.insert(&name_bytes, &value_bytes);
    Ok(consumed)
}

/// Octets of a string decoded from the block (Huffman strings are decoded).
fn string_bytes(data: &[u8], s: &HeaderString<'_>) -> Result<Vec<u8>, &'static str> {
    Ok(match s {
        HeaderString::Static(s) => s.as_bytes().to_vec(),
        HeaderString::Literal(a, b) => data[*a..*b].to_vec(),
        HeaderString::Huffman(a, b) => huffman::huffman_decode(&data[*a..*b])?,
        HeaderString::Owned(bytes) => bytes.to_vec(),
    })
}

/// Decode an HPACK string literal (RFC 7541, Section 5.2 —
/// <https://www.rfc-editor.org/rfc/rfc7541#section-5.2>) starting at
/// `data[start]`. Returns the string (as a range of `data`) and the number
/// of octets it occupies.
fn decode_string(
    data: &[u8],
    start: usize,
) -> Result<(HeaderString<'static>, usize), &'static str> {
    let rest = &data[start..];
    if rest.is_empty() {
        return Err("empty data for string decode");
    }

    let huffman_encoded = rest[0] & 0x80 != 0;
    let (length, consumed) = decode_integer(rest, 7)?;
    let length = length as usize;

    let end = consumed
        .checked_add(length)
        .filter(|&end| end <= rest.len())
        .ok_or("string length exceeds available data")?;

    let str_start = start + consumed;
    let str_end = start + end;

    let hs = if huffman_encoded {
        HeaderString::Huffman(str_start, str_end)
    } else {
        HeaderString::Literal(str_start, str_end)
    };

    Ok((hs, end))
}

/// Decode a whole header block without a dynamic table.
#[cfg(test)]
fn decode_header_block(data: &[u8]) -> Result<Vec<DecodedHeader<'static>>, &'static str> {
    let mut headers = Vec::new();
    decode_block(data, None, &mut |h| {
        headers.push(match h {
            DecodedHeader::Resolved { name, value } => DecodedHeader::Resolved {
                name: detach(name),
                value: detach(value),
            },
            DecodedHeader::UnresolvedName { index, value } => DecodedHeader::UnresolvedName {
                index,
                value: detach(value),
            },
            DecodedHeader::Unresolved(index) => DecodedHeader::Unresolved(index),
        })
    })?;
    Ok(headers)
}

/// Strings decoded without a table never borrow from one.
#[cfg(test)]
fn detach(s: HeaderString<'_>) -> HeaderString<'static> {
    match s {
        HeaderString::Static(s) => HeaderString::Static(s),
        HeaderString::Literal(a, b) => HeaderString::Literal(a, b),
        HeaderString::Huffman(a, b) => HeaderString::Huffman(a, b),
        HeaderString::Owned(_) => unreachable!("no table"),
    }
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
    fn decode_dynamic_name_reference_without_table() {
        // Literal with incremental indexing, name index 62, value "foo".
        let data = [0x7e, 0x03, b'f', b'o', b'o'];
        let headers = decode_header_block(&data).unwrap();
        assert_eq!(
            headers[0],
            DecodedHeader::UnresolvedName {
                index: 62,
                value: HeaderString::Literal(2, 5),
            }
        );
    }

    #[test]
    fn decode_error_keeps_earlier_headers() {
        // :method GET, then a literal whose value runs past the block.
        let data = [0x82, 0x04, 0x05, b'a'];
        let mut seen = Vec::new();
        let result = decode_block(&data, None, &mut |h| seen.push(format!("{h:?}")));
        assert!(result.is_err());
        assert_eq!(seen.len(), 1);
    }

    /// Render one decoded header as `name: value` (or `#index: value`).
    fn render(block: &[u8], header: &DecodedHeader<'_>) -> String {
        fn text(block: &[u8], s: &HeaderString<'_>) -> String {
            match s {
                HeaderString::Static(s) => (*s).to_string(),
                HeaderString::Literal(a, b) => String::from_utf8(block[*a..*b].to_vec()).unwrap(),
                HeaderString::Huffman(a, b) => {
                    String::from_utf8(huffman::huffman_decode(&block[*a..*b]).unwrap()).unwrap()
                }
                HeaderString::Owned(bytes) => String::from_utf8(bytes.to_vec()).unwrap(),
            }
        }
        match header {
            DecodedHeader::Resolved { name, value } => {
                format!("{}: {}", text(block, name), text(block, value))
            }
            DecodedHeader::UnresolvedName { index, value } => {
                format!("#{index}: {}", text(block, value))
            }
            DecodedHeader::Unresolved(index) => format!("#{index}"),
        }
    }

    /// Decode `blocks` in order on one table; return the header lists and
    /// the table size after each block.
    fn decode_sequence(max_size: usize, blocks: &[&str]) -> Vec<(Vec<String>, usize)> {
        let mut table = DynamicTable::new(max_size);
        blocks
            .iter()
            .map(|hex| {
                let block = hex_bytes(hex);
                let mut list = Vec::new();
                decode_block(&block, Some(&mut table), &mut |h| {
                    list.push(render(&block, &h))
                })
                .unwrap();
                (list, table.size())
            })
            .collect()
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    const C3_LISTS: [&[&str]; 3] = [
        &[
            ":method: GET",
            ":scheme: http",
            ":path: /",
            ":authority: www.example.com",
        ],
        &[
            ":method: GET",
            ":scheme: http",
            ":path: /",
            ":authority: www.example.com",
            "cache-control: no-cache",
        ],
        &[
            ":method: GET",
            ":scheme: https",
            ":path: /index.html",
            ":authority: www.example.com",
            "custom-key: custom-value",
        ],
    ];

    const C5_LISTS: [&[&str]; 3] = [
        &[
            ":status: 302",
            "cache-control: private",
            "date: Mon, 21 Oct 2013 20:13:21 GMT",
            "location: https://www.example.com",
        ],
        &[
            ":status: 307",
            "cache-control: private",
            "date: Mon, 21 Oct 2013 20:13:21 GMT",
            "location: https://www.example.com",
        ],
        &[
            ":status: 200",
            "cache-control: private",
            "date: Mon, 21 Oct 2013 20:13:22 GMT",
            "location: https://www.example.com",
            "content-encoding: gzip",
            "set-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
        ],
    ];

    fn assert_sequence(got: &[(Vec<String>, usize)], lists: &[&[&str]; 3], sizes: [usize; 3]) {
        for (i, (list, size)) in got.iter().enumerate() {
            assert_eq!(list, lists[i], "header list {i}");
            assert_eq!(*size, sizes[i], "table size after block {i}");
        }
    }

    #[test]
    fn rfc7541_c3_requests_without_huffman() {
        let got = decode_sequence(
            4096,
            &[
                "828684410f7777772e6578616d706c652e636f6d",
                "828684be58086e6f2d6361636865",
                "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
            ],
        );
        assert_sequence(&got, &C3_LISTS, [57, 110, 164]);
    }

    #[test]
    fn rfc7541_c4_requests_with_huffman() {
        let got = decode_sequence(
            4096,
            &[
                "828684418cf1e3c2e5f23a6ba0ab90f4ff",
                "828684be5886a8eb10649cbf",
                "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
            ],
        );
        assert_sequence(&got, &C3_LISTS, [57, 110, 164]);
    }

    #[test]
    fn rfc7541_c5_responses_without_huffman() {
        let got = decode_sequence(
            256,
            &[
                "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
                "4803333037c1c0bf",
                "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
            ],
        );
        assert_sequence(&got, &C5_LISTS, [222, 222, 215]);
    }

    #[test]
    fn rfc7541_c6_responses_with_huffman() {
        let got = decode_sequence(
            256,
            &[
                "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
                "4883640effc1c0bf",
                "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
            ],
        );
        assert_sequence(&got, &C5_LISTS, [222, 222, 215]);
    }

    #[test]
    fn dynamic_index_past_the_table_is_an_error() {
        // RFC 7541, Section 2.3.3 — "Indices strictly greater than the sum
        // of the lengths of both tables MUST be treated as a decoding error."
        let mut table = DynamicTable::new(4096);
        assert!(decode_block(&[0xbe], Some(&mut table), &mut |_| {}).is_err());
        assert!(decode_block(&[0x7e, 0x00], Some(&mut table), &mut |_| {}).is_err());
    }

    #[test]
    fn dynamic_name_reference_is_resolved_from_the_table() {
        let mut table = DynamicTable::new(4096);
        let first = hex_bytes("400a637573746f6d2d6b65790c637573746f6d2d76616c7565");
        decode_block(&first, Some(&mut table), &mut |_| {}).unwrap();
        // Literal without indexing, name index 62 (custom-key), value "v".
        let block = [0x0f, 0x2f, 0x01, b'v'];
        let mut list = Vec::new();
        decode_block(&block, Some(&mut table), &mut |h| {
            list.push(render(&block, &h))
        })
        .unwrap();
        assert_eq!(list, ["custom-key: v"]);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn size_update_after_a_field_is_an_error() {
        // RFC 7541, Section 4.2 — the update "MUST occur at the beginning of
        // the first header block following the change".
        let mut seen = 0;
        assert!(decode_block(&[0x20, 0x3f, 0x01, 0x82], None, &mut |_| seen += 1).is_ok());
        assert_eq!(seen, 1);
        assert_eq!(
            decode_block(&[0x82, 0x20], None, &mut |_| {}),
            Err("HPACK dynamic table size update after a header field")
        );
    }

    #[test]
    fn size_update_evicts_and_is_bounded() {
        let mut table = DynamicTable::new(4096);
        let first = hex_bytes("400a637573746f6d2d6b65790c637573746f6d2d76616c7565");
        decode_block(&first, Some(&mut table), &mut |_| {}).unwrap();
        assert_eq!(table.len(), 1);
        // RFC 7541, Section 6.3 — size update to 0 empties the table.
        decode_block(&[0x20], Some(&mut table), &mut |_| {}).unwrap();
        assert_eq!(table.len(), 0);
        assert_eq!(table.max_size(), 0);
        // A size the decoder does not track is an error.
        let mut too_big = vec![0x3f];
        let mut n = MAX_TRACKED_TABLE_SIZE + 1 - 31;
        while n >= 128 {
            too_big.push((n % 128) as u8 | 0x80);
            n /= 128;
        }
        too_big.push(n as u8);
        assert!(decode_block(&too_big, Some(&mut table), &mut |_| {}).is_err());
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
