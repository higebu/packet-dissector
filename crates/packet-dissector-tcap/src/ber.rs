//! Minimal zero-copy BER reader for TCAP and its users (e.g. MAP).
//!
//! Supports what ITU-T Q.773, clause 4.1 allows: single- and multi-octet
//! tags, the short, long and indefinite length forms, and the
//! end-of-contents octets. Values are borrowed from the input; nothing is
//! allocated. Indefinite lengths are resolved without recursion, so nesting
//! depth cannot exhaust the stack.
//!
//! ## References
//! - ITU-T X.690 (02/2021), clause 8.1 (identifier, length and contents
//!   octets), 8.3 (INTEGER) and 8.19 (OBJECT IDENTIFIER):
//!   <https://www.itu.int/rec/T-REC-X.690>
//! - ITU-T Q.773 (06/97), clause 4.1 (TCAP encoding rules):
//!   <https://www.itu.int/rec/T-REC-Q.773>

use core::ops::Range;

/// Universal class. X.690, clause 8.1.2.2, Table 1.
pub const CLASS_UNIVERSAL: u8 = 0;
/// Application class.
pub const CLASS_APPLICATION: u8 = 1;
/// Context-specific class.
pub const CLASS_CONTEXT: u8 = 2;
/// Private class.
pub const CLASS_PRIVATE: u8 = 3;

/// Universal tag number of INTEGER. X.680, clause 8.4, Table 1.
pub const TAG_INTEGER: u32 = 2;
/// Universal tag number of OCTET STRING.
pub const TAG_OCTET_STRING: u32 = 4;
/// Universal tag number of NULL.
pub const TAG_NULL: u32 = 5;
/// Universal tag number of OBJECT IDENTIFIER.
pub const TAG_OID: u32 = 6;
/// Universal tag number of EXTERNAL.
pub const TAG_EXTERNAL: u32 = 8;
/// Universal tag number of ENUMERATED.
pub const TAG_ENUMERATED: u32 = 10;
/// Universal tag number of SEQUENCE / SEQUENCE OF.
pub const TAG_SEQUENCE: u32 = 16;

/// Highest tag number accepted (four extension octets of 7 bits).
const MAX_TAG_NUMBER: u32 = (1 << 28) - 1;
/// Highest number of length octets accepted in the long form.
const MAX_LENGTH_OCTETS: usize = 4;

/// Why an element could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BerError {
    /// The element needs `needed` octets of the input, which is shorter.
    Truncated {
        /// Offset (in the input) just past the octets the element needs.
        needed: usize,
    },
    /// The element is not valid BER (e.g. reserved length octet 0xFF, an
    /// indefinite length on a primitive, a tag or length too large).
    Invalid,
}

/// One BER element (tag-length-value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    /// Tag class ([`CLASS_UNIVERSAL`] .. [`CLASS_PRIVATE`]).
    pub class: u8,
    /// Whether the element is constructed.
    pub constructed: bool,
    /// Tag number.
    pub number: u32,
    /// Offset of the identifier octet.
    pub start: usize,
    /// Range of the contents octets (excluding end-of-contents octets).
    pub contents: Range<usize>,
    /// Offset just past the element (including end-of-contents octets).
    pub end: usize,
}

impl Tlv {
    /// Whether the element has the given class, form and tag number.
    pub fn is(&self, class: u8, constructed: bool, number: u32) -> bool {
        self.class == class && self.constructed == constructed && self.number == number
    }

    /// Contents octets of the element.
    pub fn value<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        data.get(self.contents.clone()).unwrap_or_default()
    }

    /// The element's identifier octet(s) as a single value (first octet for
    /// low tag numbers), convenient for matching well-known tags such as
    /// `0x62` (TCAP Begin).
    pub fn first_octet(&self, data: &[u8]) -> u8 {
        data.get(self.start).copied().unwrap_or_default()
    }
}

/// Reads the identifier and length octets at `pos`; returns the element and,
/// for the indefinite form, `None` as the contents end.
fn read_header(data: &[u8], pos: usize) -> Result<(u8, bool, u32, usize, Option<usize>), BerError> {
    let truncated = |needed| BerError::Truncated { needed };
    // X.690, clause 8.1.2 — identifier octets.
    let first = *data.get(pos).ok_or(truncated(pos + 1))?;
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    let mut number = u32::from(first & 0x1f);
    let mut p = pos + 1;
    if number == 0x1f {
        // X.690, clause 8.1.2.4 — high tag number form: bit 8 of each
        // subsequent octet is 1 except in the last octet.
        number = 0;
        loop {
            let b = *data.get(p).ok_or(truncated(p + 1))?;
            p += 1;
            // Checked before shifting, so no bits are lost.
            if number > MAX_TAG_NUMBER >> 7 {
                return Err(BerError::Invalid);
            }
            number = (number << 7) | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    // X.690, clause 8.1.3 — length octets.
    let l = *data.get(p).ok_or(truncated(p + 1))?;
    p += 1;
    let len = match l {
        // Clause 8.1.3.6 — indefinite form, constructed only.
        0x80 if constructed => return Ok((class, constructed, number, p, None)),
        0x80 => return Err(BerError::Invalid),
        // Clause 8.1.3.5 c) — the value 11111111 shall not be used.
        0xff => return Err(BerError::Invalid),
        // Clause 8.1.3.4 — short form.
        l if l & 0x80 == 0 => usize::from(l),
        // Clause 8.1.3.5 — long form.
        l => {
            let n = usize::from(l & 0x7f);
            if n > MAX_LENGTH_OCTETS {
                return Err(BerError::Invalid);
            }
            let octets = data.get(p..p + n).ok_or(truncated(p + n))?;
            p += n;
            octets
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b))
        }
    };
    let end = p.checked_add(len).ok_or(BerError::Invalid)?;
    Ok((class, constructed, number, p, Some(end)))
}

/// Reads the element that starts at `pos`.
///
/// X.690, clause 8.1.5 — an indefinite-length element ends with the
/// end-of-contents octets `00 00`; nested indefinite-length elements are
/// matched with a depth counter instead of recursion.
pub fn read(data: &[u8], pos: usize) -> Result<Tlv, BerError> {
    let (class, constructed, number, contents_start, end) = read_header(data, pos)?;
    let (contents_end, end) = match end {
        Some(end) => {
            if end > data.len() {
                return Err(BerError::Truncated { needed: end });
            }
            (end, end)
        }
        None => {
            let mut p = contents_start;
            let mut depth = 1usize;
            loop {
                if data.get(p..p + 2) == Some(&[0, 0]) {
                    p += 2;
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    continue;
                }
                match read_header(data, p)? {
                    (_, _, _, inner_start, None) => {
                        p = inner_start;
                        depth += 1;
                    }
                    (_, _, _, _, Some(inner_end)) => {
                        if inner_end > data.len() {
                            return Err(BerError::Truncated { needed: inner_end });
                        }
                        p = inner_end;
                    }
                }
            }
            (p - 2, p)
        }
    };
    Ok(Tlv {
        class,
        constructed,
        number,
        start: pos,
        contents: contents_start..contents_end,
        end,
    })
}

/// Iterator over the elements in `data[range]`, e.g. the contents of a
/// constructed element. Iteration stops at the first element that cannot
/// be read; [`Children::error`] tells whether it stopped early.
#[derive(Debug, Clone)]
pub struct Children<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
    error: Option<BerError>,
}

impl<'a> Children<'a> {
    /// Iterate the elements in `data[range]`.
    pub fn new(data: &'a [u8], range: Range<usize>) -> Self {
        Self {
            data,
            pos: range.start,
            end: range.end.min(data.len()),
            error: None,
        }
    }

    /// The error that ended iteration early, if any.
    pub fn error(&self) -> Option<BerError> {
        self.error
    }
}

impl Iterator for Children<'_> {
    type Item = Tlv;

    fn next(&mut self) -> Option<Tlv> {
        if self.pos >= self.end || self.error.is_some() {
            return None;
        }
        // Read within the enclosing contents, so an element cannot claim
        // octets of its parent's siblings.
        let bounded = self.data.get(..self.end).unwrap_or_default();
        match read(bounded, self.pos) {
            Ok(tlv) => {
                self.pos = tlv.end;
                Some(tlv)
            }
            Err(e) => {
                self.error = Some(e);
                None
            }
        }
    }
}

/// Decodes a two's complement INTEGER of 1 to 4 contents octets.
///
/// X.690, clause 8.3.2 — "the contents octets shall be a two's complement
/// binary number equal to the integer value".
pub fn integer(value: &[u8]) -> Option<i32> {
    if value.is_empty() || value.len() > 4 {
        return None;
    }
    let sign = if value[0] & 0x80 != 0 { -1i32 } else { 0 };
    Some(value.iter().fold(sign, |acc, b| (acc << 8) | i32::from(*b)))
}

/// Writes an OBJECT IDENTIFIER's contents octets in dotted notation.
///
/// X.690, clause 8.19 — each subidentifier is a series of 7-bit groups with
/// bit 8 set on all but the last octet; the first subidentifier combines the
/// first two arcs as `X * 40 + Y`. Returns `false` (writing nothing) when
/// the encoding is malformed.
pub fn write_oid(value: &[u8], w: &mut dyn std::io::Write) -> std::io::Result<bool> {
    if !oid_is_valid(value) {
        return Ok(false);
    }
    let mut first = true;
    let mut acc: u64 = 0;
    for b in value {
        acc = (acc << 7) | u64::from(b & 0x7f);
        if b & 0x80 != 0 {
            continue;
        }
        if first {
            let (x, y) = match acc {
                0..=39 => (0, acc),
                40..=79 => (1, acc - 40),
                _ => (2, acc - 80),
            };
            write!(w, "{x}.{y}")?;
            first = false;
        } else {
            write!(w, ".{acc}")?;
        }
        acc = 0;
    }
    Ok(true)
}

/// Whether `value` is a well-formed OBJECT IDENTIFIER encoding whose
/// subidentifiers fit in 63 bits.
fn oid_is_valid(value: &[u8]) -> bool {
    let mut groups = 0;
    for (i, b) in value.iter().enumerate() {
        let starts = i == 0 || value[i - 1] & 0x80 == 0;
        // X.690, clause 8.19.2 — "the leading octet of the subidentifier
        // shall not have the value 0x80".
        if starts && *b == 0x80 {
            return false;
        }
        groups = if starts { 1 } else { groups + 1 };
        if groups > 9 {
            return false;
        }
    }
    value.last().is_some_and(|b| b & 0x80 == 0)
}

#[cfg(test)]
mod tests {
    //! # ITU-T X.690 (BER subset) Coverage
    //!
    //! | Clause   | Description                              | Test                         |
    //! |----------|------------------------------------------|------------------------------|
    //! | 8.1.2    | Low and high tag number forms            | read_tags                    |
    //! | 8.1.3.4  | Short length form                        | read_tags                    |
    //! | 8.1.3.5  | Long length form, 0xFF reserved          | read_long_length             |
    //! | 8.1.3.6  | Indefinite form, nested, primitive error | read_indefinite              |
    //! | 8.1.5    | End-of-contents                          | read_indefinite              |
    //! | 8.1      | Truncation                               | read_truncated               |
    //! | 8.3      | INTEGER                                  | integers                     |
    //! | 8.19     | OBJECT IDENTIFIER                        | oids                         |

    use super::*;

    #[test]
    fn read_tags() {
        let t = read(&[0x62, 0x01, 0xaa], 0).unwrap();
        assert!(t.is(CLASS_APPLICATION, true, 2));
        assert_eq!(t.contents, 2..3);
        assert_eq!(t.end, 3);
        assert_eq!(t.value(&[0x62, 0x01, 0xaa]), &[0xaa]);
        assert_eq!(t.first_octet(&[0x62, 0x01, 0xaa]), 0x62);
        // [30] constructed: 0xBE; high tag number 200 = 0x81 0x48.
        let t = read(&[0x9f, 0x81, 0x48, 0x00], 0).unwrap();
        assert!(t.is(CLASS_CONTEXT, false, 200));
        assert_eq!(t.contents, 4..4);
        // Tag number overflow, including one that would wrap to a small
        // number if bits were shifted out.
        assert_eq!(
            read(&[0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00], 0),
            Err(BerError::Invalid)
        );
        assert_eq!(
            read(&[0x7f, 0x90, 0x80, 0x80, 0x80, 0x02, 0x00], 0),
            Err(BerError::Invalid)
        );
        // The largest accepted tag number.
        let t = read(&[0x1f, 0xff, 0xff, 0xff, 0x7f, 0x00], 0).unwrap();
        assert_eq!(t.number, MAX_TAG_NUMBER);
        assert_eq!(
            read(&[0x1f, 0x81], 0),
            Err(BerError::Truncated { needed: 3 })
        );
    }

    #[test]
    fn read_long_length() {
        let mut d = vec![0x04, 0x81, 0x80];
        d.extend_from_slice(&[0u8; 128]);
        let t = read(&d, 0).unwrap();
        assert_eq!(t.contents, 3..131);
        assert_eq!(read(&[0x04, 0xff], 0), Err(BerError::Invalid));
        assert_eq!(
            read(&[0x04, 0x85, 0, 0, 0, 0, 1], 0),
            Err(BerError::Invalid)
        );
        assert_eq!(
            read(&[0x04, 0x82, 0x01], 0),
            Err(BerError::Truncated { needed: 4 })
        );
    }

    #[test]
    fn read_indefinite() {
        // SEQUENCE (indefinite) { SEQUENCE (indefinite) { NULL } , INTEGER 1 }
        let d = [
            0x30, 0x80, 0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01, 0x00, 0x00, 0xff,
        ];
        let t = read(&d, 0).unwrap();
        assert_eq!(t.contents, 2..11);
        assert_eq!(t.end, 13);
        let kids: Vec<_> = Children::new(&d, t.contents.clone()).collect();
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].contents, 4..6);
        assert_eq!(kids[0].end, 8);
        assert!(kids[1].is(CLASS_UNIVERSAL, false, TAG_INTEGER));
        // Indefinite length on a primitive is invalid.
        assert_eq!(read(&[0x04, 0x80, 0x00, 0x00], 0), Err(BerError::Invalid));
        // Missing end-of-contents.
        assert!(matches!(
            read(&[0x30, 0x80, 0x05, 0x00], 0),
            Err(BerError::Truncated { .. })
        ));
        // Inner element overrunning the input.
        assert_eq!(
            read(&[0x30, 0x80, 0x04, 0x05, 0x00], 0),
            Err(BerError::Truncated { needed: 9 })
        );
        // Deep nesting does not recurse.
        let mut deep = vec![];
        for _ in 0..100_000 {
            deep.extend_from_slice(&[0x30, 0x80]);
        }
        for _ in 0..100_000 {
            deep.extend_from_slice(&[0x00, 0x00]);
        }
        assert_eq!(read(&deep, 0).unwrap().end, deep.len());
    }

    #[test]
    fn read_truncated() {
        assert_eq!(read(&[], 0), Err(BerError::Truncated { needed: 1 }));
        assert_eq!(read(&[0x04], 0), Err(BerError::Truncated { needed: 2 }));
        assert_eq!(
            read(&[0x04, 0x03, 0x00], 0),
            Err(BerError::Truncated { needed: 5 })
        );
        // Children stop at a malformed element and report it.
        let d = [0x02, 0x01, 0x05, 0x04, 0x09];
        let mut c = Children::new(&d, 0..d.len());
        assert!(c.next().is_some());
        assert!(c.next().is_none());
        assert_eq!(c.error(), Some(BerError::Truncated { needed: 14 }));
        assert!(c.next().is_none());
        // Children never read past their range.
        let d = [0x04, 0x02, 0xaa, 0xbb];
        let mut c = Children::new(&d, 0..3);
        assert!(c.next().is_none());
        assert!(c.error().is_some());
    }

    #[test]
    fn integers() {
        assert_eq!(integer(&[0x01]), Some(1));
        assert_eq!(integer(&[0xff]), Some(-1));
        assert_eq!(integer(&[0x80]), Some(-128));
        assert_eq!(integer(&[0x00, 0x80]), Some(128));
        assert_eq!(integer(&[0x7f, 0xff, 0xff, 0xff]), Some(i32::MAX));
        assert_eq!(integer(&[]), None);
        assert_eq!(integer(&[0, 0, 0, 0, 1]), None);
    }

    fn oid(v: &[u8]) -> Option<String> {
        let mut out = Vec::new();
        write_oid(v, &mut out)
            .unwrap()
            .then(|| String::from_utf8(out).unwrap())
    }

    #[test]
    fn oids() {
        // Q.773, Table 37 — dialogue-as-id {0 0 17 773 1 1 1}.
        assert_eq!(
            oid(&[0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01]).as_deref(),
            Some("0.0.17.773.1.1.1")
        );
        assert_eq!(oid(&[0x2b, 0x06]).as_deref(), Some("1.3.6"));
        assert_eq!(oid(&[0x88, 0x37]).as_deref(), Some("2.999"));
        assert_eq!(oid(&[]), None);
        assert_eq!(oid(&[0x86]), None);
        assert_eq!(oid(&[0x01, 0x80, 0x01]), None);
        assert_eq!(oid(&[0xff; 10]), None);
    }
}
