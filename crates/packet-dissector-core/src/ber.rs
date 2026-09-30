//! Minimal ASN.1 BER tag-length-value walker (ITU-T X.690).
//!
//! Protocol dissectors that carry BER-encoded data (SNMP, and later LDAP,
//! Kerberos, TCAP, X.509) use this module to split their input into
//! identifier, length and contents octets without allocating. It only walks
//! the TLV structure; interpreting the contents (INTEGER, OBJECT
//! IDENTIFIER, ...) is left to each protocol.
//!
//! ## References
//! - ITU-T X.690 (BER/CER/DER), clause 8.1 (general rules for encoding):
//!   <https://www.itu.int/rec/T-REC-X.690>

use crate::error::PacketError;

/// Tag class: bits 8 and 7 of the identifier octet (X.690, 8.1.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TagClass {
    /// Universal (`00`).
    Universal,
    /// Application (`01`).
    Application,
    /// Context-specific (`10`).
    ContextSpecific,
    /// Private (`11`).
    Private,
}

/// A decoded identifier: class, primitive/constructed and tag number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag {
    /// Tag class.
    pub class: TagClass,
    /// Whether the encoding is constructed (bit 6 of the identifier octet,
    /// X.690, 8.1.2.5).
    pub constructed: bool,
    /// Tag number (X.690, 8.1.2.3 and 8.1.2.4).
    pub number: u32,
}

impl Tag {
    /// Universal tag number of `BOOLEAN`.
    pub const BOOLEAN: u32 = 1;
    /// Universal tag number of `INTEGER`.
    pub const INTEGER: u32 = 2;
    /// Universal tag number of `BIT STRING`.
    pub const BIT_STRING: u32 = 3;
    /// Universal tag number of `OCTET STRING`.
    pub const OCTET_STRING: u32 = 4;
    /// Universal tag number of `NULL`.
    pub const NULL: u32 = 5;
    /// Universal tag number of `OBJECT IDENTIFIER`.
    pub const OBJECT_IDENTIFIER: u32 = 6;
    /// Universal tag number of `SEQUENCE` / `SEQUENCE OF`.
    pub const SEQUENCE: u32 = 16;

    /// Whether this is the universal tag `number` in either form.
    pub fn is_universal(&self, number: u32) -> bool {
        self.class == TagClass::Universal && self.number == number
    }
}

/// Length octets: definite (X.690, 8.1.3.4 / 8.1.3.5) or indefinite
/// (8.1.3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Length {
    /// Definite length of the contents octets.
    Definite(usize),
    /// Indefinite form: the contents end with an end-of-contents element.
    Indefinite,
}

/// One element with a definite length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// Identifier.
    pub tag: Tag,
    /// Size of the identifier and length octets.
    pub header_len: usize,
    /// Contents octets.
    pub value: &'a [u8],
}

impl Tlv<'_> {
    /// Total encoded size (identifier, length and contents octets).
    pub fn encoded_len(&self) -> usize {
        self.header_len + self.value.len()
    }
}

fn truncated(expected: usize, actual: usize) -> PacketError {
    PacketError::Truncated { expected, actual }
}

/// Read the identifier octets at the start of `data`; returns the tag and
/// the number of identifier octets.
///
/// X.690, 8.1.2.4: tag numbers of 31 and above use the high-tag-number
/// form, bits 5 to 1 of the first octet set to one followed by base-128
/// subsequent octets, bit 8 set on all but the last.
pub fn read_tag(data: &[u8]) -> Result<(Tag, usize), PacketError> {
    let first = *data.first().ok_or(truncated(1, data.len()))?;
    let class = match first >> 6 {
        0 => TagClass::Universal,
        1 => TagClass::Application,
        2 => TagClass::ContextSpecific,
        _ => TagClass::Private,
    };
    let constructed = first & 0x20 != 0;
    let mut number = u32::from(first & 0x1f);
    let mut len = 1;
    if number == 0x1f {
        number = 0;
        loop {
            let octet = *data.get(len).ok_or(truncated(len + 1, data.len()))?;
            len += 1;
            if number > (u32::MAX >> 7) {
                return Err(PacketError::InvalidHeader("BER tag number too large"));
            }
            number = (number << 7) | u32::from(octet & 0x7f);
            if octet & 0x80 == 0 {
                break;
            }
        }
    }
    Ok((
        Tag {
            class,
            constructed,
            number,
        },
        len,
    ))
}

/// Read the length octets at the start of `data`; returns the length and
/// the number of length octets.
///
/// X.690, 8.1.3.4 (short form, one octet with bit 8 zero), 8.1.3.5 (long
/// form, an initial octet giving the number of subsequent octets; the value
/// 0xFF shall not be used) and 8.1.3.6 (indefinite form, the single octet
/// 0x80).
pub fn read_length(data: &[u8]) -> Result<(Length, usize), PacketError> {
    let first = *data.first().ok_or(truncated(1, data.len()))?;
    match first {
        0x00..=0x7f => Ok((Length::Definite(usize::from(first)), 1)),
        0x80 => Ok((Length::Indefinite, 1)),
        0xff => Err(PacketError::InvalidHeader(
            "BER length octet 0xFF is reserved",
        )),
        _ => {
            let count = usize::from(first & 0x7f);
            let octets = data
                .get(1..1 + count)
                .ok_or(truncated(1 + count, data.len()))?;
            let mut length: usize = 0;
            for &octet in octets {
                if length > (usize::MAX >> 8) {
                    return Err(PacketError::InvalidHeader("BER length too large"));
                }
                length = (length << 8) | usize::from(octet);
            }
            Ok((Length::Definite(length), 1 + count))
        }
    }
}

/// Read one element with a definite length at the start of `data`.
///
/// Fails with [`PacketError::Truncated`] (relative to `data`) when the
/// element does not fit, and with [`PacketError::InvalidHeader`] for an
/// indefinite length or a malformed identifier / length.
pub fn read_tlv(data: &[u8]) -> Result<Tlv<'_>, PacketError> {
    let (tag, tag_len) = read_tag(data)?;
    let (length, length_len) = match read_length(&data[tag_len..]) {
        Ok(l) => l,
        Err(PacketError::Truncated { expected, .. }) => {
            return Err(truncated(tag_len + expected, data.len()));
        }
        Err(e) => return Err(e),
    };
    let Length::Definite(length) = length else {
        return Err(PacketError::InvalidHeader(
            "BER indefinite length not supported",
        ));
    };
    let header_len = tag_len + length_len;
    let end = header_len
        .checked_add(length)
        .ok_or(PacketError::InvalidHeader("BER length too large"))?;
    let value = data
        .get(header_len..end)
        .ok_or(truncated(end, data.len()))?;
    Ok(Tlv {
        tag,
        header_len,
        value,
    })
}

/// Iterator over consecutive definite-length elements, e.g. the contents of
/// a constructed element. Yields `(offset, element)` pairs, where `offset`
/// is relative to the iterated slice. Stops after the first error.
#[derive(Debug, Clone)]
pub struct TlvIter<'a> {
    data: &'a [u8],
    pos: usize,
    failed: bool,
}

impl<'a> TlvIter<'a> {
    /// Iterate over the elements of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            failed: false,
        }
    }

    /// Offset of the next element in the iterated slice (its length once
    /// every element has been read).
    pub fn offset(&self) -> usize {
        self.pos
    }
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Result<(usize, Tlv<'a>), PacketError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.pos >= self.data.len() {
            return None;
        }
        match read_tlv(&self.data[self.pos..]) {
            Ok(tlv) => {
                let offset = self.pos;
                self.pos += tlv.encoded_len();
                Some(Ok((offset, tlv)))
            }
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # ITU-T X.690 Coverage
    //
    // | Clause    | Description                                  | Test                              |
    // |-----------|----------------------------------------------|-----------------------------------|
    // | 8.1.2.2   | Tag class bits                               | tag_classes_and_constructed       |
    // | 8.1.2.5   | Primitive / constructed bit                  | tag_classes_and_constructed       |
    // | 8.1.2.4   | High-tag-number form                         | high_tag_number_form              |
    // | 8.1.2.4   | High-tag-number truncated / overflow         | high_tag_number_errors            |
    // | 8.1.3.4   | Short definite length                        | short_and_long_lengths            |
    // | 8.1.3.5   | Long definite length (incl. non-minimal)     | short_and_long_lengths            |
    // | 8.1.3.5 c | Length octet 0xFF rejected                   | length_errors                     |
    // | 8.1.3.6   | Indefinite length reported / rejected by TLV | indefinite_length                 |
    // | 8.1.3     | Contents beyond input (Truncated)            | tlv_truncated                     |
    // | 8.1.1     | Consecutive elements                         | iterate_elements                  |

    #[test]
    fn tag_classes_and_constructed() {
        assert_eq!(
            read_tag(&[0x30]).unwrap(),
            (
                Tag {
                    class: TagClass::Universal,
                    constructed: true,
                    number: 16
                },
                1
            )
        );
        let (t, _) = read_tag(&[0x41]).unwrap();
        assert_eq!(
            (t.class, t.constructed, t.number),
            (TagClass::Application, false, 1)
        );
        let (t, _) = read_tag(&[0xa2]).unwrap();
        assert_eq!(
            (t.class, t.constructed, t.number),
            (TagClass::ContextSpecific, true, 2)
        );
        let (t, _) = read_tag(&[0xc5]).unwrap();
        assert_eq!(t.class, TagClass::Private);
        assert!(
            Tag {
                class: TagClass::Universal,
                constructed: false,
                number: Tag::INTEGER
            }
            .is_universal(Tag::INTEGER)
        );
        assert!(!t.is_universal(5));
        assert_eq!(
            read_tag(&[]),
            Err(PacketError::Truncated {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn high_tag_number_form() {
        // [APPLICATION 31] and [CONTEXT 201] (0x81 0x49).
        assert_eq!(read_tag(&[0x5f, 0x1f]).unwrap().0.number, 31);
        let (t, n) = read_tag(&[0x9f, 0x81, 0x49]).unwrap();
        assert_eq!((t.number, n), (201, 3));
    }

    #[test]
    fn high_tag_number_errors() {
        assert_eq!(
            read_tag(&[0x9f, 0x81]),
            Err(PacketError::Truncated {
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(
            read_tag(&[0x9f, 0x90, 0x80, 0x80, 0x80, 0x80, 0x00]),
            Err(PacketError::InvalidHeader("BER tag number too large"))
        );
    }

    #[test]
    fn short_and_long_lengths() {
        assert_eq!(read_length(&[0x05]).unwrap(), (Length::Definite(5), 1));
        assert_eq!(
            read_length(&[0x82, 0x01, 0x00]).unwrap(),
            (Length::Definite(256), 3)
        );
        // RFC 3417, Section 8 —
        // <https://www.rfc-editor.org/rfc/rfc3417#section-8>: "when using the
        // definite-long form, it is permissible to use more than the minimum
        // number of length octets necessary to encode the length field."
        assert_eq!(
            read_length(&[0x84, 0, 0, 0, 3]).unwrap(),
            (Length::Definite(3), 5)
        );
    }

    #[test]
    fn length_errors() {
        assert_eq!(
            read_length(&[]),
            Err(PacketError::Truncated {
                expected: 1,
                actual: 0
            })
        );
        assert_eq!(
            read_length(&[0x82, 0x01]),
            Err(PacketError::Truncated {
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(
            read_length(&[0xff]),
            Err(PacketError::InvalidHeader(
                "BER length octet 0xFF is reserved"
            ))
        );
        assert_eq!(
            read_length(&[0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(PacketError::InvalidHeader("BER length too large"))
        );
    }

    #[test]
    fn indefinite_length() {
        assert_eq!(read_length(&[0x80]).unwrap(), (Length::Indefinite, 1));
        assert_eq!(
            read_tlv(&[0x30, 0x80, 0x00, 0x00]),
            Err(PacketError::InvalidHeader(
                "BER indefinite length not supported"
            ))
        );
    }

    #[test]
    fn tlv_and_truncation() {
        let tlv = read_tlv(&[0x02, 0x01, 0x05, 0xff]).unwrap();
        assert_eq!(tlv.tag.number, 2);
        assert_eq!(tlv.header_len, 2);
        assert_eq!(tlv.value, &[0x05]);
        assert_eq!(tlv.encoded_len(), 3);
    }

    #[test]
    fn tlv_truncated() {
        assert_eq!(
            read_tlv(&[0x04, 0x05, 1, 2]),
            Err(PacketError::Truncated {
                expected: 7,
                actual: 4
            })
        );
        assert_eq!(
            read_tlv(&[0x04]),
            Err(PacketError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn iterate_elements() {
        let data = [0x02, 0x01, 0x07, 0x05, 0x00, 0x04, 0x02, b'h', b'i'];
        let items: Vec<_> = TlvIter::new(&data).map(|r| r.unwrap()).collect();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].0, 0);
        assert_eq!(items[1].0, 3);
        assert!(items[1].1.tag.is_universal(Tag::NULL));
        assert_eq!(items[2].0, 5);
        assert_eq!(items[2].1.value, b"hi");

        let bad = [0x02, 0x01, 0x07, 0x04, 0x05, 0x00];
        let mut it = TlvIter::new(&bad);
        assert_eq!(it.offset(), 0);
        assert!(it.next().unwrap().is_ok());
        assert_eq!(it.offset(), 3);
        assert!(it.next().unwrap().is_err());
        assert!(it.next().is_none());
        assert!(TlvIter::new(&[]).next().is_none());
    }
}
