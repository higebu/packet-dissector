//! Bounds-checked reader for TLS presentation-language structures.
//!
//! ## References
//! - RFC 9846, Section 3 (Presentation Language): <https://www.rfc-editor.org/rfc/rfc9846#section-3>
//! - RFC 9000, Section 16 (Variable-Length Integer Encoding): <https://www.rfc-editor.org/rfc/rfc9000#section-16>

use core::ops::Range;

/// Bytes read from the packet together with their packet byte range.
pub(crate) type Span<'pkt> = (&'pkt [u8], Range<usize>);

/// A cursor over a byte slice that also tracks the absolute packet offset of
/// each byte, so decoded fields can carry their byte range.
///
/// Every read either succeeds and advances, or fails and leaves the reader
/// unchanged. The reader is `Copy`, so a trial parse can run on a copy.
#[derive(Clone, Copy)]
pub(crate) struct Reader<'pkt> {
    data: &'pkt [u8],
    pos: usize,
    base: usize,
}

impl<'pkt> Reader<'pkt> {
    /// Create a reader over `data`, whose first byte is at packet offset `base`.
    pub(crate) fn new(data: &'pkt [u8], base: usize) -> Self {
        Self { data, pos: 0, base }
    }

    /// Whether all bytes have been read.
    pub(crate) fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }

    /// Number of unread bytes.
    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Packet offset of the next unread byte.
    pub(crate) fn offset(&self) -> usize {
        self.base + self.pos
    }

    /// Read `n` bytes; returns them with their packet byte range.
    pub(crate) fn bytes(&mut self, n: usize) -> Option<Span<'pkt>> {
        let end = self.pos.checked_add(n)?;
        let slice = self.data.get(self.pos..end)?;
        let range = self.base + self.pos..self.base + end;
        self.pos = end;
        Some((slice, range))
    }

    /// Read a big-endian unsigned integer of `n` (1..=4) bytes.
    pub(crate) fn uint(&mut self, n: usize) -> Option<u32> {
        let (b, _) = self.bytes(n)?;
        Some(b.iter().fold(0u32, |acc, &x| (acc << 8) | u32::from(x)))
    }

    /// Read a `uint8`.
    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|(b, _)| b[0])
    }

    /// Read a `uint16`.
    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|(b, _)| u16::from_be_bytes([b[0], b[1]]))
    }

    /// Read a `uint32`.
    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.uint(4)
    }

    /// Read a variable-length vector whose length prefix is `len_size`
    /// bytes (RFC 9846, Section 3.4 —
    /// <https://www.rfc-editor.org/rfc/rfc9846#section-3.4>). Returns the
    /// vector contents (without the prefix) and their packet byte range.
    pub(crate) fn vector(&mut self, len_size: usize) -> Option<Span<'pkt>> {
        let mut r = *self;
        let len = r.uint(len_size)? as usize;
        let out = r.bytes(len)?;
        *self = r;
        Some(out)
    }

    /// Read a QUIC variable-length integer.
    ///
    /// RFC 9000, Section 16 — <https://www.rfc-editor.org/rfc/rfc9000#section-16>
    pub(crate) fn varint(&mut self) -> Option<u64> {
        let first = *self.data.get(self.pos)?;
        let len = 1usize << (first >> 6);
        let (b, _) = self.bytes(len)?;
        let mut v = u64::from(b[0] & 0x3f);
        for &x in &b[1..] {
            v = (v << 8) | u64::from(x);
        }
        Some(v)
    }
}

/// Whether `data` is exactly one vector with a `len_size`-byte length
/// prefix; returns its contents and packet range.
pub(crate) fn whole_vector(
    data: &[u8],
    base: usize,
    len_size: usize,
) -> Option<(&[u8], Range<usize>)> {
    let mut r = Reader::new(data, base);
    let v = r.vector(len_size)?;
    r.is_empty().then_some(v)
}

/// Whether `data` is a sequence of vectors, each with a `len_size`-byte
/// length prefix and at least `min_len` bytes of content, that exactly
/// fills `data`.
pub(crate) fn vectors_tile(data: &[u8], len_size: usize, min_len: usize) -> bool {
    let mut r = Reader::new(data, 0);
    while !r.is_empty() {
        match r.vector(len_size) {
            Some((v, _)) if v.len() >= min_len => {}
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_reads_and_tracks_offsets() {
        let data = [0x01, 0x00, 0x02, 0xaa, 0xbb, 0x00, 0x00, 0x00, 0x05];
        let mut r = Reader::new(&data, 100);
        assert_eq!(r.u8(), Some(1));
        assert_eq!(r.offset(), 101);
        let (v, range) = r.vector(2).unwrap();
        assert_eq!(v, &[0xaa, 0xbb]);
        assert_eq!(range, 103..105);
        assert_eq!(r.u32(), Some(5));
        assert!(r.is_empty());
        assert_eq!(r.remaining(), 0);
        assert_eq!(r.u8(), None);
        assert_eq!(r.u16(), None);
    }

    #[test]
    fn reader_failed_read_does_not_advance() {
        let data = [0x00, 0x05, 0x01];
        let mut r = Reader::new(&data, 0);
        assert!(r.vector(2).is_none());
        assert_eq!(r.remaining(), 3);
        assert!(r.bytes(usize::MAX).is_none());
        assert_eq!(r.u16(), Some(5));
    }

    #[test]
    fn reader_varint() {
        // RFC 9000, Appendix A.1 — https://www.rfc-editor.org/rfc/rfc9000#appendix-A.1
        for (bytes, value) in [
            (&[0x25][..], 37u64),
            (&[0x7b, 0xbd], 15293),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
        ] {
            let mut r = Reader::new(bytes, 0);
            assert_eq!(r.varint(), Some(value));
            assert!(r.is_empty());
        }
        let mut r = Reader::new(&[0x40], 0);
        assert_eq!(r.varint(), None);
        assert_eq!(r.remaining(), 1);
    }

    #[test]
    fn whole_vector_and_tiling() {
        assert_eq!(whole_vector(&[0x02, 1, 2], 10, 1).unwrap().1, 11..13);
        assert!(whole_vector(&[0x02, 1, 2, 3], 0, 1).is_none());
        assert!(vectors_tile(&[0x01, 9, 0x02, 1, 2], 1, 1));
        assert!(!vectors_tile(&[0x01, 9, 0x00], 1, 1));
        assert!(!vectors_tile(&[0x01, 9, 0x03, 1], 1, 1));
        assert!(vectors_tile(&[], 2, 1));
    }
}
