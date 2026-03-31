//! Offset-based reassembly buffer with gap tracking.

/// A byte buffer that accepts data at arbitrary offsets and tracks which
/// byte ranges have been filled.
///
/// `ReassemblyBuffer` is the core building block for both IP fragment
/// reassembly and TCP stream reassembly. It maintains a flat `Vec<u8>`
/// and a sorted list of filled byte ranges.
///
/// # Examples
///
/// ```
/// use packet_dissector_reassembly::ReassemblyBuffer;
///
/// let mut buf = ReassemblyBuffer::new();
/// buf.insert(0, &[0x48, 0x54, 0x54, 0x50]); // "HTTP"
/// assert_eq!(buf.contiguous_len(), 4);
/// ```
#[derive(Debug, Clone)]
pub struct ReassemblyBuffer {
    data: Vec<u8>,
    /// Sorted, non-overlapping list of filled byte ranges.
    filled: Vec<core::ops::Range<usize>>,
    total_len: Option<usize>,
}

impl ReassemblyBuffer {
    /// Create a new empty reassembly buffer.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            filled: Vec::new(),
            total_len: None,
        }
    }

    /// Insert data at the given byte offset.
    ///
    /// If the data overlaps with previously inserted data, the new data
    /// overwrites the existing bytes in the overlapping region.
    ///
    /// The buffer automatically grows to accommodate data at any offset.
    ///
    /// Returns `None` if `offset + data.len()` overflows `usize`.
    pub fn insert(&mut self, offset: usize, data: &[u8]) -> Option<()> {
        if data.is_empty() {
            return Some(());
        }

        let end = offset.checked_add(data.len())?;

        // Grow backing storage if needed
        if end > self.data.len() {
            self.data.resize(end, 0);
        }

        // Copy data into buffer
        self.data[offset..end].copy_from_slice(data);

        // Merge the new range into the filled list
        self.merge_range(offset..end);
        Some(())
    }

    /// Set the expected total byte count for this reassembly.
    ///
    /// For IP fragment reassembly, this is called when the final fragment
    /// (with MF=0) arrives, using `fragment_offset + fragment_length` as
    /// the total length.
    pub fn set_total_len(&mut self, len: usize) {
        self.total_len = Some(len);
    }

    /// Returns the expected total byte count, if set.
    pub fn total_len(&self) -> Option<usize> {
        self.total_len
    }

    /// Returns `true` if the total length has been set and all bytes from
    /// `0..total_len` have been received.
    ///
    /// When total length is 0, this returns `true` (vacuously complete).
    pub fn is_complete(&self) -> bool {
        let Some(total) = self.total_len else {
            return false;
        };

        if total == 0 {
            return true;
        }

        // Check that there is exactly one filled range covering 0..total
        self.filled.len() == 1 && self.filled[0].start == 0 && self.filled[0].end >= total
    }

    /// Returns the number of contiguous bytes available from offset 0.
    ///
    /// This is useful for TCP stream reassembly where the caller needs to
    /// know how much data can be consumed from the start of the stream.
    pub fn contiguous_len(&self) -> usize {
        match self.filled.first() {
            Some(range) if range.start == 0 => range.end,
            _ => 0,
        }
    }

    /// Returns a reference to the underlying byte buffer.
    ///
    /// Note: bytes in unfilled gaps contain unspecified values (zero from
    /// initial allocation, but this is not guaranteed after future changes).
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consume the buffer and return the underlying byte vector.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Returns the total number of bytes that have been received
    /// (counting each byte position only once, even if overwritten).
    pub fn bytes_received(&self) -> usize {
        self.filled.iter().map(|r| r.end - r.start).sum()
    }

    /// Remove the first `n` contiguous bytes from the buffer, shifting
    /// remaining data and filled ranges forward.
    ///
    /// This is used for TCP stream reassembly where parsed messages are
    /// consumed from the front of the buffer while retaining unparsed data.
    ///
    /// # Panics
    ///
    /// Panics if `n > contiguous_len()` — consuming beyond the contiguous
    /// region would cross a gap, which is a programming error.
    pub fn consume(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        assert!(
            n <= self.contiguous_len(),
            "cannot consume {n} bytes: only {} contiguous bytes available",
            self.contiguous_len()
        );

        // Remove the first n bytes from the data vector
        self.data.drain(..n);

        // Shift all filled ranges down by n and remove any that are fully consumed
        let mut new_filled = Vec::with_capacity(self.filled.len());
        for range in &self.filled {
            if range.end <= n {
                // Fully consumed — skip
                continue;
            }
            let start = range.start.saturating_sub(n);
            let end = range.end - n;
            new_filled.push(start..end);
        }
        self.filled = new_filled;

        // Keep total_len consistent with the new coordinate space so that
        // is_complete() remains correct after consuming bytes.
        if let Some(tl) = self.total_len {
            self.total_len = Some(tl.saturating_sub(n));
        }
    }

    /// Merge a new range into the sorted `filled` list, coalescing any
    /// overlapping or adjacent ranges.
    fn merge_range(&mut self, new: core::ops::Range<usize>) {
        // Find the first filled range that could overlap or be adjacent
        // (its end >= new.start)
        let start_idx = self.filled.partition_point(|r| r.end < new.start);

        // Find the last filled range that overlaps or is adjacent
        // (its start <= new.end)
        let end_idx = self.filled[start_idx..].partition_point(|r| r.start <= new.end) + start_idx;

        if start_idx == end_idx {
            // No overlap — insert new range
            self.filled.insert(start_idx, new);
        } else {
            // Merge with overlapping ranges
            let merged_start = self.filled[start_idx].start.min(new.start);
            let merged_end = self.filled[end_idx - 1].end.max(new.end);
            self.filled[start_idx] = merged_start..merged_end;
            if end_idx - start_idx > 1 {
                self.filled.drain((start_idx + 1)..end_idx);
            }
        }
    }
}

impl Default for ReassemblyBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_buffer_is_empty() {
        let buf = ReassemblyBuffer::new();
        assert_eq!(buf.contiguous_len(), 0);
        assert_eq!(buf.bytes_received(), 0);
        assert!(!buf.is_complete());
        assert!(buf.data().is_empty());
        assert_eq!(buf.total_len(), None);
    }

    #[test]
    fn insert_at_zero() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2, 3, 4]);
        assert_eq!(buf.contiguous_len(), 4);
        assert_eq!(buf.bytes_received(), 4);
        assert_eq!(buf.data(), &[1, 2, 3, 4]);
    }

    #[test]
    fn insert_empty_data_is_noop() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[]);
        assert_eq!(buf.contiguous_len(), 0);
        assert_eq!(buf.bytes_received(), 0);
    }

    #[test]
    fn insert_at_nonzero_offset_creates_gap() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(10, &[0xAA, 0xBB]);
        assert_eq!(buf.contiguous_len(), 0); // gap at 0..10
        assert_eq!(buf.bytes_received(), 2);
        assert_eq!(buf.data()[10], 0xAA);
        assert_eq!(buf.data()[11], 0xBB);
    }

    #[test]
    fn fill_gap_updates_contiguous_len() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(4, &[5, 6, 7, 8]);
        assert_eq!(buf.contiguous_len(), 0);

        buf.insert(0, &[1, 2, 3, 4]);
        assert_eq!(buf.contiguous_len(), 8);
        assert_eq!(buf.data(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn overlapping_insert_overwrites() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2, 3, 4]);
        buf.insert(2, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(buf.contiguous_len(), 5);
        assert_eq!(buf.data(), &[1, 2, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn complete_when_total_len_set_and_all_filled() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2, 3, 4]);
        assert!(!buf.is_complete());

        buf.set_total_len(4);
        assert!(buf.is_complete());
    }

    #[test]
    fn not_complete_with_gaps() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2]);
        buf.insert(4, &[5, 6]);
        buf.set_total_len(6);
        assert!(!buf.is_complete());

        // Fill the gap
        buf.insert(2, &[3, 4]);
        assert!(buf.is_complete());
    }

    #[test]
    fn not_complete_without_total_len() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2, 3, 4]);
        assert!(!buf.is_complete());
    }

    #[test]
    fn three_fragments_out_of_order() {
        let mut buf = ReassemblyBuffer::new();

        // Fragment 2: offset=8, data=[9..16]
        buf.insert(8, &[9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(buf.contiguous_len(), 0);

        // Fragment 0: offset=0, data=[1..8]
        buf.insert(0, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(buf.contiguous_len(), 16);

        // Fragment 1 (last, MF=0): offset=16, data=[17..20]
        buf.insert(16, &[17, 18, 19, 20]);
        buf.set_total_len(20);

        assert!(buf.is_complete());
        assert_eq!(buf.bytes_received(), 20);
        let expected: Vec<u8> = (1..=20).collect();
        assert_eq!(buf.data(), expected.as_slice());
    }

    #[test]
    fn duplicate_insert_same_offset() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2, 3]);
        buf.insert(0, &[4, 5, 6]);
        assert_eq!(buf.contiguous_len(), 3);
        assert_eq!(buf.bytes_received(), 3);
        // New data overwrites
        assert_eq!(buf.data(), &[4, 5, 6]);
    }

    #[test]
    fn adjacent_ranges_merge() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2]);
        buf.insert(2, &[3, 4]);
        buf.insert(4, &[5, 6]);
        assert_eq!(buf.contiguous_len(), 6);
        assert_eq!(buf.bytes_received(), 6);
    }

    #[test]
    fn into_data_returns_owned() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[0xDE, 0xAD]);
        let owned = buf.into_data();
        assert_eq!(owned, vec![0xDE, 0xAD]);
    }

    #[test]
    fn default_is_same_as_new() {
        let buf = ReassemblyBuffer::default();
        assert_eq!(buf.contiguous_len(), 0);
        assert!(buf.data().is_empty());
    }

    #[test]
    fn many_gaps_then_fill_all() {
        let mut buf = ReassemblyBuffer::new();
        // Insert at offsets 0, 4, 8, 12 (each 2 bytes, leaving 2-byte gaps)
        buf.insert(0, &[1, 2]);
        buf.insert(4, &[5, 6]);
        buf.insert(8, &[9, 10]);
        buf.insert(12, &[13, 14]);

        assert_eq!(buf.contiguous_len(), 2);

        // Fill all gaps
        buf.insert(2, &[3, 4]);
        buf.insert(6, &[7, 8]);
        buf.insert(10, &[11, 12]);

        assert_eq!(buf.contiguous_len(), 14);
        buf.set_total_len(14);
        assert!(buf.is_complete());
    }

    #[test]
    fn large_overlap_spanning_multiple_ranges() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2]);
        buf.insert(6, &[7, 8]);
        buf.insert(12, &[13, 14]);

        // Now insert a large chunk that spans all gaps
        buf.insert(0, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
        assert_eq!(buf.contiguous_len(), 14);
        assert_eq!(buf.bytes_received(), 14);
    }

    #[test]
    fn insert_overflow_returns_none() {
        let mut buf = ReassemblyBuffer::new();
        assert_eq!(buf.insert(usize::MAX, &[1, 2]), None);
        assert_eq!(buf.insert(usize::MAX - 1, &[1, 2, 3]), None);
        // Buffer should be unchanged
        assert_eq!(buf.bytes_received(), 0);
    }

    #[test]
    fn zero_length_reassembly_is_complete() {
        let mut buf = ReassemblyBuffer::new();
        buf.set_total_len(0);
        assert!(buf.is_complete());
    }

    #[test]
    fn consume_removes_front_bytes() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2, 3, 4, 5, 6]);
        buf.consume(3);
        assert_eq!(buf.contiguous_len(), 3);
        assert_eq!(buf.data(), &[4, 5, 6]);
    }

    #[test]
    fn consume_all_bytes() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2, 3]);
        buf.consume(3);
        assert_eq!(buf.contiguous_len(), 0);
        assert!(buf.data().is_empty());
        assert_eq!(buf.bytes_received(), 0);
    }

    #[test]
    fn consume_zero_is_noop() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2, 3]);
        buf.consume(0);
        assert_eq!(buf.contiguous_len(), 3);
        assert_eq!(buf.data(), &[1, 2, 3]);
    }

    #[test]
    fn consume_with_trailing_gap() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2, 3, 4]);
        buf.insert(8, &[9, 10]); // gap at 4..8
        assert_eq!(buf.contiguous_len(), 4);
        buf.consume(2);
        assert_eq!(buf.contiguous_len(), 2);
        assert_eq!(&buf.data()[..2], &[3, 4]);
        // The gap should now be at offset 2..6 (shifted down by 2)
        buf.insert(2, &[5, 6, 7, 8]);
        assert_eq!(buf.contiguous_len(), 8);
    }

    #[test]
    #[should_panic(expected = "cannot consume")]
    fn consume_beyond_contiguous_panics() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2]);
        buf.insert(4, &[5, 6]); // gap at 2..4
        buf.consume(3); // only 2 contiguous bytes
    }

    #[test]
    fn consume_then_insert_works() {
        let mut buf = ReassemblyBuffer::new();
        buf.insert(0, &[1, 2, 3, 4]);
        buf.consume(2);
        buf.insert(2, &[7, 8]); // insert at new end
        assert_eq!(buf.contiguous_len(), 4);
        assert_eq!(buf.data(), &[3, 4, 7, 8]);
    }
}
