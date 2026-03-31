//! Reassembly table for managing multiple concurrent reassembly sessions.

use std::collections::HashMap;
use std::hash::Hash;

use crate::buffer::ReassemblyBuffer;

/// Configuration for a [`ReassemblyTable`].
#[derive(Debug, Clone, Default)]
pub struct ReassemblyConfig {
    /// Maximum number of concurrent reassembly entries.
    ///
    /// When the limit is reached, new entries are rejected with
    /// [`ReassemblyError::TableFull`]. `None` means no limit.
    pub max_entries: Option<usize>,

    /// Maximum buffer size in bytes for a single reassembly entry.
    ///
    /// Insertions that would grow a buffer beyond this limit are rejected
    /// with [`ReassemblyError::BufferLimitExceeded`]. `None` means no limit.
    pub max_buffer_bytes: Option<usize>,
}

/// Errors that can occur during reassembly operations.
#[derive(Debug, thiserror::Error)]
pub enum ReassemblyError {
    /// A single buffer would exceed the configured byte limit.
    #[error("buffer limit exceeded: requested {requested} bytes, limit is {limit} bytes")]
    BufferLimitExceeded {
        /// The configured limit.
        limit: usize,
        /// The size that would result from the insertion.
        requested: usize,
    },

    /// The table is full (reached `max_entries`).
    #[error("reassembly table full: max {max_entries} entries")]
    TableFull {
        /// The configured maximum number of entries.
        max_entries: usize,
    },

    /// An arithmetic overflow occurred when computing the end offset.
    #[error("offset overflow: offset + length exceeds usize")]
    OffsetOverflow,
}

impl ReassemblyError {
    /// Returns the configured limit if this is a `BufferLimitExceeded` error.
    pub fn limit(&self) -> Option<usize> {
        match self {
            Self::BufferLimitExceeded { limit, .. } => Some(*limit),
            _ => None,
        }
    }

    /// Returns the requested size if this is a `BufferLimitExceeded` error.
    pub fn requested(&self) -> Option<usize> {
        match self {
            Self::BufferLimitExceeded { requested, .. } => Some(*requested),
            _ => None,
        }
    }

    /// Returns the max entries if this is a `TableFull` error.
    pub fn max_entries(&self) -> Option<usize> {
        match self {
            Self::TableFull { max_entries } => Some(*max_entries),
            _ => None,
        }
    }
}

/// A table that manages multiple concurrent reassembly sessions.
///
/// Each session is identified by a caller-defined key type `K` (e.g., a
/// tuple of IP addresses and fragment ID for IP reassembly, or a TCP
/// 4-tuple for stream reassembly).
///
/// # Type Parameters
///
/// - `K`: The key type used to identify reassembly sessions. Must implement
///   `Hash + Eq`.
///
/// # Examples
///
/// ```
/// use packet_dissector_reassembly::{ReassemblyTable, ReassemblyConfig};
///
/// // IP fragment reassembly keyed by (src, dst, protocol, id)
/// let mut table: ReassemblyTable<(u32, u32, u8, u16)> = ReassemblyTable::new();
///
/// let key = (0x0A000001, 0x0A000002, 6, 0x1234);
/// table.insert(key, 0, &[1, 2, 3, 4]).unwrap();
/// assert_eq!(table.get(&key).unwrap().contiguous_len(), 4);
/// ```
pub struct ReassemblyTable<K> {
    entries: HashMap<K, ReassemblyEntry>,
    config: ReassemblyConfig,
}

struct ReassemblyEntry {
    buffer: ReassemblyBuffer,
    fragment_count: u32,
}

impl<K: Hash + Eq> ReassemblyTable<K> {
    /// Create a new reassembly table with default (unlimited) configuration.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            config: ReassemblyConfig::default(),
        }
    }

    /// Create a new reassembly table with the given configuration.
    pub fn with_config(config: ReassemblyConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
        }
    }

    /// Insert data at the given offset for the specified reassembly key.
    ///
    /// If no entry exists for the key, a new one is created. Returns a
    /// reference to the updated buffer.
    ///
    /// # Errors
    ///
    /// - [`ReassemblyError::TableFull`] if the table is at capacity and the
    ///   key is new.
    /// - [`ReassemblyError::BufferLimitExceeded`] if the insertion would grow
    ///   the buffer beyond `max_buffer_bytes`.
    pub fn insert(
        &mut self,
        key: K,
        offset: usize,
        data: &[u8],
    ) -> Result<&ReassemblyBuffer, ReassemblyError> {
        let is_new = !self.entries.contains_key(&key);

        // Check table capacity for new entries
        if is_new {
            if let Some(max) = self.config.max_entries {
                if self.entries.len() >= max {
                    return Err(ReassemblyError::TableFull { max_entries: max });
                }
            }
        }

        // Check for offset overflow
        let new_end = offset
            .checked_add(data.len())
            .ok_or(ReassemblyError::OffsetOverflow)?;

        // Check buffer size limit
        if let Some(max_bytes) = self.config.max_buffer_bytes {
            let current_len = self
                .entries
                .get(&key)
                .map(|e| e.buffer.data().len())
                .unwrap_or(0);
            let required = new_end.max(current_len);
            if required > max_bytes {
                return Err(ReassemblyError::BufferLimitExceeded {
                    limit: max_bytes,
                    requested: required,
                });
            }
        }

        let entry = self.entries.entry(key).or_insert_with(|| ReassemblyEntry {
            buffer: ReassemblyBuffer::new(),
            fragment_count: 0,
        });
        // insert won't fail here since we already validated the offset above
        entry.buffer.insert(offset, data);
        entry.fragment_count += 1;

        Ok(&entry.buffer)
    }

    /// Set the expected total length for the specified reassembly key.
    ///
    /// This is typically called when the final fragment arrives (e.g., an IP
    /// fragment with MF=0).
    ///
    /// Returns `false` if no entry exists for the key.
    pub fn set_total_len(&mut self, key: &K, len: usize) -> bool {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.buffer.set_total_len(len);
            true
        } else {
            false
        }
    }

    /// Look up the reassembly buffer for the given key.
    pub fn get(&self, key: &K) -> Option<&ReassemblyBuffer> {
        self.entries.get(key).map(|e| &e.buffer)
    }

    /// Remove and return the reassembly buffer for the given key.
    pub fn remove(&mut self, key: &K) -> Option<ReassemblyBuffer> {
        self.entries.remove(key).map(|e| e.buffer)
    }

    /// Returns `true` if the reassembly for the given key is complete.
    pub fn is_complete(&self, key: &K) -> bool {
        self.entries
            .get(key)
            .is_some_and(|e| e.buffer.is_complete())
    }

    /// Returns the number of active reassembly entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove all entries from the table.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the number of fragments received for the given key.
    pub fn fragment_count(&self, key: &K) -> Option<u32> {
        self.entries.get(key).map(|e| e.fragment_count)
    }
}

impl<K: Hash + Eq> Default for ReassemblyTable<K> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestKey = (u32, u32, u16); // (src, dst, id)

    fn key1() -> TestKey {
        (1, 2, 100)
    }

    fn key2() -> TestKey {
        (3, 4, 200)
    }

    #[test]
    fn new_table_is_empty() {
        let table: ReassemblyTable<TestKey> = ReassemblyTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn insert_and_get() {
        let mut table: ReassemblyTable<TestKey> = ReassemblyTable::new();
        table.insert(key1(), 0, &[1, 2, 3]).unwrap();

        let buf = table.get(&key1()).unwrap();
        assert_eq!(buf.contiguous_len(), 3);
        assert_eq!(buf.data(), &[1, 2, 3]);
    }

    #[test]
    fn multiple_inserts_same_key() {
        let mut table: ReassemblyTable<TestKey> = ReassemblyTable::new();
        table.insert(key1(), 0, &[1, 2]).unwrap();
        table.insert(key1(), 2, &[3, 4]).unwrap();

        let buf = table.get(&key1()).unwrap();
        assert_eq!(buf.contiguous_len(), 4);
        assert_eq!(table.fragment_count(&key1()), Some(2));
    }

    #[test]
    fn independent_keys() {
        let mut table: ReassemblyTable<TestKey> = ReassemblyTable::new();
        table.insert(key1(), 0, &[1, 2]).unwrap();
        table.insert(key2(), 0, &[0xAA, 0xBB]).unwrap();

        assert_eq!(table.len(), 2);
        assert_eq!(table.get(&key1()).unwrap().data(), &[1, 2]);
        assert_eq!(table.get(&key2()).unwrap().data(), &[0xAA, 0xBB]);
    }

    #[test]
    fn remove_returns_buffer() {
        let mut table: ReassemblyTable<TestKey> = ReassemblyTable::new();
        table.insert(key1(), 0, &[1, 2, 3]).unwrap();

        let buf = table.remove(&key1()).unwrap();
        assert_eq!(buf.data(), &[1, 2, 3]);
        assert!(table.is_empty());
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut table: ReassemblyTable<TestKey> = ReassemblyTable::new();
        assert!(table.remove(&key1()).is_none());
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let table: ReassemblyTable<TestKey> = ReassemblyTable::new();
        assert!(table.get(&key1()).is_none());
    }

    #[test]
    fn is_complete_delegates_to_buffer() {
        let mut table: ReassemblyTable<TestKey> = ReassemblyTable::new();
        table.insert(key1(), 0, &[1, 2, 3, 4]).unwrap();

        assert!(!table.is_complete(&key1()));

        table.set_total_len(&key1(), 4);
        assert!(table.is_complete(&key1()));
    }

    #[test]
    fn set_total_len_nonexistent_returns_false() {
        let mut table: ReassemblyTable<TestKey> = ReassemblyTable::new();
        assert!(!table.set_total_len(&key1(), 100));
    }

    #[test]
    fn clear_removes_all() {
        let mut table: ReassemblyTable<TestKey> = ReassemblyTable::new();
        table.insert(key1(), 0, &[1]).unwrap();
        table.insert(key2(), 0, &[2]).unwrap();
        assert_eq!(table.len(), 2);

        table.clear();
        assert!(table.is_empty());
    }

    #[test]
    fn max_entries_rejects_new_key() {
        let config = ReassemblyConfig {
            max_entries: Some(1),
            max_buffer_bytes: None,
        };
        let mut table: ReassemblyTable<TestKey> = ReassemblyTable::with_config(config);

        table.insert(key1(), 0, &[1]).unwrap();
        let err = table.insert(key2(), 0, &[2]).unwrap_err();
        assert!(matches!(err, ReassemblyError::TableFull { max_entries: 1 }));
    }

    #[test]
    fn max_entries_allows_existing_key() {
        let config = ReassemblyConfig {
            max_entries: Some(1),
            max_buffer_bytes: None,
        };
        let mut table: ReassemblyTable<TestKey> = ReassemblyTable::with_config(config);

        table.insert(key1(), 0, &[1]).unwrap();
        // Same key should still work
        table.insert(key1(), 1, &[2]).unwrap();
        assert_eq!(table.get(&key1()).unwrap().contiguous_len(), 2);
    }

    #[test]
    fn max_buffer_bytes_rejects_oversized() {
        let config = ReassemblyConfig {
            max_entries: None,
            max_buffer_bytes: Some(4),
        };
        let mut table: ReassemblyTable<TestKey> = ReassemblyTable::with_config(config);

        table.insert(key1(), 0, &[1, 2]).unwrap();
        let err = table.insert(key1(), 0, &[1, 2, 3, 4, 5]).unwrap_err();
        assert!(matches!(
            err,
            ReassemblyError::BufferLimitExceeded {
                limit: 4,
                requested: 5
            }
        ));
    }

    #[test]
    fn max_buffer_bytes_checks_end_offset() {
        let config = ReassemblyConfig {
            max_entries: None,
            max_buffer_bytes: Some(10),
        };
        let mut table: ReassemblyTable<TestKey> = ReassemblyTable::with_config(config);

        // offset 8 + 4 bytes = end at 12 > limit 10
        let err = table.insert(key1(), 8, &[1, 2, 3, 4]).unwrap_err();
        assert!(matches!(
            err,
            ReassemblyError::BufferLimitExceeded {
                limit: 10,
                requested: 12
            }
        ));
    }

    #[test]
    fn default_is_same_as_new() {
        let table: ReassemblyTable<TestKey> = ReassemblyTable::default();
        assert!(table.is_empty());
    }

    #[test]
    fn offset_overflow_returns_error() {
        let mut table: ReassemblyTable<TestKey> = ReassemblyTable::new();
        let err = table.insert(key1(), usize::MAX, &[1, 2]).unwrap_err();
        assert!(matches!(err, ReassemblyError::OffsetOverflow));
    }

    // --- Scenario tests ---

    #[test]
    fn ip_fragment_reassembly_scenario() {
        let mut table: ReassemblyTable<(u32, u32, u8, u16)> = ReassemblyTable::new();
        let key = (0x0A000001, 0x0A000002, 6u8, 0x1234u16);

        // Fragment 0: offset=0, len=8, MF=1
        table.insert(key, 0, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert!(!table.is_complete(&key));

        // Fragment 2: offset=16, len=4, MF=0 (last)
        table.insert(key, 16, &[17, 18, 19, 20]).unwrap();
        table.set_total_len(&key, 20); // offset + len = 16 + 4 = 20
        assert!(!table.is_complete(&key)); // still missing fragment 1

        // Fragment 1: offset=8, len=8, MF=1
        table
            .insert(key, 8, &[9, 10, 11, 12, 13, 14, 15, 16])
            .unwrap();
        assert!(table.is_complete(&key));

        let buf = table.remove(&key).unwrap();
        let expected: Vec<u8> = (1..=20).collect();
        assert_eq!(buf.data(), expected.as_slice());
    }

    #[test]
    fn tcp_stream_reassembly_scenario() {
        let mut table: ReassemblyTable<(u32, u32, u16, u16)> = ReassemblyTable::new();
        let key = (0x0A000001, 0x0A000002, 12345u16, 80u16);

        // SYN-ACK established, ISN = 1000
        let isn: u32 = 1000;

        // Segment 1: seq=1000, len=10
        table.insert(key, 0, &[0; 10]).unwrap();
        assert_eq!(table.get(&key).unwrap().contiguous_len(), 10);

        // Segment 3 arrives out of order: seq=1020, len=5
        table.insert(key, 20, &[0; 5]).unwrap();
        assert_eq!(table.get(&key).unwrap().contiguous_len(), 10); // gap at 10..20

        // Segment 2: seq=1010, len=10 (fills the gap)
        table.insert(key, (1010 - isn) as usize, &[0; 10]).unwrap();
        assert_eq!(table.get(&key).unwrap().contiguous_len(), 25);

        // Retransmission of segment 1 (duplicate)
        table.insert(key, 0, &[0; 10]).unwrap();
        assert_eq!(table.get(&key).unwrap().contiguous_len(), 25);
    }
}
