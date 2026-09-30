//! HPACK dynamic table (RFC 7541, Section 2.3.2 and Section 4).
//!
//! ## References
//! - RFC 7541, Section 2.3.2: <https://www.rfc-editor.org/rfc/rfc7541#section-2.3.2>
//! - RFC 7541, Section 4: <https://www.rfc-editor.org/rfc/rfc7541#section-4>

use std::collections::VecDeque;

/// Per-entry overhead added to the name and value lengths.
///
/// RFC 7541, Section 4.1 — "The size of an entry is the sum of its name's
/// length in octets (as defined in Section 5.2), its value's length in
/// octets, and 32." — <https://www.rfc-editor.org/rfc/rfc7541#section-4.1>
const ENTRY_OVERHEAD: usize = 32;

/// One dynamic table entry.
#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) name: Box<[u8]>,
    pub(crate) value: Box<[u8]>,
}

impl Entry {
    fn size(&self) -> usize {
        self.name.len() + self.value.len() + ENTRY_OVERHEAD
    }
}

/// The dynamic table of one HPACK decoding context.
///
/// RFC 7541, Section 2.3.2 — "The dynamic table consists of a list of
/// header fields maintained in first-in, first-out order. The first and
/// newest entry in a dynamic table is at the lowest index, and the oldest
/// entry of a dynamic table is at the highest index." —
/// <https://www.rfc-editor.org/rfc/rfc7541#section-2.3.2>
#[derive(Debug)]
pub(crate) struct DynamicTable {
    /// Newest entry first.
    entries: VecDeque<Entry>,
    size: usize,
    max_size: usize,
}

impl DynamicTable {
    /// Create an empty table with the given maximum size.
    pub(crate) fn new(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size,
        }
    }

    /// Current size (RFC 7541, Section 4.1).
    pub(crate) fn size(&self) -> usize {
        self.size
    }

    /// Current maximum size.
    #[cfg(test)]
    pub(crate) fn max_size(&self) -> usize {
        self.max_size
    }

    /// Number of entries.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Entry at the 1-based dynamic index (index 1 is HPACK index 62).
    pub(crate) fn get(&self, index: usize) -> Option<&Entry> {
        index.checked_sub(1).and_then(|i| self.entries.get(i))
    }

    /// Change the maximum size, evicting entries that no longer fit.
    ///
    /// RFC 7541, Section 4.3 — "Whenever the maximum size for the dynamic
    /// table is reduced, entries are evicted from the end of the dynamic
    /// table until the size of the dynamic table is less than or equal to
    /// the maximum size." — <https://www.rfc-editor.org/rfc/rfc7541#section-4.3>
    pub(crate) fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
        self.evict_to(max_size);
    }

    /// Add an entry at the front of the table.
    ///
    /// RFC 7541, Section 4.4 — "Before a new entry is added to the dynamic
    /// table, entries are evicted from the end of the dynamic table until
    /// the size of the dynamic table is less than or equal to (maximum
    /// size - new entry size) or until the table is empty." and "If the size of
    /// the new entry is less than or equal to the maximum size, that entry
    /// is added to the table. It is not an error to attempt to add an entry
    /// that is larger than the maximum size; an attempt to add an entry
    /// larger than the maximum size causes the table to be emptied of all
    /// existing entries and results in an empty table." —
    /// <https://www.rfc-editor.org/rfc/rfc7541#section-4.4>
    pub(crate) fn insert(&mut self, name: &[u8], value: &[u8]) {
        let entry = Entry {
            name: name.into(),
            value: value.into(),
        };
        let entry_size = entry.size();
        if entry_size > self.max_size {
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.evict_to(self.max_size - entry_size);
        self.size += entry_size;
        self.entries.push_front(entry);
    }

    fn evict_to(&mut self, limit: usize) {
        while self.size > limit {
            let Some(old) = self.entries.pop_back() else {
                break;
            };
            self.size -= old.size();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_puts_the_newest_entry_first() {
        let mut table = DynamicTable::new(4096);
        table.insert(b"a", b"1");
        table.insert(b"b", b"2");
        assert_eq!(&*table.get(1).unwrap().name, b"b");
        assert_eq!(&*table.get(2).unwrap().name, b"a");
        assert!(table.get(0).is_none());
        assert!(table.get(3).is_none());
        assert_eq!(table.size(), 2 * 34);
    }

    #[test]
    fn insert_evicts_the_oldest_entries() {
        // Room for exactly two 34-octet entries.
        let mut table = DynamicTable::new(68);
        table.insert(b"a", b"1");
        table.insert(b"b", b"2");
        table.insert(b"c", b"3");
        assert_eq!(table.len(), 2);
        assert_eq!(&*table.get(2).unwrap().name, b"b");
    }

    #[test]
    fn oversized_entry_empties_the_table() {
        let mut table = DynamicTable::new(40);
        table.insert(b"a", b"1");
        table.insert(b"name", b"too long value");
        assert_eq!(table.len(), 0);
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn reducing_the_maximum_size_evicts() {
        let mut table = DynamicTable::new(4096);
        table.insert(b"a", b"1");
        table.insert(b"b", b"2");
        table.set_max_size(40);
        assert_eq!(table.len(), 1);
        assert_eq!(&*table.get(1).unwrap().name, b"b");
        assert_eq!(table.max_size(), 40);
    }
}
