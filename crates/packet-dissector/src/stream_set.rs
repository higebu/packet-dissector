//! Bounded set of TCP stream directions.
//!
//! Used by dissectors that remember a property of a TCP connection across
//! segments (for example that it speaks HTTP/2) and must not grow without
//! bound on captures with many connections.

use std::collections::{HashMap, VecDeque};

use packet_dissector_core::dissector::TcpStreamKey;

/// A set of TCP stream directions holding at most `capacity` entries.
///
/// When the set is full, inserting a new direction forgets the oldest one.
/// Each entry carries the generation it was inserted with, so a stale key
/// left in `order` after a removal never evicts a newer entry.
pub(crate) struct StreamSet {
    entries: HashMap<TcpStreamKey, u64>,
    /// Insertion order for eviction (may hold stale keys).
    order: VecDeque<(TcpStreamKey, u64)>,
    generation: u64,
    capacity: usize,
}

impl StreamSet {
    /// Create an empty set that holds at most `capacity` directions.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            generation: 0,
            capacity,
        }
    }

    /// Whether `key` is in the set.
    pub(crate) fn contains(&self, key: &TcpStreamKey) -> bool {
        !self.entries.is_empty() && self.entries.contains_key(key)
    }

    /// Add `key`, forgetting the oldest directions when the set is full.
    pub(crate) fn insert(&mut self, key: TcpStreamKey) {
        if self.entries.contains_key(&key) {
            return;
        }
        while self.entries.len() >= self.capacity {
            let Some((old, generation)) = self.order.pop_front() else {
                break;
            };
            if self.entries.get(&old) == Some(&generation) {
                self.entries.remove(&old);
            }
        }
        self.generation += 1;
        self.entries.insert(key, self.generation);
        self.order.push_back((key, self.generation));
    }

    /// Remove `key` from the set.
    pub(crate) fn remove(&mut self, key: &TcpStreamKey) {
        if self.entries.is_empty() || self.entries.remove(key).is_none() {
            return;
        }
        // Drop stale keys once they dominate the eviction order.
        if self.order.len() > self.entries.len() * 2 + 64 {
            let entries = &self.entries;
            self.order.retain(|(k, g)| entries.get(k) == Some(g));
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> TcpStreamKey {
        ([0; 16], [1; 16], port, 80)
    }

    #[test]
    fn insert_contains_remove() {
        let mut set = StreamSet::new(4);
        assert!(!set.contains(&key(1)));
        set.insert(key(1));
        set.insert(key(1));
        assert!(set.contains(&key(1)));
        assert_eq!(set.len(), 1);
        set.remove(&key(1));
        set.remove(&key(1));
        assert!(!set.contains(&key(1)));
    }

    #[test]
    fn full_set_forgets_the_oldest_direction() {
        let mut set = StreamSet::new(3);
        for port in 1..=4 {
            set.insert(key(port));
        }
        assert_eq!(set.len(), 3);
        assert!(!set.contains(&key(1)));
        assert!(set.contains(&key(4)));
    }

    #[test]
    fn stale_order_entry_does_not_evict_a_reinserted_key() {
        let mut set = StreamSet::new(2);
        set.insert(key(1));
        set.remove(&key(1));
        set.insert(key(2));
        set.insert(key(1));
        // The stale (key(1), 1) entry is popped without removing the live
        // key(1); the oldest live entry, key(2), is evicted instead.
        set.insert(key(3));
        assert!(set.contains(&key(1)));
        assert!(!set.contains(&key(2)));
        assert!(set.contains(&key(3)));
    }

    #[test]
    fn remove_compacts_the_eviction_order() {
        let mut set = StreamSet::new(1000);
        for port in 0..200 {
            set.insert(key(port));
        }
        for port in 0..200 {
            set.remove(&key(port));
        }
        assert_eq!(set.len(), 0);
        assert!(set.order.len() <= 64);
    }

    #[test]
    fn zero_capacity_still_holds_the_latest_direction() {
        let mut set = StreamSet::new(0);
        set.insert(key(1));
        set.insert(key(2));
        assert!(set.contains(&key(2)));
    }
}
