//! IPv4 / IPv6 fragment reassembly for the dissector registry.
//!
//! The IPv4 dissector and the IPv6 Fragment header dissector report every
//! fragment through [`IpFragmentContext`]. This module buffers the fragment
//! data per datagram and, once every fragment has arrived, lets the
//! registry dissect the upper layers of the reassembled datagram on the
//! packet that completed it. Packets carrying an incomplete datagram end
//! after their IP layer.
//!
//! ## References
//! - RFC 791, Section 3.2 (IPv4 fragmentation and reassembly):
//!   <https://www.rfc-editor.org/rfc/rfc791#section-3.2>
//! - RFC 8200, Section 4.5 (IPv6 Fragment header and reassembly; includes
//!   the overlapping-fragment rule of RFC 5722):
//!   <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>
//! - RFC 5722 (Handling of Overlapping IPv6 Fragments):
//!   <https://www.rfc-editor.org/rfc/rfc5722>

use std::collections::{HashMap, VecDeque};
use std::ops::Range;
use std::sync::Mutex;

use packet_dissector_core::dissector::{DispatchHint, IpFragmentContext};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{Field, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_reassembly::ReassemblyBuffer;

use super::registry::DissectorRegistry;

/// Fragment reassembly key, see [`IpFragmentContext::frag_key`].
pub(crate) type FragKey = ([u8; 16], [u8; 16], u8, u32);

/// Largest value of the reassembled datagram's 16-bit length field (IPv4
/// Total Length, IPv6 Payload Length).
///
/// RFC 8200, Section 4.5 — "If the length and offset of a fragment are such
/// that the Payload Length of the packet reassembled from that fragment
/// would exceed 65,535 octets, then that fragment must be discarded".
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>
const MAX_DATAGRAM_LEN: usize = 65_535;

/// Maximum number of datagrams being reassembled at once. When a fragment of
/// a new datagram arrives while this many are buffered, the oldest datagrams
/// are dropped. This stands in for the reassembly timer of RFC 791,
/// Section 3.2 and RFC 8200, Section 4.5, which a dissector without packet
/// timestamps cannot run.
const MAX_FRAGMENT_GROUPS: usize = 1024;

/// Maximum bytes buffered across all datagrams being reassembled. When a
/// fragment arrives while more bytes are buffered, the oldest datagrams are
/// dropped.
const MAX_FRAGMENT_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Reassembly state of one datagram.
struct FragmentGroup {
    buffer: ReassemblyBuffer,
    /// Byte ranges of the fragments received, used to detect overlapping
    /// IPv6 fragments.
    fragments: Vec<Range<usize>>,
    /// Protocol of the offset-zero fragment, once it has arrived.
    protocol: Option<u8>,
    /// Number of fragments that contributed data.
    count: u32,
    /// Generation the group was created with, to skip stale `order` entries.
    generation: u64,
}

/// A datagram whose fragments have all arrived.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Reassembled {
    /// The reassembled payload (fragmentable part).
    pub(crate) data: Vec<u8>,
    /// Protocol of the offset-zero fragment.
    pub(crate) protocol: u8,
    /// Number of fragments that contributed data.
    pub(crate) fragment_count: u32,
}

/// Centralized IP fragment reassembly service.
pub(crate) struct IpReassemblyService {
    groups: HashMap<FragKey, FragmentGroup>,
    /// Creation order for eviction; may hold stale entries.
    order: VecDeque<(FragKey, u64)>,
    generation: u64,
    /// Bytes allocated by the buffers of all groups.
    total_bytes: usize,
}

impl IpReassemblyService {
    pub(crate) fn new() -> Self {
        Self {
            groups: HashMap::new(),
            order: VecDeque::new(),
            generation: 0,
            total_bytes: 0,
        }
    }

    /// Add one fragment carrying `data`, whose declared length is
    /// `ctx.payload_len`. Returns the reassembled datagram when this
    /// fragment completes it.
    pub(crate) fn add_fragment(
        &mut self,
        ctx: &IpFragmentContext,
        data: &[u8],
    ) -> Option<Reassembled> {
        let start = ctx.offset_bytes;
        let end = start.checked_add(data.len())?;

        // RFC 791, Section 3.2 — "If an internet datagram is fragmented, its
        // data portion must be broken on 8 octet boundaries."
        // https://www.rfc-editor.org/rfc/rfc791#section-3.2
        // RFC 8200, Section 4.5 — "If the length of a fragment, as derived
        // from the fragment packet's Payload Length field, is not a multiple
        // of 8 octets and the M flag of that fragment is 1, then that
        // fragment must be discarded".
        // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
        if ctx.more_fragments && data.len() % 8 != 0 {
            return None;
        }
        // A reassembled length field above 65,535 octets cannot exist (RFC
        // 791, Section 3.1 Total Length is 16 bits; RFC 8200, Section 4.5
        // requires discarding such a fragment).
        if ctx.unfragmentable_len.saturating_add(end) > MAX_DATAGRAM_LEN {
            return None;
        }

        let key = ctx.frag_key;
        if !self.groups.contains_key(&key) {
            self.evict_for_new_group();
            self.generation += 1;
            self.order.push_back((key, self.generation));
            self.groups.insert(
                key,
                FragmentGroup {
                    buffer: ReassemblyBuffer::new(),
                    fragments: Vec::new(),
                    protocol: None,
                    count: 0,
                    generation: self.generation,
                },
            );
        }
        let group = self.groups.get_mut(&key)?;

        if Self::conflicts(group, ctx, start, end, data) {
            self.remove(&key);
            return None;
        }
        if is_ipv6(&key)
            && group.fragments.contains(&(start..end))
            && group.buffer.data().get(start..end) == Some(data)
        {
            // RFC 8200, Section 4.5 — "an implementation may choose to
            // detect this case and drop exact duplicate fragments while
            // keeping the other fragments belonging to the same packet."
            return None;
        }

        let before = group.buffer.data().len();
        group.buffer.insert(start, data)?;
        let after = group.buffer.data().len();
        self.total_bytes += after - before;
        group.fragments.push(start..end);
        group.count += 1;
        if start == 0 {
            group.protocol = Some(ctx.protocol);
        }
        if !ctx.more_fragments {
            group.buffer.set_total_len(end);
        }

        if !group.buffer.is_complete() {
            return None;
        }
        let protocol = group.protocol?;
        let count = group.count;
        let total = group.buffer.total_len()?;
        let group = self.remove(&key)?;
        let mut data = group.buffer.into_data();
        data.truncate(total);
        Some(Reassembled {
            data,
            protocol,
            fragment_count: count,
        })
    }

    /// Whether the fragment `start..end` cannot belong to the datagram
    /// buffered in `group`, which is then abandoned.
    ///
    /// - A last fragment (MF/M = 0) that ends elsewhere than an earlier last
    ///   fragment, or before data already received, and any fragment that
    ///   extends past the end fixed by a last fragment, leave no consistent
    ///   datagram length.
    /// - IPv6: RFC 8200, Section 4.5 — "If any of the fragments being
    ///   reassembled overlap with any other fragments being reassembled for
    ///   the same packet, reassembly of that packet must be abandoned and
    ///   all the fragments that have been received for that packet must be
    ///   discarded". Exact duplicates are handled by the caller.
    ///   <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>
    ///
    /// Overlapping IPv4 fragments are not a conflict: RFC 791, Section 3.2 —
    /// "In the case that two or more fragments contain the same data either
    /// identically or through a partial overlap, this procedure will use the
    /// more recently arrived copy in the data buffer and datagram
    /// delivered." <https://www.rfc-editor.org/rfc/rfc791#section-3.2>
    fn conflicts(
        group: &FragmentGroup,
        ctx: &IpFragmentContext,
        start: usize,
        end: usize,
        data: &[u8],
    ) -> bool {
        let received_end = group.fragments.iter().map(|r| r.end).max().unwrap_or(0);
        match group.buffer.total_len() {
            Some(total) if end > total || (!ctx.more_fragments && end != total) => return true,
            None if !ctx.more_fragments && end < received_end => return true,
            _ => {}
        }
        if !is_ipv6(&ctx.frag_key) {
            return false;
        }
        group.fragments.iter().any(|r| {
            let exact_duplicate =
                *r == (start..end) && group.buffer.data().get(start..end) == Some(data);
            !exact_duplicate && r.start < end && start < r.end
        })
    }

    /// Drop a datagram's buffered fragments.
    fn remove(&mut self, key: &FragKey) -> Option<FragmentGroup> {
        let group = self.groups.remove(key)?;
        self.total_bytes = self.total_bytes.saturating_sub(group.buffer.data().len());
        if self.order.len() > self.groups.len() * 2 + 64 {
            let groups = &self.groups;
            self.order
                .retain(|(k, g)| groups.get(k).is_some_and(|group| group.generation == *g));
        }
        Some(group)
    }

    /// Drop the oldest datagrams until a new one fits within the limits.
    fn evict_for_new_group(&mut self) {
        while self.groups.len() >= MAX_FRAGMENT_GROUPS || self.total_bytes > MAX_FRAGMENT_BYTES {
            let Some((key, generation)) = self.order.pop_front() else {
                break;
            };
            if self
                .groups
                .get(&key)
                .is_some_and(|group| group.generation == generation)
            {
                self.remove(&key);
            }
        }
    }
}

/// Whether `key` identifies an IPv6 datagram (see
/// [`IpFragmentContext::IPV6_KEY_PROTOCOL`]). An IPv4 datagram with Protocol
/// 44 is treated the same way; the IPv6 Fragment header never follows an
/// IPv4 header.
fn is_ipv6(key: &FragKey) -> bool {
    key.2 == IpFragmentContext::IPV6_KEY_PROTOCOL
}

/// Create a new `Mutex<IpReassemblyService>` for use in `DissectorRegistry`.
pub(crate) fn new_ip_reassembly() -> Mutex<IpReassemblyService> {
    Mutex::new(IpReassemblyService::new())
}

fn lock_poisoned(_: impl Sized) -> PacketError {
    PacketError::InvalidHeader("ip reassembly lock poisoned")
}

impl DissectorRegistry {
    /// Buffer one IP fragment and, when it completes its datagram, dissect
    /// the upper layers of the reassembled datagram into `buf`.
    ///
    /// `payload` is the fragment data, which starts at absolute offset
    /// `offset`. The reassembled datagram is stored in the buffer's
    /// auxiliary data and dissected with the same dispatch loop (and the
    /// same `stop` predicate) as the enclosing packet, so its layers follow
    /// the IP layer and their ranges continue from `offset`, as with ESP
    /// decryption.
    pub(crate) fn handle_ip_fragment<'pkt, F>(
        &self,
        ctx: &IpFragmentContext,
        payload: &[u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
        stop: &mut F,
    ) -> Result<(), PacketError>
    where
        F: FnMut(&DissectBuffer<'pkt>, &DispatchHint) -> bool,
    {
        let reassembled = self
            .ip_reassembly
            .lock()
            .map_err(lock_poisoned)?
            .add_fragment(ctx, payload);
        let Some(reassembled) = reassembled else {
            return Ok(());
        };
        Self::add_ip_reassembly_fields(buf, &reassembled);

        // The dispatch loop uses `offset` both as an index into its input
        // and as the absolute offset recorded in layer ranges, so the
        // datagram is prefixed with `offset` padding bytes.
        let mut padded = vec![0u8; offset];
        padded.extend_from_slice(&reassembled.data);
        let aux_handle = buf.push_aux_data(&padded);
        let input = Self::aux_bytes(buf, aux_handle, 0..padded.len());
        // RFC 8200, Section 4.5 — the Next Header of the offset-zero
        // fragment identifies the fragmentable part; for IPv4 every fragment
        // carries the same Protocol (it is part of the key).
        self.dispatch_loop(
            input,
            buf,
            offset,
            input.len(),
            DispatchHint::ByIpProtocol(reassembled.protocol),
            stop,
        )
    }

    /// Report the reassembly on the IP layer that completed the datagram
    /// (the last layer in `buf`), when its dissector declares the
    /// `fragment_count` / `reassembled_length` fields.
    fn add_ip_reassembly_fields(buf: &mut DissectBuffer<'_>, reassembled: &Reassembled) {
        let Some(layer) = buf.layers().last() else {
            return;
        };
        let (name, descriptors, range) = (layer.name, layer.field_descriptors, layer.range.clone());
        let find = |field: &str| descriptors.iter().find(|d| d.name == field);
        let mut fields = Vec::with_capacity(2);
        if let Some(descriptor) = find("fragment_count") {
            fields.push(Field {
                descriptor,
                value: FieldValue::U32(reassembled.fragment_count),
                range: range.clone(),
            });
        }
        if let Some(descriptor) = find("reassembled_length") {
            fields.push(Field {
                descriptor,
                value: FieldValue::U32(reassembled.data.len() as u32),
                range,
            });
        }
        if !fields.is_empty() {
            buf.append_fields_to_layer(name, &fields);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(key: FragKey, offset: usize, more: bool, len: usize) -> IpFragmentContext {
        IpFragmentContext::new(key, 17, offset, more, len)
    }

    fn v4(id: u32) -> FragKey {
        ([0; 16], [1; 16], 17, id)
    }

    fn v6(id: u32) -> FragKey {
        ([2; 16], [3; 16], IpFragmentContext::IPV6_KEY_PROTOCOL, id)
    }

    #[test]
    fn completes_when_all_fragments_arrive() {
        let mut service = IpReassemblyService::new();
        assert_eq!(
            service.add_fragment(&ctx(v4(1), 8, false, 4), b"wxyz"),
            None
        );
        let done = service
            .add_fragment(&ctx(v4(1), 0, true, 8), b"abcdefgh")
            .unwrap();
        assert_eq!(done.data, b"abcdefghwxyz");
        assert_eq!(done.protocol, 17);
        assert_eq!(done.fragment_count, 2);
        assert!(service.groups.is_empty());
        assert_eq!(service.total_bytes, 0);
    }

    #[test]
    fn ipv6_overlap_abandons_group() {
        let mut service = IpReassemblyService::new();
        assert_eq!(
            service.add_fragment(&ctx(v6(1), 0, true, 16), &[0; 16]),
            None
        );
        assert_eq!(
            service.add_fragment(&ctx(v6(1), 8, true, 16), &[1; 16]),
            None
        );
        assert!(service.groups.is_empty());
        assert_eq!(service.total_bytes, 0);
    }

    #[test]
    fn ipv6_changed_duplicate_is_an_overlap() {
        let mut service = IpReassemblyService::new();
        service.add_fragment(&ctx(v6(1), 0, true, 8), &[0; 8]);
        service.add_fragment(&ctx(v6(1), 0, true, 8), &[1; 8]);
        assert!(service.groups.is_empty());
    }

    #[test]
    fn eviction_drops_the_oldest_group() {
        let mut service = IpReassemblyService::new();
        for id in 0..MAX_FRAGMENT_GROUPS as u32 {
            service.add_fragment(&ctx(v4(id), 0, true, 8), &[0; 8]);
        }
        assert_eq!(service.groups.len(), MAX_FRAGMENT_GROUPS);
        service.add_fragment(&ctx(v4(u32::MAX), 0, true, 8), &[0; 8]);
        assert_eq!(service.groups.len(), MAX_FRAGMENT_GROUPS);
        assert!(!service.groups.contains_key(&v4(0)));
        assert!(service.groups.contains_key(&v4(1)));
        assert!(service.groups.contains_key(&v4(u32::MAX)));
    }

    #[test]
    fn eviction_honours_the_byte_budget() {
        let mut service = IpReassemblyService::new();
        let big = vec![0u8; 65_528];
        let groups = MAX_FRAGMENT_BYTES / big.len() + 1;
        for id in 0..groups as u32 {
            service.add_fragment(&ctx(v4(id), 0, true, big.len()), &big);
        }
        assert!(service.total_bytes > MAX_FRAGMENT_BYTES);
        service.add_fragment(&ctx(v4(u32::MAX), 0, true, 8), &[0; 8]);
        assert!(service.total_bytes <= MAX_FRAGMENT_BYTES + 8);
        assert!(!service.groups.contains_key(&v4(0)));
    }

    #[test]
    fn eviction_skips_stale_order_entries() {
        let mut service = IpReassemblyService::new();
        // Complete a datagram, then reuse its key: the first order entry is
        // stale and must not evict the new group.
        service.add_fragment(&ctx(v4(0), 8, false, 8), &[0; 8]);
        service.add_fragment(&ctx(v4(0), 0, true, 8), &[0; 8]);
        assert!(service.groups.is_empty());
        service.add_fragment(&ctx(v4(0), 0, true, 8), &[0; 8]);
        for id in 1..MAX_FRAGMENT_GROUPS as u32 {
            service.add_fragment(&ctx(v4(id), 0, true, 8), &[0; 8]);
        }
        service.add_fragment(&ctx(v4(u32::MAX), 0, true, 8), &[0; 8]);
        assert!(!service.groups.contains_key(&v4(0)));
        assert!(service.groups.contains_key(&v4(1)));
    }

    #[test]
    fn remove_compacts_order() {
        let mut service = IpReassemblyService::new();
        for id in 0..200 {
            service.add_fragment(&ctx(v6(id), 0, true, 8), &[0; 8]);
            service.add_fragment(&ctx(v6(id), 0, true, 8), &[1; 8]);
        }
        assert!(service.groups.is_empty());
        assert!(service.order.len() <= 64);
    }

    #[test]
    fn offset_overflow_is_ignored() {
        let mut service = IpReassemblyService::new();
        assert_eq!(
            service.add_fragment(&ctx(v4(1), usize::MAX, false, 1), &[0]),
            None
        );
        assert!(service.groups.is_empty());
    }

    #[test]
    fn lock_poisoned_error() {
        assert_eq!(
            lock_poisoned(()),
            PacketError::InvalidHeader("ip reassembly lock poisoned")
        );
    }
}
