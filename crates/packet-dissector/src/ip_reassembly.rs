//! IPv4 / IPv6 fragment reassembly for the dissector registry.
//!
//! The IPv4 dissector and the IPv6 Fragment header dissector report every
//! fragment through [`IpFragmentContext`]. During full dissection this
//! module buffers the fragment data per datagram and, once every fragment
//! has arrived, the registry dissects the upper layers of the reassembled
//! datagram on the packet that completed it. Packets carrying an incomplete
//! datagram end after their IP layer.
//!
//! Reassembly is stateful: every packet is expected to be dissected once,
//! in capture order, on the same registry.
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

use packet_dissector_core::dissector::{DispatchHint, DissectResult, IpFragmentContext};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{Field, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_reassembly::ReassemblyBuffer;

use super::registry::{DissectorRegistry, TmpPrefix, no_stop};

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

/// Maximum number of distinct fragments of one datagram. A datagram of at
/// most 65,535 octets split on 8-octet boundaries has at most 8,192
/// non-overlapping fragments; a datagram that needs more (overlapping
/// variants) is abandoned.
///
/// RFC 791, Section 3.2 — "This format allows 2**13 = 8192 fragments of 8
/// octets each for a total of 65,536 octets."
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.2>
const MAX_FRAGMENTS_PER_DATAGRAM: usize = 8192;

/// Maximum number of datagrams being reassembled at once. When a fragment of
/// a new datagram arrives while this many are buffered, the oldest datagrams
/// are dropped. This stands in for the reassembly timer of RFC 791,
/// Section 3.2 (<https://www.rfc-editor.org/rfc/rfc791#section-3.2>) and
/// RFC 8200, Section 4.5
/// (<https://www.rfc-editor.org/rfc/rfc8200#section-4.5>), which a dissector
/// without packet timestamps cannot run.
const MAX_FRAGMENT_GROUPS: usize = 1024;

/// Maximum bytes buffered across all datagrams being reassembled. When a
/// fragment of a new datagram arrives while more bytes are buffered, the
/// oldest datagrams are dropped.
const MAX_FRAGMENT_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Reassembly state of one datagram.
struct FragmentGroup {
    buffer: ReassemblyBuffer,
    /// Byte ranges of the distinct fragments received, sorted by
    /// `(start, end)`. For IPv6 they never overlap.
    fragments: Vec<Range<usize>>,
    /// Protocol and [`IpFragmentContext::unfragmentable_len`] of the
    /// offset-zero fragment, once it has arrived.
    first: Option<(u8, usize)>,
    /// The datagram was abandoned because of overlapping IPv6 fragments;
    /// its remaining fragments are discarded on arrival.
    abandoned: bool,
    /// Generation the group was created with, to skip stale `order` entries.
    generation: u64,
}

impl FragmentGroup {
    /// Bytes accounted to this group in the service's byte budget.
    fn bytes(&self) -> usize {
        self.buffer.data().len() + self.fragments.len() * core::mem::size_of::<Range<usize>>()
    }
}

/// A datagram whose fragments have all arrived.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Reassembled {
    /// The reassembled payload (fragmentable part).
    pub(crate) data: Vec<u8>,
    /// Protocol of the offset-zero fragment.
    pub(crate) protocol: u8,
    /// Number of distinct fragments (by offset and length) it was built from.
    pub(crate) fragment_count: u32,
}

/// Centralized IP fragment reassembly service.
pub(crate) struct IpReassemblyService {
    groups: HashMap<FragKey, FragmentGroup>,
    /// Creation order for eviction; may hold stale entries.
    order: VecDeque<(FragKey, u64)>,
    generation: u64,
    /// Bytes accounted to all groups (see [`FragmentGroup::bytes`]).
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

    /// Add one fragment carrying `data`. Returns the reassembled datagram
    /// when this fragment completes it.
    pub(crate) fn add_fragment(
        &mut self,
        ctx: &IpFragmentContext,
        data: &[u8],
    ) -> Option<Reassembled> {
        let key = ctx.frag_key;
        let ipv6 = is_ipv6(&key);
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
        // RFC 8200, Section 4.5 — "If the length and offset of a fragment are
        // such that the Payload Length of the packet reassembled from that
        // fragment would exceed 65,535 octets, then that fragment must be
        // discarded". For IPv4 only the data is bounded here; the header of
        // the reassembled datagram is the offset-zero fragment's, checked on
        // completion.
        // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
        let headers = if ipv6 { ctx.unfragmentable_len } else { 0 };
        if headers.saturating_add(end) > MAX_DATAGRAM_LEN {
            return None;
        }

        let is_new = !self.groups.contains_key(&key);
        self.evict_to_limits(&key, is_new);
        if is_new {
            self.generation += 1;
            self.order.push_back((key, self.generation));
            self.groups.insert(
                key,
                FragmentGroup {
                    buffer: ReassemblyBuffer::new(),
                    fragments: Vec::new(),
                    first: None,
                    abandoned: false,
                    generation: self.generation,
                },
            );
        }
        let group = self.groups.get_mut(&key)?;
        if group.abandoned {
            return None;
        }
        let position = group
            .fragments
            .binary_search_by(|r| (r.start, r.end).cmp(&(start, end)));

        let overlap = match position {
            // RFC 8200, Section 4.5 — "an implementation may choose to detect
            // this case and drop exact duplicate fragments while keeping the
            // other fragments belonging to the same packet."
            // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
            Ok(_) if ipv6 && group.buffer.data().get(start..end) == Some(data) => return None,
            // Same range with different data: an overlap for IPv6.
            Ok(_) => ipv6,
            Err(i) => ipv6 && Self::overlaps_neighbour(&group.fragments, i, start, end),
        };
        if overlap {
            self.abandon(&key);
            return None;
        }
        let too_many = position.is_err() && group.fragments.len() >= MAX_FRAGMENTS_PER_DATAGRAM;
        if too_many || Self::length_conflict(group, ctx.more_fragments, end) {
            // The buffered fragments cannot form one datagram with this one:
            // without a reassembly timer they are most likely left over from
            // an earlier datagram that reused the key (RFC 4963, Section 2 —
            // https://www.rfc-editor.org/rfc/rfc4963#section-2). Drop them
            // and start afresh with this fragment, which an empty group
            // always accepts.
            self.remove(&key);
            return self.add_fragment(ctx, data);
        }

        let before = group.bytes();
        group.buffer.insert(start, data)?;
        if let Err(i) = position {
            group.fragments.insert(i, start..end);
        }
        if start == 0 {
            group.first = Some((ctx.protocol, ctx.unfragmentable_len));
        }
        if !ctx.more_fragments {
            group.buffer.set_total_len(end);
        }
        self.total_bytes += group.bytes() - before;

        if !group.buffer.is_complete() {
            return None;
        }
        let (protocol, headers) = group.first?;
        let total = group.buffer.total_len()?;
        let group = self.remove(&key)?;
        // RFC 791, Section 3.2 — the reassembled datagram takes the header
        // of the first fragment: "TL <- TDL+(IHL*4)", which must fit the
        // 16-bit Total Length (RFC 791, Section 3.1).
        // https://www.rfc-editor.org/rfc/rfc791#section-3.2
        // https://www.rfc-editor.org/rfc/rfc791#section-3.1
        if headers.saturating_add(total) > MAX_DATAGRAM_LEN {
            return None;
        }
        let fragment_count = group.fragments.len() as u32;
        let mut data = group.buffer.into_data();
        data.truncate(total);
        Some(Reassembled {
            data,
            protocol,
            fragment_count,
        })
    }

    /// Whether the new fragment `start..end`, to be inserted at index `i` of
    /// the sorted, non-overlapping `fragments`, overlaps a fragment already
    /// received. Only the neighbours can overlap it.
    ///
    /// RFC 8200, Section 4.5 — "If any of the fragments being reassembled
    /// overlap with any other fragments being reassembled for the same
    /// packet, reassembly of that packet must be abandoned and all the
    /// fragments that have been received for that packet must be
    /// discarded". <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>
    ///
    /// Overlapping IPv4 fragments are not checked: RFC 791, Section 3.2 —
    /// "In the case that two or more fragments contain the same data either
    /// identically or through a partial overlap, this procedure will use the
    /// more recently arrived copy in the data buffer and datagram
    /// delivered." <https://www.rfc-editor.org/rfc/rfc791#section-3.2>
    fn overlaps_neighbour(fragments: &[Range<usize>], i: usize, start: usize, end: usize) -> bool {
        let overlaps = |r: &Range<usize>| r.start < end && start < r.end;
        i.checked_sub(1)
            .and_then(|p| fragments.get(p))
            .is_some_and(overlaps)
            || fragments.get(i).is_some_and(overlaps)
    }

    /// Whether a fragment ending at `end` leaves no consistent datagram
    /// length: a last fragment (MF/M = 0) that ends elsewhere than an
    /// earlier last fragment or before data already received, or any
    /// fragment that extends past the end fixed by a last fragment.
    fn length_conflict(group: &FragmentGroup, more_fragments: bool, end: usize) -> bool {
        match group.buffer.total_len() {
            Some(total) => end > total || (!more_fragments && end != total),
            // The buffer grows to the end of the furthest fragment.
            None => !more_fragments && end < group.buffer.data().len(),
        }
    }

    /// Abandon an IPv6 datagram with overlapping fragments: drop its data
    /// but keep the group, so fragments of it that arrive later are
    /// discarded too.
    ///
    /// RFC 5722, Section 4 — "the entire datagram (and any constituent
    /// fragments, including those not yet received) MUST be silently
    /// discarded." <https://www.rfc-editor.org/rfc/rfc5722#section-4>
    fn abandon(&mut self, key: &FragKey) {
        if let Some(group) = self.groups.get_mut(key) {
            self.total_bytes = self.total_bytes.saturating_sub(group.bytes());
            group.buffer = ReassemblyBuffer::new();
            group.fragments = Vec::new();
            group.first = None;
            group.abandoned = true;
        }
    }

    /// Drop a datagram's buffered fragments.
    fn remove(&mut self, key: &FragKey) -> Option<FragmentGroup> {
        let group = self.groups.remove(key)?;
        self.total_bytes = self.total_bytes.saturating_sub(group.bytes());
        if self.order.len() > self.groups.len() * 2 + 64 {
            let groups = &self.groups;
            self.order
                .retain(|(k, g)| groups.get(k).is_some_and(|group| group.generation == *g));
        }
        Some(group)
    }

    /// Drop the oldest datagrams other than `keep` (the datagram of the
    /// fragment being processed) until the group count, counting a new
    /// group for `keep` when `is_new`, and the byte budget are within the
    /// limits. The byte budget may be exceeded by the fragment being added.
    fn evict_to_limits(&mut self, keep: &FragKey, is_new: bool) {
        let mut kept = false;
        while self.groups.len() + usize::from(is_new) > MAX_FRAGMENT_GROUPS
            || self.total_bytes > MAX_FRAGMENT_BYTES
        {
            let Some((key, generation)) = self.order.pop_front() else {
                break;
            };
            let live = self
                .groups
                .get(&key)
                .is_some_and(|group| group.generation == generation);
            if !live {
                continue;
            }
            if key == *keep {
                // Only `keep` is left to evict.
                self.order.push_back((key, generation));
                if kept {
                    break;
                }
                kept = true;
                continue;
            }
            self.remove(&key);
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
    /// Feed the fragment a dissector reported in `result` (whose header ends
    /// at absolute offset `offset`; its input ends at `end`) to the
    /// reassembly and dissect the reassembled datagram if it completes.
    ///
    /// Returns `None` when the dispatch chain should go on with the
    /// dissector's own hint instead: `result` carries no fragment, the
    /// dissection is shallow (`full` is `false`), or the fragment's data was
    /// not captured in full (snaplen truncation), so it cannot be
    /// reassembled.
    pub(crate) fn reassemble_reported_fragment(
        &self,
        result: &DissectResult,
        data: &[u8],
        buf: &mut DissectBuffer<'_>,
        offset: usize,
        end: usize,
        full: bool,
    ) -> Option<Result<(), PacketError>> {
        let ctx = result.ip_fragment_context.as_ref()?;
        if !full || end.saturating_sub(offset) < ctx.payload_len {
            return None;
        }
        let payload = &data[offset..offset + ctx.payload_len];
        Some(self.handle_ip_fragment(ctx, payload, buf, offset))
    }

    /// Buffer one IP fragment and, when it completes its datagram, dissect
    /// the upper layers of the reassembled datagram into `buf`.
    ///
    /// `payload` is the fragment data, which starts at absolute offset
    /// `offset`. As with ESP decryption, the reassembled datagram is
    /// dissected from a local buffer (prefixed with `offset` padding bytes
    /// so the new layers' ranges continue from the IP layer) into a
    /// temporary `DissectBuffer`, then merged into `buf` with byte fields
    /// remapped into `buf`'s auxiliary data. The temporary buffer starts
    /// with a copy of `buf`'s layers so upper-layer dissectors (e.g. TCP,
    /// which keys streams on the IP addresses) see the enclosing layers.
    pub(crate) fn handle_ip_fragment(
        &self,
        ctx: &IpFragmentContext,
        payload: &[u8],
        buf: &mut DissectBuffer<'_>,
        offset: usize,
    ) -> Result<(), PacketError> {
        let reassembled = self
            .ip_reassembly
            .lock()
            .map_err(lock_poisoned)?
            .add_fragment(ctx, payload);
        let Some(reassembled) = reassembled else {
            return Ok(());
        };
        Self::add_ip_reassembly_fields(buf, &reassembled);

        let aux_handle = buf.push_aux_data(&reassembled.data);
        let protocol = reassembled.protocol;
        let mut padded = reassembled.data;
        padded.splice(0..0, core::iter::repeat_n(0u8, offset));

        let mut tmp_buf = DissectBuffer::new();
        tmp_buf.set_verify_checksums(buf.verify_checksums());
        for layer in buf.layers() {
            tmp_buf.push_layer(layer.clone());
        }
        for field in buf.fields() {
            tmp_buf.push_raw_field(field.clone());
        }
        tmp_buf.extend_scratch(buf.scratch());
        let prefix = TmpPrefix {
            layers: buf.layers().len(),
            fields: buf.field_count(),
            scratch: buf.scratch_len(),
        };

        // RFC 8200, Section 4.5 — "Only the value from the Offset zero
        // fragment packet is used for reassembly."
        // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
        // For IPv4 every fragment carries the same Protocol (it is part of
        // the key). `no_stop` keeps the recursive instantiation independent
        // of the caller's predicate; only full dissection gets here.
        let mut inner_stop = no_stop;
        let result = self.dispatch_loop(
            &padded,
            &mut tmp_buf,
            offset,
            padded.len(),
            DispatchHint::ByIpProtocol(protocol),
            &mut inner_stop,
            true,
        );
        // Layers dissected before an error are kept, as on the main path.
        Self::merge_tmp_tail(buf, tmp_buf, prefix, &padded, offset, aux_handle);
        result
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
        assert!(service.groups[&v6(1)].abandoned);
        assert_eq!(service.total_bytes, 0);
        // RFC 5722, Section 4 — fragments not yet received are discarded too.
        // https://www.rfc-editor.org/rfc/rfc5722#section-4
        assert_eq!(service.add_fragment(&ctx(v6(1), 0, true, 8), &[0; 8]), None);
        assert_eq!(
            service.add_fragment(&ctx(v6(1), 8, false, 8), &[0; 8]),
            None
        );
        assert_eq!(service.total_bytes, 0);
    }

    #[test]
    fn ipv6_changed_duplicate_is_an_overlap() {
        let mut service = IpReassemblyService::new();
        service.add_fragment(&ctx(v6(1), 0, true, 8), &[0; 8]);
        service.add_fragment(&ctx(v6(1), 0, true, 8), &[1; 8]);
        assert!(service.groups[&v6(1)].abandoned);
    }

    #[test]
    fn reassembled_header_must_fit_total_length() {
        // RFC 791, Section 3.2 — TL <- TDL+(IHL*4) with the first fragment's
        // header: 60 + 65,480 > 65,535.
        // https://www.rfc-editor.org/rfc/rfc791#section-3.2
        let mut service = IpReassemblyService::new();
        let first = ctx(v4(1), 0, true, 8).with_unfragmentable_len(60);
        service.add_fragment(&first, &[0; 8]);
        let data = vec![0u8; 65_472];
        let last = ctx(v4(1), 8, false, data.len()).with_unfragmentable_len(20);
        assert_eq!(service.add_fragment(&last, &data), None);
        assert!(service.groups.is_empty());
    }

    #[test]
    fn byte_budget_is_enforced_for_existing_groups() {
        let mut service = IpReassemblyService::new();
        let groups = MAX_FRAGMENT_BYTES / 65_000 + 2;
        for id in 0..groups as u32 {
            service.add_fragment(&ctx(v4(id), 0, true, 8), &[0; 8]);
        }
        // Growing existing groups evicts the oldest other ones.
        for id in 0..groups as u32 {
            service.add_fragment(&ctx(v4(id), 64_992, true, 8), &[0; 8]);
        }
        assert!(service.total_bytes <= MAX_FRAGMENT_BYTES + 65_000);
        assert!(service.groups.len() < groups);
        assert!(service.groups.contains_key(&v4(groups as u32 - 1)));
    }

    #[test]
    fn eviction_keeps_the_datagram_being_processed() {
        let mut service = IpReassemblyService::new();
        service.add_fragment(&ctx(v4(0), 0, true, 8), &[0; 8]);
        // Pretend the budget is exceeded by the only group: it is kept.
        service.total_bytes = MAX_FRAGMENT_BYTES + 1;
        service.evict_to_limits(&v4(0), false);
        assert!(service.groups.contains_key(&v4(0)));
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
            service.add_fragment(&ctx(v4(id), 0, true, 8), &[0; 8]);
            assert!(
                service
                    .add_fragment(&ctx(v4(id), 8, false, 1), &[0])
                    .is_some()
            );
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
    fn ipv4_duplicates_are_counted_once() {
        let mut service = IpReassemblyService::new();
        service.add_fragment(&ctx(v4(1), 0, true, 8), b"abcdefgh");
        service.add_fragment(&ctx(v4(1), 0, true, 8), b"ABCDEFGH");
        assert_eq!(service.groups[&v4(1)].fragments.len(), 1);
        let done = service
            .add_fragment(&ctx(v4(1), 8, false, 1), b"z")
            .unwrap();
        // RFC 791, Section 3.2 — the more recently arrived copy is used.
        // https://www.rfc-editor.org/rfc/rfc791#section-3.2
        assert_eq!(done.data, b"ABCDEFGHz");
        assert_eq!(done.fragment_count, 2);
    }

    #[test]
    fn too_many_distinct_fragments_restart_the_datagram() {
        let mut service = IpReassemblyService::new();
        // Overlapping IPv4 variants: 16- and 24-byte fragments at every
        // 8-octet offset of the first 32 KiB, all distinct.
        let half = MAX_FRAGMENTS_PER_DATAGRAM / 2;
        for i in 0..MAX_FRAGMENTS_PER_DATAGRAM {
            let len = if i < half { 16 } else { 24 };
            service.add_fragment(&ctx(v4(1), (i % half) * 8, true, len), &[0; 24][..len]);
        }
        assert_eq!(
            service.groups[&v4(1)].fragments.len(),
            MAX_FRAGMENTS_PER_DATAGRAM
        );
        // One more distinct fragment: the datagram restarts with it.
        service.add_fragment(&ctx(v4(1), 8, true, 32), &[0; 32]);
        assert_eq!(service.groups[&v4(1)].fragments, vec![8..40_usize]);
        assert_eq!(service.total_bytes, service.groups[&v4(1)].bytes());
    }

    #[test]
    fn conflicting_fragment_restarts_the_datagram() {
        // A last fragment ending before data already received cannot belong
        // to the buffered datagram: it starts a new one (key reuse).
        let mut service = IpReassemblyService::new();
        service.add_fragment(&ctx(v4(1), 16, true, 8), &[0; 8]);
        assert_eq!(
            service.add_fragment(&ctx(v4(1), 8, false, 8), &[1; 8]),
            None
        );
        assert_eq!(service.groups[&v4(1)].fragments, vec![8..16_usize]);
        let done = service
            .add_fragment(&ctx(v4(1), 0, true, 8), &[2; 8])
            .unwrap();
        assert_eq!(done.data, [[2; 8], [1; 8]].concat());
        assert_eq!(service.total_bytes, 0);
    }

    #[test]
    fn lock_poisoned_error() {
        assert_eq!(
            lock_poisoned(()),
            PacketError::InvalidHeader("ip reassembly lock poisoned")
        );
    }
}
