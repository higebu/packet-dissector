//! TCP stream reassembly logic extracted from the dissector registry.
//!
//! This module contains all TCP-specific reassembly types, constants, and the
//! `handle_tcp_segment` / `add_reassembly_fields` methods on
//! [`DissectorRegistry`](super::registry::DissectorRegistry).
//!
//! ## References
//! - RFC 9293 (TCP): <https://www.rfc-editor.org/rfc/rfc9293>
//! - RFC 7766 (DNS over TCP, pipelining): <https://www.rfc-editor.org/rfc/rfc7766>

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use packet_dissector_core::dissector::{DispatchHint, Dissector, TcpStreamContext};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{Field, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_reassembly::ReassemblyBuffer;

use super::registry::{DissectorRegistry, bound_payload_end};

/// TCP stream key: IP addresses (encoded as 16 bytes) + ports.
pub(crate) type StreamKey = ([u8; 16], [u8; 16], u16, u16);

/// Maximum allowed distance (in bytes) between the current base_seq
/// and an incoming TCP segment's sequence number before we treat it
/// as a new logical stream to avoid unbounded allocations.
const MAX_STREAM_WINDOW: usize = 1_048_576; // 1 MiB

/// Maximum number of concurrent reassembly streams. When a segment arrives
/// while more streams are buffered, the oldest streams are evicted.
/// This prevents unbounded memory growth from captures with many
/// incomplete TCP streams.
const MAX_REASSEMBLY_STREAMS: usize = 512;

/// Maximum total bytes buffered across all reassembly streams. When a
/// segment arrives while more bytes are buffered, the oldest streams are
/// evicted. This bounds worst-case memory usage to approximately this value
/// plus one MAX_STREAM_WINDOW.
const MAX_REASSEMBLY_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Maximum number of stream directions whose delivery position is
/// remembered (two per connection). Oldest entries are forgotten first.
const MAX_TRACKED_DIRECTIONS: usize = 131_072;

/// Per-stream reassembly state for TCP stream reassembly.
pub(crate) struct TcpStreamState {
    pub(crate) buffer: ReassemblyBuffer,
    /// Sequence number of the first byte in `buffer`, used as the base
    /// offset for inserting subsequent segments into the reassembly buffer.
    pub(crate) base_seq: u32,
    /// Number of TCP segments received for this stream.
    pub(crate) segment_count: u32,
    /// Minimum bytes needed for the upper-layer dissector to succeed, as
    /// reported by the last `PacketError::Truncated { expected }`. When set,
    /// re-dissection is skipped until at least this many contiguous bytes
    /// are available, avoiding O(n²) repeated parsing attempts.
    pub(crate) min_needed: Option<usize>,
}

/// Centralized TCP stream reassembly service.
pub(crate) struct TcpReassemblyService {
    pub(crate) streams: HashMap<StreamKey, TcpStreamState>,
    /// Total bytes currently buffered across all streams.
    pub(crate) total_bytes: usize,
    /// Insertion order for eviction. The front of the deque is the oldest.
    pub(crate) order: VecDeque<StreamKey>,
    /// Per direction: the sequence number right after the last byte handed
    /// to the upper-layer dissector. Bytes before it
    /// have been dissected, so a segment carrying them is a retransmission;
    /// bytes after it that precede a buffered stream are reordered data.
    ///
    /// Each entry carries the generation it was inserted with, so a stale
    /// key left in `delivered_order` never evicts a newer entry.
    delivered: HashMap<StreamKey, (u32, u64)>,
    /// Insertion order of `delivered` for eviction (may hold stale keys).
    delivered_order: VecDeque<(StreamKey, u64)>,
    /// Generation counter for `delivered` entries.
    delivered_generation: u64,
}

impl TcpReassemblyService {
    pub(crate) fn new() -> Self {
        Self {
            streams: HashMap::new(),
            total_bytes: 0,
            order: VecDeque::new(),
            delivered: HashMap::new(),
            delivered_order: VecDeque::new(),
            delivered_generation: 0,
        }
    }

    /// Evict the oldest stream other than `keep` to free resources.
    /// Returns `true` if a stream was evicted.
    fn evict_oldest(&mut self, keep: &StreamKey) -> bool {
        let mut kept = false;
        while let Some(key) = self.order.pop_front() {
            if key == *keep && self.streams.contains_key(&key) {
                // The stream being processed is never evicted before its own
                // segment is inserted; move it to the back and go on.
                if kept {
                    self.order.push_back(key);
                    return false;
                }
                kept = true;
                self.order.push_back(key);
                continue;
            }
            if let Some(state) = self.streams.remove(&key) {
                self.total_bytes = self
                    .total_bytes
                    .saturating_sub(state.buffer.bytes_received());
                return true;
            }
            // Key already removed (e.g., after successful parse); try next.
        }
        false
    }

    /// Evict the oldest streams, except `keep` (the stream of the segment
    /// being processed), until both the stream count and the byte budget
    /// are within limits. Returns the number of evicted streams.
    ///
    /// This runs before a segment is processed, so the limits may be
    /// exceeded by one new stream or one segment in between.
    pub(crate) fn evict_to_limits(&mut self, keep: &StreamKey) -> u32 {
        let mut evicted = 0;
        while (self.streams.len() > MAX_REASSEMBLY_STREAMS
            || self.total_bytes > MAX_REASSEMBLY_BYTES)
            && self.evict_oldest(keep)
        {
            evicted += 1;
        }
        evicted
    }

    /// Drop a stream's buffered data.
    fn remove_stream(&mut self, key: &StreamKey) {
        if let Some(state) = self.streams.remove(key) {
            self.total_bytes = self
                .total_bytes
                .saturating_sub(state.buffer.bytes_received());
            self.compact_order();
        }
    }

    /// Drop everything known about one direction of a connection.
    fn forget(&mut self, key: &StreamKey) {
        self.remove_stream(key);
        if self.delivered.remove(key).is_some()
            && self.delivered_order.len() > self.delivered.len() * 2 + 64
        {
            let delivered = &self.delivered;
            self.delivered_order
                .retain(|(k, g)| delivered.get(k).is_some_and(|&(_, dg)| dg == *g));
        }
    }

    /// The delivery position recorded for a direction, if any.
    fn delivered_seq(&self, key: &StreamKey) -> Option<u32> {
        self.delivered.get(key).map(|&(seq, _)| seq)
    }

    /// Set the delivery position of `key` to `seq`, inserting the entry
    /// (and evicting the oldest ones) when the direction is new.
    fn set_delivered(&mut self, key: StreamKey, seq: u32) {
        if let Some(entry) = self.delivered.get_mut(&key) {
            entry.0 = seq;
            return;
        }
        while self.delivered.len() >= MAX_TRACKED_DIRECTIONS {
            let Some((old, generation)) = self.delivered_order.pop_front() else {
                break;
            };
            if self
                .delivered
                .get(&old)
                .is_some_and(|&(_, g)| g == generation)
            {
                self.delivered.remove(&old);
            }
        }
        self.delivered_generation += 1;
        self.delivered.insert(key, (seq, self.delivered_generation));
        self.delivered_order
            .push_back((key, self.delivered_generation));
    }

    /// Record that every byte before `end` has been handed to the
    /// upper-layer dissector. The position only moves forward: dissecting a
    /// retransmission of older data does not move it back.
    fn record_delivered(&mut self, key: StreamKey, end: u32) {
        if let Some(cur) = self.delivered_seq(&key) {
            let ahead = end.wrapping_sub(cur) as usize;
            if ahead == 0 || ahead > MAX_STREAM_WINDOW {
                return;
            }
        }
        self.set_delivered(key, end);
    }

    /// Reset a stream's reassembly state (e.g., on large sequence jump).
    pub(crate) fn reset_stream(&mut self, key: &StreamKey, new_base_seq: u32) {
        if let Some(state) = self.streams.get_mut(key) {
            self.total_bytes = self
                .total_bytes
                .saturating_sub(state.buffer.bytes_received());
            state.buffer = ReassemblyBuffer::new();
            state.base_seq = new_base_seq;
            state.segment_count = 0;
            state.min_needed = None;
        }
    }

    /// Consume bytes from a stream after successful upper-layer parsing.
    pub(crate) fn consume_from_stream(&mut self, key: &StreamKey, consumed: usize) {
        let Some(state) = self.streams.get_mut(key) else {
            return;
        };
        let before = state.buffer.bytes_received();
        state.buffer.consume(consumed);
        let after = state.buffer.bytes_received();
        self.total_bytes = self.total_bytes.saturating_sub(before - after);
        state.base_seq = state.base_seq.wrapping_add(consumed as u32);
        state.segment_count = 0;
        state.min_needed = None;
        let base_seq = state.base_seq;
        if state.buffer.contiguous_len() == 0 && after == 0 {
            self.streams.remove(key);
            self.compact_order();
        }
        self.record_delivered(*key, base_seq);
    }

    /// Remove stale entries from `order` when it has grown significantly
    /// larger than `streams`, preventing unbounded growth from completed
    /// or reset streams whose keys linger in the eviction deque.
    fn compact_order(&mut self) {
        if self.order.len() > self.streams.len() * 2 + 64 {
            self.order.retain(|k| self.streams.contains_key(k));
        }
    }

    /// Insert a segment into the reassembly buffer, tracking total bytes.
    ///
    /// If the offset causes an internal overflow, the stream is reset and
    /// this segment (at `seq`) is treated as the first one.
    pub(crate) fn insert_segment(
        &mut self,
        key: &StreamKey,
        byte_offset: usize,
        data: &[u8],
        seq: u32,
    ) {
        let Some(state) = self.streams.get_mut(key) else {
            return;
        };
        let mut bytes_before = state.buffer.bytes_received();
        if state.buffer.insert(byte_offset, data).is_none() {
            // The insert failed (e.g. offset overflow). Remove the old
            // buffer's contribution from the global byte count, reset the
            // stream, and re-insert at offset 0.
            self.total_bytes = self.total_bytes.saturating_sub(bytes_before);
            state.buffer = ReassemblyBuffer::new();
            state.base_seq = seq;
            state.segment_count = 0;
            state.min_needed = None;
            let _ = state.buffer.insert(0, data);
            // After reset, bytes_before must reflect the new (empty) baseline
            // so the delta below adds the full new buffer size.
            bytes_before = 0;
        }
        let bytes_after = state.buffer.bytes_received();
        self.total_bytes += bytes_after.saturating_sub(bytes_before);
        state.segment_count += 1;
    }

    /// Insert reordered data that ends at (or overlaps) the stream's base:
    /// `data` precedes `base_seq` and becomes the new start of the buffer.
    /// `rest` is the part of the segment at or after the old base.
    fn prepend_segment(&mut self, key: &StreamKey, data: &[u8], rest: &[u8]) {
        let Some(state) = self.streams.get_mut(key) else {
            return;
        };
        let before = state.buffer.bytes_received();
        if state.buffer.prepend(data).is_none() {
            return;
        }
        let _ = state.buffer.insert(data.len(), rest);
        state.base_seq = state.base_seq.wrapping_sub(data.len() as u32);
        state.segment_count += 1;
        state.min_needed = None;
        let after = state.buffer.bytes_received();
        self.total_bytes += after.saturating_sub(before);
    }
}

/// Create a new `Mutex<TcpReassemblyService>` for use in `DissectorRegistry`.
pub(crate) fn new_tcp_reassembly() -> Mutex<TcpReassemblyService> {
    Mutex::new(TcpReassemblyService::new())
}

fn lock_poisoned(_: impl Sized) -> PacketError {
    PacketError::InvalidHeader("tcp reassembly lock poisoned")
}

impl DissectorRegistry {
    /// Handle one TCP segment for the upper-layer dissector `upper`.
    ///
    /// Applies the connection lifecycle to the reassembly state, then
    /// dissects every complete message in the segment (buffering incomplete
    /// ones when the segment was captured in full), including any body a
    /// message announces with a non-`End` dispatch hint.
    ///
    /// - SYN starts the direction afresh: stale buffered data is dropped
    ///   (RFC 9293, Section 3.5 —
    ///   <https://www.rfc-editor.org/rfc/rfc9293#section-3.5>). The stream
    ///   start (ISN+1) arrives in [`TcpStreamContext::stream_start`].
    /// - FIN ("No more data from sender", RFC 9293, Section 3.1 —
    ///   <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>) releases the
    ///   direction's state after the segment's data, unless the buffer
    ///   still has a gap that reordered segments may fill.
    /// - RST releases both directions' state after the segment's data:
    ///   RFC 9293, Section 3.10.7.4 — "All segment queues should be
    ///   flushed." <https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4>
    ///
    /// `captured_all` is `false` when the capture holds fewer bytes than the
    /// segment occupies in sequence space (snaplen truncation). Buffering
    /// them would leave a gap before the next segment and stall the stream,
    /// so the captured bytes are dissected directly without reassembly.
    pub(crate) fn handle_tcp_segment<'pkt>(
        &self,
        ctx: &TcpStreamContext,
        payload: &'pkt [u8],
        captured_all: bool,
        upper: &dyn Dissector,
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<(), PacketError> {
        if ctx.is_syn() {
            // Everything known about the direction belongs to an earlier
            // connection. The emptiness checks skip hashing the key in the
            // common case (`HashMap::remove` hashes before looking up).
            let mut service = self.tcp_reassembly.lock().map_err(lock_poisoned)?;
            if !service.streams.is_empty() || !service.delivered.is_empty() {
                service.forget(&ctx.stream_key);
            }
        }

        let result = if payload.is_empty() {
            Ok(())
        } else if captured_all {
            self.handle_tcp_reassembly(ctx, payload, upper, buf, offset)
        } else {
            self.dissect_stream_messages(upper, payload, buf, offset).1
        };

        if ctx.is_rst() {
            let mut service = self.tcp_reassembly.lock().map_err(lock_poisoned)?;
            service.forget(&ctx.stream_key);
            service.forget(&ctx.reverse_key());
        } else if ctx.is_fin() {
            // A FIN that arrives before missing data (reordering) leaves a
            // gap in the buffer; keep the state so the missing segments can
            // still complete it. Otherwise nothing more can follow the FIN.
            let mut service = self.tcp_reassembly.lock().map_err(lock_poisoned)?;
            let has_gap = service
                .streams
                .get(&ctx.stream_key)
                .is_some_and(|state| state.buffer.bytes_received() > state.buffer.contiguous_len());
            if !has_gap {
                service.forget(&ctx.stream_key);
            }
        }
        result
    }

    /// Dissect consecutive messages from the start of `data` until it is
    /// exhausted or a message fails. Returns the number of bytes consumed
    /// by complete messages and the first error, if any.
    ///
    /// Loops to handle pipelined messages — RFC 7766, Section 6.2.1 allows
    /// multiple DNS messages on a single TCP connection.
    /// <https://www.rfc-editor.org/rfc/rfc7766#section-6.2.1>
    fn dissect_stream_messages<'a>(
        &self,
        upper: &dyn Dissector,
        data: &'a [u8],
        buf: &mut DissectBuffer<'a>,
        offset: usize,
    ) -> (usize, Result<(), PacketError>) {
        let mut pos = 0;
        while pos < data.len() {
            match self.dissect_stream_message(upper, &data[pos..], buf, offset + pos) {
                Ok(n) => pos += n,
                Err(e) => return (pos, Err(e)),
            }
        }
        (pos, Ok(()))
    }

    /// Dissect one upper-layer message at the start of `data` and, when it
    /// returns a non-`End` hint, the body that follows it. Returns the
    /// number of bytes the message occupies.
    ///
    /// The body is bounded by [`DissectResult::payload_len`] (e.g. SIP's
    /// Content-Length, RFC 3261, Section 18.3 —
    /// <https://www.rfc-editor.org/rfc/rfc3261#section-18.3>), so bytes after
    /// it are dissected as the next message. Without a bound the body runs
    /// to the end of `data`.
    ///
    /// [`DissectResult::payload_len`]: packet_dissector_core::dissector::DissectResult::payload_len
    fn dissect_stream_message<'a>(
        &self,
        upper: &dyn Dissector,
        data: &'a [u8],
        buf: &mut DissectBuffer<'a>,
        offset: usize,
    ) -> Result<usize, PacketError> {
        let result = upper.dissect(data, buf, offset)?;
        let header_len = result.bytes_consumed.min(data.len());
        if header_len == 0 {
            // A dissector that reports success but consumes zero bytes
            // cannot make forward progress and would leave the stream stuck
            // retrying the same data.
            return Err(PacketError::InvalidHeader(
                "upper-layer dissector returned zero bytes_consumed on success",
            ));
        }
        if matches!(result.next, DispatchHint::End) {
            return Ok(header_len);
        }
        let end = bound_payload_end(data.len(), header_len, result.payload_len);
        self.dissect_body(&data[..end], buf, offset, header_len, result.next);
        Ok(end)
    }

    /// Run a small dispatch loop over a message body `data[pos..]`.
    ///
    /// Only the plain hint chain is followed: the embedded / decrypted
    /// payload and TCP middleware of `dispatch_loop` do not apply inside a
    /// message body.
    ///
    /// The body belongs to the message whether or not it parses, so body
    /// errors are ignored: they must not fail the enclosing message.
    fn dissect_body<'a>(
        &self,
        data: &'a [u8],
        buf: &mut DissectBuffer<'a>,
        offset: usize,
        mut pos: usize,
        mut next: DispatchHint,
    ) {
        let mut end = data.len();
        // Like `dispatch_loop`, allow one zero-consumption step for thin
        // dispatchers that only change the hint.
        let mut stalled = false;
        while pos < end {
            let Some(dissector) = self.lookup_dissector(&next) else {
                break;
            };
            let Ok(result) = dissector.dissect(&data[pos..end], buf, offset + pos) else {
                break;
            };
            if result.bytes_consumed == 0 {
                if stalled {
                    break;
                }
                stalled = true;
            } else {
                stalled = false;
            }
            pos += result.bytes_consumed;
            end = bound_payload_end(end, pos, result.payload_len);
            next = result.next;
        }
    }

    /// Reassemble a fully captured segment with the stream's buffered data
    /// and dissect every complete message.
    fn handle_tcp_reassembly<'pkt>(
        &self,
        ctx: &TcpStreamContext,
        payload: &'pkt [u8],
        upper: &dyn Dissector,
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<(), PacketError> {
        let key = ctx.stream_key;
        let mut seq = ctx.seq;
        let mut payload = payload;
        let mut offset = offset;

        // Fast path: when there is no existing buffered data for this stream,
        // try the upper dissector directly on the payload slice to avoid an
        // allocation+copy. Only fall through to the buffered path when the
        // upper dissector reports Truncated.
        let (no_buffered_data, evicted) = {
            let mut service = self.tcp_reassembly.lock().map_err(lock_poisoned)?;
            let evicted = service.evict_to_limits(&key);
            (!service.streams.contains_key(&key), evicted)
        };
        if evicted > 0 {
            Self::add_eviction_field(buf, offset, payload.len(), evicted);
        }
        if no_buffered_data {
            let (consumed, result) = self.dissect_stream_messages(upper, payload, buf, offset);
            if consumed > 0 {
                let mut service = self.tcp_reassembly.lock().map_err(lock_poisoned)?;
                service.record_delivered(key, seq.wrapping_add(consumed as u32));
            }
            match result {
                Ok(()) => return Ok(()),
                // Buffer the unparsed tail via the reassembly path below.
                Err(PacketError::Truncated { .. }) => {}
                Err(e) => return Err(e),
            }
            seq = seq.wrapping_add(consumed as u32);
            payload = &payload[consumed..];
            offset += consumed;
        }

        let mut service = self.tcp_reassembly.lock().map_err(lock_poisoned)?;

        if !service.streams.contains_key(&key) {
            service.order.push_back(key);
            service.streams.insert(
                key,
                TcpStreamState {
                    buffer: ReassemblyBuffer::new(),
                    base_seq: seq,
                    segment_count: 0,
                    min_needed: None,
                },
            );
        }

        // Handle TCP sequence number wrapping and distinguish between:
        //   - forward in-window data,
        //   - data before the buffered stream (reordering or retransmission),
        //   - large jumps or 4-tuple reuse (which reset the stream).
        let base_seq = service.streams[&key].base_seq;
        let forward = seq.wrapping_sub(base_seq) as usize;
        let backward = base_seq.wrapping_sub(seq) as usize;

        let byte_offset: usize;
        let segment: &[u8];

        if forward <= MAX_STREAM_WINDOW {
            // In-window forward data (or an exact match with base_seq).
            byte_offset = forward;
            segment = payload;
            service.insert_segment(&key, byte_offset, segment, seq);
        } else if backward <= MAX_STREAM_WINDOW {
            if backward > payload.len() {
                // Entirely before the buffered stream with a gap in between:
                // a retransmission of older data, or reordering we cannot
                // place without leaving a hole at the stream start.
                return Ok(());
            }
            // RFC 9293, Section 3.10 — segments "are generally queued and
            // processed in sequence number order", and "When a segment
            // overlaps other already received segments, we reconstruct the
            // segment to contain just the new data"
            // <https://www.rfc-editor.org/rfc/rfc9293#section-3.10>.
            //
            // Bytes before `base_seq` but at or after the delivery position
            // (the end of the last dissected message, or ISN+1 from the SYN)
            // were never handed to the upper layer: they are reordered data
            // and start the stream. Bytes already delivered, or any bytes
            // when the delivery position is unknown (the capture started
            // mid-connection), are treated as a retransmission and dropped.
            let undelivered = service
                .delivered_seq(&key)
                .or(ctx.stream_start)
                .map(|d| base_seq.wrapping_sub(d) as usize)
                .filter(|&n| n <= MAX_STREAM_WINDOW)
                .unwrap_or(0);
            let new_len = backward.min(undelivered);
            if new_len > 0 {
                let new_data = &payload[backward - new_len..backward];
                service.prepend_segment(&key, new_data, &payload[backward..]);
                byte_offset = 0;
                segment = &payload[backward - new_len..];
            } else {
                if backward == payload.len() {
                    return Ok(());
                }
                // Trim the already-seen prefix so we only insert new data
                // that aligns with base_seq at offset 0 in the buffer.
                segment = &payload[backward..];
                byte_offset = 0;
                service.insert_segment(&key, byte_offset, segment, base_seq);
            }
        } else {
            // The distance in either direction is unreasonably large:
            // assume this is a new logical stream (e.g., 4-tuple reuse or
            // large seq jump) and reset the reassembly state to avoid
            // unbounded allocations.
            service.reset_stream(&key, seq);
            byte_offset = 0;
            segment = payload;
            service.insert_segment(&key, byte_offset, segment, seq);
        }

        let Some(state) = service.streams.get(&key) else {
            return Ok(());
        };
        let available = state.buffer.contiguous_len();
        let segment_count = state.segment_count;

        // Skip re-dissection if we haven't accumulated enough contiguous
        // bytes to satisfy the upper dissector's last Truncated requirement.
        if state.min_needed.is_some_and(|needed| available < needed) || available == 0 {
            drop(service);
            Self::add_reassembly_fields(
                buf,
                offset,
                payload.len(),
                segment_count,
                upper.short_name(),
            );
            return Ok(());
        }

        // Copy contiguous data while holding the lock. The copy is required
        // because the upper-layer dissector call below must not hold the
        // reassembly mutex (it may re-enter the registry). We copy only the
        // contiguous prefix — not the entire backing buffer.
        let contiguous_data: Vec<u8> = state.buffer.data()[..available].to_vec();
        // The buffer contains only the current segment's data when this is
        // the first segment (count == 1), it was inserted at offset 0
        // (no backward trim gap), and the received bytes match exactly the
        // inserted segment length (not the original payload length, which
        // may differ after backward trimming).
        let buffer_only_current_segment = state.segment_count == 1
            && byte_offset == 0
            && state.buffer.bytes_received() == segment.len()
            && segment.len() == payload.len();

        // Release the lock before calling the upper-layer dissector
        drop(service);

        // Use the real packet offset when the reassembled data comes entirely
        // from the current TCP segment so that the upper layer's field ranges
        // are contiguous with the TCP layer. For data spanning multiple
        // segments, use synthetic offset 0 since the bytes do not correspond
        // to a contiguous region in the current packet.
        let upper_offset = if buffer_only_current_segment {
            offset
        } else {
            0
        };

        // Because `contiguous_data` is a local buffer, each message is
        // dissected into a temporary DissectBuffer and merged into the main
        // buf. The contiguous data is stored in aux_data so Bytes/Str fields
        // can be remapped to a stable location with the correct lifetime.
        let aux_handle = buf.push_aux_data(&contiguous_data);
        let mut pos = 0;
        while pos < contiguous_data.len() {
            let mut tmp_buf = DissectBuffer::new();
            tmp_buf.set_verify_checksums(buf.verify_checksums());
            match self.dissect_stream_message(
                upper,
                &contiguous_data[pos..],
                &mut tmp_buf,
                upper_offset + pos,
            ) {
                Ok(consumed) => {
                    self.tcp_reassembly
                        .lock()
                        .map_err(lock_poisoned)?
                        .consume_from_stream(&key, consumed);
                    Self::merge_tmp_buf(buf, tmp_buf, &contiguous_data, 0, aux_handle);
                    pos += consumed;
                }
                Err(PacketError::Truncated { expected, .. }) => {
                    // Not enough data yet — record the minimum needed bytes so
                    // subsequent segments can skip re-dissection until enough
                    // contiguous data has accumulated.
                    let mut service = self.tcp_reassembly.lock().map_err(lock_poisoned)?;
                    if let Some(state) = service.streams.get_mut(&key) {
                        state.min_needed = Some(expected);
                    }
                    drop(service);
                    // Only add reassembly fields if no message was parsed yet
                    // from this segment (i.e., the first iteration).
                    if pos == 0 {
                        Self::add_reassembly_fields(
                            buf,
                            offset,
                            payload.len(),
                            segment_count,
                            upper.short_name(),
                        );
                    }
                    break;
                }
                Err(e) => {
                    // The buffered bytes cannot be parsed. Drop them so later
                    // segments of this direction start afresh instead of
                    // re-parsing the same bad prefix forever.
                    self.tcp_reassembly
                        .lock()
                        .map_err(lock_poisoned)?
                        .remove_stream(&key);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Report on the TCP layer that `evicted` buffered streams were dropped
    /// to stay within the reassembly memory limits.
    fn add_eviction_field(
        buf: &mut DissectBuffer<'_>,
        offset: usize,
        data_len: usize,
        evicted: u32,
    ) {
        use packet_dissector_tcp::{FD_REASSEMBLY_EVICTED, FIELD_DESCRIPTORS as TCP_FD};

        buf.append_fields_to_layer(
            "TCP",
            &[Field {
                descriptor: &TCP_FD[FD_REASSEMBLY_EVICTED],
                value: FieldValue::U32(evicted),
                range: offset..offset + data_len,
            }],
        );
    }

    /// Add reassembly status fields to both the TCP layer and a thin
    /// upper-protocol layer so that protocol filters (e.g., `-p dns`)
    /// match intermediate segments.
    pub(crate) fn add_reassembly_fields(
        buf: &mut DissectBuffer<'_>,
        offset: usize,
        data_len: usize,
        segment_count: u32,
        upper_short_name: &'static str,
    ) {
        use packet_dissector_tcp::{
            FD_REASSEMBLY_IN_PROGRESS, FD_SEGMENT_COUNT, FIELD_DESCRIPTORS as TCP_FD,
        };

        let range = offset..offset + data_len;

        // Append reassembly fields to the TCP layer by extending its field
        // range. The fields are pushed into the flat buffer immediately after
        // the TCP layer's existing fields.
        buf.append_fields_to_layer(
            "TCP",
            &[
                Field {
                    descriptor: &TCP_FD[FD_REASSEMBLY_IN_PROGRESS],
                    value: FieldValue::U8(1),
                    range: range.clone(),
                },
                Field {
                    descriptor: &TCP_FD[FD_SEGMENT_COUNT],
                    value: FieldValue::U32(segment_count),
                    range: range.clone(),
                },
            ],
        );

        // Add a thin upper-protocol layer with reassembly metadata so that
        // protocol filters (e.g., `bask read -p dns`) match this packet.
        buf.begin_layer(upper_short_name, None, TCP_FD, range.clone());
        buf.push_field(
            &TCP_FD[FD_REASSEMBLY_IN_PROGRESS],
            FieldValue::U8(1),
            range.clone(),
        );
        buf.push_field(
            &TCP_FD[FD_SEGMENT_COUNT],
            FieldValue::U32(segment_count),
            range,
        );
        buf.end_layer();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> StreamKey {
        ([0; 16], [1; 16], port, 80)
    }

    fn add_stream(service: &mut TcpReassemblyService, k: StreamKey, data: &[u8]) {
        service.order.push_back(k);
        service.streams.insert(
            k,
            TcpStreamState {
                buffer: ReassemblyBuffer::new(),
                base_seq: 0,
                segment_count: 0,
                min_needed: None,
            },
        );
        service.insert_segment(&k, 0, data, 0);
    }

    #[test]
    fn eviction_skips_the_stream_being_processed() {
        let mut service = TcpReassemblyService::new();
        for port in 0..=MAX_REASSEMBLY_STREAMS as u16 {
            add_stream(&mut service, key(port), b"x");
        }
        // The oldest stream is the one being processed: the next one goes.
        assert_eq!(service.evict_to_limits(&key(0)), 1);
        assert!(service.streams.contains_key(&key(0)));
        assert!(!service.streams.contains_key(&key(1)));
    }

    #[test]
    fn eviction_stops_when_only_the_kept_stream_remains() {
        let mut service = TcpReassemblyService::new();
        add_stream(&mut service, key(0), b"x");
        assert!(!service.evict_oldest(&key(0)));
        assert!(service.streams.contains_key(&key(0)));
    }

    #[test]
    fn delivered_positions_are_bounded_and_generation_checked() {
        let mut service = TcpReassemblyService::new();
        // Forget + re-record leaves a stale deque entry for key(0).
        service.record_delivered(key(0), 10);
        service.forget(&key(0));
        service.record_delivered(key(0), 20);
        for port in 1..MAX_TRACKED_DIRECTIONS as u32 {
            let k = ([0; 16], [2; 16], (port >> 16) as u16, port as u16);
            service.set_delivered(k, port);
        }
        assert_eq!(service.delivered.len(), MAX_TRACKED_DIRECTIONS);
        // The stale entry is popped without removing the live key(0) entry;
        // the live entry is the oldest and is evicted next.
        service.set_delivered(key(1), 1);
        assert_eq!(service.delivered.len(), MAX_TRACKED_DIRECTIONS);
        assert_eq!(service.delivered_seq(&key(0)), None);
        assert_eq!(service.delivered_seq(&key(1)), Some(1));
    }

    #[test]
    fn delivered_position_only_moves_forward() {
        let mut service = TcpReassemblyService::new();
        service.record_delivered(key(0), 1000);
        service.record_delivered(key(0), 900);
        assert_eq!(service.delivered_seq(&key(0)), Some(1000));
        service.record_delivered(key(0), 1100);
        assert_eq!(service.delivered_seq(&key(0)), Some(1100));
    }

    #[test]
    fn forget_compacts_delivered_order() {
        let mut service = TcpReassemblyService::new();
        for port in 0..200 {
            service.record_delivered(key(port), 1);
        }
        for port in 0..200 {
            service.forget(&key(port));
        }
        assert!(service.delivered.is_empty());
        assert!(service.delivered_order.len() <= 64);
    }

    #[test]
    fn remove_stream_compacts_order() {
        let mut service = TcpReassemblyService::new();
        for port in 0..200 {
            add_stream(&mut service, key(port), b"x");
        }
        for port in 0..200 {
            service.remove_stream(&key(port));
        }
        assert_eq!(service.total_bytes, 0);
        assert!(service.order.len() <= 64);
    }

    #[test]
    fn insert_overflow_resets_stream() {
        let mut service = TcpReassemblyService::new();
        add_stream(&mut service, key(0), b"abc");
        service.insert_segment(&key(0), usize::MAX, b"de", 77);
        let state = &service.streams[&key(0)];
        assert_eq!(state.base_seq, 77);
        assert_eq!(state.buffer.contiguous_len(), 2);
        assert_eq!(service.total_bytes, 2);
    }

    #[test]
    fn operations_on_unknown_stream_are_noops() {
        let mut service = TcpReassemblyService::new();
        service.insert_segment(&key(0), 0, b"x", 0);
        service.prepend_segment(&key(0), b"x", b"");
        service.consume_from_stream(&key(0), 1);
        service.reset_stream(&key(0), 5);
        assert!(service.streams.is_empty());
        assert_eq!(service.total_bytes, 0);
    }

    #[test]
    fn lock_poisoned_error() {
        assert_eq!(
            lock_poisoned(()),
            PacketError::InvalidHeader("tcp reassembly lock poisoned")
        );
    }
}
