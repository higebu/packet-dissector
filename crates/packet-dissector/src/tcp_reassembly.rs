//! TCP stream reassembly logic extracted from the dissector registry.
//!
//! This module contains all TCP-specific reassembly types, constants, and the
//! `handle_tcp_reassembly` / `add_reassembly_fields` methods on
//! [`DissectorRegistry`](super::registry::DissectorRegistry).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use packet_dissector_core::dissector::{DispatchHint, DissectResult, TcpStreamContext};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{Field, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_reassembly::ReassemblyBuffer;

use super::registry::DissectorRegistry;

/// TCP stream key: IP addresses (encoded as 16 bytes) + ports.
pub(crate) type StreamKey = ([u8; 16], [u8; 16], u16, u16);

/// Maximum allowed distance (in bytes) between the current base_seq
/// and an incoming TCP segment's sequence number before we treat it
/// as a new logical stream to avoid unbounded allocations.
const MAX_STREAM_WINDOW: usize = 1_048_576; // 1 MiB

/// Maximum number of concurrent reassembly streams before the oldest
/// stream is evicted. This prevents unbounded memory growth from captures
/// with many incomplete TCP streams.
const MAX_REASSEMBLY_STREAMS: usize = 512;

/// Maximum total bytes buffered across all reassembly streams before the
/// oldest stream is evicted. This bounds worst-case memory usage to
/// approximately this value plus one MAX_STREAM_WINDOW.
const MAX_REASSEMBLY_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Per-stream reassembly state for TCP stream reassembly.
pub(crate) struct TcpStreamState {
    pub(crate) buffer: ReassemblyBuffer,
    /// The first TCP sequence number seen for this stream, used as the base
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
}

impl TcpReassemblyService {
    pub(crate) fn new() -> Self {
        Self {
            streams: HashMap::new(),
            total_bytes: 0,
            order: VecDeque::new(),
        }
    }

    /// Evict the oldest stream to free resources.
    fn evict_oldest(&mut self) {
        while let Some(key) = self.order.front().copied() {
            self.order.pop_front();
            if let Some(state) = self.streams.remove(&key) {
                self.total_bytes = self
                    .total_bytes
                    .saturating_sub(state.buffer.bytes_received());
                return;
            }
            // Key already removed (e.g., after successful parse); try next.
        }
    }

    /// Ensure capacity by evicting oldest streams until both stream count
    /// and byte budget are within limits.
    pub(crate) fn ensure_capacity(&mut self) {
        while self.streams.len() >= MAX_REASSEMBLY_STREAMS
            || self.total_bytes > MAX_REASSEMBLY_BYTES
        {
            if self.order.is_empty() {
                break;
            }
            self.evict_oldest();
        }
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
        if let Some(state) = self.streams.get_mut(key) {
            let before = state.buffer.bytes_received();
            state.buffer.consume(consumed);
            let after = state.buffer.bytes_received();
            self.total_bytes = self.total_bytes.saturating_sub(before - after);
            state.base_seq = state.base_seq.wrapping_add(consumed as u32);
            state.segment_count = 0;
            state.min_needed = None;
            if state.buffer.contiguous_len() == 0 && after == 0 {
                self.streams.remove(key);
                self.compact_order();
            }
        }
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
}

/// Create a new `Mutex<TcpReassemblyService>` for use in `DissectorRegistry`.
pub(crate) fn new_tcp_reassembly() -> Mutex<TcpReassemblyService> {
    Mutex::new(TcpReassemblyService::new())
}

impl DissectorRegistry {
    /// Handle TCP stream reassembly for a single segment.
    ///
    /// Returns `Some(DissectResult)` when the upper dissector completed on
    /// the fast path (no buffering needed), allowing the dispatch loop to
    /// propagate the result and continue chaining.
    ///
    /// Returns `None` when reassembly is in progress (buffered path and more
    /// data is needed), when the payload is empty, or when the upper-layer
    /// dissector has successfully parsed via the buffered path and no further
    /// dispatching is required (the dispatch loop terminates).
    pub(crate) fn handle_tcp_reassembly<'pkt>(
        &self,
        ctx: &TcpStreamContext,
        payload: &'pkt [u8],
        upper: &dyn packet_dissector_core::dissector::Dissector,
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<Option<DissectResult>, PacketError> {
        let mut ctx = ctx.clone();
        let mut payload = payload;
        let mut offset = offset;
        loop {
            if payload.is_empty() {
                return Ok(None);
            }

            // Fast path: when there is no existing buffered data for this stream,
            // try the upper dissector directly on the payload slice to avoid an
            // allocation+copy. Only fall through to the buffered path when the
            // upper dissector reports Truncated.
            //
            // Loop to handle pipelined messages — RFC 7766, Section 6.2.1 allows
            // multiple DNS messages on a single TCP connection.
            // <https://www.rfc-editor.org/rfc/rfc7766#section-6.2.1>
            {
                let service = self
                    .tcp_reassembly
                    .lock()
                    .map_err(|_| PacketError::InvalidHeader("tcp reassembly lock poisoned"))?;
                let no_buffered_data = !service.streams.contains_key(&ctx.stream_key);
                drop(service);

                if no_buffered_data {
                    let mut fast_remaining = payload;
                    let mut fast_offset = offset;
                    let mut last_result: Option<DissectResult> = None;
                    loop {
                        if fast_remaining.is_empty() {
                            break;
                        }
                        match upper.dissect(fast_remaining, buf, fast_offset) {
                            Ok(result) => {
                                let consumed = result.bytes_consumed.min(fast_remaining.len());
                                if consumed == 0 {
                                    return Err(PacketError::InvalidHeader(
                                        "upper dissector returned zero bytes_consumed on success",
                                    ));
                                }
                                fast_remaining = &fast_remaining[consumed..];
                                fast_offset += consumed;
                                // When the dissector signals a non-End hint (e.g.,
                                // ByContentType for an HTTP body), the remaining
                                // bytes belong to a different protocol — not another
                                // message for this dissector. Stop the pipelining
                                // loop and delegate to the sub-dissector.
                                let done = !matches!(result.next, DispatchHint::End);
                                last_result = Some(result);
                                if done {
                                    break;
                                }
                            }
                            Err(PacketError::Truncated { .. }) => {
                                // Fall through to the buffered reassembly path below
                                // for any remaining unparsed data.
                                break;
                            }
                            Err(e) => return Err(e),
                        }
                    }

                    // Dispatch remaining bytes to a sub-dissector when the upper
                    // dissector indicated a non-End hint (e.g., HTTP with
                    // Content-Type dispatch).
                    if let Some(ref last) = last_result {
                        if !fast_remaining.is_empty() && !matches!(last.next, DispatchHint::End) {
                            let sub = match &last.next {
                                DispatchHint::ByContentType(ct) => self.get_by_content_type(ct),
                                _ => None,
                            };
                            if let Some(sub_dissector) = sub {
                                if let Ok(_sub_result) =
                                    sub_dissector.dissect(fast_remaining, buf, fast_offset)
                                {
                                }
                            }
                            // Whether or not the sub-dissector consumed the body,
                            // the pipelining loop is finished — return the result.
                            return Ok(last_result);
                        }
                    }
                    let total_consumed = payload.len() - fast_remaining.len();
                    if let Some(result) = last_result {
                        if fast_remaining.is_empty() {
                            return Ok(Some(result));
                        }
                        // Some messages parsed but trailing data is incomplete.
                        // Buffer the remaining data via the normal reassembly path.
                        // We adjust the context's seq to reflect the consumed prefix
                        // so that the buffered path starts at the right position.
                        ctx = TcpStreamContext {
                            stream_key: ctx.stream_key,
                            seq: ctx.seq.wrapping_add(total_consumed as u32),
                            payload_len: fast_remaining.len(),
                        };
                        payload = fast_remaining;
                        offset = fast_offset;
                        continue;
                    }
                    // parsed_any == false: first dissect returned Truncated,
                    // fall through to the buffered reassembly path below.
                }
            }

            let mut service = self
                .tcp_reassembly
                .lock()
                .map_err(|_| PacketError::InvalidHeader("tcp reassembly lock poisoned"))?;

            // Evict oldest streams when capacity limits are exceeded (stream count).
            if !service.streams.contains_key(&ctx.stream_key) {
                service.ensure_capacity();
                service.order.push_back(ctx.stream_key);
                service.streams.insert(
                    ctx.stream_key,
                    TcpStreamState {
                        buffer: ReassemblyBuffer::new(),
                        base_seq: ctx.seq,
                        segment_count: 0,
                        min_needed: None,
                    },
                );
            }

            // Handle TCP sequence number wrapping and distinguish between:
            //   - forward in-window data,
            //   - small backward offsets (retransmissions / slight reordering),
            //   - large jumps or 4-tuple reuse (which reset the stream).
            let seq = ctx.seq;
            let base_seq = service.streams[&ctx.stream_key].base_seq;
            let forward = seq.wrapping_sub(base_seq) as usize;
            let backward = base_seq.wrapping_sub(seq) as usize;

            let byte_offset: usize;
            let segment: &[u8];

            if forward == 0 {
                // Exact match with the current base sequence number.
                byte_offset = 0;
                segment = payload;
            } else if forward <= MAX_STREAM_WINDOW {
                // Normal in-window forward data.
                byte_offset = forward;
                segment = payload;
            } else if backward <= MAX_STREAM_WINDOW {
                // Slightly behind the current base_seq: treat as retransmission
                // or overlapping out-of-order data within the window.
                if backward >= payload.len() {
                    // Entirely before the current window (pure retransmission of
                    // already-buffered/consumed data). Ignore this segment.
                    return Ok(None);
                }
                // Trim the already-seen prefix so we only insert new data that
                // aligns with base_seq at offset 0 in the buffer.
                segment = &payload[backward..];
                byte_offset = 0;
            } else {
                // The distance in either direction is unreasonably large:
                // assume this is a new logical stream (e.g., 4-tuple reuse or
                // large seq jump) and reset the reassembly state to avoid
                // unbounded allocations.
                service.reset_stream(&ctx.stream_key, seq);
                byte_offset = 0;
                segment = payload;
            }

            // Insert the data into the reassembly buffer. If the offset causes
            // an internal overflow (signaled by None), reset the stream state
            // and treat this segment as the first one.
            service.insert_segment(&ctx.stream_key, byte_offset, segment, seq);

            // Enforce byte budget after inserting new data — existing streams can
            // grow total_bytes beyond MAX_REASSEMBLY_BYTES without this check.
            service.ensure_capacity();

            // The current stream may have been evicted by ensure_capacity above.
            // If so, no reassembly state is retained for this segment, so we
            // skip adding reassembly-in-progress fields to avoid misleading
            // consumers.
            let Some(state) = service.streams.get(&ctx.stream_key) else {
                drop(service);
                return Ok(None);
            };
            let available = state.buffer.contiguous_len();

            // Skip re-dissection if we haven't accumulated enough contiguous
            // bytes to satisfy the upper dissector's last Truncated requirement.
            if let Some(needed) = state.min_needed {
                if available < needed {
                    let segment_count = state.segment_count;
                    drop(service);
                    Self::add_reassembly_fields(
                        buf,
                        offset,
                        payload.len(),
                        segment_count,
                        upper.short_name(),
                    );
                    return Ok(None);
                }
            }

            // Copy contiguous data while holding the lock. The copy is required
            // because the upper-layer dissector call below must not hold the
            // reassembly mutex (it may re-enter the registry). We copy only the
            // contiguous prefix — not the entire backing buffer.
            let contiguous_data: Vec<u8> = state.buffer.data()[..available].to_vec();
            let segment_count = state.segment_count;
            // The buffer contains only the current segment's data when this is
            // the first segment (count == 1), it was inserted at offset 0
            // (no backward trim gap), and the received bytes match exactly the
            // inserted segment length (not the original payload length, which
            // may differ after backward trimming).
            let buffer_only_current_segment = state.segment_count == 1
                && byte_offset == 0
                && state.buffer.bytes_received() == segment.len();
            let key = ctx.stream_key;

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

            // Try to dissect with available contiguous data. Loop to handle
            // pipelined messages — RFC 7766, Section 6.2.1 allows multiple DNS
            // messages on a single TCP connection.
            // <https://www.rfc-editor.org/rfc/rfc7766#section-6.2.1>
            //
            // Because `contiguous_data` is a local buffer, we dissect into a
            // temporary DissectBuffer and merge layers/fields into the main buf.
            // Store the contiguous data in aux_data so Bytes/Str fields can be
            // remapped to a stable location with the correct lifetime.
            let aux_handle = buf.push_aux_data(&contiguous_data);
            let mut remaining = &contiguous_data[..];
            let mut cur_offset = upper_offset;
            loop {
                if remaining.is_empty() {
                    break;
                }
                let mut tmp_buf = DissectBuffer::new();
                match upper.dissect(remaining, &mut tmp_buf, cur_offset) {
                    Ok(result) => {
                        // Upper layer successfully parsed — consume what it used.
                        // Clamp to the available remaining length to guard against a
                        // buggy upper-layer dissector returning a too-large value,
                        // which would otherwise panic inside ReassemblyBuffer::consume().
                        let consumed = result.bytes_consumed.min(remaining.len());
                        if consumed == 0 {
                            // A dissector that reports success but consumes zero bytes
                            // cannot make forward progress and would leave the stream
                            // stuck retrying the same data. Treat this as an error.
                            return Err(PacketError::InvalidHeader(
                                "upper-layer dissector returned zero bytes_consumed on success",
                            ));
                        }
                        {
                            let mut service = self.tcp_reassembly.lock().map_err(|_| {
                                PacketError::InvalidHeader("tcp reassembly lock poisoned")
                            })?;
                            service.consume_from_stream(&key, consumed);
                        }
                        // Merge temporary buffer layers and fields into main buf,
                        // remapping Bytes/Str from `contiguous_data` to aux_data.
                        Self::merge_tmp_buf(buf, tmp_buf, &contiguous_data, 0, aux_handle);
                        remaining = &remaining[consumed..];
                        // in the same segment or reassembled stream use contiguous offsets.
                        cur_offset += consumed;

                        // When the dissector signals a non-End hint (e.g.,
                        // ByContentType), the remaining bytes belong to a
                        // sub-protocol — not another message for this dissector.
                        if !matches!(result.next, DispatchHint::End) {
                            if !remaining.is_empty() {
                                let sub = match &result.next {
                                    DispatchHint::ByContentType(ct) => self.get_by_content_type(ct),
                                    _ => None,
                                };
                                if let Some(sub_dissector) = sub {
                                    let mut sub_buf = DissectBuffer::new();
                                    if let Ok(sub_result) =
                                        sub_dissector.dissect(remaining, &mut sub_buf, cur_offset)
                                    {
                                        let sub_consumed =
                                            sub_result.bytes_consumed.min(remaining.len());
                                        {
                                            let mut service =
                                                self.tcp_reassembly.lock().map_err(|_| {
                                                    PacketError::InvalidHeader(
                                                        "tcp reassembly lock poisoned",
                                                    )
                                                })?;
                                            service.consume_from_stream(&key, sub_consumed);
                                        }
                                        Self::merge_tmp_buf(
                                            buf,
                                            sub_buf,
                                            &contiguous_data,
                                            0,
                                            aux_handle,
                                        );
                                    }
                                }
                            }
                            break;
                        }
                    }
                    Err(PacketError::Truncated { expected, .. }) => {
                        // Not enough data yet — record the minimum needed bytes so
                        // subsequent segments can skip re-dissection until enough
                        // contiguous data has accumulated.
                        {
                            let mut service = self.tcp_reassembly.lock().map_err(|_| {
                                PacketError::InvalidHeader("tcp reassembly lock poisoned")
                            })?;
                            if let Some(state) = service.streams.get_mut(&key) {
                                state.min_needed = Some(expected);
                            }
                        }
                        // Only add reassembly fields if no message was parsed yet
                        // from this segment (i.e., the first iteration).
                        if remaining.len() == contiguous_data.len() {
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
                    Err(e) => return Err(e),
                }
            }
            return Ok(None);
        } // end loop
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
