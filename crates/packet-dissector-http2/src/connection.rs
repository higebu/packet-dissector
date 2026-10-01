//! Per-connection HTTP/2 decoding state.
//!
//! HPACK decoding is stateful. RFC 9113, Section 4.3.1 — "Field compression
//! is stateful. Each endpoint has an HPACK encoder context and an HPACK
//! decoder context that are used for encoding and decoding all field blocks
//! on a connection." (<https://www.rfc-editor.org/rfc/rfc9113#section-4.3.1>),
//! and RFC 7541, Section 2.2 — "To decompress header blocks, a decoder only
//! needs to maintain a dynamic table (see Section 2.3.2) as a decoding
//! context." (<https://www.rfc-editor.org/rfc/rfc7541#section-2.2>). A header
//! block may also span a HEADERS or PUSH_PROMISE frame and following
//! CONTINUATION frames (RFC 9113, Section 4.3 —
//! <https://www.rfc-editor.org/rfc/rfc9113#section-4.3>).
//!
//! ## References
//! - RFC 9113: <https://www.rfc-editor.org/rfc/rfc9113>
//! - RFC 7541: <https://www.rfc-editor.org/rfc/rfc7541>

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};

use packet_dissector_core::dissector::{
    DissectResult, Dissector, ProtocolLayer, SpecReference, TcpStreamContext, TcpStreamKey,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::FieldDescriptor;
use packet_dissector_core::packet::DissectBuffer;

use crate::hpack::DynamicTable;
use crate::{CONNECTION_PREFACE, FIELD_DESCRIPTORS, Http2Dissector, REFERENCES, dissect_frame};

/// Initial HPACK dynamic table size: the initial value of
/// SETTINGS_HEADER_TABLE_SIZE (4,096 octets).
///
/// RFC 9113, Section 6.5.2 — <https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2>;
/// the table size then changes only through Dynamic Table Size Updates
/// (RFC 7541, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc7541#section-4.2>).
const INITIAL_TABLE_SIZE: usize = 4096;

/// Maximum number of stream directions with decoding state (two per
/// connection). The oldest ones are forgotten first.
const MAX_TRACKED_DIRECTIONS: usize = 65_536;

/// Maximum number of octets held in dynamic tables and pending header
/// blocks across all tracked directions. The oldest directions are
/// forgotten first when a direction grows past it.
const MAX_TRACKED_BYTES: usize = 64 * 1024 * 1024;

/// Maximum size of a header block kept while waiting for CONTINUATION
/// frames. A larger block stops the direction's HPACK tracking.
const MAX_PENDING_BLOCK: usize = 256 * 1024;

/// A header block whose END_HEADERS frame has not arrived yet.
#[derive(Debug)]
struct PendingBlock {
    stream_id: u32,
    data: Vec<u8>,
}

/// Decoding state of one direction of an HTTP/2 connection.
#[derive(Debug)]
pub(crate) struct DirectionState {
    /// HPACK dynamic table of the direction's encoder, or `None` once the
    /// table can no longer be followed (a header block was lost or failed
    /// to decode). Dynamic references are then reported as unresolved
    /// rather than guessed.
    table: Option<DynamicTable>,
    /// Header block waiting for CONTINUATION frames.
    pending: Option<PendingBlock>,
}

impl DirectionState {
    fn new() -> Self {
        Self {
            table: Some(DynamicTable::new(INITIAL_TABLE_SIZE)),
            pending: None,
        }
    }

    /// Octets held by the direction: the dynamic table size (RFC 7541,
    /// Section 4.1 — <https://www.rfc-editor.org/rfc/rfc7541#section-4.1>)
    /// and the pending header block.
    pub(crate) fn memory(&self) -> usize {
        self.table.as_ref().map_or(0, DynamicTable::size)
            + self.pending.as_ref().map_or(0, |b| b.data.len())
    }

    /// The dynamic table, if it is still followed.
    pub(crate) fn table(&mut self) -> Option<&mut DynamicTable> {
        self.table.as_mut()
    }

    /// Stop following the dynamic table for the rest of the connection,
    /// dropping any pending header block.
    pub(crate) fn desynchronize(&mut self) {
        self.table = None;
        self.pending = None;
    }

    /// Keep the first fragment of a header block that continues in
    /// CONTINUATION frames.
    pub(crate) fn begin_block(&mut self, stream_id: u32, fragment: &[u8]) {
        self.pending = Some(PendingBlock {
            stream_id,
            data: fragment.to_vec(),
        });
        self.limit_pending();
    }

    /// Append a CONTINUATION fragment to the pending block of `stream_id`.
    /// Returns the whole block when `end_headers` completes it.
    ///
    /// A CONTINUATION frame without a matching pending block continues a
    /// block whose start was not seen: the dynamic table can no longer be
    /// followed.
    pub(crate) fn continue_block(
        &mut self,
        stream_id: u32,
        fragment: &[u8],
        end_headers: bool,
    ) -> Option<Vec<u8>> {
        let Some(mut block) = self.pending.take().filter(|b| b.stream_id == stream_id) else {
            self.desynchronize();
            return None;
        };
        block.data.extend_from_slice(fragment);
        if end_headers {
            return Some(block.data);
        }
        self.pending = Some(block);
        self.limit_pending();
        None
    }

    /// A frame other than CONTINUATION arrived: a pending header block can
    /// no longer be completed, so its dynamic table changes are lost.
    ///
    /// RFC 9113, Section 6.2 — "A HEADERS frame without the END_HEADERS flag
    /// set MUST be followed by a CONTINUATION frame for the same stream." —
    /// <https://www.rfc-editor.org/rfc/rfc9113#section-6.2>
    pub(crate) fn interrupt_block(&mut self) {
        if self.pending.take().is_some() {
            self.desynchronize();
        }
    }

    fn limit_pending(&mut self) {
        if self
            .pending
            .as_ref()
            .is_some_and(|b| b.data.len() > MAX_PENDING_BLOCK)
        {
            self.pending = None;
            self.desynchronize();
        }
    }
}

/// Decoding state of the tracked stream directions.
///
/// Holds at most `capacity` entries and `byte_budget` octets
/// ([`DirectionState::memory`]); the oldest directions are forgotten first.
/// Each entry carries the generation it was inserted with, so a stale key
/// left in `order` never evicts a newer entry.
struct Directions {
    states: HashMap<TcpStreamKey, (DirectionState, u64)>,
    order: VecDeque<(TcpStreamKey, u64)>,
    generation: u64,
    capacity: usize,
    /// Sum of [`DirectionState::memory`] over all entries.
    total_bytes: usize,
    byte_budget: usize,
}

impl Directions {
    fn new(capacity: usize, byte_budget: usize) -> Self {
        Self {
            states: HashMap::new(),
            order: VecDeque::new(),
            generation: 0,
            capacity,
            total_bytes: 0,
            byte_budget,
        }
    }

    fn contains(&self, key: &TcpStreamKey) -> bool {
        !self.states.is_empty() && self.states.contains_key(key)
    }

    /// Start a fresh state for `key`, replacing any earlier one.
    fn start(&mut self, key: TcpStreamKey) {
        self.remove(&key);
        while self.states.len() >= self.capacity {
            let Some((old, generation)) = self.order.pop_front() else {
                break;
            };
            if self.is_live(&old, generation) {
                self.remove(&old);
            }
        }
        self.generation += 1;
        self.states
            .insert(key, (DirectionState::new(), self.generation));
        self.order.push_back((key, self.generation));
    }

    fn is_live(&self, key: &TcpStreamKey, generation: u64) -> bool {
        self.states.get(key).is_some_and(|(_, g)| *g == generation)
    }

    fn get_mut(&mut self, key: &TcpStreamKey) -> Option<&mut DirectionState> {
        self.states.get_mut(key).map(|(state, _)| state)
    }

    /// Record that the state of `key` changed from `before` to `after`
    /// octets, then forget the oldest other directions while the total is
    /// over the byte budget.
    fn account(&mut self, key: &TcpStreamKey, before: usize, after: usize) {
        self.total_bytes = (self.total_bytes + after).saturating_sub(before);
        let mut remaining = self.order.len();
        while self.total_bytes > self.byte_budget && remaining > 0 {
            remaining -= 1;
            let Some((old, generation)) = self.order.pop_front() else {
                break;
            };
            if !self.is_live(&old, generation) {
                continue;
            }
            if old == *key {
                self.order.push_back((old, generation));
                continue;
            }
            self.remove(&old);
        }
    }

    fn remove(&mut self, key: &TcpStreamKey) {
        if self.states.is_empty() {
            return;
        }
        let Some((state, _)) = self.states.remove(key) else {
            return;
        };
        self.total_bytes = self.total_bytes.saturating_sub(state.memory());
        // Drop stale keys once they dominate the eviction order.
        if self.order.len() > self.states.len() * 2 + 64 {
            let states = &self.states;
            self.order
                .retain(|(k, g)| states.get(k).is_some_and(|(_, sg)| sg == g));
        }
    }
}

/// HTTP/2 dissector that keeps per-connection decoding state for TCP
/// streams.
///
/// Called through [`Dissector::dissect_tcp_stream`], it tracks every
/// connection whose client connection preface it sees (RFC 9113,
/// Section 3.4 — <https://www.rfc-editor.org/rfc/rfc9113#section-3.4>):
///
/// - each direction has its own HPACK dynamic table (RFC 7541, Section 2.2 —
///   <https://www.rfc-editor.org/rfc/rfc7541#section-2.2>), so indexed
///   fields and literal names that refer to earlier header blocks are
///   resolved;
/// - a header block split across HEADERS / PUSH_PROMISE and CONTINUATION
///   frames is decoded as a whole on the frame that ends it (RFC 9113,
///   Section 4.3 — <https://www.rfc-editor.org/rfc/rfc9113#section-4.3>).
///
/// When a header block is lost or fails to decode, the direction's dynamic
/// table can no longer be followed; its references are then reported as
/// unresolved (with their HPACK index) for the rest of the connection.
///
/// Connections whose preface was not seen, and [`Dissector::dissect`]
/// calls, are decoded frame by frame like [`Http2Dissector`].
///
/// Every [`Dissector::dissect_tcp_stream`] call consults the tracked
/// connections and calls [`DissectBuffer::mark_cross_packet_state`];
/// [`Dissector::dissect`] does not.
pub struct Http2ConnectionDissector {
    directions: Mutex<Directions>,
}

impl Http2ConnectionDissector {
    /// Create a dissector with no tracked connections.
    pub fn new() -> Self {
        Self {
            directions: Mutex::new(Directions::new(MAX_TRACKED_DIRECTIONS, MAX_TRACKED_BYTES)),
        }
    }

    /// Whether the direction `stream_key` belongs to a connection whose
    /// client connection preface was seen (and that has not been released
    /// or forgotten since).
    pub fn is_tracking(&self, stream_key: &TcpStreamKey) -> bool {
        self.lock().contains(stream_key)
    }

    /// A poisoned lock only means a panic elsewhere; every state change
    /// leaves the table consistent, so keep using it.
    fn lock(&self) -> std::sync::MutexGuard<'_, Directions> {
        self.directions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for Http2ConnectionDissector {
    fn default() -> Self {
        Self::new()
    }
}

impl Dissector for Http2ConnectionDissector {
    fn name(&self) -> &'static str {
        Http2Dissector.name()
    }

    fn short_name(&self) -> &'static str {
        Http2Dissector.short_name()
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        dissect_frame(data, buf, offset, None)
    }

    fn dissect_tcp_stream<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
        stream: &TcpStreamContext,
    ) -> Result<DissectResult, PacketError> {
        // Whether the direction is tracked, and its dynamic table, come
        // from earlier segments (RFC 7541, Section 2.3.2 —
        // https://www.rfc-editor.org/rfc/rfc7541#section-2.3.2).
        buf.mark_cross_packet_state();
        let mut directions = self.lock();
        let key = stream.stream_key;
        if !directions.contains(&key) {
            if !data.starts_with(CONNECTION_PREFACE) {
                drop(directions);
                return dissect_frame(data, buf, offset, None);
            }
            // The preface is "the first application data octets of a
            // connection" (RFC 9113, Section 3.4): the client has not sent a
            // header block yet, so its dynamic table starts empty. The
            // server's starts empty too, unless it is already tracked.
            directions.start(key);
            let reverse = stream.reverse_key();
            if !directions.contains(&reverse) {
                directions.start(reverse);
            }
        }
        let Some(state) = directions.get_mut(&key) else {
            return dissect_frame(data, buf, offset, None);
        };
        let before = state.memory();
        let result = dissect_frame(data, buf, offset, Some(&mut *state));
        let after = state.memory();
        directions.account(&key, before, after);
        result
    }

    fn release_tcp_stream(&self, stream_key: &TcpStreamKey) {
        self.lock().remove(stream_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::FieldValue;

    const CLIENT: TcpStreamKey = ([1; 16], [2; 16], 50000, 80);

    fn ctx(key: TcpStreamKey) -> TcpStreamContext {
        TcpStreamContext::new(key, 0, 0, 0)
    }

    fn server() -> TcpStreamKey {
        ctx(CLIENT).reverse_key()
    }

    fn frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut f = len.to_be_bytes()[1..].to_vec();
        f.push(frame_type);
        f.push(flags);
        f.extend_from_slice(&stream_id.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const END_HEADERS: u8 = 0x04;
    const HEADERS: u8 = 0x01;
    const CONTINUATION: u8 = 0x09;
    const PUSH_PROMISE: u8 = 0x05;

    /// RFC 7541, Appendix C.3.1–C.3.3 header blocks.
    const C3: [&str; 3] = [
        "828684410f7777772e6578616d706c652e636f6d",
        "828684be58086e6f2d6361636865",
        "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
    ];

    /// Dissect `data` on direction `key` and return the decoded headers of
    /// every HTTP2 layer, rendered as in the crate tests.
    fn headers(d: &Http2ConnectionDissector, key: TcpStreamKey, data: &[u8]) -> Vec<String> {
        let mut buf = DissectBuffer::new();
        d.dissect_tcp_stream(data, &mut buf, 0, &ctx(key)).unwrap();
        render(&buf)
    }

    fn render(buf: &DissectBuffer<'_>) -> Vec<String> {
        let text = |v: &FieldValue<'_>| match v {
            FieldValue::Str(s) => s.to_string(),
            FieldValue::Scratch(r) => {
                String::from_utf8(buf.scratch()[r.start as usize..r.end as usize].to_vec()).unwrap()
            }
            other => panic!("unexpected {other:?}"),
        };
        let layer = buf.layer_by_name("HTTP2").unwrap();
        let Some(field) = buf.field_by_name(layer, "headers") else {
            return Vec::new();
        };
        let FieldValue::Array(ref array) = field.value else {
            panic!("expected Array");
        };
        buf.nested_fields(array)
            .iter()
            .filter_map(|f| match f.value {
                FieldValue::Object(ref r) => Some(buf.nested_fields(r)),
                _ => None,
            })
            .map(|c| {
                let get = |n: &str| c.iter().find(|f| f.name() == n).map(|f| &f.value);
                match (get("name"), get("value"), get("index")) {
                    (Some(n), Some(v), _) => format!("{}: {}", text(n), text(v)),
                    (None, Some(v), Some(FieldValue::U32(i))) => format!("#{i}: {}", text(v)),
                    (None, None, Some(FieldValue::U32(i))) => format!("#{i}"),
                    other => panic!("unexpected {other:?}"),
                }
            })
            .collect()
    }

    /// Open a tracked connection whose first client frame carries `block`.
    fn open(d: &Http2ConnectionDissector, block: &[u8]) -> Vec<String> {
        let mut data = CONNECTION_PREFACE.to_vec();
        data.extend(frame(HEADERS, END_HEADERS | 0x01, 1, block));
        headers(d, CLIENT, &data)
    }

    /// RFC 7541, Section 2.3.2 — the dynamic table is kept across header
    /// blocks <https://www.rfc-editor.org/rfc/rfc7541#section-2.3.2>, so
    /// every message of a TCP stream reports that it used cross-packet
    /// state: opening a connection, continuing one, and finding that a
    /// direction is not tracked (that too depends on earlier segments).
    #[test]
    fn stream_messages_mark_cross_packet_state() {
        let d = Http2ConnectionDissector::new();
        let stream = |key: TcpStreamKey, data: &[u8]| {
            let mut buf = DissectBuffer::new();
            d.dissect_tcp_stream(data, &mut buf, 0, &ctx(key)).unwrap();
            buf.used_cross_packet_state()
        };
        let untracked = frame(HEADERS, END_HEADERS, 1, &hex(C3[0]));
        assert!(stream(CLIENT, &untracked));

        let mut preface = CONNECTION_PREFACE.to_vec();
        preface.extend(frame(HEADERS, END_HEADERS | 0x01, 1, &hex(C3[0])));
        assert!(stream(CLIENT, &preface));
        let next = frame(HEADERS, END_HEADERS, 3, &hex(C3[1]));
        assert!(stream(CLIENT, &next));
    }

    /// Without a stream context the connection dissector decodes each frame
    /// on its own and touches no state.
    #[test]
    fn frame_without_stream_does_not_mark_cross_packet_state() {
        let d = Http2ConnectionDissector::new();
        let data = frame(HEADERS, END_HEADERS, 1, &[0x82]);
        let mut buf = DissectBuffer::new();
        d.dissect(&data, &mut buf, 0).unwrap();
        assert!(!buf.used_cross_packet_state());
    }

    #[test]
    fn rfc7541_c3_blocks_share_the_dynamic_table() {
        let d = Http2ConnectionDissector::new();
        assert_eq!(open(&d, &hex(C3[0]))[3], ":authority: www.example.com");
        assert!(d.is_tracking(&CLIENT));
        assert!(d.is_tracking(&server()));

        let second = headers(&d, CLIENT, &frame(HEADERS, END_HEADERS, 3, &hex(C3[1])));
        assert_eq!(
            second,
            [
                ":method: GET",
                ":scheme: http",
                ":path: /",
                ":authority: www.example.com",
                "cache-control: no-cache",
            ]
        );
        let third = headers(&d, CLIENT, &frame(HEADERS, END_HEADERS, 5, &hex(C3[2])));
        assert_eq!(third[3], ":authority: www.example.com");
        assert_eq!(third[4], "custom-key: custom-value");
    }

    #[test]
    fn directions_have_separate_tables() {
        let d = Http2ConnectionDissector::new();
        open(&d, &hex(C3[0]));
        // Index 62 exists in the client's table, not in the server's.
        let mut buf = DissectBuffer::new();
        let data = frame(HEADERS, END_HEADERS, 1, &[0x88, 0xbe]);
        d.dissect_tcp_stream(&data, &mut buf, 0, &ctx(server()))
            .unwrap();
        let layer = buf.layer_by_name("HTTP2").unwrap();
        assert_eq!(render(&buf), [":status: 200"]);
        assert_eq!(
            buf.field_by_name(layer, "hpack_error").unwrap().value,
            FieldValue::Str("HPACK index past the dynamic table")
        );
        // The failed block stops tracking the server's table.
        assert_eq!(
            headers(&d, server(), &frame(HEADERS, END_HEADERS, 1, &[0xbe])),
            ["#62"]
        );
    }

    #[test]
    fn continuation_completes_a_split_header_block() {
        let d = Http2ConnectionDissector::new();
        // Split C.3.1 in the middle of the :authority literal.
        let block = hex(C3[0]);
        let (head, tail) = block.split_at(8);
        assert!(open_split(&d, head).is_empty());
        let got = headers(&d, CLIENT, &frame(CONTINUATION, END_HEADERS, 1, tail));
        assert_eq!(got[3], ":authority: www.example.com");
        // The table was updated by the reassembled block.
        let second = headers(&d, CLIENT, &frame(HEADERS, END_HEADERS, 3, &hex(C3[1])));
        assert_eq!(second[3], ":authority: www.example.com");
    }

    /// Open a tracked connection whose HEADERS frame lacks END_HEADERS.
    fn open_split(d: &Http2ConnectionDissector, head: &[u8]) -> Vec<String> {
        let mut data = CONNECTION_PREFACE.to_vec();
        data.extend(frame(HEADERS, 0, 1, head));
        headers(d, CLIENT, &data)
    }

    #[test]
    fn several_continuations_and_push_promise() {
        let d = Http2ConnectionDissector::new();
        open(&d, &[0x82]);
        let block = hex(C3[0]);
        let mut first = 2u32.to_be_bytes().to_vec();
        first.extend_from_slice(&block[..3]);
        assert!(headers(&d, CLIENT, &frame(PUSH_PROMISE, 0, 1, &first)).is_empty());
        assert!(headers(&d, CLIENT, &frame(CONTINUATION, 0, 1, &block[3..10])).is_empty());
        let got = headers(
            &d,
            CLIENT,
            &frame(CONTINUATION, END_HEADERS, 1, &block[10..]),
        );
        assert_eq!(got.len(), 4);
    }

    #[test]
    fn interleaved_frame_loses_the_pending_block() {
        let d = Http2ConnectionDissector::new();
        open_split(&d, &hex(C3[0])[..8]);
        // A PING between HEADERS and CONTINUATION (RFC 9113, Section 4.3).
        let ping = frame(0x06, 0, 0, &[0; 8]);
        headers(&d, CLIENT, &ping);
        let got = headers(&d, CLIENT, &frame(CONTINUATION, END_HEADERS, 1, b"x"));
        assert!(got.is_empty());
        // The table is no longer followed.
        assert_eq!(
            headers(&d, CLIENT, &frame(HEADERS, END_HEADERS, 3, &[0xbe])),
            ["#62"]
        );
    }

    #[test]
    fn continuation_on_another_stream_desynchronizes() {
        let d = Http2ConnectionDissector::new();
        open_split(&d, &hex(C3[0])[..8]);
        let got = headers(&d, CLIENT, &frame(CONTINUATION, END_HEADERS, 3, b"x"));
        assert!(got.is_empty());
        assert_eq!(
            headers(&d, CLIENT, &frame(HEADERS, END_HEADERS, 5, &[0xbe])),
            ["#62"]
        );
    }

    #[test]
    fn oversized_pending_block_desynchronizes() {
        let d = Http2ConnectionDissector::new();
        open_split(&d, &[0x82]);
        let chunk = vec![0u8; 16 * 1024];
        for _ in 0..=MAX_PENDING_BLOCK / chunk.len() {
            headers(&d, CLIENT, &frame(CONTINUATION, 0, 1, &chunk));
        }
        let got = headers(&d, CLIENT, &frame(CONTINUATION, END_HEADERS, 1, &[]));
        assert!(got.is_empty());
    }

    #[test]
    fn malformed_header_frame_desynchronizes() {
        let d = Http2ConnectionDissector::new();
        open(&d, &hex(C3[0]));
        // PADDED HEADERS whose Pad Length exceeds the payload: the block it
        // carries (and its table insertions) cannot be decoded.
        let bad = frame(HEADERS, END_HEADERS | 0x08, 3, &[9, 0x82]);
        let mut buf = DissectBuffer::new();
        assert!(
            d.dissect_tcp_stream(&bad, &mut buf, 0, &ctx(CLIENT))
                .is_err()
        );
        assert_eq!(
            headers(&d, CLIENT, &frame(HEADERS, END_HEADERS, 5, &[0xbe])),
            ["#62"]
        );
    }

    #[test]
    fn preface_keeps_a_tracked_reverse_direction() {
        let d = Http2ConnectionDissector::new();
        open(&d, &[0x82]);
        // The server indexes a field.
        let block = hex("400a637573746f6d2d6b65790c637573746f6d2d76616c7565");
        headers(&d, server(), &frame(HEADERS, END_HEADERS, 1, &block));
        // The client direction is released and a preface is seen again:
        // the server's table is kept.
        d.release_tcp_stream(&CLIENT);
        open(&d, &[0x82]);
        assert_eq!(
            headers(&d, server(), &frame(HEADERS, END_HEADERS, 3, &[0xbe])),
            ["custom-key: custom-value"]
        );
    }

    #[test]
    fn byte_budget_evicts_the_oldest_directions() {
        let mut dirs = Directions::new(100, 1000);
        for port in 1..=3 {
            dirs.start(key(port));
            let state = dirs.get_mut(&key(port)).unwrap();
            let before = state.memory();
            state.begin_block(1, &[0; 400]);
            let after = state.memory();
            dirs.account(&key(port), before, after);
        }
        // 3 × 400 octets exceed the budget: the oldest direction goes.
        assert!(!dirs.contains(&key(1)));
        assert!(dirs.contains(&key(2)));
        assert!(dirs.contains(&key(3)));
        assert_eq!(dirs.total_bytes, 800);
        // The direction being processed is never evicted for its own growth.
        let state = dirs.get_mut(&key(3)).unwrap();
        let before = state.memory();
        state.begin_block(1, &[0; 900]);
        let after = state.memory();
        dirs.account(&key(3), before, after);
        assert!(!dirs.contains(&key(2)));
        assert!(dirs.contains(&key(3)));
        assert_eq!(dirs.total_bytes, 900);
        dirs.remove(&key(3));
        assert_eq!(dirs.total_bytes, 0);
    }

    #[test]
    fn untracked_connection_is_decoded_frame_by_frame() {
        let d = Http2ConnectionDissector::new();
        let got = headers(&d, CLIENT, &frame(HEADERS, END_HEADERS, 1, &[0x82, 0xbe]));
        assert_eq!(got, [":method: GET", "#62"]);
        assert!(!d.is_tracking(&CLIENT));
        // A CONTINUATION is decoded on its own as well.
        let got = headers(&d, CLIENT, &frame(CONTINUATION, END_HEADERS, 1, &[0x82]));
        assert_eq!(got, [":method: GET"]);
    }

    #[test]
    fn truncated_preface_frame_still_starts_tracking() {
        let d = Http2ConnectionDissector::new();
        let mut buf = DissectBuffer::new();
        let err = d.dissect_tcp_stream(CONNECTION_PREFACE, &mut buf, 0, &ctx(CLIENT));
        assert!(matches!(err, Err(PacketError::Truncated { .. })));
        assert!(d.is_tracking(&CLIENT));
    }

    #[test]
    fn release_forgets_the_direction() {
        let d = Http2ConnectionDissector::new();
        open(&d, &hex(C3[0]));
        d.release_tcp_stream(&CLIENT);
        assert!(!d.is_tracking(&CLIENT));
        assert!(d.is_tracking(&server()));
        d.release_tcp_stream(&CLIENT);
    }

    #[test]
    fn stateless_dissect_ignores_connection_state() {
        let d = Http2ConnectionDissector::new();
        open(&d, &hex(C3[0]));
        let data = frame(HEADERS, END_HEADERS, 3, &[0xbe]);
        let mut buf = DissectBuffer::new();
        d.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(render(&buf), ["#62"]);
    }

    #[test]
    fn metadata_matches_http2_dissector() {
        let d = Http2ConnectionDissector::default();
        assert_eq!(d.name(), Http2Dissector.name());
        assert_eq!(d.short_name(), "HTTP2");
        assert_eq!(
            d.field_descriptors().len(),
            Http2Dissector.field_descriptors().len()
        );
        assert_eq!(d.references(), Http2Dissector.references());
        assert_eq!(d.layer(), Some(ProtocolLayer::Application));
    }

    fn key(port: u16) -> TcpStreamKey {
        ([0; 16], [1; 16], port, 80)
    }

    #[test]
    fn full_table_forgets_the_oldest_direction() {
        let mut dirs = Directions::new(3, usize::MAX);
        for port in 1..=4 {
            dirs.start(key(port));
        }
        assert!(!dirs.contains(&key(1)));
        assert!(dirs.contains(&key(4)));
        assert_eq!(dirs.states.len(), 3);
    }

    #[test]
    fn stale_order_entry_does_not_evict_a_restarted_key() {
        let mut dirs = Directions::new(2, usize::MAX);
        dirs.start(key(1));
        dirs.start(key(2));
        // Restarting key(1) leaves a stale (key(1), 1) entry in the order.
        dirs.start(key(1));
        dirs.start(key(3));
        assert!(dirs.contains(&key(1)));
        assert!(!dirs.contains(&key(2)));
        assert!(dirs.contains(&key(3)));
    }

    #[test]
    fn remove_compacts_the_eviction_order() {
        let mut dirs = Directions::new(1000, usize::MAX);
        for port in 0..200 {
            dirs.start(key(port));
        }
        for port in 0..200 {
            dirs.remove(&key(port));
        }
        assert!(dirs.states.is_empty());
        assert!(dirs.order.len() <= 64);
    }

    #[test]
    fn zero_capacity_still_holds_the_latest_direction() {
        let mut dirs = Directions::new(0, usize::MAX);
        dirs.start(key(1));
        dirs.start(key(2));
        assert!(dirs.contains(&key(2)));
    }
}
