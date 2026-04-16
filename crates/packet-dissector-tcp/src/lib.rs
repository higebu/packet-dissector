//! TCP (Transmission Control Protocol) dissector.
//!
//! ## References
//! - RFC 9293: <https://www.rfc-editor.org/rfc/rfc9293>

#![deny(missing_docs)]

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector, TcpStreamContext};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Minimum TCP header size (no options).
const MIN_HEADER_SIZE: usize = 20;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_SRC_PORT: usize = 0;
const FD_DST_PORT: usize = 1;
const FD_SEQ: usize = 2;
const FD_ACK: usize = 3;
const FD_DATA_OFFSET: usize = 4;
const FD_RESERVED: usize = 5;
const FD_FLAGS: usize = 6;
const FD_WINDOW: usize = 7;
const FD_CHECKSUM: usize = 8;
const FD_URGENT_POINTER: usize = 9;
const FD_OPTIONS: usize = 10;
const FD_STREAM_ID: usize = 11;
/// Index of the `reassembly_in_progress` field in [`FIELD_DESCRIPTORS`].
///
/// Used by the registry's TCP reassembly middleware to emit this field via
/// `FIELD_DESCRIPTORS[FD_REASSEMBLY_IN_PROGRESS].to_field(...)`.
pub const FD_REASSEMBLY_IN_PROGRESS: usize = 12;
/// Index of the `segment_count` field in [`FIELD_DESCRIPTORS`].
///
/// Used by the registry's TCP reassembly middleware to emit this field via
/// `FIELD_DESCRIPTORS[FD_SEGMENT_COUNT].to_field(...)`.
pub const FD_SEGMENT_COUNT: usize = 13;

/// Field descriptors for the TCP dissector.
///
/// The registry's TCP reassembly middleware references this array (via
/// [`FD_REASSEMBLY_IN_PROGRESS`] and [`FD_SEGMENT_COUNT`]) to emit
/// reassembly status fields using `to_field()`.
pub static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("src_port", "Source Port", FieldType::U16),
    FieldDescriptor::new("dst_port", "Destination Port", FieldType::U16),
    FieldDescriptor::new("seq", "Sequence Number", FieldType::U32),
    FieldDescriptor::new("ack", "Acknowledgment Number", FieldType::U32),
    FieldDescriptor::new("data_offset", "Data Offset", FieldType::U8),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U8),
    FieldDescriptor {
        name: "flags",
        display_name: "Flags",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(f) => {
                let s = tcp_flags_name(*f);
                if s.is_empty() { None } else { Some(s) }
            }
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("window", "Window", FieldType::U16),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    FieldDescriptor::new("urgent_pointer", "Urgent Pointer", FieldType::U16),
    FieldDescriptor::new("options", "Options", FieldType::Bytes).optional(),
    FieldDescriptor::new("stream_id", "Stream ID", FieldType::U32).optional(),
    FieldDescriptor::new(
        "reassembly_in_progress",
        "Reassembly In Progress",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("segment_count", "Segment Count", FieldType::U32).optional(),
];

/// Bit-to-name table for TCP control bits.
///
/// RFC 9293, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>
const TCP_FLAG_BITS: &[(u8, &str)] = &[
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
];

/// Static 256-entry lookup table for TCP flags → display name.
///
/// flags 0x00 → "" (empty), flags 0x12 → "SYN, ACK", etc.
/// Initialized once via `LazyLock` since const fn cannot do string concatenation.
static TCP_FLAGS_NAMES: std::sync::LazyLock<[String; 256]> = std::sync::LazyLock::new(|| {
    let mut table: [String; 256] = std::array::from_fn(|_| String::new());
    for i in 0u16..256 {
        let flags = i as u8;
        let mut buf = String::with_capacity(32);
        for &(bit, name) in TCP_FLAG_BITS {
            if flags & bit != 0 {
                if !buf.is_empty() {
                    buf.push_str(", ");
                }
                buf.push_str(name);
            }
        }
        table[i as usize] = buf;
    }
    table
});

/// Look up a TCP flags display name from the static table.
/// Returns `&'static str` by leaking the lazy-initialized strings.
fn tcp_flags_name(flags: u8) -> &'static str {
    // LazyLock<[String; 256]> lives for 'static, so borrowing the str is safe.
    TCP_FLAGS_NAMES[flags as usize].as_str()
}

/// TCP stream key: IP addresses (encoded as 16 bytes) + ports.
///
/// IPv4 addresses are encoded as IPv4-mapped IPv6 addresses
/// (`::ffff:a.b.c.d`) to avoid key collisions with valid IPv6 addresses.
type StreamKey = ([u8; 16], [u8; 16], u16, u16);

/// Extract the IP addresses from already-parsed layers and build a directional
/// stream key (src → dst).
///
/// Prefers the innermost (last) IP layer to handle IP-in-IP encapsulation
/// correctly, matching the behavior of [`ip_payload_len`].
///
/// Returns `None` when no IPv4 or IPv6 layer is present in the buffer.
fn extract_stream_key(buf: &DissectBuffer, src_port: u16, dst_port: u16) -> Option<StreamKey> {
    // Find the innermost IP layer (last in the layer list).
    let ip_layer = buf
        .layers()
        .iter()
        .rev()
        .find(|l| l.name == "IPv4" || l.name == "IPv6")?;

    let fields = buf.layer_fields(ip_layer);

    let (src_ip, dst_ip): ([u8; 16], [u8; 16]) = if ip_layer.name == "IPv4" {
        let src = match &fields.iter().find(|f| f.name() == "src")?.value {
            FieldValue::Ipv4Addr(addr) => ipv4_mapped(addr),
            _ => return None,
        };
        let dst = match &fields.iter().find(|f| f.name() == "dst")?.value {
            FieldValue::Ipv4Addr(addr) => ipv4_mapped(addr),
            _ => return None,
        };
        (src, dst)
    } else {
        let src = match &fields.iter().find(|f| f.name() == "src")?.value {
            FieldValue::Ipv6Addr(addr) => *addr,
            _ => return None,
        };
        let dst = match &fields.iter().find(|f| f.name() == "dst")?.value {
            FieldValue::Ipv6Addr(addr) => *addr,
            _ => return None,
        };
        (src, dst)
    };

    Some((src_ip, dst_ip, src_port, dst_port))
}

/// Canonicalize a stream key so that both directions of the same TCP
/// connection map to the same key: the "smaller" endpoint (IP, port) pair
/// is always first.
///
/// This is used for `stream_id` assignment (connection-level), but NOT for
/// reassembly where per-direction sequence numbers must be kept separate.
fn canonicalize_key(key: StreamKey) -> StreamKey {
    let (ip1, ip2, port1, port2) = key;
    if (ip1, port1) <= (ip2, port2) {
        (ip1, ip2, port1, port2)
    } else {
        (ip2, ip1, port2, port1)
    }
}

/// Compute the TCP payload length from the enclosing IP layer's length fields.
///
/// For IPv4: `payload = total_length - ip_header_len - tcp_header_len`
/// For IPv6: `payload = payload_length - tcp_header_len`
///
/// Returns `None` when no IP layer is present or the fields cannot be parsed.
/// The result is clamped to the captured slice length to handle truncated captures.
fn ip_payload_len(buf: &DissectBuffer, tcp_offset: usize, tcp_header_len: usize) -> Option<usize> {
    // Use the innermost (last) IP layer whose range precedes the TCP offset.
    let ip_layer = buf
        .layers()
        .iter()
        .rev()
        .find(|l| (l.name == "IPv4" || l.name == "IPv6") && l.range.start < tcp_offset);

    let ip_layer = ip_layer?;
    let fields = buf.layer_fields(ip_layer);

    if ip_layer.name == "IPv4" {
        let total_length = match &fields.iter().find(|f| f.name() == "total_length")?.value {
            FieldValue::U16(v) => *v as usize,
            _ => return None,
        };
        let ip_header_start = ip_layer.range.start;
        let ip_consumed = tcp_offset
            .checked_sub(ip_header_start)?
            .checked_add(tcp_header_len)?;
        Some(total_length.saturating_sub(ip_consumed))
    } else {
        let payload_length = match &fields.iter().find(|f| f.name() == "payload_length")?.value {
            FieldValue::U16(v) => *v as usize,
            _ => return None,
        };
        let ipv6_header_end = ip_layer.range.end;
        let ext_and_tcp = tcp_offset
            .checked_sub(ipv6_header_end)?
            .checked_add(tcp_header_len)?;
        Some(payload_length.saturating_sub(ext_and_tcp))
    }
}

/// Encode an IPv4 address as an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
///
/// This avoids key collisions between IPv4 and IPv6 addresses whose last
/// 12 bytes happen to be zero.
fn ipv4_mapped(addr: &[u8; 4]) -> [u8; 16] {
    let mut mapped = [0u8; 16];
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12..16].copy_from_slice(addr);
    mapped
}

/// Maximum number of tracked TCP streams before the coldest (oldest)
/// entry is evicted. This prevents unbounded memory growth while
/// preserving active connections' stream IDs.
const MAX_TRACKED_STREAMS: usize = 65_536;

/// State for the stream ID mapping, protected by a Mutex.
struct StreamIdState {
    map: HashMap<StreamKey, u32>,
    /// Insertion order for eviction. The front is the oldest (coldest) entry.
    order: VecDeque<StreamKey>,
}

impl StreamIdState {
    /// Remove stale entries from `order` when it has grown significantly
    /// larger than `map`, preventing unbounded growth from removed streams.
    fn compact_order(&mut self) {
        if self.order.len() > self.map.len() * 2 + 64 {
            self.order.retain(|k| self.map.contains_key(k));
        }
    }
}

/// TCP dissector with sequential stream ID assignment.
///
/// Maintains a mapping from TCP 4-tuples to sequential stream IDs,
/// similar to Wireshark's `tcp.stream` field. The stream ID is assigned
/// when a 4-tuple is first seen and reused for subsequent packets on the
/// same connection.
pub struct TcpDissector {
    /// Mapping from 4-tuple to assigned stream ID with eviction order.
    streams: Mutex<StreamIdState>,
    /// Counter for assigning the next stream ID.
    next_stream_id: AtomicU32,
}

impl TcpDissector {
    /// Create a new TCP dissector with empty stream state.
    pub fn new() -> Self {
        Self {
            streams: Mutex::new(StreamIdState {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
            next_stream_id: AtomicU32::new(0),
        }
    }
}

impl Default for TcpDissector {
    fn default() -> Self {
        Self::new()
    }
}

impl Dissector for TcpDissector {
    fn name(&self) -> &'static str {
        "Transmission Control Protocol"
    }

    fn short_name(&self) -> &'static str {
        "TCP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < MIN_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 9293, Section 3.1 — TCP Header Format
        // <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>
        let src_port = read_be_u16(data, 0)?;
        let dst_port = read_be_u16(data, 2)?;
        let seq = read_be_u32(data, 4)?;
        let ack = read_be_u32(data, 8)?;

        // Data Offset (4 bits) + Reserved (4 bits)
        let data_offset = (data[12] >> 4) as usize;
        let reserved = data[12] & 0x0F;

        if data_offset < 5 {
            return Err(PacketError::InvalidFieldValue {
                field: "data_offset",
                value: data_offset as u32,
            });
        }

        let header_len = data_offset * 4;
        if data.len() < header_len {
            return Err(PacketError::Truncated {
                expected: header_len,
                actual: data.len(),
            });
        }

        // RFC 9293, Section 3.1 — Flags / Control Bits (8 bits, MSB→LSB):
        // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
        // <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>
        let flags = data[13];
        let window = read_be_u16(data, 14)?;
        let checksum = read_be_u16(data, 16)?;
        let urgent_pointer = read_be_u16(data, 18)?;

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + header_len,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SRC_PORT],
            FieldValue::U16(src_port),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DST_PORT],
            FieldValue::U16(dst_port),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SEQ],
            FieldValue::U32(seq),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ACK],
            FieldValue::U32(ack),
            offset + 8..offset + 12,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DATA_OFFSET],
            FieldValue::U8(data_offset as u8),
            offset + 12..offset + 13,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_RESERVED],
            FieldValue::U8(reserved),
            offset + 12..offset + 13,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAGS],
            FieldValue::U8(flags),
            offset + 13..offset + 14,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_WINDOW],
            FieldValue::U16(window),
            offset + 14..offset + 16,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM],
            FieldValue::U16(checksum),
            offset + 16..offset + 18,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_URGENT_POINTER],
            FieldValue::U16(urgent_pointer),
            offset + 18..offset + 20,
        );

        // RFC 9293, Section 3.1 — Options (variable length, if Data Offset > 5)
        // <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>
        if header_len > MIN_HEADER_SIZE {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_OPTIONS],
                FieldValue::Bytes(&data[MIN_HEADER_SIZE..header_len]),
                offset + MIN_HEADER_SIZE..offset + header_len,
            );
        }

        // Assign a sequential stream_id based on the canonicalized TCP 4-tuple
        // so both directions of a connection share the same ID.
        if let Some(key) = extract_stream_key(buf, src_port, dst_port) {
            let canonical = canonicalize_key(key);
            let mut state = self.streams.lock().unwrap_or_else(|e| e.into_inner());

            let is_new = !state.map.contains_key(&canonical);
            if is_new {
                while state.map.len() >= MAX_TRACKED_STREAMS {
                    if let Some(old_key) = state.order.pop_front() {
                        state.map.remove(&old_key);
                    } else {
                        break;
                    }
                }
            }

            let next = &self.next_stream_id;
            let sid = *state
                .map
                .entry(canonical)
                .or_insert_with(|| next.fetch_add(1, Ordering::Relaxed));

            if is_new {
                state.order.push_back(canonical);
            }

            if flags & 0x04 != 0 {
                state.map.remove(&canonical);
                state.compact_order();
            }

            drop(state);

            buf.push_field(
                &FIELD_DESCRIPTORS[FD_STREAM_ID],
                FieldValue::U32(sid),
                offset..offset + header_len,
            );
        }

        buf.end_layer();

        // Compute TCP payload length from the IP layer's total/payload length
        let payload_len =
            ip_payload_len(buf, offset, header_len).unwrap_or(data.len() - header_len);

        match extract_stream_key(buf, src_port, dst_port) {
            Some(key) => Ok(DissectResult::with_tcp_context(
                header_len,
                DispatchHint::ByTcpPort(src_port, dst_port),
                TcpStreamContext {
                    stream_key: key,
                    seq,
                    payload_len,
                },
            )),
            None => Ok(DissectResult::new(
                header_len,
                DispatchHint::ByTcpPort(src_port, dst_port),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_flags_name_single_flag() {
        assert_eq!(tcp_flags_name(0x02), "SYN");
        assert_eq!(tcp_flags_name(0x10), "ACK");
        assert_eq!(tcp_flags_name(0x01), "FIN");
    }

    #[test]
    fn tcp_flags_name_multiple_flags() {
        assert_eq!(tcp_flags_name(0x12), "SYN, ACK");
        assert_eq!(tcp_flags_name(0x11), "FIN, ACK");
        assert_eq!(tcp_flags_name(0x18), "PSH, ACK");
        assert_eq!(tcp_flags_name(0x14), "RST, ACK");
    }

    #[test]
    fn tcp_flags_name_no_flags() {
        assert_eq!(tcp_flags_name(0x00), "");
    }

    #[test]
    fn tcp_flags_name_all_flags() {
        assert_eq!(
            tcp_flags_name(0xFF),
            "FIN, SYN, RST, PSH, ACK, URG, ECE, CWR"
        );
    }
}
