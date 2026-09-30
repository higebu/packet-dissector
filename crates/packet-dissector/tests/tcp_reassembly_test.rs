//! # TCP stream reassembly (registry middleware) Coverage
//!
//! | Spec Section         | Description                                              | Test                                                    |
//! |----------------------|----------------------------------------------------------|---------------------------------------------------------|
//! | RFC 3261 18.3        | SIP body bounded by Content-Length, next message kept    | sip_body_bounded_by_content_length_single_segment       |
//! | RFC 3261 18.3        | Same, on the buffered (reassembled) path                 | sip_body_bounded_by_content_length_reassembled          |
//! | RFC 9112 6.2         | HTTP body bounded by Content-Length, next message kept   | http_body_bounded_by_content_length_pipelined           |
//! | —                    | Non-Truncated error on reassembled data drops the buffer | buffered_parse_error_drops_stream_state                 |
//! | —                    | Non-ContentType hint honored on the buffered path        | buffered_path_follows_non_content_type_hint             |
//! | RFC 9293 3.1         | SYN data starts at ISN+1                                  | syn_payload_sequence_starts_after_isn                   |
//! | RFC 9293 3.5         | SYN discards stale reassembly state for the direction    | syn_resets_stale_reassembly_state                       |
//! | RFC 9293 3.6         | FIN releases the direction's reassembly state            | fin_releases_reassembly_state                           |
//! | RFC 9293 3.10        | FIN overtaking missing data keeps the buffer             | fin_before_missing_data_keeps_reassembly_state          |
//! | RFC 9293 3.10.7.4    | RST flushes both directions' reassembly state            | rst_flushes_both_directions                             |
//! | RFC 9293 3.10        | Reordered earlier data is inserted before the buffer     | reordered_earlier_segment_is_inserted_after_syn         |
//! | RFC 9293 3.10        | Reordered earlier data after a delivered message         | reordered_earlier_segment_is_inserted_after_delivered_message |
//! | RFC 9293 3.10        | Earlier data with unknown delivery position is dropped   | earlier_segment_with_unknown_delivery_position_is_dropped |
//! | RFC 9293 3.10        | Reordering after a SYN that reuses a 4-tuple             | reordered_segment_after_reused_tuple_syn                |
//! | RFC 9293 3.5         | SYN forgets the old connection's delivery position (ahead) | syn_forgets_stale_delivery_position_ahead             |
//! | RFC 9293 3.5         | SYN forgets the old connection's delivery position (near)  | syn_forgets_stale_delivery_position_near              |
//! | RFC 9293 3.10        | Retransmitted delivered data is not inserted             | retransmission_of_delivered_data_is_not_inserted        |
//! | —                    | Stream eviction is reported on the TCP layer             | eviction_is_reported_on_tcp_layer                       |
//! | RFC 9293 3.10        | Overlapping retransmission contributes only new bytes    | overlapping_retransmission_is_trimmed                   |
//! | RFC 9293 3.10        | Old data separated from the buffer by a gap is ignored   | old_segment_before_gap_is_ignored                       |
//! | —                    | Zero-length success from the upper dissector is an error | zero_length_upper_result_is_error                       |
//! | —                    | Body dispatcher that never consumes does not loop         | stalled_body_dispatch_terminates                        |
//! | —                    | Body parse error still consumes the body                 | body_parse_error_does_not_desync_stream                 |
//! | RFC 5036 3.1         | LDP PDU split across segments                            | ldp_pdu_reassembled                                     |

use packet_dissector::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector::error::PacketError;
use packet_dissector::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector::packet::DissectBuffer;
use packet_dissector::registry::DissectorRegistry;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH_ACK: u8 = 0x18;
const ACK: u8 = 0x10;

const CLIENT: [u8; 4] = [10, 0, 0, 1];
const SERVER: [u8; 4] = [10, 0, 0, 2];

/// Build Ethernet → IPv4 → TCP with the given addressing, flags and payload.
fn segment(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    let total_len = (20 + 20 + payload.len()) as u16;
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, 6, 0x00, 0x00]);
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&dport.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.push(0x50);
    pkt.push(flags);
    pkt.extend_from_slice(&65535u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(payload);
    pkt
}

/// Client (10.0.0.1:50000) → server (10.0.0.2:`port`) segment.
fn c2s(port: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    segment(CLIENT, SERVER, 50000, port, seq, flags, payload)
}

/// Server (10.0.0.2:`port`) → client (10.0.0.1:50000) segment.
fn s2c(port: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    segment(SERVER, CLIENT, port, 50000, seq, flags, payload)
}

fn layer_names(buf: &DissectBuffer<'_>) -> Vec<&'static str> {
    buf.layers().iter().map(|l| l.name).collect()
}

/// Values of the string field `name` in every layer called `layer`.
fn str_fields<'a>(buf: &'a DissectBuffer<'_>, layer: &str, name: &str) -> Vec<&'a str> {
    buf.layers()
        .iter()
        .filter(|l| l.name == layer)
        .filter_map(|l| buf.field_str(l, name))
        .collect()
}

fn reassembly_in_progress(buf: &DissectBuffer<'_>) -> bool {
    buf.layer_by_name("TCP")
        .and_then(|l| buf.field_u8(l, "reassembly_in_progress"))
        == Some(1)
}

const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\n";

fn sip_invite_with_sdp() -> Vec<u8> {
    let mut msg = format!(
        "INVITE sip:bob@example.com SIP/2.0\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n",
        SDP.len()
    )
    .into_bytes();
    msg.extend_from_slice(SDP);
    msg
}

/// A partial INVITE header section: `Truncated` on its own, and an error if
/// another request line is glued to it.
const STALE_HEAD: &[u8] = b"INVITE sip:stale@example.com SIP/2.0\r\nVia: x\r\n";

const SIP_OPTIONS: &[u8] = b"OPTIONS sip:bob@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";

#[test]
fn sip_body_bounded_by_content_length_single_segment() {
    let reg = DissectorRegistry::default();
    let mut payload = sip_invite_with_sdp();
    payload.extend_from_slice(SIP_OPTIONS);

    let pkt = c2s(5060, 1000, PSH_ACK, &payload);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(
        layer_names(&buf),
        ["Ethernet", "IPv4", "TCP", "SIP", "SDP", "SIP"]
    );
    assert_eq!(str_fields(&buf, "SIP", "method"), ["INVITE", "OPTIONS"]);
    let sdp = buf.layer_by_name("SDP").unwrap();
    assert_eq!(sdp.range.len(), SDP.len());
}

#[test]
fn sip_body_bounded_by_content_length_reassembled() {
    let reg = DissectorRegistry::default();
    let mut stream = sip_invite_with_sdp();
    stream.extend_from_slice(SIP_OPTIONS);
    let split = 20;

    let pkt = c2s(5060, 1000, PSH_ACK, &stream[..split]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    let pkt = c2s(5060, 1000 + split as u32, PSH_ACK, &stream[split..]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(
        layer_names(&buf),
        ["Ethernet", "IPv4", "TCP", "SIP", "SDP", "SIP"]
    );
    assert_eq!(str_fields(&buf, "SIP", "method"), ["INVITE", "OPTIONS"]);
    assert!(!reassembly_in_progress(&buf));
}

#[cfg(feature = "ldp")]
#[test]
fn ldp_pdu_reassembled() {
    let reg = DissectorRegistry::default();
    // LDP PDU (RFC 5036, Section 3.1) with an Address message.
    let mut pdu = vec![0, 1, 0, 28, 10, 0, 0, 1, 0, 0];
    pdu.extend_from_slice(&[0x03, 0x00, 0, 18, 0, 0, 0, 1]); // Address
    pdu.extend_from_slice(&[0x01, 0x01, 0, 10, 0, 1, 10, 0, 0, 1, 10, 0, 0, 2]);
    let split = 12;

    let pkt = c2s(646, 1000, PSH_ACK, &pdu[..split]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    let pkt = c2s(646, 1000 + split as u32, PSH_ACK, &pdu[split..]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4", "TCP", "LDP"]);
    assert!(!reassembly_in_progress(&buf));
    let ldp = buf.layer_by_name("LDP").unwrap();
    let addresses: Vec<_> = buf
        .layer_fields(ldp)
        .iter()
        .filter(|f| f.name() == "address")
        .map(|f| f.value.clone())
        .collect();
    assert_eq!(
        addresses,
        [
            FieldValue::Ipv4Addr([10, 0, 0, 1]),
            FieldValue::Ipv4Addr([10, 0, 0, 2])
        ]
    );
    assert!(buf.layer_fields(ldp).iter().all(|f| f.name() != "data"));
}

#[test]
fn http_body_bounded_by_content_length_pipelined() {
    let reg = DissectorRegistry::default();
    let body = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\n";
    let mut payload = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    payload.extend_from_slice(body);
    payload.extend_from_slice(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");

    let pkt = s2c(80, 5000, PSH_ACK, &payload);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(
        layer_names(&buf),
        ["Ethernet", "IPv4", "TCP", "HTTP", "SDP", "HTTP"]
    );
    let codes: Vec<_> = buf
        .layers()
        .iter()
        .filter(|l| l.name == "HTTP")
        .filter_map(|l| buf.field_u16(l, "status_code"))
        .collect();
    assert_eq!(codes, [200, 204]);
}

#[test]
fn buffered_parse_error_drops_stream_state() {
    let reg = DissectorRegistry::default();
    let head = b"INVITE sip:bob@example.com SIP/2.0\r\nVia: x\r\n";
    // Completes the header section with a line httparse rejects.
    let bad = b"not a header line\r\n\r\n";

    let pkt = c2s(5060, 1000, PSH_ACK, head);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    let seq2 = 1000 + head.len() as u32;
    let pkt = c2s(5060, seq2, PSH_ACK, bad);
    let mut buf = DissectBuffer::new();
    assert!(reg.dissect(&pkt, &mut buf).is_err());

    // The bad bytes are gone: the next message parses on its own.
    let seq3 = seq2 + bad.len() as u32;
    let pkt = c2s(5060, seq3, PSH_ACK, SIP_OPTIONS);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
}

/// Length-prefixed test framing on TCP port 7000: one length byte, then
/// that many body bytes, dispatched to UDP port 9 (any non-ContentType
/// hint works).
struct LenPrefixed;

static LP_FIELDS: &[FieldDescriptor] = &[FieldDescriptor::new("len", "Length", FieldType::U8)];

impl Dissector for LenPrefixed {
    fn name(&self) -> &'static str {
        "Length Prefixed"
    }
    fn short_name(&self) -> &'static str {
        "LP"
    }
    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        LP_FIELDS
    }
    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        let Some(&len) = data.first() else {
            return Err(PacketError::Truncated {
                expected: 1,
                actual: 0,
            });
        };
        if data.len() < 1 + len as usize {
            return Err(PacketError::Truncated {
                expected: 1 + len as usize,
                actual: data.len(),
            });
        }
        buf.begin_layer("LP", None, LP_FIELDS, offset..offset + 1);
        buf.push_field(&LP_FIELDS[0], FieldValue::U8(len), offset..offset + 1);
        buf.end_layer();
        Ok(DissectResult::new(1, DispatchHint::ByUdpPort(9, 9)).with_payload_len(len as usize))
    }
}

/// Consumes all input as one "Body" layer.
struct BodySink;

impl Dissector for BodySink {
    fn name(&self) -> &'static str {
        "Body"
    }
    fn short_name(&self) -> &'static str {
        "Body"
    }
    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }
    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        buf.begin_layer("Body", None, &[], offset..offset + data.len());
        buf.end_layer();
        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

#[test]
fn buffered_path_follows_non_content_type_hint() {
    let mut reg = DissectorRegistry::default();
    reg.register_by_tcp_port(7000, Box::new(LenPrefixed))
        .unwrap();
    reg.register_by_udp_port(9, Box::new(BodySink)).unwrap();

    // Two messages: [3]"abc" and [2]"de", split inside the first body.
    let stream = [3, b'a', b'b', b'c', 2, b'd', b'e'];
    let pkt = c2s(7000, 1, PSH_ACK, &stream[..2]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    let pkt = c2s(7000, 3, PSH_ACK, &stream[2..]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let names = layer_names(&buf);
    assert_eq!(names[3..], ["LP", "Body", "LP", "Body"]);
    let bodies: Vec<_> = buf
        .layers()
        .iter()
        .filter(|l| l.name == "Body")
        .map(|l| l.range.len())
        .collect();
    assert_eq!(bodies, [3, 2]);
}

#[test]
fn syn_payload_sequence_starts_after_isn() {
    let reg = DissectorRegistry::default();
    let isn = 7000u32;
    let (a, b) = SIP_OPTIONS.split_at(20);

    // SYN carrying data (e.g. TCP Fast Open): the data starts at ISN+1.
    let pkt = c2s(5060, isn, SYN, a);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    let pkt = c2s(5060, isn + 1 + a.len() as u32, PSH_ACK, b);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
}

#[test]
fn syn_resets_stale_reassembly_state() {
    let reg = DissectorRegistry::default();

    // Old connection leaves a partial message buffered.
    let pkt = c2s(5060, 1000, PSH_ACK, STALE_HEAD);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    // New connection on the same 4-tuple, close in sequence space.
    let isn = 1100u32;
    let pkt = c2s(5060, isn, SYN, &[]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let pkt = c2s(5060, isn + 1, PSH_ACK, SIP_OPTIONS);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
}

#[test]
fn fin_releases_reassembly_state() {
    let reg = DissectorRegistry::default();
    let head = STALE_HEAD;

    let pkt = c2s(5060, 1000, PSH_ACK, head);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    // FIN: no more data from this sender; the partial message is dropped.
    let fin_seq = 1000 + head.len() as u32;
    let pkt = c2s(5060, fin_seq, FIN | ACK, &[]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Data at the old stream position is no longer glued to the stale head.
    let pkt = c2s(5060, fin_seq, PSH_ACK, SIP_OPTIONS);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
}

#[test]
fn rst_flushes_both_directions() {
    let reg = DissectorRegistry::default();
    let head = STALE_HEAD;

    let pkt = c2s(5060, 1000, PSH_ACK, head);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    // The server resets the connection.
    let pkt = s2c(5060, 9000, RST | ACK, &[]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let seq = 1000 + head.len() as u32;
    let pkt = c2s(5060, seq, PSH_ACK, SIP_OPTIONS);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
}

/// Split `SIP_OPTIONS` so the tail is shorter than a SIP start-line and
/// therefore reports `Truncated` on its own.
fn options_split() -> (&'static [u8], &'static [u8]) {
    SIP_OPTIONS.split_at(SIP_OPTIONS.len() - 9)
}

#[test]
fn reordered_earlier_segment_is_inserted_after_syn() {
    let reg = DissectorRegistry::default();
    let isn = 4000u32;
    let (a, b) = options_split();

    let pkt = c2s(5060, isn, SYN, &[]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // The second segment arrives first.
    let pkt = c2s(5060, isn + 1 + a.len() as u32, PSH_ACK, b);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    let pkt = c2s(5060, isn + 1, PSH_ACK, a);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
    assert!(!reassembly_in_progress(&buf));
}

#[test]
fn reordered_earlier_segment_is_inserted_after_delivered_message() {
    let reg = DissectorRegistry::default();
    let first = sip_invite_with_sdp();
    let (a, b) = options_split();
    let seq_a = 500 + first.len() as u32;

    // No SYN seen, but a complete message fixes the delivery position.
    let pkt = c2s(5060, 500, PSH_ACK, &first);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let pkt = c2s(5060, seq_a + a.len() as u32, PSH_ACK, b);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    let pkt = c2s(5060, seq_a, PSH_ACK, a);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
}

/// Without a SYN or an earlier message, data before the buffered stream may
/// be a retransmission from before the capture started; it is not glued in
/// front of the buffer.
#[test]
fn earlier_segment_with_unknown_delivery_position_is_dropped() {
    let reg = DissectorRegistry::default();
    let (a, b) = options_split();

    let pkt = c2s(5060, 500 + a.len() as u32, PSH_ACK, b);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    let pkt = c2s(5060, 500, PSH_ACK, a);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(str_fields(&buf, "SIP", "method").is_empty());
}

#[test]
fn retransmission_of_delivered_data_is_not_inserted() {
    let reg = DissectorRegistry::default();
    let first = sip_invite_with_sdp();
    let (head, tail) = SIP_OPTIONS.split_at(30);

    // A complete INVITE, then the start of an OPTIONS request.
    let pkt = c2s(5060, 100, PSH_ACK, &first);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["INVITE"]);
    let seq2 = 100 + first.len() as u32;
    let pkt = c2s(5060, seq2, PSH_ACK, head);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    // Retransmission of the INVITE must not be prepended to the buffer.
    let pkt = c2s(5060, 100, PSH_ACK, &first);
    let mut buf = DissectBuffer::new();
    let _ = reg.dissect(&pkt, &mut buf);

    let pkt = c2s(5060, seq2 + head.len() as u32, PSH_ACK, tail);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
}

#[test]
fn eviction_is_reported_on_tcp_layer() {
    let reg = DissectorRegistry::default();
    let head = &SIP_OPTIONS[..20];

    // Fill the stream table past its limit with partial messages.
    for i in 0..=512u16 {
        let pkt = segment(CLIENT, SERVER, 10000 + i, 5060, 1, PSH_ACK, head);
        let mut buf = DissectBuffer::new();
        reg.dissect(&pkt, &mut buf).unwrap();
        let tcp = buf.layer_by_name("TCP").unwrap();
        assert!(buf.field_u32(tcp, "reassembly_evicted").is_none());
    }

    let pkt = segment(CLIENT, SERVER, 20000, 5060, 1, PSH_ACK, head);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let tcp = buf.layer_by_name("TCP").unwrap();
    assert_eq!(buf.field_u32(tcp, "reassembly_evicted"), Some(1));
}

#[test]
fn overlapping_retransmission_is_trimmed() {
    let reg = DissectorRegistry::default();
    let first = sip_invite_with_sdp();
    let head = &SIP_OPTIONS[..30];
    let seq2 = 100 + first.len() as u32;

    let pkt = c2s(5060, 100, PSH_ACK, &first);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let pkt = c2s(5060, seq2, PSH_ACK, head);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    // Retransmits the last 10 delivered bytes plus the whole OPTIONS.
    let mut overlap = first[first.len() - 10..].to_vec();
    overlap.extend_from_slice(SIP_OPTIONS);
    let pkt = c2s(5060, seq2 - 10, PSH_ACK, &overlap);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);

    // The stream continues after the OPTIONS.
    let pkt = c2s(5060, seq2 + SIP_OPTIONS.len() as u32, PSH_ACK, SIP_OPTIONS);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
}

#[test]
fn old_segment_before_gap_is_ignored() {
    let reg = DissectorRegistry::default();
    let (head, tail) = SIP_OPTIONS.split_at(30);

    let pkt = c2s(5060, 1000, PSH_ACK, head);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(reassembly_in_progress(&buf));

    // Ends 10 bytes before the buffered stream starts.
    let pkt = c2s(5060, 1000 - 20, PSH_ACK, &[b'x'; 10]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert!(buf.layer_by_name("SIP").is_none());

    let pkt = c2s(5060, 1000 + head.len() as u32, PSH_ACK, tail);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
}

#[test]
fn body_parse_error_does_not_desync_stream() {
    let reg = DissectorRegistry::default();
    let body = b"not sdp";
    let mut stream = format!(
        "INVITE sip:bob@example.com SIP/2.0\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    stream.extend_from_slice(body);
    stream.extend_from_slice(SIP_OPTIONS);

    // Buffered path: the invalid SDP body is skipped, not re-parsed as SIP.
    let pkt = c2s(5060, 1, PSH_ACK, &stream[..20]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let pkt = c2s(5060, 21, PSH_ACK, &stream[20..]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["INVITE", "OPTIONS"]);
    assert!(buf.layer_by_name("SDP").is_none());
}

#[test]
fn fin_before_missing_data_keeps_reassembly_state() {
    let reg = DissectorRegistry::default();
    let (head, rest) = SIP_OPTIONS.split_at(20);
    let (mid, tail) = rest.split_at(10);
    let seq_mid = 1000 + head.len() as u32;
    let seq_tail = seq_mid + mid.len() as u32;

    let pkt = c2s(5060, 1000, PSH_ACK, head);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    // The tail and FIN overtake the middle segment.
    let pkt = c2s(5060, seq_tail, FIN | PSH_ACK, tail);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let pkt = c2s(5060, seq_mid, PSH_ACK, mid);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
}

#[test]
fn reordered_segment_after_reused_tuple_syn() {
    let reg = DissectorRegistry::default();
    let first = sip_invite_with_sdp();
    let (a, b) = options_split();

    // An earlier connection delivered data far ahead in sequence space.
    let pkt = c2s(5060, 900_000, PSH_ACK, &first);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // New connection on the same 4-tuple; its first two segments swap.
    let isn = 100u32;
    let pkt = c2s(5060, isn, SYN, &[]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let pkt = c2s(5060, isn + 1 + a.len() as u32, PSH_ACK, b);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let pkt = c2s(5060, isn + 1, PSH_ACK, a);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
}

/// Returns success without consuming anything, with a fixed hint.
struct Stall(DispatchHint);

impl Dissector for Stall {
    fn name(&self) -> &'static str {
        "Stall"
    }
    fn short_name(&self) -> &'static str {
        "Stall"
    }
    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }
    fn dissect<'pkt>(
        &self,
        _data: &'pkt [u8],
        _buf: &mut DissectBuffer<'pkt>,
        _offset: usize,
    ) -> Result<DissectResult, PacketError> {
        Ok(DissectResult::new(0, self.0.clone()))
    }
}

#[test]
fn zero_length_upper_result_is_error() {
    let mut reg = DissectorRegistry::default();
    reg.register_by_tcp_port(7001, Box::new(Stall(DispatchHint::End)))
        .unwrap();
    let pkt = c2s(7001, 1, PSH_ACK, b"abc");
    let mut buf = DissectBuffer::new();
    assert_eq!(
        reg.dissect(&pkt, &mut buf),
        Err(PacketError::InvalidHeader(
            "upper-layer dissector returned zero bytes_consumed on success"
        ))
    );
}

#[test]
fn stalled_body_dispatch_terminates() {
    let mut reg = DissectorRegistry::default();
    reg.register_by_tcp_port(7000, Box::new(LenPrefixed))
        .unwrap();
    reg.register_by_udp_port(9, Box::new(Stall(DispatchHint::ByUdpPort(9, 9))))
        .unwrap();
    let pkt = c2s(7000, 1, PSH_ACK, &[2, b'a', b'b', 1, b'c']);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let lp = buf.layers().iter().filter(|l| l.name == "LP").count();
    assert_eq!(lp, 2);
}

/// A delivery position left by an earlier connection on the same 4-tuple
/// must not survive the new connection's SYN: a coalesced retransmission of
/// already-dissected data would otherwise be inserted and dissected twice.
#[test]
fn syn_forgets_stale_delivery_position_ahead() {
    let reg = DissectorRegistry::default();
    let (a, b) = options_split();

    // Earlier connection delivers far ahead in sequence space.
    let pkt = c2s(5060, 900_000, PSH_ACK, SIP_OPTIONS);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let isn = 100u32;
    let pkt = c2s(5060, isn, SYN, &[]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    // First message of the new connection is delivered on the fast path.
    let pkt = c2s(5060, isn + 1, PSH_ACK, SIP_OPTIONS);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);

    // The second message's tail arrives first ...
    let second = isn + 1 + SIP_OPTIONS.len() as u32;
    let pkt = c2s(5060, second + a.len() as u32, PSH_ACK, b);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    // ... then a retransmission of the first message coalesced with the
    // second message's head. Only the second message is new.
    let mut coalesced = SIP_OPTIONS.to_vec();
    coalesced.extend_from_slice(a);
    let pkt = c2s(5060, isn + 1, PSH_ACK, &coalesced);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
}

/// Same, with the stale position just after the new stream start: the
/// reordered first segment must be inserted whole.
#[test]
fn syn_forgets_stale_delivery_position_near() {
    let reg = DissectorRegistry::default();
    let (a, b) = options_split();
    let isn = 100u32;

    // Earlier connection delivered up to isn + 11.
    let old = SIP_OPTIONS;
    let old_seq = isn + 11 - old.len() as u32;
    let pkt = c2s(5060, old_seq, PSH_ACK, old);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let pkt = c2s(5060, isn, SYN, &[]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let pkt = c2s(5060, isn + 1 + a.len() as u32, PSH_ACK, b);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let pkt = c2s(5060, isn + 1, PSH_ACK, a);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(str_fields(&buf, "SIP", "method"), ["OPTIONS"]);
}
