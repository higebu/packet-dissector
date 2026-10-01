//! # RFC 9113 (HTTP/2 over a TCP connection) Coverage
//!
//! | RFC Section | Description                                                  | Test                                              |
//! |-------------|--------------------------------------------------------------|---------------------------------------------------|
//! | 3.3, 3.4    | Frames after the client preface stay HTTP/2 (both directions) | frames_after_preface_are_http2                    |
//! | 4.1         | Several frames in one segment after the preface              | several_frames_in_one_segment                     |
//! | 3.4, 4.1    | Server frames seen before any client segment                 | server_frames_without_preface_are_http2           |
//! | 4.1         | Frame header split across segments is reassembled            | frame_header_split_across_segments                |
//! | 4.1, 5.5    | Unknown frame type on a known HTTP/2 connection              | unknown_frame_type_on_known_connection            |
//! | 9112 3      | HTTP/1.1 on port 80 is unaffected                            | http1_request_is_not_http2                        |
//! | 3.4         | A frame-like HTTP/1.1 body does not mark the connection      | frame_like_body_does_not_mark_connection          |
//! | 9293 3.5    | SYN on a reused 4-tuple forgets the HTTP/2 connection        | syn_forgets_http2_connection                      |
//! | 9293 3.10.7.4 | RST forgets the HTTP/2 connection (both directions)        | rst_forgets_http2_connection                      |
//! | 9293 3.6    | FIN forgets the sender's direction only                      | fin_forgets_sender_direction                      |

mod common;

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

/// Client (10.0.0.1:50000) → server (10.0.0.2:80) segment.
fn c2s(seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    segment(CLIENT, SERVER, 50000, 80, seq, flags, payload)
}

/// Server (10.0.0.2:80) → client (10.0.0.1:50000) segment.
fn s2c(seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    segment(SERVER, CLIENT, 80, 50000, seq, flags, payload)
}

/// Layer names after Ethernet / IPv4 / TCP, after asserting that every
/// layer is listed with fields by `all_field_schemas()`.
fn upper_layers(buf: &DissectBuffer<'_>) -> Vec<&'static str> {
    common::assert_layers_have_schema(buf);
    buf.layers().iter().skip(3).map(|l| l.name).collect()
}

/// Frame types of every HTTP2 layer, in order.
fn frame_types(buf: &DissectBuffer<'_>) -> Vec<u8> {
    buf.layers()
        .iter()
        .filter(|l| l.name == "HTTP2")
        .filter_map(|l| buf.field_u8(l, "frame_type"))
        .collect()
}

fn dissect_ok(reg: &DissectorRegistry, pkt: &[u8]) -> (Vec<&'static str>, Vec<u8>) {
    let mut buf = DissectBuffer::new();
    reg.dissect(pkt, &mut buf).unwrap();
    (upper_layers(&buf), frame_types(&buf))
}

/// Upper layer names, whether or not dissection succeeds.
fn layers_any(reg: &DissectorRegistry, pkt: &[u8]) -> Vec<&'static str> {
    let mut buf = DissectBuffer::new();
    let _ = reg.dissect(pkt, &mut buf);
    upper_layers(&buf)
}

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Empty SETTINGS frame (RFC 9113, Section 6.5).
const SETTINGS_EMPTY: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
/// SETTINGS frame with the ACK flag.
const SETTINGS_ACK: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00];
/// WINDOW_UPDATE on stream 0, increment 65535 (RFC 9113, Section 6.9).
const WINDOW_UPDATE: &[u8] = &[
    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
];
/// HEADERS on stream 1, END_STREAM | END_HEADERS (RFC 9113, Section 6.2).
const HEADERS: &[u8] = &[
    0x00, 0x00, 0x05, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, 0x82, 0x86, 0x84, 0x41, 0x80,
];
/// Server SETTINGS with MAX_CONCURRENT_STREAMS = 100.
const SERVER_SETTINGS: &[u8] = &[
    0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x64,
];

/// Preface + empty SETTINGS + WINDOW_UPDATE, as in the issue's packet 1.
fn client_preface_segment() -> Vec<u8> {
    [PREFACE, SETTINGS_EMPTY, WINDOW_UPDATE].concat()
}

#[test]
fn frames_after_preface_are_http2() {
    let reg = DissectorRegistry::default();
    let first = client_preface_segment();

    let got = dissect_ok(&reg, &c2s(1000, PSH_ACK, &first));
    assert_eq!(got.0, ["HTTP2", "HTTP2"]);
    assert_eq!(got.1, [0x04, 0x08]);

    let seq = 1000 + first.len() as u32;
    let got = dissect_ok(&reg, &c2s(seq, PSH_ACK, HEADERS));
    assert_eq!(got.0, ["HTTP2"]);
    assert_eq!(got.1, [0x01]);

    let got = dissect_ok(&reg, &s2c(5000, PSH_ACK, SERVER_SETTINGS));
    assert_eq!(got.0, ["HTTP2"]);
    assert_eq!(got.1, [0x04]);
}

#[test]
fn several_frames_in_one_segment() {
    let reg = DissectorRegistry::default();
    let first = client_preface_segment();
    dissect_ok(&reg, &c2s(1000, PSH_ACK, &first));

    let payload = [SETTINGS_ACK, HEADERS, WINDOW_UPDATE].concat();
    let seq = 1000 + first.len() as u32;
    let got = dissect_ok(&reg, &c2s(seq, PSH_ACK, &payload));
    assert_eq!(got.0, ["HTTP2", "HTTP2", "HTTP2"]);
    assert_eq!(got.1, [0x04, 0x01, 0x08]);
}

#[test]
fn server_frames_without_preface_are_http2() {
    // The capture starts after the client preface: the server's first
    // segment is the first one seen on the connection.
    let reg = DissectorRegistry::default();
    let payload = [SERVER_SETTINGS, SETTINGS_ACK].concat();
    let got = dissect_ok(&reg, &s2c(5000, PSH_ACK, &payload));
    assert_eq!(got.0, ["HTTP2", "HTTP2"]);
    assert_eq!(got.1, [0x04, 0x04]);

    // A later client frame is recognised on its own as well.
    let got = dissect_ok(&reg, &c2s(1000, PSH_ACK, HEADERS));
    assert_eq!(got.0, ["HTTP2"]);
}

#[test]
fn frame_header_split_across_segments() {
    let reg = DissectorRegistry::default();
    let first = client_preface_segment();
    dissect_ok(&reg, &c2s(1000, PSH_ACK, &first));

    // The first 5 octets of a HEADERS frame: shorter than a frame header.
    let seq = 1000 + first.len() as u32;
    let (head, tail) = HEADERS.split_at(5);
    let pkt = c2s(seq, PSH_ACK, head);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(upper_layers(&buf).first(), Some(&"HTTP2"));
    assert_eq!(
        buf.layer_by_name("TCP")
            .and_then(|l| buf.field_u8(l, "reassembly_in_progress")),
        Some(1)
    );

    let got = dissect_ok(&reg, &c2s(seq + head.len() as u32, PSH_ACK, tail));
    assert_eq!(got.0, ["HTTP2"]);
    assert_eq!(got.1, [0x01]);
}

#[test]
fn unknown_frame_type_on_known_connection() {
    // RFC 9113, Section 4.1 — "Implementations MUST ignore and discard
    // frames of unknown types." The frame still belongs to HTTP/2 —
    // https://www.rfc-editor.org/rfc/rfc9113#section-4.1
    let reg = DissectorRegistry::default();
    let first = client_preface_segment();
    dissect_ok(&reg, &c2s(1000, PSH_ACK, &first));

    let unknown = [
        0x00, 0x00, 0x02, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd,
    ];
    let seq = 1000 + first.len() as u32;
    let got = dissect_ok(&reg, &c2s(seq, PSH_ACK, &unknown));
    assert_eq!(got.0, ["HTTP2"]);
    assert_eq!(got.1, [0xfa]);
}

#[test]
fn http1_request_is_not_http2() {
    let reg = DissectorRegistry::default();
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let got = dissect_ok(&reg, &c2s(1000, PSH_ACK, req));
    assert_eq!(got.0, ["HTTP"]);
}

#[test]
fn frame_like_body_does_not_mark_connection() {
    // The capture starts in the middle of an HTTP/1.1 response body whose
    // first octets happen to form a valid WINDOW_UPDATE frame header.
    let reg = DissectorRegistry::default();
    assert_eq!(
        layers_any(&reg, &s2c(5000, PSH_ACK, WINDOW_UPDATE)),
        ["HTTP2"]
    );

    // Only the client connection preface marks a connection as HTTP/2:
    // the next request on the connection is still HTTP/1.1.
    let req = b"GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let got = dissect_ok(&reg, &c2s(1000, PSH_ACK, req));
    assert_eq!(got.0, ["HTTP"]);
}

/// Open an HTTP/2 connection and return the next client sequence number.
fn open_http2(reg: &DissectorRegistry) -> u32 {
    let first = client_preface_segment();
    dissect_ok(reg, &c2s(1000, PSH_ACK, &first));
    1000 + first.len() as u32
}

/// An unknown-type frame: HTTP/2 only when the connection is known.
const UNKNOWN_FRAME: &[u8] = &[0x00, 0x00, 0x00, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00];

#[test]
fn syn_forgets_http2_connection() {
    let reg = DissectorRegistry::default();
    open_http2(&reg);

    // The 4-tuple is reused by a new connection that speaks HTTP/1.1.
    dissect_ok(&reg, &c2s(7000, SYN, &[]));
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let got = dissect_ok(&reg, &c2s(7001, PSH_ACK, req));
    assert_eq!(got.0, ["HTTP"]);
}

#[test]
fn rst_forgets_http2_connection() {
    let reg = DissectorRegistry::default();
    let seq = open_http2(&reg);

    dissect_ok(&reg, &s2c(5000, RST | ACK, &[]));

    // Both directions are forgotten: an unknown-type frame is no longer
    // taken as HTTP/2 in either of them.
    assert_ne!(
        layers_any(&reg, &c2s(seq, PSH_ACK, UNKNOWN_FRAME)),
        ["HTTP2"]
    );
    assert_ne!(
        layers_any(&reg, &s2c(5000, PSH_ACK, UNKNOWN_FRAME)),
        ["HTTP2"]
    );
}

#[test]
fn fin_forgets_sender_direction() {
    let reg = DissectorRegistry::default();
    let seq = open_http2(&reg);

    // The client closes its direction; the server may still send.
    dissect_ok(&reg, &c2s(seq, FIN | ACK, &[]));

    let got = dissect_ok(&reg, &s2c(5000, PSH_ACK, UNKNOWN_FRAME));
    assert_eq!(got.0, ["HTTP2"]);

    assert_ne!(
        layers_any(&reg, &c2s(seq, PSH_ACK, UNKNOWN_FRAME)),
        ["HTTP2"]
    );
}

/// Decoded headers of the last HTTP2 layer, as `name: value` or `#index`.
fn last_headers(buf: &DissectBuffer<'_>) -> Vec<String> {
    use packet_dissector::field::FieldValue;
    let layer = buf
        .layers()
        .iter()
        .rev()
        .find(|l| l.name == "HTTP2")
        .unwrap();
    let Some(field) = buf.field_by_name(layer, "headers") else {
        return Vec::new();
    };
    let FieldValue::Array(ref array) = field.value else {
        panic!("expected Array");
    };
    let text = |v: &FieldValue<'_>| match v {
        FieldValue::Str(s) => s.to_string(),
        FieldValue::Scratch(r) => {
            String::from_utf8(buf.scratch()[r.start as usize..r.end as usize].to_vec()).unwrap()
        }
        other => panic!("unexpected {other:?}"),
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
                (_, _, Some(FieldValue::U32(i))) => format!("#{i}"),
                other => panic!("unexpected {other:?}"),
            }
        })
        .collect()
}

/// HEADERS frame (END_HEADERS, plus `flags`) on `stream` carrying `block`.
fn headers_frame(flags: u8, stream: u32, block: &[u8]) -> Vec<u8> {
    let mut f = (block.len() as u32).to_be_bytes()[1..].to_vec();
    f.extend_from_slice(&[0x01, flags]);
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(block);
    f
}

/// RFC 7541, Appendix C.3.1 and C.3.2 request header blocks.
const C3_1: &[u8] = &[
    0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x2e, 0x63, 0x6f, 0x6d,
];
const C3_2: &[u8] = &[
    0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65,
];

#[test]
fn hpack_dynamic_table_across_packets() {
    let reg = DissectorRegistry::default();
    let first = [PREFACE, SETTINGS_EMPTY, &headers_frame(0x05, 1, C3_1)].concat();
    let pkt = c2s(1000, PSH_ACK, &first);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(last_headers(&buf)[3], ":authority: www.example.com");

    // The second request refers to :authority by dynamic index 62.
    let seq = 1000 + first.len() as u32;
    let pkt = c2s(seq, PSH_ACK, &headers_frame(0x05, 3, C3_2));
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(
        last_headers(&buf),
        [
            ":method: GET",
            ":scheme: http",
            ":path: /",
            ":authority: www.example.com",
            "cache-control: no-cache",
        ]
    );
}

#[test]
fn header_block_split_across_packets() {
    let reg = DissectorRegistry::default();
    // HEADERS without END_HEADERS, ending inside the :authority literal.
    let (head, tail) = C3_1.split_at(8);
    let mut headers = headers_frame(0x01, 1, head);
    headers[4] = 0x01; // END_STREAM only
    let first = [PREFACE, SETTINGS_EMPTY, &headers].concat();
    dissect_ok(&reg, &c2s(1000, PSH_ACK, &first));

    let mut continuation = headers_frame(0x04, 1, tail);
    continuation[3] = 0x09; // CONTINUATION
    let pkt = c2s(1000 + first.len() as u32, PSH_ACK, &continuation);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(last_headers(&buf)[3], ":authority: www.example.com");
}
