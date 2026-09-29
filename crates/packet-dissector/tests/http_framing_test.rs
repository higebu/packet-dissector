//! # RFC 9112 (HTTP/1.1 message body length) Coverage
//!
//! | RFC Section   | Description                                        | Test                                   |
//! |---------------|----------------------------------------------------|----------------------------------------|
//! | 9112 7.1      | Chunked response, hex chunk size (issue case A)    | http_chunked_hex_size                  |
//! | 9112 7.1      | Chunked response in one segment (case B)           | http_chunked_single_segment            |
//! | 9112 6.3 r3   | Transfer-Encoding overrides Content-Length (C)     | http_transfer_encoding_overrides_cl    |
//! | 9112 6.3 r1   | 304 with Content-Length has no body (D)            | http_304_has_no_body                   |
//! | 9110 5.5      | obs-text header value (E)                          | http_obs_text_header_value             |
//! | 9112 5        | 66 header fields (F)                               | http_many_headers                      |
//! | 9112 6.3 r8   | Close-delimited HTTP/1.0 response (G)              | http_close_delimited_response          |
//! | 9112 7.1      | Chunked body reassembled across segments           | http_chunked_across_segments           |
//! | 9112 6.3 r1   | 204 followed by a pipelined response               | http_204_then_pipelined_response       |

use packet_dissector::packet::DissectBuffer;
use packet_dissector::registry::DissectorRegistry;

/// Ethernet → IPv4 → TCP (10.0.0.2:80 → 10.0.0.1:50000) with `payload`.
fn from_server(seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, 6, 0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&80u16.to_be_bytes());
    pkt.extend_from_slice(&50000u16.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(payload);
    pkt
}

/// Assert that all layers have contiguous, non-empty byte ranges.
fn assert_layers_contiguous(buf: &DissectBuffer<'_>) {
    let mut expected_start = 0;
    for layer in buf.layers() {
        assert_eq!(layer.range.start, expected_start, "layer {}", layer.name);
        assert!(layer.range.end > layer.range.start, "layer {}", layer.name);
        expected_start = layer.range.end;
    }
}

/// Dissect one segment on a fresh registry and return the HTTP layers'
/// byte ranges as (start, end) (relative to the TCP payload) and whether reassembly is
/// in progress.
fn http_ranges(payload: &[u8]) -> (Vec<(usize, usize)>, bool) {
    let reg = DissectorRegistry::default();
    let pkt = from_server(1, payload);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_layers_contiguous(&buf);
    let tcp = buf.layer_by_name("TCP").unwrap();
    let in_progress = buf.field_u8(tcp, "reassembly_in_progress") == Some(1);
    let ranges = buf
        .layers()
        .iter()
        .filter(|l| l.name == "HTTP")
        .map(|l| (l.range.start - 54, l.range.end - 54))
        .collect();
    (ranges, in_progress)
}

#[test]
fn http_chunked_hex_size() {
    let p = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              1a\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\n\r\n";
    assert_eq!(http_ranges(p), (vec![(0, p.len())], false));
}

#[test]
fn http_chunked_single_segment() {
    let p = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    assert_eq!(http_ranges(p), (vec![(0, p.len())], false));
}

#[test]
fn http_transfer_encoding_overrides_cl() {
    let p = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n\
              5\r\nhello\r\n0\r\n\r\n";
    assert_eq!(http_ranges(p), (vec![(0, p.len())], false));
}

#[test]
fn http_304_has_no_body() {
    let p = b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1234\r\n\r\n";
    assert_eq!(http_ranges(p), (vec![(0, p.len())], false));
}

#[test]
fn http_obs_text_header_value() {
    let p = b"HTTP/1.1 200 OK\r\nX-Name: caf\xe9\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(http_ranges(p), (vec![(0, p.len())], false));
}

#[test]
fn http_many_headers() {
    let mut p = b"HTTP/1.1 200 OK\r\n".to_vec();
    for i in 0..65 {
        p.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
    }
    p.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    assert_eq!(http_ranges(&p), (vec![(0, p.len())], false));
}

#[test]
fn http_close_delimited_response() {
    let p = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nhello world body";
    let (ranges, in_progress) = http_ranges(p);
    assert!(!in_progress);
    assert_eq!(ranges.len(), 1);
}

#[test]
fn http_chunked_across_segments() {
    let reg = DissectorRegistry::default();
    let p = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let split = 52;

    let first = from_server(1, &p[..split]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&first, &mut buf).unwrap();
    let tcp = buf.layer_by_name("TCP").unwrap();
    assert_eq!(buf.field_u8(tcp, "reassembly_in_progress"), Some(1));

    let second = from_server(1 + split as u32, &p[split..]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&second, &mut buf).unwrap();
    let http = buf.layer_by_name("HTTP").unwrap();
    assert_eq!(buf.field_str(http, "body_framing"), Some("chunked"));
    assert_eq!(buf.field_u32(http, "chunk_count"), Some(1));
    let tcp = buf.layer_by_name("TCP").unwrap();
    assert!(buf.field_u8(tcp, "reassembly_in_progress").is_none());
}

#[test]
fn http_204_then_pipelined_response() {
    let first = b"HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n";
    let mut p = first.to_vec();
    p.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    assert_eq!(
        http_ranges(&p),
        (vec![(0, first.len()), (first.len(), p.len())], false)
    );
}
