//! # RFC 3261 / RFC 5626 (SIP transport framing) Coverage
//!
//! | Spec Section     | Description                                            | Test                                        |
//! |------------------|--------------------------------------------------------|---------------------------------------------|
//! | RFC 3261 18.3    | UDP: no Content-Length, body runs to end of datagram   | sip_udp_body_without_content_length         |
//! | RFC 3261 7.5     | TCP: CRLF ping before a message in the next segment    | sip_tcp_crlf_ping_then_message              |
//! | RFC 3261 7.5     | TCP: CRLF ping and message in one segment              | sip_tcp_crlf_ping_and_message_one_segment   |
//! | RFC 5626 4.4.1   | TCP: single-CRLF pong                                  | sip_tcp_crlf_pong                           |
//! | RFC 3261 7.3     | UDP: more than 64 header fields                        | sip_udp_many_headers                        |

mod common;

use packet_dissector::field::FieldValue;
use packet_dissector::packet::DissectBuffer;
use packet_dissector::registry::DissectorRegistry;

const SRC: [u8; 4] = [10, 0, 0, 1];
const DST: [u8; 4] = [10, 0, 0, 2];

fn eth_ipv4(pkt: &mut Vec<u8>, protocol: u8, l4_len: usize) {
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&((20 + l4_len) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, protocol, 0x00, 0x00]);
    pkt.extend_from_slice(&SRC);
    pkt.extend_from_slice(&DST);
}

fn udp_5060(payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    eth_ipv4(&mut pkt, 17, 8 + payload.len());
    pkt.extend_from_slice(&5060u16.to_be_bytes());
    pkt.extend_from_slice(&5060u16.to_be_bytes());
    pkt.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(payload);
    pkt
}

fn tcp_to_5060(seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    eth_ipv4(&mut pkt, 6, 20 + payload.len());
    pkt.extend_from_slice(&50000u16.to_be_bytes());
    pkt.extend_from_slice(&5060u16.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(payload);
    pkt
}

/// Assert that all layers have contiguous, non-empty byte ranges,
/// and that each is listed with fields by `all_field_schemas()`.
fn assert_layers_contiguous(buf: &DissectBuffer<'_>) {
    common::assert_layers_have_schema(buf);
    let mut expected_start = 0;
    for layer in buf.layers() {
        assert_eq!(layer.range.start, expected_start, "layer {}", layer.name);
        assert!(layer.range.end > layer.range.start, "layer {}", layer.name);
        expected_start = layer.range.end;
    }
}

fn names(buf: &DissectBuffer<'_>) -> Vec<&'static str> {
    buf.layers().iter().map(|l| l.name).collect()
}

fn sip_str_fields<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> Vec<&'a str> {
    buf.layers()
        .iter()
        .filter(|l| l.name == "SIP")
        .filter_map(|l| buf.field_str(l, name))
        .collect()
}

const OPTIONS: &[u8] = b"OPTIONS sip:bob@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";

#[test]
fn sip_udp_body_without_content_length() {
    let reg = DissectorRegistry::default();
    let sdp = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\n\
                t=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";
    let mut payload = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                        Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n\
                        Content-Type: application/sdp\r\n\r\n"
        .to_vec();
    let header_len = payload.len();
    payload.extend_from_slice(sdp);
    let pkt = udp_5060(&payload);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_layers_contiguous(&buf);
    assert_eq!(names(&buf), ["Ethernet", "IPv4", "UDP", "SIP", "SDP"]);
    let sdp_layer = buf.layer_by_name("SDP").unwrap();
    assert_eq!(sdp_layer.range, 42 + header_len..pkt.len());
}

#[test]
fn sip_tcp_crlf_ping_then_message() {
    let reg = DissectorRegistry::default();
    let ping = tcp_to_5060(1000, b"\r\n\r\n");
    let mut buf = DissectBuffer::new();
    reg.dissect(&ping, &mut buf).unwrap();
    assert_layers_contiguous(&buf);
    assert_eq!(sip_str_fields(&buf, "keep_alive"), ["ping"]);
    let tcp = buf.layer_by_name("TCP").unwrap();
    assert!(buf.field_u8(tcp, "reassembly_in_progress").is_none());

    let msg = tcp_to_5060(1004, OPTIONS);
    let mut buf = DissectBuffer::new();
    reg.dissect(&msg, &mut buf).unwrap();
    assert_layers_contiguous(&buf);
    assert_eq!(sip_str_fields(&buf, "method"), ["OPTIONS"]);
}

#[test]
fn sip_tcp_crlf_ping_and_message_one_segment() {
    let reg = DissectorRegistry::default();
    let mut payload = b"\r\n\r\n".to_vec();
    payload.extend_from_slice(OPTIONS);
    let pkt = tcp_to_5060(1000, &payload);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_layers_contiguous(&buf);
    assert_eq!(sip_str_fields(&buf, "method"), ["OPTIONS"]);
    let sip = buf.layer_by_name("SIP").unwrap();
    assert_eq!(sip.range, 54..pkt.len());
}

#[test]
fn sip_tcp_crlf_pong() {
    let reg = DissectorRegistry::default();
    let pkt = tcp_to_5060(1000, b"\r\n");
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_layers_contiguous(&buf);
    assert_eq!(sip_str_fields(&buf, "keep_alive"), ["pong"]);
}

#[test]
fn sip_udp_many_headers() {
    let reg = DissectorRegistry::default();
    let mut payload = b"OPTIONS sip:bob@example.com SIP/2.0\r\n".to_vec();
    for i in 0..65 {
        payload.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
    }
    payload.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    let pkt = udp_5060(&payload);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_layers_contiguous(&buf);
    let sip = buf.layer_by_name("SIP").unwrap();
    assert_eq!(buf.field_u32(sip, "content_length"), Some(0));
    assert!(matches!(
        buf.field_by_name(sip, "headers").unwrap().value,
        FieldValue::Array(_)
    ));
}
