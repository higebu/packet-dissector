//! # Cross-packet state reporting (registry) Coverage
//!
//! [`DissectBuffer::used_cross_packet_state`] tells a caller whether a
//! packet's dissection read or updated state kept across packets. Each
//! stateful part of the registry must set it, and stateless chains must not.
//!
//! | Spec Section         | Description                                              | Test                                                    |
//! |----------------------|----------------------------------------------------------|---------------------------------------------------------|
//! | RFC 826              | ARP marks no state                                       | stateless_chains_mark_no_state                          |
//! | RFC 792              | ICMP Echo marks no state                                 | stateless_chains_mark_no_state                          |
//! | RFC 768, RFC 1035    | UDP / DNS marks no state                                 | stateless_chains_mark_no_state                          |
//! | RFC 9293 3.5         | TCP stream ID marks state                                | tcp_segments_mark_state                                 |
//! | RFC 9293 3.10        | TCP reassembly middleware marks state                    | tcp_reassembly_middleware_marks_state                   |
//! | RFC 9113 3.4         | HTTP/2 connection (HPACK) marks state                    | http2_over_tcp_marks_state                              |
//! | RFC 7011 8           | IPFIX Template / Data Set over UDP marks state           | ipfix_over_udp_marks_state_only_with_sets               |
//! | RFC 3954 7           | NetFlow v9 (decode-as) marks state, v5 does not          | netflow_decode_as_marks_state_by_version                |
//! | RFC 4303 3.4.4       | ESP decrypted inner TCP marks state, inner UDP does not  | esp_decrypted_inner_chain_reports_state                 |
//! | RFC 4303 3.4.4       | ESP inner TCP marks state even when the chain fails      | esp_decrypted_inner_error_keeps_state                   |
//! | —                    | Flag resets on clear, accumulates without clear          | flag_follows_buffer_reuse                               |
//!
//! IP fragment reassembly is covered in `ip_reassembly_test.rs`.

#![cfg(all(
    feature = "ethernet",
    feature = "arp",
    feature = "ipv4",
    feature = "icmp",
    feature = "tcp",
    feature = "udp",
    feature = "dns",
    feature = "http2",
    feature = "ipfix",
    feature = "esp-decrypt"
))]

use packet_dissector::dissector::{DispatchHint, DissectResult, Dissector, TcpStreamContext};
use packet_dissector::error::PacketError;
use packet_dissector::field::FieldDescriptor;
use packet_dissector::packet::DissectBuffer;
use packet_dissector::registry::DissectorRegistry;

const SRC: [u8; 4] = [192, 0, 2, 1];
const DST: [u8; 4] = [192, 0, 2, 2];

fn ethernet(ethertype: u16) -> Vec<u8> {
    let mut p = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    p.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    p.extend_from_slice(&ethertype.to_be_bytes());
    p
}

/// IPv4 header (no options) carrying `protocol` and `data`.
fn ipv4_header(protocol: u8, data: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0x00];
    p.extend_from_slice(&((20 + data.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 1, 0, 0, 64, protocol, 0, 0]);
    p.extend_from_slice(&SRC);
    p.extend_from_slice(&DST);
    p.extend_from_slice(data);
    p
}

/// Ethernet → IPv4 → `protocol` with `data`.
fn ipv4(protocol: u8, data: &[u8]) -> Vec<u8> {
    let mut p = ethernet(0x0800);
    p.extend_from_slice(&ipv4_header(protocol, data));
    p
}

fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = sport.to_be_bytes().to_vec();
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    u
}

fn tcp(sport: u16, dport: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = sport.to_be_bytes().to_vec();
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes());
    t.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(payload);
    t
}

/// A DNS query for `example.com` A (RFC 1035, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc1035#section-4.1>).
fn dns_query() -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(b"\x07example\x03com\x00");
    m.extend_from_slice(&[0, 1, 0, 1]);
    m
}

/// An IPFIX Message with the given Sets (RFC 7011, Section 3.1 —
/// <https://www.rfc-editor.org/rfc/rfc7011#section-3.1>).
fn ipfix_message(sets: &[Vec<u8>]) -> Vec<u8> {
    let body = sets.concat();
    let mut m = vec![0, 10];
    m.extend_from_slice(&((16 + body.len()) as u16).to_be_bytes());
    m.extend_from_slice(&[0; 12]);
    m.extend_from_slice(&body);
    m
}

/// A Set (or FlowSet) with the given ID and body.
fn set(id: u16, body: &[u8]) -> Vec<u8> {
    let mut s = id.to_be_bytes().to_vec();
    s.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
    s.extend_from_slice(body);
    s
}

/// Template 256 with one sourceIPv4Address (8) field.
fn template_256() -> Vec<u8> {
    [&256u16.to_be_bytes()[..], &[0, 1, 0, 8, 0, 4]].concat()
}

/// Full dissection of `packet`; returns whether it used cross-packet state.
fn marks_state(reg: &DissectorRegistry, packet: &[u8]) -> bool {
    let mut buf = DissectBuffer::new();
    reg.dissect(packet, &mut buf).unwrap();
    buf.used_cross_packet_state()
}

#[test]
fn stateless_chains_mark_no_state() {
    let reg = DissectorRegistry::default();

    // ARP request — RFC 826 <https://www.rfc-editor.org/rfc/rfc826>.
    let mut arp = ethernet(0x0806);
    arp.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]);
    arp.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    arp.extend_from_slice(&SRC);
    arp.extend_from_slice(&[0; 6]);
    arp.extend_from_slice(&DST);
    assert!(!marks_state(&reg, &arp));

    // ICMP Echo — RFC 792 <https://www.rfc-editor.org/rfc/rfc792>.
    assert!(!marks_state(&reg, &ipv4(1, &[8, 0, 0, 0, 0, 1, 0, 1])));

    // UDP / DNS, dissected repeatedly with the same registry.
    let dns = ipv4(17, &udp(40000, 53, &dns_query()));
    assert!(!marks_state(&reg, &dns));
    assert!(!marks_state(&reg, &dns));
}

#[test]
fn tcp_segments_mark_state() {
    let reg = DissectorRegistry::default();
    // SYN, a data-less ACK, and a segment with payload on an unknown port.
    assert!(marks_state(&reg, &ipv4(6, &tcp(40000, 9, 0, 0x02, &[]))));
    assert!(marks_state(&reg, &ipv4(6, &tcp(40000, 9, 1, 0x10, &[]))));
    assert!(marks_state(&reg, &ipv4(6, &tcp(40000, 9, 1, 0x18, b"x"))));
}

/// A transport dissector that hands the registry a TCP stream context
/// without touching any state itself, so only the registry's TCP
/// reassembly middleware can set the flag.
struct StreamOnly;

static STREAM_ONLY_FIELDS: &[FieldDescriptor] = &[];

impl Dissector for StreamOnly {
    fn name(&self) -> &'static str {
        "Stream Only"
    }

    fn short_name(&self) -> &'static str {
        "STREAM"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        STREAM_ONLY_FIELDS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        buf.begin_layer("STREAM", None, STREAM_ONLY_FIELDS, offset..offset);
        buf.end_layer();
        let key = ([1; 16], [2; 16], 40000, 53);
        Ok(DissectResult::with_tcp_context(
            0,
            DispatchHint::ByTcpPort(40000, 53),
            TcpStreamContext::new(key, 0, data.len(), 0),
        ))
    }
}

#[test]
fn tcp_reassembly_middleware_marks_state() {
    let mut reg = DissectorRegistry::default();
    reg.register_by_ip_protocol_or_replace(253, Box::new(StreamOnly));
    // DNS over TCP: a 2-octet length prefix (RFC 1035, Section 4.2.2 —
    // https://www.rfc-editor.org/rfc/rfc1035#section-4.2.2).
    let query = dns_query();
    let mut message = (query.len() as u16).to_be_bytes().to_vec();
    message.extend_from_slice(&query);
    let packet = ipv4(253, &message);

    let mut buf = DissectBuffer::new();
    reg.dissect(&packet, &mut buf).unwrap();
    assert!(buf.layer_by_name("DNS").is_some());
    assert!(buf.used_cross_packet_state());
}

#[test]
fn http2_over_tcp_marks_state() {
    let reg = DissectorRegistry::default();
    // RFC 9113, Section 3.4 — client connection preface and a SETTINGS
    // frame (https://www.rfc-editor.org/rfc/rfc9113#section-3.4).
    let mut preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    preface.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    let packet = ipv4(6, &tcp(40000, 80, 1, 0x18, &preface));
    let mut buf = DissectBuffer::new();
    reg.dissect(&packet, &mut buf).unwrap();
    assert!(buf.layer_by_name("HTTP2").is_some());
    assert!(buf.used_cross_packet_state());
}

#[test]
fn ipfix_over_udp_marks_state_only_with_sets() {
    let reg = DissectorRegistry::default();
    let header_only = ipv4(17, &udp(40000, 4739, &ipfix_message(&[])));
    assert!(!marks_state(&reg, &header_only));

    let template = ipv4(
        17,
        &udp(40000, 4739, &ipfix_message(&[set(2, &template_256())])),
    );
    assert!(marks_state(&reg, &template));

    let data = ipv4(
        17,
        &udp(40000, 4739, &ipfix_message(&[set(256, &[10, 0, 0, 1])])),
    );
    assert!(marks_state(&reg, &data));
}

#[test]
fn netflow_decode_as_marks_state_by_version() {
    let mut reg = DissectorRegistry::default();
    let netflow = reg.create_dissector_by_name("netflow").unwrap();
    reg.register_by_udp_port_or_replace(2055, netflow);

    // NetFlow v5 header with no records (Cisco, Table B-3).
    let mut v5 = vec![0, 5, 0, 0];
    v5.extend_from_slice(&[0; 20]);
    assert!(!marks_state(&reg, &ipv4(17, &udp(40000, 2055, &v5))));

    // NetFlow v9 Template FlowSet (RFC 3954, Section 5.2 —
    // https://www.rfc-editor.org/rfc/rfc3954#section-5.2).
    let mut v9 = vec![0, 9, 0, 1];
    v9.extend_from_slice(&[0; 16]);
    v9.extend_from_slice(&set(0, &template_256()));
    assert!(marks_state(&reg, &ipv4(17, &udp(40000, 2055, &v9))));
}

/// Ethernet → IPv4 → ESP with NULL encryption (RFC 2410 —
/// <https://www.rfc-editor.org/rfc/rfc2410>) whose payload is the inner
/// IPv4 datagram `inner`; the trailer has no padding and Next Header 4
/// (IPv4). RFC 4303, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc4303#section-2>.
fn esp_null(inner: &[u8]) -> Vec<u8> {
    let mut esp = 0x1001u32.to_be_bytes().to_vec();
    esp.extend_from_slice(&1u32.to_be_bytes());
    esp.extend_from_slice(inner);
    esp.extend_from_slice(&[0, 4]);
    ipv4(50, &esp)
}

fn esp_registry() -> DissectorRegistry {
    use packet_dissector::dissectors::esp::{AuthenticationAlgorithm, EncryptionAlgorithm, EspSa};

    let reg = DissectorRegistry::default();
    reg.add_esp_sa(
        0x1001,
        EspSa {
            encryption: EncryptionAlgorithm::Null,
            enc_key: vec![],
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
            esn: None,
        },
    );
    reg
}

#[test]
fn esp_decrypted_inner_chain_reports_state() {
    // The SA is configuration, not state learned from packets.
    let reg = esp_registry();
    let inner_udp = esp_null(&ipv4_header(17, &udp(40000, 53, &dns_query())));
    let mut buf = DissectBuffer::new();
    reg.dissect(&inner_udp, &mut buf).unwrap();
    assert!(buf.layer_by_name("DNS").is_some());
    assert!(!buf.used_cross_packet_state());

    let inner_tcp = esp_null(&ipv4_header(6, &tcp(40000, 9, 0, 0x02, &[])));
    let mut buf = DissectBuffer::new();
    reg.dissect(&inner_tcp, &mut buf).unwrap();
    assert_eq!(buf.layers().iter().filter(|l| l.name == "TCP").count(), 1);
    assert!(buf.used_cross_packet_state());
}

#[test]
fn esp_decrypted_inner_error_keeps_state() {
    // The inner TCP segment assigns a stream ID, then its BGP message fails
    // (Marker not all ones, RFC 4271, Section 4.1 —
    // https://www.rfc-editor.org/rfc/rfc4271#section-4.1).
    let reg = esp_registry();
    let mut bgp = vec![0u8; 16];
    bgp.extend_from_slice(&[0, 19, 4]);
    let packet = esp_null(&ipv4_header(6, &tcp(40000, 179, 1, 0x18, &bgp)));
    let mut buf = DissectBuffer::new();
    assert!(reg.dissect(&packet, &mut buf).is_err());
    assert!(buf.used_cross_packet_state());
}

#[test]
fn flag_follows_buffer_reuse() {
    let reg = DissectorRegistry::default();
    let tcp_packet = ipv4(6, &tcp(40000, 9, 0, 0x02, &[]));
    let dns_packet = ipv4(17, &udp(40000, 53, &dns_query()));

    let mut buf = DissectBuffer::new();
    reg.dissect(&tcp_packet, &mut buf).unwrap();
    assert!(buf.used_cross_packet_state());
    buf.clear();
    reg.dissect(&dns_packet, &mut buf).unwrap();
    assert!(!buf.used_cross_packet_state());
    // Without clearing, the buffer reports whether any packet used state.
    reg.dissect(&tcp_packet, &mut buf).unwrap();
    reg.dissect(&dns_packet, &mut buf).unwrap();
    assert!(buf.used_cross_packet_state());
}
