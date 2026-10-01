//! # IP fragment reassembly (registry middleware) Coverage
//!
//! | Spec Section         | Description                                              | Test                                                    |
//! |----------------------|----------------------------------------------------------|---------------------------------------------------------|
//! | RFC 791 3.2          | In-order IPv4 fragments reassemble into UDP/DNS          | ipv4_fragments_in_order_reassemble                      |
//! | RFC 791 3.2          | Reverse-order IPv4 fragments reassemble                  | ipv4_fragments_in_reverse_order_reassemble              |
//! | RFC 791 3.2          | Duplicate IPv4 fragment does not break reassembly        | ipv4_duplicate_fragment_reassembles                     |
//! | RFC 791 3.2          | Overlapping IPv4 data: the more recent copy is used      | ipv4_overlap_uses_more_recent_copy                      |
//! | RFC 791 3.2          | Fragments grouped by src, dst, protocol and ID           | ipv4_fragments_of_different_datagrams_are_not_mixed     |
//! | RFC 791 3.2          | Incomplete datagram ends the chain after IPv4            | ipv4_incomplete_datagram_ends_after_ip                  |
//! | RFC 791 3.2          | Non-last fragment not on an 8-octet boundary is dropped  | ipv4_fragment_not_multiple_of_8_is_discarded            |
//! | RFC 791 3.1          | Reassembled Total Length above 65,535 is dropped         | ipv4_oversized_fragment_is_discarded                    |
//! | —                    | Conflicting last fragments abandon the datagram          | ipv4_conflicting_last_fragment_abandons_datagram        |
//! | RFC 4963 2           | Conflicting fragment restarts the datagram (ID reuse)    | ipv4_conflicting_last_fragment_restarts_datagram        |
//! | RFC 791 3.2          | IPv4 entry dissector fragments reassemble                | ipv4_entry_dissector_fragments_reassemble               |
//! | —                    | Snaplen-truncated fragment is dissected, not buffered    | ipv4_truncated_fragment_is_not_buffered                 |
//! | RFC 9293 3.1         | TCP segment in a fragmented datagram keeps its length    | ipv4_fragmented_tcp_segment_reassembles                 |
//! | RFC 9293 3.10        | Fragmented segment completes a buffered TCP stream       | ipv4_fragmented_segment_completes_buffered_tcp_stream   |
//! | —                    | Summary dissection leaves the reassembly state alone     | ipv4_summary_does_not_reassemble                        |
//! | —                    | Projected dissection leaves the reassembly state alone   | ipv4_projected_does_not_reassemble                      |
//! | RFC 8200 4.5         | In-order IPv6 fragments reassemble into UDP/DNS          | ipv6_fragments_in_order_reassemble                      |
//! | RFC 8200 4.5         | Reverse-order IPv6 fragments reassemble                  | ipv6_fragments_in_reverse_order_reassemble              |
//! | RFC 8200 4.5         | Next Header of the offset-zero fragment is used          | ipv6_next_header_from_first_fragment                    |
//! | RFC 8200 4.5         | Per-fragment extension headers precede Fragment header   | ipv6_fragments_after_hop_by_hop_reassemble              |
//! | RFC 8200 4.5, 5722 4 | Overlapping IPv6 fragments abandon the datagram          | ipv6_overlap_abandons_datagram                          |
//! | RFC 8200 4.5         | Exact duplicate IPv6 fragment is dropped, rest kept      | ipv6_exact_duplicate_is_dropped                         |
//! | RFC 8200 4.5         | M=1 fragment length not a multiple of 8 is discarded     | ipv6_fragment_not_multiple_of_8_is_discarded            |
//! | RFC 8200 4.5         | Reassembled Payload Length above 65,535 is discarded     | ipv6_oversized_fragment_is_discarded                    |
//! | RFC 8200 4.5         | Atomic fragment is processed on its own                  | ipv6_atomic_fragment_is_not_buffered                    |
//! | RFC 791 3.2          | Every IPv4 fragment marks cross-packet state             | ipv4_fragments_mark_cross_packet_state                  |
//! | —                    | Unfragmented / shallow dissection marks no state         | ipv4_unfragmented_and_shallow_mark_no_cross_packet_state |
//! | RFC 8200 4.5         | Every IPv6 fragment marks cross-packet state             | ipv6_fragments_mark_cross_packet_state                  |
//! | RFC 8200 4.5         | Atomic fragment marks no cross-packet state              | ipv6_atomic_fragment_marks_no_cross_packet_state        |

#![cfg(all(
    feature = "ip-reassembly",
    feature = "ethernet",
    feature = "ipv4",
    feature = "ipv6",
    feature = "tcp",
    feature = "udp",
    feature = "dns"
))]

mod common;

use packet_dissector::field::FieldValue;
use packet_dissector::packet::DissectBuffer;
use packet_dissector::registry::DissectorRegistry;

const SRC4: [u8; 4] = [192, 0, 2, 1];
const DST4: [u8; 4] = [192, 0, 2, 2];
const SRC6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const DST6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

/// A DNS response for `example.com` A with `answers` A records
/// (192.0.2.1, 192.0.2.2, ...), RFC 1035, Section 4.1.
/// <https://www.rfc-editor.org/rfc/rfc1035#section-4.1.>
fn dns_response(answers: u8) -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, answers, 0, 0, 0, 0];
    m.extend_from_slice(b"\x07example\x03com\x00");
    m.extend_from_slice(&[0, 1, 0, 1]);
    for i in 0..answers {
        m.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4]);
        m.extend_from_slice(&[192, 0, 2, i + 1]);
    }
    m
}

/// UDP datagram from port 53 to port 40000 carrying `payload`.
fn udp(payload: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&53u16.to_be_bytes());
    d.extend_from_slice(&40000u16.to_be_bytes());
    d.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(payload);
    d
}

/// TCP segment from port 53 to port 40000 (PSH|ACK) carrying `payload`.
fn tcp(seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&53u16.to_be_bytes());
    d.extend_from_slice(&40000u16.to_be_bytes());
    d.extend_from_slice(&seq.to_be_bytes());
    d.extend_from_slice(&0u32.to_be_bytes());
    d.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    d.extend_from_slice(payload);
    d
}

fn ethernet(ethertype: u16) -> Vec<u8> {
    let mut p = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    p.extend_from_slice(&ethertype.to_be_bytes());
    p
}

/// Ethernet + IPv4 packet carrying `data` with the given fragmentation
/// fields (RFC 791, Section 3.1). `offset` is in 8-octet units.
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
fn ipv4(id: u16, protocol: u8, mf: bool, offset: u16, data: &[u8]) -> Vec<u8> {
    let mut p = ethernet(0x0800);
    p.extend_from_slice(&[0x45, 0x00]);
    p.extend_from_slice(&((20 + data.len()) as u16).to_be_bytes());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&((u16::from(mf) << 13) | offset).to_be_bytes());
    p.extend_from_slice(&[64, protocol, 0, 0]);
    p.extend_from_slice(&SRC4);
    p.extend_from_slice(&DST4);
    p.extend_from_slice(data);
    p
}

/// Ethernet + IPv6 packet carrying `ext` (extension headers ending in a
/// Fragment header) and `data`. `first_nh` is the IPv6 Next Header.
fn ipv6_raw(first_nh: u8, ext: &[u8], data: &[u8]) -> Vec<u8> {
    let mut p = ethernet(0x86dd);
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&((ext.len() + data.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[first_nh, 64]);
    p.extend_from_slice(&SRC6);
    p.extend_from_slice(&DST6);
    p.extend_from_slice(ext);
    p.extend_from_slice(data);
    p
}

/// IPv6 Fragment header (RFC 8200, Section 4.5). `offset` is in 8-octet units.
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>
fn fragment_header(next_header: u8, id: u32, m: bool, offset: u16) -> [u8; 8] {
    let off_m = (offset << 3) | u16::from(m);
    let mut h = [next_header, 0, 0, 0, 0, 0, 0, 0];
    h[2..4].copy_from_slice(&off_m.to_be_bytes());
    h[4..8].copy_from_slice(&id.to_be_bytes());
    h
}

/// Ethernet + IPv6 + Fragment header + `data`.
fn ipv6(id: u32, next_header: u8, m: bool, offset: u16, data: &[u8]) -> Vec<u8> {
    ipv6_raw(44, &fragment_header(next_header, id, m, offset), data)
}

/// Split `payload` into fragments of the given sizes (the last one takes
/// the rest): (offset in 8-octet units, more fragments, data).
fn split<'a>(payload: &'a [u8], sizes: &[usize]) -> Vec<(u16, bool, &'a [u8])> {
    let mut out = Vec::new();
    let mut pos = 0;
    for &size in sizes {
        out.push(((pos / 8) as u16, true, &payload[pos..pos + size]));
        pos += size;
    }
    out.push(((pos / 8) as u16, false, &payload[pos..]));
    out
}

fn names(buf: &DissectBuffer<'_>) -> Vec<&'static str> {
    buf.layers().iter().map(|l| l.name).collect()
}

/// Assert that all layers have contiguous, non-empty byte ranges, and that
/// each is listed with fields by `all_field_schemas()`.
fn assert_layers_contiguous(buf: &DissectBuffer<'_>) {
    common::assert_layers_have_schema(buf);
    let mut expected_start = 0;
    for layer in buf.layers() {
        assert_eq!(layer.range.start, expected_start, "layer {}", layer.name);
        assert!(layer.range.end > layer.range.start, "layer {}", layer.name);
        expected_start = layer.range.end;
    }
}

/// Names and values of every field of the layers named in `layers`, for
/// comparing a reassembled dissection with an unfragmented one. Container
/// values hold flat-buffer indices, which differ when the IP layer carries
/// reassembly fields, so only their kind is compared.
fn upper_fields(buf: &DissectBuffer<'_>, layers: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for layer in buf.layers().iter().filter(|l| layers.contains(&l.name)) {
        out.push(layer.name.to_string());
        for field in buf.layer_fields(layer) {
            let value = match field.value {
                FieldValue::Array(_) => "Array".to_string(),
                FieldValue::Object(_) => "Object".to_string(),
                ref v => format!("{v:?}"),
            };
            out.push(format!("{}={value}", field.name()));
        }
    }
    out
}

/// All `rdata` IPv4 addresses decoded in the buffer.
fn a_records(buf: &DissectBuffer<'_>) -> Vec<[u8; 4]> {
    buf.fields()
        .iter()
        .filter(|f| f.name() == "rdata")
        .filter_map(|f| match f.value {
            FieldValue::Ipv4Addr(a) => Some(a),
            _ => None,
        })
        .collect()
}

fn u_field(buf: &DissectBuffer<'_>, layer: &str, name: &str) -> Option<u32> {
    let layer = buf.layers().iter().rev().find(|l| l.name == layer)?;
    match buf.field_by_name(layer, name)?.value {
        FieldValue::U8(v) => Some(u32::from(v)),
        FieldValue::U16(v) => Some(u32::from(v)),
        FieldValue::U32(v) => Some(v),
        _ => None,
    }
}

/// Feed `packets` to `reg` in order and return the layer names of each.
fn feed(reg: &DissectorRegistry, packets: &[Vec<u8>]) -> Vec<Vec<&'static str>> {
    packets
        .iter()
        .map(|p| {
            let mut buf = DissectBuffer::new();
            reg.dissect(p, &mut buf).unwrap();
            names(&buf)
        })
        .collect()
}

/// Check that the upper layers in `buf` match those of the unfragmented
/// `reference` packet.
fn assert_upper_match(buf: &DissectBuffer<'_>, reference: &[u8]) {
    assert_layers_contiguous(buf);
    let mut ref_buf = DissectBuffer::new();
    DissectorRegistry::default()
        .dissect(reference, &mut ref_buf)
        .unwrap();
    let upper = ["UDP", "TCP", "DNS"];
    assert!(!upper_fields(&ref_buf, &upper).is_empty());
    assert_eq!(upper_fields(buf, &upper), upper_fields(&ref_buf, &upper));
}

/// Dissect `packet` on `reg` and check that it completes a datagram whose
/// upper layers match the unfragmented `reference` packet.
fn assert_matches_unfragmented(reg: &DissectorRegistry, packet: &[u8], reference: &[u8]) {
    let mut buf = DissectBuffer::new();
    reg.dissect(packet, &mut buf).unwrap();
    assert_upper_match(&buf, reference);
}

fn ipv4_fragments(id: u16, payload: &[u8], sizes: &[usize]) -> Vec<Vec<u8>> {
    split(payload, sizes)
        .into_iter()
        .map(|(off, mf, d)| ipv4(id, 17, mf, off, d))
        .collect()
}

fn ipv6_fragments(id: u32, payload: &[u8], sizes: &[usize]) -> Vec<Vec<u8>> {
    split(payload, sizes)
        .into_iter()
        .map(|(off, m, d)| ipv6(id, 17, m, off, d))
        .collect()
}

#[test]
fn ipv4_fragments_in_order_reassemble() {
    let datagram = udp(&dns_response(10));
    let frags = ipv4_fragments(0x2a, &datagram, &[64, 64]);
    let reg = DissectorRegistry::default();

    let layers = feed(&reg, &frags[..2]);
    assert_eq!(layers, vec![vec!["Ethernet", "IPv4"]; 2]);

    let mut buf = DissectBuffer::new();
    reg.dissect(&frags[2], &mut buf).unwrap();
    assert_eq!(names(&buf), ["Ethernet", "IPv4", "UDP", "DNS"]);
    assert_eq!(
        a_records(&buf),
        (1..=10).map(|i| [192, 0, 2, i]).collect::<Vec<_>>()
    );
    assert_eq!(u_field(&buf, "IPv4", "fragment_count"), Some(3));
    assert_eq!(
        u_field(&buf, "IPv4", "reassembled_length"),
        Some(datagram.len() as u32)
    );
    assert_upper_match(&buf, &ipv4(0x2a, 17, false, 0, &datagram));
}

#[test]
fn ipv4_entry_dissector_fragments_reassemble() {
    // IPv4 as the entry dissector (raw IPv4 input without a link layer).
    use packet_dissector::dissectors::ipv4::Ipv4Dissector;

    let datagram = udp(&dns_response(10));
    let mut reg = DissectorRegistry::default();
    reg.set_entry_dissector(Box::new(Ipv4Dissector));
    let frags: Vec<Vec<u8>> = ipv4_fragments(30, &datagram, &[64])
        .into_iter()
        .map(|p| p[14..].to_vec())
        .collect();

    let mut buf = DissectBuffer::new();
    reg.dissect(&frags[0], &mut buf).unwrap();
    assert_eq!(names(&buf), ["IPv4"]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&frags[1], &mut buf).unwrap();
    assert_eq!(names(&buf), ["IPv4", "UDP", "DNS"]);
    assert_eq!(a_records(&buf).len(), 10);
}

#[test]
fn ipv4_conflicting_last_fragment_restarts_datagram() {
    // A fragment that cannot belong to the buffered datagram (here a last
    // fragment ending before data already received) replaces the stale
    // fragments: with no reassembly timer they most likely belong to an
    // earlier datagram that reused the Identification (RFC 4963, Section 2).
    // https://www.rfc-editor.org/rfc/rfc4963#section-2
    let old = udp(&dns_response(10));
    let datagram = udp(&dns_response(2));
    let reg = DissectorRegistry::default();
    feed(&reg, &[ipv4(31, 17, true, 16, &old[128..136])]);
    let frags = ipv4_fragments(31, &datagram, &[32]);
    feed(&reg, &frags[1..]);
    assert_matches_unfragmented(&reg, &frags[0], &ipv4(31, 17, false, 0, &datagram));
}

#[test]
fn ipv4_fragments_in_reverse_order_reassemble() {
    let datagram = udp(&dns_response(10));
    let mut frags = ipv4_fragments(7, &datagram, &[48, 72]);
    frags.reverse();
    let reg = DissectorRegistry::default();

    let layers = feed(&reg, &frags[..2]);
    assert_eq!(layers, vec![vec!["Ethernet", "IPv4"]; 2]);
    // The first fragment arrives last and completes the datagram.
    assert_matches_unfragmented(&reg, &frags[2], &ipv4(7, 17, false, 0, &datagram));
}

#[test]
fn ipv4_duplicate_fragment_reassembles() {
    let datagram = udp(&dns_response(10));
    let frags = ipv4_fragments(8, &datagram, &[64, 64]);
    let reg = DissectorRegistry::default();

    feed(
        &reg,
        &[frags[0].clone(), frags[1].clone(), frags[1].clone()],
    );
    assert_matches_unfragmented(&reg, &frags[2], &ipv4(8, 17, false, 0, &datagram));
    let mut buf = DissectBuffer::new();
    DissectorRegistry::default()
        .dissect(&frags[2], &mut buf)
        .unwrap();
    assert_eq!(names(&buf), ["Ethernet", "IPv4"]);
}

#[test]
fn ipv4_overlap_uses_more_recent_copy() {
    // RFC 791, Section 3.2 — "In the case that two or more fragments contain
    // the same data either identically or through a partial overlap, this
    // procedure will use the more recently arrived copy in the data buffer
    // and datagram delivered."
    // https://www.rfc-editor.org/rfc/rfc791#section-3.2
    let datagram = udp(&dns_response(4));
    let mut bogus = datagram[..16].to_vec();
    bogus[8..].fill(0xff);
    let reg = DissectorRegistry::default();

    feed(
        &reg,
        &[
            ipv4(9, 17, true, 0, &bogus),
            ipv4(9, 17, true, 0, &datagram[..16]),
        ],
    );
    assert_matches_unfragmented(
        &reg,
        &ipv4(9, 17, false, 2, &datagram[16..]),
        &ipv4(9, 17, false, 0, &datagram),
    );
}

#[test]
fn ipv4_fragments_of_different_datagrams_are_not_mixed() {
    let datagram = udp(&dns_response(4));
    let reg = DissectorRegistry::default();
    let first = ipv4(1, 17, true, 0, &datagram[..16]);
    // Same ID but different protocol, and different ID.
    let other_protocol = ipv4(1, 6, false, 2, &datagram[16..]);
    let other_id = ipv4(2, 17, false, 2, &datagram[16..]);

    let layers = feed(&reg, &[first, other_protocol, other_id]);
    assert_eq!(layers, vec![vec!["Ethernet", "IPv4"]; 3]);
}

#[test]
fn ipv4_incomplete_datagram_ends_after_ip() {
    // The issue's reproduction: only the second fragment of a UDP datagram.
    let reg = DissectorRegistry::default();
    let packet = ipv4(0x2a, 17, false, 1, &[0xde, 0xad, 0xbe, 0xef, 0, 0x10, 0, 0]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&packet, &mut buf).unwrap();
    assert_eq!(names(&buf), ["Ethernet", "IPv4"]);
    assert_eq!(u_field(&buf, "IPv4", "fragment_count"), None);
}

#[test]
fn ipv4_fragment_not_multiple_of_8_is_discarded() {
    // RFC 791, Section 3.2 — "If an internet datagram is fragmented, its data
    // portion must be broken on 8 octet boundaries."
    // https://www.rfc-editor.org/rfc/rfc791#section-3.2
    let datagram = udp(&dns_response(4));
    let reg = DissectorRegistry::default();
    feed(&reg, &[ipv4(3, 17, true, 0, &datagram[..12])]);
    let layers = feed(&reg, &[ipv4(3, 17, false, 1, &datagram[8..])]);
    assert_eq!(layers, vec![vec!["Ethernet", "IPv4"]]);
}

#[test]
fn ipv4_oversized_fragment_is_discarded() {
    // RFC 791, Section 3.1 — Total Length is a 16-bit field, so a datagram
    // whose fragments end past 65,535 octets cannot be reassembled.
    // https://www.rfc-editor.org/rfc/rfc791#section-3.1
    let reg = DissectorRegistry::default();
    let datagram = udp(&dns_response(1));
    feed(&reg, &[ipv4(4, 17, true, 0, &datagram[..8])]);
    let tail = vec![0u8; 16];
    // Offset 8190 * 8 = 65520; 20 + 65520 + 16 > 65535.
    let layers = feed(&reg, &[ipv4(4, 17, false, 8190, &tail)]);
    assert_eq!(layers, vec![vec!["Ethernet", "IPv4"]]);
}

#[test]
fn ipv4_conflicting_last_fragment_abandons_datagram() {
    let datagram = udp(&dns_response(4));
    let reg = DissectorRegistry::default();
    feed(
        &reg,
        &[
            ipv4(5, 17, false, 4, &datagram[32..40]),
            // A second "last" fragment ending elsewhere is inconsistent.
            ipv4(5, 17, false, 5, &datagram[40..]),
        ],
    );
    let layers = feed(&reg, &[ipv4(5, 17, true, 0, &datagram[..32])]);
    assert_eq!(layers, vec![vec!["Ethernet", "IPv4"]]);
}

#[test]
fn ipv4_truncated_fragment_is_not_buffered() {
    let datagram = udp(&dns_response(4));
    let reg = DissectorRegistry::default();
    let mut first = ipv4(6, 17, true, 0, &datagram[..32]);
    first.truncate(first.len() - 8); // snaplen cut
    // Not reassembled: the first fragment's own upper layers are dissected
    // as far as they were captured.
    let mut buf = DissectBuffer::new();
    let _ = reg.dissect(&first, &mut buf);
    assert_eq!(&names(&buf)[..3], ["Ethernet", "IPv4", "UDP"]);
    let layers = feed(&reg, &[ipv4(6, 17, false, 4, &datagram[32..])]);
    assert_eq!(layers, vec![vec!["Ethernet", "IPv4"]]);
}

#[test]
fn ipv4_fragmented_tcp_segment_reassembles() {
    // DNS over TCP (RFC 7766): 2-octet length prefix + message.
    let message = dns_response(6);
    let mut stream = (message.len() as u16).to_be_bytes().to_vec();
    stream.extend_from_slice(&message);
    let segment = tcp(1000, &stream);
    let reg = DissectorRegistry::default();
    let frags: Vec<_> = split(&segment, &[64])
        .into_iter()
        .map(|(off, mf, d)| ipv4(11, 6, mf, off, d))
        .collect();

    feed(&reg, &frags[..1]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&frags[1], &mut buf).unwrap();
    assert_eq!(names(&buf), ["Ethernet", "IPv4", "TCP", "DNS"]);
    assert_eq!(
        a_records(&buf),
        (1..=6).map(|i| [192, 0, 2, i]).collect::<Vec<_>>()
    );
}

#[test]
fn ipv4_fragmented_segment_completes_buffered_tcp_stream() {
    // An HTTP request split across two TCP segments; the second segment is
    // fragmented. The request is reassembled by the TCP middleware inside
    // the reassembled datagram, and its fields must stay valid after the
    // inner dissection is merged into the packet's buffer.
    let request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let (head, tail) = request.split_at(10);
    let tcp80 = |seq: u32, payload: &[u8]| {
        let mut d = tcp(seq, payload);
        d[0..2].copy_from_slice(&40000u16.to_be_bytes());
        d[2..4].copy_from_slice(&80u16.to_be_bytes());
        d
    };
    let reg = DissectorRegistry::default();
    feed(&reg, &[ipv4(20, 6, false, 0, &tcp80(1, head))]);
    let segment = tcp80(1 + head.len() as u32, tail);
    let frags: Vec<_> = split(&segment, &[24])
        .into_iter()
        .map(|(off, mf, d)| ipv4(21, 6, mf, off, d))
        .collect();
    feed(&reg, &frags[..1]);

    let mut buf = DissectBuffer::new();
    reg.dissect(&frags[1], &mut buf).unwrap();
    assert_eq!(names(&buf), ["Ethernet", "IPv4", "TCP", "HTTP"]);
    let http = buf.layer_by_name("HTTP").unwrap();
    assert_eq!(buf.field_str(http, "method"), Some("GET"));
    assert_eq!(buf.field_str(http, "uri"), Some("/index.html"));
}

#[test]
fn ipv4_summary_does_not_reassemble() {
    // Shallow dissection leaves the (stateful) reassembly alone: the first
    // fragment is summarized by its own transport header and a non-initial
    // fragment ends after IPv4.
    let datagram = udp(&dns_response(10));
    let frags = ipv4_fragments(12, &datagram, &[64]);
    let reg = DissectorRegistry::default();

    let mut buf = DissectBuffer::new();
    let summary = reg.dissect_summary(&frags[0], &mut buf).unwrap();
    assert_eq!(names(&buf), ["Ethernet", "IPv4", "UDP"]);
    assert_eq!(summary.next_protocol, Some("DNS"));

    let mut buf = DissectBuffer::new();
    let summary = reg.dissect_summary(&frags[1], &mut buf).unwrap();
    assert_eq!(names(&buf), ["Ethernet", "IPv4"]);
    assert_eq!(summary.next_protocol, None);

    // Full dissection of the same packets still reassembles the datagram.
    feed(&reg, &frags[..1]);
    assert_matches_unfragmented(&reg, &frags[1], &ipv4(12, 17, false, 0, &datagram));
}

#[test]
fn ipv4_projected_does_not_reassemble() {
    use packet_dissector::summary::FieldProjection;

    let datagram = udp(&dns_response(10));
    let frags = ipv4_fragments(13, &datagram, &[64]);
    let reg = DissectorRegistry::default();
    let mut projection = FieldProjection::new([("DNS", "id")]);
    for frag in &frags {
        let mut buf = DissectBuffer::new();
        let _ = reg.dissect_projected(frag, &mut buf, &mut projection);
    }
    // The last fragment ended after IPv4 and the state was not touched.
    assert!(!projection.is_satisfied());
    feed(&reg, &frags[..1]);
    assert_matches_unfragmented(&reg, &frags[1], &ipv4(13, 17, false, 0, &datagram));
}

#[test]
fn ipv6_fragments_in_order_reassemble() {
    let datagram = udp(&dns_response(10));
    let frags = ipv6_fragments(0xdead_beef, &datagram, &[64, 64]);
    let reg = DissectorRegistry::default();

    let layers = feed(&reg, &frags[..2]);
    assert_eq!(layers, vec![vec!["Ethernet", "IPv6", "IPv6 Fragment"]; 2]);

    let mut buf = DissectBuffer::new();
    reg.dissect(&frags[2], &mut buf).unwrap();
    assert_eq!(
        names(&buf),
        ["Ethernet", "IPv6", "IPv6 Fragment", "UDP", "DNS"]
    );
    assert_eq!(u_field(&buf, "IPv6 Fragment", "fragment_count"), Some(3));
    assert_eq!(
        u_field(&buf, "IPv6 Fragment", "reassembled_length"),
        Some(datagram.len() as u32)
    );
    assert_upper_match(&buf, &ipv6_raw(17, &[], &datagram));
}

#[test]
fn ipv6_fragments_in_reverse_order_reassemble() {
    let datagram = udp(&dns_response(10));
    let mut frags = ipv6_fragments(1, &datagram, &[80, 40]);
    frags.reverse();
    let reg = DissectorRegistry::default();

    feed(&reg, &frags[..2]);
    assert_matches_unfragmented(&reg, &frags[2], &ipv6_raw(17, &[], &datagram));
}

#[test]
fn ipv6_next_header_from_first_fragment() {
    // RFC 8200, Section 4.5 — "The Next Header values in the Fragment headers
    // of different fragments of the same original packet may differ. Only
    // the value from the Offset zero fragment packet is used for
    // reassembly."
    // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
    let datagram = udp(&dns_response(4));
    let reg = DissectorRegistry::default();
    feed(&reg, &[ipv6(2, 17, true, 0, &datagram[..32])]);
    assert_matches_unfragmented(
        &reg,
        &ipv6(2, 59, false, 4, &datagram[32..]),
        &ipv6_raw(17, &[], &datagram),
    );
}

#[test]
fn ipv6_fragments_after_hop_by_hop_reassemble() {
    // Hop-by-Hop Options header (8 octets, PadN) before the Fragment header.
    let datagram = udp(&dns_response(4));
    let reg = DissectorRegistry::default();
    let ext = |m: bool, offset: u16| {
        let mut e = vec![44, 0, 1, 4, 0, 0, 0, 0];
        e.extend_from_slice(&fragment_header(17, 3, m, offset));
        e
    };
    feed(&reg, &[ipv6_raw(0, &ext(true, 0), &datagram[..32])]);
    let last = ipv6_raw(0, &ext(false, 4), &datagram[32..]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&last, &mut buf).unwrap();
    assert_eq!(
        names(&buf),
        [
            "Ethernet",
            "IPv6",
            "IPv6 Hop-by-Hop",
            "IPv6 Fragment",
            "UDP",
            "DNS"
        ]
    );
    assert_eq!(a_records(&buf).len(), 4);
}

#[test]
fn ipv6_overlap_abandons_datagram() {
    // RFC 8200, Section 4.5 — "If any of the fragments being reassembled
    // overlap with any other fragments being reassembled for the same
    // packet, reassembly of that packet must be abandoned and all the
    // fragments that have been received for that packet must be
    // discarded".
    // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
    let datagram = udp(&dns_response(4));
    let reg = DissectorRegistry::default();
    feed(
        &reg,
        &[
            ipv6(4, 17, true, 0, &datagram[..32]),
            ipv6(4, 17, true, 2, &datagram[16..40]),
        ],
    );
    // RFC 5722, Section 4 — "the entire datagram (and any constituent
    // fragments, including those not yet received) MUST be silently
    // discarded." Well-formed fragments sent afterwards do not complete it.
    // https://www.rfc-editor.org/rfc/rfc5722#section-4
    let layers = feed(
        &reg,
        &[
            ipv6(4, 17, false, 5, &datagram[40..]),
            ipv6(4, 17, true, 0, &datagram[..40]),
        ],
    );
    assert_eq!(layers, vec![vec!["Ethernet", "IPv6", "IPv6 Fragment"]; 2]);
}

#[test]
fn ipv6_exact_duplicate_is_dropped() {
    // RFC 8200, Section 4.5 — "an implementation may choose to detect this
    // case and drop exact duplicate fragments while keeping the other
    // fragments belonging to the same packet."
    // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
    let datagram = udp(&dns_response(10));
    let frags = ipv6_fragments(5, &datagram, &[64, 64]);
    let reg = DissectorRegistry::default();
    feed(
        &reg,
        &[frags[0].clone(), frags[1].clone(), frags[0].clone()],
    );
    assert_matches_unfragmented(&reg, &frags[2], &ipv6_raw(17, &[], &datagram));
}

#[test]
fn ipv6_fragment_not_multiple_of_8_is_discarded() {
    // RFC 8200, Section 4.5 — "If the length of a fragment, as derived from
    // the fragment packet's Payload Length field, is not a multiple of 8
    // octets and the M flag of that fragment is 1, then that fragment must
    // be discarded".
    // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
    let datagram = udp(&dns_response(4));
    let reg = DissectorRegistry::default();
    feed(&reg, &[ipv6(6, 17, true, 0, &datagram[..20])]);
    let layers = feed(&reg, &[ipv6(6, 17, false, 2, &datagram[16..])]);
    assert_eq!(layers, vec![vec!["Ethernet", "IPv6", "IPv6 Fragment"]]);
}

#[test]
fn ipv6_oversized_fragment_is_discarded() {
    // RFC 8200, Section 4.5 — "If the length and offset of a fragment are
    // such that the Payload Length of the packet reassembled from that
    // fragment would exceed 65,535 octets, then that fragment must be
    // discarded".
    // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
    let reg = DissectorRegistry::default();
    let datagram = udp(&dns_response(1));
    feed(&reg, &[ipv6(7, 17, true, 0, &datagram[..8])]);
    // 8191 * 8 + 16 = 65544 > 65535.
    let layers = feed(&reg, &[ipv6(7, 17, false, 8191, &[0; 16])]);
    assert_eq!(layers, vec![vec!["Ethernet", "IPv6", "IPv6 Fragment"]]);
}

#[test]
fn ipv6_atomic_fragment_is_not_buffered() {
    // RFC 8200, Section 4.5 — a whole datagram "should be processed as a
    // fully reassembled packet ... Any other fragments that match this
    // packet ... should be processed independently."
    // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
    let datagram = udp(&dns_response(4));
    let reg = DissectorRegistry::default();
    feed(&reg, &[ipv6(8, 17, true, 0, &datagram[..32])]);
    let atomic = ipv6(8, 17, false, 0, &datagram);
    let mut buf = DissectBuffer::new();
    reg.dissect(&atomic, &mut buf).unwrap();
    assert_eq!(
        names(&buf),
        ["Ethernet", "IPv6", "IPv6 Fragment", "UDP", "DNS"]
    );
    assert_eq!(u_field(&buf, "IPv6 Fragment", "fragment_count"), None);
}

/// Whether a full dissection of `packet` reports cross-packet state use.
fn marks_state(reg: &DissectorRegistry, packet: &[u8]) -> bool {
    let mut buf = DissectBuffer::new();
    reg.dissect(packet, &mut buf).unwrap();
    buf.used_cross_packet_state()
}

#[test]
fn ipv4_fragments_mark_cross_packet_state() {
    // Buffered fragments change the reassembly state; the last one reads it.
    let datagram = udp(&dns_response(10));
    let frags = ipv4_fragments(0x51, &datagram, &[64, 64]);
    let reg = DissectorRegistry::default();
    for frag in &frags {
        assert!(marks_state(&reg, frag));
    }
    // A lone non-initial fragment is buffered too.
    let lone = ipv4(0x52, 17, false, 1, &[0xde, 0xad, 0xbe, 0xef, 0, 0x10, 0, 0]);
    assert!(marks_state(&reg, &lone));
}

#[test]
fn ipv4_unfragmented_and_shallow_mark_no_cross_packet_state() {
    use packet_dissector::summary::FieldProjection;

    let datagram = udp(&dns_response(10));
    let reg = DissectorRegistry::default();
    assert!(!marks_state(&reg, &ipv4(0x53, 17, false, 0, &datagram)));

    // Shallow dissection never feeds fragments to the reassembly.
    let frags = ipv4_fragments(0x54, &datagram, &[64]);
    for frag in &frags {
        let mut buf = DissectBuffer::new();
        reg.dissect_summary(frag, &mut buf).unwrap();
        assert!(!buf.used_cross_packet_state());
        let mut buf = DissectBuffer::new();
        let mut projection = FieldProjection::new([("DNS", "id")]);
        // The first fragment's DNS message is cut short (an error), which
        // must not hide state use either.
        let _ = reg.dissect_projected(frag, &mut buf, &mut projection);
        assert!(!buf.used_cross_packet_state());
    }
}

#[test]
fn ipv6_fragments_mark_cross_packet_state() {
    let datagram = udp(&dns_response(10));
    let frags = ipv6_fragments(0x55, &datagram, &[64, 64]);
    let reg = DissectorRegistry::default();
    for frag in &frags {
        assert!(marks_state(&reg, frag));
    }
    assert!(!marks_state(&reg, &ipv6_raw(17, &[], &datagram)));
}

#[test]
fn ipv6_atomic_fragment_marks_no_cross_packet_state() {
    // RFC 8200, Section 4.5 — an atomic fragment is a whole datagram and is
    // processed without the reassembly state.
    // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
    let datagram = udp(&dns_response(4));
    let reg = DissectorRegistry::default();
    assert!(!marks_state(&reg, &ipv6(0x56, 17, false, 0, &datagram)));
}
