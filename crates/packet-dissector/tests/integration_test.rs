//! End-to-end integration tests for multi-layer packet dissection.
//!
//! Tests full packet parsing through the DissectorRegistry, chaining
//! dissectors from L2 (Ethernet) through L7 (DNS).
//!
//! ## Test organisation
//!
//! | Stack                                    | Test                                          |
//! |------------------------------------------|-----------------------------------------------|
//! | Ethernet → IPv4 → UDP → DNS             | integration_ethernet_ipv4_udp_dns             |
//! | Ethernet → IPv4 → UDP → mDNS            | integration_ethernet_ipv4_udp_mdns            |
//! | Ethernet → IPv4 → TCP (SYN)             | integration_ethernet_ipv4_tcp_syn             |
//! | Ethernet → ARP                           | integration_ethernet_arp                      |
//! | Ethernet → LLDP                          | integration_ethernet_lldp                     |
//! | Ethernet → IPv4 → ICMP Echo             | integration_ethernet_ipv4_icmp_echo           |
//! | Ethernet → IPv4 → IGMPv2 Report         | integration_ethernet_ipv4_igmp_v2_report      |
//! | Ethernet → IPv4 → IGMPv3 Report         | integration_ethernet_ipv4_igmp_v3_report      |
//! | Ethernet → IPv6 → ICMPv6 Echo           | integration_ethernet_ipv6_icmpv6_echo         |
//! | Ethernet → IPv6 → TCP                    | integration_ethernet_ipv6_tcp                 |
//! | Ethernet → IPv6 → UDP → DNS             | integration_ethernet_ipv6_udp_dns             |
//! | Ethernet → IPv4 → SCTP                   | integration_ethernet_ipv4_sctp                |
//! | Ethernet → IPv4 → SCTP → Diameter (CER)  | integration_ethernet_ipv4_sctp_diameter       |
//! | Ethernet → IPv6 → HBH → Fragment → TCP  | integration_ethernet_ipv6_ext_headers         |
//! | 802.1Q → IPv4 → UDP                      | integration_vlan_ipv4_udp                     |
//! | 802.1ad QinQ → IPv4 → UDP                | integration_qinq_ipv4_udp                     |
//! | Unknown EtherType                         | integration_unknown_protocol_stops_gracefully |
//! | Ethernet → IPv4 → UDP → DHCP Discover    | integration_ethernet_ipv4_udp_dhcp_discover   |
//! | Ethernet → IPv4 → UDP → DHCP Offer       | integration_ethernet_ipv4_udp_dhcp_offer      |
//! | Ethernet → IPv4 → UDP → DHCP ACK (port 68)| integration_ethernet_ipv4_udp_dhcp_ack       |
//! | Ethernet → IPv6 → UDP → DHCPv6 Solicit    | integration_ethernet_ipv6_udp_dhcpv6_solicit |
//! | Ethernet → IPv6 → UDP → DHCPv6 Advertise  | integration_ethernet_ipv6_udp_dhcpv6_advertise |
//! | Ethernet → IPv6 → UDP → DHCPv6 Reply (PD) | integration_ethernet_ipv6_udp_dhcpv6_reply_pd |
//! | Ethernet → IPv6 → SRv6 → TCP              | integration_ethernet_ipv6_srv6_tcp            |
//! | Ethernet → IPv6 → SRv6 (3 SIDs) → UDP     | integration_ethernet_ipv6_srv6_multi_seg_udp  |
//! | Ethernet → IPv6 → SRv6 → IPv4 → TCP       | integration_ethernet_ipv6_srv6_inner_ipv4_tcp |
//! | Ethernet → IPv6 → SRv6 → IPv6 → UDP       | integration_ethernet_ipv6_srv6_inner_ipv6_udp |
//! | Ethernet → IPv6 → SRv6(mobile) → TCP       | integration_ethernet_ipv6_srv6_mobile_gtp6_e  |
//! | Ethernet → IPv4 → TCP → DNS (over TCP)    | integration_ethernet_ipv4_tcp_dns             |
//! | Ethernet → IPv6 → ICMPv6 NS               | integration_ethernet_ipv6_icmpv6_neighbor_solicitation |
//! | Ethernet → IPv6 → ICMPv6 RA + Prefix Info | integration_ethernet_ipv6_icmpv6_router_advertisement |
//! | Ethernet → IPv4 → UDP → GTPv1-U → IPv4     | integration_ethernet_ipv4_udp_gtpv1u_ipv4            |
//! | Ethernet → IPv4 → UDP → GTPv1-U → IPv6     | integration_ethernet_ipv4_udp_gtpv1u_ipv6            |
//! | Ethernet → IPv4 → UDP → GTPv1-U (ext) → IPv4 | integration_ethernet_ipv4_udp_gtpv1u_ext_ipv4      |
//! | Ethernet → IPv4 → TCP → HTTP GET              | integration_ethernet_ipv4_tcp_http_request          |
//! | Ethernet → IPv4 → TCP → HTTP 200 OK           | integration_ethernet_ipv4_tcp_http_response         |
//! | Ethernet → IPv4 → UDP → SIP INVITE            | integration_ethernet_ipv4_udp_sip_invite            |
//! | Ethernet → IPv4 → TCP → SIP 200 OK            | integration_ethernet_ipv4_tcp_sip_response          |
//! | Ethernet → IPv4 → UDP → GTPv2-C (Create Session) | integration_ethernet_ipv4_udp_gtpv2c_create_session |
//! | Ethernet → IPv4 → UDP → GTPv2-C (Echo Request)   | integration_ethernet_ipv4_udp_gtpv2c_echo_request   |
//! | Ethernet → IPv4 → UDP → PFCP (Heartbeat)          | integration_ethernet_ipv4_udp_pfcp_heartbeat        |
//! | Ethernet → IPv4 → UDP → PFCP (Session Est.)       | integration_ethernet_ipv4_udp_pfcp_session_establishment |
//! | SLL2 → IPv4 → UDP                                 | integration_sll2_ipv4_udp                           |
//! | SLL → IPv4 → UDP                                  | integration_sll_ipv4_udp                            |
//! | SLL2 → IPv6 → TCP (SYN)                           | integration_sll2_ipv6_tcp_syn                       |
//! | Ethernet → IPv4 → GRE → IPv4 → UDP                | integration_ethernet_ipv4_gre_ipv4                   |
//! | Ethernet → IPv4 → GRE → IPv6 → UDP                | integration_ethernet_ipv4_gre_ipv6                   |
//! | Ethernet → IPv4 → TCP → TLS ClientHello            | ethernet_ipv4_tcp_tls_client_hello                   |
//! | Ethernet → IPv4 → TCP → TLS Alert                  | ethernet_ipv4_tcp_tls_alert                          |
//! | Ethernet → IPv4 → UDP → STUN Binding Request       | integration_ethernet_ipv4_udp_stun_binding_request   |
//! | Ethernet → IPv4 → GRE (Key) → IPv4 → UDP          | integration_ethernet_ipv4_gre_key_ipv4               |
//! | link_type=1 (Ethernet) via dissect_with_link_type  | integration_dissect_with_link_type_ethernet          |
//! | Ethernet → LACP                                     | integration_ethernet_lacp                            |
//! | Ethernet → LLC → STP Config BPDU                    | integration_ethernet_llc_stp_config                  |
//! | Ethernet → LLC → STP TCN BPDU                       | integration_ethernet_llc_stp_tcn                     |
//! | Ethernet → LLC → RST BPDU                           | integration_ethernet_llc_rstp                        |
//! | Ethernet → MPLS → IPv4 → UDP                         | integration_ethernet_mpls_ipv4_udp                   |
//! | Ethernet → MPLS (2 labels) → IPv4 → UDP              | integration_ethernet_mpls_two_labels_ipv4_udp        |
//! | Ethernet → IPv4 → UDP → NTP (Client)                 | integration_ethernet_ipv4_udp_ntp_client             |
//! | Ethernet → IPv4 → UDP → BFD (Up)                     | integration_ethernet_ipv4_udp_bfd_up                 |
//! | PPP (HDLC) → IPv4 → UDP                               | integration_ppp_ipv4_udp                              |
//! | PPP → LCP (inline)                                     | integration_ppp_lcp_inline                            |
//! | Ethernet → IPv4 → UDP → GENEVE → Ethernet → IPv4 → UDP | integration_ethernet_ipv4_udp_geneve_ipv4        |
//! | Ethernet → IPv4 → UDP → GENEVE (opts) → Ethernet → IPv4 | integration_ethernet_ipv4_udp_geneve_with_options |
//! | Ethernet → IPv4 → UDP → L2TP → PPP → IPv4 → UDP          | ethernet_ipv4_udp_l2tp_ppp_ipv4_udp              |
//! | Ethernet → IPv4 → UDP → L2TP(L) → PPP → IPv4 → UDP      | ethernet_ipv4_udp_l2tp_length_ppp_ipv4_udp       |
//! | Ethernet → IPv4 → UDP → L2TP (control)                   | ethernet_ipv4_udp_l2tp_control                   |
//! | Ethernet → IPv4 → L2TPv3 (IP, data)                       | integration_ethernet_ipv4_l2tpv3_ip_data             |
//! | Ethernet → IPv4 → L2TPv3 (IP, control SCCRQ)              | integration_ethernet_ipv4_l2tpv3_ip_control          |
//! | Ethernet → IPv4 → UDP → L2TPv3-UDP (control SCCRP)        | integration_ethernet_ipv4_udp_l2tpv3_control         |
//! | Ethernet → IPv4 → UDP → L2TPv3-UDP (data)                 | integration_ethernet_ipv4_udp_l2tpv3_data            |
//! | Ethernet → IPv4 → AH → TCP                                 | integration_ethernet_ipv4_ah_tcp                     |
//! | Ethernet → IPv4 → ESP                                       | integration_ethernet_ipv4_esp                        |
//! | Ethernet → IPv4 → ESP (NULL tunnel) → IPv4 → UDP             | integration_ethernet_ipv4_esp_null_ipv4_udp          |
//! | Ethernet → IPv4 → ESP (NULL transport) → UDP                  | integration_ethernet_ipv4_esp_null_transport_udp     |
//! | Ethernet → IPv4 → UDP(500) → IKEv2 IKE_SA_INIT              | integration_ethernet_ipv4_udp_ike_sa_init            |
//! | Ethernet → IPv4 → UDP → RTP                                  | integration_ethernet_ipv4_udp_rtp                    |
//! | Ethernet → IPv4 → UDP → QUIC Initial                          | integration_ethernet_ipv4_udp_quic_initial            |
//! | Ethernet → IPv4 → UDP → QUIC Short Header                     | integration_ethernet_ipv4_udp_quic_short              |
//! | Ethernet → IPv4 → TCP → HTTP/2 (h2c)                        | integration_ethernet_ipv4_tcp_http2_settings         |
//! | Ethernet → IPv4 → TCP → HTTP/1.1 (via HttpDispatcher)       | integration_ethernet_ipv4_tcp_http_dispatcher_http11 |
//! | Ethernet → IPv4 → TCP → HTTP 301 (Content-Type dispatch)   | integration_ethernet_ipv4_tcp_http_response_content_type |

use packet_dissector::dissector::{
    DispatchHint, DissectResult, Dissector, DissectorPlugin, DissectorTable,
};
use packet_dissector::error::PacketError;
use packet_dissector::field::{FieldDescriptor, FieldValue, MacAddr};
use packet_dissector::packet::DissectBuffer;
use packet_dissector::registry::DissectorRegistry;

/// Encode a domain name into DNS wire format for test assertions.
fn dns_wire_name(name: &str) -> Vec<u8> {
    let mut result = Vec::new();
    if !name.is_empty() {
        for label in name.split('.') {
            result.push(label.len() as u8);
            result.extend_from_slice(label.as_bytes());
        }
    }
    result.push(0);
    result
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

/// Get the display name for a field from its display_fn, if any.
fn display_name_for(
    buf: &packet_dissector::packet::DissectBuffer<'_>,
    layer: &packet_dissector::packet::Layer,
    field_name: &str,
) -> Option<&'static str> {
    buf.resolve_display_name(layer, &format!("{field_name}_name"))
}

/// Collect the direct children of a container (Array or Object) from a flat field range.
///
/// In the flat buffer, an `Array(start..end)` contains its direct children and
/// all their nested fields. Each child that is itself an `Object(a..b)` or
/// `Array(a..b)` spans indices `[child_idx..b)`, so the next sibling starts at
/// index `b`. For scalar children the next sibling is at `child_idx + 1`.
fn direct_children<'a, 'pkt>(
    buf: &'a DissectBuffer<'pkt>,
    range: &std::ops::Range<u32>,
) -> Vec<&'a packet_dissector::field::Field<'pkt>> {
    let all = buf.nested_fields(range);
    let base = range.start as usize;
    let mut result = Vec::new();
    let mut i = 0usize;
    while i < all.len() {
        result.push(&all[i]);
        match &all[i].value {
            FieldValue::Object(r) | FieldValue::Array(r) => {
                // skip past all nested children
                i = (r.end as usize) - base;
            }
            _ => {
                i += 1;
            }
        }
    }
    result
}

/// Assert that all layers in the packet have contiguous, non-empty byte ranges.
fn assert_layers_contiguous(buf: &DissectBuffer<'_>) {
    let mut expected_start = 0;
    for layer in buf.layers() {
        assert_eq!(
            layer.range.start, expected_start,
            "Layer '{}' starts at {} but expected {}",
            layer.name, layer.range.start, expected_start
        );
        assert!(
            layer.range.end > layer.range.start,
            "Layer '{}' has empty range",
            layer.name
        );
        expected_start = layer.range.end;
    }
}

// ---------------------------------------------------------------------------
// Packet builder helpers
// ---------------------------------------------------------------------------

/// Ethernet header (14 bytes).
fn push_ethernet(pkt: &mut Vec<u8>, dst: [u8; 6], src: [u8; 6], ethertype: u16) {
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&ethertype.to_be_bytes());
}

/// 802.1Q VLAN tag (4 bytes). Call between Ethernet src MAC and real EtherType.
fn push_vlan_tag(pkt: &mut Vec<u8>, vid: u16, inner_ethertype: u16) {
    // TPID is already written as ethertype by push_ethernet (0x8100).
    // PCP=0, DEI=0, VID
    pkt.extend_from_slice(&vid.to_be_bytes());
    pkt.extend_from_slice(&inner_ethertype.to_be_bytes());
}

/// IPv4 header (20 bytes, IHL=5). Returns start index for length fixup.
fn push_ipv4(pkt: &mut Vec<u8>, protocol: u8, src: [u8; 4], dst: [u8; 4]) -> usize {
    let start = pkt.len();
    pkt.push(0x45); // Version=4, IHL=5
    pkt.push(0x00); // DSCP=0, ECN=0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Total Length (placeholder)
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // Identification
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // Flags + Fragment Offset
    pkt.push(64); // TTL
    pkt.push(protocol);
    pkt.extend_from_slice(&[0x00, 0x00]); // Header Checksum
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    start
}

/// Fix IPv4 Total Length field after payload has been appended.
fn fixup_ipv4_length(pkt: &mut [u8], ipv4_start: usize) {
    let total_len = (pkt.len() - ipv4_start) as u16;
    pkt[ipv4_start + 2..ipv4_start + 4].copy_from_slice(&total_len.to_be_bytes());
}

/// IPv6 header (40 bytes). Returns start index for payload-length fixup.
fn push_ipv6(pkt: &mut Vec<u8>, next_header: u8, src: [u8; 16], dst: [u8; 16]) -> usize {
    let start = pkt.len();
    pkt.push(0x60); // Version=6
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00); // Traffic Class + Flow Label
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Payload Length (placeholder)
    pkt.push(next_header);
    pkt.push(64); // Hop Limit
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    start
}

/// Fix IPv6 Payload Length field after payload has been appended.
fn fixup_ipv6_payload_length(pkt: &mut [u8], ipv6_start: usize) {
    let payload_len = (pkt.len() - ipv6_start - 40) as u16;
    pkt[ipv6_start + 4..ipv6_start + 6].copy_from_slice(&payload_len.to_be_bytes());
}

/// UDP header (8 bytes). Returns start index for length fixup.
fn push_udp(pkt: &mut Vec<u8>, src_port: u16, dst_port: u16) -> usize {
    let start = pkt.len();
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Length (placeholder)
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
    start
}

/// Fix UDP Length field after payload has been appended.
fn fixup_udp_length(pkt: &mut [u8], udp_start: usize) {
    let udp_len = (pkt.len() - udp_start) as u16;
    pkt[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());
}

/// TCP header (20 bytes, data offset=5).
fn push_tcp(pkt: &mut Vec<u8>, src_port: u16, dst_port: u16, flags: u8) {
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&0x00000001u32.to_be_bytes()); // Seq
    pkt.extend_from_slice(&0x00000000u32.to_be_bytes()); // Ack
    pkt.push(0x50); // Data Offset = 5
    pkt.push(flags);
    pkt.extend_from_slice(&65535u16.to_be_bytes()); // Window
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // Urgent Pointer
}

/// VXLAN header (8 bytes). I flag set, specified VNI.
///
/// # Panics
/// Panics if `vni` exceeds the 24-bit range (> 0x00FF_FFFF).
fn push_vxlan(pkt: &mut Vec<u8>, vni: u32) {
    assert!(vni <= 0x00FF_FFFF, "VNI must fit in 24 bits, got {vni:#x}");
    pkt.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]); // Flags (I=1), reserved
    let vni_be = vni.to_be_bytes();
    pkt.extend_from_slice(&vni_be[1..4]); // 24-bit VNI
    pkt.push(0x00); // Reserved
}

/// GRE header (variable length). No optional fields = 4 bytes.
fn push_gre(pkt: &mut Vec<u8>, protocol_type: u16) {
    // C=0, K=0, S=0, Ver=0
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&protocol_type.to_be_bytes());
}

/// GRE header with Key field (8 bytes).
fn push_gre_with_key(pkt: &mut Vec<u8>, protocol_type: u16, key: u32) {
    // K=1 (bit 2 of byte 0 = 0x20)
    pkt.extend_from_slice(&[0x20, 0x00]);
    pkt.extend_from_slice(&protocol_type.to_be_bytes());
    pkt.extend_from_slice(&key.to_be_bytes());
}

/// ICMP Echo Request/Reply (8 bytes).
fn push_icmp_echo(pkt: &mut Vec<u8>, icmp_type: u8, id: u16, seq: u16) {
    pkt.push(icmp_type);
    pkt.push(0x00); // Code
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
}

/// ICMPv6 Echo Request/Reply (8 bytes).
fn push_icmpv6_echo(pkt: &mut Vec<u8>, icmpv6_type: u8, id: u16, seq: u16) {
    pkt.push(icmpv6_type);
    pkt.push(0x00); // Code
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
}

/// SCTP common header (12 bytes).
fn push_sctp(pkt: &mut Vec<u8>, src_port: u16, dst_port: u16) {
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&0xAABBCCDDu32.to_be_bytes()); // Verification Tag
    pkt.extend_from_slice(&0x00000000u32.to_be_bytes()); // Checksum
}

/// DNS query for "example.com" A record.
fn push_dns_query(pkt: &mut Vec<u8>, txid: u16) {
    pkt.extend_from_slice(&txid.to_be_bytes()); // Transaction ID
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // ARCOUNT
    // QNAME: example.com
    pkt.push(7);
    pkt.extend_from_slice(b"example");
    pkt.push(3);
    pkt.extend_from_slice(b"com");
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
}

/// IPv6 Hop-by-Hop extension header (8 bytes).
fn push_ipv6_hop_by_hop(pkt: &mut Vec<u8>, next_header: u8) {
    pkt.push(next_header);
    pkt.push(0); // Hdr Ext Len: 0 (= 8 bytes total)
    pkt.push(1); // PadN option type
    pkt.push(4); // PadN length
    pkt.extend_from_slice(&[0, 0, 0, 0]); // padding
}

/// IPv6 Fragment extension header (8 bytes).
fn push_ipv6_fragment(pkt: &mut Vec<u8>, next_header: u8, offset: u16, m_flag: bool, id: u32) {
    pkt.push(next_header);
    pkt.push(0); // Reserved
    let frag_word = (offset << 3) | if m_flag { 1 } else { 0 };
    pkt.extend_from_slice(&frag_word.to_be_bytes());
    pkt.extend_from_slice(&id.to_be_bytes());
}

// ---------------------------------------------------------------------------
// Composite packet builders (used by multiple tests)
// ---------------------------------------------------------------------------

const MAC_DST: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const MAC_SRC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
const IPV4_SRC: [u8; 4] = [192, 168, 1, 100];
const IPV4_DST: [u8; 4] = [8, 8, 8, 8];
const IPV6_SRC: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const IPV6_DST: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

fn build_eth_ipv4_udp_dns_query() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 17, IPV4_SRC, IPV4_DST);
    let udp_start = push_udp(&mut pkt, 12345, 53);
    push_dns_query(&mut pkt, 0xABCD);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ip_start);
    pkt
}

fn build_eth_ipv4_tcp_syn() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0; 6], [0; 6], 0x0800);
    let ip_start = push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]);
    push_tcp(&mut pkt, 54321, 80, 0x02); // SYN
    fixup_ipv4_length(&mut pkt, ip_start);
    pkt
}

fn build_eth_arp_request() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0xff; 6], MAC_SRC, 0x0806);
    // ARP (28 bytes for Ethernet/IPv4)
    pkt.extend_from_slice(&1u16.to_be_bytes()); // HTYPE: Ethernet
    pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // PTYPE: IPv4
    pkt.push(6); // HLEN
    pkt.push(4); // PLEN
    pkt.extend_from_slice(&1u16.to_be_bytes()); // OPER: Request
    pkt.extend_from_slice(&MAC_SRC); // SHA
    pkt.extend_from_slice(&[192, 168, 1, 1]); // SPA
    pkt.extend_from_slice(&[0x00; 6]); // THA
    pkt.extend_from_slice(&[192, 168, 1, 2]); // TPA
    pkt
}

fn build_eth_ipv4_icmp_echo() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 1, IPV4_SRC, IPV4_DST);
    push_icmp_echo(&mut pkt, 8, 0x1234, 1); // Echo Request
    fixup_ipv4_length(&mut pkt, ip_start);
    pkt
}

fn build_eth_ipv6_icmpv6_echo() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    let ip_start = push_ipv6(&mut pkt, 58, IPV6_SRC, IPV6_DST);
    push_icmpv6_echo(&mut pkt, 128, 0x5678, 42); // Echo Request
    fixup_ipv6_payload_length(&mut pkt, ip_start);
    pkt
}

fn build_eth_ipv6_tcp() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    let ip_start = push_ipv6(&mut pkt, 6, IPV6_SRC, IPV6_DST);
    push_tcp(&mut pkt, 54321, 443, 0x02); // SYN
    fixup_ipv6_payload_length(&mut pkt, ip_start);
    pkt
}

fn build_eth_ipv6_udp_dns() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    let ip_start = push_ipv6(&mut pkt, 17, IPV6_SRC, IPV6_DST);
    let udp_start = push_udp(&mut pkt, 12345, 53);
    push_dns_query(&mut pkt, 0xBEEF);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv6_payload_length(&mut pkt, ip_start);
    pkt
}

fn build_eth_ipv4_sctp() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 132, IPV4_SRC, IPV4_DST);
    push_sctp(&mut pkt, 36412, 36412); // Common SCTP ports (S1AP)
    fixup_ipv4_length(&mut pkt, ip_start);
    pkt
}

fn build_eth_ipv6_ext_headers_tcp() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    // IPv6 NH=0 (Hop-by-Hop)
    let ip_start = push_ipv6(&mut pkt, 0, IPV6_SRC, IPV6_DST);
    // Hop-by-Hop NH=44 (Fragment)
    push_ipv6_hop_by_hop(&mut pkt, 44);
    // Fragment NH=6 (TCP), offset=0, M=0, ID=0x12345678
    push_ipv6_fragment(&mut pkt, 6, 0, false, 0x12345678);
    // TCP SYN
    push_tcp(&mut pkt, 54321, 80, 0x02);
    fixup_ipv6_payload_length(&mut pkt, ip_start);
    pkt
}

fn build_vlan_ipv4_udp() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x8100); // 802.1Q TPID
    push_vlan_tag(&mut pkt, 100, 0x0800); // VID=100, inner=IPv4
    let ip_start = push_ipv4(&mut pkt, 17, IPV4_SRC, IPV4_DST);
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ip_start);
    pkt
}

fn build_qinq_ipv4_udp() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x88A8); // 802.1ad S-Tag
    push_vlan_tag(&mut pkt, 200, 0x8100); // outer tag points to inner C-Tag
    push_vlan_tag(&mut pkt, 100, 0x0800); // inner tag points to IPv4
    let ip_start = push_ipv4(&mut pkt, 17, IPV4_SRC, IPV4_DST);
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ip_start);
    pkt
}

// ---------------------------------------------------------------------------
// Ethernet, IPv4, IPv6, ARP, DNS
// ---------------------------------------------------------------------------

#[test]
fn integration_ethernet_ipv4_udp_dns() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv4_udp_dns_query();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);

    // Layer 0: Ethernet
    let eth = &buf.layers()[0];
    assert_eq!(eth.name, "Ethernet");
    assert_eq!(
        buf.field_by_name(eth, "ethertype").unwrap().value,
        FieldValue::U16(0x0800)
    );

    // Layer 1: IPv4
    let ipv4 = &buf.layers()[1];
    assert_eq!(ipv4.name, "IPv4");
    assert_eq!(
        buf.field_by_name(ipv4, "protocol").unwrap().value,
        FieldValue::U8(17)
    ); // UDP
    assert_eq!(
        buf.field_by_name(ipv4, "src").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 100])
    );
    assert_eq!(
        buf.field_by_name(ipv4, "dst").unwrap().value,
        FieldValue::Ipv4Addr([8, 8, 8, 8])
    );

    // Layer 2: UDP
    let udp = &buf.layers()[2];
    assert_eq!(udp.name, "UDP");
    assert_eq!(
        buf.field_by_name(udp, "src_port").unwrap().value,
        FieldValue::U16(12345)
    );
    assert_eq!(
        buf.field_by_name(udp, "dst_port").unwrap().value,
        FieldValue::U16(53)
    );

    // Layer 3: DNS
    let dns = &buf.layers()[3];
    assert_eq!(dns.name, "DNS");
    assert_eq!(
        buf.field_by_name(dns, "id").unwrap().value,
        FieldValue::U16(0xABCD)
    );
    assert_eq!(
        buf.field_by_name(dns, "qr").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(dns, "rd").unwrap().value,
        FieldValue::U8(1)
    );
    let questions = {
        let f = buf.field_by_name(dns, "questions").unwrap();
        let FieldValue::Array(ref r) = f.value else {
            panic!("expected Array")
        };
        buf.nested_fields(r)
    };
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _or) = questions[0].value else {
                    panic!("expected Object")
                };
                let _fs = buf.nested_fields(_or);
                _fs.iter()
                    .find(|f| f.name() == "name")
                    .unwrap()
                    .value
                    .clone()
            }
        },
        FieldValue::Bytes(dns_wire_name("example.com").leak())
    );
}

#[test]
fn integration_ethernet_ipv4_tcp_syn() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv4_tcp_syn();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 3);
    assert_layers_contiguous(&buf);

    let eth = &buf.layers()[0];
    assert_eq!(eth.name, "Ethernet");

    let ipv4 = &buf.layers()[1];
    assert_eq!(ipv4.name, "IPv4");
    assert_eq!(
        buf.field_by_name(ipv4, "protocol").unwrap().value,
        FieldValue::U8(6)
    ); // TCP

    let tcp = &buf.layers()[2];
    assert_eq!(tcp.name, "TCP");
    assert_eq!(
        buf.field_by_name(tcp, "src_port").unwrap().value,
        FieldValue::U16(54321)
    );
    assert_eq!(
        buf.field_by_name(tcp, "dst_port").unwrap().value,
        FieldValue::U16(80)
    );
    assert_eq!(
        buf.field_by_name(tcp, "flags").unwrap().value,
        FieldValue::U8(0x02)
    ); // SYN
}

#[test]
fn integration_ethernet_arp() {
    let reg = DissectorRegistry::default();
    let data = build_eth_arp_request();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 2);
    assert_layers_contiguous(&buf);

    let eth = &buf.layers()[0];
    assert_eq!(eth.name, "Ethernet");
    assert_eq!(
        buf.field_by_name(eth, "ethertype").unwrap().value,
        FieldValue::U16(0x0806)
    );

    let arp = &buf.layers()[1];
    assert_eq!(arp.name, "ARP");
    assert_eq!(
        buf.field_by_name(arp, "oper").unwrap().value,
        FieldValue::U16(1)
    ); // Request
    assert_eq!(
        buf.field_by_name(arp, "spa").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 1])
    );
    assert_eq!(
        buf.field_by_name(arp, "tpa").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 2])
    );
}

#[test]
fn integration_unknown_protocol_stops_gracefully() {
    let reg = DissectorRegistry::default();

    // Ethernet frame with unknown EtherType (0x9999)
    let mut pkt = vec![0u8; 14];
    pkt[12..14].copy_from_slice(&0x9999u16.to_be_bytes());

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 1);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[0].name, "Ethernet");
}

// ---------------------------------------------------------------------------
// ICMP
// ---------------------------------------------------------------------------

#[test]
fn integration_ethernet_ipv4_icmp_echo() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv4_icmp_echo();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 3);
    assert_layers_contiguous(&buf);

    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(
        buf.field_by_name(&buf.layers()[0], "ethertype")
            .unwrap()
            .value,
        FieldValue::U16(0x0800)
    );

    let ipv4 = &buf.layers()[1];
    assert_eq!(ipv4.name, "IPv4");
    assert_eq!(
        buf.field_by_name(ipv4, "protocol").unwrap().value,
        FieldValue::U8(1)
    ); // ICMP

    let icmp = &buf.layers()[2];
    assert_eq!(icmp.name, "ICMP");
    assert_eq!(
        buf.field_by_name(icmp, "type").unwrap().value,
        FieldValue::U8(8)
    ); // Echo Request
    assert_eq!(
        buf.field_by_name(icmp, "code").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(icmp, "identifier").unwrap().value,
        FieldValue::U16(0x1234)
    );
    assert_eq!(
        buf.field_by_name(icmp, "sequence_number").unwrap().value,
        FieldValue::U16(1)
    );
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

#[test]
fn integration_ethernet_ipv6_icmpv6_echo() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv6_icmpv6_echo();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 3);
    assert_layers_contiguous(&buf);

    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(
        buf.field_by_name(&buf.layers()[0], "ethertype")
            .unwrap()
            .value,
        FieldValue::U16(0x86DD)
    );

    let ipv6 = &buf.layers()[1];
    assert_eq!(ipv6.name, "IPv6");
    assert_eq!(
        buf.field_by_name(ipv6, "next_header").unwrap().value,
        FieldValue::U8(58)
    ); // ICMPv6
    assert_eq!(
        buf.field_by_name(ipv6, "src").unwrap().value,
        FieldValue::Ipv6Addr(IPV6_SRC)
    );
    assert_eq!(
        buf.field_by_name(ipv6, "dst").unwrap().value,
        FieldValue::Ipv6Addr(IPV6_DST)
    );

    let icmpv6 = &buf.layers()[2];
    assert_eq!(icmpv6.name, "ICMPv6");
    assert_eq!(
        buf.field_by_name(icmpv6, "type").unwrap().value,
        FieldValue::U8(128)
    ); // Echo Request
    assert_eq!(
        buf.field_by_name(icmpv6, "identifier").unwrap().value,
        FieldValue::U16(0x5678)
    );
    assert_eq!(
        buf.field_by_name(icmpv6, "sequence_number").unwrap().value,
        FieldValue::U16(42)
    );
}

#[test]
fn integration_ethernet_ipv6_tcp() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv6_tcp();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 3);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[0].name, "Ethernet");

    let ipv6 = &buf.layers()[1];
    assert_eq!(ipv6.name, "IPv6");
    assert_eq!(
        buf.field_by_name(ipv6, "next_header").unwrap().value,
        FieldValue::U8(6)
    );

    let tcp = &buf.layers()[2];
    assert_eq!(tcp.name, "TCP");
    assert_eq!(
        buf.field_by_name(tcp, "src_port").unwrap().value,
        FieldValue::U16(54321)
    );
    assert_eq!(
        buf.field_by_name(tcp, "dst_port").unwrap().value,
        FieldValue::U16(443)
    );
    assert_eq!(
        buf.field_by_name(tcp, "flags").unwrap().value,
        FieldValue::U8(0x02)
    ); // SYN
}

#[test]
fn integration_ethernet_ipv6_udp_dns() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv6_udp_dns();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv6");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "DNS");

    let dns = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(dns, "id").unwrap().value,
        FieldValue::U16(0xBEEF)
    );
    let questions = {
        let f = buf.field_by_name(dns, "questions").unwrap();
        let FieldValue::Array(ref r) = f.value else {
            panic!("expected Array")
        };
        buf.nested_fields(r)
    };
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _or) = questions[0].value else {
                    panic!("expected Object")
                };
                let _fs = buf.nested_fields(_or);
                _fs.iter()
                    .find(|f| f.name() == "name")
                    .unwrap()
                    .value
                    .clone()
            }
        },
        FieldValue::Bytes(dns_wire_name("example.com").leak())
    );
}

// ---------------------------------------------------------------------------
// SCTP
// ---------------------------------------------------------------------------

#[test]
fn integration_ethernet_ipv4_sctp() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv4_sctp();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 3);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[0].name, "Ethernet");

    let ipv4 = &buf.layers()[1];
    assert_eq!(ipv4.name, "IPv4");
    assert_eq!(
        buf.field_by_name(ipv4, "protocol").unwrap().value,
        FieldValue::U8(132)
    );

    let sctp = &buf.layers()[2];
    assert_eq!(sctp.name, "SCTP");
    assert_eq!(
        buf.field_by_name(sctp, "src_port").unwrap().value,
        FieldValue::U16(36412)
    );
    assert_eq!(
        buf.field_by_name(sctp, "dst_port").unwrap().value,
        FieldValue::U16(36412)
    );
    assert_eq!(
        buf.field_by_name(sctp, "verification_tag").unwrap().value,
        FieldValue::U32(0xAABBCCDD)
    );
}

/// Append an SCTP DATA chunk (type=0) with RFC 9260 Section 3.3.1 header.
fn push_sctp_data_chunk(pkt: &mut Vec<u8>, flags: u8, tsn: u32, ppi: u32, user_data: &[u8]) {
    let length = 16 + user_data.len();
    pkt.push(0); // type = DATA
    pkt.push(flags);
    pkt.extend_from_slice(&(length as u16).to_be_bytes());
    pkt.extend_from_slice(&tsn.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Stream ID
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Stream Seq
    pkt.extend_from_slice(&ppi.to_be_bytes());
    pkt.extend_from_slice(user_data);
    // Pad to 4-byte boundary
    let padding = (4 - (length % 4)) % 4;
    pkt.resize(pkt.len() + padding, 0);
}

/// Build a minimal Diameter CER (header + Origin-Host AVP).
fn build_diameter_cer_bytes() -> Vec<u8> {
    let origin_host = b"host.example.com";
    let avp_length = 8 + origin_host.len();
    let avp_padded = (avp_length + 3) & !3;
    let total = 20 + avp_padded;

    let mut buf = Vec::with_capacity(total);
    buf.push(1); // version
    buf.push(((total >> 16) & 0xFF) as u8);
    buf.push(((total >> 8) & 0xFF) as u8);
    buf.push((total & 0xFF) as u8);
    buf.push(0x80); // R flag (Request)
    buf.push(0x00);
    buf.push(0x01);
    buf.push(0x01); // command_code = 257 (CER)
    buf.extend_from_slice(&0u32.to_be_bytes()); // Application-ID
    buf.extend_from_slice(&1u32.to_be_bytes()); // HbH
    buf.extend_from_slice(&1u32.to_be_bytes()); // E2E

    // Origin-Host AVP (264, M flag)
    buf.extend_from_slice(&264u32.to_be_bytes());
    buf.push(0x40); // M flag
    buf.push(((avp_length >> 16) & 0xFF) as u8);
    buf.push(((avp_length >> 8) & 0xFF) as u8);
    buf.push((avp_length & 0xFF) as u8);
    buf.extend_from_slice(origin_host);
    buf.resize(total, 0);
    buf
}

fn build_eth_ipv4_sctp_diameter() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 132, IPV4_SRC, IPV4_DST);
    push_sctp(&mut pkt, 3868, 3868);
    let cer = build_diameter_cer_bytes();
    // B+E flags (0x03): Beginning and Ending fragment (unfragmented)
    push_sctp_data_chunk(&mut pkt, 0x03, 1, 46, &cer);
    fixup_ipv4_length(&mut pkt, ip_start);
    pkt
}

#[test]
fn integration_ethernet_ipv4_sctp_diameter() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv4_sctp_diameter();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert!(
        buf.layers().len() >= 4,
        "expected at least 4 layers, got {}",
        buf.layers().len()
    );
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "SCTP");
    assert_eq!(buf.layers()[3].name, "Diameter");

    let diameter = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(diameter, "command_code").unwrap().value,
        FieldValue::U32(257)
    );
    assert_eq!(
        buf.resolve_display_name(diameter, "command_code_name"),
        Some("Capabilities-Exchange-Request")
    );
}

// ---------------------------------------------------------------------------
// IPv6 extension headers
// ---------------------------------------------------------------------------

#[test]
fn integration_ethernet_ipv6_ext_headers() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv6_ext_headers_tcp();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 5);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv6");
    assert_eq!(buf.layers()[2].name, "IPv6 Hop-by-Hop");
    assert_eq!(buf.layers()[3].name, "IPv6 Fragment");
    assert_eq!(buf.layers()[4].name, "TCP");

    // Verify the extension header chain is correct
    let ipv6 = &buf.layers()[1];
    assert_eq!(
        buf.field_by_name(ipv6, "next_header").unwrap().value,
        FieldValue::U8(0)
    ); // Hop-by-Hop

    let hbh = &buf.layers()[2];
    assert_eq!(
        buf.field_by_name(hbh, "next_header").unwrap().value,
        FieldValue::U8(44) // Fragment
    );

    let frag = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(frag, "next_header").unwrap().value,
        FieldValue::U8(6) // TCP
    );
    assert_eq!(
        buf.field_by_name(frag, "identification").unwrap().value,
        FieldValue::U32(0x12345678)
    );

    let tcp = &buf.layers()[4];
    assert_eq!(
        buf.field_by_name(tcp, "src_port").unwrap().value,
        FieldValue::U16(54321)
    );
}

// ---------------------------------------------------------------------------
// 802.1Q VLAN
// ---------------------------------------------------------------------------

#[test]
fn integration_vlan_ipv4_udp() {
    let reg = DissectorRegistry::default();
    let data = build_vlan_ipv4_udp();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 3);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[0].name, "Ethernet");

    let eth = &buf.layers()[0];
    assert_eq!(
        buf.field_by_name(eth, "ethertype").unwrap().value,
        FieldValue::U16(0x0800)
    );
    // VLAN fields should be present
    assert!(buf.field_by_name(eth, "vlan_id").is_some());
    assert_eq!(
        buf.field_by_name(eth, "vlan_id").unwrap().value,
        FieldValue::U16(100)
    );

    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
}

#[test]
fn integration_qinq_ipv4_udp() {
    let reg = DissectorRegistry::default();
    let data = build_qinq_ipv4_udp();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 3);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[0].range, 0..22);

    let eth = &buf.layers()[0];
    let eth_fields = buf.layer_fields(eth);
    let vlan_tpids: Vec<_> = eth_fields
        .iter()
        .filter(|f| f.name() == "vlan_tpid")
        .map(|f| f.value.clone())
        .collect();
    let vlan_ids: Vec<_> = eth_fields
        .iter()
        .filter(|f| f.name() == "vlan_id")
        .map(|f| f.value.clone())
        .collect();

    assert_eq!(
        vlan_tpids,
        vec![FieldValue::U16(0x88A8), FieldValue::U16(0x8100)]
    );
    assert_eq!(vlan_ids, vec![FieldValue::U16(200), FieldValue::U16(100)]);
    assert_eq!(
        buf.field_by_name(eth, "ethertype").unwrap().value,
        FieldValue::U16(0x0800)
    );

    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
}

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

const MAC_DHCP_CLIENT: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

/// Build a minimal DHCP message (236-byte header + magic cookie + options).
fn build_dhcp_message(
    op: u8,
    xid: u32,
    chaddr: [u8; 6],
    yiaddr: [u8; 4],
    options: &[u8],
) -> Vec<u8> {
    let mut msg = vec![0u8; 236];
    msg[0] = op;
    msg[1] = 1; // htype: Ethernet
    msg[2] = 6; // hlen
    msg[4..8].copy_from_slice(&xid.to_be_bytes());
    msg[16..20].copy_from_slice(&yiaddr);
    msg[28..34].copy_from_slice(&chaddr);
    // Magic cookie
    msg.extend_from_slice(&[99, 130, 83, 99]);
    msg.extend_from_slice(options);
    msg
}

fn dhcp_option(code: u8, data: &[u8]) -> Vec<u8> {
    let mut opt = vec![code, data.len() as u8];
    opt.extend_from_slice(data);
    opt
}

/// Build Ethernet → IPv4 → UDP frame carrying a DHCP payload.
fn build_eth_ipv4_udp_dhcp(
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    ip_src: [u8; 4],
    ip_dst: [u8; 4],
    udp_src: u16,
    udp_dst: u16,
    dhcp_payload: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, eth_dst, eth_src, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 17, ip_src, ip_dst);
    let udp_start = push_udp(&mut pkt, udp_src, udp_dst);
    pkt.extend_from_slice(dhcp_payload);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ip_start);
    pkt
}

#[test]
fn integration_ethernet_ipv4_udp_dhcp_discover() {
    let reg = DissectorRegistry::default();

    let mut opts = Vec::new();
    opts.extend_from_slice(&dhcp_option(53, &[1])); // DHCP Discover
    opts.extend_from_slice(&dhcp_option(50, &[192, 168, 1, 100])); // Requested IP
    opts.push(255); // End

    let dhcp_msg = build_dhcp_message(1, 0xDEADBEEF, MAC_DHCP_CLIENT, [0; 4], &opts);
    let data = build_eth_ipv4_udp_dhcp(
        [0xff; 6],
        MAC_DHCP_CLIENT,
        [0, 0, 0, 0],
        [255, 255, 255, 255],
        68,
        67,
        &dhcp_msg,
    );

    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "DHCP");

    let dhcp = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(dhcp, "op").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(dhcp, "xid").unwrap().value,
        FieldValue::U32(0xDEADBEEF)
    );
    assert_eq!(
        buf.field_by_name(dhcp, "dhcp_message_type").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(dhcp, "requested_ip").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 100])
    );
}

#[test]
fn integration_ethernet_ipv4_udp_dhcp_offer() {
    let reg = DissectorRegistry::default();

    let mut opts = Vec::new();
    opts.extend_from_slice(&dhcp_option(53, &[2])); // DHCP Offer
    opts.extend_from_slice(&dhcp_option(54, &[192, 168, 1, 1])); // Server ID
    opts.extend_from_slice(&dhcp_option(51, &86400u32.to_be_bytes())); // Lease time
    opts.extend_from_slice(&dhcp_option(1, &[255, 255, 255, 0])); // Subnet mask
    opts.extend_from_slice(&dhcp_option(3, &[192, 168, 1, 1])); // Router
    opts.extend_from_slice(&dhcp_option(6, &[8, 8, 8, 8])); // DNS
    opts.push(255);

    let dhcp_msg = build_dhcp_message(2, 0xCAFEBABE, MAC_DHCP_CLIENT, [192, 168, 1, 100], &opts);
    let data = build_eth_ipv4_udp_dhcp(
        MAC_DHCP_CLIENT,
        MAC_SRC,
        [192, 168, 1, 1],
        [192, 168, 1, 100],
        67,
        68,
        &dhcp_msg,
    );

    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[3].name, "DHCP");

    let dhcp = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(dhcp, "op").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(dhcp, "yiaddr").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 100])
    );
    assert_eq!(
        buf.field_by_name(dhcp, "dhcp_message_type").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(dhcp, "server_identifier").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 1])
    );
    assert_eq!(
        buf.field_by_name(dhcp, "lease_time").unwrap().value,
        FieldValue::U32(86400)
    );
    assert_eq!(
        buf.field_by_name(dhcp, "subnet_mask").unwrap().value,
        FieldValue::Ipv4Addr([255, 255, 255, 0])
    );
    // Router and DNS are now Array values
    let FieldValue::Array(ref routers_range) = buf.field_by_name(dhcp, "router").unwrap().value
    else {
        panic!("expected Array")
    };
    let routers = buf.nested_fields(routers_range);
    assert_eq!(routers.len(), 1);
    assert_eq!(routers[0].value, FieldValue::Ipv4Addr([192, 168, 1, 1]));
    let FieldValue::Array(ref dns_range) = buf.field_by_name(dhcp, "dns_server").unwrap().value
    else {
        panic!("expected Array")
    };
    let dns = buf.nested_fields(dns_range);
    assert_eq!(dns.len(), 1);
    assert_eq!(dns[0].value, FieldValue::Ipv4Addr([8, 8, 8, 8]));
}

#[test]
fn integration_ethernet_ipv4_udp_dhcp_ack() {
    let reg = DissectorRegistry::default();

    let mut opts = Vec::new();
    opts.extend_from_slice(&dhcp_option(53, &[5])); // DHCP ACK
    opts.push(255);

    let dhcp_msg = build_dhcp_message(2, 0x11223344, MAC_DHCP_CLIENT, [10, 0, 0, 50], &opts);
    let data = build_eth_ipv4_udp_dhcp(
        MAC_DHCP_CLIENT,
        MAC_SRC,
        [10, 0, 0, 1],
        [10, 0, 0, 50],
        67,
        68,
        &dhcp_msg,
    );

    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[3].name, "DHCP");
    assert_eq!(
        buf.field_by_name(&buf.layers()[3], "dhcp_message_type")
            .unwrap()
            .value,
        FieldValue::U8(5)
    );
}

// ---------------------------------------------------------------------------
// DHCPv6
// ---------------------------------------------------------------------------

/// Build a DHCPv6 option: option-code (2) + option-len (2) + data.
fn dhcpv6_option(code: u16, data: &[u8]) -> Vec<u8> {
    let mut opt = Vec::new();
    opt.extend_from_slice(&code.to_be_bytes());
    opt.extend_from_slice(&(data.len() as u16).to_be_bytes());
    opt.extend_from_slice(data);
    opt
}

/// Build a DHCPv6 client/server message.
fn build_dhcpv6_message(msg_type: u8, txid: u32, options: &[u8]) -> Vec<u8> {
    let mut msg = vec![
        msg_type,
        ((txid >> 16) & 0xFF) as u8,
        ((txid >> 8) & 0xFF) as u8,
        (txid & 0xFF) as u8,
    ];
    msg.extend_from_slice(options);
    msg
}

/// Build Ethernet → IPv6 → UDP frame carrying a DHCPv6 payload.
fn build_eth_ipv6_udp_dhcpv6(udp_src: u16, udp_dst: u16, dhcpv6_payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    let ip_start = push_ipv6(&mut pkt, 17, IPV6_SRC, IPV6_DST);
    let udp_start = push_udp(&mut pkt, udp_src, udp_dst);
    pkt.extend_from_slice(dhcpv6_payload);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv6_payload_length(&mut pkt, ip_start);
    pkt
}

#[test]
fn integration_ethernet_ipv6_udp_dhcpv6_solicit() {
    let reg = DissectorRegistry::default();

    let mut opts = Vec::new();
    // Client ID (option 1)
    let duid = [
        0x00, 0x01, 0x00, 0x01, 0x1c, 0x39, 0xcf, 0x88, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    ];
    opts.extend_from_slice(&dhcpv6_option(1, &duid));
    // Elapsed Time (option 8)
    opts.extend_from_slice(&dhcpv6_option(8, &0u16.to_be_bytes()));
    // Option Request (option 6): DNS (23)
    opts.extend_from_slice(&dhcpv6_option(6, &23u16.to_be_bytes()));

    let dhcpv6_msg = build_dhcpv6_message(1, 0xABCDEF, &opts); // Solicit
    let data = build_eth_ipv6_udp_dhcpv6(546, 547, &dhcpv6_msg);

    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv6");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "DHCPv6");

    let dhcpv6 = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(dhcpv6, "msg_type").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(dhcpv6, "transaction_id").unwrap().value,
        FieldValue::U32(0xABCDEF)
    );
    let FieldValue::Array(ref options_range) = buf.field_by_name(dhcpv6, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = direct_children(&buf, options_range);
    assert_eq!(options.len(), 3);
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _or) = options[0].value else {
                    panic!("expected Object")
                };
                let _fs = buf.nested_fields(_or);
                _fs.iter()
                    .find(|f| f.name() == "client_id")
                    .unwrap()
                    .value
                    .clone()
            }
        },
        FieldValue::Bytes(&duid)
    );
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _or) = options[1].value else {
                    panic!("expected Object")
                };
                let _fs = buf.nested_fields(_or);
                _fs.iter()
                    .find(|f| f.name() == "elapsed_time")
                    .unwrap()
                    .value
                    .clone()
            }
        },
        FieldValue::U16(0)
    );
}

#[test]
fn integration_ethernet_ipv6_udp_dhcpv6_advertise() {
    let reg = DissectorRegistry::default();

    let mut opts = Vec::new();
    // Server ID (option 2)
    let server_duid = [
        0x00, 0x01, 0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];
    opts.extend_from_slice(&dhcpv6_option(2, &server_duid));

    // IA_NA (option 3) with IA Address sub-option
    let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let ia_addr_opt = dhcpv6_option(5, &{
        let mut ia = Vec::new();
        ia.extend_from_slice(&addr);
        ia.extend_from_slice(&3600u32.to_be_bytes()); // preferred
        ia.extend_from_slice(&7200u32.to_be_bytes()); // valid
        ia
    });
    let mut ia_na = Vec::new();
    ia_na.extend_from_slice(&1u32.to_be_bytes()); // IAID
    ia_na.extend_from_slice(&3600u32.to_be_bytes()); // T1
    ia_na.extend_from_slice(&5400u32.to_be_bytes()); // T2
    ia_na.extend_from_slice(&ia_addr_opt);
    opts.extend_from_slice(&dhcpv6_option(3, &ia_na));

    // DNS Server (option 23)
    let dns_addr = [
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
    ];
    opts.extend_from_slice(&dhcpv6_option(23, &dns_addr));

    let dhcpv6_msg = build_dhcpv6_message(2, 0xABCDEF, &opts); // Advertise
    let data = build_eth_ipv6_udp_dhcpv6(547, 546, &dhcpv6_msg);

    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[3].name, "DHCPv6");

    let dhcpv6 = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(dhcpv6, "msg_type").unwrap().value,
        FieldValue::U8(2)
    );
    let FieldValue::Array(ref options_range) = buf.field_by_name(dhcpv6, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = direct_children(&buf, options_range);
    assert_eq!(options.len(), 3); // Server ID, IA_NA, DNS
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _or) = options[0].value else {
                    panic!("expected Object")
                };
                let _fs = buf.nested_fields(_or);
                _fs.iter()
                    .find(|f| f.name() == "server_id")
                    .unwrap()
                    .value
                    .clone()
            }
        },
        FieldValue::Bytes(&server_duid)
    );
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _or) = options[1].value else {
                    panic!("expected Object")
                };
                let _fs = buf.nested_fields(_or);
                _fs.iter()
                    .find(|f| f.name() == "iaid")
                    .unwrap()
                    .value
                    .clone()
            }
        },
        FieldValue::U32(1)
    );
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _or) = options[1].value else {
                    panic!("expected Object")
                };
                let _fs = buf.nested_fields(_or);
                _fs.iter().find(|f| f.name() == "t1").unwrap().value.clone()
            }
        },
        FieldValue::U32(3600)
    );
    let FieldValue::Object(ref dns_opt_range) = options[2].value else {
        panic!("expected Object")
    };
    let dns_opt_fields = buf.nested_fields(dns_opt_range);
    let dns_servers_field = dns_opt_fields
        .iter()
        .find(|f| f.name() == "dns_servers")
        .unwrap();
    let FieldValue::Array(ref dns_servers_range) = dns_servers_field.value else {
        panic!("expected Array")
    };
    let dns_servers = buf.nested_fields(dns_servers_range);
    assert_eq!(dns_servers[0].value, FieldValue::Ipv6Addr(dns_addr));
}

#[test]
fn integration_ethernet_ipv6_udp_dhcpv6_reply_pd() {
    let reg = DissectorRegistry::default();

    let mut opts = Vec::new();

    // Server ID (option 2)
    let server_duid = [
        0x00, 0x01, 0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];
    opts.extend_from_slice(&dhcpv6_option(2, &server_duid));

    // IA_PD (option 25) with IA Prefix sub-option (option 26)
    let prefix = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut ia_prefix_data = Vec::new();
    ia_prefix_data.extend_from_slice(&3600u32.to_be_bytes()); // preferred
    ia_prefix_data.extend_from_slice(&7200u32.to_be_bytes()); // valid
    ia_prefix_data.push(48); // prefix-length
    ia_prefix_data.extend_from_slice(&prefix);
    let ia_prefix_opt = dhcpv6_option(26, &ia_prefix_data);

    let mut ia_pd = Vec::new();
    ia_pd.extend_from_slice(&1u32.to_be_bytes()); // IAID
    ia_pd.extend_from_slice(&1800u32.to_be_bytes()); // T1
    ia_pd.extend_from_slice(&2700u32.to_be_bytes()); // T2
    ia_pd.extend_from_slice(&ia_prefix_opt);
    opts.extend_from_slice(&dhcpv6_option(25, &ia_pd));

    let dhcpv6_msg = build_dhcpv6_message(7, 0xABCDEF, &opts); // Reply
    let data = build_eth_ipv6_udp_dhcpv6(547, 546, &dhcpv6_msg);

    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[3].name, "DHCPv6");

    let dhcpv6 = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(dhcpv6, "msg_type").unwrap().value,
        FieldValue::U8(7)
    );
    let FieldValue::Array(ref options_range) = buf.field_by_name(dhcpv6, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = direct_children(&buf, options_range);
    assert_eq!(options.len(), 2); // Server ID, IA_PD
    // IA_PD
    let ia_pd = options[1];
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _r) = ia_pd.value else {
                    panic!("expected Object")
                };
                buf.nested_fields(_r).iter().find(|f| f.name() == "iaid")
            }
        }
        .unwrap()
        .value,
        FieldValue::U32(1)
    );
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _r) = ia_pd.value else {
                    panic!("expected Object")
                };
                buf.nested_fields(_r).iter().find(|f| f.name() == "t1")
            }
        }
        .unwrap()
        .value,
        FieldValue::U32(1800)
    );
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _r) = ia_pd.value else {
                    panic!("expected Object")
                };
                buf.nested_fields(_r).iter().find(|f| f.name() == "t2")
            }
        }
        .unwrap()
        .value,
        FieldValue::U32(2700)
    );
    // IA Prefix sub-option
    let FieldValue::Object(ref ia_pd_obj_range) = ia_pd.value else {
        panic!("expected Object")
    };
    let ia_pd_direct = direct_children(&buf, ia_pd_obj_range);
    let ia_pd_opts_field = ia_pd_direct.iter().find(|f| f.name() == "options").unwrap();
    let FieldValue::Array(ref ia_pd_opts_range) = ia_pd_opts_field.value else {
        panic!("expected Array")
    };
    // Navigate through the nested Array structure: options -> inner array -> Object
    let ia_pd_opts_inner = direct_children(&buf, ia_pd_opts_range);
    assert_eq!(ia_pd_opts_inner.len(), 1);
    let FieldValue::Array(ref inner_range) = ia_pd_opts_inner[0].value else {
        panic!("expected inner Array, got {:?}", ia_pd_opts_inner[0].value)
    };
    let ia_pd_opts = direct_children(&buf, inner_range);
    assert_eq!(ia_pd_opts.len(), 1);
    let FieldValue::Object(ref ia_prefix_range) = ia_pd_opts[0].value else {
        panic!("expected Object, got {:?}", ia_pd_opts[0].value)
    };
    let ia_prefix_fields = buf.nested_fields(ia_prefix_range);
    assert_eq!(
        ia_prefix_fields
            .iter()
            .find(|f| f.name() == "prefix_length")
            .unwrap()
            .value,
        FieldValue::U8(48)
    );
    assert_eq!(
        ia_prefix_fields
            .iter()
            .find(|f| f.name() == "prefix")
            .unwrap()
            .value,
        FieldValue::Ipv6Addr(prefix)
    );
}

// ---------------------------------------------------------------------------
// SRv6
// ---------------------------------------------------------------------------

const SRV6_SID_A: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const SRV6_SID_B: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];
const SRV6_SID_C: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
];

/// Build an SRH: fixed 8 bytes + segment list.
fn push_srv6(pkt: &mut Vec<u8>, next_header: u8, segments_left: u8, segments: &[[u8; 16]]) {
    let num_segments = segments.len();
    let total_len = 8 + num_segments * 16;
    let hdr_ext_len = (total_len / 8) - 1;
    let last_entry = if num_segments == 0 {
        0
    } else {
        (num_segments - 1) as u8
    };
    pkt.push(next_header);
    pkt.push(hdr_ext_len as u8);
    pkt.push(4); // Routing Type = 4
    pkt.push(segments_left);
    pkt.push(last_entry);
    pkt.push(0); // Flags
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Tag
    for seg in segments {
        pkt.extend_from_slice(seg);
    }
}

#[test]
fn integration_ethernet_ipv6_srv6_tcp() {
    let reg = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    // IPv6 NH=43 (Routing Header)
    let ip_start = push_ipv6(&mut pkt, 43, IPV6_SRC, IPV6_DST);
    // SRv6 with 1 segment, NH=6 (TCP)
    push_srv6(&mut pkt, 6, 1, &[SRV6_SID_A]);
    push_tcp(&mut pkt, 54321, 80, 0x02); // SYN
    fixup_ipv6_payload_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Ethernet → IPv6 → (RoutingDissector: 0 bytes) → SRv6 → TCP
    // RoutingDissector consumes 0 bytes and dispatches by routing type,
    // so it doesn't add a layer.
    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv6");
    assert_eq!(buf.layers()[2].name, "SRv6");
    assert_eq!(buf.layers()[3].name, "TCP");

    let srv6 = &buf.layers()[2];
    assert_eq!(
        buf.field_by_name(srv6, "routing_type").unwrap().value,
        FieldValue::U8(4)
    );
    assert_eq!(
        buf.field_by_name(srv6, "segments_left").unwrap().value,
        FieldValue::U8(1)
    );
    let segments = {
        let f = buf.field_by_name(srv6, "segments").unwrap();
        let FieldValue::Array(ref r) = f.value else {
            panic!("expected Array")
        };
        buf.nested_fields(r)
    };
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].value, FieldValue::Ipv6Addr(SRV6_SID_A));

    let tcp = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(tcp, "src_port").unwrap().value,
        FieldValue::U16(54321)
    );
    assert_eq!(
        buf.field_by_name(tcp, "dst_port").unwrap().value,
        FieldValue::U16(80)
    );
}

#[test]
fn integration_ethernet_ipv6_srv6_multi_seg_udp() {
    let reg = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    let ip_start = push_ipv6(&mut pkt, 43, IPV6_SRC, IPV6_DST);
    // SRv6 with 3 segments, NH=17 (UDP)
    push_srv6(&mut pkt, 17, 2, &[SRV6_SID_A, SRV6_SID_B, SRV6_SID_C]);
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv6_payload_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv6");
    assert_eq!(buf.layers()[2].name, "SRv6");
    assert_eq!(buf.layers()[3].name, "UDP");

    let srv6 = &buf.layers()[2];
    assert_eq!(
        buf.field_by_name(srv6, "last_entry").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(srv6, "segments_left").unwrap().value,
        FieldValue::U8(2)
    );
    let segments = {
        let f = buf.field_by_name(srv6, "segments").unwrap();
        let FieldValue::Array(ref r) = f.value else {
            panic!("expected Array")
        };
        buf.nested_fields(r)
    };
    assert_eq!(segments.len(), 3);
    assert_eq!(segments[0].value, FieldValue::Ipv6Addr(SRV6_SID_A));
    assert_eq!(segments[1].value, FieldValue::Ipv6Addr(SRV6_SID_B));
    assert_eq!(segments[2].value, FieldValue::Ipv6Addr(SRV6_SID_C));
}

// ---------------------------------------------------------------------------
// Ethernet → IPv4 → TCP → DNS (over TCP)
// ---------------------------------------------------------------------------

fn build_eth_ipv4_tcp_dns() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 6, IPV4_SRC, IPV4_DST); // protocol=6 (TCP)
    push_tcp(&mut pkt, 54321, 53, 0x18); // ACK+PSH (data)

    // DNS over TCP: 2-byte length prefix + DNS query
    let dns_start = pkt.len();
    pkt.extend_from_slice(&0u16.to_be_bytes()); // placeholder for length
    push_dns_query(&mut pkt, 0xFACE);
    let dns_msg_len = (pkt.len() - dns_start - 2) as u16;
    pkt[dns_start..dns_start + 2].copy_from_slice(&dns_msg_len.to_be_bytes());

    fixup_ipv4_length(&mut pkt, ip_start);
    pkt
}

#[test]
fn integration_ethernet_ipv4_tcp_dns() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv4_tcp_dns();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);

    // Layer 0: Ethernet
    assert_eq!(buf.layers()[0].name, "Ethernet");

    // Layer 1: IPv4
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(
        buf.field_by_name(&buf.layers()[1], "protocol")
            .unwrap()
            .value,
        FieldValue::U8(6) // TCP
    );

    // Layer 2: TCP
    assert_eq!(buf.layers()[2].name, "TCP");
    assert_eq!(
        buf.field_by_name(&buf.layers()[2], "dst_port")
            .unwrap()
            .value,
        FieldValue::U16(53)
    );

    // Layer 3: DNS (parsed via DnsTcpDissector)
    assert_eq!(buf.layers()[3].name, "DNS");
    assert_eq!(
        buf.field_by_name(&buf.layers()[3], "id").unwrap().value,
        FieldValue::U16(0xFACE)
    );
    assert_eq!(
        buf.field_by_name(&buf.layers()[3], "qr").unwrap().value,
        FieldValue::U8(0)
    );
}

// ---------------------------------------------------------------------------
// ICMPv6 Neighbor Discovery
// ---------------------------------------------------------------------------

/// ICMPv6 Neighbor Solicitation (24 bytes).
fn push_icmpv6_neighbor_solicitation(pkt: &mut Vec<u8>, target: [u8; 16]) {
    pkt.push(135); // Type
    pkt.push(0); // Code
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved
    pkt.extend_from_slice(&target);
}

/// NDP option with 8-byte alignment.
fn push_ndp_option(pkt: &mut Vec<u8>, opt_type: u8, data: &[u8]) {
    let total = 2 + data.len();
    let padded = total.div_ceil(8) * 8;
    let length_units = (padded / 8) as u8;
    pkt.push(opt_type);
    pkt.push(length_units);
    pkt.extend_from_slice(data);
    pkt.resize(pkt.len() + padded - total, 0);
}

#[test]
fn integration_ethernet_ipv6_icmpv6_neighbor_solicitation() {
    let reg = DissectorRegistry::default();

    let target = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    let ip_start = push_ipv6(&mut pkt, 58, IPV6_SRC, IPV6_DST);
    push_icmpv6_neighbor_solicitation(&mut pkt, target);
    // Add Source Link-Layer Address option
    push_ndp_option(&mut pkt, 1, &MAC_SRC);
    fixup_ipv6_payload_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 3);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv6");
    assert_eq!(buf.layers()[2].name, "ICMPv6");

    let icmpv6 = &buf.layers()[2];
    assert_eq!(
        buf.field_by_name(icmpv6, "type").unwrap().value,
        FieldValue::U8(135)
    );
    assert_eq!(
        buf.field_by_name(icmpv6, "target_address").unwrap().value,
        FieldValue::Ipv6Addr(target)
    );

    // Verify NDP options were parsed
    let FieldValue::Array(ref options_range) = buf.field_by_name(icmpv6, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = direct_children(&buf, options_range);
    assert_eq!(options.len(), 1);
    let FieldValue::Object(ref opt_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt = buf.nested_fields(opt_range);
    assert_eq!(
        opt.iter().find(|f| f.name() == "type").unwrap().value,
        FieldValue::U8(1)
    );
}

// ---------------------------------------------------------------------------
// SRv6 inner packet encapsulation
// ---------------------------------------------------------------------------

const INNER_IPV4_SRC: [u8; 4] = [10, 0, 0, 1];
const INNER_IPV4_DST: [u8; 4] = [10, 0, 0, 2];
const INNER_IPV6_SRC: [u8; 16] = [
    0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const INNER_IPV6_DST: [u8; 16] = [
    0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];

#[test]
fn integration_ethernet_ipv6_srv6_inner_ipv4_tcp() {
    let reg = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    // Outer IPv6, NH=43 (Routing Header)
    let outer_ip_start = push_ipv6(&mut pkt, 43, IPV6_SRC, IPV6_DST);
    // SRv6 with 1 segment, NH=4 (IPv4-in-IPv6)
    push_srv6(&mut pkt, 4, 1, &[SRV6_SID_A]);
    // Inner IPv4 → TCP
    let inner_ip_start = push_ipv4(&mut pkt, 6, INNER_IPV4_SRC, INNER_IPV4_DST);
    push_tcp(&mut pkt, 54321, 80, 0x02);
    fixup_ipv4_length(&mut pkt, inner_ip_start);
    fixup_ipv6_payload_length(&mut pkt, outer_ip_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Ethernet → IPv6 → SRv6 → IPv4 → TCP
    assert_eq!(buf.layers().len(), 5);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv6");
    assert_eq!(buf.layers()[2].name, "SRv6");
    assert_eq!(buf.layers()[3].name, "IPv4");
    assert_eq!(buf.layers()[4].name, "TCP");
    assert_layers_contiguous(&buf);

    let ipv4 = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(ipv4, "src").unwrap().value,
        FieldValue::Ipv4Addr(INNER_IPV4_SRC)
    );
    assert_eq!(
        buf.field_by_name(ipv4, "dst").unwrap().value,
        FieldValue::Ipv4Addr(INNER_IPV4_DST)
    );
}

#[test]
fn integration_ethernet_ipv6_icmpv6_router_advertisement() {
    let reg = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    let ip_start = push_ipv6(&mut pkt, 58, IPV6_SRC, IPV6_DST);

    // RA header (16 bytes)
    pkt.push(134); // Type
    pkt.push(0); // Code
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
    pkt.push(64); // Cur Hop Limit
    pkt.push(0xC0); // M + O flags
    pkt.extend_from_slice(&1800u16.to_be_bytes()); // Router Lifetime
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Reachable Time
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Retrans Timer

    // Prefix Information option (32 bytes): type=3, length=4
    let mut prefix_opt = vec![0u8; 32];
    prefix_opt[0] = 3;
    prefix_opt[1] = 4;
    prefix_opt[2] = 64; // prefix_length
    prefix_opt[3] = 0xC0; // L + A flags
    prefix_opt[4..8].copy_from_slice(&2592000u32.to_be_bytes());
    prefix_opt[8..12].copy_from_slice(&604800u32.to_be_bytes());
    prefix_opt[16] = 0x20;
    prefix_opt[17] = 0x01;
    prefix_opt[18] = 0x0d;
    prefix_opt[19] = 0xb8;
    pkt.extend_from_slice(&prefix_opt);

    fixup_ipv6_payload_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 3);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[2].name, "ICMPv6");

    let icmpv6 = &buf.layers()[2];
    assert_eq!(
        buf.field_by_name(icmpv6, "type").unwrap().value,
        FieldValue::U8(134)
    );
    assert_eq!(
        buf.field_by_name(icmpv6, "cur_hop_limit").unwrap().value,
        FieldValue::U8(64)
    );
    assert_eq!(
        buf.field_by_name(icmpv6, "flags").unwrap().value,
        FieldValue::U8(0xC0)
    );
    assert_eq!(
        buf.field_by_name(icmpv6, "router_lifetime").unwrap().value,
        FieldValue::U16(1800)
    );

    // Verify Prefix Information option
    let FieldValue::Array(ref options_range) = buf.field_by_name(icmpv6, "options").unwrap().value
    else {
        panic!("expected Array")
    };
    let options = direct_children(&buf, options_range);
    assert_eq!(options.len(), 1);
    let FieldValue::Object(ref opt_range) = options[0].value else {
        panic!("expected Object")
    };
    let opt = buf.nested_fields(opt_range);
    assert_eq!(
        opt.iter()
            .find(|f| f.name() == "prefix_length")
            .unwrap()
            .value,
        FieldValue::U8(64)
    );
}

#[test]
fn integration_ethernet_ipv6_srv6_inner_ipv6_udp() {
    let reg = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    // Outer IPv6, NH=43 (Routing Header)
    let outer_ip_start = push_ipv6(&mut pkt, 43, IPV6_SRC, IPV6_DST);
    // SRv6 with 1 segment, NH=41 (IPv6-in-IPv6)
    push_srv6(&mut pkt, 41, 1, &[SRV6_SID_A]);
    // Inner IPv6 → UDP
    let inner_ip_start = push_ipv6(&mut pkt, 17, INNER_IPV6_SRC, INNER_IPV6_DST);
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv6_payload_length(&mut pkt, inner_ip_start);
    fixup_ipv6_payload_length(&mut pkt, outer_ip_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Ethernet → IPv6(outer) → SRv6 → IPv6(inner) → UDP
    assert_eq!(buf.layers().len(), 5);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv6");
    assert_eq!(buf.layers()[2].name, "SRv6");
    assert_eq!(buf.layers()[3].name, "IPv6");
    assert_eq!(buf.layers()[4].name, "UDP");
    assert_layers_contiguous(&buf);

    let inner_ipv6 = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(inner_ipv6, "src").unwrap().value,
        FieldValue::Ipv6Addr(INNER_IPV6_SRC)
    );
    assert_eq!(
        buf.field_by_name(inner_ipv6, "dst").unwrap().value,
        FieldValue::Ipv6Addr(INNER_IPV6_DST)
    );
}

#[test]
fn integration_ethernet_ipv6_srv6_mobile_gtp6_e() {
    // SRv6 with mobile encoding (End.M.GTP6.E): Args.Mob.Session in argument.
    // Build a custom registry with SID structure configuration.
    let mut reg = DissectorRegistry::default();
    let ss = packet_dissector::dissectors::srv6::SidStructure {
        locator_block_bits: 48,
        locator_node_bits: 16,
        function_bits: 16,
        argument_bits: 48,
        csid_flavor: packet_dissector::dissectors::srv6::CsidFlavor::Classic,
        mobile_encoding: Some(packet_dissector::dissectors::srv6::MobileSidEncoding::EndMGtp6E),
    };
    reg.register_by_ipv6_routing_type_or_replace(
        4,
        Box::new(packet_dissector::dissectors::srv6::Srv6Dissector::with_sid_structure(ss)),
    );

    // SID: LOC(48) + Node(16) + Func(16) + AMS(40) + pad(8)
    // AMS: QFI=9, R=0, U=0, PDU Session ID=0x12345678
    let mobile_sid: [u8; 16] = [
        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, // LOC
        0x00, 0x02, // Node
        0x00, 0x47, // Func
        0x24, 0x12, 0x34, 0x56, 0x78, // AMS
        0x00, // pad
    ];

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    let ip_start = push_ipv6(&mut pkt, 43, IPV6_SRC, IPV6_DST);
    push_srv6(&mut pkt, 6, 1, &[mobile_sid]);
    push_tcp(&mut pkt, 54321, 80, 0x02);
    fixup_ipv6_payload_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[2].name, "SRv6");

    let srv6 = &buf.layers()[2];
    // Verify segments_structure includes mobile fields
    let structure = {
        let f = buf.field_by_name(srv6, "segments_structure").unwrap();
        let FieldValue::Array(ref r) = f.value else {
            panic!("expected Array")
        };
        direct_children(&buf, r)
    };
    assert_eq!(structure.len(), 1);

    let seg0 = structure[0];
    // Standard fields
    assert!(
        {
            {
                let FieldValue::Object(ref _r) = seg0.value else {
                    panic!("expected Object")
                };
                buf.nested_fields(_r)
                    .iter()
                    .find(|f| f.name() == "locator_block")
            }
        }
        .is_some()
    );
    assert!(
        {
            {
                let FieldValue::Object(ref _r) = seg0.value else {
                    panic!("expected Object")
                };
                buf.nested_fields(_r)
                    .iter()
                    .find(|f| f.name() == "function")
            }
        }
        .is_some()
    );

    // Mobile field: Args.Mob.Session
    let ams = {
        {
            let FieldValue::Object(ref _r) = seg0.value else {
                panic!("expected Object")
            };
            buf.nested_fields(_r)
                .iter()
                .find(|f| f.name() == "args_mob_session")
        }
    }
    .unwrap();
    let FieldValue::Object(ref ams_obj_range) = ams.value else {
        panic!("expected Object")
    };
    let ams_obj = buf.nested_fields(ams_obj_range);
    let qfi = ams_obj.iter().find(|f| f.name() == "qfi").unwrap();
    assert_eq!(qfi.value, FieldValue::U8(9));
    let pdu_id = ams_obj
        .iter()
        .find(|f| f.name() == "pdu_session_id")
        .unwrap();
    assert_eq!(pdu_id.value, FieldValue::U32(0x12345678));

    assert_layers_contiguous(&buf);
}

// ---------------------------------------------------------------------------
// GTPv1-U helpers
// ---------------------------------------------------------------------------

/// GTPv1-U header (8 bytes, no optional fields). Returns start index for length fixup.
fn push_gtpv1u(pkt: &mut Vec<u8>, teid: u32) -> usize {
    let start = pkt.len();
    // Octet 1: Version=1, PT=1, Spare=0, E=0, S=0, PN=0 → 0x30
    pkt.push(0x30);
    // Octet 2: Message Type = 255 (G-PDU)
    pkt.push(0xFF);
    // Octets 3-4: Length (placeholder)
    pkt.extend_from_slice(&0u16.to_be_bytes());
    // Octets 5-8: TEID
    pkt.extend_from_slice(&teid.to_be_bytes());
    start
}

/// GTPv1-U header with E flag set and a PDU Session Container extension header.
/// Returns start index for length fixup.
fn push_gtpv1u_with_ext(pkt: &mut Vec<u8>, teid: u32) -> usize {
    let start = pkt.len();
    // Octet 1: Version=1, PT=1, Spare=0, E=1, S=0, PN=0 → 0x34
    pkt.push(0x34);
    // Octet 2: Message Type = 255 (G-PDU)
    pkt.push(0xFF);
    // Octets 3-4: Length (placeholder)
    pkt.extend_from_slice(&0u16.to_be_bytes());
    // Octets 5-8: TEID
    pkt.extend_from_slice(&teid.to_be_bytes());
    // Octets 9-10: Sequence Number (not meaningful)
    pkt.extend_from_slice(&0u16.to_be_bytes());
    // Octet 11: N-PDU Number (not meaningful)
    pkt.push(0x00);
    // Octet 12: Next Extension Header Type = 0x85 (PDU Session Container)
    pkt.push(0x85);
    // Extension header: PDU Session Container (4 bytes)
    pkt.push(0x01); // Length = 1 (4 bytes)
    pkt.extend_from_slice(&[0x09, 0x00]); // Content
    pkt.push(0x00); // Next Extension Header Type = 0 (no more)
    start
}

/// Fix GTPv1-U Length field after payload has been appended.
fn fixup_gtpv1u_length(pkt: &mut [u8], gtpv1u_start: usize) {
    let length = (pkt.len() - gtpv1u_start - 8) as u16;
    pkt[gtpv1u_start + 2..gtpv1u_start + 4].copy_from_slice(&length.to_be_bytes());
}

// ---------------------------------------------------------------------------
// GTPv1-U integration tests
// ---------------------------------------------------------------------------

/// Ethernet → IPv4 → UDP → GTPv1-U → IPv4 (inner)
#[test]
fn integration_ethernet_ipv4_udp_gtpv1u_ipv4() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // Outer: Ethernet → IPv4 → UDP (port 2152)
    push_ethernet(&mut pkt, [0xAA; 6], [0xBB; 6], 0x0800);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 2152, 2152);

    // GTPv1-U header
    let gtp_start = push_gtpv1u(&mut pkt, 0x12345678);

    // Inner: IPv4 header (20 bytes, protocol=TCP)
    let inner_ipv4_start = push_ipv4(&mut pkt, 6, [192, 168, 1, 1], [192, 168, 1, 2]);
    // Inner: TCP header
    push_tcp(&mut pkt, 12345, 80, 0x02); // SYN

    // Fix lengths
    fixup_ipv4_length(&mut pkt, inner_ipv4_start);
    fixup_gtpv1u_length(&mut pkt, gtp_start);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Ethernet → IPv4 → UDP → GTPv1-U → IPv4 → TCP
    assert_eq!(buf.layers().len(), 6);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "GTPv1-U");
    assert_eq!(buf.layers()[4].name, "IPv4");
    assert_eq!(buf.layers()[5].name, "TCP");
    assert_layers_contiguous(&buf);

    // Verify GTPv1-U fields
    let gtp = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(gtp, "version").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(gtp, "teid").unwrap().value,
        FieldValue::U32(0x12345678)
    );
    assert_eq!(
        buf.field_by_name(gtp, "message_type").unwrap().value,
        FieldValue::U8(255)
    );

    // Verify inner IPv4
    let inner_ipv4 = &buf.layers()[4];
    assert_eq!(
        buf.field_by_name(inner_ipv4, "src").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 1])
    );
    assert_eq!(
        buf.field_by_name(inner_ipv4, "dst").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 2])
    );
}

/// Ethernet → IPv4 → UDP → GTPv1-U → IPv6 (inner)
#[test]
fn integration_ethernet_ipv4_udp_gtpv1u_ipv6() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    let inner_src: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let inner_dst: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    // Outer: Ethernet → IPv4 → UDP (port 2152)
    push_ethernet(&mut pkt, [0xAA; 6], [0xBB; 6], 0x0800);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 2152, 2152);

    // GTPv1-U header
    let gtp_start = push_gtpv1u(&mut pkt, 0xDEADBEEF);

    // Inner: IPv6 header (40 bytes, next_header=17 UDP)
    let inner_ipv6_start = push_ipv6(&mut pkt, 17, inner_src, inner_dst);
    // Inner: UDP header
    let inner_udp_start = push_udp(&mut pkt, 5000, 80);

    // Fix lengths
    fixup_udp_length(&mut pkt, inner_udp_start);
    fixup_ipv6_payload_length(&mut pkt, inner_ipv6_start);
    fixup_gtpv1u_length(&mut pkt, gtp_start);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Ethernet → IPv4 → UDP → GTPv1-U → IPv6 → UDP
    assert_eq!(buf.layers().len(), 6);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "GTPv1-U");
    assert_eq!(buf.layers()[4].name, "IPv6");
    assert_eq!(buf.layers()[5].name, "UDP");
    assert_layers_contiguous(&buf);

    // Verify inner IPv6
    let inner_ipv6 = &buf.layers()[4];
    assert_eq!(
        buf.field_by_name(inner_ipv6, "src").unwrap().value,
        FieldValue::Ipv6Addr(inner_src)
    );
}

/// Ethernet → IPv4 → UDP → GTPv1-U (with extension header) → IPv4 (inner)
#[test]
fn integration_ethernet_ipv4_udp_gtpv1u_ext_ipv4() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // Outer: Ethernet → IPv4 → UDP (port 2152)
    push_ethernet(&mut pkt, [0xAA; 6], [0xBB; 6], 0x0800);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 2152, 2152);

    // GTPv1-U header with extension
    let gtp_start = push_gtpv1u_with_ext(&mut pkt, 0xCAFEBABE);

    // Inner: IPv4 header (20 bytes, protocol=UDP)
    let inner_ipv4_start = push_ipv4(&mut pkt, 17, [172, 16, 0, 1], [172, 16, 0, 2]);
    let inner_udp_start = push_udp(&mut pkt, 3000, 4000);

    // Fix lengths
    fixup_udp_length(&mut pkt, inner_udp_start);
    fixup_ipv4_length(&mut pkt, inner_ipv4_start);
    fixup_gtpv1u_length(&mut pkt, gtp_start);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Ethernet → IPv4 → UDP → GTPv1-U → IPv4 → UDP
    assert_eq!(buf.layers().len(), 6);
    assert_eq!(buf.layers()[3].name, "GTPv1-U");
    assert_eq!(buf.layers()[4].name, "IPv4");
    assert_eq!(buf.layers()[5].name, "UDP");
    assert_layers_contiguous(&buf);

    // Verify GTPv1-U has extension headers
    let gtp = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(gtp, "e").unwrap().value,
        FieldValue::U8(1)
    );
    let ext = buf.field_by_name(gtp, "extension_headers").unwrap();
    assert_eq!(
        {
            {
                let FieldValue::Array(ref _ar) = ext.value else {
                    panic!("expected Array")
                };
                direct_children(&buf, _ar)
            }
        }
        .len(),
        1
    );
}

/// Verify that `DissectorRegistry` implements `Send`, allowing it to be moved
/// to another thread (e.g. one registry per capture file/thread).
/// `Sync` is intentionally absent: sharing a registry across threads via `Arc`
/// degrades throughput, so the type system prevents that pattern.
#[test]
fn registry_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<packet_dissector::registry::DissectorRegistry>();
}

// ---------------------------------------------------------------------------
// Plugin / DissectorTable tests
// ---------------------------------------------------------------------------

/// A minimal stub dissector for testing plugin registration.
struct StubDissector {
    short: &'static str,
}

impl Dissector for StubDissector {
    fn name(&self) -> &'static str {
        "Stub"
    }
    fn short_name(&self) -> &'static str {
        self.short
    }
    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }
    fn dissect(
        &self,
        _data: &[u8],
        _packet: &mut DissectBuffer<'_>,
        _offset: usize,
    ) -> Result<DissectResult, PacketError> {
        Ok(DissectResult::new(0, DispatchHint::End))
    }
}

#[test]
fn register_dissector_by_udp_port() {
    let mut reg = DissectorRegistry::new();
    reg.register_dissector(
        DissectorTable::UdpPort(9999),
        Box::new(StubDissector { short: "Stub" }),
    )
    .unwrap();
    assert!(reg.get_by_udp_port(9999).is_some());
    assert_eq!(reg.get_by_udp_port(9999).unwrap().short_name(), "Stub");
}

#[test]
fn register_dissector_by_tcp_port() {
    let mut reg = DissectorRegistry::new();
    reg.register_dissector(
        DissectorTable::TcpPort(8080),
        Box::new(StubDissector { short: "StubTCP" }),
    )
    .unwrap();
    assert_eq!(reg.get_by_tcp_port(8080).unwrap().short_name(), "StubTCP");
}

#[test]
fn register_dissector_by_ethertype() {
    let mut reg = DissectorRegistry::new();
    reg.register_dissector(
        DissectorTable::EtherType(0xBEEF),
        Box::new(StubDissector { short: "Beef" }),
    )
    .unwrap();
    assert_eq!(reg.get_by_ethertype(0xBEEF).unwrap().short_name(), "Beef");
}

#[test]
fn register_dissector_by_ip_protocol() {
    let mut reg = DissectorRegistry::new();
    reg.register_dissector(
        DissectorTable::IpProtocol(200),
        Box::new(StubDissector { short: "P200" }),
    )
    .unwrap();
    assert_eq!(reg.get_by_ip_protocol(200).unwrap().short_name(), "P200");
}

#[test]
fn register_dissector_by_sctp_port() {
    let mut reg = DissectorRegistry::new();
    reg.register_dissector(
        DissectorTable::SctpPort(3868),
        Box::new(StubDissector { short: "Dia" }),
    )
    .unwrap();
    assert_eq!(reg.get_by_sctp_port(3868).unwrap().short_name(), "Dia");
}

#[test]
fn register_dissector_by_ipv6_routing_type() {
    let mut reg = DissectorRegistry::new();
    reg.register_dissector(
        DissectorTable::Ipv6RoutingType(99),
        Box::new(StubDissector { short: "RT99" }),
    )
    .unwrap();
    assert_eq!(
        reg.get_by_ipv6_routing_type(99).unwrap().short_name(),
        "RT99"
    );
}

#[test]
fn register_dissector_entry() {
    let mut reg = DissectorRegistry::new();
    reg.register_dissector(
        DissectorTable::Entry,
        Box::new(StubDissector { short: "Entry" }),
    )
    .unwrap();
    // Entry dissector is used implicitly by dissect(); verify via dissect call
    let mut buf = DissectBuffer::new();
    let result = reg.dissect(&[], &mut buf);
    // StubDissector returns 0 bytes_consumed, so it should succeed on empty input
    assert!(result.is_ok());
}

#[test]
fn register_dissector_ipv6_routing_fallback() {
    let mut reg = DissectorRegistry::new();
    reg.register_dissector(
        DissectorTable::Ipv6RoutingFallback,
        Box::new(StubDissector { short: "FB" }),
    )
    .unwrap();
    // Fallback is returned when no specific routing type matches
    assert_eq!(
        reg.get_by_ipv6_routing_type(255).unwrap().short_name(),
        "FB"
    );
}

#[test]
fn register_dissector_duplicate_key_error() {
    let mut reg = DissectorRegistry::new();
    reg.register_dissector(
        DissectorTable::UdpPort(5000),
        Box::new(StubDissector { short: "A" }),
    )
    .unwrap();
    let err = reg
        .register_dissector(
            DissectorTable::UdpPort(5000),
            Box::new(StubDissector { short: "B" }),
        )
        .unwrap_err();
    assert!(err.to_string().contains("udp_port"));
}

#[test]
fn register_dissector_or_replace_returns_previous() {
    let mut reg = DissectorRegistry::new();
    reg.register_dissector(
        DissectorTable::UdpPort(6000),
        Box::new(StubDissector { short: "Old" }),
    )
    .unwrap();
    let prev = reg.register_dissector_or_replace(
        DissectorTable::UdpPort(6000),
        Box::new(StubDissector { short: "New" }),
    );
    assert_eq!(prev.unwrap().short_name(), "Old");
    assert_eq!(reg.get_by_udp_port(6000).unwrap().short_name(), "New");
}

#[test]
fn register_dissector_or_replace_none_when_empty() {
    let mut reg = DissectorRegistry::new();
    let prev = reg.register_dissector_or_replace(
        DissectorTable::TcpPort(7000),
        Box::new(StubDissector { short: "First" }),
    );
    assert!(prev.is_none());
}

struct TestPlugin;

impl DissectorPlugin for TestPlugin {
    fn dissectors(&self) -> Vec<(DissectorTable, Box<dyn Dissector>)> {
        vec![
            (
                DissectorTable::UdpPort(4789),
                Box::new(StubDissector { short: "VXLAN" }),
            ),
            (
                DissectorTable::UdpPort(6081),
                Box::new(StubDissector { short: "GUE" }),
            ),
        ]
    }
}

#[test]
fn register_plugin_adds_all_dissectors() {
    let mut reg = DissectorRegistry::new();
    reg.register_plugin(&TestPlugin).unwrap();
    assert_eq!(reg.get_by_udp_port(4789).unwrap().short_name(), "VXLAN");
    assert_eq!(reg.get_by_udp_port(6081).unwrap().short_name(), "GUE");
}

#[test]
fn register_plugin_stops_on_duplicate() {
    let mut reg = DissectorRegistry::new();
    reg.register_dissector(
        DissectorTable::UdpPort(4789),
        Box::new(StubDissector { short: "Existing" }),
    )
    .unwrap();
    let err = reg.register_plugin(&TestPlugin).unwrap_err();
    assert!(err.to_string().contains("udp_port"));
}

// ---------------------------------------------------------------------------
// HTTP integration tests
// ---------------------------------------------------------------------------

/// Ethernet → IPv4 → TCP → HTTP GET request
#[test]
fn integration_ethernet_ipv4_tcp_http_request() {
    let registry = DissectorRegistry::default();

    let http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]);
    push_tcp(&mut pkt, 12345, 80, 0x18); // PSH+ACK
    pkt.extend_from_slice(http_payload);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    // Should have 4 layers: Ethernet, IPv4, TCP, HTTP
    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "TCP");
    assert_eq!(buf.layers()[3].name, "HTTP");

    let http = buf.layer_by_name("HTTP").unwrap();
    assert_eq!(
        buf.field_by_name(http, "method").unwrap().value,
        FieldValue::Str("GET")
    );
    assert_eq!(
        buf.field_by_name(http, "uri").unwrap().value,
        FieldValue::Str("/index.html")
    );
    assert_eq!(
        buf.field_by_name(http, "version").unwrap().value,
        FieldValue::Str("HTTP/1.1")
    );
    assert_eq!(
        buf.field_by_name(http, "is_response").unwrap().value,
        FieldValue::U8(0)
    );

    let headers = {
        let f = buf.field_by_name(http, "headers").unwrap();
        let FieldValue::Array(ref r) = f.value else {
            panic!("expected Array")
        };
        direct_children(&buf, r)
    };
    assert_eq!(headers.len(), 1);
}

/// Ethernet → IPv4 → TCP → HTTP 200 OK response
#[test]
fn integration_ethernet_ipv4_tcp_http_response() {
    let registry = DissectorRegistry::default();

    let body = b"<html>OK</html>";
    let http_payload_str = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
    let mut http_payload = http_payload_str.into_bytes();
    http_payload.extend_from_slice(body);

    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 6, [10, 0, 0, 2], [10, 0, 0, 1]);
    push_tcp(&mut pkt, 80, 12345, 0x18); // PSH+ACK
    pkt.extend_from_slice(&http_payload);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[3].name, "HTTP");

    let http = buf.layer_by_name("HTTP").unwrap();
    assert_eq!(
        buf.field_by_name(http, "is_response").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(http, "status_code").unwrap().value,
        FieldValue::U16(200)
    );
    assert_eq!(
        buf.field_by_name(http, "reason_phrase").unwrap().value,
        FieldValue::Str("OK")
    );
    assert_eq!(
        buf.field_by_name(http, "content_length").unwrap().value,
        FieldValue::U32(body.len() as u32)
    );
}

/// Ethernet → IPv4 → TCP → HTTP 301 (with Content-Type: text/html).
///
/// Regression test: the TCP reassembly fast-path pipelining loop previously
/// re-called the HTTP dissector on the body bytes after the HTTP dissector
/// returned `ByContentType` dispatch, causing "invalid HTTP request line".
#[test]
fn integration_ethernet_ipv4_tcp_http_response_content_type() {
    let registry = DissectorRegistry::default();

    let body = b"<html><body>301 Moved</body></html>";
    let http_payload_str = format!(
        "HTTP/1.1 301 Moved Permanently\r\n\
         Content-Type: text/html; charset=UTF-8\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    );
    let mut http_payload = http_payload_str.into_bytes();
    http_payload.extend_from_slice(body);

    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 6, [10, 0, 0, 2], [10, 0, 0, 1]);
    push_tcp(&mut pkt, 80, 12345, 0x18); // PSH+ACK
    pkt.extend_from_slice(&http_payload);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    // Must have at least Ethernet + IPv4 + TCP + HTTP
    assert!(
        buf.layers().len() >= 4,
        "expected ≥4 layers, got {}",
        buf.layers().len()
    );
    let http = buf.layer_by_name("HTTP").unwrap();
    assert_eq!(
        buf.field_by_name(http, "is_response").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(http, "status_code").unwrap().value,
        FieldValue::U16(301)
    );
    assert_eq!(
        buf.field_by_name(http, "content_length").unwrap().value,
        FieldValue::U32(body.len() as u32)
    );
}
// ---------------------------------------------------------------------------

/// Ethernet → IPv4 → UDP → SIP INVITE request.
#[test]
fn integration_ethernet_ipv4_udp_sip_invite() {
    let registry = DissectorRegistry::default();

    let sip_payload = b"INVITE sip:bob@example.net SIP/2.0\r\n\
                        Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
                        To: Bob <sip:bob@example.net>\r\n\
                        From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                        Call-ID: a84b4c76e66710@pc33.example.com\r\n\
                        CSeq: 314159 INVITE\r\n\
                        Contact: <sip:alice@pc33.example.com>\r\n\
                        Content-Length: 0\r\n\r\n";

    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 5060, 5060);
    pkt.extend_from_slice(sip_payload);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "SIP");
    assert_layers_contiguous(&buf);

    let sip = buf.layer_by_name("SIP").unwrap();
    assert_eq!(
        buf.field_by_name(sip, "is_response").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(sip, "method").unwrap().value,
        FieldValue::Str("INVITE")
    );
    assert_eq!(
        buf.field_by_name(sip, "uri").unwrap().value,
        FieldValue::Str("sip:bob@example.net")
    );
    assert_eq!(
        buf.field_by_name(sip, "version").unwrap().value,
        FieldValue::Str("SIP/2.0")
    );
}

/// Ethernet → IPv4 → TCP → SIP 200 OK response.
#[test]
fn integration_ethernet_ipv4_tcp_sip_response() {
    let registry = DissectorRegistry::default();

    let sip_payload = b"SIP/2.0 200 OK\r\n\
                        Via: SIP/2.0/TCP server10.example.net;branch=z9hG4bKnashds8\r\n\
                        To: Bob <sip:bob@example.net>;tag=2493k59kd\r\n\
                        From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                        Call-ID: a84b4c76e66710@pc33.example.com\r\n\
                        CSeq: 314159 INVITE\r\n\
                        Contact: <sip:bob@192.0.2.4>\r\n\
                        Content-Length: 0\r\n\r\n";

    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 6, [10, 0, 0, 2], [10, 0, 0, 1]);
    push_tcp(&mut pkt, 12345, 5060, 0x18); // PSH+ACK
    pkt.extend_from_slice(sip_payload);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[3].name, "SIP");
    assert_layers_contiguous(&buf);

    let sip = buf.layer_by_name("SIP").unwrap();
    assert_eq!(
        buf.field_by_name(sip, "is_response").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(sip, "status_code").unwrap().value,
        FieldValue::U16(200)
    );
    assert_eq!(
        buf.field_by_name(sip, "reason_phrase").unwrap().value,
        FieldValue::Str("OK")
    );
}

/// Ethernet → IPv4 → TCP → SIP 200 OK response (server→client: src=5060, dst=ephemeral).
///
/// Verifies that port dispatch works correctly when the *source* port is
/// the registered SIP port, which is the typical server→client direction.
#[test]
fn integration_ethernet_ipv4_tcp_sip_response_server_to_client() {
    let registry = DissectorRegistry::default();

    let sip_payload = b"SIP/2.0 200 OK\r\n\
                        Via: SIP/2.0/TCP server10.example.net;branch=z9hG4bKnashds8\r\n\
                        To: Bob <sip:bob@example.net>;tag=2493k59kd\r\n\
                        From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                        Call-ID: a84b4c76e66710@pc33.example.com\r\n\
                        CSeq: 314159 INVITE\r\n\
                        Contact: <sip:bob@192.0.2.4>\r\n\
                        Content-Length: 0\r\n\r\n";

    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 6, [10, 0, 0, 2], [10, 0, 0, 1]);
    push_tcp(&mut pkt, 5060, 49152, 0x18); // PSH+ACK, src=5060 (server→client)
    pkt.extend_from_slice(sip_payload);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[3].name, "SIP");
    assert_layers_contiguous(&buf);

    let sip = buf.layer_by_name("SIP").unwrap();
    assert_eq!(
        buf.field_by_name(sip, "is_response").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(sip, "status_code").unwrap().value,
        FieldValue::U16(200)
    );
}

// ---------------------------------------------------------------------------
// GTPv2-C helpers
// ---------------------------------------------------------------------------

/// GTPv2-C header with TEID (T=1, 12 bytes). Returns start index for length fixup.
fn push_gtpv2c_with_teid(
    pkt: &mut Vec<u8>,
    msg_type: u8,
    teid: u32,
    seq: u32,
    ies: &[u8],
) -> usize {
    let start = pkt.len();
    let msg_length = (8 + ies.len()) as u16; // TEID(4) + Seq(3) + Spare(1) + IEs
    // Octet 1: Version=2, P=0, T=1, MP=0, spare=0
    pkt.push(0x48);
    // Octet 2: Message type
    pkt.push(msg_type);
    // Octets 3-4: Message length
    pkt.extend_from_slice(&msg_length.to_be_bytes());
    // Octets 5-8: TEID
    pkt.extend_from_slice(&teid.to_be_bytes());
    // Octets 9-11: Sequence Number (24 bits)
    pkt.push(((seq >> 16) & 0xFF) as u8);
    pkt.push(((seq >> 8) & 0xFF) as u8);
    pkt.push((seq & 0xFF) as u8);
    // Octet 12: Spare
    pkt.push(0x00);
    // IEs
    pkt.extend_from_slice(ies);
    start
}

/// GTPv2-C header without TEID (T=0, 8 bytes). Returns start index for length fixup.
fn push_gtpv2c_without_teid(pkt: &mut Vec<u8>, msg_type: u8, seq: u32, ies: &[u8]) -> usize {
    let start = pkt.len();
    let msg_length = (4 + ies.len()) as u16; // Seq(3) + Spare(1) + IEs
    // Octet 1: Version=2, P=0, T=0, MP=0, spare=0
    pkt.push(0x40);
    // Octet 2: Message type
    pkt.push(msg_type);
    // Octets 3-4: Message length
    pkt.extend_from_slice(&msg_length.to_be_bytes());
    // Octets 5-7: Sequence Number (24 bits)
    pkt.push(((seq >> 16) & 0xFF) as u8);
    pkt.push(((seq >> 8) & 0xFF) as u8);
    pkt.push((seq & 0xFF) as u8);
    // Octet 8: Spare
    pkt.push(0x00);
    // IEs
    pkt.extend_from_slice(ies);
    start
}

// ---------------------------------------------------------------------------
// GTPv2-C integration tests
// ---------------------------------------------------------------------------

/// Ethernet → IPv4 → UDP → GTPv2-C (Create Session Request with TEID + IEs)
#[test]
fn integration_ethernet_ipv4_udp_gtpv2c_create_session() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // Build IEs: Recovery IE (type=3, length=1, value=5)
    let recovery_ie: &[u8] = &[3, 0, 1, 0, 5];

    // Outer: Ethernet → IPv4 → UDP (port 2123)
    push_ethernet(&mut pkt, [0xAA; 6], [0xBB; 6], 0x0800);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 2123, 2123);

    // GTPv2-C Create Session Request (type=32, T=1)
    push_gtpv2c_with_teid(&mut pkt, 32, 0x12345678, 0x000001, recovery_ie);

    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Ethernet → IPv4 → UDP → GTPv2-C
    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "GTPv2-C");
    assert_layers_contiguous(&buf);

    // Verify GTPv2-C fields
    let gtpv2c = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(gtpv2c, "version").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(gtpv2c, "teid_flag").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(gtpv2c, "message_type").unwrap().value,
        FieldValue::U8(32)
    );
    assert_eq!(
        display_name_for(&buf, gtpv2c, "message_type"),
        Some("Create Session Request")
    );
    assert_eq!(
        buf.field_by_name(gtpv2c, "teid").unwrap().value,
        FieldValue::U32(0x12345678)
    );
    assert_eq!(
        buf.field_by_name(gtpv2c, "sequence_number").unwrap().value,
        FieldValue::U32(1)
    );
    // IEs should be present
    assert!(buf.field_by_name(gtpv2c, "ies").is_some());
}

/// Ethernet → IPv4 → UDP → GTPv2-C (Echo Request, no TEID)
#[test]
fn integration_ethernet_ipv4_udp_gtpv2c_echo_request() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // Recovery IE (type=3, length=1, value=10)
    let recovery_ie: &[u8] = &[3, 0, 1, 0, 10];

    // Outer: Ethernet → IPv4 → UDP (port 2123)
    push_ethernet(&mut pkt, [0xAA; 6], [0xBB; 6], 0x0800);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 2123, 2123);

    // GTPv2-C Echo Request (type=1, T=0)
    push_gtpv2c_without_teid(&mut pkt, 1, 0x000042, recovery_ie);

    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Ethernet → IPv4 → UDP → GTPv2-C
    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[3].name, "GTPv2-C");
    assert_layers_contiguous(&buf);

    let gtpv2c = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(gtpv2c, "version").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(gtpv2c, "teid_flag").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(gtpv2c, "message_type").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        display_name_for(&buf, gtpv2c, "message_type"),
        Some("Echo Request")
    );
    assert!(buf.field_by_name(gtpv2c, "teid").is_none()); // T=0: no TEID
    assert_eq!(
        buf.field_by_name(gtpv2c, "sequence_number").unwrap().value,
        FieldValue::U32(0x42)
    );
}

// ---------------------------------------------------------------------------
// SLL / SLL2 integration tests
// ---------------------------------------------------------------------------

/// Build a SLL2 header (20 bytes).
fn push_sll2(pkt: &mut Vec<u8>, protocol_type: u16, interface_index: u32, packet_type: u8) {
    pkt.extend_from_slice(&protocol_type.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // reserved
    pkt.extend_from_slice(&interface_index.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // arphrd_type: ARPHRD_ETHER
    pkt.push(packet_type);
    pkt.push(6); // ll_addr_len
    pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // ll_addr
    pkt.extend_from_slice(&[0x00, 0x00]); // pad
}

/// Build a SLL header (16 bytes).
fn push_sll(pkt: &mut Vec<u8>, packet_type: u16, protocol_type: u16) {
    pkt.extend_from_slice(&packet_type.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // arphrd_type: ARPHRD_ETHER
    pkt.extend_from_slice(&6u16.to_be_bytes()); // ll_addr_len
    pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // ll_addr
    pkt.extend_from_slice(&[0x00, 0x00]); // pad
    pkt.extend_from_slice(&protocol_type.to_be_bytes());
}

/// SLL2 → IPv4 → UDP through dissect_with_link_type.
#[test]
fn integration_sll2_ipv4_udp() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();
    push_sll2(&mut pkt, 0x0800, 1, 0); // SLL2: IPv4, iface 1, unicast
    let ipv4_start = pkt.len();
    push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry
        .dissect_with_link_type(&pkt, 276, &mut buf)
        .unwrap();
    assert_eq!(buf.layers().len(), 3);
    assert_eq!(buf.layers()[0].name, "SLL2");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_layers_contiguous(&buf);

    // Verify SLL2 fields
    assert_eq!(
        buf.field_by_name(&buf.layers()[0], "protocol_type")
            .unwrap()
            .value,
        FieldValue::U16(0x0800)
    );
    assert_eq!(
        buf.field_by_name(&buf.layers()[0], "interface_index")
            .unwrap()
            .value,
        FieldValue::U32(1)
    );
}

/// SLL → IPv4 → UDP through dissect_with_link_type.
#[test]
fn integration_sll_ipv4_udp() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();
    push_sll(&mut pkt, 0, 0x0800); // SLL: unicast, IPv4
    let ipv4_start = pkt.len();
    push_ipv4(&mut pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);
    let udp_start = push_udp(&mut pkt, 5060, 5060);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry
        .dissect_with_link_type(&pkt, 113, &mut buf)
        .unwrap();
    assert_eq!(buf.layers().len(), 3);
    assert_eq!(buf.layers()[0].name, "SLL");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_layers_contiguous(&buf);

    assert_eq!(
        buf.field_by_name(&buf.layers()[0], "protocol_type")
            .unwrap()
            .value,
        FieldValue::U16(0x0800)
    );
}

/// SLL2 → IPv6 → TCP SYN through dissect_with_link_type.
#[test]
fn integration_sll2_ipv6_tcp_syn() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();
    push_sll2(&mut pkt, 0x86DD, 2, 4); // SLL2: IPv6, iface 2, outgoing
    let ipv6_start = pkt.len();
    push_ipv6(
        &mut pkt,
        6, // TCP
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
    );
    push_tcp(&mut pkt, 54321, 443, 0x02); // SYN
    fixup_ipv6_payload_length(&mut pkt, ipv6_start);

    let mut buf = DissectBuffer::new();
    registry
        .dissect_with_link_type(&pkt, 276, &mut buf)
        .unwrap();
    assert_eq!(buf.layers().len(), 3);
    assert_eq!(buf.layers()[0].name, "SLL2");
    assert_eq!(buf.layers()[1].name, "IPv6");
    assert_eq!(buf.layers()[2].name, "TCP");
    assert_layers_contiguous(&buf);
}

/// dissect_with_link_type with link_type=1 (Ethernet) falls back to Ethernet entry.
#[test]
fn integration_dissect_with_link_type_ethernet() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0xff; 6],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        0x0800,
    );
    let ipv4_start = pkt.len();
    push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    // link_type=1 should fall back to the entry dissector (Ethernet)
    let mut buf = DissectBuffer::new();
    registry.dissect_with_link_type(&pkt, 1, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 3);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_layers_contiguous(&buf);
}

// ---------------------------------------------------------------------------
// Ethernet → LACP
// ---------------------------------------------------------------------------

/// Build a minimal LACPDU payload (110 bytes).
fn push_lacp(pkt: &mut Vec<u8>) {
    let start = pkt.len();
    pkt.resize(start + 110, 0);
    // IEEE 802.1AX-2020, Section 6.4.2.3
    pkt[start] = 0x01; // Subtype: LACP
    pkt[start + 1] = 0x01; // Version: 1
    // Actor Information TLV
    pkt[start + 2] = 0x01; // TLV Type
    pkt[start + 3] = 0x14; // Length = 20
    pkt[start + 4] = 0x80;
    pkt[start + 5] = 0x00; // Actor System Priority
    // Actor System MAC: 00:11:22:33:44:55
    pkt[start + 6] = 0x00;
    pkt[start + 7] = 0x11;
    pkt[start + 8] = 0x22;
    pkt[start + 9] = 0x33;
    pkt[start + 10] = 0x44;
    pkt[start + 11] = 0x55;
    pkt[start + 12] = 0x00;
    pkt[start + 13] = 0x01; // Actor Key
    pkt[start + 14] = 0x00;
    pkt[start + 15] = 0x80; // Actor Port Priority
    pkt[start + 16] = 0x00;
    pkt[start + 17] = 0x01; // Actor Port
    pkt[start + 18] = 0x3D; // Actor State
    // Partner Information TLV
    pkt[start + 22] = 0x02; // TLV Type
    pkt[start + 23] = 0x14; // Length = 20
    pkt[start + 24] = 0x80;
    pkt[start + 25] = 0x00; // Partner System Priority
    pkt[start + 26] = 0xAA;
    pkt[start + 27] = 0xBB;
    pkt[start + 28] = 0xCC;
    pkt[start + 29] = 0xDD;
    pkt[start + 30] = 0xEE;
    pkt[start + 31] = 0xFF; // Partner System MAC
    pkt[start + 32] = 0x00;
    pkt[start + 33] = 0x02; // Partner Key
    pkt[start + 34] = 0x00;
    pkt[start + 35] = 0x80; // Partner Port Priority
    pkt[start + 36] = 0x00;
    pkt[start + 37] = 0x02; // Partner Port
    pkt[start + 38] = 0x3F; // Partner State
    // Collector Information TLV
    pkt[start + 42] = 0x03; // TLV Type
    pkt[start + 43] = 0x10; // Length = 16
    pkt[start + 44] = 0x00;
    pkt[start + 45] = 0x32; // Max Delay = 50
    // Terminator TLV
    pkt[start + 58] = 0x00; // TLV Type
    pkt[start + 59] = 0x00; // Length
}

/// Ethernet (EtherType 0x8809) → LACP
#[test]
fn integration_ethernet_lacp() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();
    // LACP destination is the Slow Protocols multicast: 01:80:C2:00:00:02
    push_ethernet(
        &mut pkt,
        [0x01, 0x80, 0xC2, 0x00, 0x00, 0x02],
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        0x8809, // Slow Protocols EtherType
    );
    push_lacp(&mut pkt);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 2);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "LACP");
    assert_layers_contiguous(&buf);

    // Verify key LACP fields through the registry
    let lacp = buf.layer_by_name("LACP").unwrap();
    assert_eq!(
        buf.field_by_name(lacp, "subtype").unwrap().value,
        FieldValue::U8(0x01)
    );
    assert_eq!(
        buf.field_by_name(lacp, "version").unwrap().value,
        FieldValue::U8(0x01)
    );
    assert_eq!(
        buf.field_by_name(lacp, "actor_key").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(lacp, "partner_key").unwrap().value,
        FieldValue::U16(2)
    );
    assert_eq!(
        buf.field_by_name(lacp, "collector_max_delay")
            .unwrap()
            .value,
        FieldValue::U16(50)
    );
}

// ---------------------------------------------------------------------------
// GRE tests
// ---------------------------------------------------------------------------

/// Ethernet → IPv4 → GRE → IPv4 → UDP
#[test]
fn integration_ethernet_ipv4_gre_ipv4() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // Ethernet
    push_ethernet(&mut pkt, [0xff; 6], [0x11; 6], 0x0800);

    // Outer IPv4 (protocol 47 = GRE)
    let outer_ipv4_start = push_ipv4(&mut pkt, 47, [10, 0, 0, 1], [10, 0, 0, 2]);

    // GRE (no optional fields, protocol_type = 0x0800 for IPv4)
    push_gre(&mut pkt, 0x0800);

    // Inner IPv4 (protocol 17 = UDP)
    let inner_ipv4_start = push_ipv4(&mut pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);

    // UDP
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, inner_ipv4_start);
    fixup_ipv4_length(&mut pkt, outer_ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 5);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "GRE");
    assert_eq!(buf.layers()[3].name, "IPv4");
    assert_eq!(buf.layers()[4].name, "UDP");
    assert_layers_contiguous(&buf);

    // Verify GRE fields
    let gre = buf
        .layers()
        .iter()
        .filter(|l| l.name == "GRE")
        .collect::<Vec<_>>();
    assert_eq!(gre.len(), 1);
    assert_eq!(
        buf.field_by_name(gre[0], "protocol_type").unwrap().value,
        FieldValue::U16(0x0800)
    );
}

/// Ethernet → IPv4 → GRE → IPv6 → UDP
#[test]
fn integration_ethernet_ipv4_gre_ipv6() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();

    push_ethernet(&mut pkt, [0xff; 6], [0x11; 6], 0x0800);
    let outer_ipv4_start = push_ipv4(&mut pkt, 47, [10, 0, 0, 1], [10, 0, 0, 2]);

    // GRE with Protocol Type = 0x86DD (IPv6)
    push_gre(&mut pkt, 0x86DD);

    let src6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let ipv6_start = push_ipv6(&mut pkt, 17, src6, dst6);

    let udp_start = push_udp(&mut pkt, 5000, 6000);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv6_payload_length(&mut pkt, ipv6_start);
    fixup_ipv4_length(&mut pkt, outer_ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 5);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "GRE");
    assert_eq!(buf.layers()[3].name, "IPv6");
    assert_eq!(buf.layers()[4].name, "UDP");
    assert_layers_contiguous(&buf);
}

/// Ethernet → IPv4 → GRE (with Key) → IPv4 → UDP
#[test]
fn integration_ethernet_ipv4_gre_key_ipv4() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();

    push_ethernet(&mut pkt, [0xff; 6], [0x11; 6], 0x0800);
    let outer_ipv4_start = push_ipv4(&mut pkt, 47, [10, 0, 0, 1], [10, 0, 0, 2]);

    // GRE with Key = 0xDEADBEEF
    push_gre_with_key(&mut pkt, 0x0800, 0xDEADBEEF);

    let inner_ipv4_start = push_ipv4(&mut pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, inner_ipv4_start);
    fixup_ipv4_length(&mut pkt, outer_ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 5);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "GRE");
    assert_eq!(buf.layers()[3].name, "IPv4");
    assert_eq!(buf.layers()[4].name, "UDP");
    assert_layers_contiguous(&buf);

    // Verify GRE Key
    let gre = buf.layer_by_name("GRE").unwrap();
    assert_eq!(
        buf.field_by_name(gre, "key_present").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(gre, "key").unwrap().value,
        FieldValue::U32(0xDEADBEEF)
    );
}

// STP / RSTP helpers
// ---------------------------------------------------------------------------

/// Ethernet header for 802.3 LLC frame (14 bytes): dst + src + length field.
/// Returns start index of the length field for later fixup.
fn push_ethernet_llc(pkt: &mut Vec<u8>, dst: [u8; 6], src: [u8; 6]) -> usize {
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(&src);
    let length_offset = pkt.len();
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Length (placeholder)
    // LLC header: DSAP=0x42, SSAP=0x42, Control=0x03 (STP)
    pkt.push(0x42);
    pkt.push(0x42);
    pkt.push(0x03);
    length_offset
}

/// Fix the 802.3 length field after LLC payload has been appended.
fn fixup_802_3_length(pkt: &mut [u8], length_offset: usize) {
    // Length covers everything after the Ethernet header (from LLC onward).
    let llc_payload_len = (pkt.len() - length_offset - 2) as u16;
    pkt[length_offset..length_offset + 2].copy_from_slice(&llc_payload_len.to_be_bytes());
}

/// STP Configuration BPDU (35 bytes): protocol_id(2) + version(1) + type(1) + flags(1) +
/// root_id(8) + root_path_cost(4) + bridge_id(8) + port_id(2) + timers(8).
fn push_stp_config_bpdu(pkt: &mut Vec<u8>) {
    // Protocol ID = 0x0000
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Version = 0 (STP)
    pkt.push(0x00);
    // Type = 0x00 (Configuration)
    pkt.push(0x00);
    // Flags: TC=1
    pkt.push(0x01);
    // Root Bridge ID: priority=0x8000, MAC=00:AA:BB:CC:DD:EE
    pkt.extend_from_slice(&[0x80, 0x00]);
    pkt.extend_from_slice(&[0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    // Root Path Cost = 4
    pkt.extend_from_slice(&4u32.to_be_bytes());
    // Bridge ID: priority=0x8001, MAC=00:11:22:33:44:55
    pkt.extend_from_slice(&[0x80, 0x01]);
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // Port ID = 0x8002
    pkt.extend_from_slice(&0x8002u16.to_be_bytes());
    // Message Age = 256 (1s)
    pkt.extend_from_slice(&256u16.to_be_bytes());
    // Max Age = 5120 (20s)
    pkt.extend_from_slice(&5120u16.to_be_bytes());
    // Hello Time = 512 (2s)
    pkt.extend_from_slice(&512u16.to_be_bytes());
    // Forward Delay = 3840 (15s)
    pkt.extend_from_slice(&3840u16.to_be_bytes());
}

/// STP TCN BPDU (4 bytes).
fn push_stp_tcn_bpdu(pkt: &mut Vec<u8>) {
    pkt.extend_from_slice(&[0x00, 0x00]); // Protocol ID
    pkt.push(0x00); // Version
    pkt.push(0x80); // Type = TCN
}

/// RST BPDU (36 bytes): same as Config BPDU but version=2, type=0x02, + version1_length(1).
fn push_rstp_bpdu(pkt: &mut Vec<u8>) {
    pkt.extend_from_slice(&[0x00, 0x00]); // Protocol ID
    pkt.push(0x02); // Version = 2 (RSTP)
    pkt.push(0x02); // Type = RST
    pkt.push(0x3E); // Flags: Proposal=1, Role=3(Designated), Learning=1, Forwarding=1
    // Root Bridge ID
    pkt.extend_from_slice(&[0x80, 0x00]);
    pkt.extend_from_slice(&[0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    // Root Path Cost = 0
    pkt.extend_from_slice(&0u32.to_be_bytes());
    // Bridge ID
    pkt.extend_from_slice(&[0x80, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // Port ID
    pkt.extend_from_slice(&0x8001u16.to_be_bytes());
    // Timers
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Message Age
    pkt.extend_from_slice(&5120u16.to_be_bytes()); // Max Age
    pkt.extend_from_slice(&512u16.to_be_bytes()); // Hello Time
    pkt.extend_from_slice(&3840u16.to_be_bytes()); // Forward Delay
    // Version 1 Length = 0
    pkt.push(0x00);
}

// STP multicast destination MAC (IEEE 802.1D-2004, Section 7.12.3).
const STP_DST: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00];
const MAC_SRC_STP: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

// ---------------------------------------------------------------------------
// STP / RSTP integration tests
// ---------------------------------------------------------------------------

#[test]
fn integration_ethernet_llc_stp_config() {
    let mut pkt = Vec::new();
    let len_offset = push_ethernet_llc(&mut pkt, STP_DST, MAC_SRC_STP);
    push_stp_config_bpdu(&mut pkt);
    fixup_802_3_length(&mut pkt, len_offset);

    let registry = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 2); // Ethernet, STP
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "STP");
    assert_layers_contiguous(&buf);

    // Verify Ethernet LLC fields
    let eth = &buf.layers()[0];
    assert_eq!(
        buf.field_by_name(eth, "llc_dsap").unwrap().value,
        FieldValue::U8(0x42)
    );

    // Verify STP fields
    let stp = &buf.layers()[1];
    assert_eq!(
        display_name_for(&buf, stp, "bpdu_type"),
        Some("Configuration")
    );
    assert_eq!(
        buf.field_by_name(stp, "root_path_cost").unwrap().value,
        FieldValue::U32(4)
    );
}

#[test]
fn integration_ethernet_llc_stp_tcn() {
    let mut pkt = Vec::new();
    let len_offset = push_ethernet_llc(&mut pkt, STP_DST, MAC_SRC_STP);
    push_stp_tcn_bpdu(&mut pkt);
    fixup_802_3_length(&mut pkt, len_offset);

    let registry = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 2);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "STP");
    assert_layers_contiguous(&buf);

    let stp = &buf.layers()[1];
    assert_eq!(
        display_name_for(&buf, stp, "bpdu_type"),
        Some("Topology Change Notification")
    );
}

#[test]
fn integration_ethernet_llc_rstp() {
    let mut pkt = Vec::new();
    let len_offset = push_ethernet_llc(&mut pkt, STP_DST, MAC_SRC_STP);
    push_rstp_bpdu(&mut pkt);
    fixup_802_3_length(&mut pkt, len_offset);

    let registry = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 2);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "STP");
    assert_layers_contiguous(&buf);

    let stp = &buf.layers()[1];
    assert_eq!(display_name_for(&buf, stp, "bpdu_type"), Some("RST"));
    assert_eq!(
        buf.field_by_name(stp, "version").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(stp, "version1_length").unwrap().value,
        FieldValue::U8(0)
    );
}

// ---------------------------------------------------------------------------
// Ethernet → LLDP
// ---------------------------------------------------------------------------

fn build_eth_lldp() -> Vec<u8> {
    let mut pkt = Vec::new();
    // LLDP destination: 01:80:C2:00:00:0E (nearest bridge)
    push_ethernet(
        &mut pkt,
        [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E],
        MAC_SRC,
        0x88CC,
    );
    // Chassis ID TLV: type=1, length=7 (subtype MAC + 6 bytes)
    pkt.extend_from_slice(&0x0207u16.to_be_bytes());
    pkt.push(4); // subtype: MAC address
    pkt.extend_from_slice(&MAC_SRC);
    // Port ID TLV: type=2, length=4 (subtype locally assigned + "ge0")
    pkt.extend_from_slice(&0x0404u16.to_be_bytes());
    pkt.push(7); // subtype: Locally assigned
    pkt.extend_from_slice(b"ge0");
    // TTL TLV: type=3, length=2
    pkt.extend_from_slice(&0x0602u16.to_be_bytes());
    pkt.extend_from_slice(&120u16.to_be_bytes());
    // System Name TLV: type=5, length=6 "switch"
    let sname = b"switch";
    let hdr = (5u16 << 9) | sname.len() as u16;
    pkt.extend_from_slice(&hdr.to_be_bytes());
    pkt.extend_from_slice(sname);
    // End Of LLDPDU
    pkt.extend_from_slice(&0x0000u16.to_be_bytes());
    pkt
}

#[test]
fn integration_ethernet_lldp() {
    let reg = DissectorRegistry::default();
    let data = build_eth_lldp();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 2);
    assert_layers_contiguous(&buf);

    let eth = &buf.layers()[0];
    assert_eq!(eth.name, "Ethernet");
    assert_eq!(
        buf.field_by_name(eth, "ethertype").unwrap().value,
        FieldValue::U16(0x88CC)
    );

    let lldp = &buf.layers()[1];
    assert_eq!(lldp.name, "LLDP");
    let tlvs_range = match &buf.field_by_name(lldp, "tlvs").unwrap().value {
        FieldValue::Array(elems) => elems.clone(),
        _ => panic!("expected Array"),
    };
    let tlvs = direct_children(&buf, &tlvs_range);
    // Chassis ID + Port ID + TTL + System Name + End = 5 TLVs
    assert_eq!(tlvs.len(), 5);

    // Verify Chassis ID subtype
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _or) = tlvs[0].value else {
                    panic!("expected Object")
                };
                let _fs = buf.nested_fields(_or);
                _fs.iter()
                    .find(|f| f.name() == "type")
                    .unwrap()
                    .value
                    .clone()
            }
        },
        FieldValue::U8(1)
    );

    // Verify TTL
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _or) = tlvs[2].value else {
                    panic!("expected Object")
                };
                let _fs = buf.nested_fields(_or);
                _fs.iter()
                    .find(|f| f.name() == "ttl")
                    .unwrap()
                    .value
                    .clone()
            }
        },
        FieldValue::U16(120)
    );

    // Verify System Name
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _or) = tlvs[3].value else {
                    panic!("expected Object")
                };
                let _fs = buf.nested_fields(_or);
                _fs.iter()
                    .find(|f| f.name() == "value")
                    .unwrap()
                    .value
                    .clone()
            }
        },
        FieldValue::Bytes(b"switch")
    );
}

// ---------------------------------------------------------------------------
// MPLS helpers
// ---------------------------------------------------------------------------

/// Push a single MPLS label stack entry (4 bytes).
fn push_mpls(pkt: &mut Vec<u8>, label: u32, tc: u8, s: u8, ttl: u8) {
    let word: u32 =
        (label << 12) | ((tc as u32 & 0x07) << 9) | ((s as u32 & 0x01) << 8) | ttl as u32;
    pkt.extend_from_slice(&word.to_be_bytes());
}

// ---------------------------------------------------------------------------
// Ethernet → MPLS → IPv4 → UDP
// ---------------------------------------------------------------------------

#[test]
fn integration_ethernet_mpls_ipv4_udp() {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x00; 6], 0x8847);
    push_mpls(&mut pkt, 100, 0, 1, 64);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let reg = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers().len(), 4); // Ethernet, MPLS, IPv4, UDP
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "MPLS");
    assert_eq!(buf.layers()[2].name, "IPv4");
    assert_eq!(buf.layers()[3].name, "UDP");

    // Verify MPLS label stack
    let mpls = buf.layer_by_name("MPLS").unwrap();
    let FieldValue::Array(ref stack_range) = buf.field_by_name(mpls, "label_stack").unwrap().value
    else {
        panic!("expected Array")
    };
    let stack = direct_children(&buf, stack_range);
    assert_eq!(stack.len(), 1);
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _or) = stack[0].value else {
                    panic!("expected Object")
                };
                let _fs = buf.nested_fields(_or);
                _fs.iter()
                    .find(|f| f.name() == "label")
                    .unwrap()
                    .value
                    .clone()
            }
        },
        FieldValue::U32(100)
    );
}

// ---------------------------------------------------------------------------
// Ethernet → MPLS (2 labels) → IPv4 → UDP
// ---------------------------------------------------------------------------

#[test]
fn integration_ethernet_mpls_two_labels_ipv4_udp() {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x00; 6], 0x8847);
    push_mpls(&mut pkt, 200, 5, 0, 128);
    push_mpls(&mut pkt, 300, 3, 1, 64);
    let ipv4_start = push_ipv4(&mut pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);
    let udp_start = push_udp(&mut pkt, 5060, 5060);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let reg = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers().len(), 4); // Ethernet, MPLS, IPv4, UDP
    assert_eq!(buf.layers()[1].name, "MPLS");

    let mpls = buf.layer_by_name("MPLS").unwrap();
    let FieldValue::Array(ref stack_range) = buf.field_by_name(mpls, "label_stack").unwrap().value
    else {
        panic!("expected Array")
    };
    let stack = direct_children(&buf, stack_range);
    assert_eq!(stack.len(), 2);
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _or) = stack[0].value else {
                    panic!("expected Object")
                };
                let _fs = buf.nested_fields(_or);
                _fs.iter()
                    .find(|f| f.name() == "label")
                    .unwrap()
                    .value
                    .clone()
            }
        },
        FieldValue::U32(200)
    );
    assert_eq!(
        {
            {
                let FieldValue::Object(ref _or) = stack[1].value else {
                    panic!("expected Object")
                };
                let _fs = buf.nested_fields(_or);
                _fs.iter()
                    .find(|f| f.name() == "label")
                    .unwrap()
                    .value
                    .clone()
            }
        },
        FieldValue::U32(300)
    );
}

// ---- VXLAN tests ----

/// Ethernet → IPv4 → UDP(4789) → VXLAN → inner Ethernet → inner IPv4 → inner UDP
#[test]
fn integration_ethernet_ipv4_udp_vxlan_ethernet_ipv4_udp() {
    let reg = DissectorRegistry::default();

    let mut pkt = Vec::new();

    // Outer Ethernet
    push_ethernet(
        &mut pkt,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02],
        0x0800,
    );

    // Outer IPv4 (proto=17 UDP)
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);

    // Outer UDP (dst=4789)
    let udp_start = push_udp(&mut pkt, 50000, 4789);

    // VXLAN (VNI=42)
    push_vxlan(&mut pkt, 42);

    // Inner Ethernet
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
        0x0800,
    );

    // Inner IPv4 (proto=17 UDP)
    let inner_ipv4_start = push_ipv4(&mut pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);

    // Inner UDP
    let inner_udp_start = push_udp(&mut pkt, 12345, 80);

    // Fix lengths
    fixup_ipv4_length(&mut pkt, inner_ipv4_start);
    fixup_udp_length(&mut pkt, inner_udp_start);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Expect 7 layers: Ethernet, IPv4, UDP, VXLAN, Ethernet, IPv4, UDP
    assert_eq!(buf.layers().len(), 7);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "VXLAN");
    assert_eq!(buf.layers()[4].name, "Ethernet");
    assert_eq!(buf.layers()[5].name, "IPv4");
    assert_eq!(buf.layers()[6].name, "UDP");

    assert_layers_contiguous(&buf);

    // Verify VXLAN fields
    let vxlan = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(vxlan, "vni").unwrap().value,
        FieldValue::U32(42)
    );
    assert_eq!(
        buf.field_by_name(vxlan, "vni_valid").unwrap().value,
        FieldValue::U8(1)
    );

    // Verify inner Ethernet addresses
    let inner_eth = &buf.layers()[4];
    assert_eq!(
        buf.field_by_name(inner_eth, "dst").unwrap().value,
        FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    );
    assert_eq!(
        buf.field_by_name(inner_eth, "src").unwrap().value,
        FieldValue::MacAddr(MacAddr([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]))
    );

    // Verify inner UDP ports
    let inner_udp = &buf.layers()[6];
    assert_eq!(
        buf.field_by_name(inner_udp, "src_port").unwrap().value,
        FieldValue::U16(12345)
    );
    assert_eq!(
        buf.field_by_name(inner_udp, "dst_port").unwrap().value,
        FieldValue::U16(80)
    );
}

// ---------------------------------------------------------------------------
// Ethernet → IPv4 → UDP → NTP (Client Request)
// ---------------------------------------------------------------------------

#[test]
fn integration_ethernet_ipv4_udp_ntp_client() {
    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 12345, 123);

    // NTP client request: LI=0, VN=4, Mode=3 (Client), Stratum=0
    let ntp_start = pkt.len();
    pkt.push((4 << 3) | 3); // LI=0, VN=4, Mode=3
    pkt.push(0); // Stratum
    pkt.push(6); // Poll
    pkt.push(0xEC); // Precision: -20 as i8
    pkt.extend_from_slice(&[0; 4]); // Root Delay
    pkt.extend_from_slice(&[0; 4]); // Root Dispersion
    pkt.extend_from_slice(&[0; 4]); // Reference ID
    pkt.extend_from_slice(&[0; 8]); // Reference Timestamp
    pkt.extend_from_slice(&[0; 8]); // Origin Timestamp
    pkt.extend_from_slice(&[0; 8]); // Receive Timestamp
    pkt.extend_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_be_bytes()); // Transmit Timestamp
    let _ = ntp_start;

    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let registry = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);

    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "NTP");

    let ntp = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(ntp, "version").unwrap().value,
        FieldValue::U8(4)
    );
    assert_eq!(
        buf.field_by_name(ntp, "mode").unwrap().value,
        FieldValue::U8(3)
    );
    assert_eq!(display_name_for(&buf, ntp, "mode"), Some("client"));
    assert_eq!(
        buf.field_by_name(ntp, "transmit_timestamp").unwrap().value,
        FieldValue::U64(0xDEAD_BEEF_CAFE_BABE)
    );
}

// ---------------------------------------------------------------------------
// BFD integration tests
// ---------------------------------------------------------------------------

#[test]
fn integration_ethernet_ipv4_udp_bfd_up() {
    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 49152, 3784);

    // BFD Control packet: Version=1, Diag=0 (No Diagnostic), State=3 (Up)
    let byte0 = 1u8 << 5; // version=1, diag=0
    let byte1 = 3u8 << 6; // state=Up, all flags 0
    pkt.push(byte0);
    pkt.push(byte1);
    pkt.push(3); // detect mult
    pkt.push(24); // length
    pkt.extend_from_slice(&1u32.to_be_bytes()); // my discriminator
    pkt.extend_from_slice(&2u32.to_be_bytes()); // your discriminator
    pkt.extend_from_slice(&1_000_000u32.to_be_bytes()); // desired min tx
    pkt.extend_from_slice(&1_000_000u32.to_be_bytes()); // required min rx
    pkt.extend_from_slice(&0u32.to_be_bytes()); // required min echo rx

    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let registry = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);

    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "BFD");

    let bfd = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(bfd, "version").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(bfd, "state").unwrap().value,
        FieldValue::U8(3)
    );
    assert_eq!(display_name_for(&buf, bfd, "state"), Some("Up"));
    assert_eq!(
        buf.field_by_name(bfd, "my_discriminator").unwrap().value,
        FieldValue::U32(1)
    );
    assert_eq!(
        buf.field_by_name(bfd, "your_discriminator").unwrap().value,
        FieldValue::U32(2)
    );
}

// ---------------------------------------------------------------------------
// GENEVE helpers
// ---------------------------------------------------------------------------

/// GENEVE header (8 bytes, no options). Protocol Type uses EtherType values.
fn push_geneve(pkt: &mut Vec<u8>, protocol_type: u16, vni: u32) {
    push_geneve_with_options(pkt, protocol_type, vni, &[]);
}

/// GENEVE header with options.
fn push_geneve_with_options(pkt: &mut Vec<u8>, protocol_type: u16, vni: u32, options: &[u8]) {
    let opt_len = (options.len() / 4) as u8;
    pkt.push(opt_len);
    pkt.push(0x00);
    pkt.extend_from_slice(&protocol_type.to_be_bytes());
    pkt.push(((vni >> 16) & 0xFF) as u8);
    pkt.push(((vni >> 8) & 0xFF) as u8);
    pkt.push((vni & 0xFF) as u8);
    pkt.push(0x00);
    pkt.extend_from_slice(options);
}

// ---------------------------------------------------------------------------
// GENEVE integration tests
// ---------------------------------------------------------------------------

/// Ethernet → IPv4 → UDP(6081) → GENEVE → Ethernet → IPv4 → UDP
#[test]
fn integration_ethernet_ipv4_udp_geneve_ipv4() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // Outer Ethernet
    push_ethernet(&mut pkt, [0xff; 6], [0x11; 6], 0x0800);

    // Outer IPv4 (protocol 17 = UDP)
    let outer_ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);

    // Outer UDP (port 6081 = GENEVE)
    let outer_udp_start = push_udp(&mut pkt, 50000, 6081);

    // GENEVE (Protocol Type = 0x6558 = Transparent Ethernet Bridging, VNI = 100)
    push_geneve(&mut pkt, 0x6558, 100);

    // Inner Ethernet
    push_ethernet(&mut pkt, [0xaa; 6], [0xbb; 6], 0x0800);

    // Inner IPv4 (protocol 17 = UDP)
    let inner_ipv4_start = push_ipv4(&mut pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);

    // Inner UDP
    let inner_udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, inner_udp_start);
    fixup_ipv4_length(&mut pkt, inner_ipv4_start);
    fixup_udp_length(&mut pkt, outer_udp_start);
    fixup_ipv4_length(&mut pkt, outer_ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 7);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "GENEVE");
    assert_eq!(buf.layers()[4].name, "Ethernet");
    assert_eq!(buf.layers()[5].name, "IPv4");
    assert_eq!(buf.layers()[6].name, "UDP");
    assert_layers_contiguous(&buf);

    // Verify GENEVE fields
    let geneve = buf.layer_by_name("GENEVE").unwrap();
    assert_eq!(
        buf.field_by_name(geneve, "protocol_type").unwrap().value,
        FieldValue::U16(0x6558)
    );
    assert_eq!(
        buf.field_by_name(geneve, "vni").unwrap().value,
        FieldValue::U32(100)
    );
    assert_eq!(
        buf.field_by_name(geneve, "version").unwrap().value,
        FieldValue::U8(0)
    );
    assert!(buf.field_by_name(geneve, "options").is_none());
}

/// Ethernet → IPv4 → UDP(6081) → GENEVE (with options) → Ethernet → IPv4
#[test]
fn integration_ethernet_ipv4_udp_geneve_with_options() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // Outer Ethernet
    push_ethernet(&mut pkt, [0xff; 6], [0x11; 6], 0x0800);

    // Outer IPv4 (protocol 17 = UDP)
    let outer_ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);

    // Outer UDP (port 6081 = GENEVE)
    let outer_udp_start = push_udp(&mut pkt, 50000, 6081);

    // GENEVE with 8 bytes of options (Protocol Type = 0x6558, VNI = 200)
    let options: &[u8] = &[
        // Option: Class=0x0102, Type=0x01, R=0, Length=1 (4 bytes of data)
        0x01, 0x02, 0x01, 0x01, 0xDE, 0xAD, 0xBE, 0xEF,
    ];
    push_geneve_with_options(&mut pkt, 0x6558, 200, options);

    // Inner Ethernet
    push_ethernet(&mut pkt, [0xaa; 6], [0xbb; 6], 0x0800);

    // Inner IPv4 (protocol 17 = UDP)
    let inner_ipv4_start = push_ipv4(&mut pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);

    // Inner UDP
    let inner_udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, inner_udp_start);
    fixup_ipv4_length(&mut pkt, inner_ipv4_start);
    fixup_udp_length(&mut pkt, outer_udp_start);
    fixup_ipv4_length(&mut pkt, outer_ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 7);
    assert_eq!(buf.layers()[3].name, "GENEVE");
    assert_layers_contiguous(&buf);

    // Verify GENEVE fields
    let geneve = buf.layer_by_name("GENEVE").unwrap();
    assert_eq!(
        buf.field_by_name(geneve, "opt_len").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(geneve, "vni").unwrap().value,
        FieldValue::U32(200)
    );
    assert_eq!(
        buf.field_by_name(geneve, "options").unwrap().value,
        FieldValue::Bytes(options)
    );
}

// ---------------------------------------------------------------------------
// Ethernet → IPv4 → OSPFv2 Hello
// ---------------------------------------------------------------------------

#[test]
fn integration_ethernet_ipv4_ospfv2_hello() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // Ethernet
    push_ethernet(
        &mut pkt,
        [0x01, 0x00, 0x5e, 0x00, 0x00, 0x05],
        [0xaa; 6],
        0x0800,
    );

    // IPv4 (protocol 89 = OSPF)
    let ipv4_start = push_ipv4(&mut pkt, 89, [10, 0, 0, 1], [224, 0, 0, 5]);

    // OSPFv2 Hello packet
    let ospf_start = pkt.len();
    pkt.push(2); // Version
    pkt.push(1); // Type = Hello
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Packet Length (placeholder)
    pkt.extend_from_slice(&[1, 1, 1, 1]); // Router ID
    pkt.extend_from_slice(&[0, 0, 0, 0]); // Area ID
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // Auth Type
    pkt.extend_from_slice(&[0u8; 8]); // Authentication
    // Hello body
    pkt.extend_from_slice(&[255, 255, 255, 0]); // Network Mask
    pkt.extend_from_slice(&[0, 10]); // Hello Interval
    pkt.push(0x02); // Options
    pkt.push(1); // Router Priority
    pkt.extend_from_slice(&[0, 0, 0, 40]); // Router Dead Interval
    pkt.extend_from_slice(&[10, 0, 0, 1]); // DR
    pkt.extend_from_slice(&[0, 0, 0, 0]); // BDR
    // One neighbor
    pkt.extend_from_slice(&[2, 2, 2, 2]);

    // Fix OSPF packet length
    let ospf_len = (pkt.len() - ospf_start) as u16;
    pkt[ospf_start + 2..ospf_start + 4].copy_from_slice(&ospf_len.to_be_bytes());

    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers().len(), 3);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "OSPFv2");

    let ospf = buf.layer_by_name("OSPFv2").unwrap();
    assert_eq!(
        buf.field_by_name(ospf, "version").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(ospf, "msg_type").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(display_name_for(&buf, ospf, "msg_type"), Some("Hello"));
    assert_eq!(
        buf.field_by_name(ospf, "router_id").unwrap().value,
        FieldValue::Ipv4Addr([1, 1, 1, 1])
    );
    assert_eq!(
        buf.field_by_name(ospf, "auth_type").unwrap().value,
        FieldValue::U16(0)
    );
    assert_eq!(
        buf.field_by_name(ospf, "network_mask").unwrap().value,
        FieldValue::Ipv4Addr([255, 255, 255, 0])
    );
    assert_eq!(
        buf.field_by_name(ospf, "hello_interval").unwrap().value,
        FieldValue::U16(10)
    );
    assert_eq!(
        buf.field_by_name(ospf, "router_dead_interval")
            .unwrap()
            .value,
        FieldValue::U32(40)
    );
    assert_eq!(
        buf.field_by_name(ospf, "designated_router").unwrap().value,
        FieldValue::Ipv4Addr([10, 0, 0, 1])
    );
    let neighbors = {
        let f = buf.field_by_name(ospf, "neighbors").unwrap();
        let FieldValue::Array(ref r) = f.value else {
            panic!("expected Array")
        };
        buf.nested_fields(r)
    };
    assert_eq!(neighbors.len(), 1);
    assert_eq!(neighbors[0].value, FieldValue::Ipv4Addr([2, 2, 2, 2]));
}

// ---------------------------------------------------------------------------
// Ethernet → IPv6 → OSPFv3 Hello
// ---------------------------------------------------------------------------

#[test]
fn integration_ethernet_ipv6_ospfv3_hello() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // Ethernet
    push_ethernet(
        &mut pkt,
        [0x33, 0x33, 0x00, 0x00, 0x00, 0x05],
        [0xaa; 6],
        0x86DD,
    );

    // IPv6 (next header 89 = OSPF)
    let ipv6_start = push_ipv6(
        &mut pkt,
        89,
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5],
    );

    // OSPFv3 Hello packet
    let ospf_start = pkt.len();
    pkt.push(3); // Version
    pkt.push(1); // Type = Hello
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Packet Length (placeholder)
    pkt.extend_from_slice(&[1, 1, 1, 1]); // Router ID
    pkt.extend_from_slice(&[0, 0, 0, 0]); // Area ID
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
    pkt.push(0); // Instance ID
    pkt.push(0); // Reserved
    // Hello body
    pkt.extend_from_slice(&[0, 0, 0, 1]); // Interface ID
    pkt.push(1); // Router Priority
    pkt.extend_from_slice(&[0x00, 0x00, 0x13]); // Options (24-bit)
    pkt.extend_from_slice(&[0, 10]); // Hello Interval
    pkt.extend_from_slice(&[0, 40]); // Router Dead Interval
    pkt.extend_from_slice(&[10, 0, 0, 1]); // DR
    pkt.extend_from_slice(&[0, 0, 0, 0]); // BDR

    // Fix OSPFv3 packet length
    let ospf_len = (pkt.len() - ospf_start) as u16;
    pkt[ospf_start + 2..ospf_start + 4].copy_from_slice(&ospf_len.to_be_bytes());

    fixup_ipv6_payload_length(&mut pkt, ipv6_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers().len(), 3);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv6");
    assert_eq!(buf.layers()[2].name, "OSPFv3");

    let ospf = buf.layer_by_name("OSPFv3").unwrap();
    assert_eq!(
        buf.field_by_name(ospf, "version").unwrap().value,
        FieldValue::U8(3)
    );
    assert_eq!(
        buf.field_by_name(ospf, "msg_type").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(display_name_for(&buf, ospf, "msg_type"), Some("Hello"));
    assert_eq!(
        buf.field_by_name(ospf, "router_id").unwrap().value,
        FieldValue::Ipv4Addr([1, 1, 1, 1])
    );
    assert_eq!(
        buf.field_by_name(ospf, "instance_id").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(ospf, "interface_id").unwrap().value,
        FieldValue::U32(1)
    );
    assert_eq!(
        buf.field_by_name(ospf, "router_priority").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(ospf, "options").unwrap().value,
        FieldValue::U32(0x13)
    );
    assert_eq!(
        buf.field_by_name(ospf, "hello_interval").unwrap().value,
        FieldValue::U16(10)
    );
    assert_eq!(
        buf.field_by_name(ospf, "router_dead_interval")
            .unwrap()
            .value,
        FieldValue::U16(40)
    );
    assert_eq!(
        buf.field_by_name(ospf, "designated_router").unwrap().value,
        FieldValue::Ipv4Addr([10, 0, 0, 1])
    );
    let neighbors = {
        let f = buf.field_by_name(ospf, "neighbors").unwrap();
        let FieldValue::Array(ref r) = f.value else {
            panic!("expected Array")
        };
        buf.nested_fields(r)
    };
    assert_eq!(neighbors.len(), 0);
}

// ---------------------------------------------------------------------------
// IS-IS over IEEE 802.2 LLC
// ---------------------------------------------------------------------------

/// Build an Ethernet + LLC (DSAP=0xFE) + IS-IS L1 LAN IIH frame.
fn push_ethernet_llc_isis(pkt: &mut Vec<u8>, dst: [u8; 6], src: [u8; 6]) -> usize {
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(&src);
    let length_offset = pkt.len();
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Length (placeholder)
    // LLC header: DSAP=0xFE, SSAP=0xFE, Control=0x03 (IS-IS)
    pkt.push(0xFE);
    pkt.push(0xFE);
    pkt.push(0x03);
    length_offset
}

/// Builds an IS-IS L1 LAN IIH PDU with Area Address and Protocols Supported TLVs.
fn push_isis_l1_lan_iih(pkt: &mut Vec<u8>) {
    let iih_start = pkt.len();
    // Common header (8 bytes)
    pkt.extend_from_slice(&[
        0x83, // NLPID
        27,   // Header Length
        0x01, // Version
        0x00, // ID Length (0=6)
        15,   // PDU Type: L1 LAN IIH
        0x01, // Version
        0x00, // Reserved
        0x00, // Max Area Addresses
    ]);
    // LAN IIH specific
    pkt.push(0x01); // Circuit Type: L1
    // Source ID (6 bytes)
    pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    // Holding Time = 30
    pkt.extend_from_slice(&30u16.to_be_bytes());
    // PDU Length placeholder (will be fixed up)
    let pdu_len_offset = pkt.len();
    pkt.extend_from_slice(&0u16.to_be_bytes());
    // Priority = 64
    pkt.push(0x40);
    // LAN ID (7 bytes)
    pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01]);

    // TLV 1: Area Addresses (area 49.0001)
    pkt.extend_from_slice(&[0x01, 0x04, 0x03, 0x49, 0x00, 0x01]);
    // TLV 129: Protocols Supported (IPv4)
    pkt.extend_from_slice(&[0x81, 0x01, 0xCC]);
    // TLV 132: IP Interface Address (10.0.0.1)
    pkt.extend_from_slice(&[0x84, 0x04, 10, 0, 0, 1]);

    // Fix up PDU Length
    let pdu_len = (pkt.len() - iih_start) as u16;
    pkt[pdu_len_offset..pdu_len_offset + 2].copy_from_slice(&pdu_len.to_be_bytes());
}

#[test]
fn integration_ethernet_llc_isis_l1_lan_iih() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();
    // IS-IS uses well-known multicast: 01:80:C2:00:00:14 (L1) or 01:80:C2:00:00:15 (L2)
    let length_offset = push_ethernet_llc_isis(
        &mut pkt,
        [0x01, 0x80, 0xC2, 0x00, 0x00, 0x14],
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    );
    push_isis_l1_lan_iih(&mut pkt);
    fixup_802_3_length(&mut pkt, length_offset);

    let mut buf = DissectBuffer::new();
    registry
        .dissect(&pkt, &mut buf)
        .expect("dissect must succeed");
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers().len(), 2);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "ISIS");

    let isis = buf.layer_by_name("ISIS").unwrap();
    assert_eq!(display_name_for(&buf, isis, "pdu_type"), Some("L1 LAN IIH"));
    assert_eq!(
        buf.field_by_name(isis, "source_id").unwrap().value,
        FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    );
    assert_eq!(
        buf.field_by_name(isis, "holding_time").unwrap().value,
        FieldValue::U16(30)
    );
    assert_eq!(
        buf.field_by_name(isis, "priority").unwrap().value,
        FieldValue::U8(64)
    );

    // Verify TLVs were parsed
    let tlvs = buf.field_by_name(isis, "tlvs").unwrap();
    if let FieldValue::Array(ref arr) = tlvs.value {
        assert_eq!(direct_children(&buf, arr).len(), 3);
    } else {
        panic!("expected Array for tlvs");
    }
}

// ---------------------------------------------------------------------------
// BGP
// ---------------------------------------------------------------------------

/// Push a BGP KEEPALIVE message (19 bytes).
fn push_bgp_keepalive(pkt: &mut Vec<u8>) {
    pkt.extend_from_slice(&[0xFF; 16]); // Marker
    pkt.extend_from_slice(&19u16.to_be_bytes()); // Length
    pkt.push(4); // Type = KEEPALIVE
}

/// Push a BGP OPEN message with no optional parameters.
fn push_bgp_open(pkt: &mut Vec<u8>, my_as: u16, hold_time: u16, bgp_id: [u8; 4]) {
    pkt.extend_from_slice(&[0xFF; 16]); // Marker
    pkt.extend_from_slice(&29u16.to_be_bytes()); // Length
    pkt.push(1); // Type = OPEN
    pkt.push(4); // Version
    pkt.extend_from_slice(&my_as.to_be_bytes());
    pkt.extend_from_slice(&hold_time.to_be_bytes());
    pkt.extend_from_slice(&bgp_id);
    pkt.push(0); // Opt Params Len = 0
}

#[test]
fn ethernet_ipv4_tcp_bgp_keepalive() {
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]); // TCP
    push_tcp(&mut pkt, 12345, 179, 0x18); // PSH+ACK
    push_bgp_keepalive(&mut pkt);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4); // Ethernet, IPv4, TCP, BGP
    assert_layers_contiguous(&buf);

    let bgp = buf.layer_by_name("BGP").unwrap();
    assert_eq!(
        buf.field_by_name(bgp, "type").unwrap().value,
        FieldValue::U8(4)
    );
    assert_eq!(display_name_for(&buf, bgp, "type"), Some("KEEPALIVE"));
    assert_eq!(
        buf.field_by_name(bgp, "length").unwrap().value,
        FieldValue::U16(19)
    );
}

#[test]
fn ethernet_ipv4_tcp_bgp_open() {
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]);
    push_tcp(&mut pkt, 179, 54321, 0x18);
    push_bgp_open(&mut pkt, 65001, 180, [10, 0, 0, 1]);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);

    let bgp = buf.layer_by_name("BGP").unwrap();
    assert_eq!(display_name_for(&buf, bgp, "type"), Some("OPEN"));
    assert_eq!(
        buf.field_by_name(bgp, "version").unwrap().value,
        FieldValue::U8(4)
    );
    assert_eq!(
        buf.field_by_name(bgp, "my_as").unwrap().value,
        FieldValue::U16(65001)
    );
    assert_eq!(
        buf.field_by_name(bgp, "hold_time").unwrap().value,
        FieldValue::U16(180)
    );
    assert_eq!(
        buf.field_by_name(bgp, "bgp_identifier").unwrap().value,
        FieldValue::Ipv4Addr([10, 0, 0, 1])
    );
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

/// Push a TLS record: [content_type(1), version(2), length(2), payload...]
fn push_tls_record(pkt: &mut Vec<u8>, content_type: u8, version: u16, payload: &[u8]) {
    pkt.push(content_type);
    pkt.extend_from_slice(&version.to_be_bytes());
    pkt.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    pkt.extend_from_slice(payload);
}

#[test]
fn ethernet_ipv4_tcp_tls_client_hello() {
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]); // TCP
    push_tcp(&mut pkt, 49152, 443, 0x18); // PSH+ACK → port 443

    // Build a realistic ClientHello body with SNI extension
    let mut ch_body = Vec::new();
    ch_body.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2
    ch_body.extend_from_slice(&[0xaa; 32]); // random
    ch_body.push(0x00); // session_id_len = 0
    ch_body.extend_from_slice(&[0x00, 0x04]); // cipher_suites_len = 4
    ch_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    ch_body.extend_from_slice(&[0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ch_body.push(0x01); // compression_methods_len = 1
    ch_body.push(0x00); // null compression
    // SNI extension for "example.com"
    let hostname = b"example.com";
    let sni_list_len = (1 + 2 + hostname.len()) as u16;
    let sni_ext_len = 2 + sni_list_len;
    let ext_total_len = 4 + sni_ext_len;
    ch_body.extend_from_slice(&ext_total_len.to_be_bytes()); // extensions_len
    ch_body.extend_from_slice(&[0x00, 0x00]); // ext_type = server_name(0)
    ch_body.extend_from_slice(&sni_ext_len.to_be_bytes()); // ext_data_len
    ch_body.extend_from_slice(&sni_list_len.to_be_bytes()); // server_name_list_len
    ch_body.push(0x00); // name_type = host_name(0)
    ch_body.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
    ch_body.extend_from_slice(hostname);

    // Wrap in handshake header
    let ch_len = ch_body.len() as u32;
    let mut hs = vec![0x01]; // HandshakeType = ClientHello(1)
    hs.push((ch_len >> 16) as u8);
    hs.push((ch_len >> 8) as u8);
    hs.push(ch_len as u8);
    hs.extend_from_slice(&ch_body);
    push_tls_record(&mut pkt, 0x16, 0x0301, &hs);

    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4); // Ethernet, IPv4, TCP, TLS
    assert_layers_contiguous(&buf);

    let tls = buf.layer_by_name("TLS").unwrap();
    assert_eq!(
        buf.field_by_name(tls, "content_type").unwrap().value,
        FieldValue::U8(22)
    );
    assert_eq!(
        display_name_for(&buf, tls, "content_type"),
        Some("Handshake")
    );
    assert_eq!(
        buf.field_by_name(tls, "version").unwrap().value,
        FieldValue::U16(0x0301)
    );
    assert_eq!(display_name_for(&buf, tls, "version"), Some("TLS 1.0"));
    assert_eq!(
        buf.field_by_name(tls, "handshake_type").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        display_name_for(&buf, tls, "handshake_type"),
        Some("Client Hello")
    );
    // ClientHello body fields
    assert_eq!(
        buf.field_by_name(tls, "handshake_version").unwrap().value,
        FieldValue::U16(0x0303)
    );
    let FieldValue::Array(ref suites_range) =
        buf.field_by_name(tls, "cipher_suites").unwrap().value
    else {
        panic!("expected Array")
    };
    let suites = buf.nested_fields(suites_range);
    assert_eq!(suites.len(), 2);
    assert_eq!(suites[0].value, FieldValue::U16(0x1301));
    assert_eq!(suites[1].value, FieldValue::U16(0xc02f));
    // SNI extension
    let FieldValue::Array(ref exts_range) = buf.field_by_name(tls, "extensions").unwrap().value
    else {
        panic!("expected Array")
    };
    let exts = direct_children(&buf, exts_range);
    assert_eq!(exts.len(), 1);
    let FieldValue::Object(ref sni_obj_range) = exts[0].value else {
        panic!("expected Object")
    };
    let sni_obj = buf.nested_fields(sni_obj_range);
    let sni_field = sni_obj.iter().find(|f| f.name() == "server_name").unwrap();
    assert_eq!(sni_field.value, FieldValue::Bytes(b"example.com"));
}

#[test]
fn ethernet_ipv4_tcp_tls_server_hello() {
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 6, [10, 0, 0, 2], [10, 0, 0, 1]);
    push_tcp(&mut pkt, 443, 49152, 0x18);

    // Build ServerHello body (no extensions)
    let mut sh_body = Vec::new();
    sh_body.extend_from_slice(&[0x03, 0x03]); // server_version = TLS 1.2
    sh_body.extend_from_slice(&[0xbb; 32]); // random
    sh_body.push(0x00); // session_id_len = 0
    sh_body.extend_from_slice(&[0x13, 0x01]); // cipher_suite = TLS_AES_128_GCM_SHA256
    sh_body.push(0x00); // compression_method = null

    let sh_len = sh_body.len() as u32;
    let mut hs = vec![0x02]; // HandshakeType = ServerHello(2)
    hs.push((sh_len >> 16) as u8);
    hs.push((sh_len >> 8) as u8);
    hs.push(sh_len as u8);
    hs.extend_from_slice(&sh_body);
    push_tls_record(&mut pkt, 0x16, 0x0303, &hs);

    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);

    let tls = buf.layer_by_name("TLS").unwrap();
    assert_eq!(
        buf.field_by_name(tls, "handshake_type").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        display_name_for(&buf, tls, "handshake_type"),
        Some("Server Hello")
    );
    assert_eq!(
        buf.field_by_name(tls, "cipher_suite").unwrap().value,
        FieldValue::U16(0x1301)
    );
    assert_eq!(
        display_name_for(&buf, tls, "cipher_suite"),
        Some("TLS_AES_128_GCM_SHA256")
    );
}

#[test]
fn ethernet_ipv4_tcp_tls_alert() {
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]);
    push_tcp(&mut pkt, 443, 49152, 0x18);

    // TLS alert record: fatal(2) handshake_failure(40)
    push_tls_record(&mut pkt, 0x15, 0x0303, &[0x02, 0x28]);

    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);

    let tls = buf.layer_by_name("TLS").unwrap();
    assert_eq!(display_name_for(&buf, tls, "content_type"), Some("Alert"));
    assert_eq!(display_name_for(&buf, tls, "alert_level"), Some("fatal"));
    assert_eq!(
        display_name_for(&buf, tls, "alert_description"),
        Some("handshake_failure")
    );
}

// ---------------------------------------------------------------------------
// L2TP
// ---------------------------------------------------------------------------

/// Push an L2TP data message header (minimal: T=0, L=0, S=0, O=0, Ver=2).
fn push_l2tp_data(pkt: &mut Vec<u8>, tunnel_id: u16, session_id: u16) {
    // Flags/Version: T=0, L=0, S=0, O=0, P=0, Ver=2
    pkt.extend_from_slice(&[0x00, 0x02]);
    pkt.extend_from_slice(&tunnel_id.to_be_bytes());
    pkt.extend_from_slice(&session_id.to_be_bytes());
}

/// Push an L2TP data message header with L bit (T=0, L=1, S=0, O=0, Ver=2).
/// Returns the start index for length fixup via [`fixup_l2tp_length`].
fn push_l2tp_data_with_length(pkt: &mut Vec<u8>, tunnel_id: u16, session_id: u16) -> usize {
    let start = pkt.len();
    // Flags/Version: T=0, L=1, S=0, O=0, P=0, Ver=2
    pkt.extend_from_slice(&[0x40, 0x02]);
    pkt.extend_from_slice(&[0x00, 0x00]); // Length placeholder
    pkt.extend_from_slice(&tunnel_id.to_be_bytes());
    pkt.extend_from_slice(&session_id.to_be_bytes());
    start
}

/// Push an L2TP control message header (T=1, L=1, S=1, O=0, P=0, Ver=2).
/// Returns the start index for length fixup.
fn push_l2tp_control(
    pkt: &mut Vec<u8>,
    tunnel_id: u16,
    session_id: u16,
    ns: u16,
    nr: u16,
) -> usize {
    let start = pkt.len();
    // Flags/Version: T=1, L=1, S=1, O=0, P=0, Ver=2
    pkt.extend_from_slice(&[0xC8, 0x02]);
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Length (placeholder)
    pkt.extend_from_slice(&tunnel_id.to_be_bytes());
    pkt.extend_from_slice(&session_id.to_be_bytes());
    pkt.extend_from_slice(&ns.to_be_bytes());
    pkt.extend_from_slice(&nr.to_be_bytes());
    start
}

/// Fix L2TP control message Length field after payload has been appended.
fn fixup_l2tp_length(pkt: &mut [u8], l2tp_start: usize) {
    let l2tp_len = (pkt.len() - l2tp_start) as u16;
    pkt[l2tp_start + 2..l2tp_start + 4].copy_from_slice(&l2tp_len.to_be_bytes());
}

#[test]
fn ethernet_ipv4_udp_l2tp_ppp_ipv4_udp() {
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 1701, 1701);
    push_l2tp_data(&mut pkt, 42, 7);
    // PPP frame (HDLC framing): Address=0xFF, Control=0x03, Protocol=0x0021 (IPv4)
    pkt.extend_from_slice(&[0xFF, 0x03, 0x00, 0x21]);
    // Inner IPv4 + UDP
    let inner_ip_start = pkt.len();
    push_ipv4(&mut pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);
    let inner_udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, inner_udp_start);
    fixup_ipv4_length(&mut pkt, inner_ip_start);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    // Ethernet, IPv4, UDP, L2TP, PPP, IPv4, UDP
    assert_eq!(buf.layers().len(), 7);
    assert_layers_contiguous(&buf);

    let l2tp = buf.layer_by_name("L2TP").unwrap();
    assert_eq!(
        buf.field_by_name(l2tp, "is_control").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "tunnel_id").unwrap().value,
        FieldValue::U16(42)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "session_id").unwrap().value,
        FieldValue::U16(7)
    );

    let ppp = buf.layer_by_name("PPP").unwrap();
    assert_eq!(
        buf.field_by_name(ppp, "address").unwrap().value,
        FieldValue::U8(0xFF)
    );
    assert_eq!(
        buf.field_by_name(ppp, "control").unwrap().value,
        FieldValue::U8(0x03)
    );
    assert_eq!(
        buf.field_by_name(ppp, "protocol").unwrap().value,
        FieldValue::U16(0x0021)
    );
}

/// L2TP data message with L bit set: the embedded_payload mechanism bounds
/// the PPP input to the L2TP Length field, ignoring trailing bytes.
#[test]
fn ethernet_ipv4_udp_l2tp_length_ppp_ipv4_udp() {
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 1701, 1701);
    let l2tp_start = push_l2tp_data_with_length(&mut pkt, 42, 7);
    // PPP frame (HDLC framing): Address=0xFF, Control=0x03, Protocol=0x0021 (IPv4)
    pkt.extend_from_slice(&[0xFF, 0x03, 0x00, 0x21]);
    // Inner IPv4 + UDP
    let inner_ip_start = pkt.len();
    push_ipv4(&mut pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);
    let inner_udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, inner_udp_start);
    fixup_ipv4_length(&mut pkt, inner_ip_start);
    fixup_l2tp_length(&mut pkt, l2tp_start);
    // Append trailing bytes that must NOT be parsed as PPP
    pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    // Ethernet, IPv4, UDP, L2TP, PPP, IPv4, UDP
    assert_eq!(buf.layers().len(), 7);

    let l2tp = buf.layer_by_name("L2TP").unwrap();
    assert_eq!(
        buf.field_by_name(l2tp, "is_control").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "length_present").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "tunnel_id").unwrap().value,
        FieldValue::U16(42)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "session_id").unwrap().value,
        FieldValue::U16(7)
    );

    let ppp = buf.layer_by_name("PPP").unwrap();
    assert_eq!(
        buf.field_by_name(ppp, "address").unwrap().value,
        FieldValue::U8(0xFF)
    );
    assert_eq!(
        buf.field_by_name(ppp, "control").unwrap().value,
        FieldValue::U8(0x03)
    );
    assert_eq!(
        buf.field_by_name(ppp, "protocol").unwrap().value,
        FieldValue::U16(0x0021)
    );
}

#[test]
fn ethernet_ipv4_udp_l2tp_control() {
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 1701, 1701);
    let l2tp_start = push_l2tp_control(&mut pkt, 100, 0, 1, 0);
    fixup_l2tp_length(&mut pkt, l2tp_start);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4); // Ethernet, IPv4, UDP, L2TP
    assert_layers_contiguous(&buf);

    let l2tp = buf.layer_by_name("L2TP").unwrap();
    assert_eq!(
        buf.field_by_name(l2tp, "is_control").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "tunnel_id").unwrap().value,
        FieldValue::U16(100)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "session_id").unwrap().value,
        FieldValue::U16(0)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "ns").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "nr").unwrap().value,
        FieldValue::U16(0)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "length").unwrap().value,
        FieldValue::U16(12)
    );
}

// ---------------------------------------------------------------------------
// L2TPv3 tests
// ---------------------------------------------------------------------------

/// Push an L2TPv3 over IP control header (16 bytes): 4 zero bytes + flags/version + length + CCID + Ns + Nr.
fn push_l2tpv3_ip_control(pkt: &mut Vec<u8>, length: u16, ccid: u32, ns: u16, nr: u16) {
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Session ID = 0
    pkt.extend_from_slice(&[0xC8, 0x03]); // T=1, L=1, S=1, Ver=3
    pkt.extend_from_slice(&length.to_be_bytes());
    pkt.extend_from_slice(&ccid.to_be_bytes());
    pkt.extend_from_slice(&ns.to_be_bytes());
    pkt.extend_from_slice(&nr.to_be_bytes());
}

/// Push an L2TPv3 AVP.
fn push_l2tpv3_avp(
    pkt: &mut Vec<u8>,
    mandatory: bool,
    vendor_id: u16,
    attr_type: u16,
    value: &[u8],
) {
    let length = 6 + value.len();
    let first_word = if mandatory { 0x8000 } else { 0x0000 } | (length as u16 & 0x03FF);
    pkt.extend_from_slice(&first_word.to_be_bytes());
    pkt.extend_from_slice(&vendor_id.to_be_bytes());
    pkt.extend_from_slice(&attr_type.to_be_bytes());
    pkt.extend_from_slice(value);
}

/// Push an L2TPv3 over UDP control header (12 bytes): flags/version + length + CCID + Ns + Nr.
fn push_l2tpv3_udp_control(pkt: &mut Vec<u8>, length: u16, ccid: u32, ns: u16, nr: u16) {
    pkt.extend_from_slice(&[0xC8, 0x03]); // T=1, L=1, S=1, Ver=3
    pkt.extend_from_slice(&length.to_be_bytes());
    pkt.extend_from_slice(&ccid.to_be_bytes());
    pkt.extend_from_slice(&ns.to_be_bytes());
    pkt.extend_from_slice(&nr.to_be_bytes());
}

/// Ethernet → IPv4 → L2TPv3 (IP, data message)
#[test]
fn integration_ethernet_ipv4_l2tpv3_ip_data() {
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 115, [10, 0, 0, 1], [10, 0, 0, 2]); // protocol=115 (L2TP)
    // L2TPv3 data: Session ID = 0x00001234
    pkt.extend_from_slice(&[0x00, 0x00, 0x12, 0x34]);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 3);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "L2TPv3");
    assert_layers_contiguous(&buf);

    let l2tp = buf.layer_by_name("L2TPv3").unwrap();
    assert_eq!(
        buf.field_by_name(l2tp, "session_id").unwrap().value,
        FieldValue::U32(0x00001234)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "is_control").unwrap().value,
        FieldValue::U8(0)
    );
}

/// Ethernet → IPv4 → L2TPv3 (IP, control SCCRQ)
#[test]
fn integration_ethernet_ipv4_l2tpv3_ip_control() {
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 115, [10, 0, 0, 1], [10, 0, 0, 2]);
    // L2TPv3 control: length=20 (12 header + 8 AVP)
    push_l2tpv3_ip_control(&mut pkt, 20, 0x0001, 0, 0);
    // Message Type AVP: SCCRQ (1)
    push_l2tpv3_avp(&mut pkt, true, 0, 0, &[0x00, 0x01]);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers().len(), 3);
    assert_eq!(buf.layers()[2].name, "L2TPv3");

    let l2tp = buf.layer_by_name("L2TPv3").unwrap();
    assert_eq!(
        buf.field_by_name(l2tp, "is_control").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "version").unwrap().value,
        FieldValue::U8(3)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "message_type").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(display_name_for(&buf, l2tp, "message_type"), Some("SCCRQ"));
}

/// Ethernet → IPv4 → UDP → L2TPv3-UDP (control SCCRP)
#[test]
fn integration_ethernet_ipv4_udp_l2tpv3_control() {
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 1701, 1701);
    // L2TPv3-UDP control: length=20 (12 header + 8 AVP)
    push_l2tpv3_udp_control(&mut pkt, 20, 0x0002, 1, 0);
    // Message Type AVP: SCCRP (2)
    push_l2tpv3_avp(&mut pkt, true, 0, 0, &[0x00, 0x02]);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "L2TPv3-UDP");
    assert_layers_contiguous(&buf);

    let l2tp = buf.layer_by_name("L2TPv3-UDP").unwrap();
    assert_eq!(
        buf.field_by_name(l2tp, "t_bit").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "version").unwrap().value,
        FieldValue::U8(3)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "message_type").unwrap().value,
        FieldValue::U16(2)
    );
    assert_eq!(display_name_for(&buf, l2tp, "message_type"), Some("SCCRP"));
}

/// Ethernet → IPv4 → UDP → L2TPv3-UDP (data message)
#[test]
fn integration_ethernet_ipv4_udp_l2tpv3_data() {
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 1701, 1701);
    // L2TPv3-UDP data: T=0, Ver=3, Reserved=0, Session ID=0xABCD0001
    pkt.extend_from_slice(&[0x00, 0x03]); // T=0, Ver=3
    pkt.extend_from_slice(&[0x00, 0x00]); // Reserved
    pkt.extend_from_slice(&[0xAB, 0xCD, 0x00, 0x01]); // Session ID
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[3].name, "L2TPv3-UDP");
    assert_layers_contiguous(&buf);

    let l2tp = buf.layer_by_name("L2TPv3-UDP").unwrap();
    assert_eq!(
        buf.field_by_name(l2tp, "t_bit").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(l2tp, "session_id").unwrap().value,
        FieldValue::U32(0xABCD0001)
    );
}

// ---------------------------------------------------------------------------
// PPP → IPv4 → UDP (via link_type=9, LINKTYPE_PPP)
// ---------------------------------------------------------------------------

#[test]
fn integration_ppp_ipv4_udp() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // PPP frame with HDLC framing: Address=0xFF, Control=0x03, Protocol=0x0021 (IPv4)
    pkt.extend_from_slice(&[0xFF, 0x03, 0x00, 0x21]);

    let ipv4_start = pkt.len();
    push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    // LINKTYPE_PPP = 9
    let mut buf = DissectBuffer::new();
    registry.dissect_with_link_type(&pkt, 9, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 3);
    assert_eq!(buf.layers()[0].name, "PPP");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_layers_contiguous(&buf);

    let ppp = buf.layer_by_name("PPP").unwrap();
    assert_eq!(
        buf.field_by_name(ppp, "address").unwrap().value,
        FieldValue::U8(0xFF)
    );
    assert_eq!(
        buf.field_by_name(ppp, "control").unwrap().value,
        FieldValue::U8(0x03)
    );
    assert_eq!(
        buf.field_by_name(ppp, "protocol").unwrap().value,
        FieldValue::U16(0x0021)
    );
    let proto_field = buf.field_by_name(ppp, "protocol").unwrap();
    let display =
        proto_field.descriptor.display_fn.unwrap()(&proto_field.value, buf.layer_fields(ppp));
    assert_eq!(display, Some("IPv4"));
}

// ---------------------------------------------------------------------------
// PPP → LCP (via link_type=50, no HDLC, control protocol inline)
// ---------------------------------------------------------------------------

#[test]
fn integration_ppp_lcp_inline() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // PPP frame without HDLC framing: Protocol=0xC021 (LCP)
    pkt.extend_from_slice(&[0xC0, 0x21]);

    // LCP Configure-Request with MRU option
    #[rustfmt::skip]
    pkt.extend_from_slice(&[
        0x01, 0x01, 0x00, 0x08, // Code=1 (Configure-Request), Id=1, Len=8
        1, 4, 0x05, 0xDC,       // MRU=1500
    ]);

    // LINKTYPE_PPP_ETHER = 50
    let mut buf = DissectBuffer::new();
    registry.dissect_with_link_type(&pkt, 50, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 1); // PPP only (LCP parsed inline)
    assert_eq!(buf.layers()[0].name, "PPP");
    assert_layers_contiguous(&buf);

    let ppp = buf.layer_by_name("PPP").unwrap();
    assert_eq!(
        buf.field_by_name(ppp, "protocol").unwrap().value,
        FieldValue::U16(0xC021)
    );
    let proto_field = buf.field_by_name(ppp, "protocol").unwrap();
    let display =
        proto_field.descriptor.display_fn.unwrap()(&proto_field.value, buf.layer_fields(ppp));
    assert_eq!(display, Some("LCP"));
    // payload field contains the parsed LCP Object
    assert!(matches!(
        buf.field_by_name(ppp, "payload").unwrap().value,
        FieldValue::Object(_)
    ));
}

// ===========================================================================
// IPsec: AH, ESP, IKE
// ===========================================================================

/// Ethernet → IPv4 → AH → (TCP payload)
///
/// Verifies AH dissection with 12-byte ICV followed by next protocol dispatch.
#[test]
fn integration_ethernet_ipv4_ah_tcp() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // Ethernet
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);

    // IPv4 with protocol=51 (AH)
    let ipv4_start = push_ipv4(&mut pkt, 51, [10, 0, 0, 1], [10, 0, 0, 2]);

    // AH header: payload_len=4 → total = (4+2)*4 = 24 bytes (12 bytes ICV)
    pkt.push(6); // Next Header: TCP
    pkt.push(4); // Payload Length
    pkt.extend_from_slice(&[0x00, 0x00]); // Reserved
    pkt.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // SPI
    pkt.extend_from_slice(&1u32.to_be_bytes()); // Sequence Number
    pkt.extend_from_slice(&[0xAA; 12]); // ICV (12 bytes)

    // TCP header (SYN)
    push_tcp(&mut pkt, 12345, 80, 0x02);

    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4); // Ethernet, IPv4, AH, TCP
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "AH");
    assert_eq!(buf.layers()[3].name, "TCP");

    let ah = buf.layer_by_name("AH").unwrap();
    assert_eq!(
        buf.field_by_name(ah, "spi").unwrap().value,
        FieldValue::U32(0xDEAD_BEEF)
    );
    assert_eq!(
        buf.field_by_name(ah, "sequence_number").unwrap().value,
        FieldValue::U32(1)
    );
    assert_eq!(
        buf.resolve_display_name(ah, "next_header_name"),
        Some("TCP")
    );
    assert_eq!(
        buf.field_by_name(ah, "icv").unwrap().value,
        FieldValue::Bytes(&[0xAA; 12])
    );

    assert_layers_contiguous(&buf);
}

/// Ethernet → IPv4 → ESP
///
/// Verifies ESP dissection (SPI + Seq + encrypted data, no further dispatch).
/// The final byte 0xEE (238) is not a known IP protocol, so the NULL
/// decryption heuristic does not match and the payload is displayed as
/// opaque encrypted_data.
#[test]
fn integration_ethernet_ipv4_esp() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);

    let ipv4_start = push_ipv4(&mut pkt, 50, [10, 0, 0, 1], [10, 0, 0, 2]);

    // ESP header + encrypted data
    pkt.extend_from_slice(&0x0000_1001u32.to_be_bytes()); // SPI
    pkt.extend_from_slice(&5u32.to_be_bytes()); // Sequence Number
    pkt.extend_from_slice(&[0xEE; 32]); // Encrypted data

    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 3); // Ethernet, IPv4, ESP
    assert_eq!(buf.layers()[2].name, "ESP");

    let esp = buf.layer_by_name("ESP").unwrap();
    assert_eq!(
        buf.field_by_name(esp, "spi").unwrap().value,
        FieldValue::U32(0x0000_1001)
    );
    assert_eq!(
        buf.field_by_name(esp, "sequence_number").unwrap().value,
        FieldValue::U32(5)
    );
    assert_eq!(
        buf.field_by_name(esp, "encrypted_data").unwrap().value,
        FieldValue::Bytes(&[0xEE; 32])
    );

    assert_layers_contiguous(&buf);
}

/// Ethernet → IPv4 → ESP (NULL, tunnel mode) → IPv4 → UDP
///
/// Verifies automatic NULL encryption decoding for ESP tunnel mode when no SA
/// is configured. The ESP trailer's next_header=4 indicates an encapsulated
/// IPv4 packet, so the heuristic chains into the inner IPv4 and UDP
/// dissectors.
#[test]
fn integration_ethernet_ipv4_esp_null_ipv4_udp() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let outer_ipv4_start = push_ipv4(&mut pkt, 50, [10, 0, 0, 1], [10, 0, 0, 2]);

    // ESP header
    pkt.extend_from_slice(&0x0000_2001u32.to_be_bytes()); // SPI
    pkt.extend_from_slice(&1u32.to_be_bytes()); // Sequence Number

    // Inner IPv4 + UDP packet (plaintext — NULL encryption).
    // Ports are chosen to avoid any application-layer dispatch so the
    // dissection chain stops cleanly at UDP.
    let inner_ipv4_start = push_ipv4(&mut pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);
    let inner_udp_start = push_udp(&mut pkt, 12345, 54321);
    pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // UDP payload
    fixup_udp_length(&mut pkt, inner_udp_start);
    fixup_ipv4_length(&mut pkt, inner_ipv4_start);

    // ESP trailer: pad_length=0, next_header=4 (IPv4-in-IPv4)
    pkt.push(0x00); // pad_length
    pkt.push(0x04); // next_header = IPv4

    fixup_ipv4_length(&mut pkt, outer_ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Ethernet, outer IPv4, ESP, inner IPv4, UDP
    assert_eq!(buf.layers().len(), 5);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "ESP");
    assert_eq!(buf.layers()[3].name, "IPv4");
    assert_eq!(buf.layers()[4].name, "UDP");

    let esp = &buf.layers()[2];
    assert_eq!(
        buf.field_by_name(esp, "spi").unwrap().value,
        FieldValue::U32(0x0000_2001)
    );
    assert_eq!(
        buf.field_by_name(esp, "sequence_number").unwrap().value,
        FieldValue::U32(1)
    );
    assert_eq!(
        buf.field_by_name(esp, "next_header").unwrap().value,
        FieldValue::U8(4)
    );
    assert_eq!(
        buf.field_by_name(esp, "pad_length").unwrap().value,
        FieldValue::U8(0)
    );
    // encrypted_data must not be present when the heuristic succeeded.
    assert!(buf.field_by_name(esp, "encrypted_data").is_none());

    // Inner UDP ports are visible.
    let udp = &buf.layers()[4];
    assert_eq!(
        buf.field_by_name(udp, "src_port").unwrap().value,
        FieldValue::U16(12345)
    );
    assert_eq!(
        buf.field_by_name(udp, "dst_port").unwrap().value,
        FieldValue::U16(54321)
    );
}

/// Ethernet → IPv4 → ESP (NULL, transport mode) → UDP
///
/// Verifies automatic NULL encryption decoding for ESP transport mode when
/// no SA is configured. Unlike tunnel mode, the ESP payload directly
/// contains an upper-layer protocol (here UDP) without an inner IP header;
/// the ESP trailer's next_header=17 indicates the upper-layer protocol.
#[test]
fn integration_ethernet_ipv4_esp_null_transport_udp() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ipv4_start = push_ipv4(&mut pkt, 50, [10, 0, 0, 1], [10, 0, 0, 2]);

    // ESP header
    pkt.extend_from_slice(&0x0000_3003u32.to_be_bytes()); // SPI
    pkt.extend_from_slice(&7u32.to_be_bytes()); // Sequence Number

    // Inner UDP packet directly (transport mode — no inner IP header).
    let udp_start = push_udp(&mut pkt, 10000, 20000);
    pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // UDP payload
    fixup_udp_length(&mut pkt, udp_start);

    // ESP trailer: pad_length=0, next_header=17 (UDP)
    pkt.push(0x00);
    pkt.push(0x11);

    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Ethernet, IPv4, ESP, UDP (no inner IP layer)
    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[2].name, "ESP");
    assert_eq!(buf.layers()[3].name, "UDP");

    let esp = &buf.layers()[2];
    assert_eq!(
        buf.field_by_name(esp, "next_header").unwrap().value,
        FieldValue::U8(17)
    );
    assert!(buf.field_by_name(esp, "encrypted_data").is_none());

    let udp = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(udp, "src_port").unwrap().value,
        FieldValue::U16(10000)
    );
    assert_eq!(
        buf.field_by_name(udp, "dst_port").unwrap().value,
        FieldValue::U16(20000)
    );
}

/// Ethernet → IPv4 → UDP(500) → IKEv2 IKE_SA_INIT
///
/// Verifies IKE dissection through the full stack.
#[test]
fn integration_ethernet_ipv4_udp_ike_sa_init() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);

    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 500, 500);

    // IKE header (28 bytes)
    pkt.extend_from_slice(&[0x01; 8]); // Initiator SPI
    pkt.extend_from_slice(&[0x00; 8]); // Responder SPI
    pkt.push(33); // Next Payload: SA
    pkt.push(0x20); // Version: Major=2, Minor=0
    pkt.push(34); // Exchange Type: IKE_SA_INIT
    pkt.push(0x08); // Flags: Initiator
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Message ID
    pkt.extend_from_slice(&36u32.to_be_bytes()); // Length: 28 + 8 (1 payload)

    // SA Payload (8 bytes): next=0, critical=0, length=8, data=[0xAA; 4]
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x08, 0xAA, 0xAA, 0xAA, 0xAA]);

    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4); // Ethernet, IPv4, UDP, IKE
    assert_eq!(buf.layers()[3].name, "IKE");

    let ike = buf.layer_by_name("IKE").unwrap();
    assert_eq!(
        buf.field_by_name(ike, "initiator_spi").unwrap().value,
        FieldValue::Bytes(&[0x01; 8])
    );
    assert_eq!(
        buf.field_by_name(ike, "major_version").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        display_name_for(&buf, ike, "exchange_type"),
        Some("IKE_SA_INIT")
    );
    assert_eq!(
        buf.field_by_name(ike, "flag_initiator").unwrap().value,
        FieldValue::U8(1)
    );

    // Verify payload chain
    if let FieldValue::Array(ref payloads) = buf.field_by_name(ike, "payloads").unwrap().value {
        assert_eq!(direct_children(&buf, payloads).len(), 1);
    } else {
        panic!("expected Array for payloads");
    }

    assert_layers_contiguous(&buf);
}

/// Ethernet → IPv4 → UDP → RTP (programmatic registration, no well-known port).
#[test]
fn integration_ethernet_ipv4_udp_rtp() {
    let mut reg = DissectorRegistry::default();

    // RTP has no well-known port; register on an arbitrary port for this test.
    #[cfg(feature = "rtp")]
    #[cfg(feature = "udp")]
    reg.register_by_udp_port(5004, Box::new(packet_dissector_rtp::RtpDissector))
        .expect("test registration must succeed");

    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 5004, 5004);

    // RTP header: V=2, P=0, X=0, CC=0, M=1, PT=111, seq=1000
    pkt.push(0x80); // V=2, P=0, X=0, CC=0
    pkt.push(0x80 | 111); // M=1, PT=111
    pkt.extend_from_slice(&1000u16.to_be_bytes()); // seq=1000
    pkt.extend_from_slice(&160_000u32.to_be_bytes()); // timestamp
    pkt.extend_from_slice(&0x12345678u32.to_be_bytes()); // SSRC

    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);

    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "RTP");

    let rtp = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(rtp, "version").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(rtp, "marker").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(rtp, "payload_type").unwrap().value,
        FieldValue::U8(111)
    );
    assert_eq!(
        buf.field_by_name(rtp, "sequence_number").unwrap().value,
        FieldValue::U16(1000)
    );
    assert_eq!(
        buf.field_by_name(rtp, "timestamp").unwrap().value,
        FieldValue::U32(160_000)
    );
    assert_eq!(
        buf.field_by_name(rtp, "ssrc").unwrap().value,
        FieldValue::U32(0x12345678)
    );
}

// ---------------------------------------------------------------------------
// Ethernet → IPv4 → UDP → mDNS
// ---------------------------------------------------------------------------

fn build_eth_ipv4_udp_mdns_query() -> Vec<u8> {
    let mut pkt = Vec::new();
    // mDNS multicast: dst 224.0.0.251, src 192.168.1.100
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 17, IPV4_SRC, [224, 0, 0, 251]);
    let udp_start = push_udp(&mut pkt, 5353, 5353);
    push_dns_query(&mut pkt, 0x0000); // mDNS typically uses txid=0
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ip_start);
    pkt
}

#[test]
fn integration_ethernet_ipv4_udp_mdns() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv4_udp_mdns_query();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "mDNS");

    assert_layers_contiguous(&buf);

    // Verify mDNS layer fields
    let mdns = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(mdns, "id").unwrap().value,
        FieldValue::U16(0)
    );
    assert_eq!(
        buf.field_by_name(mdns, "qr").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(mdns, "qdcount").unwrap().value,
        FieldValue::U16(1)
    );
}

// ---------------------------------------------------------------------------
// PFCP (3GPP TS 29.244)
// ---------------------------------------------------------------------------

/// PFCP node-related message (S=0, 8-byte header). Returns start index for length fixup.
fn push_pfcp_node_msg(pkt: &mut Vec<u8>, msg_type: u8, seq: u32, ies: &[u8]) -> usize {
    let start = pkt.len();
    let msg_length = (4 + ies.len()) as u16; // Seq(3) + Spare(1) + IEs
    // Octet 1: version=1, Spare=0, Spare=0, FO=0, MP=0, S=0
    pkt.push(0x20);
    // Octet 2: message type
    pkt.push(msg_type);
    // Octets 3-4: message length
    pkt.extend_from_slice(&msg_length.to_be_bytes());
    // Octets 5-7: Sequence Number (24 bits)
    pkt.push(((seq >> 16) & 0xFF) as u8);
    pkt.push(((seq >> 8) & 0xFF) as u8);
    pkt.push((seq & 0xFF) as u8);
    // Octet 8: Spare
    pkt.push(0x00);
    // IEs
    pkt.extend_from_slice(ies);
    start
}

/// PFCP session-related message (S=1, 16-byte header). Returns start index for length fixup.
fn push_pfcp_session_msg(
    pkt: &mut Vec<u8>,
    msg_type: u8,
    seid: u64,
    seq: u32,
    ies: &[u8],
) -> usize {
    let start = pkt.len();
    let msg_length = (12 + ies.len()) as u16; // SEID(8) + Seq(3) + Spare(1) + IEs
    // Octet 1: version=1, Spare=0, Spare=0, FO=0, MP=0, S=1
    pkt.push(0x21);
    // Octet 2: message type
    pkt.push(msg_type);
    // Octets 3-4: message length
    pkt.extend_from_slice(&msg_length.to_be_bytes());
    // Octets 5-12: SEID
    pkt.extend_from_slice(&seid.to_be_bytes());
    // Octets 13-15: Sequence Number (24 bits)
    pkt.push(((seq >> 16) & 0xFF) as u8);
    pkt.push(((seq >> 8) & 0xFF) as u8);
    pkt.push((seq & 0xFF) as u8);
    // Octet 16: Spare
    pkt.push(0x00);
    // IEs
    pkt.extend_from_slice(ies);
    start
}

/// Ethernet → IPv4 → UDP → PFCP (Heartbeat Request, S=0)
#[test]
fn integration_ethernet_ipv4_udp_pfcp_heartbeat() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // Recovery Time Stamp IE: type=96, length=4, value=0x12345678
    let recovery_ie: &[u8] = &[0x00, 0x60, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78];

    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 8805, 8805);

    // PFCP Heartbeat Request (type=1, S=0)
    push_pfcp_node_msg(&mut pkt, 1, 0x000001, recovery_ie);

    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "PFCP");

    assert_layers_contiguous(&buf);

    // Verify PFCP fields
    let pfcp = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(pfcp, "version").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(pfcp, "s_flag").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(pfcp, "message_type").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        display_name_for(&buf, pfcp, "message_type"),
        Some("Heartbeat Request")
    );
    assert_eq!(
        buf.field_by_name(pfcp, "sequence_number").unwrap().value,
        FieldValue::U32(1)
    );
    assert!(buf.field_by_name(pfcp, "seid").is_none()); // S=0: no SEID
    assert!(buf.field_by_name(pfcp, "ies").is_some());
}

/// Ethernet → IPv4 → UDP → PFCP (Session Establishment Request, S=1)
#[test]
fn integration_ethernet_ipv4_udp_pfcp_session_establishment() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // Node ID IE (type=60): IPv4 address 10.0.0.1
    let node_id_ie: &[u8] = &[0x00, 0x3C, 0x00, 0x05, 0x00, 10, 0, 0, 1];
    // Recovery Time Stamp IE (type=96): value=0xAABBCCDD
    let recovery_ie: &[u8] = &[0x00, 0x60, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD];

    let mut ies = Vec::new();
    ies.extend_from_slice(node_id_ie);
    ies.extend_from_slice(recovery_ie);

    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 8805, 8805);

    // PFCP Session Establishment Request (type=50, S=1)
    push_pfcp_session_msg(&mut pkt, 50, 0x0000000100000002, 0x000001, &ies);

    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[3].name, "PFCP");

    assert_layers_contiguous(&buf);

    // Verify PFCP fields
    let pfcp = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(pfcp, "version").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(pfcp, "s_flag").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(pfcp, "message_type").unwrap().value,
        FieldValue::U8(50)
    );
    assert_eq!(
        display_name_for(&buf, pfcp, "message_type"),
        Some("Session Establishment Request")
    );
    assert_eq!(
        buf.field_by_name(pfcp, "seid").unwrap().value,
        FieldValue::U64(0x0000000100000002)
    );
    assert_eq!(
        buf.field_by_name(pfcp, "sequence_number").unwrap().value,
        FieldValue::U32(1)
    );
    assert!(buf.field_by_name(pfcp, "ies").is_some());
}

// ---------------------------------------------------------------------------
// SCTP → NGAP (NGSetupRequest)
// ---------------------------------------------------------------------------

/// Minimal NGAP NGSetupRequest payload (APER): initiatingMessage, proc=21,
/// crit=reject, 1 IE (GlobalRANNodeID id=27).
#[cfg(any(
    all(feature = "sctp", feature = "ngap"),
    all(feature = "linux_sll", feature = "sctp", feature = "ngap")
))]
const NGAP_NG_SETUP_REQUEST: &[u8] = &[
    0x00, 0x15, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x00, 0x1a, 0x00, 0x05, 0x00, 0x02, 0xf8, 0x39, 0x10,
];

#[cfg(all(feature = "sctp", feature = "ngap"))]
#[test]
fn integration_ethernet_ipv4_sctp_ngap() {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 132, IPV4_SRC, IPV4_DST);
    push_sctp(&mut pkt, 9487, 38412);
    push_sctp_data_chunk(&mut pkt, 0x03, 1, 60, NGAP_NG_SETUP_REQUEST);
    fixup_ipv4_length(&mut pkt, ip_start);

    let reg = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert!(
        buf.layers().len() >= 4,
        "expected at least 4 layers, got {}",
        buf.layers().len()
    );
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "SCTP");
    assert_eq!(buf.layers()[3].name, "NGAP");

    let ngap = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(ngap, "pdu_type").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        display_name_for(&buf, ngap, "procedure_code"),
        Some("NGSetup")
    );

    let ies = buf.field_by_name(ngap, "ies").unwrap();
    if let FieldValue::Array(ref arr) = ies.value {
        assert_eq!(direct_children(&buf, arr).len(), 1);
    } else {
        panic!("expected ies to be Array");
    }
}

/// NGAP InitialUEMessage with parsed IE values: AMF-UE-NGAP-ID (5 bytes),
/// RAN-UE-NGAP-ID (4 bytes), NAS-PDU with plain 5GMM Registration Request,
/// and RRCEstablishmentCause.
#[cfg(all(feature = "sctp", feature = "ngap"))]
#[test]
fn integration_ngap_ie_parsing_and_nas_pdu() {
    // Build NGAP InitialUEMessage (proc=15) with structured IEs.
    let mut ngap_payload = Vec::new();

    // NGAP-PDU header
    ngap_payload.push(0x00); // initiatingMessage
    ngap_payload.push(0x0F); // procedure code = 15 (InitialUEMessage)
    ngap_payload.push(0x00); // criticality = reject

    // Build ProtocolIE-Container
    let mut container = Vec::new();
    container.push(0x00); // SEQUENCE preamble

    // IE count = 4
    container.push(0x00);
    container.push(0x04);

    // IE 85: RAN-UE-NGAP-ID = 42
    container.extend_from_slice(&[0x00, 0x55]); // id = 85
    container.push(0x00); // criticality = reject
    container.push(0x04); // length = 4
    container.extend_from_slice(&[0x00, 0x00, 0x00, 0x2A]); // value = 42

    // IE 38: NAS-PDU (plain 5GMM Registration Request)
    let nas_bytes = [0x7E, 0x00, 0x41]; // EPD=5GMM, plain, Registration request
    container.extend_from_slice(&[0x00, 0x26]); // id = 38
    container.push(0x00); // criticality = reject
    let nas_aper_len = 1 + nas_bytes.len(); // APER OCTET STRING length byte + NAS data
    container.push(nas_aper_len as u8); // IE value length
    container.push(nas_bytes.len() as u8); // APER OCTET STRING length
    container.extend_from_slice(&nas_bytes);

    // IE 112: UEContextRequest = requested (0)
    container.extend_from_slice(&[0x00, 0x70]); // id = 112
    container.push(0x00); // criticality = reject
    container.push(0x01); // length = 1
    container.push(0x00); // value = 0 (requested)

    // IE 90: RRCEstablishmentCause = mo-Signalling (3)
    container.extend_from_slice(&[0x00, 0x5A]); // id = 90
    container.push(0x00); // criticality = reject
    container.push(0x01); // length = 1
    container.push(0x03); // value = 3 (mo-Signalling)

    // Value length determinant
    if container.len() < 128 {
        ngap_payload.push(container.len() as u8);
    } else {
        let len = container.len() as u16;
        ngap_payload.push(0x80 | ((len >> 8) as u8 & 0x3F));
        ngap_payload.push((len & 0xFF) as u8);
    }
    ngap_payload.extend_from_slice(&container);

    // Build full packet
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 132, IPV4_SRC, IPV4_DST);
    push_sctp(&mut pkt, 9487, 38412);
    push_sctp_data_chunk(&mut pkt, 0x03, 1, 60, &ngap_payload);
    fixup_ipv4_length(&mut pkt, ip_start);

    let reg = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let ngap = &buf.layers()[3];
    assert_eq!(ngap.name, "NGAP");
    assert_eq!(
        display_name_for(&buf, ngap, "procedure_code"),
        Some("InitialUEMessage")
    );

    let ies = buf.field_by_name(ngap, "ies").unwrap();
    if let FieldValue::Array(ref arr) = ies.value {
        let ies_fields = direct_children(&buf, arr);
        assert_eq!(ies_fields.len(), 4);

        // IE 85: RAN-UE-NGAP-ID → parsed as Object with ran_ue_ngap_id=42
        if let FieldValue::Object(ref ie_fields) = ies_fields[0].value {
            let ie_fs = buf.nested_fields(ie_fields);
            let ran_id = ie_fs.iter().find(|f| f.name() == "ran_ue_ngap_id").unwrap();
            assert_eq!(ran_id.value, FieldValue::U32(42));
        }

        // IE 38: NAS-PDU → parsed as Object containing NAS message
        if let FieldValue::Object(ref ie_fields) = ies_fields[1].value {
            let ie_fs = buf.nested_fields(ie_fields);
            let nas_pdu = ie_fs.iter().find(|f| f.name() == "nas_pdu").unwrap();
            if let FieldValue::Object(ref nas_fields) = nas_pdu.value {
                let nf_fs = buf.nested_fields(nas_fields);
                let mt = nf_fs.iter().find(|f| f.name() == "message_type").unwrap();
                assert_eq!(mt.value, FieldValue::U8(0x41));
            } else {
                panic!("expected NAS-PDU to be Object");
            }
        }

        // IE 112: UEContextRequest → parsed as Object with ue_context_request=0
        if let FieldValue::Object(ref ie_fields) = ies_fields[2].value {
            let ie_fs = buf.nested_fields(ie_fields);
            let ucr = ie_fs
                .iter()
                .find(|f| f.name() == "ue_context_request")
                .unwrap();
            assert_eq!(ucr.value, FieldValue::U8(0));
        }

        // IE 90: RRCEstablishmentCause → parsed as Object with rrc_establishment_cause=3
        if let FieldValue::Object(ref ie_fields) = ies_fields[3].value {
            let ie_fs = buf.nested_fields(ie_fields);
            let rrc = ie_fs
                .iter()
                .find(|f| f.name() == "rrc_establishment_cause")
                .unwrap();
            assert_eq!(rrc.value, FieldValue::U8(3));
        }
    } else {
        panic!("expected ies to be Array");
    }
}

#[cfg(all(feature = "linux_sll", feature = "sctp", feature = "ngap"))]
#[test]
fn integration_sll_ipv4_sctp_ngap() {
    let reg = DissectorRegistry::default();

    let mut pkt: Vec<u8> = Vec::new();
    // SLL header (16 bytes)
    pkt.extend_from_slice(&[
        0x00, 0x00, 0x03, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x00,
    ]);
    let ip_start = pkt.len();
    pkt.extend_from_slice(&[
        0x45, 0x02, 0x00, 0x00, 0x00, 0x01, 0x40, 0x00, 0x40, 0x84, 0x00, 0x00, 0x7f, 0x00, 0x00,
        0x01, 0x7f, 0x00, 0x00, 0x01,
    ]);
    push_sctp(&mut pkt, 9487, 38412);
    push_sctp_data_chunk(&mut pkt, 0x03, 1, 60, NGAP_NG_SETUP_REQUEST);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    reg.dissect_with_link_type(&pkt, 113, &mut buf).unwrap();

    let layer_names: Vec<&str> = buf.layers().iter().map(|l| l.name).collect();
    assert!(
        layer_names.contains(&"NGAP"),
        "expected NGAP layer, got: {layer_names:?}"
    );
}

// ---------------------------------------------------------------------------
// QUIC
// ---------------------------------------------------------------------------

/// Encode a QUIC variable-length integer (RFC 9000, Section 16).
fn encode_quic_varint(value: u64) -> Vec<u8> {
    if value <= 63 {
        vec![value as u8]
    } else if value <= 16383 {
        let v = (value as u16) | 0x4000;
        v.to_be_bytes().to_vec()
    } else {
        unreachable!("integration test helper: only small varints needed")
    }
}

#[test]
fn integration_ethernet_ipv4_udp_quic_initial() {
    let reg = DissectorRegistry::default();
    let mut pkt: Vec<u8> = Vec::new();
    push_ethernet(&mut pkt, [0; 6], [0; 6], 0x0800);
    let ip_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 54321, 443);

    // QUIC Initial (long header, packet_type=0, version=1)
    let dcid = [0x01, 0x02, 0x03, 0x04];
    let scid = [0x05, 0x06];
    let payload = [0xAA; 10];
    pkt.push(0xc0); // header_form=1, fixed_bit=1, packet_type=0
    pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // version 1
    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(&dcid);
    pkt.push(scid.len() as u8);
    pkt.extend_from_slice(&scid);
    pkt.extend_from_slice(&encode_quic_varint(0)); // token length = 0
    pkt.extend_from_slice(&encode_quic_varint(payload.len() as u64)); // length
    pkt.extend_from_slice(&payload);

    fixup_ipv4_length(&mut pkt, ip_start);
    fixup_udp_length(&mut pkt, udp_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "QUIC");
    assert_eq!(buf.layers()[3].display_name, Some("QUIC Initial"));

    let quic = buf.layer_by_name("QUIC").unwrap();
    assert_eq!(
        buf.field_by_name(quic, "header_form").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(quic, "version").unwrap().value,
        FieldValue::U32(0x0000_0001)
    );
    assert_eq!(
        buf.field_by_name(quic, "dcid").unwrap().value,
        FieldValue::Bytes(&dcid)
    );
    assert_eq!(
        buf.field_by_name(quic, "scid").unwrap().value,
        FieldValue::Bytes(&scid)
    );
}

#[test]
fn integration_ethernet_ipv4_udp_quic_short() {
    let reg = DissectorRegistry::default();
    let mut pkt: Vec<u8> = Vec::new();
    push_ethernet(&mut pkt, [0; 6], [0; 6], 0x0800);
    let ip_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 443, 54321);

    // QUIC Short Header: header_form=0, fixed_bit=1, spin_bit=1, key_phase=0
    pkt.push(0x60); // 0b01100000
    pkt.extend_from_slice(&[0xBB; 20]); // DCID + encrypted payload

    fixup_ipv4_length(&mut pkt, ip_start);
    fixup_udp_length(&mut pkt, udp_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[3].name, "QUIC");
    assert_eq!(buf.layers()[3].display_name, Some("QUIC Short Header"));

    let quic = buf.layer_by_name("QUIC").unwrap();
    assert_eq!(
        buf.field_by_name(quic, "header_form").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(quic, "spin_bit").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(quic, "key_phase").unwrap().value,
        FieldValue::U8(0)
    );
}

// ---------------------------------------------------------------------------
// STUN
// ---------------------------------------------------------------------------

#[test]
fn integration_ethernet_ipv4_udp_stun_binding_request() {
    let reg = DissectorRegistry::default();
    let mut pkt: Vec<u8> = Vec::new();
    push_ethernet(&mut pkt, [0; 6], [0; 6], 0x0800);
    let ip_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 12345, 3478);

    // STUN Binding Request (RFC 8489)
    pkt.extend_from_slice(&[
        0x00, 0x01, // Message Type: Binding Request
        0x00, 0x00, // Message Length: 0
        0x21, 0x12, 0xA4, 0x42, // Magic Cookie
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Transaction ID (12 bytes)
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    ]);

    fixup_ipv4_length(&mut pkt, ip_start);
    fixup_udp_length(&mut pkt, udp_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "STUN");

    let stun = buf.layer_by_name("STUN").unwrap();
    assert_eq!(
        buf.field_by_name(stun, "message_class").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.resolve_display_name(stun, "message_class_name"),
        Some("Request")
    );
    assert_eq!(
        buf.field_by_name(stun, "message_method").unwrap().value,
        FieldValue::U16(0x001)
    );
    assert_eq!(
        buf.resolve_display_name(stun, "message_method_name"),
        Some("Binding")
    );
    assert_eq!(
        buf.field_by_name(stun, "magic_cookie").unwrap().value,
        FieldValue::U32(0x2112_A442)
    );
}

// ---------------------------------------------------------------------------
// IGMP
// ---------------------------------------------------------------------------

/// IGMPv2 Membership Report (8 bytes).
fn push_igmp_v2_report(pkt: &mut Vec<u8>, group: [u8; 4]) {
    pkt.push(0x16); // type = IGMPv2 Membership Report
    pkt.push(0x00); // max resp time
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&group);
}

/// IGMPv3 Membership Report with one MODE_IS_INCLUDE record and no sources.
fn push_igmp_v3_report(pkt: &mut Vec<u8>, group: [u8; 4]) {
    pkt.push(0x22); // type = IGMPv3 Membership Report
    pkt.push(0x00); // reserved
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // flags (RFC 9776 §4.2.3)
    pkt.extend_from_slice(&1u16.to_be_bytes()); // num_group_records = 1
    // Group Record: MODE_IS_INCLUDE, aux=0, num_src=0
    pkt.push(0x01); // record_type
    pkt.push(0x00); // aux_data_len
    pkt.extend_from_slice(&0u16.to_be_bytes()); // num_sources
    pkt.extend_from_slice(&group); // multicast address
}

#[test]
fn integration_ethernet_ipv4_igmp_v2_report() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x01, 0x00, 0x5e, 0x01, 0x01, 0x01],
        MAC_SRC,
        0x0800,
    );
    let ip_start = push_ipv4(&mut pkt, 2, IPV4_SRC, [239, 1, 1, 1]);
    push_igmp_v2_report(&mut pkt, [239, 1, 1, 1]);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 3);
    assert_layers_contiguous(&buf);

    assert_eq!(buf.layers()[0].name, "Ethernet");
    let ipv4 = &buf.layers()[1];
    assert_eq!(ipv4.name, "IPv4");
    assert_eq!(
        buf.field_by_name(ipv4, "protocol").unwrap().value,
        FieldValue::U8(2)
    ); // IGMP

    let igmp = &buf.layers()[2];
    assert_eq!(igmp.name, "IGMP");
    assert_eq!(
        buf.field_by_name(igmp, "type").unwrap().value,
        FieldValue::U8(0x16)
    );
    assert_eq!(
        buf.field_by_name(igmp, "group_address").unwrap().value,
        FieldValue::Ipv4Addr([239, 1, 1, 1])
    );
}

#[test]
fn integration_ethernet_ipv4_igmp_v3_report() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x01, 0x00, 0x5e, 0x00, 0x00, 0x16],
        MAC_SRC,
        0x0800,
    );
    let ip_start = push_ipv4(&mut pkt, 2, IPV4_SRC, [224, 0, 0, 22]);
    push_igmp_v3_report(&mut pkt, [239, 2, 2, 2]);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 3);
    assert_layers_contiguous(&buf);

    let igmp = &buf.layers()[2];
    assert_eq!(igmp.name, "IGMP");
    assert_eq!(
        buf.field_by_name(igmp, "type").unwrap().value,
        FieldValue::U8(0x22)
    );
    assert_eq!(
        buf.field_by_name(igmp, "num_group_records").unwrap().value,
        FieldValue::U16(1)
    );
    if let FieldValue::Array(ref records) = buf.field_by_name(igmp, "group_records").unwrap().value
    {
        assert_eq!(direct_children(&buf, records).len(), 1);
    } else {
        panic!("expected Array for group_records");
    }
}

// HTTP/2 tests
// ---------------------------------------------------------------------------

/// Ethernet → IPv4 → TCP → HTTP/2 (h2c connection preface + SETTINGS)
#[cfg(all(
    feature = "ethernet",
    feature = "ipv4",
    feature = "tcp",
    feature = "http2"
))]
#[test]
fn integration_ethernet_ipv4_tcp_http2_settings() {
    let registry = DissectorRegistry::default();

    // Build HTTP/2 connection preface + SETTINGS frame
    let mut http2_payload = Vec::new();
    http2_payload.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    // SETTINGS frame: INITIAL_WINDOW_SIZE=65535
    let settings_param = [0x00, 0x04, 0x00, 0x00, 0xFF, 0xFF]; // id=4, value=65535
    let len = settings_param.len() as u32;
    http2_payload.push((len >> 16) as u8);
    http2_payload.push((len >> 8) as u8);
    http2_payload.push(len as u8);
    http2_payload.push(0x04); // SETTINGS
    http2_payload.push(0x00); // flags
    http2_payload.extend_from_slice(&0u32.to_be_bytes()); // stream ID 0
    http2_payload.extend_from_slice(&settings_param);

    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]);
    push_tcp(&mut pkt, 12345, 80, 0x18); // PSH+ACK
    pkt.extend_from_slice(&http2_payload);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    // Should have 4 layers: Ethernet, IPv4, TCP, HTTP2
    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "TCP");
    assert_eq!(buf.layers()[3].name, "HTTP2");

    let http2 = buf.layer_by_name("HTTP2").unwrap();
    assert_eq!(
        buf.field_by_name(http2, "magic").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(http2, "frame_type").unwrap().value,
        FieldValue::U8(0x04)
    );
    assert_eq!(
        buf.field_by_name(http2, "stream_id").unwrap().value,
        FieldValue::U32(0)
    );

    let settings = {
        let f = buf.field_by_name(http2, "settings").unwrap();
        let FieldValue::Array(ref r) = f.value else {
            panic!("expected Array")
        };
        direct_children(&buf, r)
    };
    assert_eq!(settings.len(), 1);
    let FieldValue::Object(ref s0_range) = settings[0].value else {
        panic!("expected Object")
    };
    let s0 = buf.nested_fields(s0_range);
    assert_eq!(
        s0.iter().find(|f| f.name() == "id").unwrap().value,
        FieldValue::U16(0x04)
    );
    assert_eq!(
        s0.iter().find(|f| f.name() == "value").unwrap().value,
        FieldValue::U32(65535)
    );
}

/// Ethernet → IPv4 → TCP → HTTP/1.1 (HttpDispatcher routes to HTTP/1.1)
/// Verifies that HttpDispatcher still routes HTTP/1.1 correctly.
#[cfg(all(
    feature = "ethernet",
    feature = "ipv4",
    feature = "tcp",
    feature = "http",
    feature = "http2"
))]
#[test]
fn integration_ethernet_ipv4_tcp_http_dispatcher_http11() {
    let registry = DissectorRegistry::default();

    let http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]);
    push_tcp(&mut pkt, 12345, 80, 0x18); // PSH+ACK
    pkt.extend_from_slice(http_payload);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    // Should route to HTTP (not HTTP2) because data starts with "GET"
    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[3].name, "HTTP");

    let http = buf.layer_by_name("HTTP").unwrap();
    assert_eq!(
        buf.field_by_name(http, "method").unwrap().value,
        FieldValue::Str("GET")
    );
}
